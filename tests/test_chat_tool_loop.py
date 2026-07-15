"""Single-turn chat must run a multi-round agentic tool loop.

Regression for the reported bug: after a tool call (e.g. ``file_read``) the chat
path returned the tool's raw output and ended the turn instead of feeding the
result back to the model - so "after reading the file the convo stops", and a
read → edit chain could never complete in one turn ("creating and modifying
files is buggy").

These drive ``call_llm`` (non-streaming, the web path) and ``call_llm_stream``
(streaming, the REPL path) through the real ``handle_tool_calls_with_results``
tool dispatch, asserting the tools run in order and the final answer is the
model's text - not the raw tool output.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.agent import llm_client


class _DummyLoop:
    """Run the sync request fn inline so the retry loop stays deterministic."""

    async def run_in_executor(self, executor, fn):
        return fn()


def _tool_call(call_id: str, name: str, arguments: str):
    return SimpleNamespace(
        id=call_id,
        type="function",
        function=SimpleNamespace(name=name, arguments=arguments),
    )


def _message(content=None, tool_calls=None):
    return SimpleNamespace(content=content, tool_calls=tool_calls, reasoning_content=None)


def _response(message):
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


# ── streaming chunk builders (shaped like OpenAI deltas) ────────────────────


def _text_chunk(text: str):
    delta = SimpleNamespace(content=text, reasoning_content=None, tool_calls=None)
    return SimpleNamespace(choices=[SimpleNamespace(delta=delta)])


def _tool_chunk(call_id: str, name: str, arguments: str):
    tc = SimpleNamespace(
        index=0, id=call_id, function=SimpleNamespace(name=name, arguments=arguments)
    )
    delta = SimpleNamespace(content=None, reasoning_content=None, tool_calls=[tc])
    return SimpleNamespace(choices=[SimpleNamespace(delta=delta)])


class _SyncStream:
    def __init__(self, chunks):
        self._chunks = chunks

    def __iter__(self):
        return iter(self._chunks)


class _ScriptedClient:
    """Returns each scripted response/stream in turn on successive create calls."""

    def __init__(self, scripted):
        self._scripted = list(scripted)
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        return self._scripted.pop(0)


class _ToolAgent:
    """Minimal AgentContext stand-in that dispatches tools for real."""

    def __init__(self, client):
        self._client = client
        self.tool_calls_made: list[tuple[str, dict]] = []

        self.config = SimpleNamespace(
            llm=SimpleNamespace(
                model="gpt-4",
                provider="openai",
                max_tokens=None,
                temperature=None,
                max_context_tokens=None,
                freellmapi_fallback=False,
            ),
            safety=None,
        )
        self.context = SimpleNamespace(
            get_messages=lambda: [{"role": "user", "content": "read then edit foo.py"}],
            add_assistant_message=lambda text: None,
        )

    def _get_client(self):
        return self._client

    def _build_openai_tools(self):
        return [{"type": "function", "function": {"name": "file_read", "parameters": {}}}]

    async def _execute_mcp_tool(self, name: str, args: dict) -> str:
        self.tool_calls_made.append((name, args))
        if name == "file_read":
            return "[file_read] def add(a, b):\n    return a - b  # bug"
        if name == "file_edit":
            return "[✓] Edited foo.py (1 replacement)"
        return f"[!] unknown tool {name}"


@pytest.mark.asyncio
async def test_call_llm_loops_tool_then_returns_model_text(monkeypatch):
    """Non-streaming: a file_read tool call is fed back; the turn returns the
    model's follow-up text, not the raw file dump."""
    monkeypatch.setattr(llm_client.asyncio, "get_running_loop", lambda: _DummyLoop())

    client = _ScriptedClient(
        [
            _response(_message(tool_calls=[_tool_call("c1", "file_read", '{"path": "foo.py"}')])),
            _response(_message(content="foo.py defines add(), which subtracts - a bug.")),
        ]
    )
    agent = _ToolAgent(client)

    result = await llm_client.call_llm(agent, "sys")

    assert agent.tool_calls_made == [("file_read", {"path": "foo.py"})]
    assert result == "foo.py defines add(), which subtracts - a bug."
    # The raw tool output must NOT be what the turn returns.
    assert "[file_read]" not in result


@pytest.mark.asyncio
async def test_call_llm_stream_chains_read_then_edit(monkeypatch):
    """Streaming: read → edit chains across rounds in a single turn, and the
    final streamed text (not a tool result) is returned."""
    monkeypatch.setattr(llm_client.asyncio, "get_running_loop", lambda: _DummyLoop())

    client = _ScriptedClient(
        [
            _SyncStream([_tool_chunk("c1", "file_read", '{"path": "foo.py"}')]),
            _SyncStream(
                [
                    _tool_chunk(
                        "c2",
                        "file_edit",
                        '{"path": "foo.py", "old_string": "a - b", "new_string": "a + b"}',
                    )
                ]
            ),
            _SyncStream([_text_chunk("Fixed the subtraction bug in add().")]),
        ]
    )
    agent = _ToolAgent(client)

    result = await llm_client.call_llm_stream(agent, "sys")

    assert [name for name, _ in agent.tool_calls_made] == ["file_read", "file_edit"]
    assert result == "Fixed the subtraction bug in add()."


@pytest.mark.asyncio
async def test_call_llm_stops_at_round_cap(monkeypatch):
    """A model that calls a tool every round is stopped at the cap, and the
    tools are withheld on the final call so it must answer with text."""
    monkeypatch.setattr(llm_client.asyncio, "get_running_loop", lambda: _DummyLoop())

    # Always ask for a tool; only the final (tools-withheld) call yields text.
    scripted = [
        _response(_message(tool_calls=[_tool_call(f"c{i}", "file_read", '{"path": "foo.py"}')]))
        for i in range(llm_client._MAX_CHAT_TOOL_ROUNDS)
    ]
    scripted.append(_response(_message(content="stopped after the cap")))

    captured_had_tools: list[bool] = []
    client = _ScriptedClient(scripted)
    orig_create = client._create

    def _spy_create(**kwargs):
        captured_had_tools.append("tools" in kwargs)
        return orig_create(**kwargs)

    client.chat.completions.create = _spy_create
    agent = _ToolAgent(client)

    result = await llm_client.call_llm(agent, "sys")

    assert len(agent.tool_calls_made) == llm_client._MAX_CHAT_TOOL_ROUNDS
    assert result == "stopped after the cap"
    # The final request must have withheld the tools to force a text answer.
    assert captured_had_tools[-1] is False
