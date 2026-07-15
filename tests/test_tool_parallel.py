"""Tests for parallel tool-call execution in tool_call_manager."""

from __future__ import annotations

import asyncio
import time

import pytest

from vulnclaw.agent.tool_call_manager import handle_tool_calls_with_results


class _Func:
    def __init__(self, name: str, arguments: str) -> None:
        self.name = name
        self.arguments = arguments


class _ToolCall:
    def __init__(self, call_id: str, name: str, arguments: str) -> None:
        self.id = call_id
        self.function = _Func(name, arguments)


class _Message:
    def __init__(self, tool_calls: list[_ToolCall]) -> None:
        self.tool_calls = tool_calls


class _Safety:
    def __init__(self, tool_parallel: bool = True, tool_max_concurrent: int = 5) -> None:
        self.tool_parallel = tool_parallel
        self.tool_max_concurrent = tool_max_concurrent


class _Config:
    def __init__(self, safety: _Safety) -> None:
        self.safety = safety


class _Agent:
    """Minimal agent stub whose tool execution is configurable per test."""

    def __init__(self, executor, safety: _Safety | None = None) -> None:
        self.mcp_manager = None
        self.config = _Config(safety or _Safety())
        self._executor = executor

    async def _execute_mcp_tool(self, func_name, func_args):
        return await self._executor(func_name, func_args)


def _make_message(specs: list[tuple[str, str, str]]) -> _Message:
    """specs: list of (call_id, func_name, arguments_json)."""
    return _Message([_ToolCall(cid, name, args) for cid, name, args in specs])


@pytest.mark.asyncio
async def test_parallel_executes_all_calls_and_preserves_order():
    async def executor(func_name, func_args):
        await asyncio.sleep(0.05)
        return f"ran:{func_args['n']}"

    agent = _Agent(executor, _Safety(tool_parallel=True, tool_max_concurrent=5))
    message = _make_message(
        [(f"c{i}", "probe", f'{{"n":{i}}}') for i in range(5)]
    )

    start = time.monotonic()
    results, skipped = await handle_tool_calls_with_results(agent, message)
    elapsed = time.monotonic() - start

    assert skipped == []
    assert len(results) == 5
    # Order preserved: result i corresponds to tool_call i.
    for i, r in enumerate(results):
        assert r["tool_call_id"] == f"c{i}"
        assert r["content"] == f"[tool:probe] ran:{i}"
    # 5 calls of 0.05s each run concurrently → well under serial 0.25s.
    assert elapsed < 0.2


@pytest.mark.asyncio
async def test_error_isolation_one_failure_does_not_block_others():
    async def executor(func_name, func_args):
        if func_args["n"] == 2:
            raise RuntimeError("boom")
        return f"ran:{func_args['n']}"

    agent = _Agent(executor, _Safety(tool_parallel=True, tool_max_concurrent=5))
    message = _make_message(
        [(f"c{i}", "probe", f'{{"n":{i}}}') for i in range(4)]
    )

    results, skipped = await handle_tool_calls_with_results(agent, message)

    # The failing call (n=2) is dropped; the other 3 succeed.
    assert skipped == []
    returned_ids = {r["tool_call_id"] for r in results}
    assert returned_ids == {"c0", "c1", "c3"}
    # Surviving results keep their original relative order.
    assert [r["tool_call_id"] for r in results] == ["c0", "c1", "c3"]


@pytest.mark.asyncio
async def test_concurrency_capped_at_max_concurrent():
    state = {"active": 0, "peak": 0}
    lock = asyncio.Lock()

    async def executor(func_name, func_args):
        async with lock:
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
        await asyncio.sleep(0.05)
        async with lock:
            state["active"] -= 1
        return f"ran:{func_args['n']}"

    agent = _Agent(executor, _Safety(tool_parallel=True, tool_max_concurrent=2))
    # 8 distinct calls, but dedup cap is 10, so all execute.
    message = _make_message(
        [(f"c{i}", "probe", f'{{"n":{i}}}') for i in range(8)]
    )

    results, _ = await handle_tool_calls_with_results(agent, message)

    assert len(results) == 8
    # Never more than max_concurrent (2) running at once.
    assert state["peak"] <= 2


@pytest.mark.asyncio
async def test_serial_fallback_when_parallel_disabled():
    order: list[int] = []

    async def executor(func_name, func_args):
        n = func_args["n"]
        order.append(n)
        # If serial, each call completes before the next starts.
        await asyncio.sleep(0.01)
        order.append(-n)
        return f"ran:{n}"

    agent = _Agent(executor, _Safety(tool_parallel=False, tool_max_concurrent=5))
    message = _make_message(
        [(f"c{i}", "probe", f'{{"n":{i}}}') for i in range(3)]
    )

    results, _ = await handle_tool_calls_with_results(agent, message)

    assert len(results) == 3
    # Serial execution: start/end of each call do not interleave.
    assert order == [0, 0, 1, -1, 2, -2] or order == [0, -0, 1, -1, 2, -2]


@pytest.mark.asyncio
async def test_single_call_runs_without_parallel_overhead():
    async def executor(func_name, func_args):
        return "ok"

    agent = _Agent(executor, _Safety(tool_parallel=True, tool_max_concurrent=5))
    message = _make_message([("c0", "probe", "{}")])

    results, skipped = await handle_tool_calls_with_results(agent, message)

    assert skipped == []
    assert len(results) == 1
    assert results[0]["content"] == "[tool:probe] ok"


@pytest.mark.asyncio
async def test_mcp_tool_executed_exactly_once_per_call():
    """Regression: _execute_single must not re-invoke mcp_manager.call_tool.

    Previously it called call_tool a second time to read structured_content,
    which ran every MCP-backed tool's side effect twice.
    """

    class _CountingMcp:
        def __init__(self) -> None:
            self.calls = 0

        async def call_tool(self, name, args):
            self.calls += 1
            return {"ok": True, "content": "done", "structured_content": {"n": args.get("n")}}

    mcp = _CountingMcp()

    class _McpAgent:
        def __init__(self) -> None:
            self.mcp_manager = mcp
            self.config = _Config(_Safety(tool_parallel=True, tool_max_concurrent=5))

        async def _execute_mcp_tool(self, func_name, func_args):
            # Mirror the real dispatch: genuine MCP tools go through call_tool once.
            result = await self.mcp_manager.call_tool(func_name, func_args)
            return str(result.get("content"))

    message = _make_message([(f"c{i}", "probe", f'{{"n":{i}}}') for i in range(3)])
    results, _ = await handle_tool_calls_with_results(_McpAgent(), message)

    assert len(results) == 3
    # Exactly one execution per tool call - not double.
    assert mcp.calls == 3


@pytest.mark.asyncio
async def test_missing_config_defaults_to_parallel():
    async def executor(func_name, func_args):
        await asyncio.sleep(0.05)
        return f"ran:{func_args['n']}"

    # Agent without a config attribute at all - should still parallelize.
    class _BareAgent:
        mcp_manager = None

        async def _execute_mcp_tool(self, func_name, func_args):
            return await executor(func_name, func_args)

    message = _make_message(
        [(f"c{i}", "probe", f'{{"n":{i}}}') for i in range(4)]
    )

    start = time.monotonic()
    results, _ = await handle_tool_calls_with_results(_BareAgent(), message)
    elapsed = time.monotonic() - start

    assert len(results) == 4
    assert elapsed < 0.18
