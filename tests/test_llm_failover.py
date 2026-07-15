"""Tests for multi-key failover rotation in the LLM call retry loop."""

import sys
from types import ModuleType, SimpleNamespace

import pytest

from vulnclaw.agent.llm_client import (
    _call_with_persistent_retries,
    _is_key_exhausted_error,
)


class FakeAgent:
    """Minimal stand-in exposing the key-pool surface the retry loop uses."""

    def __init__(self, keys):
        self._key_pool = list(keys)
        self._key_index = 0

    def current_key(self):
        return self._key_pool[self._key_index]

    def rotate_api_key(self) -> bool:
        if len(self._key_pool) > 1:
            self._key_index = (self._key_index + 1) % len(self._key_pool)
            return True
        return False


def _ok_response():
    return SimpleNamespace(choices=[object()])


def _full_ok_response():
    message = SimpleNamespace(content="ok", tool_calls=None, reasoning_content=None)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


class TestIsKeyExhaustedError:
    def test_detects_rate_limit_and_quota_signals(self):
        for text in [
            "error code: 429 too many requests",
            "rate limit exceeded",
            "rate_limit_exceeded",
            "your quota has been exhausted",
            "deepseek: insufficient balance (402)",
            "账户余额不足",
            "code 1302 concurrency limit",
            "code 1113 balance",
        ]:
            assert _is_key_exhausted_error(text.lower()) is True, text

    def test_ignores_unrelated_errors(self):
        for text in [
            "connection reset by peer",
            "model not found",
            "invalid function arguments json string",
        ]:
            assert _is_key_exhausted_error(text.lower()) is False, text


class TestRotateApiKey:
    def test_rotate_advances_index(self):
        agent = FakeAgent(["k1", "k2"])
        assert agent.current_key() == "k1"
        assert agent.rotate_api_key() is True
        assert agent.current_key() == "k2"

    def test_rotate_single_key_is_noop(self):
        agent = FakeAgent(["only"])
        assert agent.rotate_api_key() is False
        assert agent.current_key() == "only"


class TestFailover:
    async def test_rotates_past_rate_limited_key(self):
        agent = FakeAgent(["bad", "good"])

        def request_fn():
            if agent.current_key() == "bad":
                raise RuntimeError("Error code: 429 - rate limit exceeded")
            return _ok_response()

        response, _ = await _call_with_persistent_retries(agent, request_fn, "test")
        assert response.choices
        assert agent.current_key() == "good"

    async def test_rotates_past_invalid_key_then_succeeds(self):
        agent = FakeAgent(["bad", "good"])

        def request_fn():
            if agent.current_key() == "bad":
                raise RuntimeError("invalid api key provided")
            return _ok_response()

        response, _ = await _call_with_persistent_retries(agent, request_fn, "test")
        assert response.choices
        assert agent.current_key() == "good"

    async def test_raises_when_all_keys_invalid(self):
        agent = FakeAgent(["bad1", "bad2"])

        def request_fn():
            raise RuntimeError("invalid api key provided")

        with pytest.raises(RuntimeError):
            await _call_with_persistent_retries(agent, request_fn, "test")

    async def test_single_key_auth_error_raises_fast(self):
        agent = FakeAgent(["only"])

        def request_fn():
            raise RuntimeError("unauthorized: invalid api key")

        with pytest.raises(RuntimeError):
            await _call_with_persistent_retries(agent, request_fn, "test")


class TestCallLlmUsesRotatedClient:
    """Regression test: call_llm/call_llm_auto must not close over a stale client.

    rotate_api_key() invalidates agent._client so the *next* _get_client() call
    rebuilds with the new key. If call_llm_auto captured `client =
    agent._get_client()` once and reused it across retries, every retry after a
    rotation would still hit the old (failed) key's client. The retry loop must
    call agent._get_client() fresh on every attempt.
    """

    async def test_call_llm_auto_retries_with_freshly_rotated_client(self, monkeypatch):
        from vulnclaw.agent import llm_client

        class DummyLoop:
            async def run_in_executor(self, executor, fn):
                return fn()

        class DummyClient:
            def __init__(self, key):
                self.key = key
                self.chat = SimpleNamespace(
                    completions=SimpleNamespace(create=self._create)
                )

            def _create(self, **kwargs):
                if self.key == "bad":
                    raise RuntimeError("Error code: 429 - rate limit exceeded")
                return _full_ok_response()

        class DummyAgent:
            _key_pool = ["bad", "good"]
            _key_index = 0

            class _Config:
                class _LLM:
                    model = "gpt-4o-mini"
                    max_tokens = 256
                    temperature = 0.1
                    provider = "openai"
                    reasoning_effort = "high"

                llm = _LLM()

            class _Context:
                @staticmethod
                def get_messages():
                    return []

                @staticmethod
                def add_assistant_message(text):
                    return None

            config = _Config()
            context = _Context()

            def _build_openai_tools(self):
                return []

            def _get_client(self):
                # Mirrors AgentCore._get_client(): reflects the *current*
                # rotation index, not whatever was current when first called.
                return DummyClient(self._key_pool[self._key_index])

            def rotate_api_key(self) -> bool:
                if len(self._key_pool) > 1:
                    self._key_index = (self._key_index + 1) % len(self._key_pool)
                    return True
                return False

        dummy = DummyAgent()
        monkeypatch.setattr(llm_client.asyncio, "get_running_loop", lambda: DummyLoop())

        result = await llm_client.call_llm_auto(dummy, "sys", "round")

        assert dummy._key_index == 1
        assert "ok" in result

    async def test_call_llm_retries_with_freshly_rotated_client(self, monkeypatch):
        from vulnclaw.agent import llm_client

        class DummyLoop:
            async def run_in_executor(self, executor, fn):
                return fn()

        class DummyClient:
            def __init__(self, key):
                self.key = key
                self.chat = SimpleNamespace(
                    completions=SimpleNamespace(create=self._create)
                )

            def _create(self, **kwargs):
                if self.key == "bad":
                    raise RuntimeError("invalid api key provided")
                return _full_ok_response()

        class DummyAgent:
            _key_pool = ["bad", "good"]
            _key_index = 0

            class _Config:
                class _LLM:
                    model = "gpt-4o-mini"
                    max_tokens = 256
                    temperature = 0.1
                    provider = "openai"
                    reasoning_effort = "high"

                llm = _LLM()

            class _Context:
                @staticmethod
                def get_messages():
                    return []

            config = _Config()
            context = _Context()

            def _build_openai_tools(self):
                return []

            def _get_client(self):
                return DummyClient(self._key_pool[self._key_index])

            def rotate_api_key(self) -> bool:
                if len(self._key_pool) > 1:
                    self._key_index = (self._key_index + 1) % len(self._key_pool)
                    return True
                return False

        dummy = DummyAgent()
        monkeypatch.setattr(llm_client.asyncio, "get_running_loop", lambda: DummyLoop())

        await llm_client.call_llm(dummy, "sys")

        assert dummy._key_index == 1


class TestAgentCoreRotation:
    def _agent(self, **llm):
        from vulnclaw.agent.core import AgentCore
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        for k, v in llm.items():
            setattr(config.llm, k, v)
        return AgentCore(config)

    def test_pool_from_api_keys(self):
        agent = self._agent(api_keys=["k1", "k2"])
        assert agent._key_pool == ["k1", "k2"]
        assert agent._current_api_key() == "k1"

    def test_pool_falls_back_to_single_key(self):
        agent = self._agent(api_key="solo")
        assert agent._key_pool == ["solo"]
        assert agent.rotate_api_key() is False

    def test_rotate_advances_and_invalidates_client(self, monkeypatch):
        fake_openai = ModuleType("openai")

        class FakeOpenAI:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        fake_openai.OpenAI = FakeOpenAI
        monkeypatch.setitem(sys.modules, "openai", fake_openai)

        agent = self._agent(api_keys=["k1", "k2"])
        agent._get_client()
        assert agent._client is not None
        assert agent.rotate_api_key() is True
        assert agent._client is None
        assert agent._current_api_key() == "k2"


class TestFreellmapiFallback:
    """ChatGPT usage-cap (429 usage_limit_reached) fails over to local FreeLLMAPI."""

    def test_is_chatgpt_usage_limit_error_detects_marker(self):
        from vulnclaw.agent.llm_client import _is_chatgpt_usage_limit_error

        assert (
            _is_chatgpt_usage_limit_error(
                'error code: 429 - {"error":{"type":"usage_limit_reached"}}'
            )
            is True
        )
        assert _is_chatgpt_usage_limit_error("rate limit exceeded") is False
        assert _is_chatgpt_usage_limit_error("error code: 429 too many requests") is False

    def _agent(self, **llm):
        from vulnclaw.agent.core import AgentCore
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        for k, v in llm.items():
            setattr(config.llm, k, v)
        return AgentCore(config)

    def test_maybe_switch_requires_opt_in_and_key(self):
        from vulnclaw.agent.llm_client import _maybe_switch_to_freellmapi_fallback

        agent = self._agent()
        error_text = "usage_limit_reached"

        # Not opted in -> no-op.
        assert _maybe_switch_to_freellmapi_fallback(agent, error_text) is False
        assert agent._chatgpt_usage_exhausted is False

        # Opted in but no unified key configured -> still a no-op.
        agent.config.llm.freellmapi_fallback = True
        assert _maybe_switch_to_freellmapi_fallback(agent, error_text) is False
        assert agent._chatgpt_usage_exhausted is False

        # Opted in + key present -> switches, and rewrites kwargs["model"] in
        # place so an in-flight retry loop targets the fallback immediately.
        agent.config.llm.freellmapi_api_key = "freellmapi-test"
        kwargs = {"model": "gpt-5.5", "messages": []}
        assert _maybe_switch_to_freellmapi_fallback(agent, error_text, kwargs) is True
        assert agent._chatgpt_usage_exhausted is True
        assert kwargs["model"] == "auto"

    def test_maybe_switch_ignores_unrelated_errors(self):
        from vulnclaw.agent.llm_client import _maybe_switch_to_freellmapi_fallback

        agent = self._agent(freellmapi_fallback=True, freellmapi_api_key="freellmapi-test")

        assert _maybe_switch_to_freellmapi_fallback(agent, "rate limit exceeded") is False
        assert agent._chatgpt_usage_exhausted is False

    def test_get_client_routes_to_freellmapi_once_exhausted(self, monkeypatch):
        fake_openai = ModuleType("openai")
        created: list[dict] = []

        class FakeOpenAI:
            def __init__(self, **kwargs):
                created.append(kwargs)

        fake_openai.OpenAI = FakeOpenAI
        monkeypatch.setitem(sys.modules, "openai", fake_openai)

        agent = self._agent(
            freellmapi_fallback=True,
            freellmapi_api_key="freellmapi-test",
            freellmapi_base_url="http://localhost:3001/v1",
        )
        agent._chatgpt_usage_exhausted = True

        agent._get_client()

        assert created[-1]["api_key"] == "freellmapi-test"
        assert created[-1]["base_url"] == "http://localhost:3001/v1"

    async def test_call_llm_fails_over_to_freellmapi_after_usage_cap(self, monkeypatch):
        """End-to-end: usage_limit_reached on the primary switches backends and
        completes the *same* conversation against FreeLLMAPI instead of dying."""
        from vulnclaw.agent import llm_client

        class DummyLoop:
            async def run_in_executor(self, executor, fn):
                return fn()

        class DummyClient:
            def __init__(self, name):
                self.name = name
                self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

            def _create(self, **kwargs):
                if self.name == "chatgpt":
                    raise RuntimeError(
                        'Error code: 429 - {"error":{"type":"usage_limit_reached"}}'
                    )
                # Fallback must see the *whole* forwarded conversation and the
                # freellmapi (not ChatGPT-only) model.
                assert kwargs["model"] == "auto"
                assert kwargs["messages"][-1]["content"] == "help me create a .exe file"
                return _full_ok_response()

        class DummyAgent:
            _chatgpt_usage_exhausted = False

            class _Config:
                class _LLM:
                    model = "gpt-5.5"
                    max_tokens = 256
                    temperature = 0.1
                    provider = "openai"
                    reasoning_effort = "high"
                    freellmapi_fallback = True
                    freellmapi_api_key = "freellmapi-test"
                    freellmapi_base_url = "http://localhost:3001/v1"
                    freellmapi_model = "auto"

                llm = _LLM()

            class _Context:
                @staticmethod
                def get_messages():
                    return [{"role": "user", "content": "help me create a .exe file"}]

            config = _Config()
            context = _Context()

            def _build_openai_tools(self):
                return []

            def _get_client(self):
                return DummyClient("freellmapi" if self._chatgpt_usage_exhausted else "chatgpt")

            def rotate_api_key(self):
                return False

        dummy = DummyAgent()
        monkeypatch.setattr(llm_client.asyncio, "get_running_loop", lambda: DummyLoop())

        result = await llm_client.call_llm(dummy, "sys")

        assert dummy._chatgpt_usage_exhausted is True
        assert "ok" in result

    async def test_call_llm_stream_fails_over_to_freellmapi_after_usage_cap(self, monkeypatch):
        """Same failover, but through the streaming path the REPL actually uses."""
        from vulnclaw.agent import llm_client

        def _text_chunk(text):
            delta = SimpleNamespace(content=text, reasoning_content=None, tool_calls=None)
            return SimpleNamespace(choices=[SimpleNamespace(delta=delta)])

        class DummyClient:
            def __init__(self, name):
                self.name = name
                self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

            def _create(self, **kwargs):
                if self.name == "chatgpt":
                    raise RuntimeError(
                        'Error code: 429 - {"error":{"type":"usage_limit_reached"}}'
                    )
                assert kwargs["model"] == "auto"
                assert kwargs["messages"][-1]["content"] == "help me create a .exe file"
                return [_text_chunk("ok from freellmapi")]

        class DummyAgent:
            _chatgpt_usage_exhausted = False

            class _Config:
                class _LLM:
                    model = "gpt-5.5"
                    max_tokens = 256
                    temperature = 0.1
                    provider = "openai"
                    reasoning_effort = "high"
                    freellmapi_fallback = True
                    freellmapi_api_key = "freellmapi-test"
                    freellmapi_base_url = "http://localhost:3001/v1"
                    freellmapi_model = "auto"

                llm = _LLM()

            class _Context:
                @staticmethod
                def get_messages():
                    return [{"role": "user", "content": "help me create a .exe file"}]

            config = _Config()
            context = _Context()

            def _build_openai_tools(self):
                return []

            def _get_client(self):
                return DummyClient("freellmapi" if self._chatgpt_usage_exhausted else "chatgpt")

        class RecordingSink:
            def __init__(self):
                self.statuses: list[str] = []
                self.content: list[str] = []

            def on_status(self, message):
                self.statuses.append(message)

            def on_thinking_token(self, token):
                pass

            def on_content_token(self, token):
                self.content.append(token)

            def on_tool_call(self, name, args):
                pass

            def on_tool_result(self, result_summary):
                pass

            def on_stream_end(self):
                pass

        dummy = DummyAgent()
        sink = RecordingSink()

        result = await llm_client.call_llm_stream(dummy, "sys", sink)

        assert dummy._chatgpt_usage_exhausted is True
        assert "ok from freellmapi" in result
        assert "".join(sink.content) == "ok from freellmapi"
        assert any("freellmapi" in s.lower() for s in sink.statuses)


class TestActiveBackendLabel:
    """The 'Thinking... [backend/model]' status label always names the
    backend the *next* request will actually hit."""

    def _agent(self, **llm):
        from vulnclaw.agent.core import AgentCore
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        for k, v in llm.items():
            setattr(config.llm, k, v)
        return AgentCore(config)

    def test_labels_primary_provider_and_model(self):
        from vulnclaw.agent.llm_client import _active_backend_label

        agent = self._agent(provider="openai", model="gpt-5.5")
        assert _active_backend_label(agent) == "openai/gpt-5.5"

    def test_labels_freellmapi_when_base_url_points_there_even_with_stale_provider(self):
        """Regression: llm.provider is a cosmetic free-text field a user can
        leave stale (e.g. 'deepseek') after switching llm.base_url to point
        directly at FreeLLMAPI as the *primary* backend, not via the usage-cap
        fallback. The label must reflect the real endpoint, not that field."""
        from vulnclaw.agent.llm_client import _active_backend_label

        agent = self._agent(
            provider="deepseek",
            base_url="http://localhost:3001/v1",
            freellmapi_base_url="http://localhost:3001/v1",
            model="auto",
        )
        assert _active_backend_label(agent) == "freellmapi/auto"

    def test_labels_freellmapi_once_exhausted_and_enabled(self):
        from vulnclaw.agent.llm_client import _active_backend_label

        agent = self._agent(
            provider="openai",
            model="gpt-5.5",
            freellmapi_fallback=True,
            freellmapi_model="auto",
        )
        agent._chatgpt_usage_exhausted = True

        assert _active_backend_label(agent) == "freellmapi/auto"

    def test_stays_on_primary_label_when_exhausted_but_fallback_disabled(self):
        from vulnclaw.agent.llm_client import _active_backend_label

        agent = self._agent(provider="openai", model="gpt-5.5", freellmapi_fallback=False)
        agent._chatgpt_usage_exhausted = True

        assert _active_backend_label(agent) == "openai/gpt-5.5"

    async def test_streaming_status_includes_backend_label(self, monkeypatch):
        """End-to-end: the label shown in on_status must match where the call
        actually lands (regression guard against the label and the routing
        logic in AgentCore._get_client silently drifting apart)."""
        from vulnclaw.agent import llm_client

        def _text_chunk(text):
            delta = SimpleNamespace(content=text, reasoning_content=None, tool_calls=None)
            return SimpleNamespace(choices=[SimpleNamespace(delta=delta)])

        class DummyClient:
            def __init__(self):
                self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

            def _create(self, **kwargs):
                return [_text_chunk("ok")]

        class DummyAgent:
            _chatgpt_usage_exhausted = False

            class _Config:
                class _LLM:
                    model = "gpt-5.5"
                    max_tokens = 256
                    temperature = 0.1
                    provider = "openai"
                    reasoning_effort = "high"
                    freellmapi_fallback = False

                llm = _LLM()

            class _Context:
                @staticmethod
                def get_messages():
                    return [{"role": "user", "content": "hi"}]

            config = _Config()
            context = _Context()

            def _build_openai_tools(self):
                return []

            def _get_client(self):
                return DummyClient()

        class RecordingSink:
            def __init__(self):
                self.statuses = []

            def on_status(self, message):
                self.statuses.append(message)

            def on_thinking_token(self, token):
                pass

            def on_content_token(self, token):
                pass

            def on_tool_call(self, name, args):
                pass

            def on_tool_result(self, result_summary):
                pass

            def on_stream_end(self):
                pass

        dummy = DummyAgent()
        sink = RecordingSink()

        await llm_client.call_llm_stream(dummy, "sys", sink)

        assert any("openai/gpt-5.5" in s for s in sink.statuses)
