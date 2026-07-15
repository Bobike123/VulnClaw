"""LLM client helpers for AgentCore."""

from __future__ import annotations

import asyncio
import inspect
import json
import sys
from typing import TYPE_CHECKING, Any, Optional, Protocol, runtime_checkable

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext


from vulnclaw.agent.token_counter import estimate_tokens, truncate_messages
from vulnclaw.agent.tool_call_manager import handle_tool_calls_with_results

_CONTEXT_USABLE_RATIO = 0.9

# Single-turn chat (AgentCore.chat) has no outer loop, so it must run its own
# agentic tool loop: execute the model's tool calls, feed the results back, and
# let it respond — repeating so it can chain steps like read → edit → confirm in
# one turn. This caps how many such rounds a single chat turn may take before we
# withhold the tools and force a final text answer (runaway guard).
_MAX_CHAT_TOOL_ROUNDS = 8


def _fit_context_window(agent: AgentContext, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Truncate messages to fit the configured context window (90% usable budget)."""
    llm = getattr(agent, "config", None)
    llm = getattr(llm, "llm", None) if llm is not None else None
    max_context = getattr(llm, "max_context_tokens", None)
    if not isinstance(max_context, (int, float)) or isinstance(max_context, bool):
        return messages
    if max_context <= 0:
        return messages

    budget = int(max_context * _CONTEXT_USABLE_RATIO)
    current = estimate_tokens(messages)
    if current <= budget:
        return messages

    trimmed = truncate_messages(messages, budget, preserve_system=True)
    try:
        from rich.console import Console

        Console().print(
            f"[yellow][!] Context ~{current} tokens exceeds window budget {budget}, "
            f"truncated to ~{estimate_tokens(trimmed)} tokens[/yellow]"
        )
    except Exception:
        print(f"[!] Context truncated: {current} → {estimate_tokens(trimmed)} tokens (budget {budget})")
    return trimmed


def extract_response(message: Any) -> str:
    """Extract the actual response text from an LLM message.

    Handles:
    1. Normal content (no thinking)
    2. Content with inline <thinking> tags (open/closed)
    3. Separate reasoning_content field (DeepSeek R1, etc.)
    """
    content = message.content or ""
    reasoning = getattr(message, "reasoning_content", None) or ""
    if reasoning and not content:
        content = f"<thinking>\n{reasoning}\n</thinking>\n"
    elif reasoning and content:
        content = f"<thinking>\n{reasoning}\n</thinking>\n{content}"
    return content


def _is_non_retriable_llm_error(error_text: str) -> bool:
    """Return True for configuration/auth errors that should fail fast."""
    hard_fail_markers = [
        "bad_request_error",
        "incorrect api key",
        "invalid api key",
        "invalid chat setting",
        "invalid function arguments json string",
        "tool_call_id",
        "authentication",
        "unauthorized",
        "permission denied",
        "model not found",
        "no such model",
        "invalid_request_error",
        "unsupported parameter",
    ]
    return any(marker in error_text for marker in hard_fail_markers)


def _is_key_exhausted_error(error_text: str) -> bool:
    """Return True for errors that mean the *current* API key is unusable.

    These are rate-limit / quota / balance exhaustion signals where switching to
    a different key is the right recovery. Covers OpenAI-style 429/quota plus
    deepseek (402 insufficient balance) and zhipu (codes 1302/1113, 余额) errors.
    """
    exhausted_markers = [
        "rate limit",
        "rate_limit",
        "too many requests",
        "429",
        "quota",
        "insufficient balance",
        "余额",  # zhipu/deepseek: account balance insufficient
        "402",
        "1302",  # zhipu: concurrency / rate limit
        "1113",  # zhipu: account balance insufficient
    ]
    return any(marker in error_text for marker in exhausted_markers)


def _is_chatgpt_usage_limit_error(error_text: str) -> bool:
    """Return True for the ChatGPT-backend-specific usage-cap error.

    Distinct from the generic ``_is_key_exhausted_error`` rate-limit markers:
    this is the ChatGPT subscription's *account-level* usage cap (not a
    transient per-key rate limit), which won't clear by rotating keys or
    retrying in a few seconds — it needs a different backend, or a multi-hour
    wait for the quota to reset.
    """
    return "usage_limit_reached" in error_text


def _maybe_switch_to_freellmapi_fallback(
    agent: AgentContext, error_text: str, kwargs: dict[str, Any] | None = None
) -> bool:
    """Fail the current session over to the local FreeLLMAPI router.

    Triggered only by the ChatGPT usage-cap error, and only when the user has
    opted in (``llm.freellmapi_fallback``) and configured a unified API key.
    Marks the agent as exhausted (sticky for the rest of this AgentCore's
    life — see ``AgentCore._get_client``) and, if given the in-flight
    ``kwargs`` dict, swaps its ``model`` in place so an immediate retry in the
    same call targets the fallback instead of the dead ChatGPT backend.
    """
    if not _is_chatgpt_usage_limit_error(error_text):
        return False
    llm = agent.config.llm
    if not getattr(llm, "freellmapi_fallback", False):
        return False
    if not getattr(llm, "freellmapi_api_key", ""):
        return False

    already_switched = agent._chatgpt_usage_exhausted
    agent._chatgpt_usage_exhausted = True
    if kwargs is not None:
        kwargs["model"] = str(getattr(llm, "freellmapi_model", "") or "auto")
    if not already_switched:
        print(
            "[!] ChatGPT usage limit reached — switching to local FreeLLMAPI "
            f"({getattr(llm, 'freellmapi_base_url', '')}) for the rest of this session.",
            file=sys.stdout,
            flush=True,
        )
    return True


def _is_openai_reasoning_model(provider: str, model: str) -> bool:
    """Return True for OpenAI models that use the newer reasoning parameter set."""
    if provider.lower() != "openai":
        return False
    normalized = model.lower()
    return normalized.startswith(("o1", "o3", "o4", "gpt-5"))


def _active_backend_label(agent: AgentContext) -> str:
    """Human-readable ``provider/model`` (or ``freellmapi/model``) for status lines.

    Mirrors the same fallback predicate ``build_chat_completion_kwargs`` and
    ``AgentCore._get_client`` use, so the label always names whichever backend
    the *next* request actually goes to. Detects FreeLLMAPI by the actual
    ``base_url`` in play (fallback-triggered *or* configured as the primary
    backend directly), not just the free-text ``llm.provider`` field — that
    field is only a cosmetic label a user can leave stale (e.g. still says
    "deepseek" after pointing ``base_url`` at FreeLLMAPI), so trusting it alone
    would silently mislabel exactly the case this status line exists for.
    """
    llm = agent.config.llm
    if getattr(agent, "_chatgpt_usage_exhausted", False) and getattr(llm, "freellmapi_fallback", False):
        return f"freellmapi/{str(getattr(llm, 'freellmapi_model', '') or 'auto')}"

    base_url = str(getattr(llm, "base_url", "") or "").strip().lower()
    model = str(getattr(llm, "model", "") or "").strip()
    freellmapi_base_url = str(getattr(llm, "freellmapi_base_url", "") or "").strip().lower()
    if base_url and (base_url == freellmapi_base_url or "freellmapi" in base_url):
        return f"freellmapi/{model or 'auto'}"

    provider = str(getattr(llm, "provider", "") or "").strip()
    return f"{provider}/{model}" if provider else (model or "unknown")


def build_chat_completion_kwargs(
    agent: AgentContext,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    *,
    max_tokens: int | None = None,
    temperature: float | None = None,
) -> dict[str, Any]:
    """Build provider-compatible Chat Completions kwargs.

    OpenAI reasoning/GPT-5 models reject the legacy max_tokens field and expect
    max_completion_tokens instead. Other OpenAI-compatible providers may still
    require the older field, so keep the switch scoped to OpenAI's newer model
    families.
    """
    llm = agent.config.llm
    provider = str(getattr(llm, "provider", "") or "").lower()
    if getattr(agent, "_chatgpt_usage_exhausted", False) and getattr(llm, "freellmapi_fallback", False):
        # On the FreeLLMAPI fallback, ChatGPT-only model slugs (e.g. gpt-5.5)
        # don't exist there — use its own configured/"auto" model instead.
        model = str(getattr(llm, "freellmapi_model", "") or "auto")
    else:
        model = str(getattr(llm, "model", "") or "")
    token_limit = max_tokens if max_tokens is not None else getattr(llm, "max_tokens", None)
    temp = temperature if temperature is not None else getattr(llm, "temperature", None)
    uses_reasoning_params = _is_openai_reasoning_model(provider, model)

    kwargs: dict[str, Any] = {
        "model": model,
        "messages": messages,
    }
    if token_limit is not None:
        if uses_reasoning_params:
            kwargs["max_completion_tokens"] = token_limit
        else:
            kwargs["max_tokens"] = token_limit
    if temp is not None and not uses_reasoning_params:
        kwargs["temperature"] = temp
    if tools:
        kwargs["tools"] = tools
    if uses_reasoning_params:
        reasoning_effort = getattr(llm, "reasoning_effort", None)
        if reasoning_effort:
            kwargs["reasoning_effort"] = reasoning_effort
    return kwargs


async def _call_with_persistent_retries(
    agent: AgentContext,
    request_fn,
    stage_label: str,
    *,
    kwargs: dict[str, Any] | None = None,
) -> tuple[Any, int]:
    """Keep retrying retriable LLM calls until success or manual interruption.

    ``kwargs`` is the same dict object closed over by ``request_fn`` (when the
    caller has one) — passing it through lets a ChatGPT-usage-cap failure swap
    ``kwargs["model"]`` to the FreeLLMAPI fallback in place, so the very next
    retry in this loop already targets the right backend/model.

    Returns:
        (response, retry_attempts)
    """
    loop = asyncio.get_running_loop()
    retry_attempts = 0
    pool_size = len(getattr(agent, "_key_pool", None) or [])
    can_rotate = pool_size > 1 and callable(getattr(agent, "rotate_api_key", None))
    keys_tried: set[int] = set()

    while True:
        try:
            maybe_response = loop.run_in_executor(None, request_fn)
            response = await maybe_response if inspect.isawaitable(maybe_response) else maybe_response
            if response is not None and getattr(response, "choices", None):
                return response, retry_attempts

            retry_attempts += 1
            print(
                f"[!] {stage_label} LLM API returned an abnormal response, reconnect attempt {retry_attempts}... (retry in 5s)",
                file=sys.stdout,
                flush=True,
            )
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            raise
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            error_text = str(exc).lower()

            # ChatGPT account-level usage cap: rotating keys or waiting 5s
            # won't help (it's a multi-hour reset), so switch backend instead
            # of joining the generic retry-forever path below.
            if _maybe_switch_to_freellmapi_fallback(agent, error_text, kwargs):
                retry_attempts += 1
                continue

            is_exhausted = _is_key_exhausted_error(error_text)
            is_auth = _is_non_retriable_llm_error(error_text)

            # Multi-key failover: rotate past a rate-limited / quota-drained /
            # invalid key to the next one before falling back to plain retry.
            if can_rotate and (is_exhausted or is_auth):
                keys_tried.add(getattr(agent, "_key_index", 0))
                if len(keys_tried) < pool_size:
                    agent.rotate_api_key()
                    retry_attempts += 1
                    print(
                        f"[!] {stage_label} current key failed ({exc}), switching to the next API key and retrying...",
                        file=sys.stdout,
                        flush=True,
                    )
                    continue
                # Every key has now failed in this burst.
                if is_auth and not is_exhausted:
                    # All keys are invalid/unauthorized -> nothing to recover.
                    raise
                # All keys rate-limited: keep cycling, but back off first so we
                # never hard-fail on transient quota limits.
                keys_tried.clear()
                agent.rotate_api_key()
                retry_attempts += 1
                print(
                    f"[!] {stage_label} all API keys are rate-limited, reconnect attempt {retry_attempts}... (retry in 5s)",
                    file=sys.stdout,
                    flush=True,
                )
                await asyncio.sleep(5)
                continue

            if is_auth and not is_exhausted:
                raise

            retry_attempts += 1
            print(
                f"[!] {stage_label} LLM connection error, reconnect attempt {retry_attempts}... ({exc})",
                file=sys.stdout,
                flush=True,
            )
            await asyncio.sleep(5)


def _prepend_retry_notice(text: str, retry_attempts: int) -> str:
    """Annotate a successful response if retries happened within the same round."""
    if retry_attempts <= 0:
        return text
    return f"[LLM recovery] Recovered after {retry_attempts} reconnect attempt(s) this round.\n{text}"


def _format_tool_results_fallback(
    tool_results: list[dict[str, Any]], skipped_info: list[str]
) -> str:
    """Build a plain-text fallback summary when provider tool-summary format is incompatible."""
    parts = ["[tool results processed] The current provider does not support standard tool-summary callbacks; downgraded to a plain-text result summary:"]
    for item in tool_results:
        content = item.get("content", "") if isinstance(item, dict) else str(item)
        if len(content) > 800:
            content = content[:400] + "\n...[omitted]...\n" + content[-400:]
        parts.append(content)
    if skipped_info:
        parts.append("⚠️ Skipped this round: " + "; ".join(skipped_info))
    return "\n".join(parts)


def _assistant_tool_call_message(content: str, tool_calls: list[Any]) -> dict[str, Any]:
    """Build the assistant message that echoes the tool calls we just executed.

    This is the message that must precede the ``role=tool`` results in the
    conversation so the provider can pair each result to its call by id.
    """
    return {
        "role": "assistant",
        "content": content or "",
        "tool_calls": [
            {
                "id": tc.id,
                "type": "function",
                "function": {"name": tc.function.name, "arguments": tc.function.arguments},
            }
            for tc in tool_calls
        ],
    }


def _executed_tool_calls(tool_results: list[dict[str, Any]]) -> list[Any]:
    """Recover the tool_call objects from handle_tool_calls_with_results output.

    Malformed entries (missing the ``tool_call`` key) are logged and skipped so a
    single bad result can't abort the round.
    """
    executed: list[Any] = []
    for tr in tool_results:
        if isinstance(tr, dict) and "tool_call" in tr:
            executed.append(tr["tool_call"])
        else:
            print(
                f"[!] Skipping abnormal tool result: {type(tr).__name__} {str(tr)[:100]}",
                file=sys.stderr,
            )
    return executed


def _append_tool_result_messages(
    messages: list[dict[str, Any]], tool_results: list[dict[str, Any]]
) -> None:
    """Append one ``role=tool`` message per executed tool result, in order."""
    for tr in tool_results:
        if isinstance(tr, dict) and "tool_call_id" in tr:
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tr["tool_call_id"],
                    "content": tr.get("content", ""),
                }
            )


async def call_llm(
    agent: AgentContext,
    system_prompt: str,
    *,
    stream_sink: Optional["StreamSink"] = None,
) -> str:
    """Call the LLM with the current context and system prompt (single turn)."""
    if stream_sink is not None:
        return await call_llm_stream(agent, system_prompt, stream_sink)

    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(agent.context.get_messages())
    messages = _fit_context_window(agent, messages)
    tools = agent._build_openai_tools()

    kwargs = build_chat_completion_kwargs(agent, messages, tools)

    response, retry_attempts = await _call_with_persistent_retries(
        agent,
        lambda: agent._get_client().chat.completions.create(**kwargs),
        "single-round",
        kwargs=kwargs,
    )

    choice = response.choices[0]
    total_retries = retry_attempts
    rounds = 0
    # Agentic tool loop: execute the model's tool calls, feed the results back,
    # and call it again until it answers without a tool call (or we hit the cap).
    # This is what lets a single chat turn chain steps like read → edit → confirm
    # instead of returning the first tool's raw output and stopping.
    while getattr(choice.message, "tool_calls", None):
        rounds += 1
        tool_results, _skipped = await handle_tool_calls_with_results(agent, choice.message)
        executed = _executed_tool_calls(tool_results)
        if not executed:
            break
        messages.append(_assistant_tool_call_message(choice.message.content or "", executed))
        _append_tool_result_messages(messages, tool_results)

        force_text = rounds >= _MAX_CHAT_TOOL_ROUNDS
        if force_text:
            kwargs.pop("tools", None)  # cap reached: withhold tools to force an answer
        kwargs["messages"] = _fit_context_window(agent, messages)

        response, more = await _call_with_persistent_retries(
            agent,
            lambda: agent._get_client().chat.completions.create(**kwargs),
            "single-round",
            kwargs=kwargs,
        )
        total_retries += more
        choice = response.choices[0]
        if force_text:
            break

    return _prepend_retry_notice(extract_response(choice.message), total_retries)


async def call_llm_auto(
    agent: AgentContext,
    system_prompt: str,
    round_context: str,
    *,
    stream_sink: Optional["StreamSink"] = None,
) -> str:
    """Call the LLM in auto-pentest mode with round context appended."""
    if stream_sink is not None:
        return await call_llm_auto_stream(agent, system_prompt, round_context, stream_sink)

    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(agent.context.get_messages())
    messages.append({"role": "user", "content": round_context})
    messages = _fit_context_window(agent, messages)
    tools = agent._build_openai_tools()

    kwargs = build_chat_completion_kwargs(agent, messages, tools)

    response, retry_attempts = await _call_with_persistent_retries(
        agent,
        lambda: agent._get_client().chat.completions.create(**kwargs),
        "autonomous-loop",
        kwargs=kwargs,
    )

    choice = response.choices[0]
    if choice.message.tool_calls:
        tool_results, skipped_info = await handle_tool_calls_with_results(agent, choice.message)

        executed_tcs = []
        for tc in tool_results:
            if not isinstance(tc, dict) or "tool_call" not in tc:
                import sys

                print(f"[!] Skipping abnormal tool result: {type(tc).__name__} {str(tc)[:100]}", file=sys.stderr)
                continue
            executed_tcs.append(tc["tool_call"])

        assistant_msg = {
            "role": "assistant",
            "content": choice.message.content or "",
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in executed_tcs
            ],
        }
        messages.append(assistant_msg)

        for tool_result in tool_results:
            if isinstance(tool_result, dict) and "tool_call_id" in tool_result:
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_result["tool_call_id"],
                        "content": tool_result.get("content", ""),
                    }
                )

        tool_summary_parts = []
        for tc in executed_tcs:
            try:
                args_str = str(tc.function.arguments)[:200]
            except Exception:
                args_str = "<unreadable>"
            tool_summary_parts.append(f"Called tool: {tc.function.name}({args_str})")
        for tr in tool_results:
            content = tr.get("content", "") if isinstance(tr, dict) else str(tr)
            if len(content) > 1000:
                content = content[:500] + "\n...[omitted]...\n" + content[-500:]
            tool_summary_parts.append(f"Tool result: {content}")
            if (
                isinstance(tr, dict)
                and isinstance(tr.get("structured_content"), dict)
                and tr["structured_content"]
            ):
                structured = json.dumps(tr["structured_content"], ensure_ascii=False)
                if len(structured) > 1000:
                    structured = structured[:500] + "\n...[omitted]...\n" + structured[-500:]
                tool_summary_parts.append(f"Structured result: {structured}")
        if skipped_info:
            tool_summary_parts.append(f"⚠️ Skipped this round: {'; '.join(skipped_info)}")

        try:
            kwargs["messages"] = _fit_context_window(agent, messages)
            response2, second_retry_attempts = await _call_with_persistent_retries(
                agent,
                lambda: agent._get_client().chat.completions.create(**kwargs),
                "tool-summary",
                kwargs=kwargs,
            )
            final_text = extract_response(response2.choices[0].message)
            # 上下文已由 loop_controller L55 / core.py L385 写入，避免重复
            return _prepend_retry_notice(final_text, retry_attempts + second_retry_attempts)
        except Exception as e2:
            error_text = str(e2).lower()
            if _is_non_retriable_llm_error(error_text):
                fallback = _format_tool_results_fallback(tool_results, skipped_info)
                # 同上: 不在此写入上下文
                return fallback
            return f"[tool results processed] continue-analysis error: {e2}"

    return _prepend_retry_notice(extract_response(choice.message), retry_attempts)


# === Stream LLM Call Helpers ===


class _AsyncIterWrapper:
    """Wrap sync iterable as async iterable for unified async for usage.

    OpenAI sync client → sync Stream（需包装后 async for）
    测试 mock / async client → async Stream（直接用 async for）
    """

    def __init__(self, iterable):
        self._iter = iter(iterable)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._iter)
        except StopIteration:
            raise StopAsyncIteration


def _ensure_async_iter(response):
    """返回 async 可迭代对象，兼容 sync 和 async Stream。

    检查顺序：async 可迭代 → sync 可迭代 → 不可迭代返回 None（触发降级）。
    """
    if hasattr(response, "__aiter__"):
        return response
    if hasattr(response, "__iter__"):
        return _AsyncIterWrapper(response)
    return None  # 不是可迭代对象，由调用方走降级路径


def _collect_tool_call_deltas(delta: Any, tool_calls_chunks: list[dict]) -> None:
    """从单个流式 delta 中提取 tool_call 分片，追加到累积列表。

    处理各 provider 的差异：
    - 某些 provider 第一个分片只带 id（function 字段为 None）
    - 某些 provider name 与 arguments 分别在不同分片到达
    - index 缺失/为 None（回退到 0）
    - tc_delta 本身为 None
    """
    tc = getattr(delta, "tool_calls", None)
    if not tc:
        return
    for tc_delta in tc:
        if tc_delta is None:
            continue
        # function 字段在仅含 id 的首个分片中可能为 None
        func = getattr(tc_delta, "function", None)
        if func is not None:
            name = getattr(func, "name", None) or ""
            arguments = getattr(func, "arguments", None) or ""
        else:
            name = ""
            arguments = ""
        index = getattr(tc_delta, "index", None)
        if index is None:
            index = 0
        tool_calls_chunks.append({
            "index": index,
            "id": getattr(tc_delta, "id", None) or "",
            "function": {"name": name, "arguments": arguments},
        })


def _validate_tool_call(tool_call: Any) -> bool:
    """验证聚合后的 tool_call 是否完整可用。

    要求：
    - id 非空（某些 provider 仅在首个分片给出，分片丢失会导致空 id）
    - function.name 非空
    - arguments 为合法 JSON 或空字符串（流式中断会产生截断的不完整 JSON）
    """
    tc_id = getattr(tool_call, "id", None)
    if not tc_id:
        return False
    func = getattr(tool_call, "function", None)
    if func is None or not getattr(func, "name", None):
        return False
    arguments = getattr(func, "arguments", None)
    if arguments in (None, ""):
        return True
    try:
        json.loads(arguments)
        return True
    except (json.JSONDecodeError, TypeError):
        return False


def _build_tool_call(tc_id: str, name: str, arguments: str) -> Any:
    """构造一个 tool_call 对象。

    优先使用 OpenAI 官方 pydantic 类型（生产路径）；导入失败时回退到等价
    轻量对象（仅暴露下游用到的 .id/.type/.function.name/.function.arguments），
    保证组装逻辑可在不安装 openai 的环境中独立测试。
    """
    try:
        from openai.types.chat.chat_completion_message_tool_call import (
            ChatCompletionMessageToolCall,
            Function,
        )

        return ChatCompletionMessageToolCall(
            id=tc_id,
            type="function",
            function=Function(name=name, arguments=arguments),
        )
    except Exception:
        func = type("Function", (), {"name": name, "arguments": arguments})()
        return type("ToolCall", (), {"id": tc_id, "type": "function", "function": func})()


def _assemble_tool_calls(tool_calls_chunks: list[dict]) -> list[Any]:
    """将累积的流式分片按 index 聚合为完整 tool_call 列表。

    跨多个 chunk 分片到达的 id/name/arguments 按 index 对齐拼接。
    聚合后逐个校验，丢弃缺失 id、缺失 name 或 arguments JSON 不完整的调用并记录警告。
    """
    if not tool_calls_chunks:
        return []

    # 按 index 对齐拼接（dict 保持首次出现顺序）
    tc_by_index: dict[int, dict] = {}
    for tc_chunk in tool_calls_chunks:
        idx = tc_chunk["index"]
        if idx not in tc_by_index:
            tc_by_index[idx] = {"id": "", "function": {"name": "", "arguments": ""}}
        tc_by_index[idx]["id"] += tc_chunk["id"]
        tc_by_index[idx]["function"]["name"] += tc_chunk["function"]["name"]
        tc_by_index[idx]["function"]["arguments"] += tc_chunk["function"]["arguments"]

    tool_calls: list[Any] = []
    for tc_data in tc_by_index.values():
        candidate = _build_tool_call(
            tc_data["id"],
            tc_data["function"]["name"],
            tc_data["function"]["arguments"],
        )
        if not _validate_tool_call(candidate):
            print(
                f"[!] Discarding incomplete streamed tool_call: id={tc_data['id']!r} "
                f"name={tc_data['function']['name']!r} "
                f"args={tc_data['function']['arguments'][:80]!r}",
                file=sys.stderr,
                flush=True,
            )
            continue
        tool_calls.append(candidate)

    return tool_calls


async def _consume_stream(
    stream_sink: "StreamSink", _stream: Any
) -> tuple[str, list[dict]]:
    """Consume one streaming completion, emitting tokens to the sink.

    Returns ``(full_text, tool_calls_chunks)`` — the accumulated text (with any
    reasoning wrapped in ``<thinking>``) and the raw tool-call deltas for later
    assembly. Does not call ``on_stream_end``; the caller owns round boundaries.
    """
    full_text = ""
    reasoning_buffer = ""
    tool_calls_chunks: list[dict] = []
    async for chunk in _stream:
        if not (chunk.choices and len(chunk.choices) > 0):
            continue
        delta = chunk.choices[0].delta

        reasoning = getattr(delta, "reasoning_content", None) or ""
        if reasoning:
            reasoning_buffer += reasoning
            stream_sink.on_thinking_token(reasoning)

        content = getattr(delta, "content", None) or ""
        if content:
            if reasoning_buffer:
                full_text += f"<thinking>\n{reasoning_buffer}\n</thinking>\n"
                reasoning_buffer = ""
            stream_sink.on_content_token(content)
            full_text += content

        _collect_tool_call_deltas(delta, tool_calls_chunks)

    if reasoning_buffer:
        full_text += f"<thinking>\n{reasoning_buffer}\n</thinking>\n"
    return full_text, tool_calls_chunks


async def _stream_tool_loop(
    agent: AgentContext,
    messages: list[dict[str, Any]],
    kwargs: dict[str, Any],
    full_text: str,
    tool_calls_chunks: list[dict],
    stream_sink: "StreamSink",
) -> str:
    """Drive the streamed agentic tool loop for single-turn chat.

    Given the first streamed turn's text and tool-call deltas, execute the tools,
    feed the results back, and keep streaming follow-up turns until the model
    answers without a tool call (or the round cap is hit). Returns the final
    streamed text.

    A follow-up round that errors mid-stream is recovered WITHOUT re-running the
    tools: the continuation is retried non-streamed (which carries key rotation
    and the ChatGPT usage-cap → FreeLLMAPI switch); if that also fails, the tool
    results already gathered are summarized as plain text.
    """
    rounds = 0
    while tool_calls_chunks:
        tool_calls = _assemble_tool_calls(tool_calls_chunks)
        if not tool_calls:
            break
        rounds += 1
        for tc in tool_calls:
            stream_sink.on_tool_call(tc.function.name, tc.function.arguments[:200])

        dummy_msg = type("obj", (object,), {"content": full_text, "tool_calls": tool_calls})()
        tool_results, skipped_info = await handle_tool_calls_with_results(agent, dummy_msg)
        executed = _executed_tool_calls(tool_results)
        if not executed:
            break
        for tr in tool_results:
            if isinstance(tr, dict) and "content" in tr:
                preview = str(tr["content"])
                stream_sink.on_tool_result(
                    preview[:200] + ("..." if len(preview) > 200 else "")
                )

        messages.append(_assistant_tool_call_message(full_text, executed))
        _append_tool_result_messages(messages, tool_results)

        force_text = rounds >= _MAX_CHAT_TOOL_ROUNDS
        if force_text:
            kwargs.pop("tools", None)  # cap reached: withhold tools to force an answer
        kwargs["messages"] = _fit_context_window(agent, messages)
        stream_sink.on_status(f"Summarizing... ({_active_backend_label(agent)})")

        try:
            response = agent._get_client().chat.completions.create(**kwargs, stream=True)
            _stream = _ensure_async_iter(response)
            if _stream is None:
                raise ValueError("LLM response is not a valid stream object")
            full_text, tool_calls_chunks = await _consume_stream(stream_sink, _stream)
            stream_sink.on_stream_end()
        except Exception:
            try:
                resp, _ = await _call_with_persistent_retries(
                    agent,
                    lambda: agent._get_client().chat.completions.create(**kwargs),
                    "tool-summary",
                    kwargs=kwargs,
                )
                full_text = extract_response(resp.choices[0].message)
            except Exception:
                full_text = _format_tool_results_fallback(tool_results, skipped_info)
            stream_sink.on_content_token(full_text)
            stream_sink.on_stream_end()
            return full_text

        if force_text:
            break

    return full_text


async def call_llm_stream(
    agent: AgentContext,
    system_prompt: str,
    stream_sink: Optional["StreamSink"] = None,
    *,
    _retried_via_fallback: bool = False,
) -> str:
    """Call the LLM with streaming output.

    Args:
        agent: AgentCore instance
        system_prompt: System prompt
        stream_sink: Output sink for streaming (None = silent)

    Returns:
        Full response text (same as non-streaming version)
    """
    if stream_sink is None:
        stream_sink = _NullSink()

    client = agent._get_client()

    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(agent.context.get_messages())
    messages = _fit_context_window(agent, messages)
    tools = agent._build_openai_tools()

    kwargs = build_chat_completion_kwargs(agent, messages, tools)

    try:
        stream_sink.on_status(f"Thinking... ({_active_backend_label(agent)})")
        response = client.chat.completions.create(**kwargs, stream=True)

        # 自动适配 sync/async Stream（sync Stream 用 _AsyncIterWrapper 包装）
        _stream = _ensure_async_iter(response)
        if _stream is None:
            raise ValueError("LLM response is not a valid stream object")
        full_text, tool_calls_chunks = await _consume_stream(stream_sink, _stream)
        stream_sink.on_stream_end()

        # Tool calls present → run the agentic tool loop (execute, feed results
        # back, keep streaming follow-up turns) so the model reacts to what it
        # read/wrote instead of the raw tool output ending the turn.
        if tool_calls_chunks:
            return await _stream_tool_loop(
                agent, messages, kwargs, full_text, tool_calls_chunks, stream_sink
            )

        return full_text

    except Exception as e:
        # Fallback to non-streaming on streaming-related errors or general failures
        error_text = str(e).lower()

        # ChatGPT usage cap: switch backend and redo this call once, rather
        # than falling through to the "streaming not supported" handling
        # below (which doesn't apply) or re-raising and losing the request.
        if not _retried_via_fallback and _maybe_switch_to_freellmapi_fallback(agent, error_text):
            stream_sink.on_status(f"Retrying... ({_active_backend_label(agent)})")
            return await call_llm_stream(agent, system_prompt, stream_sink, _retried_via_fallback=True)

        streaming_markers = [
            "not supported", "not implemented", "streaming",
            "requires an object with __aiter__",
            "stream is not iterable", "doesn't support",
            "not a valid stream",
        ]
        if any(marker in error_text for marker in streaming_markers):
            # Provider doesn't support streaming or other streaming error, fall back
            pass
        else:
            # Other error, re-raise
            raise

    # Fallback: non-streaming with simulated streaming
    # Use existing call_llm as fallback
    response_fallback, _ = await _call_with_persistent_retries(
        agent,
        lambda: agent._get_client().chat.completions.create(**kwargs),
        "single-round",
        kwargs=kwargs,
    )

    # 降级到非流式 call_llm（有 retry + tool_calls 处理），行为一致
    return await call_llm(agent, system_prompt)


async def call_llm_auto_stream(
    agent: AgentContext,
    system_prompt: str,
    round_context: str,
    stream_sink: Optional["StreamSink"] = None,
    *,
    _retried_via_fallback: bool = False,
) -> str:
    """Call the LLM in auto-pentest mode with streaming output.

    Args:
        agent: AgentCore instance
        system_prompt: System prompt
        round_context: Round context for auto mode
        stream_sink: Output sink for streaming (None = silent)

    Returns:
        Full response text
    """
    if stream_sink is None:
        stream_sink = _NullSink()

    client = agent._get_client()

    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(agent.context.get_messages())
    messages.append({"role": "user", "content": round_context})
    messages = _fit_context_window(agent, messages)
    tools = agent._build_openai_tools()

    kwargs = build_chat_completion_kwargs(agent, messages, tools)

    try:
        # First LLM call with streaming
        stream_sink.on_status(f"Thinking... ({_active_backend_label(agent)})")
        response = client.chat.completions.create(**kwargs, stream=True)

        full_text = ""
        reasoning_buffer = ""
        tool_calls_chunks: list[dict] = []

        # 自动适配 sync/async Stream
        _stream = _ensure_async_iter(response)
        if _stream is None:
            raise ValueError("LLM response is not a valid stream object")
        async for chunk in _stream:
            if chunk.choices and len(chunk.choices) > 0:
                delta = chunk.choices[0].delta

                # Handle reasoning_content
                reasoning = getattr(delta, "reasoning_content", None) or ""
                if reasoning:
                    reasoning_buffer += reasoning
                    stream_sink.on_thinking_token(reasoning)

                # Handle content
                content = getattr(delta, "content", None) or ""
                if content:
                    if reasoning_buffer:
                        full_text += f"<thinking>\n{reasoning_buffer}\n</thinking>\n"
                        reasoning_buffer = ""
                    stream_sink.on_content_token(content)
                    full_text += content

                # Handle tool_calls
                _collect_tool_call_deltas(delta, tool_calls_chunks)

        stream_sink.on_stream_end()

        # Flush reasoning（重置缓冲，避免泄漏到第二轮总结流导致重复输出）
        if reasoning_buffer:
            full_text += f"<thinking>\n{reasoning_buffer}\n</thinking>\n"
            reasoning_buffer = ""

        # Check if we have tool calls
        choice_dummy = type("obj", (object,), {"message": type("obj", (object,), {
            "content": full_text,
            "tool_calls": None,
        })()})()

        # Reconstruct message for tool call handling
        # We need to check if there are tool calls from the accumulated chunks
        if tool_calls_chunks:
            tool_calls = _assemble_tool_calls(tool_calls_chunks)

            if tool_calls:
                # [修改] 流式聚合后 tool_calls 仅存在于 delta 片段中, 需回填到聚合消息对象以便后续处理
                # Patch the dummy message with actual tool calls
                choice_dummy.message.tool_calls = tool_calls
                # Execute tool calls
                for tc in tool_calls:
                    stream_sink.on_tool_call(tc.function.name, tc.function.arguments[:200])

                tool_results, skipped_info = await handle_tool_calls_with_results(agent, choice_dummy.message)

                for tr in tool_results:
                    if isinstance(tr, dict) and "content" in tr:
                        content = tr["content"]
                        if len(content) > 200:
                            content = content[:200] + "..."
                        stream_sink.on_tool_result(content)

                # Continue with the messages including tool results
                assistant_msg = {
                    "role": "assistant",
                    "content": full_text,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in tool_calls
                    ],
                }
                messages.append(assistant_msg)

                for tool_result in tool_results:
                    if isinstance(tool_result, dict) and "tool_call_id" in tool_result:
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_result["tool_call_id"],
                            "content": tool_result.get("content", ""),
                        })

                # Second LLM call (streaming) for summary
                kwargs["messages"] = _fit_context_window(agent, messages)
                stream_sink.on_status(f"Summarizing... ({_active_backend_label(agent)})")

                try:
                    response2 = client.chat.completions.create(**kwargs, stream=True)
                    full_text = ""

                    _stream2 = _ensure_async_iter(response2)
                    if _stream2 is None:
                        raise ValueError("LLM response is not a valid stream object")
                    async for chunk in _stream2:
                        if chunk.choices and len(chunk.choices) > 0:
                            delta = chunk.choices[0].delta
                            reasoning = getattr(delta, "reasoning_content", None) or ""
                            if reasoning:
                                reasoning_buffer += reasoning
                                stream_sink.on_thinking_token(reasoning)

                            content = getattr(delta, "content", None) or ""
                            if content:
                                if reasoning_buffer:
                                    full_text += f"<thinking>\n{reasoning_buffer}\n</thinking>\n"
                                    reasoning_buffer = ""
                                stream_sink.on_content_token(content)
                                full_text += content

                    if reasoning_buffer:
                        full_text += f"<thinking>\n{reasoning_buffer}\n</thinking>\n"

                    # 上下文由 loop_controller L55 写入，不在此重复添加
                    stream_sink.on_stream_end()
                    return full_text

                except Exception as e2:
                    error_text = str(e2).lower()
                    if not _retried_via_fallback and _maybe_switch_to_freellmapi_fallback(
                        agent, error_text
                    ):
                        stream_sink.on_status(f"Retrying... ({_active_backend_label(agent)})")
                        return await call_llm_auto_stream(
                            agent,
                            system_prompt,
                            round_context,
                            stream_sink,
                            _retried_via_fallback=True,
                        )
                    if _is_non_retriable_llm_error(error_text):
                        fallback = _format_tool_results_fallback(tool_results, skipped_info)
                        # 同上: 不在此写入上下文
                        return fallback
                    return f"[tool results processed] continue-analysis error: {e2}"

        # 上下文已由调用方写入，不在此重复添加
        return full_text

    except (NotImplementedError, ValueError, Exception) as e:
        error_text = str(e).lower()

        if not _retried_via_fallback and _maybe_switch_to_freellmapi_fallback(agent, error_text):
            stream_sink.on_status(f"Retrying... ({_active_backend_label(agent)})")
            return await call_llm_auto_stream(
                agent, system_prompt, round_context, stream_sink, _retried_via_fallback=True
            )

        if not any(
            marker in error_text
            for marker in [
                "not supported", "not implemented", "streaming",
            ]
        ):
            raise

    # Fallback to non-streaming
    return await call_llm_auto(agent, system_prompt, round_context)


# === Stream Output Protocol ===


@runtime_checkable
class StreamSink(Protocol):
    """输出流接收器抽象。

    LLM 调用层通过此接口将输出定向到不同目标（CLI/Web/静默）。
    放在 llm_client.py 中符合 CONTRIBUTING.md 的模块放置原则。
    """

    def on_status(self, message: str) -> None:
        """显示状态提示（如 "Thinking..."）。"""
        ...

    def on_thinking_token(self, token: str) -> None:
        """接收思考过程的 token（可选择是否显示）。"""
        ...

    def on_content_token(self, token: str) -> None:
        """接收正文 token。"""
        ...

    def on_tool_call(self, tool_name: str, args: str) -> None:
        """显示工具调用提示。"""
        ...

    def on_tool_result(self, result_summary: str) -> None:
        """显示工具结果摘要。"""
        ...

    def on_stream_end(self) -> None:
        """流式结束回调（换行/清理）。"""
        ...


class _NullSink:
    """空实现，确保无 sink 时不产生任何输出。"""

    def on_status(self, message: str) -> None:
        pass

    def on_thinking_token(self, token: str) -> None:
        pass

    def on_content_token(self, token: str) -> None:
        pass

    def on_tool_call(self, tool_name: str, args: str) -> None:
        pass

    def on_tool_result(self, result_summary: str) -> None:
        pass

    def on_stream_end(self) -> None:
        pass
