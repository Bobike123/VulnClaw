"""Agent built-in tools and OpenAI tool schema helpers."""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext

from urllib.parse import urlparse

from vulnclaw.agent.constraint_policy import validate_tool_action
from vulnclaw.agent.file_tools import (
    execute_file_edit,
    execute_file_read,
    execute_file_write,
    execute_list_dir,
)
from vulnclaw.agent.network_scan import (
    attach_network_scan_to_session,
    build_nmap_command,
    build_nmap_plan,
    deescalate_nmap_argv,
    nmap_failure_needs_deescalation,
    nmap_has_raw_socket_access,
    parse_nmap_xml_structured,
    summarize_network_scan,
    target_is_private_literal,
    without_privileged_nmap_args,
)
from vulnclaw.intel.tools import (
    INTEL_TOOL_NAMES,
    dispatch_intel_tool,
    intel_tool_schemas,
)
from vulnclaw.safety.redaction import redact
from vulnclaw.safety.sandbox import precheck as sandbox_precheck
from vulnclaw.safety.sandbox import run_sandboxed

BLOCKED_PATTERNS: list[str] = [
    r"os\.\s*system\s*\(",
    r"subprocess\.\s*Popen\s*\(",
    r"shutil\.\s*rmtree\s*\(",
    r"__import__\s*\(\s*['\"]os['\"]",
    r"open\s*\(\s*['\"].*vulnclaw.*config",
    r"open\s*\(\s*['\"].*\.vulnclaw",
]

RESERVED_IP_RANGES: list[tuple[str, str, str]] = [
    ("198.18.0.0", "198.19.255.255", "RFC 2544 benchmark address"),
    ("10.0.0.0", "10.255.255.255", "RFC 1918 private address"),
    ("172.16.0.0", "172.31.255.255", "RFC 1918 private address"),
    ("192.168.0.0", "192.168.255.255", "RFC 1918 private address"),
    ("127.0.0.0", "127.255.255.255", "RFC 1122 loopback address"),
    ("169.254.0.0", "169.254.255.255", "RFC 3927 link-local"),
    ("0.0.0.0", "0.255.255.255", "RFC 1122 current network"),
    ("224.0.0.0", "239.255.255.255", "RFC 5771 multicast address"),
    ("240.0.0.0", "255.255.255.255", "RFC 1112 reserved address"),
]

# ── Central scope enforcement ───────────────────────────────────────────
# Every target-directed tool call funnels through execute_mcp_tool, so this is
# the single chokepoint where engagement scope is enforced (deny-by-default for
# anything beyond localhost). See vulnclaw.safety.scope for the model.


def _get_scope_validator(agent: AgentContext):
    """Build (and cache) the agent's ScopeValidator from its config."""
    cached = getattr(agent, "_scope_validator", None)
    if cached is not None:
        return cached
    config = getattr(agent, "config", None)
    if config is None:
        return None
    try:
        from vulnclaw.safety.scope import ScopeValidator

        validator = ScopeValidator.from_config(config)
    except Exception:
        return None
    try:
        agent._scope_validator = validator
    except Exception:
        pass
    return validator


def extract_scope_targets(tool_name: str, args: dict[str, Any]) -> list[str]:
    """Return the target URLs/hosts a given tool invocation would contact."""
    name = (tool_name or "").strip().lower()
    out: list[str] = []

    def _add(value: Any) -> None:
        if value:
            out.append(str(value))

    if name in ("fetch", "js_recon", "dir_enum"):
        _add(args.get("url"))
    elif name == "nmap_scan":
        _add(args.get("target"))
    elif name == "unauth_test":
        _add(args.get("base_url"))
        for ep in args.get("endpoints") or []:
            if isinstance(ep, str) and "://" in ep:
                out.append(ep)
    elif name in ("subdomain_enum", "space_search"):
        _add(args.get("domain"))
    elif name == "brute_force_login":
        _add(args.get("url"))
        _add(args.get("submit_action"))
    elif name == "python_execute":
        for match in re.findall(r"https?://[^\s'\"`)]+", str(args.get("code", "") or "")):
            out.append(match)
    else:
        # Unknown / MCP tool — best-effort check of the common target keys.
        for key in ("url", "target", "base_url", "host"):
            _add(args.get(key))
    return out


def _enforce_scope(agent: AgentContext, tool_name: str, args: dict[str, Any]) -> str | None:
    """Return an out-of-scope error when a tool would contact an out-of-scope target."""
    validator = _get_scope_validator(agent)
    if validator is None or not getattr(validator, "enforce", False):
        return None
    for target in extract_scope_targets(tool_name, args):
        decision = validator.check_url(target) if "://" in target else validator.check_host(target)
        if not decision.allowed:
            session = getattr(agent, "session_state", None)
            if session is not None and hasattr(session, "add_constraint_violation_event"):
                session.add_constraint_violation_event(
                    source="tool",
                    action="scope",
                    tool_name=tool_name,
                    code="scope_denied",
                    severity="high",
                    summary=decision.error_message(),
                    detail=decision.reason,
                )
            return decision.error_message()
    return None


def _get_approval_gate(agent: AgentContext):
    """Build (and cache) the agent's ApprovalGate from its config."""
    cached = getattr(agent, "_approval_gate", None)
    if cached is not None:
        return cached
    config = getattr(agent, "config", None)
    if config is None:
        return None
    try:
        from vulnclaw.safety.approval import ApprovalGate

        gate = ApprovalGate.from_config(config)
    except Exception:
        return None
    try:
        agent._approval_gate = gate
    except Exception:
        pass
    return gate


def _get_audit_logger(agent: AgentContext):
    """Build (and cache) the agent's AuditLogger; log session_start on first use.

    Returns None when auditing is disabled or unavailable so callers can skip
    logging cheaply. The logger is the single place tool calls, denials, approval
    decisions, and budget stops are recorded for the session's tamper-evident log.
    """
    cached = getattr(agent, "_audit_logger", None)
    if cached is not None:
        return None if cached is False else cached
    config = getattr(agent, "config", None)
    if config is None:
        return None
    audit_cfg = getattr(config, "audit", None)
    if audit_cfg is not None and not getattr(audit_cfg, "enabled", True):
        try:
            agent._audit_logger = False  # sentinel: disabled, don't rebuild
        except Exception:
            pass
        return None
    try:
        from vulnclaw.safety.audit import AuditLogger

        session = getattr(agent, "session_state", None)
        target = str(getattr(session, "target", "") or "")
        started = str(getattr(session, "started_at", "") or "")
        session_id = f"{target or 'session'}-{started}" if started else (target or "session")
        logger = AuditLogger.from_config(config, session_id)
        llm = getattr(config, "llm", None)
        logger.session_start(
            target=target,
            model=str(getattr(llm, "model", "") or ""),
            provider=str(getattr(llm, "provider", "") or ""),
        )
    except Exception:
        return None
    try:
        agent._audit_logger = logger
    except Exception:
        pass
    return logger


def _audit(agent: AgentContext, method: str, **kwargs) -> None:
    """Best-effort audit call; never raises into the tool path."""
    logger = _get_audit_logger(agent)
    if logger is None:
        return
    try:
        getattr(logger, method)(**kwargs)
    except Exception:
        pass


def _scope_allows(validator, target: str) -> bool:
    try:
        decision = validator.check_url(target) if "://" in target else validator.check_host(target)
        return bool(decision.allowed)
    except Exception:
        return False


def _enforce_approval(agent: AgentContext, tool_name: str, args: dict[str, Any]) -> str | None:
    """Gate high-risk actions: risky-skill enable switch, scope phase/feature, then approval.

    Returns a user-facing block message when the action is disallowed, else None.
    """
    config = getattr(agent, "config", None)
    if config is None:
        return None
    try:
        from vulnclaw.agent.constraint_policy import infer_tool_action
        from vulnclaw.safety.approval import classify_risk, required_capability
    except Exception:
        return None

    action = infer_tool_action(tool_name, args or {})
    targets = extract_scope_targets(tool_name, args)
    target = targets[0] if targets else ""
    request = classify_risk(tool_name, args, target=target, action=action)
    if request is None:
        return None  # not a high-risk action

    session = getattr(agent, "session_state", None)

    def _event(code: str, summary: str) -> None:
        if session is not None and hasattr(session, "add_constraint_violation_event"):
            session.add_constraint_violation_event(
                source="tool",
                action=request.action,
                tool_name=tool_name,
                code=code,
                severity="high",
                summary=summary,
                detail=request.reason,
            )

    # 1. Risky-skill enable switch (default-deny).
    cap = required_capability(request.action)
    risky_cfg = getattr(config, "risky_tools", None)
    if cap and not getattr(risky_cfg, cap, False):
        msg = (
            f"[risky_tool_disabled] '{request.action}' is disabled by default. Enable "
            f"risky_tools.{cap} for an authorized engagement (scope + approval still apply)."
        )
        _event("risky_tool_disabled", msg)
        return msg

    # 2. Scope phase / feature gate.
    validator = _get_scope_validator(agent)
    if validator is not None:
        if request.action in ("exploit", "post_exploitation") and not validator.check_phase(
            "exploit_validation"
        ):
            msg = (
                "[scope_violation] exploitation not permitted: scope does not allow the "
                "'exploit_validation' phase. Add it to allowed_phases in your scope file."
            )
            _event("scope_phase_denied", msg)
            return msg
        if request.action == "osint" and not validator.is_feature_allowed("osint"):
            msg = (
                "[scope_violation] OSINT not permitted: enable features.osint in your scope "
                "file for authorized public-target OSINT."
            )
            _event("scope_feature_denied", msg)
            return msg
        request.scope_match = "in-scope" if _scope_allows(validator, target) else "unverified"

    # 3. Human approval.
    gate = _get_approval_gate(agent)
    if gate is None:
        return None
    decision = gate.evaluate(request)
    if decision.allowed:
        _event("approval_granted", f"approved: {request.action} via {tool_name}")
        return None
    _event("approval_dry_run" if decision.is_dry_run else "approval_denied", decision.message())
    return decision.message()


async def execute_mcp_tool(agent: AgentContext, tool_name: str, args: dict[str, Any]) -> str:
    """Execute a tool call via MCP manager or built-in tools."""
    session = getattr(agent, "session_state", None)
    constraints = getattr(session, "task_constraints", None)
    if constraints is not None:
        tool_violation = validate_tool_action(tool_name, args, constraints)
        if tool_violation is not None:
            if session is not None and hasattr(session, "add_constraint_violation_event"):
                from vulnclaw.agent.constraint_policy import infer_tool_action

                session.add_constraint_violation_event(
                    source="tool",
                    action=infer_tool_action(tool_name, args),
                    tool_name=tool_name,
                    code="tool_action_blocked",
                    severity="high",
                    summary=tool_violation,
                    detail=json.dumps(args, ensure_ascii=False)[:500],
                )
            return f"[constraint_violation] {tool_violation}"

    if tool_name in INTEL_TOOL_NAMES:
        return await dispatch_intel_tool(agent, tool_name, args)

    audit_target = ""
    try:
        _at = extract_scope_targets(tool_name, args)
        audit_target = _at[0] if _at else ""
    except Exception:
        audit_target = ""

    # Central scope gate: no target-directed tool runs against an out-of-scope
    # host. This is the single chokepoint every tool dispatch passes through.
    scope_violation = _enforce_scope(agent, tool_name, args)
    if scope_violation is not None:
        _audit(agent, "denied", action="scope", reason=scope_violation,
               target=audit_target, tool=tool_name)
        return scope_violation

    # Human-approval gate: risky skills are default-deny and need approval.
    approval_block = _enforce_approval(agent, tool_name, args)
    if approval_block is not None:
        _audit(agent, "denied", action="approval", reason=approval_block,
               target=audit_target, tool=tool_name)
        return approval_block

    # Persistent-mode safety budget / emergency stop: once a duration/cycle/
    # tool-call ceiling is hit — or an operator drops the emergency-stop file —
    # no further tool calls are dispatched. Inert outside persistent runs
    # (agent._budget is only set for the duration of persistent_pentest).
    budget = getattr(agent, "_budget", None)
    if budget is not None:
        reason = budget.check()
        if reason is not None:
            _audit(agent, "denied", action="budget", reason=reason,
                   target=audit_target, tool=tool_name)
            return budget.status().message()
        budget.record_tool_call()

    # Passed every safety gate — record what was allowed to run.
    _audit(agent, "tool_call", tool=tool_name, target=audit_target, status="dispatched")

    if tool_name == "python_execute":
        return await execute_python(agent, args)

    if tool_name == "file_read":
        return await execute_file_read(agent, args)

    if tool_name == "file_write":
        return await execute_file_write(agent, args)

    if tool_name == "file_edit":
        return await execute_file_edit(agent, args)

    if tool_name == "list_dir":
        return await execute_list_dir(agent, args)

    if tool_name == "load_skill_reference":
        try:
            from vulnclaw.skills.loader import load_skill_reference

            skill_name = args.get("skill_name", "")
            ref_name = args.get("reference_name", "")
            content = load_skill_reference(skill_name, ref_name)
            if content:
                return content
            return f"[!] Reference doc not found: {skill_name}/{ref_name}"
        except Exception as e:
            return f"[!] Error loading reference doc: {e}"

    if tool_name == "nmap_scan":
        return await execute_nmap(agent, args)

    if tool_name == "crypto_decode":
        try:
            from vulnclaw.skills.crypto_tools import execute as crypto_execute

            operation = args.get("operation", "")
            input_str = args.get("input", "")
            kwargs: dict[str, Any] = {}
            for key in ("key", "iv", "shift", "secret", "header", "algorithm"):
                if key in args and args[key]:
                    kwargs[key] = args[key]
                    if key == "shift":
                        kwargs[key] = int(args[key])
            result = crypto_execute(operation=operation, input_str=input_str, **kwargs)
            if result.get("success"):
                return f"[✓] {operation} result:\n{result['result']}"
            return f"[!] {operation} failed: {result.get('error', 'unknown error')}"
        except Exception as e:
            return f"[!] Crypto tool execution error: {e}"

    if tool_name == "brute_force_login":
        return await execute_brute_force(agent, args)

    if tool_name in {"space_search", "subdomain_enum", "js_recon", "dir_enum", "unauth_test"}:
        from vulnclaw.agent import recon_tools

        dispatch = {
            "space_search": recon_tools.execute_space_search,
            "subdomain_enum": recon_tools.execute_subdomain_enum,
            "js_recon": recon_tools.execute_js_recon,
            "dir_enum": recon_tools.execute_dir_enum,
            "unauth_test": recon_tools.execute_unauth_test,
        }
        try:
            return await dispatch[tool_name](agent, args)
        except Exception as e:
            return f"[!] Tool execution error ({tool_name}): {e}"

    if not agent.mcp_manager:
        return f"[!] MCP manager not initialized; cannot run tool: {tool_name}"

    try:
        result = await agent.mcp_manager.call_tool(tool_name, args)
        if isinstance(result, dict):
            if result.get("ok", False):
                content = result.get("content")
                structured = result.get("structured_content")
                summary_parts: list[str] = []
                if content is not None:
                    summary_parts.append(str(content))
                if isinstance(structured, dict) and structured:
                    summary_parts.append(
                        f"[structured] {json.dumps(structured, ensure_ascii=False)}"
                    )
                if summary_parts:
                    return "\n".join(summary_parts)
                return f"[tool:{tool_name}] completed"

            message = str(result.get("message") or "")
            suggestion = str(result.get("suggestion") or "")
            error_type = str(result.get("error_type") or "error")
            if suggestion:
                return f"[{error_type}] {message}\n[suggestion] {suggestion}".strip()
            return f"[{error_type}] {message}".strip()

        text = str(result)
        if text.strip() in ("undefined", "null", "None"):
            return f"[!] Tool {tool_name} returned an empty result (undefined); the call may have failed"
        return text
    except Exception as e:
        return f"[!] Tool execution error ({tool_name}): {e}"


def enforce_port_constraints(agent: AgentContext, ports: list[int], *, target: str = "") -> str | None:
    """Return a user-facing violation message when requested ports are out of scope."""
    session = getattr(agent, "session_state", None)
    constraints = getattr(session, "task_constraints", None)
    if constraints is None or constraints.is_empty():
        return None

    if constraints.allowed_ports:
        disallowed = [port for port in ports if port not in constraints.allowed_ports]
        if disallowed:
            allowed = ", ".join(str(p) for p in constraints.allowed_ports)
            denied = ", ".join(str(p) for p in disallowed)
            suffix = f" for target {target}" if target else ""
            return f"[constraint_violation] Port(s) {denied} are outside allowed scope [{allowed}]{suffix}."

    blocked = [port for port in ports if port in constraints.blocked_ports]
    if blocked:
        denied = ", ".join(str(p) for p in blocked)
        suffix = f" for target {target}" if target else ""
        return f"[constraint_violation] Port(s) {denied} are blocked by task constraints{suffix}."

    return None


def enforce_host_path_constraints(
    agent: AgentContext, *, host: str = "", path: str = "", target: str = ""
) -> str | None:
    """Return a user-facing violation when host/path are out of scope."""
    session = getattr(agent, "session_state", None)
    constraints = getattr(session, "task_constraints", None)
    if constraints is None or constraints.is_empty():
        return None

    if constraints.allowed_hosts and host and host not in constraints.allowed_hosts:
        allowed = ", ".join(constraints.allowed_hosts)
        return f"[constraint_violation] Host {host} is outside allowed scope [{allowed}] for target {target or host}."

    if host and host in constraints.blocked_hosts:
        return f"[constraint_violation] Host {host} is blocked by task constraints for target {target or host}."

    if constraints.allowed_paths and path and path not in constraints.allowed_paths:
        allowed = ", ".join(constraints.allowed_paths)
        return f"[constraint_violation] Path {path} is outside allowed scope [{allowed}] for target {target or host}."

    if path and path in constraints.blocked_paths:
        return f"[constraint_violation] Path {path} is blocked by task constraints for target {target or host}."

    return None


def infer_ports_from_nmap_args(args: dict[str, Any]) -> list[int]:
    """Infer concrete target ports from nmap arguments for constraint checks."""
    custom_ports = str(args.get("ports", "") or "").strip()
    scan_type = str(args.get("scan_type", "top_ports") or "top_ports")

    if custom_ports:
        ports: list[int] = []
        for chunk in custom_ports.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                start_text, end_text = chunk.split("-", 1)
                try:
                    start = int(start_text)
                    end = int(end_text)
                except ValueError:
                    continue
                if 0 < start <= end <= 65535:
                    ports.extend(range(start, end + 1))
                continue
            try:
                port = int(chunk)
            except ValueError:
                continue
            if 0 < port <= 65535:
                ports.append(port)
        return sorted(set(ports))

    if scan_type == "top_ports":
        return []
    return []


def infer_port_from_url(url: str) -> int | None:
    """Infer request port from URL."""
    try:
        parsed = urlparse(url)
    except Exception:
        return None
    if parsed.port:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None


def build_openai_tools(mcp_manager: Any) -> list[dict[str, Any]]:
    """Build OpenAI function calling schema from MCP tools + built-in tools."""
    tools: list[dict[str, Any]] = []

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "load_skill_reference",
                "description": "Load a specific Skill's reference doc for detailed pentest methodology, workflows, or command references. Use this tool when the system prompt mentions 'available reference docs'.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "skill_name": {
                            "type": "string",
                            "description": "Skill name, e.g. client-reverse, web-security-advanced, ai-mcp-security, intranet-pentest-advanced, pentest-tools, rapid-checklist, crypto-toolkit, ctf-web, ctf-crypto, ctf-misc, osint-recon, secknowledge-skill",
                        },
                        "reference_name": {
                            "type": "string",
                            "description": "Reference doc filename, e.g. 02-client-api-reverse-and-burp.md, web-injection.md, encoding-cheatsheet.md",
                        },
                    },
                    "required": ["skill_name", "reference_name"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "python_execute",
                "description": (
                    "Execute a Python code snippet. Use for: building complex HTTP requests and parsing responses, "
                    "encoding conversion and data processing, batch-testing different payloads, comparing response diffs, "
                    "performing math, etc. Code runs in a restricted environment with a 30-second timeout. "
                    "Preinstalled libs: requests, beautifulsoup4, pycryptodome, base64, json, re, etc. "
                    "Important: use this tool to build HTTP requests instead of guessing the response content."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "The Python code to run. Multi-line supported; may import the standard library and requests/bs4, etc.",
                        },
                        "purpose": {
                            "type": "string",
                            "description": "Brief statement of purpose (for the audit log), e.g. 'build an HTTP request to test loose-comparison bypass'",
                        },
                    },
                    "required": ["code"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "file_read",
                "description": (
                    "Read a file from the directory VulnClaw was launched in (your project/workbench dir, "
                    "not the pentest target). Use for reading source code, configs, PoC scripts, previous "
                    "reports, wordlists, etc. Paths are relative to the launch directory; absolute paths "
                    "outside it are refused."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path, relative to the launch directory"},
                        "offset": {"type": "integer", "description": "Line number to start reading from (0-based, optional)"},
                        "limit": {"type": "integer", "description": "Max number of lines to read from offset (optional)"},
                    },
                    "required": ["path"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "file_write",
                "description": (
                    "Create or overwrite a file in the directory VulnClaw was launched in (e.g. save a PoC "
                    "script, exploit payload, or draft report to disk). Creates parent directories as needed. "
                    "Paths outside the launch directory are refused."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path, relative to the launch directory"},
                        "content": {"type": "string", "description": "Full file content to write"},
                    },
                    "required": ["path", "content"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "file_edit",
                "description": (
                    "Make a targeted edit to an existing file in the launch directory by replacing an exact "
                    "string match. old_string must match exactly (including whitespace) and, by default, "
                    "uniquely — include enough surrounding context to disambiguate, or pass replace_all."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path, relative to the launch directory"},
                        "old_string": {"type": "string", "description": "Exact text to find and replace"},
                        "new_string": {"type": "string", "description": "Replacement text"},
                        "replace_all": {
                            "type": "boolean",
                            "description": "Replace every occurrence instead of requiring a unique match (default false)",
                        },
                    },
                    "required": ["path", "old_string", "new_string"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "list_dir",
                "description": (
                    "List files and subdirectories at a path inside the launch directory (default: the "
                    "launch directory itself). Non-recursive."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Directory path, relative to the launch directory (default: '.')",
                        },
                    },
                    "required": [],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "crypto_decode",
                "description": (
                    "Encoding/decoding and crypto tool. Use it for base64/hex/URL/HTML/Unicode-encoded strings, "
                    "computing hashes, decrypting AES/DES, parsing JWT, and similar. "
                    "Important: do not guess decoding results; always use this tool for accuracy. "
                    "Supported operations: base64_encode/decode, base32_encode/decode, base58_encode/decode, "
                    "hex_encode/decode, url_encode/decode, html_encode/decode, unicode_encode/decode, "
                    "rot13_encode/decode, caesar_encode/decode, morse_encode/decode, "
                    "md5_hash, sha1_hash, sha256_hash, sha512_hash, "
                    "aes_encrypt/decrypt, jwt_decode/encode, auto_decode"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "operation": {"type": "string", "description": "Operation name"},
                        "input": {
                            "type": "string",
                            "description": "The input string to process (text to encode/decode/hash/encrypt)",
                        },
                        "key": {
                            "type": "string",
                            "description": "Encryption/decryption key (required for AES/DES, 16/24/32 bytes)",
                        },
                        "iv": {"type": "string", "description": "AES initialization vector (16 bytes, optional)"},
                        "shift": {
                            "type": "integer",
                            "description": "Caesar cipher shift (default 3; if omitted when decoding, brute-forces all shifts)",
                        },
                        "secret": {"type": "string", "description": "JWT signing key"},
                    },
                    "required": ["operation", "input"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "nmap_scan",
                "description": (
                    "nmap network port scanner. During recon, discovers a target's open ports, service versions, and OS fingerprints.\n"
                    "Usage examples:\n"
                    "  Scan common ports: scan_type=top_ports, target=1.2.3.4\n"
                    "  SYN scan: scan_type=syn, target=1.2.3.4 (requires admin privileges)\n"
                    "  Service version detection: scan_type=service, target=1.2.3.4\n"
                    "  Vulnerability scan: scan_type=vuln, target=1.2.3.4\n"
                    "  Full scan: scan_type=full, target=1.2.3.4\n"
                    "Prefer nmap_scan over building a socket scan with python_execute; nmap is more capable and accurate."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target IP address or domain (required), e.g. 192.168.1.1 or scanme.nmap.org",
                        },
                        "scan_type": {
                            "type": "string",
                            "description": "Scan type: top_ports/syn/tcp/service/os/vuln/full",
                        },
                        "ports": {
                            "type": "string",
                            "description": "Specific ports or range (optional), e.g. 80,443,8080 or 1-1000",
                        },
                        "timing": {
                            "type": "integer",
                            "description": "Timing template 0-5 (default 4); higher is faster but easier to detect",
                        },
                        "profile": {
                            "type": "string",
                            "description": "Optional network scan profile: adaptive/fast/thorough/stealth. The profile adjusts ports, timing, service probes, and safe scripts together.",
                        },
                    },
                    "required": ["target"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "brute_force_login",
                "description": (
                    "Password brute-force against a login form. Automatically manages the session cookie, "
                    "extracts and refreshes the CSRF token, and decides login success/failure. "
                    "Completes all password attempts in a single call and returns the result for each password."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Login page URL",
                        },
                        "username_field": {
                            "type": "string",
                            "description": "Username field name, e.g. 'username'",
                        },
                        "password_field": {
                            "type": "string",
                            "description": "Password field name, e.g. 'password'",
                        },
                        "csrf_field": {
                            "type": "string",
                            "description": "CSRF token field name, e.g. 'user_token'",
                        },
                        "username": {
                            "type": "string",
                            "description": "Username to brute-force",
                        },
                        "passwords": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of passwords to try (max 20)",
                        },
                        "success_keyword": {
                            "type": "string",
                            "description": "Keyword that appears on success, e.g. 'Welcome', 'Dashboard'",
                        },
                        "failure_keyword": {
                            "type": "string",
                            "description": "Keyword that appears on failure, e.g. 'Login failed'",
                        },
                        "submit_action": {
                            "type": "string",
                            "description": "Form submission target URL (optional; if omitted, taken from the form's action attribute)",
                        },
                        "extra_data": {
                            "type": "object",
                            "description": "Extra form fields, e.g. {\"Login\": \"Login\"}",
                        },
                    },
                    "required": ["url", "password_field", "passwords"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "space_search",
                "description": (
                    "Attack-surface asset search (FOFA/Hunter/Quake/Shodan/ZoomEye/0.zone). "
                    "During recon, passively discovers target assets, IPs, ports, subdomains, titles, and component fingerprints without touching the target directly. "
                    "Given a domain, builds each engine's domain query automatically; you may also pass full query syntax. "
                    "With engine=all, queries every engine that has a configured key concurrently."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "engine": {
                            "type": "string",
                            "description": "fofa/hunter/quake/shodan/zoomeye/zerozone/all; default fofa",
                        },
                        "query": {
                            "type": "string",
                            "description": "Engine-native query syntax, e.g. 'domain=\"x.com\"', 'app=\"Struts2\"' (optional)",
                        },
                        "domain": {
                            "type": "string",
                            "description": "Target root domain; builds each engine's domain query automatically (used when query is not given)",
                        },
                        "size": {"type": "integer", "description": "Number of results to return; default 100"},
                    },
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "subdomain_enum",
                "description": (
                    "Subdomain enumeration. First passively aggregates via configured asset-search engines, then DNS-resolves a small built-in wordlist, "
                    "and returns a deduplicated list of live subdomains. Prefer this over writing your own brute-force in python_execute."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Root domain, e.g. nju.edu.cn"},
                        "brute": {
                            "type": "boolean",
                            "description": "Whether to enable the built-in DNS wordlist brute-force (default true)",
                        },
                    },
                    "required": ["domain"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "js_recon",
                "description": (
                    "JavaScript recon (inspired by URLFinder). Fetches the target page and all referenced .js files, "
                    "extracting API endpoints/paths, related domains, absolute URLs, and likely hardcoded secrets (AK/SK, tokens, JWTs, private keys, etc.). "
                    "By default auto_probe=true: probes each collected same-origin endpoint for unauthorized access (safe GET only, skipping destructive endpoints). "
                    "Prefer it during recon so later testing is driven by real extracted endpoints rather than guessed ones."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target page URL"},
                        "max_js": {
                            "type": "integer",
                            "description": "Maximum number of JS files to fetch (default 30)",
                        },
                        "auto_probe": {
                            "type": "boolean",
                            "description": "Whether to auto-probe collected endpoints for unauthorized access (default true)",
                        },
                        "auth_header": {
                            "type": "string",
                            "description": "Optional auth header for a differential check, e.g. 'Authorization: Bearer xxx', to verify whether data is reachable without a token",
                        },
                    },
                    "required": ["url"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "unauth_test",
                "description": (
                    "Unauthorized-access probe. Requests each of a set of endpoints (usually collected by js_recon) without credentials, "
                    "and judges by status code / response body / content type: ⚠ likely unauthorized (returns data) / ✓ auth-blocked / ↪ redirect to login / — not found. "
                    "When auth_header is given, does a with/without-token differential; if the same data is reachable without a token, it flags 🔴 confirmed unauthorized. "
                    "Strictly read-only: sends safe GETs only, skips destructive endpoints like delete/update/sms, and never bulk-iterates IDs."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "base_url": {"type": "string", "description": "Target base URL (defines the same-origin scope)"},
                        "endpoints": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of endpoint paths/URLs to test (from js_recon endpoints/paths)",
                        },
                        "auth_header": {
                            "type": "string",
                            "description": "Optional auth header for a differential, e.g. 'Authorization: Bearer xxx' or 'Cookie: session=...'",
                        },
                        "max_endpoints": {
                            "type": "integer",
                            "description": "Maximum number of endpoints to probe (default 60)",
                        },
                    },
                    "required": ["base_url", "endpoints"],
                },
            },
        }
    )

    tools.append(
        {
            "type": "function",
            "function": {
                "name": "dir_enum",
                "description": (
                    "Directory/file enumeration (inspired by dirsearch). Concurrent wordlist brute-force with a 404 baseline and global wildcard-response detection "
                    "(a random path returning 200 flags wildcarding and stops), plus status-code and response-length filtering. "
                    "Safe GET probes only; never touches destructive paths like delete/update."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target base URL, e.g. https://x.com/"},
                        "extensions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Extensions to expand, e.g. ['php','jsp','bak','zip'] (optional)",
                        },
                        "wordlist": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Additional custom paths (a heuristic wordlist based on naming patterns, optional)",
                        },
                    },
                    "required": ["url"],
                },
            },
        }
    )

    tools.extend(intel_tool_schemas())

    if mcp_manager:
        for schema in mcp_manager.get_tool_schemas():
            tools.append(
                {
                    "type": "function",
                    "function": {
                        "name": schema.get("name", ""),
                        "description": schema.get("description", ""),
                        "parameters": schema.get(
                            "inputSchema", {"type": "object", "properties": {}}
                        ),
                    },
                }
            )

    return tools


async def execute_nmap(agent: AgentContext, args: dict[str, Any]) -> str:
    target = args.get("target", "").strip()
    if not target:
        return "[!] nmap_scan requires a target parameter (target IP or domain)"

    host_violation = enforce_host_path_constraints(agent, host=target.lower(), target=target)
    if host_violation:
        return host_violation

    violation = enforce_port_constraints(agent, infer_ports_from_nmap_args(args), target=target)
    if violation:
        return violation

    try:
        ips = socket.getaddrinfo(target, None, socket.AF_INET)
        if ips:
            ip = ips[0][4][0]
            is_reserved, reason = is_reserved_ip(ip)
            if is_reserved and not target_is_private_literal(target):
                return (
                    f"[SKIP] Target {target} resolves to a reserved/internal address ({reason}, IP: {ip})\n"
                    f"Skipping the nmap scan. Prefer gathering info via web fingerprinting, directory enumeration, etc., "
                    f"and do not waste rounds on a reserved address."
                )
    except Exception:
        pass

    scan_type = args.get("scan_type", "top_ports")
    custom_ports = args.get("ports", "")
    timing = int(args.get("timing", 4))
    profile = str(args.get("profile", "") or "").strip().lower()

    nmap_cmd = shutil.which("nmap")
    if not nmap_cmd:
        try:
            result = subprocess.run(
                ["where.exe", "nmap"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                nmap_cmd = result.stdout.strip().split("\n")[0]
        except Exception:
            pass
    if not nmap_cmd:
        return "[!] nmap is not installed or not on PATH. Ensure nmap is installed and added to the system PATH."

    if profile:
        plan = build_nmap_plan(
            profile=profile,
            scan_type=str(scan_type or ""),
            ports=str(custom_ports or ""),
            timing=timing,
            prior_recon=getattr(getattr(agent, "session_state", None), "recon_data", {}),
        )
        privileged = nmap_has_raw_socket_access()
        cmd = build_nmap_command(nmap_cmd, target, plan, privileged=privileged)
        deescalated_note = (
            ""
            if privileged or plan.args == without_privileged_nmap_args(plan.args)
            else "[i] Running without admin privileges: skipped OS fingerprinting (-O), and downgraded the SYN scan to a connect scan (-sT).\n"
        )
    else:
        plan = None
        privileged = nmap_has_raw_socket_access()
        deescalated_note = ""
        cmd = [nmap_cmd, "-v" if scan_type == "full" else "-q", f"-T{max(0, min(5, timing))}"]
        if scan_type == "top_ports":
            cmd.extend(["--top-ports", "100", "-oX", "-"])
        elif scan_type == "syn":
            cmd.extend(["-sS" if privileged else "-sT", "-oX", "-"])
            if not privileged:
                deescalated_note = "[i] Running without admin privileges: using a connect scan (-sT) instead of a SYN scan (-sS).\n"
        elif scan_type == "tcp":
            cmd.extend(["-sT", "-oX", "-"])
        elif scan_type == "service":
            cmd.extend(["-sV", "-oX", "-"])
        elif scan_type == "os":
            if privileged:
                cmd.extend(["-O", "-oX", "-"])
            else:
                cmd.extend(["-sV", "-oX", "-"])
                deescalated_note = (
                    "[i] Running without admin privileges: OS fingerprinting (-O) unavailable; using service detection (-sV) instead.\n"
                )
        elif scan_type == "vuln":
            cmd.extend(["--script", "vuln", "-oX", "-"])
        elif scan_type == "full":
            if privileged:
                cmd.extend(["-sS", "-O", "-sV", "--script", "default,safe", "-oX", "-"])
            else:
                cmd.extend(["-sT", "-sV", "--script", "default,safe", "-oX", "-"])
                deescalated_note = (
                    "[i] Running without admin privileges: skipped OS fingerprinting (-O), "
                    "and downgraded the SYN scan to a connect scan (-sT).\n"
                )
        else:
            cmd.extend(["-sV", "-oX", "-"])

        if custom_ports:
            cmd.extend(["-p", custom_ports])
        cmd.append(target)

    try:
        kwargs: dict[str, Any] = {
            "capture_output": True,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "timeout": 120,
        }
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            kwargs["startupinfo"] = startupinfo
        result = subprocess.run(cmd, **kwargs)
        if (
            result.returncode != 0
            and not result.stdout
            and nmap_failure_needs_deescalation(result.stderr or "")
        ):
            fallback_cmd = deescalate_nmap_argv(cmd)
            if fallback_cmd != cmd:
                fallback = subprocess.run(fallback_cmd, **kwargs)
                if fallback.returncode == 0 or fallback.stdout:
                    result = fallback
                    deescalated_note = "[i] Retried with unprivileged nmap arguments after a permission error.\n"
    except subprocess.TimeoutExpired:
        return "[!] nmap scan timed out (120s); reduce the scan scope or use faster timing"
    except PermissionError:
        return "[!] nmap execution denied (insufficient privileges). On Windows, run the terminal as Administrator."
    except Exception as e:
        return f"[!] nmap execution error: {e}"

    if result.returncode != 0 and not result.stdout:
        return f"[!] nmap scan failed ({result.returncode}): {result.stderr[:500]}"
    output = result.stdout or result.stderr
    human_summary = parse_nmap_xml(output, target)
    structured = parse_nmap_xml_structured(output, target)
    if getattr(agent, "session_state", None) is not None:
        attach_network_scan_to_session(
            agent.session_state,
            structured,
            profile=profile or str(scan_type or "top_ports"),
            safe_probes=profile != "vuln",
        )
    if profile:
        network_summary = summarize_network_scan(structured)
        return f"{deescalated_note}{human_summary}\n\n{network_summary}"
    return f"{deescalated_note}{human_summary}"


def is_reserved_ip(ip: str) -> tuple[bool, str]:
    try:
        import ipaddress

        addr = ipaddress.ip_address(ip)
        for start, end, desc in RESERVED_IP_RANGES:
            if ipaddress.ip_address(start) <= addr <= ipaddress.ip_address(end):
                return True, desc
        return False, ""
    except Exception:
        return False, ""


def validate_scan_target(target: str) -> str:
    try:
        ips = socket.getaddrinfo(target, None, socket.AF_INET)
        if not ips:
            return ""
        ip = ips[0][4][0]
        is_reserved, reason = is_reserved_ip(ip)
        if is_reserved:
            return (
                f"\n\n⚠️ **Warning: target {target} resolves to a reserved/internal address ({reason})\n"
                f"   IP: {ip}\n"
                f"   Results from scanning this address do not reflect the real system's security state.\n"
                f"   Port information in the nmap results may be unrelated to the real target.**"
            )
    except Exception:
        pass
    return ""


def parse_nmap_xml(xml_output: str, target: str) -> str:
    if not xml_output or "<nmaprun" not in xml_output:
        lines = xml_output.strip().splitlines()[:80]
        return "nmap raw output:\n" + "\n".join(lines)

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        lines = xml_output.strip().splitlines()[:80]
        return "nmap raw output:\n" + "\n".join(lines)

    lines = [f"nmap scan results — {target}", "=" * 60]
    for host in root.findall(".//host"):
        hostname = host.find(".//hostname[@type='user']")
        addrs = [a.get("addr", "") for a in host.findall("address")]
        status = host.find("status")
        status_val = status.get("state", "unknown") if status is not None else "unknown"
        host_ip = addrs[0] if addrs else target
        reserved, reason = is_reserved_ip(host_ip)
        if reserved:
            host_str = (
                f"\n[host] {host_ip} ⚠️ **reserved address ({reason}); test-network results do not reflect the real target's security state**"
            )
        else:
            host_str = f"\n[host] {host_ip}"
        if hostname is not None:
            host_str += f" ({hostname.get('name', '')})"
        host_str += f" — {status_val}"
        lines.append(host_str)

        for port in host.findall(".//port"):
            port_id = port.get("portid", "")
            proto = port.get("protocol", "tcp")
            port_state = port.find("state")
            svc = port.find("service")
            state_val = port_state.get("state", "unknown") if port_state is not None else "unknown"
            svc_name = svc.get("name", "") if svc is not None else ""
            svc_product = svc.get("product", "") if svc is not None else ""
            svc_version = svc.get("version", "") if svc is not None else ""
            lines.append(
                f"  {proto.upper():5} {port_id}/{'s' if svc is not None and svc.get('tunnel') == 'ssl' else ''} "
                f"{state_val:8}{svc_name:15}{(svc_product + ' ' + svc_version).rstrip()}"
            )
            for script in port.findall("script"):
                lines.append(f"    | {script.get('id', '')}: {script.get('output', '')[:120]}")

    runstats = root.find(".//runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            elapsed = finished.get("elapsed", "")
            summary = finished.get("summary", "")
            lines.append(f"\nCompleted in: {elapsed}s | {summary}")
    return "\n".join(lines) or f"nmap scan complete (no output): {target}"


def _resolve_python_execute_mode(agent: AgentContext) -> str:
    safety = getattr(agent.config, "safety", None)
    if safety is None:
        return "trusted-local"

    mode = str(getattr(safety, "python_execute_mode", "") or "").strip().lower()
    if not mode and getattr(safety, "python_execute_restricted", False):
        return "safe"
    if mode in {"safe", "lab", "trusted-local"}:
        return mode
    return "trusted-local"


def _write_python_audit(
    agent: AgentContext,
    *,
    code: str,
    purpose: str,
    mode: str,
    status: str,
    decision: str = "executed",
    blocked_reason: str = "",
    code_sha256: str = "",
    duration_s: float | None = None,
    generated_files: list[str] | None = None,
    start_time: str = "",
    end_time: str = "",
) -> None:
    """Append a redacted, hashed audit record for one python_execute request.

    Records the decision, code hash, timing, status and any generated files.
    Never writes the raw code or secrets — the preview is redacted and truncated.
    """
    safety = getattr(agent.config, "safety", None)
    if safety is None or not getattr(safety, "python_execute_audit_enabled", True):
        return

    try:
        import hashlib
        from datetime import datetime

        from vulnclaw.config.settings import PYTHON_EXECUTE_AUDIT_FILE, ensure_dirs

        ensure_dirs()
        digest = code_sha256 or hashlib.sha256(code.encode("utf-8", "replace")).hexdigest()
        record = {
            "timestamp": end_time or datetime.now().isoformat(),
            "start_time": start_time,
            "end_time": end_time,
            "target": getattr(getattr(agent, "session_state", None), "target", None),
            "mode": mode,
            "purpose": redact(purpose)[:200],
            "decision": decision,
            "status": status,
            "blocked_reason": blocked_reason,
            "code_sha256": digest,
            "code_lines": code.count("\n") + 1,
            "code_preview": redact(code)[:300],
            "duration_s": duration_s,
            "generated_files": generated_files or [],
        }
        with open(PYTHON_EXECUTE_AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        return


async def execute_python(agent: AgentContext, args: dict[str, Any]) -> str:
    code = args.get("code", "")
    purpose = args.get("purpose", "")
    if not code.strip():
        return "[!] Code is empty; nothing executed"

    safety = getattr(agent.config, "safety", None)

    # 1. Default-deny: python_execute is high-risk (arbitrary local code) and off
    #    unless explicitly opted in via config / env / CLI flag.
    if safety is None or not getattr(safety, "enable_python_execute", False):
        _write_python_audit(
            agent,
            code=code,
            purpose=purpose,
            mode="-",
            decision="disabled",
            status="blocked",
            blocked_reason="python_execute disabled by default",
        )
        return (
            "[!] python_execute is DISABLED by default (high-risk local code execution).\n"
            "Enable it only for an authorized engagement: set safety.enable_python_execute=true, "
            "export VULNCLAW_SAFETY_PYTHON_EXECUTE_ENABLED=1, or pass --enable-python-execute.\n"
            "In-scope HTTP testing can use the scope-checked `fetch` tool instead."
        )

    mode = _resolve_python_execute_mode(agent)

    # 2. Scope: refuse code that references an out-of-scope host / path.
    url_matches = re.findall(r"https?://([a-zA-Z0-9._:-]+)(/[^\s'\"`]*)?", code)
    for raw_host, path in url_matches:
        host = raw_host.split(":", 1)[0].lower()
        host_violation = enforce_host_path_constraints(
            agent, host=host, path=(path or "").rstrip("/"), target=host
        )
        if host_violation:
            _write_python_audit(
                agent,
                code=code,
                purpose=purpose,
                mode=mode,
                decision="blocked",
                status="blocked",
                blocked_reason="scope",
            )
            return host_violation

    # 3. Line-count limit.
    max_lines = getattr(safety, "python_execute_max_lines", 50)
    if code.count("\n") + 1 > max_lines:
        _write_python_audit(
            agent,
            code=code,
            purpose=purpose,
            mode=mode,
            decision="blocked",
            status="blocked",
            blocked_reason="max_lines",
        )
        return f"[!] Code exceeds the max line limit ({max_lines})"

    # 4. Static denylist: process spawning / native memory access can escape the
    #    in-process sandbox guards, so they are refused before running.
    blocked = sandbox_precheck(code)
    if blocked:
        _write_python_audit(
            agent,
            code=code,
            purpose=purpose,
            mode=mode,
            decision="blocked",
            status="blocked",
            blocked_reason=blocked,
        )
        return (
            f"[!] python_execute blocked: disallowed operation '{blocked}'. "
            "Process spawning and native-memory access are not permitted in the sandbox."
        )

    # 5. Run in the hardened sandbox, off-thread so the event loop keeps moving.
    from datetime import datetime

    start_time = datetime.now().isoformat()
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        lambda: run_sandboxed(
            code,
            mode=mode,
            allow_network=getattr(safety, "python_execute_allow_network", False),
            timeout_s=getattr(safety, "python_execute_timeout_seconds", 30),
            max_memory_mb=getattr(safety, "python_execute_max_memory_mb", 1024),
            max_file_size_mb=getattr(safety, "python_execute_max_file_size_mb", 10),
            max_output_chars=getattr(safety, "python_execute_max_output_chars", 8000),
        ),
    )
    end_time = datetime.now().isoformat()

    if result.status == "timeout":
        agent.runtime.python_timeout_rounds += 1

    _write_python_audit(
        agent,
        code=code,
        purpose=purpose,
        mode=mode,
        decision="executed",
        status=result.status,
        blocked_reason=result.blocked_reason,
        code_sha256=result.code_hash,
        duration_s=result.duration_s,
        generated_files=result.generated_files,
        start_time=start_time,
        end_time=end_time,
    )

    # 6. Render output, neutralizing completion markers that could fool the loop.
    output = result.output or ""
    for sig in ("[DONE]", "[COMPLETE]"):
        output = output.replace(sig, f"[BLOCKED_{sig[1:-1]}]")

    warning_prefix = ""
    if getattr(safety, "python_execute_show_warning", True):
        warning_prefix = (
            f"[!] Security notice: python_execute ran local code in the {mode} sandbox.\n---\n"
        )

    timeout_s = getattr(safety, "python_execute_timeout_seconds", 30)
    if result.status == "timeout":
        return f"{warning_prefix}[!] Python execution timed out after {timeout_s}s"
    if not output.strip():
        return f"{warning_prefix}[+] Python executed ({mode}, {result.status}) with no output"
    return f"{warning_prefix}[+] Python execution result ({mode}, {result.status}):\n{output}"


def _sync_cookies_to_shared_jar(
    agent: AgentContext, cookies: list[tuple[str, str, str, str]]
) -> None:
    """Copy session cookies into the agent's shared _fetch_cookies jar.

    This allows the ``fetch`` tool (which uses ``_fetch_cookies``) to
    immediately use the authenticated session obtained by
    ``brute_force_login`` without requiring a separate re-login.
    """
    if not agent or not cookies:
        return
    mcp = getattr(agent, "mcp_manager", None)
    if not mcp:
        return
    try:
        import httpx

        jar = getattr(mcp, "_fetch_cookies", None)
        if jar is None:
            jar = httpx.Cookies()
            mcp._fetch_cookies = jar
        for name, value, domain, path in cookies:
            if name and value:
                jar.set(name, value, domain=domain or "", path=path or "/")
    except Exception:
        pass


async def execute_brute_force(agent: AgentContext, args: dict[str, Any]) -> str:
    """Execute a login brute-force with automatic CSRF/session management.

    Handles the full flow in one call:
    GET login page → extract CSRF + session → POST passwords → detect result
    """
    import asyncio
    import re
    import time

    url = str(args.get("url", "") or "").strip()
    password_field = str(args.get("password_field", "") or "").strip()
    csrf_field = str(args.get("csrf_field", "") or "").strip()
    username_field = str(args.get("username_field", "") or "").strip()
    username = str(args.get("username", "") or "").strip()
    passwords = args.get("passwords", [])
    success_keyword = str(args.get("success_keyword", "") or "").strip()
    failure_keyword = str(args.get("failure_keyword", "") or "").strip()
    submit_action = str(args.get("submit_action", "") or "").strip()
    extra_data = args.get("extra_data", {}) or {}
    submit_url = submit_action or url

    if not url or not password_field or not passwords:
        return "[!] Missing required parameters: url, password_field, passwords"

    if not isinstance(passwords, list) or not passwords:
        return "[!] passwords must be a non-empty list"

    passwords = passwords[:20]
    total = len(passwords)

    try:
        import httpx
    except ImportError:
        return "[!] httpx is not installed; cannot run the brute-force"

    def extract_csrf(html: str, field_name: str) -> str | None:
        """Extract CSRF token from HTML input field."""
        if not field_name:
            return None
        pattern = re.compile(
            rf'name=["\']{re.escape(field_name)}["\'][^>]*value=["\']([^"\']+)',
            re.IGNORECASE,
        )
        m = pattern.search(html)
        if m:
            return m.group(1)
        # Try alternative: value before name
        pattern2 = re.compile(
            rf'value=["\']([^"\']+)[^>]*name=["\']{re.escape(field_name)}',
            re.IGNORECASE,
        )
        m = pattern2.search(html)
        return m.group(1) if m else None

    results: list[str] = []
    start_time = time.time()
    attempts = 0
    found_password: str | None = None

    # Collect cookies from the internal client so we can sync them
    # back to the shared _fetch_cookies jar after a successful login.
    session_cookies: list[tuple[str, str, str, str]] = []  # name, value, domain, path

    async with httpx.AsyncClient(
        verify=False,
        timeout=30.0,
        follow_redirects=True,
    ) as client:
        # Step 1: Get login page for initial CSRF and session
        try:
            resp = await asyncio.wait_for(
                client.get(url),
                timeout=30.0,
            )
            html = resp.text
        except Exception as e:
            return f"[!] Failed to fetch the login page: {e}"

        csrf_token = extract_csrf(html, csrf_field)
        if csrf_token is None and csrf_field:
            results.append(f"[!] Warning: CSRF field '{csrf_field}' not found on the login page")

        # Auto-detect submit button values from login page HTML.
        # Many forms (DVWA, etc.) check isset($_POST['SubmitButtonName'])
        # before processing authentication. Without the button's name=value,
        # the server skips auth and just re-renders the page.
        auto_fields: dict[str, str] = {}
        for input_match in re.finditer(
            r'<(?:input|button)\s[^>]*type=["\']submit["\'][^>]*>',
            html,
            re.IGNORECASE,
        ):
            tag = input_match.group()
            name_m = re.search(r'name\s*=\s*["\']([^"\']+)["\']', tag, re.IGNORECASE)
            val_m = re.search(r'value\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if name_m:
                auto_fields[name_m.group(1)] = val_m.group(1) if val_m else name_m.group(1)

        # Step 2: Try each password
        for i, password in enumerate(passwords, 1):
            form_data: dict[str, str] = {}
            if username_field and username:
                form_data[username_field] = username
            form_data[password_field] = password
            if csrf_token and csrf_field:
                form_data[csrf_field] = csrf_token
            # Auto-detected submit buttons come first so they can be
            # overridden by explicit extra_data if needed.
            form_data.update(auto_fields)
            form_data.update({k: str(v) for k, v in extra_data.items()})

            try:
                resp = await asyncio.wait_for(
                    client.post(submit_url, data=form_data),
                    timeout=30.0,
                )
                attempts += 1
                response_html = resp.text
                status = resp.status_code

                # Determine success or failure
                is_success = False
                reason = ""
                csrf_markers = ["csrf token is incorrect", "csrf token mismatch",
                                "token mismatch", "invalid token"]

                if success_keyword and success_keyword.lower() in response_html.lower():
                    is_success = True
                    reason = f"'{success_keyword}'"
                elif failure_keyword and failure_keyword.lower() in response_html.lower():
                    is_success = False
                    reason = f"'{failure_keyword}'"
                elif any(m in response_html.lower() for m in csrf_markers):
                    is_success = False
                    reason = "CSRF token error (new token synced automatically)"
                elif status == 302:
                    is_success = True
                    reason = "Status 302 (redirect)"
                elif "logout" in response_html.lower() or "welcome" in response_html.lower():
                    is_success = True
                    reason = "detected an already-logged-in state"
                else:
                    # Include a short snippet from the response so the model
                    # can diagnose what the server actually returned.
                    snippet = response_html.strip()[:200].replace("\n", " ")
                    is_success = False
                    reason = snippet

                prefix = "[✓]" if is_success else "[✗]"
                pw_preview = password[:40].replace("\n", "\\n")
                results.append(f"{prefix} {pw_preview} → {'success' if is_success else 'failure'} ({reason})")

                # Extract new CSRF from response for next attempt
                new_token = extract_csrf(response_html, csrf_field)
                if new_token:
                    csrf_token = new_token

                # Stop early on success if keyword matched
                if is_success and success_keyword:
                    found_password = password
                    break

            except Exception as e:
                pw_preview = password[:30].replace("\n", "\\n")
                results.append(f"[!] {pw_preview} → request failed: {e}")
                continue

        # Save cookies from the internal client for potential sharing with
        # the fetch tool's cookie jar.
        try:
            for cookie in client.cookies.jar:
                session_cookies.append(
                    (cookie.name, cookie.value, cookie.domain, cookie.path)
                )
        except Exception:
            pass

    elapsed = time.time() - start_time

    # Sync session cookies to the shared _fetch_cookies jar so that
    # subsequent `fetch` calls from the agent are already authenticated.
    if found_password and session_cookies:
        _sync_cookies_to_shared_jar(agent, session_cookies)

    summary = [
        f"[+] Brute-force complete — {url}",
        f"    User: {username or '(unspecified)'}",
        "",
        "    Results:",
    ]
    for r in results:
        summary.append(f"    {r}")
    summary.append("")
    summary.append(f"    Elapsed: {elapsed:.1f}s")
    summary.append(f"    Attempts: {attempts}/{total}")

    return "\n".join(summary)
