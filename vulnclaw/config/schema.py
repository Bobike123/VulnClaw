"""VulnClaw configuration schema - Pydantic models for type-safe config."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ── LLM Provider Presets ────────────────────────────────────────────


class LLMProvider(str, Enum):
    """Supported LLM providers with OpenAI-compatible APIs."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    MINIMAX = "minimax"
    DEEPSEEK = "deepseek"
    ZHIPU = "zhipu"
    MOONSHOT = "moonshot"
    QWEN = "qwen"
    SILICONFLOW = "siliconflow"
    DOUBAO = "doubao"
    BAICHUAN = "baichuan"
    STEPFUN = "stepfun"
    SENSETIME = "sensetime"
    YI = "yi"
    CUSTOM = "custom"


# Provider preset definitions: base_url + default_model + notes
PROVIDER_PRESETS: dict[LLMProvider, dict[str, str]] = {
    LLMProvider.OPENAI: {
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o",
        "label": "OpenAI",
    },
    LLMProvider.ANTHROPIC: {
        "base_url": "https://api.anthropic.com/v1",
        "default_model": "claude-sonnet-5",
        "label": "Anthropic Claude",
    },
    LLMProvider.MINIMAX: {
        "base_url": "https://api.minimaxi.com/v1",
        "default_model": "MiniMax-M3",
        "label": "MiniMax",
    },
    LLMProvider.DEEPSEEK: {
        "base_url": "https://api.deepseek.com",
        "default_model": "deepseek-v4-pro",
        "label": "DeepSeek",
    },
    LLMProvider.ZHIPU: {
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "default_model": "glm-4.7",
        "label": "Zhipu GLM",
    },
    LLMProvider.MOONSHOT: {
        "base_url": "https://api.moonshot.cn/v1",
        "default_model": "kimi-k2.6",
        "label": "Kimi (Moonshot)",
    },
    LLMProvider.QWEN: {
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "default_model": "qwen3-max",
        "label": "Qwen (Tongyi)",
    },
    LLMProvider.SILICONFLOW: {
        "base_url": "https://api.siliconflow.cn/v1",
        "default_model": "deepseek-ai/DeepSeek-V4-Flash",
        "label": "SiliconFlow",
    },
    LLMProvider.DOUBAO: {
        "base_url": "https://ark.cn-beijing.volces.com/api/v3",
        "default_model": "Doubao-Seed-2.0-Pro",
        "label": "Doubao (ByteDance)",
    },
    LLMProvider.BAICHUAN: {
        "base_url": "https://api.baichuan-ai.com/v1",
        "default_model": "Baichuan4-Turbo",
        "label": "Baichuan",
    },
    LLMProvider.STEPFUN: {
        "base_url": "https://api.stepfun.com/v1",
        "default_model": "step-3.5-flash",
        "label": "StepFun",
    },
    LLMProvider.SENSETIME: {
        "base_url": "https://api.sensenova.cn/v1",
        "default_model": "SenseNova-6.7-Flash-Lite",
        "label": "SenseTime (SenseNova)",
    },
    LLMProvider.YI: {
        "base_url": "https://api.lingyiwanwu.com/v1",
        "default_model": "yi-lightning",
        "label": "01.AI (Yi)",
    },
    LLMProvider.CUSTOM: {
        "base_url": "",
        "default_model": "",
        "label": "Custom",
    },
}


class LLMConfig(BaseModel):
    """LLM provider configuration."""

    provider: str = Field(
        default="openai",
        description="LLM provider name (openai/anthropic/minimax/deepseek/zhipu/moonshot/qwen/siliconflow/doubao/baichuan/stepfun/sensetime/yi/custom)",
    )
    api_key: str = Field(default="", description="Static API key for the chosen provider (auth_mode=static)")
    api_keys: list[str] = Field(
        default_factory=list,
        description="Optional list of API keys to fail over between when one is "
        "rate-limited, out of quota, or invalid. Overrides api_key when non-empty.",
    )
    auth_mode: str = Field(
        default="static",
        description="Credential mode: static (api_key) or oauth (browser sign-in via `vulnclaw login`).",
    )
    # ── OAuth (auth_mode=oauth) ─────────────────────────────────────────
    # Tokens are obtained by `vulnclaw login` and refreshed silently. These two
    # endpoints are set automatically by the login flow.
    oauth_token_url: str = Field(
        default="", description="OAuth token endpoint (code/refresh exchange)"
    )
    oauth_client_id: str = Field(
        default="", description="OAuth client_id used for token exchange/refresh"
    )
    chatgpt_auto_proxy: bool = Field(
        default=False,
        description=(
            "When signed in with a ChatGPT subscription, auto-start a built-in "
            "local proxy that bridges chat.completions to the ChatGPT backend "
            "(no external proxy needed)."
        ),
    )
    base_url: str = Field(
        default="https://api.openai.com/v1",
        description="OpenAI-compatible API base URL (auto-filled by provider)",
    )
    model: str = Field(default="gpt-4o", description="Model name to use (auto-filled by provider)")
    max_tokens: int = Field(default=4096, description="Max tokens per response")
    max_context_tokens: int = Field(
        default=128000, description="Max context window tokens before sliding-window truncation"
    )
    temperature: float = Field(default=0.1, description="Sampling temperature")
    reasoning_effort: str = Field(
        default="high", description="Reasoning effort level (OpenAI o-series only)"
    )
    # ── FreeLLMAPI fallback ──────────────────────────────────────────────
    # Local self-hosted router (github.com/tashfeenahmed/freellmapi) aggregating
    # free tiers from multiple providers behind one OpenAI-compatible endpoint.
    # When the ChatGPT OAuth backend reports its usage cap is exhausted, VulnClaw
    # can transparently fail over to it for the rest of the session.
    freellmapi_fallback: bool = Field(
        default=False,
        description=(
            "Automatically fail over to a local FreeLLMAPI instance when the "
            "ChatGPT OAuth backend reports its usage limit is exhausted."
        ),
    )
    freellmapi_base_url: str = Field(
        default="http://localhost:3001/v1", description="FreeLLMAPI OpenAI-compatible base URL"
    )
    freellmapi_api_key: str = Field(
        default="", description="FreeLLMAPI unified bearer token (freellmapi-...)"
    )
    freellmapi_model: str = Field(
        default="auto", description="Model requested from FreeLLMAPI ('auto' lets its router pick)"
    )

    def key_pool(self) -> list[str]:
        """Return the ordered, de-blanked list of usable static API keys.

        Prefers ``api_keys`` when it has any non-empty entry; otherwise falls
        back to the single ``api_key``. Whitespace-only entries are dropped.
        """
        candidates = self.api_keys or ([self.api_key] if self.api_key else [])
        return [k.strip() for k in candidates if k and k.strip()]

    def primary_key(self) -> str:
        """Return the first usable static API key, or an empty string if none."""
        pool = self.key_pool()
        return pool[0] if pool else ""


class MCPTransportConfig(BaseModel):
    """MCP server transport configuration."""

    type: str = Field(description="Transport type: stdio, sse, streamable-http")
    command: str | None = Field(default=None, description="Command to start the server (stdio)")
    args: list[str] | None = Field(default=None, description="Command arguments")
    url: str | None = Field(default=None, description="Server URL (sse / streamable-http)")
    env: dict[str, str] | None = Field(
        default=None, description="Environment variables (stdio) / HTTP headers (streamable-http)"
    )
    startup_timeout: int = Field(default=30000, description="Startup timeout in ms")
    tool_timeout: int = Field(default=300000, description="Tool call timeout in ms")


class MCPServerConfig(BaseModel):
    """Single MCP server configuration."""

    name: str = Field(description="Server identifier")
    enabled: bool = Field(default=True, description="Whether to auto-start this server")
    priority: int = Field(default=1, description="Priority: 0=critical, 1=normal, 2=optional")
    transport: MCPTransportConfig = Field(description="Transport configuration")
    description: str = Field(default="", description="Human-readable description")


class MCPServersConfig(BaseModel):
    """All MCP servers configuration."""

    servers: dict[str, MCPServerConfig] = Field(default_factory=dict)


class ReconConfig(BaseModel):
    """Information-gathering configuration: space-mapping API keys + recon knobs.

    Keys are read here OR from environment variables (FOFA_KEY, HUNTER_KEY,
    QUAKE_KEY, ZOOMEYE_KEY, SHODAN_KEY, ZEROZONE_KEY) - never hard-coded. Put real
    keys in ~/.vulnclaw/config.yaml (gitignored), not in source.
    """

    fofa_email: str = Field(default="", description="FOFA account email")
    fofa_key: str = Field(default="", description="FOFA API key")
    hunter_key: str = Field(default="", description="Hunter (QiAnXin Eagle Eye) API key")
    quake_key: str = Field(default="", description="Quake (360) API token")
    zoomeye_key: str = Field(default="", description="ZoomEye API key")
    shodan_key: str = Field(default="", description="Shodan API key")
    zerozone_key: str = Field(default="", description="0.zone (LingLing Security) API key")
    http_timeout: float = Field(default=15.0, description="Per-request HTTP timeout (s)")
    max_concurrency: int = Field(default=20, description="Max concurrent recon requests")
    space_size: int = Field(default=100, description="Default result size per space-mapping query")
    dir_wordlist_path: str = Field(
        default="", description="Optional path to a custom directory-bruteforce wordlist"
    )
    dir_max_requests: int = Field(
        default=1500, description="Hard cap on requests per directory-enumeration call"
    )
    js_max_files: int = Field(
        default=30, description="Max JavaScript files fetched per js_recon call"
    )


class SafetyConfig(BaseModel):
    """Safety / sandbox configuration.

    Defaults are deliberately deny-by-default: ``python_execute`` is a high-risk
    capability (arbitrary local code execution) and must be explicitly opted in
    via config, env, or CLI flag before it will run.
    """

    enable_python_execute: bool = Field(
        default=False,
        description="Enable the high-risk python_execute built-in tool. Disabled by "
        "default; requires an explicit opt-in (config/env/--enable-python-execute).",
    )
    python_execute_require_confirmation: bool = Field(
        default=True,
        description="Require an explicit interactive confirmation (TTY) before the "
        "first python_execute run in a session. Non-interactive runs rely on the "
        "config/env/flag opt-in above.",
    )
    python_execute_restricted: bool = Field(
        default=False,
        description="Restricted mode: block file I/O and network in python_execute",
    )
    python_execute_mode: str = Field(
        default="safe",
        description="Execution mode for python_execute: safe (most restrictive, "
        "default), lab, trusted-local. Higher modes relax the sandbox and must be "
        "chosen deliberately for authorized lab targets only.",
    )
    python_execute_allow_network: bool = Field(
        default=False,
        description="Allow outbound network access from python_execute. Disabled by "
        "default; in-scope HTTP testing should use the fetch tool which is scope-checked.",
    )
    python_execute_max_lines: int = Field(
        default=50,
        description="Max lines of code allowed per python_execute call",
    )
    python_execute_show_warning: bool = Field(
        default=True,
        description="Show a security warning before each python_execute invocation",
    )
    python_execute_timeout_seconds: int = Field(
        default=30,
        description="Wall-clock timeout (seconds) for a single python_execute call",
    )
    python_execute_max_memory_mb: int = Field(
        default=256,
        description="Max address-space (MB) for a python_execute subprocess (POSIX only)",
    )
    python_execute_max_output_chars: int = Field(
        default=8000,
        description="Max stdout/stderr characters returned from a python_execute call",
    )
    python_execute_max_file_size_mb: int = Field(
        default=10,
        description="Max size (MB) of any single file the sandbox may create (POSIX only)",
    )
    python_execute_audit_enabled: bool = Field(
        default=True,
        description="Write python_execute audit records to the local config directory",
    )
    tool_parallel: bool = Field(
        default=True,
        description="Execute independent tool calls in a single LLM turn concurrently",
    )
    tool_max_concurrent: int = Field(
        default=5,
        description="Max number of tool calls executed concurrently per round (1=serial)",
    )


class ScopeConfig(BaseModel):
    """Engagement scope enforcement configuration.

    Scope is the central authorization boundary for all target-directed network
    activity. Defaults are deny-by-default for anything beyond the local machine:
    localhost is allowed, private lab ranges require an explicit opt-in, and public
    targets must be allowlisted in a scope file (see ``.vulnclaw-scope.yaml``).
    """

    enforce: bool = Field(
        default=True,
        description="Enforce scope on every target-directed network action. "
        "Disabling this removes the central authorization boundary - not recommended.",
    )
    scope_file: str = Field(
        default="",
        description="Path to a .vulnclaw-scope.yaml scope file. When empty, VulnClaw "
        "looks for ./.vulnclaw-scope.yaml then ~/.vulnclaw/scope.yaml.",
    )
    allow_localhost: bool = Field(
        default=True,
        description="Allow loopback/localhost targets without an explicit scope file",
    )
    allow_private_lab: bool = Field(
        default=False,
        description="Allow RFC1918 private-lab ranges without a scope file entry "
        "(requires deliberate opt-in / confirmation)",
    )
    allow_public: bool = Field(
        default=False,
        description="Allow public targets without a scope-file allowlist entry. "
        "Strongly discouraged; public targets should always be explicitly allowlisted.",
    )


class AuditConfig(BaseModel):
    """Structured audit-log configuration."""

    enabled: bool = Field(
        default=True,
        description="Write structured JSONL audit events (tool calls, denials, "
        "approvals, scope decisions) to the audit log.",
    )
    hash_chain: bool = Field(
        default=True,
        description="Chain each audit event to the SHA-256 of the previous event for "
        "tamper-evidence.",
    )
    audit_dir: str = Field(
        default="",
        description="Directory for audit logs. When empty, uses <config_dir>/audit.",
    )


class ApprovalConfig(BaseModel):
    """Human-approval gate for high-risk actions.

    Risky actions (exploitation, PoC, credential handling, public OSINT, request
    mutation, browser form submission, persistent mode) require approval before
    running. In non-interactive mode approval must come from a signed approval
    file; there is no silent auto-approve.
    """

    require_approval: bool = Field(
        default=True,
        description="Require explicit human approval before any high-risk action.",
    )
    mode: str = Field(
        default="non-interactive",
        description="Approval mode: interactive (prompt on a TTY), non-interactive "
        "(require a matching entry in the approval file), or dry-run (never execute "
        "risky actions - explain what would happen instead).",
    )
    approval_file: str = Field(
        default="",
        description="Path to a signed approvals file. When empty, VulnClaw looks for "
        "./.vulnclaw-approvals.yaml then <config_dir>/approvals.yaml.",
    )


class RiskyToolsConfig(BaseModel):
    """Per-capability enable switches for high-risk skills. All default-deny.

    A risky capability runs only when it is enabled here AND the scope permits it
    (phase/feature) AND the action is approved.
    """

    enable_exploit: bool = Field(default=False, description="Allow exploitation actions")
    enable_post_exploitation: bool = Field(
        default=False, description="Allow post-exploitation actions"
    )
    enable_waf_bypass: bool = Field(default=False, description="Allow WAF-bypass actions")
    enable_persistent: bool = Field(default=False, description="Allow persistent autonomous mode")
    enable_poc_generation: bool = Field(
        default=False, description="Allow runnable proof-of-concept generation"
    )
    enable_js_secret_extraction: bool = Field(
        default=False,
        description="Include (redacted, fingerprint-only) JS secret findings; values are "
        "never shown regardless of this setting",
    )
    enable_osint: bool = Field(
        default=False, description="Allow OSINT / subdomain enumeration against public targets"
    )
    enable_brute_force: bool = Field(
        default=False, description="Allow credential brute-force actions"
    )
    enable_browser: bool = Field(
        default=False,
        description="Allow active browser interaction (form fill/submit, clicks, in-page "
        "JavaScript execution) via the chrome-devtools MCP server. Passive browsing "
        "(navigate/read/screenshot) is never gated.",
    )
    enable_request_mutation: bool = Field(
        default=False,
        description="Allow sending crafted/raw HTTP requests through a proxy or the browser "
        "network context (Burp send_http*_request, chrome_network_request). Read-only proxy "
        "history is never gated.",
    )


class BudgetConfig(BaseModel):
    """Safety budgets and emergency stop for persistent (open-ended) autonomous runs.

    All ceilings are opt-in: a value of 0 means unlimited for that dimension. The
    emergency-stop file is a kill switch - creating it halts the run at the next
    checkpoint regardless of the other limits (and even when ``enabled`` is off).
    """

    enabled: bool = Field(
        default=True,
        description="Enforce duration/cycle/tool-call ceilings during persistent mode. "
        "The emergency-stop file is honoured even when this is disabled.",
    )
    max_duration_minutes: int = Field(
        default=0,
        description="Wall-clock ceiling for a persistent run in minutes (0 = unlimited).",
    )
    max_cycles: int = Field(
        default=0,
        description="Global safety cap on persistent cycles, independent of the "
        "session's own persistent_max_cycles (0 = unlimited).",
    )
    max_tool_calls: int = Field(
        default=0,
        description="Ceiling on total tool calls across a persistent run (0 = unlimited).",
    )
    emergency_stop_file: str = Field(
        default="",
        description="Extra path whose presence halts the run. The defaults "
        "./.vulnclaw-STOP and ./.vulnclaw-stop are always checked as well.",
    )


class SessionConfig(BaseModel):
    """Session / output configuration."""

    output_dir: Path = Field(default=Path("./vulnclaw-output"), description="Output directory")
    auto_save: bool = Field(default=True, description="Auto-save session state")
    report_format: str = Field(
        default="markdown", description="Default report format: markdown, html"
    )
    poc_language: str = Field(default="python", description="Default PoC language: python, bash")
    max_rounds: int = Field(default=15, description="Max autonomous pentest rounds (1-100)")
    # Autonomous engine: "solve" = goal-driven OODA (default), "rounds" = legacy fixed-round loop
    engine: str = Field(
        default="solve", description="Autonomous engine: solve (goal-driven) or rounds (legacy)"
    )
    # Solve-engine knobs
    solve_max_steps: int = Field(
        default=40, description="Safety cap on solve explore steps (not a fixed workflow length)"
    )
    solve_max_intents: int = Field(default=3, description="Max new intents per reason step")
    solve_max_tool_rounds: int = Field(
        default=6, description="Max tool-calling rounds per intent exploration"
    )
    solve_max_parallel: int = Field(
        default=3, description="Max intents explored concurrently per solve batch (1=serial)"
    )
    show_thinking: bool = Field(
        default=False, description="Show LLM thinking/reasoning output (default: off)"
    )
    repl_parallel_enabled: bool = Field(
        default=True,
        description="Use bounded child-agent fan-out by default for REPL auto-mode "
        "(legacy 'rounds' engine only; the 'solve' engine uses solve_max_parallel)",
    )
    repl_parallel_agents: int = Field(
        default=3,
        description="Default child-agent count for REPL auto-mode fan-out",
    )
    repl_parallel_depth: int = Field(
        default=1,
        description="Default child-agent discovery depth for REPL auto-mode fan-out",
    )
    repl_parallel_worker_rounds: int = Field(
        default=3,
        description="Max rounds per REPL parallel worker",
    )
    repl_parallel_surface_limit: int = Field(
        default=20,
        description="Maximum discovered surfaces considered by REPL parallel auto-mode",
    )
    # Dead-loop detection
    stale_rounds_threshold: int = Field(
        default=5,
        description="Consecutive rounds without progress before dead-loop warning (1-50)",
    )
    # Persistent pentest configuration
    persistent_rounds_per_cycle: int = Field(
        default=100, description="Rounds per persistent pentest cycle"
    )
    persistent_max_cycles: int = Field(
        default=10, description="Max cycles for persistent pentest (0=unlimited)"
    )
    persistent_auto_report: bool = Field(
        default=True, description="Auto-generate report after each cycle"
    )
    # Language configuration
    language: str = Field(
        default="auto", description="UI language: auto, zh, en"
    )
    reasoning_state_enabled: bool = Field(
        default=True, description="Enable reasoning state tracking"
    )
    reflexion_enabled: bool = Field(
        default=True, description="Enable reflexion feedback loop"
    )
    reflexion_max_same_vuln_fails: int = Field(
        default=2, description="Max repeated failures for the same vulnerability"
    )
    reflexion_max_total_no_progress: int = Field(
        default=5, description="Max total rounds without progress before reflexion"
    )
    escalation_max_level: int = Field(
        default=4, description="Max escalation level"
    )
    plugin_runtime_enabled: bool = Field(
        default=True, description="Enable plugin runtime"
    )
    plugin_default_timeout: int = Field(
        default=10, description="Default plugin timeout in seconds"
    )
    plugin_max_requests_per_target: int = Field(
        default=30, description="Max plugin requests per target"
    )
    evidence_min_report_level: str = Field(
        default="L4", description="Minimum evidence level for report inclusion"
    )

class VulnClawConfig(BaseModel):
    """Top-level VulnClaw configuration."""

    llm: LLMConfig = Field(default_factory=LLMConfig)
    mcp: MCPServersConfig = Field(default_factory=MCPServersConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    approval: ApprovalConfig = Field(default_factory=ApprovalConfig)
    risky_tools: RiskyToolsConfig = Field(default_factory=RiskyToolsConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    recon: ReconConfig = Field(default_factory=ReconConfig)

    model_config = ConfigDict(
        env_prefix="VULNCLAW_",
        env_nested_delimiter="__",
    )


# ── Built-in MCP server definitions (MVP) ──────────────────────────

BUILTIN_MCP_SERVERS: dict[str, dict[str, Any]] = {
    "fetch": {
        "name": "fetch",
        "enabled": True,
        "priority": 0,
        "description": "HTTP request tool for API testing & web interaction",
        "transport": {
            "type": "stdio",
            "command": "uvx",
            "args": ["mcp-server-fetch"],
        },
    },
    "memory": {
        "name": "memory",
        "enabled": True,
        "priority": 0,
        "description": "Context memory & session state persistence",
        "transport": {
            "type": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-memory"],
        },
    },
    "chrome-devtools": {
        "name": "chrome-devtools",
        "enabled": False,
        "priority": 0,
        "description": "Browser automation for Web app pentest",
        "transport": {
            "type": "stdio",
            "command": "npx",
            "args": ["-y", "chrome-devtools-mcp@latest"],
        },
    },
    "burp": {
        "name": "burp",
        "enabled": False,
        "priority": 0,
        "description": "Burp Suite proxy integration for HTTP interception via SSE",
        "transport": {
            "type": "sse",
            "url": "http://127.0.0.1:9876",
        },
    },
}
