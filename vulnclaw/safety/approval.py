"""Human-approval gate for high-risk actions.

Risky actions (exploitation, post-exploitation, credential brute-force, public
OSINT, JS secret extraction, PoC generation, persistent mode, request mutation,
browser form submission) must be approved before they run.

Approval modes:
- ``dry-run``          - never execute; explain what would happen.
- ``interactive``      - prompt on a TTY (denied when no TTY is attached).
- ``non-interactive``  - approve only when a matching entry exists in a signed
  approval file; otherwise deny. There is no silent auto-approve.

This module has no dependency on the agent layer: the caller classifies the
action (it already knows the target/action) and this module decides.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"
RISK_CRITICAL = "critical"

# Maps a risky action to the RiskyToolsConfig switch that must be enabled for it.
CAPABILITY_BY_ACTION: dict[str, str] = {
    "exploit": "enable_exploit",
    "post_exploitation": "enable_post_exploitation",
    "waf_bypass": "enable_waf_bypass",
    "persistent": "enable_persistent",
    "poc_generation": "enable_poc_generation",
    "js_secret_extraction": "enable_js_secret_extraction",
    "osint": "enable_osint",
    "credential_bruteforce": "enable_brute_force",
    "browser_interaction": "enable_browser",
    "request_mutation": "enable_request_mutation",
}

# Active browser tools that submit forms, click, or execute in-page JavaScript.
# Passive tools (navigate/read/screenshot/console/pentest-analysis) are NOT listed:
# they are reconnaissance and must never be gated.
BROWSER_INTERACTION_TOOLS = frozenset(
    {"chrome_click_element", "chrome_fill_or_select", "chrome_javascript"}
)

# Tools that send a crafted/raw HTTP request (proxy request-crafting, browser
# network context). Read-only proxy history (get_proxy_http_history) is excluded.
REQUEST_MUTATION_TOOLS = frozenset(
    {"chrome_network_request", "send_http1_request", "send_http2_request"}
)


def required_capability(action: str) -> Optional[str]:
    """Return the RiskyToolsConfig field that gates *action*, if any."""
    return CAPABILITY_BY_ACTION.get((action or "").strip().lower())


@dataclass
class ApprovalRequest:
    action: str
    tool: str
    target: str = ""
    reason: str = ""
    risk: str = RISK_HIGH
    scope_match: str = ""
    side_effects: list[str] = field(default_factory=list)
    sends_payload: bool = False
    mutates: bool = False

    def summary(self) -> str:
        """Human-readable approval block (shown before an interactive decision)."""
        return "\n".join(
            [
                "── Approval required ──",
                f"action:        {self.action}",
                f"tool:          {self.tool}",
                f"target:        {self.target or '(none)'}",
                f"risk:          {self.risk}",
                f"reason:        {self.reason or '(unspecified)'}",
                f"scope match:   {self.scope_match or 'n/a'}",
                f"side effects:  {', '.join(self.side_effects) or '(none stated)'}",
                f"sends payload: {self.sends_payload}",
                f"mutates state: {self.mutates}",
            ]
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "tool": self.tool,
            "target": self.target,
            "reason": self.reason,
            "risk": self.risk,
            "scope_match": self.scope_match,
            "side_effects": list(self.side_effects),
            "sends_payload": self.sends_payload,
            "mutates": self.mutates,
        }


@dataclass
class ApprovalDecision:
    outcome: str  # approved | denied | dry_run | not_required
    request: Optional[ApprovalRequest] = None
    reason: str = ""

    @property
    def allowed(self) -> bool:
        return self.outcome in ("approved", "not_required")

    @property
    def is_dry_run(self) -> bool:
        return self.outcome == "dry_run"

    def message(self) -> str:
        if self.outcome == "not_required":
            return ""
        if self.outcome == "dry_run":
            req = self.request
            body = req.summary() if req else ""
            return (
                "[dry-run] This high-risk action was NOT executed (approval mode is "
                f"dry-run).\n{body}"
            )
        if self.outcome == "denied":
            return (
                f"[approval_denied] {self.reason}. Provide a signed approval entry in your "
                ".vulnclaw-approvals.yaml (action/target/tool) or run in interactive mode "
                "with authorization."
            )
        return ""


def classify_risk(
    tool_name: str,
    args: Optional[dict[str, Any]] = None,
    *,
    target: str = "",
    action: str = "",
) -> Optional[ApprovalRequest]:
    """Return an ApprovalRequest when a tool call is high-risk, else None.

    *action* is the caller-supplied action class (e.g. from the agent's
    infer_tool_action). Keeping it a parameter avoids importing the agent layer.
    """
    name = (tool_name or "").strip().lower()
    act = (action or "").strip().lower()

    if name == "brute_force_login":
        return ApprovalRequest(
            action="credential_bruteforce",
            tool=name,
            target=target,
            risk=RISK_HIGH,
            reason="credential brute-force against a login form",
            sends_payload=True,
            side_effects=["repeated login attempts", "possible account lockout"],
        )
    if name in ("subdomain_enum", "space_search"):
        return ApprovalRequest(
            action="osint",
            tool=name,
            target=target,
            risk=RISK_MEDIUM,
            reason="OSINT / subdomain enumeration",
            side_effects=["queries third-party data sources"],
        )
    if name == "js_recon":
        return ApprovalRequest(
            action="js_secret_extraction",
            tool=name,
            target=target,
            risk=RISK_MEDIUM,
            reason="JavaScript endpoint and secret discovery",
            side_effects=["fetches target JS", "surfaces redacted secret fingerprints"],
        )
    if act == "post_exploitation":
        return ApprovalRequest(
            action="post_exploitation",
            tool=name,
            target=target,
            risk=RISK_CRITICAL,
            reason="post-exploitation action",
            sends_payload=True,
            mutates=True,
            side_effects=["operates on a compromised target"],
        )
    if act == "exploit":
        return ApprovalRequest(
            action="exploit",
            tool=name,
            target=target,
            risk=RISK_HIGH,
            reason="exploitation payload",
            sends_payload=True,
            mutates=True,
            side_effects=["sends an attack payload to the target"],
        )
    if name in REQUEST_MUTATION_TOOLS:
        return ApprovalRequest(
            action="request_mutation",
            tool=name,
            target=target,
            risk=RISK_HIGH,
            reason="sends a crafted HTTP request via proxy / browser network context",
            sends_payload=True,
            mutates=True,
            side_effects=["issues an attacker-controlled request against the target"],
        )
    if name in BROWSER_INTERACTION_TOOLS:
        return ApprovalRequest(
            action="browser_interaction",
            tool=name,
            target=target,
            risk=RISK_MEDIUM,
            reason="active browser interaction (form submission / click / in-page JS)",
            mutates=True,
            side_effects=["submits forms or executes JavaScript in the target page"],
        )
    return None


# ── Approval file / grants ─────────────────────────────────────────────


def _resolve_approval_path(config: Any) -> Optional[Path]:
    approval_cfg = getattr(config, "approval", None)
    configured = str(getattr(approval_cfg, "approval_file", "") or "").strip() if approval_cfg else ""
    if configured:
        return Path(configured).expanduser()
    candidates = [Path.cwd() / ".vulnclaw-approvals.yaml"]
    try:
        from vulnclaw.config.settings import CONFIG_DIR

        candidates.append(CONFIG_DIR / "approvals.yaml")
    except Exception:
        pass
    for cand in candidates:
        if cand.exists():
            return cand
    return None


def load_grants(config: Any) -> list[dict[str, Any]]:
    """Load approval grants from a signed approval file (``approvals:`` list)."""
    path = _resolve_approval_path(config)
    if path is None or not path.exists():
        return []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        grants = raw.get("approvals") or []
        return [g for g in grants if isinstance(g, dict)]
    except Exception:
        return []


def _field_ok(grant_value: Any, req_value: str) -> bool:
    gval = str(grant_value if grant_value is not None else "*").strip().lower()
    if gval in ("*", "all", ""):
        return True
    return gval == (req_value or "").strip().lower()


def _target_ok(grant_target: Any, req_target: str) -> bool:
    gval = str(grant_target if grant_target is not None else "*").strip().lower()
    if gval in ("*", "all", ""):
        return True
    rval = (req_target or "").strip().lower()
    # A grant target authorizes that host and any URL/subdomain containing it.
    return gval == rval or gval in rval


def _grant_matches(grant: dict[str, Any], req: ApprovalRequest) -> bool:
    return (
        _field_ok(grant.get("action"), req.action)
        and _field_ok(grant.get("tool"), req.tool)
        and _target_ok(grant.get("target"), req.target)
    )


def _default_prompt(request: ApprovalRequest) -> bool:
    """Prompt on a TTY; deny automatically when no TTY is attached."""
    try:
        if not sys.stdin.isatty():
            return False
        print(request.summary())
        answer = input("Approve this action? [y/N] ").strip().lower()
        return answer in ("y", "yes")
    except Exception:
        return False


class ApprovalGate:
    """Decides whether a risky action may proceed."""

    def __init__(
        self,
        *,
        mode: str = "non-interactive",
        require_approval: bool = True,
        grants: Optional[list[dict[str, Any]]] = None,
        prompt_fn: Optional[Callable[[ApprovalRequest], bool]] = None,
    ) -> None:
        self.mode = (mode or "non-interactive").strip().lower()
        self.require_approval = require_approval
        self.grants = grants or []
        self.prompt_fn = prompt_fn or _default_prompt

    @classmethod
    def from_config(
        cls, config: Any, *, prompt_fn: Optional[Callable[[ApprovalRequest], bool]] = None
    ) -> "ApprovalGate":
        approval_cfg = getattr(config, "approval", None)
        return cls(
            mode=getattr(approval_cfg, "mode", "non-interactive") if approval_cfg else "non-interactive",
            require_approval=bool(getattr(approval_cfg, "require_approval", True))
            if approval_cfg
            else True,
            grants=load_grants(config),
            prompt_fn=prompt_fn,
        )

    def evaluate(self, request: Optional[ApprovalRequest]) -> ApprovalDecision:
        if request is None:
            return ApprovalDecision("not_required")
        if not self.require_approval:
            return ApprovalDecision("approved", request, "approval not required by config")
        if self.mode == "dry-run":
            return ApprovalDecision("dry_run", request, "dry-run mode")
        if any(_grant_matches(g, request) for g in self.grants):
            return ApprovalDecision("approved", request, "matched signed approval grant")
        if self.mode == "interactive":
            ok = bool(self.prompt_fn(request))
            return ApprovalDecision(
                "approved" if ok else "denied",
                request,
                "interactive approval" if ok else "interactive denial",
            )
        return ApprovalDecision("denied", request, "no matching approval grant (non-interactive)")
