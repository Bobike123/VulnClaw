"""Scope enforcement at the central tool chokepoint + the fetch egress seam.

Proves that target-directed tool calls are deny-by-default (only localhost and
explicitly allowlisted targets run) and that denials never dispatch to a tool.
"""

from __future__ import annotations

from types import SimpleNamespace

from vulnclaw.agent import builtin_tools
from vulnclaw.agent.context import TaskConstraints
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.mcp.lifecycle import MCPLifecycleManager
from vulnclaw.safety.approval import ApprovalGate
from vulnclaw.safety.scope import Scope, ScopeAllow, ScopeFeatures, ScopeValidator


class _Session:
    def __init__(self) -> None:
        self.target = None
        self.task_constraints = TaskConstraints()
        self.events: list[dict] = []

    def add_constraint_violation_event(self, **kwargs) -> None:
        self.events.append(kwargs)


class _Mcp:
    def __init__(self) -> None:
        self.called: list[tuple] = []

    async def call_tool(self, name, args):
        self.called.append((name, args))
        return {"ok": True, "content": f"hit {args.get('url')}", "structured_content": {}}


def _agent(validator: ScopeValidator):
    agent = SimpleNamespace()
    agent.config = SimpleNamespace(safety=SimpleNamespace(enable_python_execute=False))
    agent.runtime = SimpleNamespace(python_timeout_rounds=0)
    agent.session_state = _Session()
    agent.mcp_manager = _Mcp()
    agent._scope_validator = validator
    return agent


def _enforcing(**scope_kwargs) -> ScopeValidator:
    return ScopeValidator(
        Scope(**scope_kwargs), enforce=True, allow_localhost=True, allow_private_lab=False
    )


class TestChokepoint:
    async def test_public_fetch_denied_and_not_dispatched(self):
        agent = _agent(_enforcing())
        result = await builtin_tools.execute_mcp_tool(
            agent, "fetch", {"url": "https://example.com/x"}
        )
        assert "scope_violation" in result
        assert agent.mcp_manager.called == []  # never dispatched
        assert any(e["code"] == "scope_denied" for e in agent.session_state.events)

    async def test_localhost_fetch_allowed(self):
        agent = _agent(_enforcing())
        result = await builtin_tools.execute_mcp_tool(
            agent, "fetch", {"url": "http://localhost:8080/app"}
        )
        assert "scope_violation" not in result
        assert "hit" in result
        assert agent.mcp_manager.called  # dispatched

    async def test_allowlisted_domain_allowed(self):
        agent = _agent(_enforcing(allow=ScopeAllow(domains=["target.test"])))
        result = await builtin_tools.execute_mcp_tool(
            agent, "fetch", {"url": "https://api.target.test/v1"}
        )
        assert "scope_violation" not in result
        assert agent.mcp_manager.called

    async def test_nmap_public_target_denied_before_run(self):
        agent = _agent(_enforcing())
        result = await builtin_tools.execute_mcp_tool(
            agent, "nmap_scan", {"target": "8.8.8.8", "scan_type": "tcp"}
        )
        assert "scope_violation" in result

    async def test_subdomain_enum_public_denied(self):
        agent = _agent(_enforcing())
        result = await builtin_tools.execute_mcp_tool(
            agent, "subdomain_enum", {"domain": "example.com"}
        )
        assert "scope_violation" in result

    async def test_python_execute_out_of_scope_url_denied(self):
        agent = _agent(_enforcing())
        result = await builtin_tools.execute_mcp_tool(
            agent,
            "python_execute",
            {"code": "import requests\nrequests.get('http://example.com/x')"},
        )
        assert "scope_violation" in result

    async def test_enforce_disabled_allows_public(self):
        agent = _agent(ScopeValidator(Scope(), enforce=False))
        result = await builtin_tools.execute_mcp_tool(
            agent, "fetch", {"url": "https://example.com/x"}
        )
        assert "scope_violation" not in result
        assert agent.mcp_manager.called


class TestExtractTargets:
    def test_unauth_test_targets(self):
        targets = builtin_tools.extract_scope_targets(
            "unauth_test",
            {"base_url": "https://t.test", "endpoints": ["https://t.test/a", "/b"]},
        )
        assert "https://t.test" in targets
        assert "https://t.test/a" in targets

    def test_brute_force_targets(self):
        targets = builtin_tools.extract_scope_targets(
            "brute_force_login", {"url": "http://t.test/login", "submit_action": "http://t.test/do"}
        )
        assert "http://t.test/login" in targets
        assert "http://t.test/do" in targets


def _risky_agent(*, gate, osint_feature=False, **enables):
    """Agent stub with target.test allowlisted + exploit_validation phase allowed."""
    validator = ScopeValidator(
        Scope(
            allow=ScopeAllow(domains=["target.test"]),
            allowed_phases=["recon", "scan", "exploit_validation"],
            features=ScopeFeatures(osint=osint_feature),
        ),
        enforce=True,
        allow_localhost=True,
    )
    risky = SimpleNamespace(
        enable_exploit=enables.get("enable_exploit", False),
        enable_post_exploitation=enables.get("enable_post_exploitation", False),
        enable_waf_bypass=False,
        enable_persistent=False,
        enable_poc_generation=False,
        enable_js_secret_extraction=enables.get("enable_js_secret_extraction", False),
        enable_osint=enables.get("enable_osint", False),
        enable_brute_force=enables.get("enable_brute_force", False),
        enable_browser=enables.get("enable_browser", False),
        enable_request_mutation=enables.get("enable_request_mutation", False),
    )
    agent = SimpleNamespace()
    agent.config = SimpleNamespace(risky_tools=risky)
    agent.runtime = SimpleNamespace(python_timeout_rounds=0)
    agent.session_state = _Session()
    agent.mcp_manager = _Mcp()
    agent._scope_validator = validator
    agent._approval_gate = gate
    return agent


_EXPLOIT_URL = "https://target.test/x?id=1' OR 1=1"


class TestApprovalGating:
    async def test_non_risky_recon_not_gated(self):
        agent = _risky_agent(gate=ApprovalGate(mode="non-interactive", grants=[]))
        result = await builtin_tools.execute_mcp_tool(
            agent, "fetch", {"url": "https://target.test/", "method": "GET"}
        )
        assert "risky_tool_disabled" not in result
        assert agent.mcp_manager.called  # dispatched

    async def test_exploit_disabled_by_default(self):
        agent = _risky_agent(gate=ApprovalGate(grants=[]))
        result = await builtin_tools.execute_mcp_tool(
            agent, "fetch", {"url": _EXPLOIT_URL, "method": "GET"}
        )
        assert "risky_tool_disabled" in result
        assert agent.mcp_manager.called == []

    async def test_exploit_enabled_but_no_approval_denied(self):
        agent = _risky_agent(gate=ApprovalGate(mode="non-interactive", grants=[]), enable_exploit=True)
        result = await builtin_tools.execute_mcp_tool(
            agent, "fetch", {"url": _EXPLOIT_URL, "method": "GET"}
        )
        assert "approval_denied" in result
        assert agent.mcp_manager.called == []

    async def test_exploit_enabled_and_approved_runs(self):
        gate = ApprovalGate(
            mode="non-interactive", grants=[{"action": "exploit", "target": "target.test"}]
        )
        agent = _risky_agent(gate=gate, enable_exploit=True)
        result = await builtin_tools.execute_mcp_tool(
            agent, "fetch", {"url": _EXPLOIT_URL, "method": "GET"}
        )
        assert "hit" in result
        assert agent.mcp_manager.called

    async def test_exploit_dry_run_does_not_execute(self):
        agent = _risky_agent(gate=ApprovalGate(mode="dry-run"), enable_exploit=True)
        result = await builtin_tools.execute_mcp_tool(
            agent, "fetch", {"url": _EXPLOIT_URL, "method": "GET"}
        )
        assert "dry-run" in result
        assert agent.mcp_manager.called == []

    async def test_js_secret_extraction_disabled(self):
        agent = _risky_agent(gate=ApprovalGate(grants=[]))
        result = await builtin_tools.execute_mcp_tool(
            agent, "js_recon", {"url": "https://target.test/app.js"}
        )
        assert "risky_tool_disabled" in result

    async def test_osint_disabled(self):
        agent = _risky_agent(gate=ApprovalGate(grants=[]))
        result = await builtin_tools.execute_mcp_tool(
            agent, "subdomain_enum", {"domain": "target.test"}
        )
        assert "risky_tool_disabled" in result

    async def test_osint_enabled_but_scope_feature_off(self):
        agent = _risky_agent(gate=ApprovalGate(grants=[{"action": "*", "target": "*"}]),
                             enable_osint=True, osint_feature=False)
        result = await builtin_tools.execute_mcp_tool(
            agent, "subdomain_enum", {"domain": "target.test"}
        )
        assert "OSINT not permitted" in result

    async def test_request_mutation_disabled_by_default(self):
        agent = _risky_agent(gate=ApprovalGate(grants=[]))
        result = await builtin_tools.execute_mcp_tool(
            agent, "send_http1_request", {"url": "https://target.test/x", "method": "POST"}
        )
        assert "risky_tool_disabled" in result
        assert agent.mcp_manager.called == []

    async def test_request_mutation_enabled_and_approved_runs(self):
        gate = ApprovalGate(
            mode="non-interactive", grants=[{"action": "request_mutation", "target": "target.test"}]
        )
        agent = _risky_agent(gate=gate, enable_request_mutation=True)
        result = await builtin_tools.execute_mcp_tool(
            agent, "send_http1_request", {"url": "https://target.test/x", "method": "POST"}
        )
        assert "hit" in result
        assert agent.mcp_manager.called

    async def test_browser_interaction_disabled_by_default(self):
        agent = _risky_agent(gate=ApprovalGate(grants=[]))
        result = await builtin_tools.execute_mcp_tool(
            agent, "chrome_click_element", {"selector": "#submit"}
        )
        assert "risky_tool_disabled" in result
        assert agent.mcp_manager.called == []


class TestBudgetChokepoint:
    async def test_tripped_budget_blocks_dispatch(self):
        from vulnclaw.safety.budget import Budget

        agent = _agent(_enforcing())
        agent._budget = Budget(max_tool_calls=1).start()
        agent._budget.trip()  # emergency stop
        result = await builtin_tools.execute_mcp_tool(
            agent, "fetch", {"url": "http://localhost/", "method": "GET"}
        )
        assert "[budget]" in result
        assert agent.mcp_manager.called == []

    async def test_tool_call_ceiling_enforced(self):
        from vulnclaw.safety.budget import Budget

        agent = _agent(_enforcing())
        agent._budget = Budget(max_tool_calls=1).start()
        # first call is under budget and dispatches
        r1 = await builtin_tools.execute_mcp_tool(
            agent, "fetch", {"url": "http://localhost/a", "method": "GET"}
        )
        assert "hit" in r1
        # second call trips the tool-call ceiling and is not dispatched
        r2 = await builtin_tools.execute_mcp_tool(
            agent, "fetch", {"url": "http://localhost/b", "method": "GET"}
        )
        assert "[budget]" in r2
        assert len(agent.mcp_manager.called) == 1

    async def test_no_budget_is_inert(self):
        agent = _agent(_enforcing())
        result = await builtin_tools.execute_mcp_tool(
            agent, "fetch", {"url": "http://localhost/", "method": "GET"}
        )
        assert "hit" in result


class TestFetchEgressSeam:
    def _manager(self, validator) -> MCPLifecycleManager:
        m = MCPLifecycleManager(VulnClawConfig())
        m.set_scope(validator)
        return m

    def test_out_of_scope_fetch_denied_at_egress(self):
        m = self._manager(_enforcing())
        res = m._check_fetch_constraints({"url": "https://example.com/x"})
        assert res is not None
        assert res["error_type"] == "scope_violation"

    def test_localhost_fetch_allowed_at_egress(self):
        m = self._manager(_enforcing())
        assert m._check_fetch_constraints({"url": "http://localhost:8080/"}) is None

    def test_no_scope_set_is_inert(self):
        m = MCPLifecycleManager(VulnClawConfig())  # no set_scope
        assert m._check_fetch_constraints({"url": "https://example.com/x"}) is None
