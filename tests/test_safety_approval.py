"""Tests for the human-approval gate (vulnclaw.safety.approval)."""

from __future__ import annotations

from types import SimpleNamespace

from vulnclaw.safety.approval import (
    ApprovalGate,
    ApprovalRequest,
    classify_risk,
    required_capability,
)


class TestClassifyRisk:
    def test_recon_is_not_risky(self):
        assert classify_risk("fetch", {"url": "http://x/"}, action="recon") is None
        assert classify_risk("nmap_scan", {"target": "x"}, action="recon") is None

    def test_exploit_is_high_risk(self):
        req = classify_risk("fetch", {"url": "http://x/?id=1' OR 1=1"}, action="exploit")
        assert req is not None
        assert req.action == "exploit"
        assert req.risk == "high"
        assert req.sends_payload is True

    def test_post_exploitation_is_critical(self):
        req = classify_risk("python_execute", {}, action="post_exploitation")
        assert req.action == "post_exploitation"
        assert req.risk == "critical"

    def test_brute_force_is_risky(self):
        req = classify_risk("brute_force_login", {"url": "http://x/login"}, action="scan")
        assert req.action == "credential_bruteforce"

    def test_osint_is_risky(self):
        req = classify_risk("subdomain_enum", {"domain": "x.com"}, action="recon")
        assert req.action == "osint"

    def test_js_recon_is_risky(self):
        req = classify_risk("js_recon", {"url": "http://x/"}, action="recon")
        assert req.action == "js_secret_extraction"

    def test_request_mutation_tools_are_risky(self):
        for tool in ("send_http1_request", "send_http2_request", "chrome_network_request"):
            req = classify_risk(tool, {"url": "http://x/"}, action="scan")
            assert req is not None, tool
            assert req.action == "request_mutation"
            assert req.risk == "high"
            assert req.sends_payload is True

    def test_browser_interaction_tools_are_risky(self):
        for tool in ("chrome_click_element", "chrome_fill_or_select", "chrome_javascript"):
            req = classify_risk(tool, {"selector": "#go"}, action="scan")
            assert req is not None, tool
            assert req.action == "browser_interaction"
            assert req.mutates is True

    def test_passive_browser_tools_are_not_risky(self):
        for tool in (
            "chrome_navigate",
            "chrome_read_page",
            "chrome_screenshot",
            "chrome_get_web_content",
            "get_proxy_http_history",
        ):
            assert classify_risk(tool, {"url": "http://x/"}, action="recon") is None, tool

    def test_summary_shows_required_fields(self):
        req = classify_risk("fetch", {}, target="x.com", action="exploit")
        text = req.summary()
        for field in ("action", "tool", "target", "risk", "reason", "scope match",
                      "side effects", "sends payload", "mutates state"):
            assert field in text


class TestRequiredCapability:
    def test_maps_actions_to_switches(self):
        assert required_capability("exploit") == "enable_exploit"
        assert required_capability("osint") == "enable_osint"
        assert required_capability("credential_bruteforce") == "enable_brute_force"
        assert required_capability("browser_interaction") == "enable_browser"
        assert required_capability("request_mutation") == "enable_request_mutation"
        assert required_capability("recon") is None


def _req() -> ApprovalRequest:
    return ApprovalRequest(action="exploit", tool="fetch", target="lab.test", risk="high")


class TestApprovalGate:
    def test_none_request_not_required(self):
        gate = ApprovalGate()
        assert gate.evaluate(None).outcome == "not_required"

    def test_non_interactive_denies_without_grant(self):
        gate = ApprovalGate(mode="non-interactive", grants=[])
        decision = gate.evaluate(_req())
        assert decision.outcome == "denied"
        assert decision.allowed is False

    def test_dry_run_never_executes(self):
        gate = ApprovalGate(mode="dry-run")
        decision = gate.evaluate(_req())
        assert decision.outcome == "dry_run"
        assert decision.allowed is False
        assert "dry-run" in decision.message()

    def test_matching_grant_approves(self):
        gate = ApprovalGate(
            mode="non-interactive",
            grants=[{"action": "exploit", "target": "lab.test", "tool": "*"}],
        )
        assert gate.evaluate(_req()).outcome == "approved"

    def test_non_matching_grant_denied(self):
        gate = ApprovalGate(
            mode="non-interactive",
            grants=[{"action": "exploit", "target": "other.test"}],
        )
        assert gate.evaluate(_req()).outcome == "denied"

    def test_wildcard_grant_approves(self):
        gate = ApprovalGate(mode="non-interactive", grants=[{"action": "*", "target": "*"}])
        assert gate.evaluate(_req()).outcome == "approved"

    def test_target_grant_matches_url(self):
        gate = ApprovalGate(mode="non-interactive", grants=[{"action": "exploit", "target": "lab.test"}])
        req = ApprovalRequest(action="exploit", tool="fetch", target="https://api.lab.test/x")
        assert gate.evaluate(req).outcome == "approved"

    def test_interactive_uses_prompt(self):
        approving = ApprovalGate(mode="interactive", prompt_fn=lambda r: True)
        denying = ApprovalGate(mode="interactive", prompt_fn=lambda r: False)
        assert approving.evaluate(_req()).outcome == "approved"
        assert denying.evaluate(_req()).outcome == "denied"

    def test_require_approval_disabled_approves(self):
        gate = ApprovalGate(require_approval=False)
        assert gate.evaluate(_req()).outcome == "approved"


class TestFromConfigAndGrants:
    def test_loads_grants_from_file(self, tmp_path):
        approvals = tmp_path / ".vulnclaw-approvals.yaml"
        approvals.write_text(
            "approvals:\n  - action: exploit\n    target: lab.test\n    tool: fetch\n",
            encoding="utf-8",
        )
        cfg = SimpleNamespace(
            approval=SimpleNamespace(
                mode="non-interactive", require_approval=True, approval_file=str(approvals)
            )
        )
        gate = ApprovalGate.from_config(cfg)
        assert gate.evaluate(_req()).outcome == "approved"

    def test_missing_file_denies(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = SimpleNamespace(
            approval=SimpleNamespace(mode="non-interactive", require_approval=True, approval_file="")
        )
        gate = ApprovalGate.from_config(cfg)
        assert gate.evaluate(_req()).outcome == "denied"
