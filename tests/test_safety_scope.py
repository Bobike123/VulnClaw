"""Tests for the engagement scope model + ScopeValidator (deny-by-default)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.safety.scope import (
    Scope,
    ScopeAllow,
    ScopeDeny,
    ScopeFeatures,
    ScopeValidator,
    load_scope,
)


def _validator(**scope_kwargs) -> ScopeValidator:
    """Build an enforcing validator with only localhost baseline enabled."""
    scope = Scope(**scope_kwargs)
    return ScopeValidator(
        scope,
        enforce=True,
        allow_localhost=True,
        allow_private_lab=False,
        allow_public=False,
    )


class TestDefaultDeny:
    def test_public_denied_by_default(self):
        v = _validator()
        assert v.check_host("example.com").allowed is False

    def test_localhost_allowed_by_default(self):
        v = _validator()
        assert v.check_host("localhost").allowed is True
        assert v.check_host("127.0.0.1").allowed is True
        assert v.check_host("::1").allowed is True

    def test_private_denied_unless_enabled(self):
        v = _validator()
        assert v.check_host("10.0.0.5").allowed is False
        assert v.check_host("192.168.1.10").allowed is False

    def test_private_allowed_when_baseline_enabled(self):
        scope = Scope()
        v = ScopeValidator(scope, allow_localhost=True, allow_private_lab=True)
        assert v.check_host("10.0.0.5").allowed is True
        assert v.check_host("192.168.1.10").allowed is True
        # Public still denied.
        assert v.check_host("8.8.8.8").allowed is False

    def test_enforce_disabled_allows_everything(self):
        scope = Scope()
        v = ScopeValidator(scope, enforce=False)
        assert v.check_host("evil.example.com").allowed is True
        assert v.check_url("http://8.8.8.8/x").allowed is True


class TestDomainMatching:
    def test_exact_domain_allowed(self):
        v = _validator(allow=ScopeAllow(domains=["target.test"]))
        assert v.check_host("target.test").allowed is True

    def test_subdomain_allowed_by_default(self):
        v = _validator(allow=ScopeAllow(domains=["target.test"]))
        assert v.check_host("api.target.test").allowed is True
        assert v.check_host("a.b.target.test").allowed is True

    def test_unrelated_domain_denied(self):
        v = _validator(allow=ScopeAllow(domains=["target.test"]))
        assert v.check_host("target.test.evil.com").allowed is False
        assert v.check_host("nottarget.test").allowed is False

    def test_exact_only_prefix(self):
        v = _validator(allow=ScopeAllow(domains=["=api.target.test"]))
        assert v.check_host("api.target.test").allowed is True
        # Subdomains of an exact-only entry are NOT allowed.
        assert v.check_host("x.api.target.test").allowed is False

    def test_wildcard_prefix(self):
        v = _validator(allow=ScopeAllow(domains=["*.target.test"]))
        assert v.check_host("target.test").allowed is True
        assert v.check_host("api.target.test").allowed is True


class TestIPAndCIDR:
    def test_exact_ip_allowed(self):
        v = _validator(allow=ScopeAllow(ip_ranges=["203.0.113.5/32"]))
        assert v.check_host("203.0.113.5").allowed is True
        assert v.check_host("203.0.113.6").allowed is False

    def test_cidr_range_allowed(self):
        v = _validator(allow=ScopeAllow(ip_ranges=["203.0.113.0/24"]))
        assert v.check_host("203.0.113.1").allowed is True
        assert v.check_host("203.0.113.254").allowed is True
        assert v.check_host("203.0.114.1").allowed is False

    def test_ipv6_cidr(self):
        v = _validator(allow=ScopeAllow(ip_ranges=["2001:db8::/32"]))
        assert v.check_host("2001:db8::1").allowed is True
        assert v.check_host("2001:dead::1").allowed is False

    def test_v4_entry_does_not_match_v6_target(self):
        v = _validator(allow=ScopeAllow(ip_ranges=["10.0.0.0/8"]))
        # Version mismatch must not raise and must not spuriously allow.
        assert v.check_host("2001:db8::1").allowed is False


class TestDenyPrecedence:
    def test_deny_domain_overrides_allow(self):
        v = _validator(
            allow=ScopeAllow(domains=["target.test"]),
            deny=ScopeDeny(domains=["admin.target.test"]),
        )
        assert v.check_host("www.target.test").allowed is True
        # Denied subdomain wins even though the parent is allowed.
        assert v.check_host("admin.target.test").allowed is False

    def test_deny_ip_overrides_allow_cidr(self):
        v = _validator(
            allow=ScopeAllow(ip_ranges=["10.10.0.0/16"]),
            deny=ScopeDeny(ip_ranges=["10.10.0.1/32"]),
        )
        assert v.check_host("10.10.5.5").allowed is True
        assert v.check_host("10.10.0.1").allowed is False

    def test_deny_overrides_localhost_baseline(self):
        v = _validator(deny=ScopeDeny(ip_ranges=["127.0.0.1/32"]))
        assert v.check_host("127.0.0.1").allowed is False


class TestPorts:
    def test_any_port_when_unset(self):
        v = _validator(allow=ScopeAllow(domains=["target.test"]))
        assert v.check_port(8443, host="target.test").allowed is True

    def test_port_allowlist(self):
        v = _validator(allow=ScopeAllow(domains=["target.test"], ports=[80, 443]))
        assert v.check_port(443, host="target.test").allowed is True
        assert v.check_port(3306, host="target.test").allowed is False


class TestUrl:
    def test_url_host_and_port(self):
        v = _validator(allow=ScopeAllow(domains=["target.test"], ports=[443]))
        assert v.check_url("https://api.target.test/x").allowed is True
        assert v.check_url("http://api.target.test/x").allowed is False  # port 80 not allowed
        assert v.check_url("https://evil.com/x").allowed is False

    def test_url_prefix_allowlist(self):
        v = _validator(
            allow=ScopeAllow(domains=["target.test"], url_prefixes=["https://target.test/app/"])
        )
        assert v.check_url("https://target.test/app/login").allowed is True
        assert v.check_url("https://target.test/admin").allowed is False


class TestPhasesAndFeatures:
    def test_default_phases(self):
        v = _validator()
        assert v.check_phase("recon") is True
        assert v.check_phase("scan") is True
        assert v.check_phase("report") is True
        # Exploitation is deny-by-default.
        assert v.check_phase("exploit_validation") is False

    def test_scope_file_phase_allowlist(self):
        v = _validator(allowed_phases=["recon", "exploit_validation"])
        assert v.check_phase("exploit_validation") is True
        assert v.check_phase("scan") is False

    def test_features_default_deny(self):
        v = _validator()
        assert v.is_feature_allowed("osint") is False
        assert v.is_feature_allowed("browser_automation") is False
        assert v.is_feature_allowed("burp") is False
        assert v.is_feature_allowed("poc_generation") is False

    def test_features_opt_in(self):
        v = _validator(features=ScopeFeatures(osint=True, burp=True))
        assert v.is_feature_allowed("osint") is True
        assert v.is_feature_allowed("burp") is True
        assert v.is_feature_allowed("browser_automation") is False


class TestLoadScope:
    def test_load_from_file(self, tmp_path, monkeypatch):
        scope_file = tmp_path / ".vulnclaw-scope.yaml"
        scope_file.write_text(
            "allow:\n"
            "  domains: [lab.test]\n"
            "  ports: [80, 443]\n"
            "deny:\n"
            "  domains: [secret.lab.test]\n"
            "features:\n"
            "  osint: true\n",
            encoding="utf-8",
        )
        scope_cfg = SimpleNamespace(
            scope_file=str(scope_file),
            enforce=True,
            allow_localhost=True,
            allow_private_lab=False,
            allow_public=False,
        )
        cfg = SimpleNamespace(scope=scope_cfg)

        v = ScopeValidator.from_config(cfg)
        assert v.check_host("api.lab.test").allowed is True
        assert v.check_host("secret.lab.test").allowed is False
        assert v.is_feature_allowed("osint") is True
        assert v.scope.loaded_from == str(scope_file)

    def test_missing_file_returns_defaults(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)  # no .vulnclaw-scope.yaml here
        cfg = SimpleNamespace(scope=None)

        scope = load_scope(cfg)
        assert scope.loaded_from == "<defaults>"
        assert scope.allow.domains == []

    def test_invalid_file_degrades_safely(self, tmp_path):
        bad = tmp_path / "scope.yaml"
        bad.write_text("allow: [not, a, mapping]\n", encoding="utf-8")
        scope_cfg = SimpleNamespace(
            scope_file=str(bad),
            enforce=True,
            allow_localhost=True,
            allow_private_lab=False,
            allow_public=False,
        )
        cfg = SimpleNamespace(scope=scope_cfg)

        v = ScopeValidator.from_config(cfg)
        # Degrades to defaults (localhost-only), still enforcing.
        assert v.check_host("example.com").allowed is False
        assert v.check_host("localhost").allowed is True


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
