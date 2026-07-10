"""Engagement scope — the central network-authorization boundary.

Every target-directed network action must pass through a :class:`ScopeValidator`.
The model is **deny-by-default**: only hosts/IPs explicitly allowed by the scope
file (or by a deliberately enabled baseline: localhost, and optionally private-lab
or public) are in scope. Denied entries always win over allow entries.

The validator works on the literal host/IP/URL it is given and never performs DNS
resolution itself — that keeps decisions deterministic, testable, and free of
surprise lookups. Callers that resolve a name to an IP should validate both.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field

# Phases permitted when a scope file does not restrict them. exploit_validation
# is intentionally excluded so exploitation stays deny-by-default.
DEFAULT_ALLOWED_PHASES = ("recon", "scan", "report")

VALID_PHASES = ("recon", "scan", "exploit_validation", "report")


# ── Scope file model ───────────────────────────────────────────────────


class ScopeAllow(BaseModel):
    domains: list[str] = Field(default_factory=list)
    ip_ranges: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    url_prefixes: list[str] = Field(default_factory=list)


class ScopeDeny(BaseModel):
    domains: list[str] = Field(default_factory=list)
    ip_ranges: list[str] = Field(default_factory=list)


class ScopeLimits(BaseModel):
    # 0 / 0.0 means "unset" — the caller falls back to its own defaults.
    max_request_rate: float = Field(default=0.0)
    max_concurrency: int = Field(default=0)


class ScopeFeatures(BaseModel):
    osint: bool = False
    browser_automation: bool = False
    burp: bool = False
    poc_generation: bool = False


class Scope(BaseModel):
    """Parsed contents of a ``.vulnclaw-scope.yaml`` file."""

    engagement: str = ""
    authorized_by: str = ""
    allow: ScopeAllow = Field(default_factory=ScopeAllow)
    deny: ScopeDeny = Field(default_factory=ScopeDeny)
    limits: ScopeLimits = Field(default_factory=ScopeLimits)
    allowed_phases: list[str] = Field(default_factory=list)
    features: ScopeFeatures = Field(default_factory=ScopeFeatures)
    # Where this scope came from (a path, or "<defaults>"). Not from the file.
    loaded_from: str = ""


# ── Decision object ─────────────────────────────────────────────────────


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    target: str = ""
    category: str = ""

    def error_message(self) -> str:
        """A clear, user-facing out-of-scope message (safe for tool output)."""
        return (
            f"[scope_violation] {self.target or 'target'} is out of scope: {self.reason}. "
            "Add it to your .vulnclaw-scope.yaml allowlist (with authorization) or "
            "adjust scope settings; VulnClaw is deny-by-default for out-of-scope targets."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "target": self.target,
            "category": self.category,
        }


def _allow(target: str, reason: str, category: str = "") -> ScopeDecision:
    return ScopeDecision(allowed=True, reason=reason, target=target, category=category)


def _deny(target: str, reason: str, category: str = "") -> ScopeDecision:
    return ScopeDecision(allowed=False, reason=reason, target=target, category=category)


# ── Matching helpers ─────────────────────────────────────────────────────


def _normalize_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def _as_ip(host: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _host_matches(host: str, entries: list[str]) -> bool:
    """Match a hostname against domain entries with subdomain semantics.

    - ``example.com``   matches ``example.com`` and any subdomain of it.
    - ``=api.x.com``    matches only ``api.x.com`` (exact, no subdomains).
    - ``*.example.com`` matches the base and any subdomain.
    """
    host = _normalize_host(host)
    if not host:
        return False
    for raw in entries:
        entry = (raw or "").strip().lower().rstrip(".")
        if not entry:
            continue
        if entry.startswith("="):
            if host == entry[1:]:
                return True
        elif entry.startswith("*."):
            base = entry[2:]
            if host == base or host.endswith("." + base):
                return True
        else:
            if host == entry or host.endswith("." + entry):
                return True
    return False


def _ip_in_ranges(addr: ipaddress._BaseAddress, ranges: list[str]) -> bool:
    for raw in ranges:
        entry = (raw or "").strip()
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if net.version == addr.version and addr in net:
            return True
    return False


def _ip_category(addr: ipaddress._BaseAddress) -> str:
    if addr.is_loopback:
        return "localhost"
    if addr.is_private or addr.is_link_local:
        return "private"
    return "public"


def _host_category(host: str) -> str:
    if host == "localhost" or host.endswith(".localhost"):
        return "localhost"
    # A non-IP hostname cannot be classified as private without DNS, so it is
    # treated as public (unknown) and therefore denied unless explicitly allowed.
    return "public"


# ── Validator ─────────────────────────────────────────────────────────────


class ScopeValidator:
    """Validates hosts / IPs / URLs / ports / phases / features against scope."""

    def __init__(
        self,
        scope: Scope,
        *,
        enforce: bool = True,
        allow_localhost: bool = True,
        allow_private_lab: bool = False,
        allow_public: bool = False,
    ) -> None:
        self.scope = scope
        self.enforce = enforce
        self.allow_localhost = allow_localhost
        self.allow_private_lab = allow_private_lab
        self.allow_public = allow_public

    # -- construction --------------------------------------------------------

    @classmethod
    def from_config(cls, config: Any) -> "ScopeValidator":
        scope_cfg = getattr(config, "scope", None)
        scope = load_scope(config)
        if scope_cfg is None:
            return cls(scope)
        return cls(
            scope,
            enforce=bool(getattr(scope_cfg, "enforce", True)),
            allow_localhost=bool(getattr(scope_cfg, "allow_localhost", True)),
            allow_private_lab=bool(getattr(scope_cfg, "allow_private_lab", False)),
            allow_public=bool(getattr(scope_cfg, "allow_public", False)),
        )

    # -- host / ip -----------------------------------------------------------

    def check_host(self, host: str) -> ScopeDecision:
        if not self.enforce:
            return _allow(host, "scope enforcement disabled")
        host = _normalize_host(host)
        if not host:
            return _allow(host, "no host to check")

        addr = _as_ip(host)

        # Deny precedence — a denied entry always wins.
        if addr is not None:
            if _ip_in_ranges(addr, self.scope.deny.ip_ranges):
                return _deny(host, "matches a denied IP range", _ip_category(addr))
        elif _host_matches(host, self.scope.deny.domains):
            return _deny(host, "matches a denied domain", "denied")

        # Explicit allowlist.
        if addr is not None:
            if _ip_in_ranges(addr, self.scope.allow.ip_ranges):
                return _allow(host, "in allowed IP ranges", _ip_category(addr))
            category = _ip_category(addr)
        else:
            if _host_matches(host, self.scope.allow.domains):
                return _allow(host, "in allowed domains", "allowlisted")
            category = _host_category(host)

        # Baseline allowances by category.
        if category == "localhost" and self.allow_localhost:
            return _allow(host, "localhost baseline", category)
        if category == "private" and self.allow_private_lab:
            return _allow(host, "private-lab baseline (allow_private_lab)", category)
        if category == "public" and self.allow_public:
            return _allow(host, "public baseline (allow_public)", category)

        return _deny(
            host,
            f"not in engagement scope ({category})",
            category,
        )

    def check_ip(self, ip: str) -> ScopeDecision:
        return self.check_host(ip)

    # -- port ----------------------------------------------------------------

    def check_port(self, port: Optional[int], *, host: str = "") -> ScopeDecision:
        if not self.enforce or port is None:
            return _allow(host or str(port), "no port constraint")
        ports = self.scope.allow.ports
        if ports and port not in ports:
            return _deny(
                host or str(port),
                f"port {port} is not in the allowed ports {sorted(ports)}",
            )
        return _allow(host or str(port), "port allowed")

    # -- url -----------------------------------------------------------------

    def check_url(self, url: str) -> ScopeDecision:
        if not self.enforce:
            return _allow(url, "scope enforcement disabled")
        try:
            parsed = urlparse(url)
        except Exception:
            return _deny(url, "unparseable URL")

        host = parsed.hostname or ""
        decision = self.check_host(host)
        if not decision.allowed:
            decision.target = url
            return decision

        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None
        port_decision = self.check_port(port, host=host)
        if not port_decision.allowed:
            port_decision.target = url
            return port_decision

        prefixes = self.scope.allow.url_prefixes
        if prefixes and not any(url.startswith(p) for p in prefixes):
            return _deny(url, "URL is not under an allowed url_prefix")

        return _allow(url, decision.reason, decision.category)

    # -- phases / features ---------------------------------------------------

    def check_phase(self, phase: str) -> bool:
        allowed = self.scope.allowed_phases or list(DEFAULT_ALLOWED_PHASES)
        norm = (phase or "").strip().lower()
        return norm in {p.strip().lower() for p in allowed}

    def is_feature_allowed(self, name: str) -> bool:
        return bool(getattr(self.scope.features, name, False))

    # -- limits --------------------------------------------------------------

    @property
    def max_request_rate(self) -> float:
        return self.scope.limits.max_request_rate

    @property
    def max_concurrency(self) -> int:
        return self.scope.limits.max_concurrency

    @property
    def summary(self) -> str:
        s = self.scope
        parts = [
            f"scope: {s.loaded_from or '<defaults>'}",
            f"enforce={self.enforce}",
            f"localhost={self.allow_localhost}",
            f"private_lab={self.allow_private_lab}",
            f"public={self.allow_public}",
        ]
        if s.allow.domains:
            parts.append(f"domains={s.allow.domains}")
        if s.allow.ip_ranges:
            parts.append(f"ip_ranges={s.allow.ip_ranges}")
        return " | ".join(parts)


# ── Loading ────────────────────────────────────────────────────────────────


def _resolve_scope_path(config: Any) -> Optional[Path]:
    scope_cfg = getattr(config, "scope", None)
    configured = str(getattr(scope_cfg, "scope_file", "") or "").strip() if scope_cfg else ""
    if configured:
        return Path(configured).expanduser()

    candidates = [Path.cwd() / ".vulnclaw-scope.yaml"]
    try:
        from vulnclaw.config.settings import CONFIG_DIR

        candidates.append(CONFIG_DIR / "scope.yaml")
    except Exception:
        pass
    for cand in candidates:
        if cand.exists():
            return cand
    return None


def load_scope(config: Any) -> Scope:
    """Load the engagement scope from a file, or return a defaults-only Scope."""
    path = _resolve_scope_path(config)
    if path is not None and path.exists():
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            scope = Scope.model_validate(raw)
            scope.loaded_from = str(path)
            return scope
        except Exception as exc:  # noqa: BLE001 - degrade safely to defaults
            scope = Scope(loaded_from=f"<invalid:{path}: {exc}>")
            return scope
    return Scope(loaded_from="<defaults>")


def build_scope_validator(config: Any) -> ScopeValidator:
    """Convenience: build a ScopeValidator from a VulnClawConfig."""
    return ScopeValidator.from_config(config)
