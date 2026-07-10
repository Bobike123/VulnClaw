"""Central secret-redaction utility.

Every log line, audit record, report, terminal message, and exception that could
contain a credential MUST pass through :func:`redact` first. Never write raw
secrets to disk, logs, reports, or the model context.

The redaction token preserves the secret *type* and a short, non-reversible
fingerprint (SHA-256 prefix) so an operator can correlate repeated occurrences of
the same secret across logs without ever seeing its value.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

_TOKEN = "[REDACTED:{label}:{fp}]"

# Common non-secret literals that must never be treated as a credential value
# when they appear on the right-hand side of a ``key = value`` assignment.
_NON_SECRET_LITERALS = {
    "true",
    "false",
    "null",
    "none",
    "undefined",
    "nil",
    "yes",
    "no",
    "example",
    "changeme",
    "your-key-here",
    "xxx",
}


def fingerprint(secret: str) -> str:
    """Return a short, non-reversible fingerprint of *secret* (SHA-256 prefix)."""
    return hashlib.sha256(str(secret).encode("utf-8", "replace")).hexdigest()[:12]


def _token(label: str, secret: str) -> str:
    return _TOKEN.format(label=label, fp=fingerprint(secret))


# ── Private-key blocks (PEM) — redacted whole ──────────────────────────
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
    r".*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
    re.DOTALL,
)

# ── Standalone token patterns — the whole match is the secret ──────────
# Order matters: more specific patterns first (anthropic before openai, etc.).
_TOKEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{16,}")),
    ("openai_key", re.compile(r"sk-(?!ant-)[A-Za-z0-9_-]{20,}")),
    ("aws_access_key_id", re.compile(r"(?<![A-Z0-9])A(?:KIA|SIA)[0-9A-Z]{16}(?![A-Z0-9])")),
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    ("github_token", re.compile(r"gh[posur]_[A-Za-z0-9]{36,}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("supabase_pat", re.compile(r"sbp_[A-Za-z0-9]{40}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    # JSON Web Token (also covers Supabase anon/service_role keys, which are JWTs).
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{4,}")),
]

# ── Bearer tokens — redact only the credential after the scheme ────────
_BEARER_RE = re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._~+/=-]{8,})")

# ── key = value / "key": "value" assignments (covers .env, JSON, dicts) ─
# The value class excludes brackets so an already-inserted [REDACTED:..] token
# is never re-matched and double-redacted.
_ASSIGNMENT_RE = re.compile(
    r"(?i)(?P<key>(?:api[_-]?key|secret|token|password|passwd|access[_-]?key"
    r"|secret[_-]?key|app[_-]?secret|client[_-]?secret|private[_-]?key"
    r"|auth[_-]?token|session[_-]?key))"
    r"(?P<sep>\s*[:=]\s*)"
    r"(?P<q>[\"']?)(?P<secret>[^\s\"'\[\]]{4,})(?P=q)"
)


def _redact_assignment(match: re.Match[str]) -> str:
    secret = match.group("secret")
    if secret.lower() in _NON_SECRET_LITERALS:
        return match.group(0)
    key = match.group("key")
    sep = match.group("sep")
    quote = match.group("q")
    return f"{key}{sep}{quote}{_token('secret_assignment', secret)}{quote}"


def _redact_bearer(match: re.Match[str]) -> str:
    return f"{match.group(1)}{_token('bearer', match.group(2))}"


def redact(text: Any) -> str:
    """Return *text* with any detected secrets replaced by redaction tokens.

    Safe to call on arbitrary input; non-string values are coerced with ``str``.
    """
    if text is None:
        return ""
    result = text if isinstance(text, str) else str(text)

    result = _PRIVATE_KEY_RE.sub(lambda m: _token("private_key", m.group(0)), result)
    for label, pattern in _TOKEN_PATTERNS:
        result = pattern.sub(lambda m, _label=label: _token(_label, m.group(0)), result)
    result = _BEARER_RE.sub(_redact_bearer, result)
    result = _ASSIGNMENT_RE.sub(_redact_assignment, result)
    return result


def redact_obj(obj: Any) -> Any:
    """Recursively redact secrets in strings within dicts / lists / tuples."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return type(obj)(redact_obj(v) for v in obj)
    return obj


def contains_secret(text: Any) -> bool:
    """Return True when *text* appears to contain a detectable secret."""
    return redact(text) != (text if isinstance(text, str) else str(text or ""))


def detect_secrets(text: Any) -> list[dict[str, str]]:
    """Detect secrets and return metadata only — never the raw value.

    Each entry is ``{"type": <label>, "fingerprint": <sha256 prefix>}``. Used by
    JS-secret extraction and evidence handling so findings can record *what* kind
    of secret appeared and *that* it recurred, without exposing the secret.
    """
    if not text:
        return []
    haystack = text if isinstance(text, str) else str(text)
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(label: str, value: str) -> None:
        fp = fingerprint(value)
        if (label, fp) in seen:
            return
        seen.add((label, fp))
        found.append({"type": label, "fingerprint": fp})

    for m in _PRIVATE_KEY_RE.finditer(haystack):
        _add("private_key", m.group(0))
    for label, pattern in _TOKEN_PATTERNS:
        for m in pattern.finditer(haystack):
            _add(label, m.group(0))
    for m in _BEARER_RE.finditer(haystack):
        _add("bearer", m.group(2))
    for m in _ASSIGNMENT_RE.finditer(haystack):
        if m.group("secret").lower() not in _NON_SECRET_LITERALS:
            _add("secret_assignment", m.group("secret"))
    return found
