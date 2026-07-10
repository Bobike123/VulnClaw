"""Credential-at-rest protection: file-permission hardening + optional keyring.

VulnClaw stores API keys (LLM provider keys, recon service keys) in its config
file. On a shared or multi-user host a world-readable config leaks those secrets
to every local account. This module keeps secret-bearing files owner-only and
provides a check the ``doctor``/audit surfaces can use to flag loose permissions.

The OS keyring (via the optional ``keyring`` package) is supported when present;
all keyring helpers degrade gracefully to no-ops when it is not installed, so the
rest of VulnClaw never needs to branch on availability.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

WINDOWS = os.name == "nt"

# Owner-only permissions for secret files/dirs on POSIX.
SECRET_FILE_MODE = 0o600
SECRET_DIR_MODE = 0o700

# Bits that mean "someone other than the owner can access this".
_GROUP_OTHER_MASK = stat.S_IRWXG | stat.S_IRWXO


def harden_file_permissions(path: Path | str) -> bool:
    """chmod a secret-bearing file to owner-only (0600).

    Returns True when the file now has owner-only permissions. No-op on Windows
    (POSIX mode bits don't apply) and when the file is missing.
    """
    p = Path(path)
    if WINDOWS or not p.exists():
        return False
    try:
        os.chmod(p, SECRET_FILE_MODE)
        return True
    except OSError:
        return False


def harden_dir_permissions(path: Path | str) -> bool:
    """chmod a directory holding secrets/audit logs to owner-only (0700)."""
    p = Path(path)
    if WINDOWS or not p.exists():
        return False
    try:
        os.chmod(p, SECRET_DIR_MODE)
        return True
    except OSError:
        return False


@dataclass
class PermissionFinding:
    """A secret file that is accessible beyond its owner."""

    path: str
    mode: str  # octal permission string, e.g. "644"
    group_accessible: bool
    world_accessible: bool

    def message(self) -> str:
        who = []
        if self.world_accessible:
            who.append("all users")
        elif self.group_accessible:
            who.append("the file's group")
        audience = " and ".join(who) if who else "other accounts"
        return (
            f"{self.path} is readable by {audience} (mode {self.mode}). "
            f"Restrict it with: chmod 600 {self.path}"
        )


def check_file_permissions(path: Path | str) -> Optional[PermissionFinding]:
    """Return a finding when *path* grants any group/other access (POSIX only).

    Returns ``None`` on Windows, for missing files, and for owner-only files.
    """
    p = Path(path)
    if WINDOWS or not p.exists():
        return None
    try:
        mode = p.stat().st_mode
    except OSError:
        return None
    if not (mode & _GROUP_OTHER_MASK):
        return None
    return PermissionFinding(
        path=str(p),
        mode=oct(stat.S_IMODE(mode))[2:],
        group_accessible=bool(mode & stat.S_IRWXG),
        world_accessible=bool(mode & stat.S_IRWXO),
    )


def audit_sensitive_files(paths: Iterable[Path | str]) -> list[PermissionFinding]:
    """Check several secret files, returning findings for the loose ones."""
    findings: list[PermissionFinding] = []
    for path in paths:
        finding = check_file_permissions(path)
        if finding is not None:
            findings.append(finding)
    return findings


# ── Optional OS keyring ──────────────────────────────────────────────────

KEYRING_SERVICE = "vulnclaw"


def keyring_available() -> bool:
    """Whether the optional ``keyring`` package is importable and usable."""
    try:
        import keyring  # noqa: F401

        return True
    except Exception:
        return False


def store_secret(key: str, value: str, *, service: str = KEYRING_SERVICE) -> bool:
    """Store a secret in the OS keyring. Returns False when keyring is absent."""
    if not key or value is None:
        return False
    try:
        import keyring

        keyring.set_password(service, key, value)
        return True
    except Exception:
        return False


def load_secret(key: str, *, service: str = KEYRING_SERVICE) -> Optional[str]:
    """Load a secret from the OS keyring, or ``None`` when unavailable/absent."""
    if not key:
        return None
    try:
        import keyring

        return keyring.get_password(service, key)
    except Exception:
        return None
