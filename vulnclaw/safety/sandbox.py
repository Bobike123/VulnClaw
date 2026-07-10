"""Best-effort sandbox for the high-risk ``python_execute`` tool.

This is defense-in-depth, **not** containment. It runs LLM-authored Python in a
child interpreter with:

- a dedicated temporary working directory (cleaned up after the run),
- a scrubbed, allowlisted environment (no API keys / secrets are inherited) with
  ``HOME`` redirected into the sandbox,
- an in-process guard that denies reads/writes of sensitive paths (SSH keys,
  ``.env``, cloud/browser credentials, shell history, VulnClaw config) and — in
  ``safe`` mode — confines file access to the working directory,
- outbound network disabled by default (``socket`` is neutralized),
- POSIX resource limits (CPU, address space, file size) and a wall-clock timeout,
- output-size caps.

A determined bypass (e.g. via ``ctypes`` or re-exec) remains possible on a shared
OS account. For untrusted code, run VulnClaw inside a container or dedicated VM.
The :attr:`SandboxResult.enforced` map reports exactly which controls were active.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

_MAIN_FILENAME = "_sbx_main.py"

# Constructs that can escape the in-process open()/socket guards (they spawn a
# shell, a child process, or reach native memory). These are refused statically
# in every mode — the sandbox cannot contain them. Static matching is
# best-effort and bypassable via obfuscation; it is one layer, not the boundary.
_BLOCKED_CODE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bos\s*\.\s*system\b"),
    re.compile(r"\bos\s*\.\s*popen\b"),
    re.compile(r"\bos\s*\.\s*exec[lv]\w*"),
    re.compile(r"\bos\s*\.\s*spawn\w*"),
    re.compile(r"\bos\s*\.\s*fork\b"),
    re.compile(r"\bposix_spawn\w*"),
    re.compile(r"\bsubprocess\b"),
    re.compile(r"\bpty\b"),
    re.compile(r"\bctypes\b"),
    re.compile(r"\bcffi\b"),
    re.compile(r"\bmultiprocessing\b"),
    re.compile(r"\bshutil\s*\.\s*rmtree\b"),
    re.compile(r"__import__\s*\(\s*['\"](?:os|subprocess|ctypes|pty|cffi)['\"]"),
]


def precheck(code: str) -> str | None:
    """Return the first disallowed construct found in *code*, else None."""
    for pattern in _BLOCKED_CODE_PATTERNS:
        match = pattern.search(code or "")
        if match:
            return match.group(0)
    return None

# Lowercased substrings that must never be opened, in any mode.
_SENSITIVE_PATTERNS = [
    "/.ssh", "\\.ssh", ".ssh/", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "known_hosts", "authorized_keys",
    "/.aws", "\\.aws", ".aws/",
    "/.gnupg", ".gnupg/",
    "/.kube", ".kube/config",
    "/.docker", ".docker/config",
    ".env", ".netrc", ".pgpass", ".git-credentials",
    "/.vulnclaw", "\\.vulnclaw", ".vulnclaw/",
    ".bash_history", ".zsh_history", ".python_history",
    ".mozilla", "google-chrome", "/chromium", "chrome/user data",
    "credentials.json", "client_secret",
    "/etc/shadow",
]

# The guard preamble. ``__SBX_CFG__`` is replaced with a repr() of a JSON string
# so no brace-escaping of this template is required.
_PREAMBLE_TEMPLATE = r'''
import os, sys, io, json, builtins
_SBX = json.loads(__SBX_CFG__)
_WORKDIR = os.path.realpath(_SBX["workdir"])
_REAL_HOME = (_SBX["real_home"] or "").lower()
_SENSITIVE = tuple(_SBX["sensitive"])
_SAFE_PREFIXES = tuple(os.path.realpath(p) for p in _SBX["safe_prefixes"])
_JAIL_READS = _SBX["jail_reads"]


def _sbx_reason(path, is_write):
    try:
        rp = os.path.realpath(path)
    except Exception:
        rp = str(path)
    # The sandbox owns its workdir entirely (reads and writes always allowed),
    # even when the temp dir happens to live under the user's home directory.
    if rp == _WORKDIR or rp.startswith(_WORKDIR + os.sep):
        return ""
    under_safe_prefix = any(
        rp == pref or rp.startswith(pref + os.sep) for pref in _SAFE_PREFIXES
    )
    # Reads of Python/library files are always allowed (needed for imports),
    # even when the interpreter is installed under the user's home directory.
    if (not is_write) and under_safe_prefix:
        return ""
    low = rp.replace("\\", "/").lower()
    for pat in _SENSITIVE:
        if pat in low:
            return "sensitive path"
    if _REAL_HOME and (low == _REAL_HOME or low.startswith(_REAL_HOME + "/")):
        return "user home directory"
    if is_write:
        return "write outside sandbox workdir"
    if _JAIL_READS:
        return "read outside sandbox workdir"
    return ""


_orig_open = builtins.open


def _guard_open(file, mode="r", *a, **k):
    is_write = any(c in str(mode) for c in ("w", "a", "x", "+"))
    reason = _sbx_reason(file, is_write)
    if reason:
        raise PermissionError("[sandbox] access denied (%s): %s" % (reason, file))
    return _orig_open(file, mode, *a, **k)


builtins.open = _guard_open
io.open = _guard_open

_orig_os_open = os.open
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_TRUNC", 0)


def _guard_os_open(path, flags, *a, **k):
    reason = _sbx_reason(path, bool(flags & _WRITE_FLAGS))
    if reason:
        raise PermissionError("[sandbox] access denied (%s): %s" % (reason, path))
    return _orig_os_open(path, flags, *a, **k)


os.open = _guard_os_open

if _SBX["block_network"]:
    import socket as _s

    def _no_net(*a, **k):
        raise PermissionError("[sandbox] network access is disabled in this mode")

    _s.socket = _no_net
    _s.create_connection = _no_net

try:
    os.chdir(_WORKDIR)
except Exception:
    pass

# Optional convenience imports (available to authored code without an import line).
try:
    import requests  # noqa: F401
except Exception:
    pass
try:
    from bs4 import BeautifulSoup  # noqa: F401
except Exception:
    pass
try:
    from Crypto.Cipher import AES  # noqa: F401
except Exception:
    pass
# ── end sandbox preamble ────────────────────────────────────────────────
'''


@dataclass
class SandboxResult:
    status: str  # "ok" | "timeout" | "error" | "blocked"
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    code_hash: str = ""
    mode: str = "safe"
    generated_files: list[str] = field(default_factory=list)
    enforced: dict[str, bool] = field(default_factory=dict)
    workdir: str = ""
    blocked_reason: str = ""

    @property
    def output(self) -> str:
        parts = []
        if self.stdout:
            parts.append(self.stdout)
        if self.stderr:
            parts.append("[stderr]\n" + self.stderr)
        return "\n".join(parts)


def code_hash(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8", "replace")).hexdigest()


def _build_env(workdir: str) -> dict[str, str]:
    """An allowlisted environment — no inherited secrets."""
    return {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONIOENCODING": "utf-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", ""),
        # Redirect home so ~/.ssh, ~/.aws, ~/.config/* resolve into the sandbox.
        "HOME": workdir,
        "USERPROFILE": workdir,
        "TMPDIR": workdir,
        "TEMP": workdir,
        "TMP": workdir,
    }


def _make_preexec(max_cpu: int, max_as_bytes: int, max_fsize_bytes: int):
    if os.name != "posix":
        return None

    def _limits() -> None:  # pragma: no cover - runs in the child process
        import resource

        if max_cpu > 0:
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (max_cpu, max_cpu + 2))
            except (ValueError, OSError):
                pass
        if max_as_bytes > 0:
            try:
                resource.setrlimit(resource.RLIMIT_AS, (max_as_bytes, max_as_bytes))
            except (ValueError, OSError):
                pass
        if max_fsize_bytes > 0:
            try:
                resource.setrlimit(resource.RLIMIT_FSIZE, (max_fsize_bytes, max_fsize_bytes))
            except (ValueError, OSError):
                pass

    return _limits


def _collect_generated_files(workdir: Path, limit: int = 50) -> list[str]:
    files: list[str] = []
    for root, _dirs, names in os.walk(workdir):
        for name in names:
            if name == _MAIN_FILENAME and Path(root) == workdir:
                continue
            full = Path(root) / name
            try:
                size = full.stat().st_size
            except OSError:
                size = -1
            rel = full.relative_to(workdir)
            files.append(f"{rel} ({size} bytes)")
            if len(files) >= limit:
                return files
    return files


def run_sandboxed(
    code: str,
    *,
    mode: str = "safe",
    allow_network: bool = False,
    timeout_s: int = 30,
    max_memory_mb: int = 1024,
    max_file_size_mb: int = 10,
    max_output_chars: int = 8000,
) -> SandboxResult:
    """Execute *code* in the sandbox and return a :class:`SandboxResult`."""
    mode = (mode or "safe").strip().lower()
    if mode not in ("safe", "lab", "trusted-local"):
        mode = "safe"
    # Reads are jailed to the workdir only in the most restrictive mode.
    jail_reads = mode == "safe"
    # Network is only ever on when explicitly allowed (and never in safe mode).
    block_network = not allow_network or mode == "safe"

    ch = code_hash(code)
    workdir = Path(tempfile.mkdtemp(prefix="vulnclaw-sbx-"))
    real_home = os.path.realpath(os.path.expanduser("~"))

    cfg = {
        "workdir": str(workdir),
        "real_home": real_home,
        "sensitive": _SENSITIVE_PATTERNS,
        "safe_prefixes": [sys.prefix, sys.base_prefix],
        "jail_reads": jail_reads,
        "block_network": block_network,
    }
    preamble = _PREAMBLE_TEMPLATE.replace("__SBX_CFG__", repr(json.dumps(cfg)))

    main_path = workdir / _MAIN_FILENAME
    main_path.write_text(preamble + "\n" + code, encoding="utf-8")

    posix = os.name == "posix"
    enforced = {
        "dedicated_workdir": True,
        "scrubbed_env": True,
        "home_redirected": True,
        "path_guard": True,
        "isolated_interpreter": True,
        "network_blocked": block_network,
        "rlimit_cpu": posix,
        "rlimit_as": posix,
        "rlimit_fsize": posix,
    }

    preexec = _make_preexec(
        max_cpu=timeout_s,
        max_as_bytes=max_memory_mb * 1024 * 1024,
        max_fsize_bytes=max_file_size_mb * 1024 * 1024,
    )

    started = time.monotonic()
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-X", "utf8", str(main_path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
            cwd=str(workdir),
            env=_build_env(str(workdir)),
            preexec_fn=preexec,
        )
        duration = time.monotonic() - started
        generated = _collect_generated_files(workdir)
        stdout = _clip(proc.stdout or "", max_output_chars)
        stderr = _clip(_filter_stderr(proc.stderr or ""), max_output_chars)
        status = "ok" if proc.returncode == 0 else "error"
        blocked_reason = ""
        if "[sandbox] access denied" in (proc.stderr or "") or "[sandbox] network" in (
            proc.stderr or ""
        ):
            status = "blocked"
            blocked_reason = "sandbox guard denied a filesystem/network operation"
        return SandboxResult(
            status=status,
            stdout=stdout,
            stderr=stderr,
            duration_s=round(duration, 3),
            code_hash=ch,
            mode=mode,
            generated_files=generated,
            enforced=enforced,
            workdir=str(workdir),
            blocked_reason=blocked_reason,
        )
    except subprocess.TimeoutExpired:
        return SandboxResult(
            status="timeout",
            stderr=f"execution exceeded the {timeout_s}s time limit",
            duration_s=float(timeout_s),
            code_hash=ch,
            mode=mode,
            enforced=enforced,
            workdir=str(workdir),
            blocked_reason="timeout",
        )
    except Exception as exc:  # noqa: BLE001
        return SandboxResult(
            status="error",
            stderr=f"sandbox failed to run: {exc}",
            code_hash=ch,
            mode=mode,
            enforced=enforced,
            workdir=str(workdir),
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _clip(text: str, limit: int) -> str:
    if limit > 0 and len(text) > limit:
        half = limit // 2
        return text[:half] + "\n...[truncated]...\n" + text[-half:]
    return text


def _filter_stderr(stderr: str) -> str:
    """Drop noisy optional-import failures from the convenience preamble."""
    keep = [
        line
        for line in stderr.splitlines()
        if "ImportError" not in line and "No module named" not in line
    ]
    return "\n".join(keep)


def capability_report(result: SandboxResult) -> str:
    """A short, honest description of which controls were active."""
    on = [k for k, v in result.enforced.items() if v]
    off = [k for k, v in result.enforced.items() if not v]
    lines = [f"sandbox mode={result.mode}; enforced: {', '.join(sorted(on)) or 'none'}"]
    if off:
        lines.append(f"not enforced on this platform: {', '.join(sorted(off))}")
    return "; ".join(lines)
