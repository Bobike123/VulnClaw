"""Tamper-evident structured audit logging (JSONL).

Every safety-relevant event - session start, tool call, scope denial, approval
decision, generated file, report, error - is appended as one JSON object per line
to a per-session audit file. Each event is chained to the SHA-256 of the previous
event so that after-the-fact tampering (edits, deletions, reordering) is
detectable via :func:`verify_chain`.

Secrets never reach the log: all event data is passed through
:func:`vulnclaw.safety.redaction.redact_obj` before it is written.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from vulnclaw.safety.redaction import redact, redact_obj

GENESIS_HASH = "0" * 64


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _compute_hash(core: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(core).encode("utf-8", "replace")).hexdigest()


def _resolve_audit_dir(config: Any) -> Path:
    audit_cfg = getattr(config, "audit", None)
    configured = str(getattr(audit_cfg, "audit_dir", "") or "").strip() if audit_cfg else ""
    if configured:
        return Path(configured).expanduser()
    from vulnclaw.config.settings import AUDIT_DIR

    return AUDIT_DIR


def _safe_session_component(session_id: str) -> str:
    keep = [c if (c.isalnum() or c in "-_.") else "_" for c in (session_id or "session")]
    return "".join(keep)[:80] or "session"


class AuditLogger:
    """Append-only, hash-chained JSONL audit logger for a single session."""

    def __init__(
        self,
        session_id: str,
        *,
        audit_dir: Path | str,
        enabled: bool = True,
        hash_chain: bool = True,
    ) -> None:
        self.session_id = session_id
        self.enabled = enabled
        self.hash_chain = hash_chain
        self._dir = Path(audit_dir)
        self._path = self._dir / f"session-{_safe_session_component(session_id)}.jsonl"
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash = GENESIS_HASH
        if self.enabled:
            self._dir.mkdir(parents=True, exist_ok=True)
            self._resume_chain()

    @classmethod
    def from_config(cls, config: Any, session_id: str) -> "AuditLogger":
        audit_cfg = getattr(config, "audit", None)
        return cls(
            session_id,
            audit_dir=_resolve_audit_dir(config),
            enabled=bool(getattr(audit_cfg, "enabled", True)) if audit_cfg else True,
            hash_chain=bool(getattr(audit_cfg, "hash_chain", True)) if audit_cfg else True,
        )

    @property
    def path(self) -> Path:
        return self._path

    def _resume_chain(self) -> None:
        """Continue an existing session file (persistent mode / restarts)."""
        if not self._path.exists():
            return
        last: Optional[dict[str, Any]] = None
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        last = json.loads(line)
        except Exception:
            return
        if last:
            self._seq = int(last.get("seq", -1)) + 1
            self._prev_hash = str(last.get("hash", GENESIS_HASH))

    def log(self, event: str, **data: Any) -> dict[str, Any]:
        """Append one audit event. Returns the written record (redacted)."""
        if not self.enabled:
            return {}
        with self._lock:
            core = {
                "seq": self._seq,
                "ts": _utc_now(),
                "session_id": self.session_id,
                "event": event,
                "data": redact_obj(data),
                "prev_hash": self._prev_hash if self.hash_chain else GENESIS_HASH,
            }
            record = dict(core)
            record["hash"] = _compute_hash(core)
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(_canonical(record) + "\n")
            self._seq += 1
            if self.hash_chain:
                self._prev_hash = record["hash"]
            return record

    # ── convenience wrappers ────────────────────────────────────────────

    def session_start(self, *, command: str = "", target: str = "", model: str = "",
                      provider: str = "", scope: str = "") -> dict[str, Any]:
        return self.log(
            "session_start",
            command=command,
            target=target,
            model=model,
            provider=provider,
            scope=scope,
        )

    def tool_call(self, *, tool: str, target: str = "", status: str = "",
                 args_summary: str = "", detail: str = "") -> dict[str, Any]:
        return self.log(
            "tool_call",
            tool=tool,
            target=target,
            status=status,
            args_summary=redact(args_summary),
            detail=redact(detail),
        )

    def scope_decision(self, decision: Any, *, tool: str = "") -> dict[str, Any]:
        data = decision.to_dict() if hasattr(decision, "to_dict") else {"raw": str(decision)}
        return self.log(
            "scope_denied" if not data.get("allowed", True) else "scope_allowed",
            tool=tool,
            **data,
        )

    def denied(self, *, action: str, reason: str, target: str = "",
              tool: str = "") -> dict[str, Any]:
        return self.log("denied", action=action, reason=reason, target=target, tool=tool)

    def approval(self, *, action: str, decision: str, target: str = "",
                risk: str = "", reason: str = "") -> dict[str, Any]:
        return self.log(
            "approval",
            action=action,
            decision=decision,
            target=target,
            risk=risk,
            reason=reason,
        )

    def generated_file(self, path: str, *, kind: str = "") -> dict[str, Any]:
        return self.log("generated_file", path=str(path), kind=kind)

    def report(self, *, path: str = "", fmt: str = "") -> dict[str, Any]:
        return self.log("report", path=str(path), format=fmt)

    def error(self, message: str, *, where: str = "") -> dict[str, Any]:
        return self.log("error", message=redact(message), where=where)


# ── Verification & inspection (also used by `vulnclaw audit inspect`) ──────


def verify_chain(path: Path | str) -> bool:
    """Return True when the hash chain in *path* is intact and well-linked."""
    path = Path(path)
    if not path.exists():
        return False
    prev = GENESIS_HASH
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                stored_hash = record.get("hash")
                core = {k: record[k] for k in ("seq", "ts", "session_id", "event", "data", "prev_hash")}
                if _compute_hash(core) != stored_hash:
                    return False
                if record.get("prev_hash") != prev:
                    return False
                prev = stored_hash
    except Exception:
        return False
    return True


def summarize(path: Path | str) -> dict[str, Any]:
    """Summarize a session audit file for `vulnclaw audit inspect`."""
    path = Path(path)
    summary: dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
        "event_count": 0,
        "events_by_type": {},
        "targets": [],
        "denied": [],
        "generated_files": [],
        "errors": [],
        "chain_valid": False,
        "session_id": "",
        "started_at": "",
    }
    if not path.exists():
        return summary

    targets: set[str] = set()
    events_by_type: dict[str, int] = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            summary["event_count"] += 1
            event = record.get("event", "?")
            events_by_type[event] = events_by_type.get(event, 0) + 1
            data = record.get("data", {}) or {}
            if not summary["session_id"]:
                summary["session_id"] = record.get("session_id", "")
            if event == "session_start":
                summary["started_at"] = record.get("ts", "")
            tgt = data.get("target")
            if tgt:
                targets.add(str(tgt))
            if event in ("denied", "scope_denied"):
                summary["denied"].append(
                    {"action": data.get("action") or data.get("event"),
                     "target": data.get("target", ""),
                     "reason": data.get("reason", "")}
                )
            if event == "generated_file":
                summary["generated_files"].append(data.get("path", ""))
            if event == "error":
                summary["errors"].append(data.get("message", ""))

    summary["events_by_type"] = events_by_type
    summary["targets"] = sorted(targets)
    summary["chain_valid"] = verify_chain(path)
    return summary
