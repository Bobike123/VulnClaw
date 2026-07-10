"""Persistent-mode safety budgets and emergency stop.

Autonomous *persistent* mode runs the agent in an open-ended loop. Without hard
ceilings it can run indefinitely, burn API credits, and keep contacting a target
long after an operator expected it to stop. This module provides those ceilings
plus an out-of-band emergency stop.

A :class:`Budget` tracks wall-clock time, completed cycles, and tool calls, and
reports a stop reason once any configured limit is reached. Independently, it
honours an **emergency-stop file**: creating a sentinel file (default
``.vulnclaw-STOP`` in the working directory) halts the run at the next check —
a kill switch an operator can trip from another shell without signals or IPC.

The module has no dependency on the agent layer: the caller drives it
(``start`` / ``record_cycle`` / ``record_tool_call`` / ``check``) so it stays
trivially testable and reusable.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

# Sentinel files that, if present, halt a persistent run. The first is the
# documented name; the lowercase variant is accepted for convenience.
DEFAULT_STOP_FILES = (".vulnclaw-STOP", ".vulnclaw-stop")

# Stop-reason codes (stable strings suitable for audit records / UI).
REASON_EMERGENCY_STOP = "emergency_stop"
REASON_DURATION = "duration_budget_exceeded"
REASON_CYCLES = "cycle_budget_exceeded"
REASON_TOOL_CALLS = "tool_call_budget_exceeded"
REASON_MANUAL = "manual_stop"


@dataclass
class BudgetStatus:
    """A point-in-time snapshot of budget consumption."""

    stopped: bool
    reason: str
    elapsed_seconds: float
    cycles: int
    tool_calls: int
    max_duration_seconds: float
    max_cycles: int
    max_tool_calls: int

    def message(self) -> str:
        if not self.stopped:
            return ""
        if self.reason == REASON_EMERGENCY_STOP:
            return "[budget] emergency stop file detected — halting persistent run."
        if self.reason == REASON_DURATION:
            return (
                f"[budget] duration budget reached "
                f"({self.elapsed_seconds:.0f}s ≥ {self.max_duration_seconds:.0f}s) — halting."
            )
        if self.reason == REASON_CYCLES:
            return (
                f"[budget] cycle budget reached "
                f"({self.cycles} ≥ {self.max_cycles}) — halting."
            )
        if self.reason == REASON_TOOL_CALLS:
            return (
                f"[budget] tool-call budget reached "
                f"({self.tool_calls} ≥ {self.max_tool_calls}) — halting."
            )
        if self.reason == REASON_MANUAL:
            return "[budget] persistent run stopped by operator request."
        return f"[budget] stopped: {self.reason}"


class Budget:
    """Tracks and enforces persistent-mode resource ceilings + emergency stop.

    All limits are opt-in: a limit of ``0`` (or unset) means *unlimited* for that
    dimension. A disabled budget (``enabled=False``) never stops the run, but the
    emergency-stop file is still honoured so the kill switch always works.
    """

    def __init__(
        self,
        *,
        max_duration_seconds: float = 0.0,
        max_cycles: int = 0,
        max_tool_calls: int = 0,
        stop_files: Optional[list[str]] = None,
        enabled: bool = True,
        honor_stop_file_when_disabled: bool = True,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.enabled = enabled
        self.honor_stop_file_when_disabled = honor_stop_file_when_disabled
        self.max_duration_seconds = max(0.0, float(max_duration_seconds or 0.0))
        self.max_cycles = max(0, int(max_cycles or 0))
        self.max_tool_calls = max(0, int(max_tool_calls or 0))
        self.stop_files = [str(p) for p in (stop_files or list(DEFAULT_STOP_FILES))]
        self._clock = clock
        self._start: Optional[float] = None
        self._cycles = 0
        self._tool_calls = 0
        self._tripped_reason: Optional[str] = None

    @classmethod
    def from_config(
        cls,
        config: Any,
        *,
        extra_stop_files: Optional[list[str]] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> "Budget":
        cfg = getattr(config, "budget", None)
        minutes = int(getattr(cfg, "max_duration_minutes", 0) or 0) if cfg else 0
        stop_files = list(DEFAULT_STOP_FILES)
        configured = str(getattr(cfg, "emergency_stop_file", "") or "").strip() if cfg else ""
        if configured:
            stop_files.insert(0, configured)
        if extra_stop_files:
            stop_files.extend(str(p) for p in extra_stop_files)
        return cls(
            max_duration_seconds=minutes * 60.0,
            max_cycles=int(getattr(cfg, "max_cycles", 0) or 0) if cfg else 0,
            max_tool_calls=int(getattr(cfg, "max_tool_calls", 0) or 0) if cfg else 0,
            stop_files=stop_files,
            enabled=bool(getattr(cfg, "enabled", True)) if cfg else True,
            clock=clock,
        )

    # ── lifecycle ────────────────────────────────────────────────────────

    def start(self) -> "Budget":
        """Mark the run's start time (idempotent-safe; call once at run start)."""
        self._start = self._clock()
        return self

    def record_cycle(self, n: int = 1) -> None:
        self._cycles += max(0, int(n))

    def record_tool_call(self, n: int = 1) -> None:
        self._tool_calls += max(0, int(n))

    def trip(self, reason: str = REASON_MANUAL) -> None:
        """Manually stop the run (operator kill switch / in-process signal)."""
        if self._tripped_reason is None:
            self._tripped_reason = reason or REASON_MANUAL

    # ── introspection ────────────────────────────────────────────────────

    @property
    def cycles(self) -> int:
        return self._cycles

    @property
    def tool_calls(self) -> int:
        return self._tool_calls

    def elapsed_seconds(self) -> float:
        if self._start is None:
            return 0.0
        return max(0.0, self._clock() - self._start)

    def emergency_stop_path(self) -> Optional[Path]:
        """Return the first present emergency-stop sentinel file, if any."""
        for candidate in self.stop_files:
            try:
                path = Path(candidate).expanduser()
                if path.exists():
                    return path
            except Exception:
                continue
        return None

    def check(self) -> Optional[str]:
        """Return a stop-reason code if the run should halt now, else ``None``.

        The emergency-stop file is checked even when the budget is disabled, so
        the kill switch is always available. Once tripped, the reason latches.
        """
        if self._tripped_reason is not None:
            return self._tripped_reason

        if self.enabled or self.honor_stop_file_when_disabled:
            if self.emergency_stop_path() is not None:
                self._tripped_reason = REASON_EMERGENCY_STOP
                return self._tripped_reason

        if not self.enabled:
            return None

        if self.max_duration_seconds > 0 and self.elapsed_seconds() >= self.max_duration_seconds:
            self._tripped_reason = REASON_DURATION
            return self._tripped_reason
        if self.max_cycles > 0 and self._cycles >= self.max_cycles:
            self._tripped_reason = REASON_CYCLES
            return self._tripped_reason
        if self.max_tool_calls > 0 and self._tool_calls >= self.max_tool_calls:
            self._tripped_reason = REASON_TOOL_CALLS
            return self._tripped_reason
        return None

    @property
    def stopped(self) -> bool:
        return self.check() is not None

    @property
    def reason(self) -> str:
        return self._tripped_reason or ""

    def status(self) -> BudgetStatus:
        reason = self.check() or ""
        return BudgetStatus(
            stopped=bool(reason),
            reason=reason,
            elapsed_seconds=self.elapsed_seconds(),
            cycles=self._cycles,
            tool_calls=self._tool_calls,
            max_duration_seconds=self.max_duration_seconds,
            max_cycles=self.max_cycles,
            max_tool_calls=self.max_tool_calls,
        )
