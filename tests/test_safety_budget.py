"""Tests for persistent-mode budgets and emergency stop (vulnclaw.safety.budget)."""

from __future__ import annotations

from types import SimpleNamespace

from vulnclaw.safety.budget import (
    REASON_CYCLES,
    REASON_DURATION,
    REASON_EMERGENCY_STOP,
    REASON_MANUAL,
    REASON_TOOL_CALLS,
    Budget,
)


class _FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class TestNoLimits:
    def test_unlimited_never_stops(self):
        b = Budget().start()
        for _ in range(100):
            b.record_tool_call()
            b.record_cycle()
        assert b.check() is None
        assert b.stopped is False


class TestDurationBudget:
    def test_duration_trips_at_limit(self):
        clock = _FakeClock()
        b = Budget(max_duration_seconds=60, clock=clock).start()
        assert b.check() is None
        clock.advance(59)
        assert b.check() is None
        clock.advance(1)
        assert b.check() == REASON_DURATION
        assert b.stopped is True


class TestCycleBudget:
    def test_cycles_trip_at_limit(self):
        b = Budget(max_cycles=3).start()
        b.record_cycle()
        b.record_cycle()
        assert b.check() is None
        b.record_cycle()
        assert b.check() == REASON_CYCLES


class TestToolCallBudget:
    def test_tool_calls_trip_at_limit(self):
        b = Budget(max_tool_calls=2).start()
        assert b.check() is None
        b.record_tool_call()
        assert b.check() is None
        b.record_tool_call()
        assert b.check() == REASON_TOOL_CALLS


class TestEmergencyStop:
    def test_stop_file_halts(self, tmp_path):
        stop = tmp_path / ".vulnclaw-STOP"
        b = Budget(stop_files=[str(stop)]).start()
        assert b.check() is None
        stop.write_text("halt", encoding="utf-8")
        assert b.check() == REASON_EMERGENCY_STOP
        assert b.emergency_stop_path() is None or b.reason == REASON_EMERGENCY_STOP

    def test_stop_file_honored_even_when_disabled(self, tmp_path):
        stop = tmp_path / ".vulnclaw-STOP"
        stop.write_text("halt", encoding="utf-8")
        b = Budget(enabled=False, max_cycles=1, stop_files=[str(stop)]).start()
        # ceilings ignored when disabled, but the kill switch still fires
        assert b.check() == REASON_EMERGENCY_STOP

    def test_disabled_ignores_ceilings(self, tmp_path):
        b = Budget(enabled=False, max_cycles=1, max_tool_calls=1).start()
        b.record_cycle()
        b.record_tool_call()
        assert b.check() is None


class TestManualTrip:
    def test_manual_trip_latches(self):
        b = Budget().start()
        b.trip()
        assert b.check() == REASON_MANUAL
        # A later condition does not override the latched reason.
        b.trip("something_else")
        assert b.check() == REASON_MANUAL


class TestFromConfig:
    def test_reads_budget_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = SimpleNamespace(
            budget=SimpleNamespace(
                enabled=True,
                max_duration_minutes=2,
                max_cycles=5,
                max_tool_calls=10,
                emergency_stop_file="",
            )
        )
        b = Budget.from_config(cfg)
        assert b.max_duration_seconds == 120.0
        assert b.max_cycles == 5
        assert b.max_tool_calls == 10

    def test_configured_stop_file(self, tmp_path):
        stop = tmp_path / "kill.me"
        stop.write_text("x", encoding="utf-8")
        cfg = SimpleNamespace(
            budget=SimpleNamespace(
                enabled=True,
                max_duration_minutes=0,
                max_cycles=0,
                max_tool_calls=0,
                emergency_stop_file=str(stop),
            )
        )
        b = Budget.from_config(cfg).start()
        assert b.check() == REASON_EMERGENCY_STOP

    def test_missing_budget_config_is_permissive(self):
        b = Budget.from_config(SimpleNamespace()).start()
        assert b.check() is None


class TestStatusMessage:
    def test_message_describes_reason(self):
        b = Budget(max_cycles=1).start()
        b.record_cycle()
        msg = b.status().message()
        assert "cycle budget" in msg
