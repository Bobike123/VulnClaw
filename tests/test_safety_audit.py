"""Tests for the tamper-evident audit logger (vulnclaw.safety.audit)."""

from __future__ import annotations

import json

from vulnclaw.safety import audit
from vulnclaw.safety.audit import AuditLogger, summarize, verify_chain


def _logger(tmp_path, **kw) -> AuditLogger:
    return AuditLogger("sess-1", audit_dir=tmp_path, **kw)


class TestGeneration:
    def test_writes_jsonl_events(self, tmp_path):
        log = _logger(tmp_path)
        log.session_start(command="run", target="localhost", model="gpt-4o")
        log.tool_call(tool="fetch", target="localhost", status="ok")
        lines = log.path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2
        first = json.loads(lines[0])
        assert first["event"] == "session_start"
        assert first["seq"] == 0
        assert first["data"]["target"] == "localhost"

    def test_disabled_writes_nothing(self, tmp_path):
        log = _logger(tmp_path, enabled=False)
        log.session_start(command="run")
        assert not log.path.exists()

    def test_sequence_increments(self, tmp_path):
        log = _logger(tmp_path)
        for i in range(5):
            log.log("tick", i=i)
        seqs = [json.loads(x)["seq"] for x in log.path.read_text().strip().splitlines()]
        assert seqs == [0, 1, 2, 3, 4]


class TestRedaction:
    def test_secrets_redacted_in_events(self, tmp_path):
        log = _logger(tmp_path)
        secret = "sk-abc123DEF456ghi789JKL012mno345PQR678stu"
        log.tool_call(tool="python_execute", args_summary=f"key={secret}")
        log.error(f"boom with token {secret}")
        blob = log.path.read_text(encoding="utf-8")
        assert secret not in blob
        assert "REDACTED" in blob

    def test_nested_data_redacted(self, tmp_path):
        log = _logger(tmp_path)
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJ"
        log.log("custom", headers={"Authorization": f"Bearer {jwt}"})
        blob = log.path.read_text(encoding="utf-8")
        assert jwt not in blob


class TestHashChain:
    def test_chain_is_valid(self, tmp_path):
        log = _logger(tmp_path)
        log.session_start(command="run")
        log.tool_call(tool="fetch", status="ok")
        log.denied(action="exploit", reason="not in scope")
        assert verify_chain(log.path) is True

    def test_first_event_links_to_genesis(self, tmp_path):
        log = _logger(tmp_path)
        rec = log.session_start(command="run")
        assert rec["prev_hash"] == audit.GENESIS_HASH

    def test_events_are_linked(self, tmp_path):
        log = _logger(tmp_path)
        r0 = log.log("a")
        r1 = log.log("b")
        assert r1["prev_hash"] == r0["hash"]

    def test_tamper_detected(self, tmp_path):
        log = _logger(tmp_path)
        log.session_start(command="run")
        log.tool_call(tool="fetch", status="ok")
        assert verify_chain(log.path) is True

        # Tamper with the first record's data; the chain must no longer verify.
        lines = log.path.read_text(encoding="utf-8").strip().splitlines()
        rec = json.loads(lines[0])
        rec["data"]["command"] = "exploit"  # edited after the fact
        lines[0] = json.dumps(rec)
        log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        assert verify_chain(log.path) is False

    def test_deletion_detected(self, tmp_path):
        log = _logger(tmp_path)
        log.log("a")
        log.log("b")
        log.log("c")
        lines = log.path.read_text(encoding="utf-8").strip().splitlines()
        # Drop the middle event - breaks prev_hash linkage.
        del lines[1]
        log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert verify_chain(log.path) is False

    def test_resume_continues_chain(self, tmp_path):
        log1 = _logger(tmp_path)
        log1.log("a")
        log1.log("b")
        # New logger instance for the same session appends and keeps the chain.
        log2 = _logger(tmp_path)
        log2.log("c")
        assert verify_chain(log2.path) is True
        seqs = [json.loads(x)["seq"] for x in log2.path.read_text().strip().splitlines()]
        assert seqs == [0, 1, 2]


class TestSummarize:
    def test_summary_counts_and_targets(self, tmp_path):
        log = _logger(tmp_path)
        log.session_start(command="run", target="localhost")
        log.tool_call(tool="fetch", target="localhost", status="ok")
        log.denied(action="exploit", reason="out of scope", target="evil.com")
        log.generated_file("/out/poc_01.py", kind="poc")
        log.error("kaboom")

        summary = summarize(log.path)
        assert summary["event_count"] == 5
        assert summary["events_by_type"]["tool_call"] == 1
        assert "localhost" in summary["targets"]
        assert summary["denied"][0]["action"] == "exploit"
        assert summary["generated_files"] == ["/out/poc_01.py"]
        assert summary["errors"] == ["kaboom"]
        assert summary["chain_valid"] is True
        assert summary["session_id"] == "sess-1"

    def test_summary_missing_file(self, tmp_path):
        summary = summarize(tmp_path / "nope.jsonl")
        assert summary["exists"] is False
        assert summary["event_count"] == 0
