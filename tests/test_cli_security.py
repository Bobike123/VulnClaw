"""Tests for the scope/audit CLI subcommands and `doctor --security`."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from vulnclaw.cli import main as cli_main
from vulnclaw.config.schema import VulnClawConfig


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def default_config(monkeypatch):
    config = VulnClawConfig()
    monkeypatch.setattr(cli_main, "load_config", lambda: config)
    return config


class TestScopeCommands:
    def test_scope_show(self, runner, default_config, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cli_main.app, ["scope", "show"])
        assert result.exit_code == 0
        assert "Engagement Scope" in result.output
        assert "enforce" in result.output

    def test_scope_check_localhost_in_scope(self, runner, default_config, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cli_main.app, ["scope", "check", "localhost"])
        assert result.exit_code == 0
        assert "IN SCOPE" in result.output

    def test_scope_check_public_out_of_scope(self, runner, default_config, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cli_main.app, ["scope", "check", "https://evil.example/x"])
        assert result.exit_code == 1
        assert "OUT OF SCOPE" in result.output

    def test_scope_init_writes_file(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cli_main.app, ["scope", "init"])
        assert result.exit_code == 0
        written = tmp_path / ".vulnclaw-scope.yaml"
        assert written.exists()
        assert "DEFAULT-DENY" in written.read_text(encoding="utf-8")

    def test_scope_init_refuses_overwrite(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".vulnclaw-scope.yaml").write_text("existing", encoding="utf-8")
        result = runner.invoke(cli_main.app, ["scope", "init"])
        assert result.exit_code == 1
        assert "already exists" in result.output

    def test_scope_init_force_overwrites(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".vulnclaw-scope.yaml").write_text("existing", encoding="utf-8")
        result = runner.invoke(cli_main.app, ["scope", "init", "--force"])
        assert result.exit_code == 0
        assert "engagement" in (tmp_path / ".vulnclaw-scope.yaml").read_text(encoding="utf-8")


class TestAuditCommands:
    def _write_session(self, audit_dir):
        from vulnclaw.safety.audit import AuditLogger

        logger = AuditLogger("s1-2026", audit_dir=audit_dir)
        logger.session_start(target="target.test")
        logger.tool_call(tool="fetch", target="target.test", status="dispatched")
        logger.denied(action="scope", reason="out of scope", target="evil.example", tool="fetch")
        return logger.path

    def test_audit_verify_intact(self, runner, tmp_path):
        path = self._write_session(tmp_path)
        result = runner.invoke(cli_main.app, ["audit", "verify", str(path)])
        assert result.exit_code == 0
        assert "intact" in result.output

    def test_audit_verify_tampered(self, runner, tmp_path):
        path = self._write_session(tmp_path)
        lines = path.read_text(encoding="utf-8").splitlines()
        lines[0] = lines[0].replace("target.test", "hacked.test")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = runner.invoke(cli_main.app, ["audit", "verify", str(path)])
        assert result.exit_code == 1
        assert "BROKEN" in result.output

    def test_audit_inspect_file(self, runner, tmp_path):
        path = self._write_session(tmp_path)
        result = runner.invoke(cli_main.app, ["audit", "inspect", str(path)])
        assert result.exit_code == 0
        assert "Audit summary" in result.output
        assert "intact" in result.output
        assert "denied actions" in result.output

    def test_audit_list(self, runner, monkeypatch, tmp_path):
        self._write_session(tmp_path)
        config = VulnClawConfig()
        config.audit.audit_dir = str(tmp_path)
        monkeypatch.setattr(cli_main, "load_config", lambda: config)
        result = runner.invoke(cli_main.app, ["audit", "list"])
        assert result.exit_code == 0
        assert "session-" in result.output

    def test_audit_verify_missing(self, runner, tmp_path):
        result = runner.invoke(cli_main.app, ["audit", "verify", str(tmp_path / "nope.jsonl")])
        assert result.exit_code == 1
        assert "Not found" in result.output


class TestDoctorSecurity:
    def test_doctor_security_section(self, runner, default_config, monkeypatch):
        result = runner.invoke(cli_main.app, ["doctor", "--security"])
        assert result.exit_code == 0
        assert "Security Posture" in result.output
        assert "Scope:" in result.output
        assert "Approval:" in result.output
        assert "Persistent budget" in result.output

    def test_doctor_without_security_flag_omits_section(self, runner, default_config):
        result = runner.invoke(cli_main.app, ["doctor"])
        assert result.exit_code == 0
        assert "Security Posture" not in result.output
