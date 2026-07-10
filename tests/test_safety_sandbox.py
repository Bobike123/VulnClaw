"""Tests for the python_execute sandbox (vulnclaw.safety.sandbox).

These prove the hardening controls actually fire: unsafe filesystem reads are
blocked, sensitive paths are denied in every mode, network is off by default,
long-running code is killed, and no secret environment variables are inherited.
"""

from __future__ import annotations

import os

import pytest

from vulnclaw.safety.sandbox import code_hash, run_sandboxed

POSIX = os.name == "posix"
HAS_ETC_PASSWD = os.path.exists("/etc/passwd")


class TestBasics:
    def test_hello_runs(self):
        r = run_sandboxed("print('hello-sandbox')")
        assert r.status == "ok"
        assert "hello-sandbox" in r.stdout

    def test_workdir_write_and_read_allowed(self):
        code = "open('out.txt', 'w').write('hi'); print(open('out.txt').read())"
        r = run_sandboxed(code, mode="lab")
        assert r.status == "ok"
        assert "hi" in r.stdout
        assert any("out.txt" in f for f in r.generated_files)

    def test_workdir_is_cleaned_up(self):
        r = run_sandboxed("print(1)")
        assert not os.path.exists(r.workdir)

    def test_code_hash_deterministic(self):
        assert code_hash("print(1)") == code_hash("print(1)")
        assert code_hash("print(1)") != code_hash("print(2)")

    def test_output_is_capped(self):
        r = run_sandboxed("print('A' * 20000)", max_output_chars=200)
        assert "truncated" in r.stdout
        assert len(r.stdout) < 2000


class TestFilesystemGuard:
    @pytest.mark.skipif(not HAS_ETC_PASSWD, reason="needs /etc/passwd")
    def test_read_outside_workdir_blocked_in_safe_mode(self):
        r = run_sandboxed("print(open('/etc/passwd').read())", mode="safe")
        assert r.status == "blocked"
        assert "access denied" in r.stderr

    @pytest.mark.skipif(not HAS_ETC_PASSWD, reason="needs /etc/passwd")
    def test_read_outside_workdir_allowed_in_lab_mode(self):
        # lab mode does not jail reads to the workdir (only sensitive paths blocked)
        r = run_sandboxed("print(len(open('/etc/passwd').read()))", mode="lab")
        assert r.status == "ok"

    def test_sensitive_path_denied_even_in_lab_mode(self):
        # The path need not exist — the guard denies before opening.
        r = run_sandboxed("open('/root/.ssh/id_rsa').read()", mode="lab")
        assert r.status == "blocked"
        assert "sensitive path" in r.stderr

    def test_env_file_denied(self):
        r = run_sandboxed("open('/some/dir/.env').read()", mode="trusted-local")
        assert r.status == "blocked"

    def test_write_outside_workdir_blocked(self):
        r = run_sandboxed("open('/tmp/vulnclaw_sbx_escape.txt', 'w').write('x')", mode="lab")
        assert r.status == "blocked"
        assert not os.path.exists("/tmp/vulnclaw_sbx_escape.txt")


class TestEnvScrubbing:
    def test_secret_env_not_inherited(self, monkeypatch):
        monkeypatch.setenv("VULNCLAW_LLM_API_KEY", "sk-super-secret-value-1234567890")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "totally-secret-aws-key")
        code = (
            "import os\n"
            "print('KEY=' + os.environ.get('VULNCLAW_LLM_API_KEY', 'MISSING'))\n"
            "print('AWS=' + os.environ.get('AWS_SECRET_ACCESS_KEY', 'MISSING'))\n"
        )
        r = run_sandboxed(code, mode="trusted-local", allow_network=True)
        assert r.status == "ok"
        assert "KEY=MISSING" in r.stdout
        assert "AWS=MISSING" in r.stdout
        assert "super-secret" not in r.stdout

    def test_home_redirected_into_sandbox(self):
        r = run_sandboxed("import os; print(os.path.expanduser('~'))", mode="lab")
        assert r.status == "ok"
        assert r.workdir in r.stdout


class TestNetwork:
    def test_network_off_by_default(self):
        r = run_sandboxed("import socket; socket.socket()", mode="safe")
        assert r.status == "blocked"
        assert "network" in r.stderr.lower()

    def test_safe_mode_forces_network_off(self):
        # Even with allow_network=True, safe mode keeps the network closed.
        r = run_sandboxed("import socket; socket.socket()", mode="safe", allow_network=True)
        assert r.status == "blocked"
        assert r.enforced["network_blocked"] is True

    def test_network_can_be_enabled_in_lab_mode(self):
        code = "import socket; s = socket.socket(); s.close(); print('sock-ok')"
        r = run_sandboxed(code, mode="lab", allow_network=True)
        assert r.status == "ok"
        assert "sock-ok" in r.stdout
        assert r.enforced["network_blocked"] is False


class TestLimits:
    def test_timeout_kills_long_running_code(self):
        r = run_sandboxed("import time; time.sleep(10)", timeout_s=1)
        assert r.status == "timeout"

    @pytest.mark.skipif(not POSIX, reason="resource limits are POSIX-only")
    def test_resource_limits_enforced_on_posix(self):
        r = run_sandboxed("print(1)")
        assert r.enforced["rlimit_as"] is True
        assert r.enforced["rlimit_cpu"] is True
        assert r.enforced["rlimit_fsize"] is True

    @pytest.mark.skipif(not POSIX, reason="RLIMIT_FSIZE is POSIX-only")
    def test_file_size_limit_enforced(self):
        # Writing 5 MB with a 1 MB file-size cap must not succeed.
        code = "open('big.bin', 'wb').write(b'x' * (5 * 1024 * 1024)); print('wrote')"
        r = run_sandboxed(code, mode="lab", max_file_size_mb=1)
        assert r.status != "ok"


class TestEnforcedReport:
    def test_enforced_map_present(self):
        r = run_sandboxed("print(1)")
        assert r.enforced["dedicated_workdir"] is True
        assert r.enforced["scrubbed_env"] is True
        assert r.enforced["path_guard"] is True
        assert r.enforced["home_redirected"] is True
