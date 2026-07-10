"""Tests for credential-at-rest protection (vulnclaw.safety.credentials)."""

from __future__ import annotations

import os
import stat

import pytest

from vulnclaw.safety.credentials import (
    audit_sensitive_files,
    check_file_permissions,
    harden_dir_permissions,
    harden_file_permissions,
    keyring_available,
    load_secret,
    store_secret,
)

WINDOWS = os.name == "nt"
posix_only = pytest.mark.skipif(WINDOWS, reason="POSIX permission semantics only")


@posix_only
class TestHardenPermissions:
    def test_file_becomes_owner_only(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("api_key: sk-secret", encoding="utf-8")
        os.chmod(f, 0o644)
        assert harden_file_permissions(f) is True
        mode = stat.S_IMODE(f.stat().st_mode)
        assert mode == 0o600

    def test_dir_becomes_owner_only(self, tmp_path):
        d = tmp_path / "vulnclaw"
        d.mkdir()
        os.chmod(d, 0o755)
        assert harden_dir_permissions(d) is True
        assert stat.S_IMODE(d.stat().st_mode) == 0o700

    def test_missing_file_is_noop(self, tmp_path):
        assert harden_file_permissions(tmp_path / "nope") is False


@posix_only
class TestCheckPermissions:
    def test_owner_only_has_no_finding(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("x", encoding="utf-8")
        os.chmod(f, 0o600)
        assert check_file_permissions(f) is None

    def test_world_readable_is_flagged(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("x", encoding="utf-8")
        os.chmod(f, 0o644)
        finding = check_file_permissions(f)
        assert finding is not None
        assert finding.world_accessible is True
        assert "chmod 600" in finding.message()

    def test_group_readable_is_flagged(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("x", encoding="utf-8")
        os.chmod(f, 0o640)
        finding = check_file_permissions(f)
        assert finding is not None
        assert finding.group_accessible is True
        assert finding.world_accessible is False

    def test_missing_file_has_no_finding(self, tmp_path):
        assert check_file_permissions(tmp_path / "nope") is None

    def test_audit_reports_only_loose_files(self, tmp_path):
        safe = tmp_path / "safe.yaml"
        safe.write_text("x", encoding="utf-8")
        os.chmod(safe, 0o600)
        loose = tmp_path / "loose.yaml"
        loose.write_text("x", encoding="utf-8")
        os.chmod(loose, 0o644)
        findings = audit_sensitive_files([safe, loose, tmp_path / "missing"])
        assert [f.path for f in findings] == [str(loose)]


class TestKeyringOptional:
    def test_helpers_degrade_gracefully(self):
        # With keyring absent, store/load must not raise and must signal absence.
        available = keyring_available()
        assert isinstance(available, bool)
        if not available:
            assert store_secret("k", "v") is False
            assert load_secret("k") is None
