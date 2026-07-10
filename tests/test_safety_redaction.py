"""Tests for the central secret-redaction utility (vulnclaw.safety.redaction)."""

from __future__ import annotations

from vulnclaw.safety import redaction

# Realistic-looking but fake credentials used purely to exercise the patterns.
OPENAI = "sk-abc123DEF456ghi789JKL012mno345PQR678stu"
ANTHROPIC = "sk-ant-api03-abcdefABCDEF0123456789_-abcdef"
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
AWS = "AKIAIOSFODNN7EXAMPLE"
GITHUB = "ghp_1234567890abcdefABCDEF1234567890abcd"
GOOGLE = "AIzaSyA1234567890abcdefghijklmnopqrstuv"
PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA0abcd1234\n"
    "efgh5678ijkl\n"
    "-----END RSA PRIVATE KEY-----"
)


class TestRedact:
    def test_openai_key_redacted(self):
        out = redaction.redact(f"key is {OPENAI} ok")
        assert OPENAI not in out
        assert "REDACTED:openai_key" in out

    def test_anthropic_key_redacted(self):
        out = redaction.redact(f"ANTHROPIC_API_KEY={ANTHROPIC}")
        assert ANTHROPIC not in out
        assert "REDACTED" in out

    def test_jwt_redacted(self):
        out = redaction.redact(f"token {JWT}")
        assert JWT not in out
        assert "REDACTED:jwt" in out

    def test_aws_access_key_redacted(self):
        out = redaction.redact(f"aws {AWS} end")
        assert AWS not in out
        assert "REDACTED:aws_access_key_id" in out

    def test_github_token_redacted(self):
        out = redaction.redact(f"gh {GITHUB}")
        assert GITHUB not in out
        assert "REDACTED:github_token" in out

    def test_google_api_key_redacted(self):
        out = redaction.redact(f"g {GOOGLE}")
        assert GOOGLE not in out
        assert "REDACTED:google_api_key" in out

    def test_bearer_token_redacted(self):
        out = redaction.redact("Authorization: Bearer abc123.def456-ghi789_JKL")
        assert "abc123.def456-ghi789_JKL" not in out
        assert "REDACTED:bearer" in out
        assert "Bearer" in out  # scheme preserved

    def test_private_key_block_redacted(self):
        out = redaction.redact(PRIVATE_KEY)
        assert "MIIEowIBAAKCAQEA" not in out
        assert "REDACTED:private_key" in out

    def test_env_assignment_value_redacted(self):
        out = redaction.redact("DB_PASSWORD=s3cr3tP@ssw0rd123")
        assert "s3cr3tP@ssw0rd123" not in out
        assert "DB_PASSWORD=" in out  # key preserved, value gone
        assert "REDACTED" in out

    def test_non_secret_literal_not_redacted(self):
        assert redaction.redact("token: true") == "token: true"
        assert redaction.redact("secret: null") == "secret: null"

    def test_benign_text_unchanged(self):
        text = "The quick brown fox connects to http://localhost:8080/app"
        assert redaction.redact(text) == text

    def test_no_double_redaction(self):
        out = redaction.redact(f"api_key={OPENAI}")
        # Exactly one redaction token, not a nested/re-redacted mess.
        assert out.count("REDACTED") == 1

    def test_non_string_input_coerced(self):
        assert redaction.redact(None) == ""
        assert redaction.redact(1234) == "1234"


class TestFingerprint:
    def test_deterministic_and_non_reversible(self):
        fp1 = redaction.fingerprint(OPENAI)
        fp2 = redaction.fingerprint(OPENAI)
        assert fp1 == fp2
        assert len(fp1) == 12
        assert OPENAI not in fp1
        assert redaction.fingerprint("other") != fp1


class TestRedactObj:
    def test_nested_structures(self):
        obj = {"a": f"Bearer {JWT}", "b": ["ok", f"k={OPENAI}"], "n": 5}
        out = redaction.redact_obj(obj)
        assert JWT not in str(out)
        assert OPENAI not in str(out)
        assert out["n"] == 5


class TestDetectSecrets:
    def test_returns_type_and_fingerprint_only(self):
        found = redaction.detect_secrets(f"here is {JWT} and {AWS}")
        types = {f["type"] for f in found}
        assert "jwt" in types
        assert "aws_access_key_id" in types
        # Never expose the raw value in the detection metadata.
        blob = str(found)
        assert JWT not in blob
        assert AWS not in blob
        for f in found:
            assert set(f.keys()) == {"type", "fingerprint"}

    def test_empty_input(self):
        assert redaction.detect_secrets("") == []
        assert redaction.detect_secrets(None) == []

    def test_contains_secret(self):
        assert redaction.contains_secret(f"x {OPENAI}") is True
        assert redaction.contains_secret("nothing here") is False
