from __future__ import annotations

import pytest

from restricted_exec.output_sanitize import sanitize_output


class TestAnsiStripping:
    def test_strips_color_codes(self):
        raw = "\x1b[31mERROR\x1b[0m: something failed"
        result = sanitize_output(raw)
        assert "\x1b" not in result["text"]
        assert "ERROR: something failed" in result["text"]

    def test_strips_cursor_movement(self):
        raw = "\x1b[2J\x1b[H content here"
        result = sanitize_output(raw)
        assert "\x1b" not in result["text"]
        assert "content here" in result["text"]

    def test_no_strip_when_disabled(self):
        raw = "\x1b[31mRED\x1b[0m"
        result = sanitize_output(raw, strip_ansi=False)
        assert "\x1b[31m" in result["text"]

    def test_handles_bytes_input(self):
        raw = b"\x1b[32mGREEN\x1b[0m"
        result = sanitize_output(raw)
        assert "GREEN" in result["text"]
        assert "\x1b" not in result["text"]

    def test_handles_bytes_with_invalid_utf8(self):
        raw = b"hello \xff\xfe world"
        result = sanitize_output(raw)
        assert "hello" in result["text"]
        assert "world" in result["text"]


class TestRedaction:
    def test_redacts_bearer_token(self):
        raw = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc123"
        result = sanitize_output(raw)
        assert "eyJhbGciOiJIUzI1NiJ9" not in result["text"]
        assert "[REDACTED]" in result["text"]
        assert any(r["rule"] == "BEARER" for r in result["redactions"])

    def test_redacts_basic_auth(self):
        raw = "Authorization: Basic dXNlcjpwYXNz"
        result = sanitize_output(raw)
        assert "dXNlcjpwYXNz" not in result["text"]
        assert "[REDACTED]" in result["text"]

    def test_redacts_jwt(self):
        raw = "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = sanitize_output(raw)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result["text"]

    def test_redacts_private_key(self):
        raw = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ...\n-----END RSA PRIVATE KEY-----"
        result = sanitize_output(raw)
        assert "MIIBogIBAAJ" not in result["text"]
        assert "[REDACTED]" in result["text"]

    def test_redacts_api_key_pattern(self):
        raw = "api_key=sk_live_abcdef123456"
        result = sanitize_output(raw)
        assert "sk_live_abcdef123456" not in result["text"]

    def test_redacts_token_pattern(self):
        raw = "token: ghp_xxxxxxxxxxxxxxxxxxxx"
        result = sanitize_output(raw)
        assert "ghp_xxxxxxxxxxxxxxxxxxxx" not in result["text"]

    def test_no_redaction_when_disabled(self):
        raw = "Bearer eyJhbGciOiJIUzI1NiJ9.abc123"
        result = sanitize_output(raw, redact=False)
        assert "eyJhbGciOiJIUzI1NiJ9" in result["text"]
        assert result["redactions"] == []

    def test_clean_text_no_redactions(self):
        raw = "hello world, this is normal output"
        result = sanitize_output(raw)
        assert result["text"] == raw
        assert result["redactions"] == []


class TestTruncation:
    def test_truncates_long_output(self):
        raw = "x" * 100_000
        result = sanitize_output(raw, max_chars=1000)
        assert len(result["text"]) < 1100
        assert result["truncated"] is True
        assert "[TRUNCATED]" in result["text"]

    def test_no_truncation_under_limit(self):
        raw = "short output"
        result = sanitize_output(raw)
        assert result["truncated"] is False
        assert result["text"] == raw

    def test_exact_limit(self):
        raw = "x" * 50_000
        result = sanitize_output(raw, max_chars=50_000)
        assert result["truncated"] is False

    def test_one_over_limit(self):
        raw = "x" * 50_001
        result = sanitize_output(raw, max_chars=50_000)
        assert result["truncated"] is True
