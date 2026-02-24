"""
Tests for input validation edge cases: argument validation,
redirect handling, output sanitization, and audit serialization.

Maps to SECURITY.md: A-33 (redirect escape), A-34 (audit tampering),
and general policy validation correctness.
"""

from __future__ import annotations

import json
import os

import pytest

from restricted_exec.policy import ArgSpec, CommandSpec, EnginePolicy, PolicyError
from restricted_exec.executor import ValidationError, _validate_arg, _build_argv, execute_plan
from restricted_exec.shell_sanitizer import (
    Plan as ShellPlan,
    Step as ShellStep,
    Redirect,
)
from restricted_exec.audit import AuditEvent, now
from restricted_exec.output_sanitize import sanitize_output


def _make_policy(workspace):
    return EnginePolicy(
        policy_id="test-val",
        version="0.1",
        workspace_root=workspace,
        commands={
            "echo": CommandSpec(
                command_id="echo",
                description="Echo a value",
                exec_path="/bin/echo",
                base_argv=[],
                args={"value": ArgSpec(kind="string", max_len=200)},
                arg_map={"value": ["{value}"]},
                timeout_s=2,
            ),
        },
    )


def _run_shell(policy, steps):
    plan = ShellPlan(
        policy_id=policy.policy_id,
        policy_version=policy.version,
        steps=steps,
        explain={"summary": "test"},
    )
    return execute_plan(
        policy,
        plan,
        actor={"type": "test", "id": "val-test", "tenant": "test"},
        request_id="val-test-1",
        cwd=policy.workspace_root,
    )


# ---------------------------------------------------------------------------
# Redirect edge cases (A-33)
# ---------------------------------------------------------------------------


class TestRedirectEdgeCases:
    """Test redirect path handling edge cases in executor."""

    def test_redirect_very_long_path(self, workspace):
        """Redirect to extremely long path — should not crash."""
        policy = _make_policy(workspace)
        long_name = "a" * 250
        result = _run_shell(
            policy,
            [
                ShellStep(
                    command_id="echo",
                    args={"value": "test"},
                    redirect=Redirect(stdout_path=long_name),
                )
            ],
        )
        assert result["return_codes"][-1] == 0

    def test_redirect_append_creates_file(self, workspace):
        """Redirect with append mode creates file if it doesn't exist."""
        policy = _make_policy(workspace)
        result = _run_shell(
            policy,
            [
                ShellStep(
                    command_id="echo",
                    args={"value": "first"},
                    redirect=Redirect(stdout_path="append_test.txt", stdout_append=True),
                )
            ],
        )
        assert result["return_codes"][-1] == 0
        outpath = os.path.join(workspace, "append_test.txt")
        assert os.path.exists(outpath)
        with open(outpath) as f:
            assert "first" in f.read()

    def test_redirect_append_accumulates(self, workspace):
        """Multiple appends to same file accumulate content."""
        policy = _make_policy(workspace)
        for val in ["line1", "line2", "line3"]:
            _run_shell(
                policy,
                [
                    ShellStep(
                        command_id="echo",
                        args={"value": val},
                        redirect=Redirect(stdout_path="multi.txt", stdout_append=True),
                    )
                ],
            )

        content = open(os.path.join(workspace, "multi.txt")).read()
        assert "line1" in content
        assert "line2" in content
        assert "line3" in content

    def test_redirect_overwrite_replaces(self, workspace):
        """Non-append redirect overwrites previous content."""
        policy = _make_policy(workspace)
        _run_shell(
            policy,
            [
                ShellStep(
                    command_id="echo",
                    args={"value": "old"},
                    redirect=Redirect(stdout_path="over.txt"),
                ),
            ],
        )
        _run_shell(
            policy,
            [
                ShellStep(
                    command_id="echo",
                    args={"value": "new"},
                    redirect=Redirect(stdout_path="over.txt"),
                ),
            ],
        )

        content = open(os.path.join(workspace, "over.txt")).read()
        assert "new" in content
        assert "old" not in content

    def test_redirect_to_subdirectory_created(self, workspace):
        """Redirect to nested path creates intermediate directories."""
        policy = _make_policy(workspace)
        result = _run_shell(
            policy,
            [
                ShellStep(
                    command_id="echo",
                    args={"value": "deep"},
                    redirect=Redirect(stdout_path="a/b/c/out.txt"),
                )
            ],
        )
        assert result["return_codes"][-1] == 0
        assert os.path.exists(os.path.join(workspace, "a/b/c/out.txt"))


# ---------------------------------------------------------------------------
# Policy / arg validation edge cases
# ---------------------------------------------------------------------------


class TestArgValidation:
    """Test policy and arg validation edge cases."""

    def test_unknown_arg_kind_raises(self):
        """Unknown arg kind raises PolicyError."""
        spec = ArgSpec(kind="binary")
        with pytest.raises(PolicyError, match="Unknown arg kind"):
            _validate_arg("data", spec, b"hello")

    def test_enum_with_empty_values_rejects(self):
        """Enum arg with empty values list rejects everything."""
        spec = ArgSpec(kind="enum", values=[])
        with pytest.raises(ValidationError, match="not allowed"):
            _validate_arg("mode", spec, "read")

    def test_enum_with_none_values_rejects(self):
        """Enum arg with None values rejects."""
        spec = ArgSpec(kind="enum", values=None)
        with pytest.raises(ValidationError, match="not allowed"):
            _validate_arg("mode", spec, "read")

    def test_string_min_and_max_len(self):
        """String arg with both min_len and max_len enforced."""
        spec = ArgSpec(kind="string", min_len=3, max_len=5, deny_chars="")
        with pytest.raises(ValidationError, match="too short"):
            _validate_arg("name", spec, "ab")
        with pytest.raises(ValidationError, match="too long"):
            _validate_arg("name", spec, "abcdef")
        assert _validate_arg("name", spec, "abcd") == "abcd"

    def test_int_below_min_rejected(self):
        """Int arg below min_value is rejected."""
        spec = ArgSpec(kind="int", min_value=0)
        with pytest.raises(ValidationError, match="below min"):
            _validate_arg("count", spec, -1)

    def test_int_above_max_rejected(self):
        """Int arg above max_value is rejected."""
        spec = ArgSpec(kind="int", max_value=100)
        with pytest.raises(ValidationError, match="above max"):
            _validate_arg("count", spec, 101)

    def test_nonabsolute_exec_path_rejected(self, workspace):
        """exec_path that isn't absolute is rejected at build time."""
        policy = EnginePolicy(
            policy_id="test",
            version="0.1",
            workspace_root=workspace,
            commands={
                "bad": CommandSpec(
                    command_id="bad",
                    description="bad",
                    exec_path="relative/path",
                    base_argv=[],
                    args={},
                    arg_map={},
                )
            },
        )
        step = ShellStep(command_id="bad", args={}, redirect=Redirect())
        with pytest.raises(ValidationError, match="exec_path must be absolute"):
            _build_argv(policy, step)

    def test_required_arg_missing_rejected(self):
        """Required arg that's missing raises ValidationError."""
        spec = ArgSpec(kind="string", required=True)
        with pytest.raises(ValidationError, match="Missing required"):
            _validate_arg("name", spec, None)

    def test_optional_arg_none_accepted(self):
        """Optional arg with None value returns None."""
        spec = ArgSpec(kind="string", required=False)
        assert _validate_arg("name", spec, None) is None


# ---------------------------------------------------------------------------
# Audit serialization edge cases (A-34)
# ---------------------------------------------------------------------------


class TestAuditEdgeCases:
    """Test audit event serialization edge cases."""

    def test_large_details_dict_serializes(self):
        """Audit event with large details dict serializes to JSON."""
        big = {f"key_{i}": f"value_{i}" for i in range(1000)}
        ev = AuditEvent(
            ts=now(),
            event="test",
            request_id="r-1",
            actor={"type": "test"},
            details=big,
        )
        parsed = json.loads(ev.to_json())
        assert len(parsed["details"]) == 1000

    def test_nested_details_serializes(self):
        """Deeply nested details dict serializes."""
        nested = {"a": {"b": {"c": {"d": {"e": "deep"}}}}}
        ev = AuditEvent(
            ts=now(),
            event="test",
            request_id="r-1",
            actor={"type": "test"},
            details=nested,
        )
        parsed = json.loads(ev.to_json())
        assert parsed["details"]["a"]["b"]["c"]["d"]["e"] == "deep"

    def test_special_chars_in_actor(self):
        """Actor dict with special characters serializes cleanly."""
        ev = AuditEvent(
            ts=now(),
            event="test",
            request_id="r-1",
            actor={"type": "test", "name": 'O\'Brien "the great"', "emoji": "\U0001f600"},
            details={},
        )
        parsed = json.loads(ev.to_json())
        assert parsed["actor"]["name"] == 'O\'Brien "the great"'


# ---------------------------------------------------------------------------
# Output sanitization edge cases
# ---------------------------------------------------------------------------


class TestOutputSanitizeEdgeCases:
    """Test output sanitization edge cases."""

    def test_binary_output_decoded_with_replacement(self):
        """Non-UTF8 bytes are decoded with replacement characters."""
        raw = b"hello \xff\xfe world"
        result = sanitize_output(raw)
        assert "\ufffd" in result["text"]
        assert "hello" in result["text"]

    def test_truncation_at_boundary(self):
        """Output exactly at max_chars is NOT truncated."""
        text = "x" * 50_000
        result = sanitize_output(text.encode(), max_chars=50_000)
        assert result["truncated"] is False

    def test_truncation_over_boundary(self):
        """Output over max_chars IS truncated."""
        text = "x" * 50_001
        result = sanitize_output(text.encode(), max_chars=50_000)
        assert result["truncated"] is True
        assert "[TRUNCATED]" in result["text"]

    def test_ansi_stripping(self):
        """ANSI escape codes are stripped from output."""
        raw = b"\x1b[31mERROR\x1b[0m: something"
        result = sanitize_output(raw, strip_ansi=True)
        assert "\x1b" not in result["text"]
        assert "ERROR: something" in result["text"]

    def test_empty_output(self):
        """Empty bytes produce empty text."""
        result = sanitize_output(b"")
        assert result["text"] == ""
        assert result["truncated"] is False
        assert result["redactions"] == []
