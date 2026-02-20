"""
Tests for unicode edge cases in shell word parsing and
filesystem path resolution: zero-width characters, RTL overrides,
combining characters, normalization, and homograph attacks.

Maps to SECURITY.md: A-11 (bashlex parsing), A-20 (path traversal).
"""

from __future__ import annotations

import pytest

from restricted_exec.policy import ArgSpec, CommandSpec, EnginePolicy
from restricted_exec.shell_sanitizer import sanitize_shell_to_plan
from restricted_exec.fs_sandbox import ensure_under_root


def _make_policy(workspace):
    return EnginePolicy(
        policy_id="test-uni",
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


class TestUnicodeShellParsing:
    """Test unicode handling in shell sanitizer word extraction."""

    def test_zero_width_joiner_in_shell_word(self, workspace):
        """Zero-width joiner shouldn't affect command parsing."""
        policy = _make_policy(workspace)
        src = "echo hello\u200Dworld"
        plan = sanitize_shell_to_plan(policy, src)
        assert plan.steps[0].args["value"] == "hello\u200Dworld"

    def test_homograph_latin_vs_cyrillic_a(self, workspace):
        """Cyrillic 'а' (U+0430) vs Latin 'a' — different characters."""
        policy = _make_policy(workspace)
        src = "echo \u0430bc"
        plan = sanitize_shell_to_plan(policy, src)
        assert plan.steps[0].args["value"] == "\u0430bc"


class TestUnicodePathTraversal:
    """Test unicode handling in filesystem sandbox path resolution."""

    def test_zero_width_space_in_path(self, workspace):
        """Zero-width space in a path is preserved by realpath."""
        path = "sub\u200Bdir/file.txt"
        resolved = ensure_under_root(workspace, path)
        assert resolved.startswith(workspace)

    def test_rtl_override_in_path(self, workspace):
        """RTL override character in path doesn't escape workspace."""
        path = "sub\u202Edir/file.txt"
        resolved = ensure_under_root(workspace, path)
        assert resolved.startswith(workspace)

    def test_combining_dot_above_not_period(self, workspace):
        """Combining dot-above (U+0307) is NOT a real period for path traversal."""
        path = "\u0307\u0307/etc/passwd"
        resolved = ensure_under_root(workspace, path)
        assert resolved.startswith(workspace)

    def test_nfc_nfd_normalization_path(self, workspace):
        """NFC vs NFD normalization — ensure_under_root handles both."""
        nfc_path = "caf\u00e9/file.txt"
        nfd_path = "cafe\u0301/file.txt"

        nfc_resolved = ensure_under_root(workspace, nfc_path)
        nfd_resolved = ensure_under_root(workspace, nfd_path)

        assert nfc_resolved.startswith(workspace)
        assert nfd_resolved.startswith(workspace)

    def test_fullwidth_period_not_traversal(self, workspace):
        """Fullwidth period (U+FF0E) is NOT a real period for path traversal."""
        path = "\uff0e\uff0e/etc/passwd"
        resolved = ensure_under_root(workspace, path)
        assert resolved.startswith(workspace)
