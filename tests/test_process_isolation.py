"""
Tests for process-level isolation: environment variable leakage,
pipeline timeouts, process cleanup, and zombie prevention.

Maps to SECURITY.md: A-22 (env leakage), F-03 (no env= in Popen),
pipeline timeout behavior, process group management.
"""

from __future__ import annotations

import os
import time

import pytest

from restricted_exec.policy import ArgSpec, CommandSpec, EnginePolicy
from restricted_exec.executor import execute_plan
from restricted_exec.shell_sanitizer import (
    Plan as ShellPlan,
    Step as ShellStep,
    PythonStep,
    Redirect,
    ShellDenied,
    sanitize_shell_to_plan,
)
from restricted_exec.audit import AuditEvent, AuditSink


def _make_policy(workspace):
    """Build a policy with echo, cat, env, and sleep."""
    return EnginePolicy(
        policy_id="test-iso",
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
            "cat": CommandSpec(
                command_id="cat",
                description="Read file or stdin",
                exec_path="/bin/cat",
                base_argv=[],
                args={"file": ArgSpec(kind="string", required=False, regex=r"^[A-Za-z0-9_\-\/\.]{1,200}$")},
                arg_map={"file": ["{file}"]},
                timeout_s=5,
            ),
            "env": CommandSpec(
                command_id="env",
                description="Print environment",
                exec_path="/usr/bin/env",
                base_argv=[],
                args={},
                arg_map={},
                timeout_s=2,
            ),
            "sleep": CommandSpec(
                command_id="sleep",
                description="Sleep N seconds",
                exec_path="/bin/sleep",
                base_argv=[],
                args={"value": ArgSpec(kind="string", max_len=10, deny_chars=";&|`$<>\n\r")},
                arg_map={"value": ["{value}"]},
                timeout_s=2,
            ),
        },
    )


def _run_shell(policy, steps, allowed_api=None):
    plan = ShellPlan(
        policy_id=policy.policy_id,
        policy_version=policy.version,
        steps=steps,
        explain={"summary": "test"},
    )
    return execute_plan(
        policy, plan,
        actor={"type": "test", "id": "iso-test", "tenant": "test"},
        request_id="iso-test-1",
        cwd=policy.workspace_root,
        allowed_api=allowed_api,
    )


# ---------------------------------------------------------------------------
# Environment variable isolation (A-22, F-03)
# ---------------------------------------------------------------------------


class TestEnvIsolation:
    """Document that child processes inherit parent env (unmitigated gap).

    These tests PASS today because the gap exists. They should FAIL
    when env isolation is implemented (adding env={} to Popen).
    """

    def test_child_inherits_home(self, workspace):
        """Child process can see $HOME from parent."""
        policy = _make_policy(workspace)
        result = _run_shell(policy, [
            ShellStep(command_id="env", args={}, redirect=Redirect()),
        ])
        stdout = result["stdout"]["text"]
        assert "HOME=" in stdout

    def test_child_inherits_path(self, workspace):
        """Child process can see $PATH from parent."""
        policy = _make_policy(workspace)
        result = _run_shell(policy, [
            ShellStep(command_id="env", args={}, redirect=Redirect()),
        ])
        stdout = result["stdout"]["text"]
        assert "PATH=" in stdout

    def test_child_sees_injected_secret(self, workspace):
        """If parent has a secret env var, child sees it too."""
        old = os.environ.get("TEST_SECRET_12345")
        os.environ["TEST_SECRET_12345"] = "super-secret-value"
        try:
            policy = _make_policy(workspace)
            result = _run_shell(policy, [
                ShellStep(command_id="env", args={}, redirect=Redirect()),
            ])
            stdout = result["stdout"]["text"]
            assert "TEST_SECRET_12345=super-secret-value" in stdout
        finally:
            if old is None:
                del os.environ["TEST_SECRET_12345"]
            else:
                os.environ["TEST_SECRET_12345"] = old


# ---------------------------------------------------------------------------
# Pipeline timeout behavior
# ---------------------------------------------------------------------------


class TestPipelineTimeout:
    """Test that timeout fires and cleans up all processes in a pipeline."""

    def test_last_command_timeout(self, workspace):
        """sleep as the only command — should timeout."""
        policy = _make_policy(workspace)
        result = _run_shell(policy, [
            ShellStep(command_id="sleep", args={"value": "999"}, redirect=Redirect()),
        ])
        assert result["timed_out"] is True

    def test_pipeline_last_step_timeout(self, workspace):
        """echo | sleep — last step times out, all procs killed."""
        policy = _make_policy(workspace)
        result = _run_shell(policy, [
            ShellStep(command_id="echo", args={"value": "hi"}, redirect=Redirect()),
            ShellStep(command_id="sleep", args={"value": "999"}, redirect=Redirect()),
        ])
        assert result["timed_out"] is True
        assert len(result["return_codes"]) >= 1

    def test_pipeline_first_step_timeout(self, workspace):
        """sleep | cat — first step blocks, but timeout fires on last step's communicate()."""
        policy = _make_policy(workspace)
        start = time.time()
        result = _run_shell(policy, [
            ShellStep(command_id="sleep", args={"value": "999"}, redirect=Redirect()),
            ShellStep(command_id="cat", args={}, redirect=Redirect()),
        ])
        elapsed = time.time() - start
        assert elapsed < 15

    def test_timeout_returns_return_codes(self, workspace):
        """After timeout, all processes have return codes (no zombies)."""
        policy = _make_policy(workspace)
        result = _run_shell(policy, [
            ShellStep(command_id="sleep", args={"value": "999"}, redirect=Redirect()),
        ])
        assert result["timed_out"] is True
        assert len(result["return_codes"]) > 0


# ---------------------------------------------------------------------------
# Process cleanup and return codes
# ---------------------------------------------------------------------------


class TestProcessCleanup:
    """Test process cleanup after execution."""

    def test_single_command_returns_one_rc(self, workspace):
        """Single command produces exactly one return code."""
        policy = _make_policy(workspace)
        result = _run_shell(policy, [
            ShellStep(command_id="echo", args={"value": "hi"}, redirect=Redirect()),
        ])
        assert len(result["return_codes"]) == 1
        assert result["return_codes"][0] == 0

    def test_pipeline_returns_all_rcs(self, workspace):
        """Pipeline of N commands produces N return codes."""
        policy = _make_policy(workspace)
        result = _run_shell(policy, [
            ShellStep(command_id="echo", args={"value": "hello"}, redirect=Redirect()),
            ShellStep(command_id="cat", args={}, redirect=Redirect()),
        ])
        assert len(result["return_codes"]) == 2

    def test_failed_command_nonzero_rc(self, workspace):
        """Command that fails returns nonzero exit code."""
        policy = _make_policy(workspace)
        result = _run_shell(policy, [
            ShellStep(
                command_id="cat",
                args={"file": "nonexistent_file_12345.txt"},
                redirect=Redirect(),
            ),
        ])
        assert result["return_codes"][-1] != 0

    def test_empty_plan_raises(self, workspace):
        """Empty shell input is rejected (bashlex parse fails on empty string)."""
        policy = _make_policy(workspace)
        with pytest.raises(ShellDenied, match="Shell parse failed"):
            sanitize_shell_to_plan(policy, "")

    def test_inline_python_step_drains_prev_proc(self, workspace):
        """When an inline Python step follows a shell step, prev proc is drained."""
        policy = _make_policy(workspace)
        api_set = {"mkdir", "write_text", "write_json", "read_text", "http_get"}
        plan = ShellPlan(
            policy_id=policy.policy_id,
            policy_version=policy.version,
            steps=[
                ShellStep(command_id="echo", args={"value": "before"}, redirect=Redirect()),
                PythonStep(python_src="print(1 + 1)", redirect=Redirect()),
            ],
            explain={"summary": "test drain"},
        )
        result = execute_plan(
            policy, plan,
            actor={"type": "test", "id": "t1", "tenant": "t"},
            request_id="drain-test",
            allowed_api=api_set,
        )
        assert len(result["return_codes"]) >= 2

    def test_audit_events_ordered_in_pipeline(self, workspace):
        """Audit events for a multi-step plan arrive in order."""

        class CollectingSink(AuditSink):
            def __init__(self):
                self.events = []

            def emit(self, ev):
                self.events.append(ev)

        sink = CollectingSink()
        policy = _make_policy(workspace)
        plan = ShellPlan(
            policy_id=policy.policy_id,
            policy_version=policy.version,
            steps=[
                ShellStep(command_id="echo", args={"value": "a"}, redirect=Redirect()),
                ShellStep(command_id="echo", args={"value": "b"}, redirect=Redirect()),
            ],
            explain={"summary": "test"},
        )
        execute_plan(
            policy, plan,
            actor={"type": "test", "id": "t1", "tenant": "t"},
            request_id="audit-order-test",
            audit=sink,
        )

        event_types = [e.event for e in sink.events]
        assert event_types[0] == "plan_ready"
        assert event_types[-1] == "plan_done"
        step_starts = [e for e in sink.events if e.event == "step_start"]
        assert len(step_starts) == 2
        assert step_starts[0].details["index"] == 0
        assert step_starts[1].details["index"] == 1
