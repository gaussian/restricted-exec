from __future__ import annotations

import os

import pytest

from restricted_exec.audit import AuditEvent, AuditSink
from restricted_exec.executor import ValidationError, execute_plan
from restricted_exec.policy import ArgSpec, CommandSpec, EnginePolicy
from restricted_exec.python_sanitizer import sanitize_python_to_plan
from restricted_exec.safe_api import SafeAPI
from restricted_exec.shell_sanitizer import PythonStep, sanitize_shell_to_plan


class CollectingSink(AuditSink):
    """Audit sink that collects events for assertions."""

    def __init__(self):
        self.events: list[AuditEvent] = []

    def emit(self, ev: AuditEvent) -> None:
        self.events.append(ev)


@pytest.fixture
def audit_sink():
    return CollectingSink()


class TestShellExecution:
    def test_simple_echo(self, basic_policy, default_actor, audit_sink):
        plan = sanitize_shell_to_plan(basic_policy, "echo hello")
        result = execute_plan(
            basic_policy,
            plan,
            actor=default_actor,
            request_id="test-1",
            audit=audit_sink,
        )
        assert result["type"] == "shell"
        assert result["return_codes"] == [0]
        assert result["timed_out"] is False
        assert "hello" in result["stdout"]["text"]

    def test_pipeline(self, basic_policy, default_actor, audit_sink):
        # echo hello | cat should pass through
        plan = sanitize_shell_to_plan(basic_policy, "echo hello | cat")
        result = execute_plan(
            basic_policy,
            plan,
            actor=default_actor,
            request_id="test-2",
            audit=audit_sink,
        )
        assert result["return_codes"] == [0, 0]
        assert "hello" in result["stdout"]["text"]

    def test_sequence(self, basic_policy, default_actor, audit_sink):
        plan = sanitize_shell_to_plan(
            basic_policy, "mkdir --path testdir && echo done"
        )
        result = execute_plan(
            basic_policy,
            plan,
            actor=default_actor,
            request_id="test-3",
            audit=audit_sink,
            cwd=basic_policy.workspace_root,
        )
        assert all(rc == 0 for rc in result["return_codes"])
        assert os.path.isdir(
            os.path.join(basic_policy.workspace_root, "testdir")
        )

    def test_redirect_to_file(self, basic_policy, default_actor, audit_sink):
        plan = sanitize_shell_to_plan(basic_policy, "echo hello > output.txt")
        result = execute_plan(
            basic_policy,
            plan,
            actor=default_actor,
            request_id="test-4",
            audit=audit_sink,
            cwd=basic_policy.workspace_root,
        )
        assert result["return_codes"] == [0]
        out_path = os.path.join(basic_policy.workspace_root, "output.txt")
        assert os.path.isfile(out_path)
        with open(out_path) as f:
            assert "hello" in f.read()

    def test_redirect_append(self, basic_policy, default_actor, audit_sink):
        ws = basic_policy.workspace_root
        # Write initial content
        with open(os.path.join(ws, "append.txt"), "w") as f:
            f.write("first\n")

        plan = sanitize_shell_to_plan(basic_policy, "echo second >> append.txt")
        execute_plan(
            basic_policy,
            plan,
            actor=default_actor,
            request_id="test-5",
            audit=audit_sink,
            cwd=ws,
        )
        with open(os.path.join(ws, "append.txt")) as f:
            content = f.read()
        assert "first" in content
        assert "second" in content

    def test_audit_events_emitted(self, basic_policy, default_actor, audit_sink):
        plan = sanitize_shell_to_plan(basic_policy, "echo hello")
        execute_plan(
            basic_policy,
            plan,
            actor=default_actor,
            request_id="test-audit",
            audit=audit_sink,
        )
        event_types = [ev.event for ev in audit_sink.events]
        assert "plan_ready" in event_types
        assert "step_start" in event_types
        assert "plan_done" in event_types

    def test_audit_request_id_propagated(self, basic_policy, default_actor, audit_sink):
        plan = sanitize_shell_to_plan(basic_policy, "echo hi")
        execute_plan(
            basic_policy,
            plan,
            actor=default_actor,
            request_id="my-req-id",
            audit=audit_sink,
        )
        for ev in audit_sink.events:
            assert ev.request_id == "my-req-id"

    def test_output_sanitization(self, basic_policy, default_actor, audit_sink):
        result = execute_plan(
            basic_policy,
            sanitize_shell_to_plan(basic_policy, "echo hello"),
            actor=default_actor,
            request_id="test-sanitize",
            audit=audit_sink,
        )
        assert "truncated" in result["stdout"]
        assert "redactions" in result["stdout"]


class TestShellExecutionValidation:
    def test_rejects_relative_exec_path(self, workspace, default_actor):
        policy = EnginePolicy(
            policy_id="bad",
            version="0.1",
            workspace_root=workspace,
            commands={
                "echo": CommandSpec(
                    command_id="echo",
                    description="bad exec_path",
                    exec_path="bin/echo",  # relative!
                    base_argv=[],
                    args={"value": ArgSpec(kind="string", max_len=200)},
                    arg_map={"value": ["{value}"]},
                    timeout_s=2,
                ),
            },
        )
        plan = sanitize_shell_to_plan(policy, "echo hello")
        with pytest.raises(ValidationError, match="exec_path must be absolute"):
            execute_plan(
                policy, plan, actor=default_actor, request_id="test-bad"
            )

    def test_validates_string_arg_max_len(self, workspace, default_actor):
        policy = EnginePolicy(
            policy_id="strict",
            version="0.1",
            workspace_root=workspace,
            commands={
                "echo": CommandSpec(
                    command_id="echo",
                    description="strict",
                    exec_path="/bin/echo",
                    base_argv=[],
                    args={"value": ArgSpec(kind="string", max_len=5)},
                    arg_map={"value": ["{value}"]},
                    timeout_s=2,
                ),
            },
        )
        plan = sanitize_shell_to_plan(policy, "echo toolong")
        with pytest.raises(ValidationError, match="too long"):
            execute_plan(
                policy, plan, actor=default_actor, request_id="test-len"
            )

    def test_validates_string_arg_regex(self, workspace, default_actor):
        policy = EnginePolicy(
            policy_id="regex",
            version="0.1",
            workspace_root=workspace,
            commands={
                "echo": CommandSpec(
                    command_id="echo",
                    description="regex",
                    exec_path="/bin/echo",
                    base_argv=[],
                    args={
                        "value": ArgSpec(
                            kind="string", max_len=200, regex=r"^[a-z]+$"
                        )
                    },
                    arg_map={"value": ["{value}"]},
                    timeout_s=2,
                ),
            },
        )
        plan = sanitize_shell_to_plan(policy, "echo UPPER")
        with pytest.raises(ValidationError, match="does not match regex"):
            execute_plan(
                policy, plan, actor=default_actor, request_id="test-regex"
            )

    def test_validates_enum_arg(self, workspace, default_actor):
        policy = EnginePolicy(
            policy_id="enum",
            version="0.1",
            workspace_root=workspace,
            commands={
                "echo": CommandSpec(
                    command_id="echo",
                    description="enum",
                    exec_path="/bin/echo",
                    base_argv=[],
                    args={
                        "value": ArgSpec(
                            kind="enum", values=["yes", "no"]
                        )
                    },
                    arg_map={"value": ["{value}"]},
                    timeout_s=2,
                ),
            },
        )
        plan = sanitize_shell_to_plan(policy, "echo maybe")
        with pytest.raises(ValidationError, match="not allowed"):
            execute_plan(
                policy, plan, actor=default_actor, request_id="test-enum"
            )

    def test_validates_deny_chars(self, workspace, default_actor):
        policy = EnginePolicy(
            policy_id="deny",
            version="0.1",
            workspace_root=workspace,
            commands={
                "echo": CommandSpec(
                    command_id="echo",
                    description="deny chars",
                    exec_path="/bin/echo",
                    base_argv=[],
                    args={"value": ArgSpec(kind="string", max_len=200)},
                    arg_map={"value": ["{value}"]},
                    timeout_s=2,
                ),
            },
        )
        # Default deny chars include semicolons and pipes
        plan = sanitize_shell_to_plan(policy, "echo 'hello;world'")
        with pytest.raises(ValidationError, match="forbidden char"):
            execute_plan(
                policy, plan, actor=default_actor, request_id="test-deny"
            )


class TestPythonExecution:
    def test_simple_assignment(self, empty_policy, default_actor, allowed_api, audit_sink):
        plan = sanitize_python_to_plan(empty_policy, "x = 42", allowed_api)
        result = execute_plan(
            empty_policy,
            plan,
            actor=default_actor,
            request_id="py-1",
            audit=audit_sink,
        )
        assert result["type"] == "python"
        assert result["ok"] is True
        assert result["error"] == ""

    def test_write_and_read(self, empty_policy, default_actor, allowed_api, audit_sink):
        src = '''
mkdir("test_out")
write_text("test_out/hello.txt", "world")
content = read_text("test_out/hello.txt")
'''
        plan = sanitize_python_to_plan(empty_policy, src, allowed_api)
        result = execute_plan(
            empty_policy,
            plan,
            actor=default_actor,
            request_id="py-2",
            audit=audit_sink,
        )
        assert result["ok"] is True
        path = os.path.join(
            os.path.realpath(empty_policy.workspace_root),
            "test_out/hello.txt",
        )
        assert os.path.isfile(path)

    def test_dict_subscript_at_runtime(self, empty_policy, default_actor, allowed_api, audit_sink):
        src = '''
d = {"a": 1, "b": 2}
x = d["a"]
write_text("result.txt", str(x))
'''
        plan = sanitize_python_to_plan(empty_policy, src, allowed_api)
        result = execute_plan(
            empty_policy,
            plan,
            actor=default_actor,
            request_id="py-3",
            audit=audit_sink,
        )
        assert result["ok"] is True

    def test_list_slice_at_runtime(self, empty_policy, default_actor, allowed_api, audit_sink):
        src = '''
items = [1, 2, 3, 4, 5]
subset = items[:3]
write_text("result.txt", str(len(subset)))
'''
        plan = sanitize_python_to_plan(empty_policy, src, allowed_api)
        result = execute_plan(
            empty_policy,
            plan,
            actor=default_actor,
            request_id="py-4",
            audit=audit_sink,
        )
        assert result["ok"] is True

    def test_runtime_error_captured(self, empty_policy, default_actor, allowed_api, audit_sink):
        src = '''
x = 1 / 0
'''
        plan = sanitize_python_to_plan(empty_policy, src, allowed_api)
        result = execute_plan(
            empty_policy,
            plan,
            actor=default_actor,
            request_id="py-err",
            audit=audit_sink,
        )
        assert result["ok"] is False
        assert "ZeroDivisionError" in result["error"]

    def test_audit_events_for_python(self, empty_policy, default_actor, allowed_api, audit_sink):
        plan = sanitize_python_to_plan(empty_policy, "x = 1", allowed_api)
        execute_plan(
            empty_policy,
            plan,
            actor=default_actor,
            request_id="py-audit",
            audit=audit_sink,
        )
        event_types = [ev.event for ev in audit_sink.events]
        assert "plan_ready" in event_types
        assert "plan_done" in event_types

    def test_custom_safe_api_passed(self, empty_policy, default_actor, audit_sink):
        api = SafeAPI(workspace_root=empty_policy.workspace_root)

        def custom_add(a: int, b: int) -> int:
            return a + b

        api.register("custom_add", custom_add, allowed_arg_types=(int,))

        src = """
result = custom_add(3, 4)
write_text("sum.txt", str(result))
"""
        all_api = api.get_all_api_names()
        plan = sanitize_python_to_plan(empty_policy, src, all_api)
        result = execute_plan(
            empty_policy,
            plan,
            actor=default_actor,
            request_id="py-custom",
            audit=audit_sink,
            safe_api=api,
        )
        assert result["ok"] is True
        path = os.path.join(
            os.path.realpath(empty_policy.workspace_root), "sum.txt"
        )
        with open(path) as f:
            assert f.read() == "7"


class TestInlinePythonExecution:
    """Tests for executing plans with inline Python steps (python3 -c)."""

    def test_basic_python3_c(self, basic_policy, default_actor, allowed_api, audit_sink):
        plan = sanitize_shell_to_plan(basic_policy, "python3 -c 'print(42)'")
        result = execute_plan(
            basic_policy,
            plan,
            actor=default_actor,
            request_id="inline-py-1",
            audit=audit_sink,
            allowed_api=allowed_api,
        )
        assert result["type"] == "shell"
        assert result["return_codes"] == [0]
        assert "42" in result["stdout"]["text"]

    def test_python3_c_with_shell_before_and_after(
        self, basic_policy, default_actor, allowed_api, audit_sink
    ):
        plan = sanitize_shell_to_plan(
            basic_policy, "echo before && python3 -c 'print(42)' && echo after"
        )
        result = execute_plan(
            basic_policy,
            plan,
            actor=default_actor,
            request_id="inline-py-2",
            audit=audit_sink,
            allowed_api=allowed_api,
        )
        assert all(rc == 0 for rc in result["return_codes"])

    def test_python3_c_malicious_import_denied(
        self, basic_policy, default_actor, allowed_api, audit_sink
    ):
        plan = sanitize_shell_to_plan(basic_policy, "python3 -c 'import os'")
        with pytest.raises(ValidationError, match="AST validation"):
            execute_plan(
                basic_policy,
                plan,
                actor=default_actor,
                request_id="inline-py-evil",
                audit=audit_sink,
                allowed_api=allowed_api,
            )

    def test_python3_c_malicious_eval_denied(
        self, basic_policy, default_actor, allowed_api, audit_sink
    ):
        plan = sanitize_shell_to_plan(
            basic_policy, "python3 -c 'eval(\"1+1\")'"
        )
        with pytest.raises(ValidationError, match="AST validation"):
            execute_plan(
                basic_policy,
                plan,
                actor=default_actor,
                request_id="inline-py-eval",
                audit=audit_sink,
                allowed_api=allowed_api,
            )

    def test_python3_c_redirect_to_file(
        self, basic_policy, default_actor, allowed_api, audit_sink
    ):
        plan = sanitize_shell_to_plan(
            basic_policy, "python3 -c 'print(42)' > result.txt"
        )
        result = execute_plan(
            basic_policy,
            plan,
            actor=default_actor,
            request_id="inline-py-redir",
            audit=audit_sink,
            cwd=basic_policy.workspace_root,
            allowed_api=allowed_api,
        )
        assert result["return_codes"] == [0]
        path = os.path.join(basic_policy.workspace_root, "result.txt")
        assert os.path.isfile(path)
        with open(path) as f:
            assert "42" in f.read()

    def test_python3_c_requires_allowed_api(
        self, basic_policy, default_actor, audit_sink
    ):
        plan = sanitize_shell_to_plan(basic_policy, "python3 -c 'x = 1'")
        with pytest.raises(ValidationError, match="allowed_api is required"):
            execute_plan(
                basic_policy,
                plan,
                actor=default_actor,
                request_id="inline-py-noapi",
                audit=audit_sink,
            )

    def test_python3_c_runtime_error_captured(
        self, basic_policy, default_actor, allowed_api, audit_sink
    ):
        plan = sanitize_shell_to_plan(basic_policy, "python3 -c 'x = 1 / 0'")
        result = execute_plan(
            basic_policy,
            plan,
            actor=default_actor,
            request_id="inline-py-err",
            audit=audit_sink,
            allowed_api=allowed_api,
        )
        assert result["return_codes"] == [1]

    def test_python3_c_audit_events(
        self, basic_policy, default_actor, allowed_api, audit_sink
    ):
        plan = sanitize_shell_to_plan(basic_policy, "python3 -c 'x = 1'")
        execute_plan(
            basic_policy,
            plan,
            actor=default_actor,
            request_id="inline-py-audit",
            audit=audit_sink,
            allowed_api=allowed_api,
        )
        event_types = [ev.event for ev in audit_sink.events]
        assert "plan_ready" in event_types
        assert "step_start" in event_types
        assert "plan_done" in event_types
        # Verify the step_start event has inline_python type
        step_events = [ev for ev in audit_sink.events if ev.event == "step_start"]
        assert any(ev.details.get("type") == "inline_python" for ev in step_events)

    def test_python3_c_with_safe_api_functions(
        self, basic_policy, default_actor, allowed_api, audit_sink
    ):
        plan = sanitize_shell_to_plan(
            basic_policy,
            "python3 -c 'mkdir(\"test_inline\")'"
        )
        result = execute_plan(
            basic_policy,
            plan,
            actor=default_actor,
            request_id="inline-py-api",
            audit=audit_sink,
            allowed_api=allowed_api,
        )
        assert result["return_codes"] == [0]
        assert os.path.isdir(
            os.path.join(
                os.path.realpath(basic_policy.workspace_root), "test_inline"
            )
        )
