from __future__ import annotations

import pytest

from restricted_exec.shell_sanitizer import (
    PythonStep,
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
        plan = sanitize_shell_to_plan(basic_policy, "mkdir --path d && echo hello ; echo world")
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
        with pytest.raises(ShellDenied, match="Glob character"):
            sanitize_shell_to_plan(basic_policy, "echo *")

    def test_globbing_question(self, basic_policy):
        with pytest.raises(ShellDenied, match="Glob character"):
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


class TestPythonCommandInterception:
    """Tests for python/python3 -c interception in shell sanitizer."""

    def test_python3_c_produces_python_step(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, "python3 -c 'print(1)'")
        assert len(plan.steps) == 1
        assert isinstance(plan.steps[0], PythonStep)
        assert plan.steps[0].python_src == "print(1)"

    def test_python_c_produces_python_step(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, "python -c 'x = 42'")
        assert len(plan.steps) == 1
        assert isinstance(plan.steps[0], PythonStep)
        assert plan.steps[0].python_src == "x = 42"

    def test_python3_c_double_quoted(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, 'python3 -c "x = 42"')
        assert isinstance(plan.steps[0], PythonStep)
        assert plan.steps[0].python_src == "x = 42"

    def test_python3_c_in_sequence_with_shell(self, basic_policy):
        plan = sanitize_shell_to_plan(
            basic_policy, "echo hello && python3 -c 'print(1)' && echo done"
        )
        assert len(plan.steps) == 3
        assert isinstance(plan.steps[0], Step)
        assert plan.steps[0].command_id == "echo"
        assert isinstance(plan.steps[1], PythonStep)
        assert plan.steps[1].python_src == "print(1)"
        assert isinstance(plan.steps[2], Step)
        assert plan.steps[2].command_id == "echo"

    def test_python3_c_with_semicolon_sequence(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, "echo before ; python3 -c 'x = 1' ; echo after")
        assert len(plan.steps) == 3
        assert isinstance(plan.steps[1], PythonStep)

    def test_python3_c_with_redirect(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, "python3 -c 'print(1)' > out.txt")
        assert isinstance(plan.steps[0], PythonStep)
        assert plan.steps[0].redirect.stdout_path == "out.txt"
        assert plan.steps[0].redirect.stdout_append is False

    def test_python3_c_with_append_redirect(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, "python3 -c 'print(1)' >> out.txt")
        assert isinstance(plan.steps[0], PythonStep)
        assert plan.steps[0].redirect.stdout_append is True

    def test_python3_c_star_in_code_allowed(self, basic_policy):
        """Python multiplication operator must be allowed in -c code."""
        plan = sanitize_shell_to_plan(basic_policy, "python3 -c 'x = 2 * 3'")
        assert isinstance(plan.steps[0], PythonStep)
        assert plan.steps[0].python_src == "x = 2 * 3"

    def test_python3_c_double_star_in_code_allowed(self, basic_policy):
        """Python exponentiation operator must be allowed."""
        plan = sanitize_shell_to_plan(basic_policy, "python3 -c 'x = 2 ** 3'")
        assert isinstance(plan.steps[0], PythonStep)
        assert "**" in plan.steps[0].python_src

    def test_bare_python3_denied(self, basic_policy):
        with pytest.raises(ShellDenied, match="interactive mode"):
            sanitize_shell_to_plan(basic_policy, "python3")

    def test_bare_python_denied(self, basic_policy):
        with pytest.raises(ShellDenied, match="interactive mode"):
            sanitize_shell_to_plan(basic_policy, "python")

    def test_python3_script_denied(self, basic_policy):
        with pytest.raises(ShellDenied, match="Only.*-c"):
            sanitize_shell_to_plan(basic_policy, "python3 script.py")

    def test_python3_module_denied(self, basic_policy):
        with pytest.raises(ShellDenied, match="Only.*-c"):
            sanitize_shell_to_plan(basic_policy, "python3 -m json.tool")

    def test_python3_version_flag_denied(self, basic_policy):
        with pytest.raises(ShellDenied, match="Only.*-c"):
            sanitize_shell_to_plan(basic_policy, "python3 --version")

    def test_python3_c_extra_args_denied(self, basic_policy):
        with pytest.raises(ShellDenied, match="exactly one code argument"):
            sanitize_shell_to_plan(basic_policy, "python3 -c 'print(1)' extra")

    def test_python3_c_no_code_denied(self, basic_policy):
        with pytest.raises(ShellDenied, match="exactly one code argument"):
            sanitize_shell_to_plan(basic_policy, "python3 -c")

    def test_python3_in_pipeline_denied(self, basic_policy):
        with pytest.raises(ShellDenied, match="Piping.*inline Python"):
            sanitize_shell_to_plan(basic_policy, "echo hello | python3 -c 'print(1)'")

    def test_python3_pipe_to_shell_denied(self, basic_policy):
        with pytest.raises(ShellDenied, match="Piping.*inline Python"):
            sanitize_shell_to_plan(basic_policy, "python3 -c 'print(1)' | cat")

    def test_python3_c_shell_expansion_in_code_denied(self, basic_policy):
        """Shell expansion markers in Python code must still be denied."""
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "python3 -c 'x = $(whoami)'")

    def test_plan_metadata_with_python_step(self, basic_policy):
        plan = sanitize_shell_to_plan(basic_policy, "python3 -c 'x = 1'")
        assert plan.policy_id == "test"
        assert plan.policy_version == "0.1"


class TestGlobTokenMovedToPerWord:
    """Verify glob denial moved from FORBIDDEN_TOKENS to _word_to_literal."""

    def test_star_in_shell_arg_still_denied(self, basic_policy):
        with pytest.raises(ShellDenied, match="Glob character"):
            sanitize_shell_to_plan(basic_policy, "echo *")

    def test_question_in_shell_arg_still_denied(self, basic_policy):
        with pytest.raises(ShellDenied, match="Glob character"):
            sanitize_shell_to_plan(basic_policy, "echo file?.txt")

    def test_star_in_python_code_allowed(self, basic_policy):
        """Star moved out of FORBIDDEN_TOKENS, so python -c can use it."""
        plan = sanitize_shell_to_plan(basic_policy, "python3 -c 'x = 2 * 3'")
        assert isinstance(plan.steps[0], PythonStep)

    def test_dollar_paren_still_denied_early(self, basic_policy):
        with pytest.raises(ShellDenied, match="Forbidden token"):
            sanitize_shell_to_plan(basic_policy, "echo $(whoami)")

    def test_backtick_still_denied_early(self, basic_policy):
        with pytest.raises(ShellDenied, match="Forbidden token"):
            sanitize_shell_to_plan(basic_policy, "echo `whoami`")

    def test_process_substitution_still_denied_early(self, basic_policy):
        with pytest.raises(ShellDenied, match="Forbidden token"):
            sanitize_shell_to_plan(basic_policy, "cat <(echo hello)")
