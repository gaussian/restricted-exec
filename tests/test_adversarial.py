"""Adversarial / red-team tests for restricted-exec.

Every test in this module attempts to break or bypass a security layer.
Tests are organized by attack surface:
  A. Path traversal (fs_sandbox + SafeAPI)
  B. Python sandbox escapes (python_sanitizer)
  C. Shell injection (shell_sanitizer)
  D. Runtime escapes (executor integration)
  E. Cross-layer attacks (shell → Python → fs)
"""

from __future__ import annotations

import os

import pytest

from restricted_exec.audit import AuditEvent, AuditSink
from restricted_exec.executor import ValidationError, execute_plan
from restricted_exec.fs_sandbox import FsViolation, ensure_under_root
from restricted_exec.python_sanitizer import PythonDenied, sanitize_python_to_plan
from restricted_exec.safe_api import SafeAPI
from restricted_exec.shell_sanitizer import ShellDenied, sanitize_shell_to_plan


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class CollectingSink(AuditSink):
    def __init__(self):
        self.events: list[AuditEvent] = []

    def emit(self, ev: AuditEvent) -> None:
        self.events.append(ev)


# ===================================================================
# A. Path traversal — fs_sandbox + SafeAPI
# ===================================================================


class TestAdversarialPathTraversal:
    """Try every creative path trick to escape the workspace root."""

    def test_null_byte_in_path(self, workspace):
        """Null-byte injection: classic C-string termination attack."""
        with pytest.raises((FsViolation, ValueError)):
            ensure_under_root(workspace, "file\x00../../etc/passwd")

    def test_unicode_fullwidth_dots_stay_under_root(self, workspace):
        """Fullwidth periods (\uff0e) are NOT '..' — they're literal chars."""
        result = ensure_under_root(workspace, "\uff0e\uff0e/\uff0e\uff0e/etc/passwd")
        assert result.startswith(os.path.realpath(workspace))

    def test_unicode_fullwidth_slash_stays_under_root(self, workspace):
        """Fullwidth slash (\uff0f) is not a path separator on Unix."""
        # The \uff0f is a literal character, not os.sep
        result = ensure_under_root(workspace, "a\uff0fb\uff0fc")
        assert result.startswith(os.path.realpath(workspace))

    def test_very_long_path_no_escape(self, workspace):
        """10,000-segment path stays under root (or OS rejects it)."""
        long_path = "/".join(["a"] * 10000)
        result = ensure_under_root(workspace, long_path)
        assert result.startswith(os.path.realpath(workspace))

    def test_dot_is_root(self, workspace):
        """'.' resolves to root itself — allowed."""
        assert ensure_under_root(workspace, ".") == os.path.realpath(workspace)

    def test_single_dotdot_escapes(self, workspace):
        """'..' escapes the root — must be denied."""
        with pytest.raises(FsViolation, match="escapes workspace root"):
            ensure_under_root(workspace, "..")

    def test_triple_dot_is_literal(self, workspace):
        """'...' is a literal directory name, not a traversal — stays under root."""
        result = ensure_under_root(workspace, "...")
        assert result.startswith(os.path.realpath(workspace))

    def test_backslash_separator_on_unix(self, workspace):
        """On Unix, backslash is a literal filename char — no traversal."""
        result = ensure_under_root(workspace, "..\\..\\etc\\passwd")
        assert result.startswith(os.path.realpath(workspace))

    def test_symlink_escape_blocked(self, workspace):
        """Symlink inside workspace pointing outside must be caught."""
        link_path = os.path.join(workspace, "evil_link")
        os.symlink("/tmp", link_path)
        with pytest.raises(FsViolation, match="escapes workspace root"):
            ensure_under_root(workspace, "evil_link/somefile.txt")

    def test_absolute_path_prefix_trick(self, workspace):
        """Path that starts with root string but isn't a child (e.g. root + '_evil')."""
        root_real = os.path.realpath(workspace)
        evil_path = root_real + "_evil/file.txt"
        with pytest.raises(FsViolation, match="escapes workspace root"):
            ensure_under_root(workspace, evil_path)

    def test_url_encoded_dotdot_is_literal(self, workspace):
        """%2e%2e is literal text, not decoded to '..' by the OS."""
        result = ensure_under_root(workspace, "%2e%2e/%2e%2e/etc/passwd")
        assert result.startswith(os.path.realpath(workspace))

    def test_subdir_dotdot_escape(self, workspace):
        """subdir/../../etc/passwd escapes via dotdot in the middle."""
        with pytest.raises(FsViolation, match="escapes workspace root"):
            ensure_under_root(workspace, "subdir/../../etc/passwd")

    # -- SafeAPI wrappers --

    def test_safe_api_write_text_traversal(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        with pytest.raises(FsViolation):
            api.write_text("../../etc/evil.txt", "pwned")

    def test_safe_api_read_text_absolute(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        with pytest.raises(FsViolation):
            api.read_text("/etc/passwd")

    def test_safe_api_mkdir_traversal(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        with pytest.raises(FsViolation):
            api.mkdir("../../../tmp/evil")

    def test_safe_api_write_text_null_byte(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        with pytest.raises((FsViolation, ValueError)):
            api.write_text("file\x00.txt", "data")

    def test_safe_api_write_json_traversal(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        with pytest.raises(FsViolation):
            api.write_json("../../evil.json", {"pwned": True})


# ===================================================================
# B. Python sandbox escapes — python_sanitizer
# ===================================================================


class TestAdversarialPythonSandbox:
    """Try every known Python sandbox escape technique."""

    @pytest.fixture
    def api(self):
        return {"mkdir", "write_text", "write_json", "read_text", "http_get"}

    # -- Forbidden call attempts --

    def test_chr_to_build_dunder_import(self, empty_policy, api):
        """Build '__import__' string via chr() — chr is not allowlisted."""
        with pytest.raises(PythonDenied, match="not allowlisted"):
            sanitize_python_to_plan(
                empty_policy, 'x = chr(95) + chr(95) + "import" + chr(95) + chr(95)', api
            )

    def test_getattr_denied(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: getattr"):
            sanitize_python_to_plan(empty_policy, 'getattr([], "append")', api)

    def test_hasattr_denied(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: hasattr"):
            sanitize_python_to_plan(empty_policy, 'hasattr([], "__class__")', api)

    def test_type_denied(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: type"):
            sanitize_python_to_plan(empty_policy, "type([])", api)

    def test_super_denied(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: super"):
            sanitize_python_to_plan(empty_policy, "super()", api)

    def test_object_denied(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: object"):
            sanitize_python_to_plan(empty_policy, "object()", api)

    def test_bytes_denied(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: bytes"):
            sanitize_python_to_plan(empty_policy, "bytes(10)", api)

    def test_bytearray_denied(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: bytearray"):
            sanitize_python_to_plan(empty_policy, "bytearray(10)", api)

    def test_memoryview_denied(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: memoryview"):
            sanitize_python_to_plan(empty_policy, 'memoryview(b"hi")', api)

    def test_input_denied(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: input"):
            sanitize_python_to_plan(empty_policy, 'input("prompt: ")', api)

    def test_classmethod_denied(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: classmethod"):
            sanitize_python_to_plan(empty_policy, "classmethod(print)", api)

    def test_staticmethod_denied(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: staticmethod"):
            sanitize_python_to_plan(empty_policy, "staticmethod(print)", api)

    def test_property_denied(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: property"):
            sanitize_python_to_plan(empty_policy, "property(print)", api)

    # -- Attribute access / method call attempts --

    def test_print_class_attribute(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Attribute access"):
            sanitize_python_to_plan(empty_policy, "x = print.__class__", api)

    def test_list_class_mro(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Attribute access"):
            sanitize_python_to_plan(empty_policy, "x = [].__class__.__mro__", api)

    def test_tuple_class_bases_subclasses(self, empty_policy, api):
        with pytest.raises(PythonDenied):
            sanitize_python_to_plan(empty_policy, "().__class__.__bases__[0].__subclasses__()", api)

    def test_string_upper_method_call(self, empty_policy, api):
        with pytest.raises(PythonDenied):
            sanitize_python_to_plan(empty_policy, '"hello".upper()', api)

    def test_list_append_method_call(self, empty_policy, api):
        with pytest.raises(PythonDenied):
            sanitize_python_to_plan(empty_policy, "[1, 2].append(3)", api)

    def test_string_join_method_call(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="method calls"):
            sanitize_python_to_plan(empty_policy, 'x = " ".join(["a", "b"])', api)

    def test_string_format_method_call(self, empty_policy, api):
        with pytest.raises(PythonDenied):
            sanitize_python_to_plan(empty_policy, '"{0.__class__}".format(42)', api)

    def test_bytes_decode_method_call(self, empty_policy, api):
        with pytest.raises(PythonDenied):
            sanitize_python_to_plan(empty_policy, 'b"os".decode()', api)

    # -- Dunder name access --

    def test_dunder_builtins(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Dunder name"):
            sanitize_python_to_plan(empty_policy, "x = __builtins__", api)

    def test_dunder_name(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Dunder name"):
            sanitize_python_to_plan(empty_policy, "x = __name__", api)

    def test_dunder_file(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Dunder name"):
            sanitize_python_to_plan(empty_policy, "x = __file__", api)

    def test_dunder_doc(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Dunder name"):
            sanitize_python_to_plan(empty_policy, "x = __doc__", api)

    def test_dunder_spec(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Dunder name"):
            sanitize_python_to_plan(empty_policy, "x = __spec__", api)

    # -- f-string attempts --

    def test_fstring_with_expression(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="f-string"):
            sanitize_python_to_plan(empty_policy, 'x = f"value={1+1}"', api)

    def test_fstring_with_dunder(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="f-string"):
            sanitize_python_to_plan(empty_policy, "x = f'{__import__}'", api)

    # -- Forbidden syntax --

    def test_lambda_wrapping_import(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Lambda"):
            sanitize_python_to_plan(empty_policy, 'x = lambda: __import__("os")', api)

    def test_class_with_metaclass(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="ClassDef"):
            sanitize_python_to_plan(empty_policy, "class M(type): pass", api)

    def test_function_def_hiding_exec(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="FunctionDef"):
            sanitize_python_to_plan(empty_policy, 'def f(): exec("import os")\nf()', api)

    def test_try_except_catching_errors(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Try"):
            sanitize_python_to_plan(
                empty_policy, 'try:\n  x = __import__("os")\nexcept:\n  pass', api
            )

    def test_starred_unpacking(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Starred"):
            sanitize_python_to_plan(empty_policy, "a, *b = [1, 2, 3]", api)

    def test_global_statement(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Global"):
            sanitize_python_to_plan(empty_policy, "global __builtins__", api)

    def test_delete_variable(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Delete"):
            sanitize_python_to_plan(empty_policy, "x = 1\ndel x", api)

    # -- Indirect call attempts --

    def test_call_variable_holding_function_name(self, empty_policy, api):
        """e = 'exec'; e('code') — 'e' is not in the call allowlist."""
        with pytest.raises(PythonDenied, match="not allowlisted"):
            sanitize_python_to_plan(empty_policy, 'e = "exec"\ne("print(1)")', api)

    def test_subscript_call_denied(self, empty_policy, api):
        """d['fn']() — subscript call is not a direct Name call."""
        with pytest.raises(PythonDenied, match="Only direct function calls"):
            sanitize_python_to_plan(empty_policy, 'd = {"fn": "val"}\nd["fn"]()', api)

    # -- Constructs that SHOULD be allowed (positive controls) --

    def test_walrus_operator_allowed(self, empty_policy, api):
        """NamedExpr (:=) is not in DENY_NODES."""
        plan = sanitize_python_to_plan(empty_policy, "if (x := 5):\n  y = x", api)
        assert ":=" in plan.python_src

    def test_list_comprehension_allowed(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = [i for i in range(3)]", api)

    def test_nested_list_comprehension_allowed(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = [[j for j in range(i)] for i in range(3)]", api)

    def test_dict_comprehension_allowed(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = {str(i): i for i in range(3)}", api)

    def test_set_comprehension_allowed(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = {i for i in range(3)}", api)

    def test_deeply_nested_expression_allowed(self, empty_policy, api):
        expr = "1"
        for _ in range(50):
            expr = f"({expr} + 1)"
        sanitize_python_to_plan(empty_policy, f"x = {expr}", api)

    def test_subscript_on_call_result_allowed(self, empty_policy, api):
        """str(42)[0] — subscript on function result."""
        sanitize_python_to_plan(empty_policy, "x = str(42)[0]", api)

    def test_multiple_assignment_allowed(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "a = b = c = 1", api)

    def test_augmented_assignment_allowed(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = 1\nx += 1", api)

    def test_chained_comparison_allowed(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = 5\ny = 1 < x < 10", api)

    def test_unicode_variable_name_allowed(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "\u03b1 = 42", api)

    def test_empty_source_allowed(self, empty_policy, api):
        """Empty string is valid Python (empty module body)."""
        sanitize_python_to_plan(empty_policy, "", api)

    def test_comment_only_source_allowed(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "# just a comment\n", api)

    def test_percent_format_string_allowed(self, empty_policy, api):
        """'%s' % (42,) uses BinOp(Mod), not attribute access."""
        sanitize_python_to_plan(empty_policy, 'x = "%s" % (42,)', api)

    def test_dict_constructor_with_dunder_key_allowed(self, empty_policy, api):
        """dict(__builtins__='evil') just creates a normal dict — harmless."""
        sanitize_python_to_plan(empty_policy, 'x = dict(__builtins__="evil")', api)

    def test_ternary_expression_allowed(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = 1\ny = 10 if x else 20", api)

    def test_tuple_packing_allowed(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = (1, 2, 3)", api)

    def test_unary_operators_allowed(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = -1\ny = not True\nz = ~0", api)


# ===================================================================
# C. Shell injection — shell_sanitizer
# ===================================================================


class TestAdversarialShellInjection:
    """Try every shell injection and evasion technique."""

    def test_newline_injection(self, basic_policy):
        """Newline splits into two commands; second should fail allowlist."""
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "echo hello\nrm -rf /")

    def test_null_byte_in_shell_input(self, basic_policy):
        """Null byte in shell input — bashlex treats it as part of the word.
        The resulting value contains a null byte, which is in the executor's
        SAFE_STRING_DEFAULT_DENY (\\0), so it's blocked at execution time."""
        plan = sanitize_shell_to_plan(basic_policy, "echo hello\x00world")
        assert "\x00" in plan.steps[0].args["value"]

    def test_very_long_argument(self, basic_policy):
        """100K char argument — sanitizer has no length limit, but tests it parses."""
        plan = sanitize_shell_to_plan(basic_policy, "echo " + "A" * 100000)
        assert plan.steps[0].args["value"] == "A" * 100000

    def test_unicode_in_shell_word(self, basic_policy):
        """Unicode characters are literal words — should be allowed."""
        plan = sanitize_shell_to_plan(basic_policy, "echo caf\u00e9")
        assert plan.steps[0].args["value"] == "caf\u00e9"

    def test_heredoc_attempt_denied(self, basic_policy):
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "cat << EOF")

    def test_redirect_to_dotdot_path(self, basic_policy):
        with pytest.raises((FsViolation, ShellDenied)):
            sanitize_shell_to_plan(basic_policy, "echo evil > ../outside.txt")

    def test_redirect_to_absolute_path_outside(self, basic_policy):
        with pytest.raises((FsViolation, ShellDenied)):
            sanitize_shell_to_plan(basic_policy, "echo evil > /etc/evil.txt")

    def test_variable_assignment_prefix(self, basic_policy):
        """X=evil echo hello — env var assignment denied."""
        with pytest.raises(ShellDenied, match="Variable assignments"):
            sanitize_shell_to_plan(basic_policy, "X=evil echo hello")

    def test_backtick_in_single_quotes(self, basic_policy):
        """Backtick triggers FORBIDDEN_TOKENS early deny on raw source."""
        with pytest.raises(ShellDenied, match="Forbidden token"):
            sanitize_shell_to_plan(basic_policy, "echo '`whoami`'")

    def test_dollar_in_double_quotes(self, basic_policy):
        """$HOME in double quotes — expansion detected."""
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, 'echo "$HOME"')

    def test_process_substitution_output(self, basic_policy):
        with pytest.raises(ShellDenied, match="Forbidden token"):
            sanitize_shell_to_plan(basic_policy, "echo >(cat)")

    def test_or_operator(self, basic_policy):
        with pytest.raises(ShellDenied, match="Unsupported list operator"):
            sanitize_shell_to_plan(basic_policy, "echo a || echo b")

    def test_case_statement(self, basic_policy):
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "case x in a) echo yes;; esac")

    def test_ampersand_in_word(self, basic_policy):
        """& in word content triggers backgrounding denial."""
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "echo 'hello&world'")

    def test_fd_redirect(self, basic_policy):
        """File descriptor redirect 2>&1."""
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "echo hello 2>&1")

    def test_command_not_in_allowlist(self, basic_policy):
        with pytest.raises(ShellDenied, match="not allowlisted"):
            sanitize_shell_to_plan(basic_policy, "curl http://evil.com")

    def test_multiple_commands_with_unknown(self, basic_policy):
        """Second command in sequence not allowlisted."""
        with pytest.raises(ShellDenied, match="not allowlisted"):
            sanitize_shell_to_plan(basic_policy, "echo ok && rm -rf /")

    def test_redirect_with_dotdot_in_middle(self, basic_policy):
        with pytest.raises((FsViolation, ShellDenied)):
            sanitize_shell_to_plan(basic_policy, "echo x > a/../../../etc/passwd")

    def test_command_substitution_nested(self, basic_policy):
        with pytest.raises(ShellDenied, match="Forbidden token"):
            sanitize_shell_to_plan(basic_policy, "echo $(echo $(whoami))")

    def test_dollar_brace_expansion(self, basic_policy):
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "echo ${PATH}")


# ===================================================================
# D. Runtime escapes — executor integration
# ===================================================================


class TestAdversarialRuntimeEscape:
    """Code that passes AST validation but tries to escape at runtime."""

    @pytest.fixture
    def audit_sink(self):
        return CollectingSink()

    def test_path_concatenation_escape(self, empty_policy, default_actor, allowed_api, audit_sink):
        """Build traversal path via string concatenation — caught by ensure_under_root."""
        src = 'p = "../" + "../" + "etc/passwd"\nwrite_text(p, "pwned")'
        plan = sanitize_python_to_plan(empty_policy, src, allowed_api)
        result = execute_plan(
            empty_policy, plan, actor=default_actor, request_id="adv-d1", audit=audit_sink
        )
        assert result["ok"] is False
        assert "FsViolation" in result["error"]

    def test_path_multiply_escape(self, empty_policy, default_actor, allowed_api, audit_sink):
        """Build traversal path via string multiplication."""
        src = 'p = "../" * 10 + "etc/passwd"\nwrite_text(p, "pwned")'
        plan = sanitize_python_to_plan(empty_policy, src, allowed_api)
        result = execute_plan(
            empty_policy, plan, actor=default_actor, request_id="adv-d2", audit=audit_sink
        )
        assert result["ok"] is False
        assert "FsViolation" in result["error"]

    def test_path_loop_construction_escape(
        self, empty_policy, default_actor, allowed_api, audit_sink
    ):
        """Build traversal path via a for loop."""
        src = 'p = ""\nfor i in range(5):\n  p = p + "../"\nwrite_text(p + "etc/passwd", "pwned")'
        plan = sanitize_python_to_plan(empty_policy, src, allowed_api)
        result = execute_plan(
            empty_policy, plan, actor=default_actor, request_id="adv-d3", audit=audit_sink
        )
        assert result["ok"] is False
        assert "FsViolation" in result["error"]

    def test_path_dict_fragments_escape(self, empty_policy, default_actor, allowed_api, audit_sink):
        """Build traversal path from dict fragments."""
        src = (
            'd = {"up": "../", "target": "etc/passwd"}\n'
            'p = d["up"] + d["up"] + d["up"] + d["target"]\n'
            'write_text(p, "pwned")'
        )
        plan = sanitize_python_to_plan(empty_policy, src, allowed_api)
        result = execute_plan(
            empty_policy, plan, actor=default_actor, request_id="adv-d4", audit=audit_sink
        )
        assert result["ok"] is False
        assert "FsViolation" in result["error"]

    def test_path_list_subscript_escape(self, empty_policy, default_actor, allowed_api, audit_sink):
        """Build traversal path from list elements."""
        src = (
            'parts = ["../", "../", "../", "etc/passwd"]\n'
            "p = parts[0] + parts[1] + parts[2] + parts[3]\n"
            'write_text(p, "pwned")'
        )
        plan = sanitize_python_to_plan(empty_policy, src, allowed_api)
        result = execute_plan(
            empty_policy, plan, actor=default_actor, request_id="adv-d5", audit=audit_sink
        )
        assert result["ok"] is False
        assert "FsViolation" in result["error"]

    def test_absolute_path_write_escape(self, empty_policy, default_actor, allowed_api, audit_sink):
        src = 'write_text("/etc/passwd", "pwned")'
        plan = sanitize_python_to_plan(empty_policy, src, allowed_api)
        result = execute_plan(
            empty_policy, plan, actor=default_actor, request_id="adv-d6", audit=audit_sink
        )
        assert result["ok"] is False
        assert "FsViolation" in result["error"]

    def test_absolute_path_read_escape(self, empty_policy, default_actor, allowed_api, audit_sink):
        src = 'x = read_text("/etc/hostname")'
        plan = sanitize_python_to_plan(empty_policy, src, allowed_api)
        result = execute_plan(
            empty_policy, plan, actor=default_actor, request_id="adv-d7", audit=audit_sink
        )
        assert result["ok"] is False
        assert "FsViolation" in result["error"]

    def test_absolute_path_mkdir_escape(self, empty_policy, default_actor, allowed_api, audit_sink):
        src = 'mkdir("/tmp/evil_adversarial_test")'
        plan = sanitize_python_to_plan(empty_policy, src, allowed_api)
        result = execute_plan(
            empty_policy, plan, actor=default_actor, request_id="adv-d8", audit=audit_sink
        )
        assert result["ok"] is False
        assert "FsViolation" in result["error"]

    def test_http_get_non_https(self, empty_policy, default_actor, allowed_api, audit_sink):
        src = 'http_get("http://evil.com/")'
        plan = sanitize_python_to_plan(empty_policy, src, allowed_api)
        result = execute_plan(
            empty_policy, plan, actor=default_actor, request_id="adv-d9", audit=audit_sink
        )
        assert result["ok"] is False
        assert "ApiViolation" in result["error"]

    def test_memory_exhaustion_caught(self, empty_policy, default_actor, allowed_api, audit_sink):
        """Attempting huge allocation raises MemoryError, caught by exec()."""
        src = "x = [0] * (10 ** 15)"
        plan = sanitize_python_to_plan(empty_policy, src, allowed_api)
        result = execute_plan(
            empty_policy, plan, actor=default_actor, request_id="adv-d10", audit=audit_sink
        )
        assert result["ok"] is False
        assert "MemoryError" in result["error"]

    def test_list_join_method_denied_at_ast(self, empty_policy, allowed_api):
        """'/'.join(parts) is a method call — denied at AST level, never reaches runtime."""
        with pytest.raises(PythonDenied):
            sanitize_python_to_plan(
                empty_policy,
                'parts = ["..", "..", "etc", "passwd"]\np = "/".join(parts)\nwrite_text(p, "pwned")',
                allowed_api,
            )

    def test_legitimate_operations_still_work(
        self, empty_policy, default_actor, allowed_api, audit_sink
    ):
        """Positive control: legit operations succeed after all the denial tests."""
        src = (
            'mkdir("safe_dir")\n'
            'write_text("safe_dir/data.txt", "hello")\n'
            'content = read_text("safe_dir/data.txt")\n'
            "print(content)"
        )
        plan = sanitize_python_to_plan(empty_policy, src, allowed_api)
        result = execute_plan(
            empty_policy, plan, actor=default_actor, request_id="adv-d-legit", audit=audit_sink
        )
        assert result["ok"] is True


# ===================================================================
# E. Cross-layer attacks — shell → Python → fs
# ===================================================================


class TestAdversarialCrossLayer:
    """Attacks that span multiple security layers."""

    @pytest.fixture
    def audit_sink(self):
        return CollectingSink()

    # -- python3 -c with malicious Python (shell → AST validation) --

    def test_inline_python_import_denied(
        self, basic_policy, default_actor, allowed_api, audit_sink
    ):
        plan = sanitize_shell_to_plan(basic_policy, "python3 -c 'import os'")
        with pytest.raises(ValidationError, match="AST validation"):
            execute_plan(
                basic_policy,
                plan,
                actor=default_actor,
                request_id="adv-e1",
                audit=audit_sink,
                allowed_api=allowed_api,
            )

    def test_inline_python_eval_denied(self, basic_policy, default_actor, allowed_api, audit_sink):
        plan = sanitize_shell_to_plan(basic_policy, "python3 -c 'eval(\"1+1\")'")
        with pytest.raises(ValidationError, match="AST validation"):
            execute_plan(
                basic_policy,
                plan,
                actor=default_actor,
                request_id="adv-e2",
                audit=audit_sink,
                allowed_api=allowed_api,
            )

    def test_inline_python_exec_denied(self, basic_policy, default_actor, allowed_api, audit_sink):
        plan = sanitize_shell_to_plan(basic_policy, "python3 -c 'exec(\"import os\")'")
        with pytest.raises(ValidationError, match="AST validation"):
            execute_plan(
                basic_policy,
                plan,
                actor=default_actor,
                request_id="adv-e3",
                audit=audit_sink,
                allowed_api=allowed_api,
            )

    def test_inline_python_attribute_access_denied(
        self, basic_policy, default_actor, allowed_api, audit_sink
    ):
        plan = sanitize_shell_to_plan(basic_policy, "python3 -c 'x = ().__class__'")
        with pytest.raises(ValidationError, match="AST validation"):
            execute_plan(
                basic_policy,
                plan,
                actor=default_actor,
                request_id="adv-e4",
                audit=audit_sink,
                allowed_api=allowed_api,
            )

    def test_inline_python_dunder_denied(
        self, basic_policy, default_actor, allowed_api, audit_sink
    ):
        plan = sanitize_shell_to_plan(basic_policy, "python3 -c 'x = __builtins__'")
        with pytest.raises(ValidationError, match="AST validation"):
            execute_plan(
                basic_policy,
                plan,
                actor=default_actor,
                request_id="adv-e5",
                audit=audit_sink,
                allowed_api=allowed_api,
            )

    def test_inline_python_fstring_denied(
        self, basic_policy, default_actor, allowed_api, audit_sink
    ):
        plan = sanitize_shell_to_plan(basic_policy, "python3 -c 'x = f\"{1+1}\"'")
        with pytest.raises(ValidationError, match="AST validation"):
            execute_plan(
                basic_policy,
                plan,
                actor=default_actor,
                request_id="adv-e6",
                audit=audit_sink,
                allowed_api=allowed_api,
            )

    # -- python3 -c with runtime fs escape --

    def test_inline_python_path_escape_at_runtime(
        self, basic_policy, default_actor, allowed_api, audit_sink
    ):
        """write_text('../../evil.txt', ...) passes AST but fails at runtime."""
        plan = sanitize_shell_to_plan(
            basic_policy, 'python3 -c \'write_text("../../evil.txt", "pwned")\''
        )
        result = execute_plan(
            basic_policy,
            plan,
            actor=default_actor,
            request_id="adv-e7",
            audit=audit_sink,
            allowed_api=allowed_api,
        )
        assert result["return_codes"] == [1]

    # -- Shell-level cross-layer --

    def test_dollar_in_inline_python_code(self, basic_policy):
        """$ in python source triggers _python_source_literal denial."""
        with pytest.raises(ShellDenied):
            sanitize_shell_to_plan(basic_policy, "python3 -c 'x = $HOME'")

    def test_pipeline_with_inline_python_denied(self, basic_policy):
        with pytest.raises(ShellDenied, match="Piping.*inline Python"):
            sanitize_shell_to_plan(basic_policy, "echo data | python3 -c 'print(1)'")

    def test_inline_python_pipe_to_shell_denied(self, basic_policy):
        with pytest.raises(ShellDenied, match="Piping.*inline Python"):
            sanitize_shell_to_plan(basic_policy, "python3 -c 'print(1)' | cat")

    def test_redirect_traversal_at_shell_level(self, basic_policy):
        with pytest.raises((FsViolation, ShellDenied)):
            sanitize_shell_to_plan(basic_policy, "echo evil > ../../outside.txt")

    # -- Executor deny_chars catches what sanitizer allows --

    def test_semicolon_in_quoted_string_denied_at_executor(
        self, basic_policy, default_actor, audit_sink
    ):
        """Shell sanitizer allows quoted ';', executor deny_chars catches it."""
        plan = sanitize_shell_to_plan(basic_policy, "echo 'hello;world'")
        with pytest.raises(ValidationError, match="forbidden char"):
            execute_plan(
                basic_policy,
                plan,
                actor=default_actor,
                request_id="adv-e-deny",
                audit=audit_sink,
            )

    def test_pipe_in_quoted_string_denied_at_executor(
        self, basic_policy, default_actor, audit_sink
    ):
        plan = sanitize_shell_to_plan(basic_policy, "echo 'hello|world'")
        with pytest.raises(ValidationError, match="forbidden char"):
            execute_plan(
                basic_policy,
                plan,
                actor=default_actor,
                request_id="adv-e-pipe",
                audit=audit_sink,
            )

    # -- Extension type-checking --

    def test_registered_extension_type_mismatch(self, empty_policy, default_actor, audit_sink):
        """Register str-only function, call with int — type check catches it."""
        api = SafeAPI(workspace_root=empty_policy.workspace_root)

        def only_strings(s: str) -> str:
            return s.upper()

        api.register("upper_str", only_strings, allowed_arg_types=(str,))

        all_names = api.get_all_api_names()
        src = "upper_str(42)"
        plan = sanitize_python_to_plan(empty_policy, src, all_names)
        result = execute_plan(
            empty_policy,
            plan,
            actor=default_actor,
            request_id="adv-e-type",
            audit=audit_sink,
            safe_api=api,
        )
        assert result["ok"] is False
        assert "ApiViolation" in result["error"]
