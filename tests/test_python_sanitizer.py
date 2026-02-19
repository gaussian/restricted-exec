from __future__ import annotations

import pytest

from restricted_exec.python_sanitizer import PythonDenied, PythonPlan, sanitize_python_to_plan


@pytest.fixture
def api():
    return {"mkdir", "write_text", "write_json", "read_text", "http_get"}


class TestPythonAllowed:
    """Tests for Python constructs that SHOULD be allowed."""

    def test_simple_call(self, empty_policy, api):
        plan = sanitize_python_to_plan(empty_policy, 'write_text("f.txt", "hi")', api)
        assert isinstance(plan, PythonPlan)

    def test_variable_assignment(self, empty_policy, api):
        plan = sanitize_python_to_plan(empty_policy, "x = 42", api)
        assert plan.python_src == "x = 42"

    def test_string_literal(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, 'x = "hello"', api)

    def test_int_literal(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = 42", api)

    def test_float_literal(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = 3.14", api)

    def test_bool_literal(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = True", api)

    def test_none_literal(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = None", api)

    def test_list_construction(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, 'x = [1, 2, "three"]', api)

    def test_dict_construction(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, 'x = {"a": 1, "b": 2}', api)

    def test_dict_subscript(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, 'd = {"a": 1}\nx = d["a"]', api)

    def test_list_subscript(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = [1, 2, 3]\ny = x[0]", api)

    def test_slice(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = [1, 2, 3]\ny = x[:2]", api)

    def test_slice_with_step(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = [1,2,3,4]\ny = x[::2]", api)

    def test_if_statement(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = 1\nif x:\n  y = 2", api)

    def test_if_else(self, empty_policy, api):
        sanitize_python_to_plan(
            empty_policy, "x = 1\nif x:\n  y = 2\nelse:\n  y = 3", api
        )

    def test_for_loop(self, empty_policy, api):
        sanitize_python_to_plan(
            empty_policy, "for i in range(3):\n  print(i)", api
        )

    def test_while_loop(self, empty_policy, api):
        sanitize_python_to_plan(
            empty_policy, "x = 3\nwhile x:\n  x = x - 1", api
        )

    def test_builtin_len(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, 'x = len("hello")', api)

    def test_builtin_range(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = range(10)", api)

    def test_builtin_min_max_sum(self, empty_policy, api):
        sanitize_python_to_plan(
            empty_policy, "a = min(1,2)\nb = max(1,2)\nc = sum([1,2])", api
        )

    def test_builtin_print(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, 'print("hello")', api)

    def test_builtin_type_conversions(self, empty_policy, api):
        sanitize_python_to_plan(
            empty_policy, 'x = str(42)\ny = int("7")\nz = float("3.14")', api
        )

    def test_nested_calls(self, empty_policy, api):
        sanitize_python_to_plan(
            empty_policy, 'write_text("f.txt", str(len("hello")))', api
        )

    def test_arithmetic(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = 1 + 2 * 3 - 4 / 2", api)

    def test_comparison(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = 1 < 2\ny = 3 >= 3", api)

    def test_boolean_ops(self, empty_policy, api):
        sanitize_python_to_plan(empty_policy, "x = True and False or True", api)

    def test_multiline_program(self, empty_policy, api):
        src = """
mkdir("out")
write_text("out/data.txt", "hello")
content = read_text("out/data.txt")
print(content)
"""
        plan = sanitize_python_to_plan(empty_policy, src, api)
        assert "mkdir" in plan.explain["allowed_calls"]

    def test_plan_metadata(self, empty_policy, api):
        plan = sanitize_python_to_plan(empty_policy, "x = 1", api)
        assert plan.policy_id == "test-py"
        assert plan.policy_version == "0.1"


class TestPythonDenied:
    """Tests for Python constructs that MUST be denied."""

    def test_import(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Import"):
            sanitize_python_to_plan(empty_policy, "import os", api)

    def test_from_import(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="ImportFrom"):
            sanitize_python_to_plan(empty_policy, "from os import system", api)

    def test_exec(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: exec"):
            sanitize_python_to_plan(empty_policy, 'exec("print(1)")', api)

    def test_eval(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: eval"):
            sanitize_python_to_plan(empty_policy, 'eval("1+1")', api)

    def test_compile(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: compile"):
            sanitize_python_to_plan(empty_policy, 'compile("x=1", "", "exec")', api)

    def test_open(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: open"):
            sanitize_python_to_plan(empty_policy, 'open("/etc/passwd")', api)

    def test_dunder_import(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: __import__"):
            sanitize_python_to_plan(empty_policy, '__import__("os")', api)

    def test_getattr(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: getattr"):
            sanitize_python_to_plan(empty_policy, 'getattr([], "__class__")', api)

    def test_setattr(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: setattr"):
            sanitize_python_to_plan(empty_policy, 'setattr(x, "a", 1)', api)

    def test_delattr(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: delattr"):
            sanitize_python_to_plan(empty_policy, 'delattr(x, "a")', api)

    def test_globals(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: globals"):
            sanitize_python_to_plan(empty_policy, "globals()", api)

    def test_locals(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: locals"):
            sanitize_python_to_plan(empty_policy, "locals()", api)

    def test_vars(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: vars"):
            sanitize_python_to_plan(empty_policy, "vars()", api)

    def test_dir(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: dir"):
            sanitize_python_to_plan(empty_policy, "dir()", api)

    def test_type(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: type"):
            sanitize_python_to_plan(empty_policy, "type(42)", api)

    def test_breakpoint(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: breakpoint"):
            sanitize_python_to_plan(empty_policy, "breakpoint()", api)

    def test_input(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Forbidden call: input"):
            sanitize_python_to_plan(empty_policy, "input()", api)

    def test_attribute_access(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Attribute access"):
            sanitize_python_to_plan(empty_policy, "x = ().__class__", api)

    def test_attribute_chain(self, empty_policy, api):
        with pytest.raises(PythonDenied):
            sanitize_python_to_plan(
                empty_policy, "x = ().__class__.__bases__[0].__subclasses__()", api
            )

    def test_method_call(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="method calls"):
            sanitize_python_to_plan(empty_policy, '"hello".upper()', api)

    def test_dunder_name_access(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Dunder name"):
            sanitize_python_to_plan(empty_policy, "x = __builtins__", api)

    def test_dunder_name_in_expr(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Dunder name"):
            sanitize_python_to_plan(empty_policy, "x = __name__", api)

    def test_fstring(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="f-string"):
            sanitize_python_to_plan(empty_policy, 'x = f"{1+1}"', api)

    def test_fstring_with_call(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="f-string"):
            sanitize_python_to_plan(empty_policy, 'x = f"{len([1,2])}"', api)

    def test_function_def(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="FunctionDef"):
            sanitize_python_to_plan(empty_policy, "def foo(): pass", api)

    def test_async_function_def(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="AsyncFunctionDef"):
            sanitize_python_to_plan(empty_policy, "async def foo(): pass", api)

    def test_class_def(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="ClassDef"):
            sanitize_python_to_plan(empty_policy, "class Foo: pass", api)

    def test_lambda(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Lambda"):
            sanitize_python_to_plan(empty_policy, "x = lambda: 1", api)

    def test_with_statement(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="With"):
            sanitize_python_to_plan(
                empty_policy, 'with open("f") as f:\n  pass', api
            )

    def test_try_except(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Try"):
            sanitize_python_to_plan(
                empty_policy, "try:\n  x=1\nexcept:\n  pass", api
            )

    def test_raise(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Raise"):
            sanitize_python_to_plan(
                empty_policy, 'raise Exception("oops")', api
            )

    def test_assert(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Assert"):
            sanitize_python_to_plan(empty_policy, "assert True", api)

    def test_delete(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Delete"):
            sanitize_python_to_plan(empty_policy, "x = 1\ndel x", api)

    def test_global(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Global"):
            sanitize_python_to_plan(empty_policy, "global x", api)

    def test_nonlocal_denied(self, empty_policy, api):
        # nonlocal only valid inside function, so parse will fail or Nonlocal denied
        with pytest.raises((PythonDenied, SyntaxError)):
            sanitize_python_to_plan(empty_policy, "nonlocal x", api)

    def test_starred(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="Starred"):
            sanitize_python_to_plan(empty_policy, "a, *b = [1,2,3]", api)

    def test_yield(self, empty_policy, api):
        # yield only valid inside function — parse error or denied
        with pytest.raises((PythonDenied, SyntaxError)):
            sanitize_python_to_plan(empty_policy, "yield 1", api)

    def test_not_allowlisted_call(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="not allowlisted"):
            sanitize_python_to_plan(empty_policy, "unknown_func()", api)

    def test_syntax_error(self, empty_policy, api):
        with pytest.raises(PythonDenied, match="parse failed"):
            sanitize_python_to_plan(empty_policy, "def {", api)


class TestPythonEscapeAttempts:
    """Targeted tests for known Python sandbox escape techniques."""

    def test_class_dunder_escape(self, empty_policy, api):
        with pytest.raises(PythonDenied):
            sanitize_python_to_plan(
                empty_policy,
                '().__class__.__bases__[0].__subclasses__()',
                api,
            )

    def test_string_format_escape(self, empty_policy, api):
        with pytest.raises(PythonDenied):
            sanitize_python_to_plan(
                empty_policy,
                '"{0.__class__}".format(42)',
                api,
            )

    def test_bytes_decode_escape(self, empty_policy, api):
        with pytest.raises(PythonDenied):
            sanitize_python_to_plan(
                empty_policy,
                'b"os".decode()',
                api,
            )

    def test_list_class_escape(self, empty_policy, api):
        with pytest.raises(PythonDenied):
            sanitize_python_to_plan(
                empty_policy,
                "[].__class__.__bases__",
                api,
            )
