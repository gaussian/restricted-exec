"""
Tests for resource exhaustion and denial-of-service vectors:
Python exec() memory/CPU abuse, ReDoS via policy regex, and
bool-as-int type confusion in argument validation.

Maps to SECURITY.md: A-27 (ReDoS), A-29 (memory exhaustion),
A-32 (bool/int confusion), F-04, F-07, F-08.
"""

from __future__ import annotations

import time

import pytest

from restricted_exec.policy import ArgSpec, EnginePolicy
from restricted_exec.executor import ValidationError, _validate_arg, execute_plan
from restricted_exec.python_sanitizer import sanitize_python_to_plan
from restricted_exec.safe_api import SafeAPI


def _run_python(policy, src, allowed_api=None, safe_api=None):
    actor = {"type": "test", "id": "res-test", "tenant": "test"}
    api_set = allowed_api or {"mkdir", "write_text", "write_json", "read_text", "http_get"}
    plan = sanitize_python_to_plan(policy, src, api_set)
    return execute_plan(
        policy, plan,
        actor=actor,
        request_id="res-test-1",
        safe_api=safe_api,
    )


# ---------------------------------------------------------------------------
# Python exec() resource exhaustion (A-29, F-04)
# ---------------------------------------------------------------------------


class TestResourceExhaustion:
    """Document that no resource limits exist on Python exec().

    These tests use small enough values to complete quickly, but
    demonstrate that no limits are enforced. They should start
    failing (or be updated) when resource limits are added.
    """

    def test_large_range_sum_completes(self, workspace):
        """sum(range(N)) for moderately large N — no timeout kills it."""
        policy = EnginePolicy(
            policy_id="test-res", version="0.1",
            workspace_root=workspace, commands={},
        )
        result = _run_python(policy, "x = sum(range(10**6))\nprint(x)")
        assert result["ok"] is True

    def test_string_multiplication_no_limit(self, workspace):
        """'a' * N for moderately large N — no memory limit."""
        policy = EnginePolicy(
            policy_id="test-res", version="0.1",
            workspace_root=workspace, commands={},
        )
        result = _run_python(policy, 'x = "a" * (10**7)\nprint(len(x))')
        assert result["ok"] is True

    def test_list_construction_no_limit(self, workspace):
        """list(range(N)) for moderately large N — no memory limit."""
        policy = EnginePolicy(
            policy_id="test-res", version="0.1",
            workspace_root=workspace, commands={},
        )
        result = _run_python(policy, "x = list(range(10**6))\nprint(len(x))")
        assert result["ok"] is True

    def test_nested_list_comprehension_no_limit(self, workspace):
        """Nested comprehension — CPU-intensive, no timeout."""
        policy = EnginePolicy(
            policy_id="test-res", version="0.1",
            workspace_root=workspace, commands={},
        )
        result = _run_python(
            policy,
            "x = [i * j for i in range(1000) for j in range(1000)]\nprint(len(x))",
        )
        assert result["ok"] is True


# ---------------------------------------------------------------------------
# Policy regex ReDoS (A-27, F-07)
# ---------------------------------------------------------------------------


class TestReDoS:
    """Test that regex validation in _validate_arg doesn't hang."""

    def test_catastrophic_backtracking_bounded(self):
        """Regex with catastrophic backtracking pattern completes in time."""
        spec = ArgSpec(kind="string", regex=r"(a+)+b", deny_chars="")
        evil_input = "a" * 20 + "c"

        start = time.time()
        try:
            _validate_arg("field", spec, evil_input)
        except ValidationError:
            pass
        elapsed = time.time() - start

        assert elapsed < 5, f"Regex took {elapsed:.1f}s — potential ReDoS"

    def test_regex_500_char_limit_only_in_loader(self):
        """The executor doesn't enforce regex length — only the policy loader does."""
        long_regex = "a" * 501
        spec = ArgSpec(kind="string", regex=long_regex, deny_chars="")
        result = _validate_arg("field", spec, "a" * 501)
        assert result == "a" * 501

    def test_nested_quantifier_moderate_input(self):
        """Nested quantifiers with moderate input — should complete quickly."""
        spec = ArgSpec(kind="string", regex=r"(a*)*b", deny_chars="")
        try:
            _validate_arg("field", spec, "a" * 15 + "c")
        except ValidationError:
            pass


# ---------------------------------------------------------------------------
# bool-as-int type confusion (A-32, F-08)
# ---------------------------------------------------------------------------


class TestBoolIntConfusion:
    """Document that bool passes isinstance(x, int) checks."""

    def test_true_accepted_as_int_arg(self):
        """True passes kind='int' validation."""
        spec = ArgSpec(kind="int", min_value=0, max_value=10)
        result = _validate_arg("count", spec, True)
        assert result is True

    def test_false_accepted_as_int_arg(self):
        """False passes kind='int' validation (False == 0)."""
        spec = ArgSpec(kind="int", min_value=0, max_value=10)
        result = _validate_arg("count", spec, False)
        assert result is False

    def test_false_passes_min_value_zero(self):
        """False >= 0 is True, so min_value=0 doesn't reject it."""
        spec = ArgSpec(kind="int", min_value=0)
        result = _validate_arg("count", spec, False)
        assert result is False

    def test_true_in_max_value_boundary(self):
        """True (=1) passes max_value=1."""
        spec = ArgSpec(kind="int", max_value=1)
        result = _validate_arg("count", spec, True)
        assert result is True

    def test_extension_accepts_bool_as_int(self):
        """Registered extension with int type allows True."""
        api = SafeAPI(workspace_root="/tmp/test")
        api.register(
            "add_one",
            lambda x: x + 1,
            allowed_arg_types=(int, float),
            description="test",
        )
        globs = api.build_globals()
        result = globs["add_one"](True)
        assert result == 2
