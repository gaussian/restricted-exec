from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Dict


class PythonDenied(Exception):
    pass


@dataclass
class PythonPlan:
    policy_id: str
    policy_version: str
    python_src: str
    explain: Dict[str, Any]


DENY_NODES = (
    ast.Import,
    ast.ImportFrom,
    ast.With,
    ast.AsyncWith,
    ast.Try,
    ast.TryStar,
    ast.Lambda,
    ast.ClassDef,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Global,
    ast.Nonlocal,
    ast.Delete,
    ast.Raise,
    ast.Assert,
    ast.Yield,
    ast.YieldFrom,
    ast.Await,
    ast.AsyncFor,
    ast.Starred,
    ast.MatchMapping,
    ast.MatchClass,
)

DENY_CALL_NAMES = frozenset({
    "eval", "exec", "compile", "open", "__import__",
    "getattr", "setattr", "delattr", "hasattr",
    "globals", "locals", "vars", "dir",
    "type", "super", "object",
    "breakpoint", "exit", "quit",
    "memoryview", "bytearray", "bytes",
    "classmethod", "staticmethod", "property",
    "input",
})


class _Validator(ast.NodeVisitor):
    def __init__(self, allowed_call_names: set[str]):
        self.allowed_call_names = allowed_call_names

    def generic_visit(self, node: ast.AST) -> None:
        if isinstance(node, DENY_NODES):
            raise PythonDenied(f"Forbidden syntax: {type(node).__name__}")
        super().generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # Deny all attribute access — this blocks __class__, __subclasses__, etc.
        raise PythonDenied("Attribute access is not allowed")

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name):
            fn = node.func.id
            if fn in DENY_CALL_NAMES:
                raise PythonDenied(f"Forbidden call: {fn}")
            if fn not in self.allowed_call_names:
                raise PythonDenied(f"Call not allowlisted: {fn}")
        else:
            raise PythonDenied("Only direct function calls are allowed (no method calls)")
        # Validate args recursively
        for arg in node.args:
            self.visit(arg)
        for kw in node.keywords:
            self.visit(kw.value)

    def visit_Name(self, node: ast.Name) -> None:
        # Deny access to dunder names
        if node.id.startswith("__") and node.id.endswith("__"):
            raise PythonDenied(f"Dunder name access not allowed: {node.id}")

    def visit_Constant(self, node: ast.Constant) -> None:
        pass

    def visit_Subscript(self, node: ast.Subscript) -> None:
        # Allow dict/list indexing and slicing — needed for practical use.
        # Safe because attribute access is denied (blocks __class__ chains).
        self.visit(node.value)
        self.visit(node.slice)

    def visit_Slice(self, node: ast.Slice) -> None:
        if node.lower:
            self.visit(node.lower)
        if node.upper:
            self.visit(node.upper)
        if node.step:
            self.visit(node.step)

    def visit_FormattedValue(self, node: ast.FormattedValue) -> None:
        # Deny f-strings — they can call format methods
        raise PythonDenied("f-strings are not allowed")

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        raise PythonDenied("f-strings are not allowed")


def sanitize_python_to_plan(
    policy: "EnginePolicy",  # noqa: F821
    python_src: str,
    allowed_api: set[str],
) -> PythonPlan:
    try:
        tree = ast.parse(python_src, mode="exec")
    except SyntaxError as e:
        raise PythonDenied(f"Python parse failed: {e}") from e

    # Merge allowed_api with safe builtins that are allowed as calls
    allowed_calls = allowed_api | {"len", "range", "min", "max", "sum", "print", "str", "int", "float", "bool", "list", "dict"}

    _Validator(allowed_call_names=allowed_calls).visit(tree)

    return PythonPlan(
        policy_id=policy.policy_id,
        policy_version=policy.version,
        python_src=python_src,
        explain={
            "summary": "Validated restricted Python AST (deny-by-default) to run with SafeAPI only.",
            "allowed_calls": sorted(list(allowed_api)),
        },
    )
