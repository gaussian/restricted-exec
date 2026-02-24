from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

import bashlex

from .policy import EnginePolicy
from .fs_sandbox import ensure_under_root


class ShellDenied(Exception):
    pass


# ---- Plan model ----


@dataclass
class Redirect:
    stdout_path: Optional[str] = None
    stdout_append: bool = False


@dataclass
class Step:
    command_id: str
    args: Dict[str, Any]
    redirect: Redirect = field(default_factory=Redirect)


@dataclass
class PythonStep:
    """A step holding inline Python code (from python3 -c '...') for AST-validated execution."""

    python_src: str
    redirect: Redirect = field(default_factory=Redirect)


@dataclass
class Plan:
    policy_id: str
    policy_version: str
    steps: List[Union[Step, PythonStep]]
    explain: Dict[str, Any]


# ---- Early deny on raw input ----

FORBIDDEN_TOKENS = {"$(", "`", "<(", ">("}
GLOB_CHARS = {"*", "?"}
PYTHON_COMMANDS = frozenset({"python", "python3"})


def _deny_if_contains_forbidden_raw(src: str) -> None:
    for t in FORBIDDEN_TOKENS:
        if t in src:
            raise ShellDenied(f"Forbidden token in shell input: {t}")


# ---- Compilation ----


def sanitize_shell_to_plan(policy: EnginePolicy, shell_src: str) -> Plan:
    _deny_if_contains_forbidden_raw(shell_src)

    try:
        parts = bashlex.parse(shell_src)
    except Exception as e:
        raise ShellDenied(f"Shell parse failed: {e}") from e

    steps: List[Step] = []
    explain_notes: List[str] = []

    for node in parts:
        _compile_node(policy, node, steps, explain_notes)

    if len(steps) == 0:
        raise ShellDenied("No runnable steps found")
    if len(steps) > policy.max_pipeline_steps:
        raise ShellDenied(f"Too many steps (>{policy.max_pipeline_steps})")

    return Plan(
        policy_id=policy.policy_id,
        policy_version=policy.version,
        steps=steps,
        explain={
            "summary": "Compiled shell subset into allowlisted steps (no shell execution).",
            "notes": explain_notes,
            "input": shell_src,
        },
    )


def _compile_node(
    policy: EnginePolicy,
    node: Any,
    out_steps: List[Step],
    notes: List[str],
) -> None:
    kind = getattr(node, "kind", None)

    if kind == "list":
        # bashlex list: parts = [command, operator, command, operator, ...]
        # operator nodes have .kind="operator" and .op="&&"|";"|"||"
        for part in node.parts:
            part_kind = getattr(part, "kind", None)
            if part_kind == "operator":
                op = getattr(part, "op", None)
                if op not in ("&&", ";"):
                    raise ShellDenied(f"Unsupported list operator: {op!r}")
                notes.append(f"Operator {op} compiled as sequencing")
            else:
                _compile_node(policy, part, out_steps, notes)
        return

    if kind == "pipeline":
        # bashlex pipeline: parts = [command, pipe, command, pipe, ...]
        pipeline_start = len(out_steps)
        for part in node.parts:
            part_kind = getattr(part, "kind", None)
            if part_kind == "pipe":
                continue  # pipe nodes are just separators
            _compile_node(policy, part, out_steps, notes)
        # Deny Python steps in pipelines — piping to/from inline Python is not supported
        for s in out_steps[pipeline_start:]:
            if isinstance(s, PythonStep):
                raise ShellDenied("Piping to/from inline Python is not supported")
        notes.append("Pipeline compiled as stdout->stdin wiring during execution")
        return

    if kind == "command":
        step = _compile_command(policy, node)
        out_steps.append(step)
        return

    # Explicitly deny all other constructs
    raise ShellDenied(f"Unsupported shell construct: {kind}")


def _compile_command(policy: EnginePolicy, cmd_node: Any) -> Union[Step, PythonStep]:
    redirect = Redirect()
    word_nodes: List[Any] = []

    for part in cmd_node.parts:
        part_kind = getattr(part, "kind", None)

        if part_kind == "word":
            word_nodes.append(part)

        elif part_kind == "redirect":
            op = getattr(part, "type", None)
            if op not in (">", ">>"):
                raise ShellDenied(f"Unsupported redirect operator: {op}")
            output_node = getattr(part, "output", None)
            if output_node is None:
                raise ShellDenied("Redirect missing output path")
            path = _word_to_literal(output_node)
            ensure_under_root(policy.workspace_root, path)
            redirect.stdout_path = path
            redirect.stdout_append = op == ">>"

        elif part_kind == "assignment":
            raise ShellDenied("Variable assignments are not supported")

        else:
            raise ShellDenied(f"Unsupported command part: {part_kind}")

    if not word_nodes:
        raise ShellDenied("Empty command")

    # Extract first word to identify the command
    prog = _word_to_literal(word_nodes[0])

    # Intercept python/python3 before the allowlist check
    if prog in PYTHON_COMMANDS:
        return _compile_python_command(prog, word_nodes[1:], redirect)

    # Extract remaining words for shell command processing
    words = [prog] + [_word_to_literal(n) for n in word_nodes[1:]]

    # Deny backgrounding in word content
    for w in words:
        if "&" in w:
            raise ShellDenied("Backgrounding (&) is not supported")

    # Map first word to allowlisted command_id
    if prog not in policy.commands:
        raise ShellDenied(f"Command not allowlisted: {prog}")

    spec = policy.commands[prog]
    provided_args: Dict[str, Any] = {}

    rest = words[1:]
    if rest:
        i = 0
        while i < len(rest):
            tok = rest[i]
            if tok.startswith("--"):
                name = tok[2:]
                if name not in spec.args:
                    raise ShellDenied(f"Unknown flag for {prog}: {tok}")
                if i + 1 >= len(rest):
                    raise ShellDenied(f"Missing value for flag {tok}")
                provided_args[name] = rest[i + 1]
                i += 2
            else:
                # Allow bare value only if exactly one arg exists named "value"
                if "value" in spec.args and len(spec.args) == 1:
                    provided_args["value"] = tok
                    i += 1
                else:
                    raise ShellDenied(f"Bare arg not allowed for {prog}: {tok}")

    return Step(command_id=prog, args=provided_args, redirect=redirect)


def _compile_python_command(
    prog: str,
    arg_nodes: List[Any],
    redirect: Redirect,
) -> PythonStep:
    """
    Handle `python3 -c "code"` by extracting the code for AST validation.
    Denies all other python invocation forms (scripts, modules, interactive).
    """
    if not arg_nodes:
        raise ShellDenied(f"Bare '{prog}' (interactive mode) is not allowed")

    flag = _word_to_literal(arg_nodes[0])
    if flag != "-c":
        raise ShellDenied(f"Only '{prog} -c <code>' is allowed; got: {prog} {flag}")

    if len(arg_nodes) != 2:
        raise ShellDenied(
            f"'{prog} -c' requires exactly one code argument, got {len(arg_nodes) - 1}"
        )

    python_src = _python_source_literal(arg_nodes[1])
    return PythonStep(python_src=python_src, redirect=redirect)


def _word_to_literal(word_node: Any) -> str:
    """Extract a literal string from a bashlex word node, denying any expansions."""
    # If word has non-empty parts, it contains expansions (parameter, command subst, etc.)
    parts = getattr(word_node, "parts", None)
    if parts:
        raise ShellDenied("Expansions are not supported in words")

    w = getattr(word_node, "word", None)
    if w is None:
        raise ShellDenied("Unreadable word")

    # Final safety check: deny expansion markers that bashlex might not have parsed
    if "$" in w or "`" in w:
        raise ShellDenied("Expansions are not supported")

    # Deny glob characters — harmless with shell=False but unexpected in shell commands.
    # Python source extraction uses _python_source_literal() which skips this check.
    for ch in GLOB_CHARS:
        if ch in w:
            raise ShellDenied(f"Glob character not allowed in shell words: {ch}")

    return w


def _python_source_literal(word_node: Any) -> str:
    """Extract a literal string for Python source code from a bashlex word node.

    Like _word_to_literal() but allows glob characters (* and ?) since they are
    valid Python operators (multiplication, unpacking) and not shell-relevant here.
    Still denies shell expansion markers ($ and backtick).
    """
    parts = getattr(word_node, "parts", None)
    if parts:
        raise ShellDenied("Expansions are not supported in Python source")

    w = getattr(word_node, "word", None)
    if w is None:
        raise ShellDenied("Unreadable word")

    if "$" in w or "`" in w:
        raise ShellDenied("Shell expansions are not supported in Python source")

    return w
