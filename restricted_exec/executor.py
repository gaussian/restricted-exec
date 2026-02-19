from __future__ import annotations

import os
import subprocess
from dataclasses import asdict
from typing import Any, Dict, Optional, Union

from .audit import AuditEvent, AuditSink, now
from .fs_sandbox import ensure_under_root, mkdir_p
from .output_sanitize import sanitize_output
from .policy import EnginePolicy, PolicyError, ArgSpec
from .shell_sanitizer import Plan as ShellPlan, Step as ShellStep
from .python_sanitizer import PythonPlan
from .safe_api import SafeAPI


class ValidationError(Exception):
    pass


SAFE_STRING_DEFAULT_DENY = r";&|`$<>\n\r\0"


def _validate_arg(name: str, spec: ArgSpec, value: Any) -> Any:
    if value is None:
        if spec.required:
            raise ValidationError(f"Missing required arg: {name}")
        return None

    if spec.kind == "string":
        if not isinstance(value, str):
            raise ValidationError(f"{name} must be string")
        if spec.min_len is not None and len(value) < spec.min_len:
            raise ValidationError(f"{name} too short")
        if spec.max_len is not None and len(value) > spec.max_len:
            raise ValidationError(f"{name} too long")
        deny = spec.deny_chars if spec.deny_chars is not None else SAFE_STRING_DEFAULT_DENY
        for ch in deny:
            if ch in value:
                raise ValidationError(f"{name} contains forbidden char {repr(ch)}")
        if spec.regex is not None:
            import re

            if not re.fullmatch(spec.regex, value):
                raise ValidationError(f"{name} does not match regex")
        return value

    if spec.kind == "enum":
        if not isinstance(value, str):
            raise ValidationError(f"{name} must be string")
        if not spec.values or value not in spec.values:
            raise ValidationError(f"{name} not allowed")
        return value

    if spec.kind == "int":
        if not isinstance(value, int):
            raise ValidationError(f"{name} must be int")
        if spec.min_value is not None and value < spec.min_value:
            raise ValidationError(f"{name} below min")
        if spec.max_value is not None and value > spec.max_value:
            raise ValidationError(f"{name} above max")
        return value

    raise PolicyError(f"Unknown arg kind: {spec.kind}")


def _build_argv(policy: EnginePolicy, step: ShellStep) -> tuple[list[str], int]:
    if step.command_id not in policy.commands:
        raise ValidationError(f"Command not allowlisted: {step.command_id}")

    spec = policy.commands[step.command_id]
    if not spec.exec_path.startswith("/"):
        raise ValidationError("exec_path must be absolute")

    validated = {}
    for arg_name, arg_spec in spec.args.items():
        validated[arg_name] = _validate_arg(arg_name, arg_spec, step.args.get(arg_name))

    argv = [spec.exec_path] + list(spec.base_argv)
    for arg_name, frag_tpl in spec.arg_map.items():
        v = validated.get(arg_name)
        if v is None:
            continue
        for frag in frag_tpl:
            # Only allow the expected placeholder in the format string
            expected_key = arg_name
            try:
                argv.append(frag.format(**{expected_key: v}))
            except (KeyError, IndexError, ValueError) as e:
                raise ValidationError(f"Invalid format in arg_map for {arg_name}: {e}")

    return argv, spec.timeout_s


def execute_plan(
    policy: EnginePolicy,
    plan: Union[ShellPlan, PythonPlan],
    *,
    actor: Dict[str, Any],
    request_id: str,
    audit: Optional[AuditSink] = None,
    cwd: Optional[str] = None,
    http_allow_hosts: Optional[set[str]] = None,
    safe_api: Optional[SafeAPI] = None,
) -> Dict[str, Any]:
    audit = audit or AuditSink()
    cwd = cwd or policy.workspace_root

    mkdir_p(policy.workspace_root)
    mkdir_p(cwd)

    if isinstance(plan, PythonPlan):
        return _execute_python_plan(
            policy, plan, actor, request_id, audit, cwd, http_allow_hosts, safe_api
        )

    if isinstance(plan, ShellPlan):
        return _execute_shell_plan(policy, plan, actor, request_id, audit, cwd)

    raise TypeError("Unknown plan type")


def _execute_shell_plan(
    policy: EnginePolicy,
    plan: ShellPlan,
    actor: Dict[str, Any],
    request_id: str,
    audit: AuditSink,
    cwd: str,
) -> Dict[str, Any]:
    audit.emit(
        AuditEvent(
            ts=now(),
            event="plan_ready",
            request_id=request_id,
            actor=actor,
            details={"type": "shell", "plan": asdict(plan)},
        )
    )

    prev_proc: Optional[subprocess.Popen] = None
    procs: list[subprocess.Popen] = []
    redirect_files: list = []
    last_stdout = b""
    last_stderr = b""

    for idx, step in enumerate(plan.steps):
        argv, timeout_s = _build_argv(policy, step)

        # Redirection (stdout only)
        stdout_target = subprocess.PIPE
        if step.redirect.stdout_path:
            out_path = ensure_under_root(policy.workspace_root, step.redirect.stdout_path)
            mkdir_p(os.path.dirname(out_path))
            mode = "ab" if step.redirect.stdout_append else "wb"
            f = open(out_path, mode)
            redirect_files.append(f)
            stdout_target = f

        stdin_source = prev_proc.stdout if prev_proc is not None else subprocess.DEVNULL

        audit.emit(
            AuditEvent(
                ts=now(),
                event="step_start",
                request_id=request_id,
                actor=actor,
                details={
                    "index": idx,
                    "command_id": step.command_id,
                    "argv": argv,
                    "cwd": cwd,
                    "timeout_s": timeout_s,
                },
            )
        )

        p = subprocess.Popen(
            argv,
            cwd=cwd,
            stdin=stdin_source,
            stdout=stdout_target,
            stderr=subprocess.PIPE,
            shell=False,
        )
        procs.append(p)

        # Close parent's copy of previous stdout to avoid deadlocks
        if prev_proc is not None and prev_proc.stdout is not None:
            prev_proc.stdout.close()

        prev_proc = p

    # Wait for last process
    timed_out = False
    try:
        last_timeout = policy.commands[plan.steps[-1].command_id].timeout_s
        out_b, err_b = procs[-1].communicate(timeout=last_timeout)
        last_stdout, last_stderr = out_b or b"", err_b or b""
    except subprocess.TimeoutExpired:
        timed_out = True
        for p in procs:
            try:
                p.kill()
            except Exception:
                pass

    # Wait on ALL processes to prevent zombies
    for p in procs:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()

    # Close redirect file handles
    for f in redirect_files:
        try:
            f.close()
        except Exception:
            pass

    rcs = [p.returncode for p in procs]
    sanitized_out = sanitize_output(last_stdout)
    sanitized_err = sanitize_output(last_stderr)

    audit.emit(
        AuditEvent(
            ts=now(),
            event="plan_done",
            request_id=request_id,
            actor=actor,
            details={
                "type": "shell",
                "timed_out": timed_out,
                "return_codes": rcs,
                "stdout": {
                    "truncated": sanitized_out["truncated"],
                    "redactions": sanitized_out["redactions"],
                },
                "stderr": {
                    "truncated": sanitized_err["truncated"],
                    "redactions": sanitized_err["redactions"],
                },
            },
        )
    )

    return {
        "request_id": request_id,
        "type": "shell",
        "timed_out": timed_out,
        "return_codes": rcs,
        "stdout": sanitized_out,
        "stderr": sanitized_err,
    }


def _execute_python_plan(
    policy: EnginePolicy,
    plan: PythonPlan,
    actor: Dict[str, Any],
    request_id: str,
    audit: AuditSink,
    cwd: str,
    http_allow_hosts: Optional[set[str]],
    safe_api: Optional[SafeAPI] = None,
) -> Dict[str, Any]:
    """
    Execute restricted Python via exec() with SafeAPI-only globals.

    SECURITY NOTE: exec() with restricted builtins is NOT a security boundary on its own.
    The AST validator (python_sanitizer) is the primary gate — it denies attribute access,
    imports, and dangerous calls. This exec() call is the second layer. For production,
    the real boundary is OS-level isolation (Fargate/microVM/gVisor).
    """
    audit.emit(
        AuditEvent(
            ts=now(),
            event="plan_ready",
            request_id=request_id,
            actor=actor,
            details={"type": "python", "explain": plan.explain},
        )
    )

    api = safe_api or SafeAPI(
        workspace_root=policy.workspace_root, http_allow_hosts=http_allow_hosts
    )
    safe_globals = api.build_globals()
    safe_locals: Dict[str, Any] = {}

    try:
        exec(compile(plan.python_src, "<restricted-python>", "exec"), safe_globals, safe_locals)
        ok = True
        err = ""
    except Exception as e:
        ok = False
        err = f"{type(e).__name__}: {e}"

    audit.emit(
        AuditEvent(
            ts=now(),
            event="plan_done",
            request_id=request_id,
            actor=actor,
            details={"type": "python", "ok": ok, "error": err},
        )
    )

    return {"request_id": request_id, "type": "python", "ok": ok, "error": err}
