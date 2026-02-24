"""
Secure policy loading and extension mechanism.

Loads CommandSpec definitions from TOML files with strict validation:
- exec_path must be absolute and exist on disk
- exec_path must be in an allowed directory prefix
- arg_map format strings are validated for injection
- regex patterns are validated and length-bounded
- policies can only ADD commands, not override existing ones
- optional HMAC signature verification
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import string
import tomllib
from typing import Any, Dict, List, Optional, Sequence

from .policy import ArgSpec, CommandSpec, EnginePolicy, PolicyError


class PolicyLoadError(PolicyError):
    pass


# Directories that are allowed to contain executables.
# Extend this list based on your deployment environment.
DEFAULT_ALLOWED_EXEC_DIRS: List[str] = [
    "/bin",
    "/usr/bin",
    "/usr/local/bin",
    "/sbin",
    "/usr/sbin",
]

# Maximum allowed values for safety
MAX_TIMEOUT_S = 300
MAX_ARG_REGEX_LEN = 500
MAX_ARG_MAX_LEN = 10_000
MAX_COMMAND_ID_LEN = 64
MAX_FORMAT_STRING_LEN = 256


def _validate_exec_path(
    exec_path: str,
    allowed_dirs: Sequence[str],
) -> None:
    """Validate that exec_path is absolute, exists, is executable, and is in an allowed dir."""
    if not exec_path.startswith("/"):
        raise PolicyLoadError(f"exec_path must be absolute: {exec_path}")

    real_path = os.path.realpath(exec_path)

    if not os.path.isfile(real_path):
        raise PolicyLoadError(f"exec_path does not exist: {exec_path} -> {real_path}")

    if not os.access(real_path, os.X_OK):
        raise PolicyLoadError(f"exec_path is not executable: {real_path}")

    # Check that the resolved path is in an allowed directory
    in_allowed = False
    for d in allowed_dirs:
        d_real = os.path.realpath(d)
        if real_path == d_real or real_path.startswith(d_real + os.sep):
            in_allowed = True
            break
    if not in_allowed:
        raise PolicyLoadError(
            f"exec_path not in allowed directories: {real_path} (allowed: {allowed_dirs})"
        )


def _validate_format_string(arg_name: str, fmt: str) -> None:
    """Validate that a format string only references the expected arg_name."""
    if len(fmt) > MAX_FORMAT_STRING_LEN:
        raise PolicyLoadError(f"Format string too long for {arg_name}: {len(fmt)}")

    # Parse format fields
    formatter = string.Formatter()
    try:
        parsed = list(formatter.parse(fmt))
    except (ValueError, KeyError) as e:
        raise PolicyLoadError(f"Invalid format string for {arg_name}: {e}")

    for _, field_name, _, _ in parsed:
        if field_name is None:
            continue  # literal text
        # Only the arg_name itself is allowed
        if field_name != arg_name:
            raise PolicyLoadError(
                f"Format string for {arg_name} references unexpected field: {field_name}"
            )


def _validate_regex(arg_name: str, pattern: str) -> None:
    """Validate that a regex pattern is valid and not excessively long."""
    if len(pattern) > MAX_ARG_REGEX_LEN:
        raise PolicyLoadError(
            f"Regex too long for {arg_name}: {len(pattern)} > {MAX_ARG_REGEX_LEN}"
        )
    try:
        re.compile(pattern)
    except re.error as e:
        raise PolicyLoadError(f"Invalid regex for {arg_name}: {e}")


def _parse_arg_spec(arg_name: str, raw: Dict[str, Any]) -> ArgSpec:
    """Parse and validate an ArgSpec from a TOML dict."""
    kind = raw.get("kind")
    if kind not in ("string", "enum", "int"):
        raise PolicyLoadError(f"Invalid arg kind for {arg_name}: {kind}")

    regex = raw.get("regex")
    if regex is not None:
        _validate_regex(arg_name, regex)

    max_len = raw.get("max_len")
    if max_len is not None and max_len > MAX_ARG_MAX_LEN:
        raise PolicyLoadError(f"max_len too large for {arg_name}: {max_len}")

    return ArgSpec(
        kind=kind,
        required=raw.get("required", True),
        regex=regex,
        values=raw.get("values"),
        min_value=raw.get("min_value"),
        max_value=raw.get("max_value"),
        min_len=raw.get("min_len"),
        max_len=max_len,
        deny_chars=raw.get("deny_chars"),
    )


def _parse_command_spec(
    cmd_id: str,
    raw: Dict[str, Any],
    allowed_exec_dirs: Sequence[str],
) -> CommandSpec:
    """Parse and validate a CommandSpec from a TOML dict."""
    if len(cmd_id) > MAX_COMMAND_ID_LEN:
        raise PolicyLoadError(f"Command ID too long: {cmd_id}")
    if not re.fullmatch(r"[a-zA-Z0-9_\-]+", cmd_id):
        raise PolicyLoadError(f"Invalid command ID (alphanumeric/dash/underscore only): {cmd_id}")

    exec_path = raw.get("exec_path")
    if not isinstance(exec_path, str):
        raise PolicyLoadError(f"Missing or invalid exec_path for {cmd_id}")
    _validate_exec_path(exec_path, allowed_exec_dirs)

    description = raw.get("description", "")
    base_argv = raw.get("base_argv", [])
    if not isinstance(base_argv, list) or not all(isinstance(a, str) for a in base_argv):
        raise PolicyLoadError(f"base_argv must be a list of strings for {cmd_id}")

    timeout_s = raw.get("timeout_s", 15)
    if not isinstance(timeout_s, int) or timeout_s < 1 or timeout_s > MAX_TIMEOUT_S:
        raise PolicyLoadError(f"timeout_s must be 1-{MAX_TIMEOUT_S} for {cmd_id}: {timeout_s}")

    # Parse args
    args_raw = raw.get("args", {})
    if not isinstance(args_raw, dict):
        raise PolicyLoadError(f"args must be a dict for {cmd_id}")
    args: Dict[str, ArgSpec] = {}
    for arg_name, arg_raw in args_raw.items():
        if not isinstance(arg_raw, dict):
            raise PolicyLoadError(f"Arg {arg_name} must be a dict for {cmd_id}")
        args[arg_name] = _parse_arg_spec(f"{cmd_id}.{arg_name}", arg_raw)

    # Parse and validate arg_map
    arg_map_raw = raw.get("arg_map", {})
    if not isinstance(arg_map_raw, dict):
        raise PolicyLoadError(f"arg_map must be a dict for {cmd_id}")
    arg_map: Dict[str, List[str]] = {}
    for map_name, frags in arg_map_raw.items():
        if map_name not in args:
            raise PolicyLoadError(f"arg_map references unknown arg '{map_name}' for {cmd_id}")
        if not isinstance(frags, list) or not all(isinstance(f, str) for f in frags):
            raise PolicyLoadError(f"arg_map[{map_name}] must be a list of strings for {cmd_id}")
        for frag in frags:
            _validate_format_string(map_name, frag)
        arg_map[map_name] = frags

    return CommandSpec(
        command_id=cmd_id,
        description=description,
        exec_path=exec_path,
        base_argv=base_argv,
        args=args,
        arg_map=arg_map,
        timeout_s=timeout_s,
    )


def verify_hmac(file_path: str, secret: bytes) -> bool:
    """
    Verify HMAC-SHA256 signature of a policy file.

    Expects a companion file at {file_path}.sig containing the hex-encoded HMAC.
    """
    sig_path = file_path + ".sig"
    if not os.path.isfile(sig_path):
        return False

    with open(file_path, "rb") as f:
        content = f.read()
    with open(sig_path, "r") as f:
        expected_sig = f.read().strip()

    computed = hmac.new(secret, content, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, expected_sig)


def load_policy_file(
    file_path: str,
    *,
    allowed_exec_dirs: Optional[Sequence[str]] = None,
    hmac_secret: Optional[bytes] = None,
) -> EnginePolicy:
    """
    Load an EnginePolicy from a TOML file with full validation.

    Args:
        file_path: Path to the TOML policy file.
        allowed_exec_dirs: Directories where executables may reside.
        hmac_secret: If provided, verify HMAC-SHA256 signature before loading.

    Returns:
        A validated EnginePolicy.

    Raises:
        PolicyLoadError: If validation fails at any step.
    """
    allowed_exec_dirs = allowed_exec_dirs or DEFAULT_ALLOWED_EXEC_DIRS

    if hmac_secret is not None:
        if not verify_hmac(file_path, hmac_secret):
            raise PolicyLoadError(f"HMAC verification failed for {file_path}")

    with open(file_path, "rb") as f:
        raw = tomllib.load(f)

    meta = raw.get("meta", {})
    policy_id = meta.get("policy_id")
    version = meta.get("version")
    if not policy_id or not version:
        raise PolicyLoadError("meta.policy_id and meta.version are required")

    workspace_root = meta.get("workspace_root", "/tmp/restricted-exec")
    max_pipeline_steps = meta.get("max_pipeline_steps", 8)

    commands_raw = raw.get("commands", {})
    if not isinstance(commands_raw, dict):
        raise PolicyLoadError("commands must be a dict")

    commands: Dict[str, CommandSpec] = {}
    for cmd_id, cmd_raw in commands_raw.items():
        if not isinstance(cmd_raw, dict):
            raise PolicyLoadError(f"Command {cmd_id} must be a dict")
        commands[cmd_id] = _parse_command_spec(cmd_id, cmd_raw, allowed_exec_dirs)

    return EnginePolicy(
        policy_id=policy_id,
        version=version,
        commands=commands,
        workspace_root=workspace_root,
        max_pipeline_steps=max_pipeline_steps,
    )


def merge_policies(
    base: EnginePolicy,
    extension: EnginePolicy,
    *,
    allow_override: bool = False,
) -> EnginePolicy:
    """
    Merge an extension policy into a base policy.

    By default, extensions can only ADD new commands, not override existing ones.
    workspace_root and max_pipeline_steps always come from the base policy.

    Args:
        base: The base policy.
        extension: The extension policy to merge in.
        allow_override: If True, extension commands can replace base commands.

    Returns:
        A new merged EnginePolicy.
    """
    merged_commands = dict(base.commands)

    for cmd_id, cmd_spec in extension.commands.items():
        if cmd_id in merged_commands and not allow_override:
            raise PolicyLoadError(f"Extension cannot override existing command: {cmd_id}")
        merged_commands[cmd_id] = cmd_spec

    return EnginePolicy(
        policy_id=f"{base.policy_id}+{extension.policy_id}",
        version=base.version,
        commands=merged_commands,
        workspace_root=base.workspace_root,
        max_pipeline_steps=base.max_pipeline_steps,
    )
