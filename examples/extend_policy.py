"""
Example: Loading and merging policy files to extend allowed shell commands.

This demonstrates the secure extension mechanism for adding new shell commands
via TOML policy files with full validation.
"""

import os
import tempfile

from restricted_exec.policy import EnginePolicy, CommandSpec, ArgSpec
from restricted_exec.policy_loader import load_policy_file, merge_policies
from restricted_exec.shell_sanitizer import sanitize_shell_to_plan


def create_example_policy_file(path: str) -> None:
    """Write an example TOML policy file."""
    with open(path, "w") as f:
        f.write("""\
[meta]
policy_id = "extra-tools"
version = "0.1"

[commands.ls]
description = "List directory contents"
exec_path = "/bin/ls"
base_argv = ["-la"]
timeout_s = 5

[commands.ls.args.path]
kind = "string"
required = false
regex = "^[A-Za-z0-9_/.\\\\-]{1,200}$"
max_len = 200

[commands.ls.arg_map]
path = ["{path}"]

[commands.wc]
description = "Count lines/words/chars"
exec_path = "/usr/bin/wc"
base_argv = ["-l"]
timeout_s = 5

[commands.wc.args]
# wc takes no user-provided args in this config (reads from stdin via pipeline)
""")


def base_policy() -> EnginePolicy:
    """Create a minimal base policy."""
    return EnginePolicy(
        policy_id="base",
        version="0.1",
        workspace_root="/tmp/restricted-exec-demo",
        commands={
            "echo": CommandSpec(
                command_id="echo",
                description="Echo a literal value.",
                exec_path="/bin/echo",
                base_argv=[],
                args={"value": ArgSpec(kind="string", max_len=200)},
                arg_map={"value": ["{value}"]},
                timeout_s=2,
            ),
        },
    )


if __name__ == "__main__":
    # 1. Create example policy file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        policy_path = f.name
    create_example_policy_file(policy_path)

    try:
        # 2. Load the extension policy (with full validation)
        extension = load_policy_file(policy_path)
        print(f"Loaded extension: {extension.policy_id} with commands: {list(extension.commands.keys())}")

        # 3. Merge with base
        base = base_policy()
        merged = merge_policies(base, extension)
        print(f"Merged policy: {merged.policy_id} with commands: {list(merged.commands.keys())}")

        # 4. Now we can use the extended commands
        src = "echo hello | wc"
        plan = sanitize_shell_to_plan(merged, src)
        print(f"Plan compiled: {len(plan.steps)} steps")
        for i, step in enumerate(plan.steps):
            print(f"  [{i}] {step.command_id} {step.args}")

    finally:
        os.unlink(policy_path)
