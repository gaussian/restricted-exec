from restricted_exec.policy import EnginePolicy, CommandSpec, ArgSpec
from restricted_exec.shell_sanitizer import sanitize_shell_to_plan
from restricted_exec.executor import execute_plan


def policy() -> EnginePolicy:
    return EnginePolicy(
        policy_id="demo",
        version="0.1",
        workspace_root="/tmp/restricted-exec-demo",
        commands={
            "mkdir": CommandSpec(
                command_id="mkdir",
                description="Create a directory under workspace",
                exec_path="/bin/mkdir",
                base_argv=["-p"],
                args={
                    "path": ArgSpec(
                        kind="string",
                        regex=r"^[A-Za-z0-9_\-\/\.]{1,200}$",
                    )
                },
                arg_map={"path": ["{path}"]},
                timeout_s=5,
            ),
            "curl": CommandSpec(
                command_id="curl",
                description="HTTPS GET only (demo flags).",
                exec_path="/usr/bin/curl",
                base_argv=[
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "10",
                    "--proto",
                    "=https",
                ],
                args={
                    "url": ArgSpec(
                        kind="string",
                        regex=r"^https://[A-Za-z0-9\.\-]+/[A-Za-z0-9/_\.\-]*$",
                        max_len=300,
                    )
                },
                arg_map={"url": ["{url}"]},
                timeout_s=12,
            ),
            "echo": CommandSpec(
                command_id="echo",
                description="Echo a literal value (no expansions).",
                exec_path="/bin/echo",
                base_argv=[],
                args={"value": ArgSpec(kind="string", max_len=200)},
                arg_map={"value": ["{value}"]},
                timeout_s=2,
            ),
        },
    )


if __name__ == "__main__":
    p = policy()

    src = r"""
      mkdir --path out && echo hello > out/yes.txt ; curl --url https://example.com/ > out/example.html
    """
    plan = sanitize_shell_to_plan(p, src)
    print(f"Plan: {len(plan.steps)} steps")
    for i, step in enumerate(plan.steps):
        print(f"  [{i}] {step.command_id} {step.args}")

    res = execute_plan(
        p,
        plan,
        actor={"type": "agent", "id": "a-1", "tenant": "t-1"},
        request_id="req-1",
        cwd=p.workspace_root,
    )
    print(f"Return codes: {res['return_codes']}")
    print(f"Stderr: {res['stderr']['text'][:300]}")
