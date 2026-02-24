"""
Example: Registering custom safe functions for restricted Python.

This demonstrates the SafeAPI.register() mechanism for extending
the set of functions available to restricted Python code.
"""

import hashlib

from restricted_exec.policy import EnginePolicy
from restricted_exec.python_sanitizer import sanitize_python_to_plan
from restricted_exec.executor import execute_plan
from restricted_exec.safe_api import SafeAPI


def policy() -> EnginePolicy:
    return EnginePolicy(
        policy_id="demo-extended",
        version="0.1",
        workspace_root="/tmp/restricted-exec-demo",
        commands={},
    )


# Custom safe functions to register
def sha256_hex(text: str) -> str:
    """Compute SHA-256 hash of a string."""
    return hashlib.sha256(text.encode()).hexdigest()


def join_lines(lines: list) -> str:
    """Join a list of strings with newlines."""
    return "\n".join(str(line) for line in lines)


if __name__ == "__main__":
    p = policy()

    # Create a SafeAPI and register custom functions
    api = SafeAPI(workspace_root=p.workspace_root)
    api.register(
        "sha256_hex",
        sha256_hex,
        allowed_arg_types=(str,),
        description="Compute SHA-256 hash of a string",
    )
    api.register(
        "join_lines",
        join_lines,
        allowed_arg_types=(list,),
        description="Join list items with newlines",
    )

    print(f"Available API: {sorted(api.get_all_api_names())}")

    # Validate Python using the extended API set
    py_src = """
h = sha256_hex("hello world")
print("SHA-256:", h)
result = join_lines(["line 1", "line 2", "line 3"])
write_text("out/joined.txt", result)
print("Wrote joined lines")
"""

    plan = sanitize_python_to_plan(p, py_src, allowed_api=api.get_all_api_names())
    print(f"Plan validated: {plan.explain['allowed_calls']}")

    # Execute with the custom SafeAPI instance
    res = execute_plan(
        p,
        plan,
        actor={"type": "developer", "id": "d-1", "tenant": "t-1"},
        request_id="req-ext-1",
        safe_api=api,
        cwd=p.workspace_root,
    )
    print(f"Result: ok={res['ok']}, error={res['error']}")
