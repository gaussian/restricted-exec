from restricted_exec.policy import EnginePolicy
from restricted_exec.python_sanitizer import sanitize_python_to_plan
from restricted_exec.executor import execute_plan


def policy() -> EnginePolicy:
    return EnginePolicy(
        policy_id="demo",
        version="0.1",
        workspace_root="/tmp/restricted-exec-demo",
        commands={},
    )


if __name__ == "__main__":
    p = policy()

    py = """
mkdir("out")
write_text("out/hello.txt", "hello from restricted python")
r = http_get("https://example.com/")
write_text("out/example.html", r["body_text"][:2000])
print("Done! Status:", r["status"])
"""

    allowed_api = {"mkdir", "write_text", "write_json", "read_text", "http_get"}
    plan = sanitize_python_to_plan(p, py, allowed_api=allowed_api)
    print(f"Plan: {plan.explain}")

    res = execute_plan(
        p,
        plan,
        actor={"type": "customer", "id": "c-1", "tenant": "t-1"},
        request_id="req-2",
        http_allow_hosts={"example.com"},
        cwd=p.workspace_root,
    )
    print(f"Result: ok={res['ok']}, error={res['error']}")
