from __future__ import annotations

import os
import shutil
import tempfile

import pytest

from restricted_exec.policy import ArgSpec, CommandSpec, EnginePolicy


@pytest.fixture
def workspace(tmp_path):
    """Provide a temporary workspace directory."""
    ws = str(tmp_path / "workspace")
    os.makedirs(ws, exist_ok=True)
    yield ws
    shutil.rmtree(ws, ignore_errors=True)


@pytest.fixture
def basic_policy(workspace):
    """A minimal policy with echo, mkdir, and cat."""
    return EnginePolicy(
        policy_id="test",
        version="0.1",
        workspace_root=workspace,
        commands={
            "echo": CommandSpec(
                command_id="echo",
                description="Echo a value",
                exec_path="/bin/echo",
                base_argv=[],
                args={"value": ArgSpec(kind="string", max_len=200)},
                arg_map={"value": ["{value}"]},
                timeout_s=2,
            ),
            "mkdir": CommandSpec(
                command_id="mkdir",
                description="Create directory",
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
            "cat": CommandSpec(
                command_id="cat",
                description="Read file (or stdin if no args)",
                exec_path="/bin/cat",
                base_argv=[],
                args={
                    "file": ArgSpec(
                        kind="string",
                        required=False,
                        regex=r"^[A-Za-z0-9_\-\/\.]{1,200}$",
                    )
                },
                arg_map={"file": ["{file}"]},
                timeout_s=5,
            ),
        },
    )


@pytest.fixture
def empty_policy(workspace):
    """A policy with no commands (for Python-only tests)."""
    return EnginePolicy(
        policy_id="test-py",
        version="0.1",
        workspace_root=workspace,
        commands={},
    )


@pytest.fixture
def default_actor():
    return {"type": "test", "id": "test-1", "tenant": "test"}


@pytest.fixture
def allowed_api():
    return {"mkdir", "write_text", "write_json", "read_text", "http_get"}
