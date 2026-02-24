from __future__ import annotations

import hashlib
import hmac
import os

import pytest

from restricted_exec.policy import EnginePolicy, CommandSpec, ArgSpec
from restricted_exec.policy_loader import (
    PolicyLoadError,
    load_policy_file,
    merge_policies,
    verify_hmac,
)


@pytest.fixture
def valid_toml(tmp_path):
    """Write a valid TOML policy file and return its path."""
    path = str(tmp_path / "policy.toml")
    with open(path, "w") as f:
        f.write("""\
[meta]
policy_id = "test-ext"
version = "0.2"

[commands.echo]
description = "Echo a value"
exec_path = "/bin/echo"
base_argv = []
timeout_s = 5

[commands.echo.args.value]
kind = "string"
required = true
max_len = 200

[commands.echo.arg_map]
value = ["{value}"]
""")
    return path


@pytest.fixture
def base_policy(workspace):
    return EnginePolicy(
        policy_id="base",
        version="0.1",
        workspace_root=workspace,
        commands={
            "mkdir": CommandSpec(
                command_id="mkdir",
                description="mkdir",
                exec_path="/bin/mkdir",
                base_argv=["-p"],
                args={"path": ArgSpec(kind="string")},
                arg_map={"path": ["{path}"]},
            ),
        },
    )


class TestLoadPolicyFile:
    def test_loads_valid_toml(self, valid_toml):
        policy = load_policy_file(valid_toml)
        assert policy.policy_id == "test-ext"
        assert policy.version == "0.2"
        assert "echo" in policy.commands
        assert policy.commands["echo"].exec_path == "/bin/echo"

    def test_validates_args(self, valid_toml):
        policy = load_policy_file(valid_toml)
        assert policy.commands["echo"].args["value"].kind == "string"
        assert policy.commands["echo"].args["value"].max_len == 200

    def test_validates_arg_map(self, valid_toml):
        policy = load_policy_file(valid_toml)
        assert policy.commands["echo"].arg_map == {"value": ["{value}"]}

    def test_rejects_missing_meta(self, tmp_path):
        path = str(tmp_path / "bad.toml")
        with open(path, "w") as f:
            f.write("[commands]\n")
        with pytest.raises(PolicyLoadError, match="policy_id"):
            load_policy_file(path)

    def test_rejects_nonexistent_exec_path(self, tmp_path):
        path = str(tmp_path / "bad.toml")
        with open(path, "w") as f:
            f.write("""\
[meta]
policy_id = "bad"
version = "0.1"

[commands.ghost]
description = "nonexistent"
exec_path = "/nonexistent/binary"
base_argv = []
timeout_s = 5
""")
        with pytest.raises(PolicyLoadError, match="does not exist"):
            load_policy_file(path)

    def test_rejects_relative_exec_path(self, tmp_path):
        path = str(tmp_path / "bad.toml")
        with open(path, "w") as f:
            f.write("""\
[meta]
policy_id = "bad"
version = "0.1"

[commands.rel]
description = "relative"
exec_path = "bin/echo"
base_argv = []
timeout_s = 5
""")
        with pytest.raises(PolicyLoadError, match="must be absolute"):
            load_policy_file(path)

    def test_rejects_exec_path_outside_allowed_dirs(self, tmp_path):
        # Create an executable in tmp_path (not in /usr/bin or /bin)
        exe = str(tmp_path / "my_binary")
        with open(exe, "w") as f:
            f.write("#!/bin/sh\necho hi\n")
        os.chmod(exe, 0o755)

        path = str(tmp_path / "bad.toml")
        with open(path, "w") as f:
            f.write(f"""\
[meta]
policy_id = "bad"
version = "0.1"

[commands.custom]
description = "outside allowed dirs"
exec_path = "{exe}"
base_argv = []
timeout_s = 5
""")
        with pytest.raises(PolicyLoadError, match="not in allowed directories"):
            load_policy_file(path)

    def test_allows_custom_exec_dirs(self, tmp_path):
        exe = str(tmp_path / "my_binary")
        with open(exe, "w") as f:
            f.write("#!/bin/sh\necho hi\n")
        os.chmod(exe, 0o755)

        path = str(tmp_path / "custom.toml")
        with open(path, "w") as f:
            f.write(f"""\
[meta]
policy_id = "custom"
version = "0.1"

[commands.custom]
description = "custom dir"
exec_path = "{exe}"
base_argv = []
timeout_s = 5
""")
        policy = load_policy_file(path, allowed_exec_dirs=[str(tmp_path)])
        assert "custom" in policy.commands

    def test_rejects_excessive_timeout(self, tmp_path):
        path = str(tmp_path / "bad.toml")
        with open(path, "w") as f:
            f.write("""\
[meta]
policy_id = "bad"
version = "0.1"

[commands.echo]
description = "too slow"
exec_path = "/bin/echo"
base_argv = []
timeout_s = 9999
""")
        with pytest.raises(PolicyLoadError, match="timeout_s"):
            load_policy_file(path)

    def test_rejects_invalid_command_id(self, tmp_path):
        path = str(tmp_path / "bad.toml")
        with open(path, "w") as f:
            f.write("""\
[meta]
policy_id = "bad"
version = "0.1"

[commands."rm -rf"]
description = "sneaky"
exec_path = "/bin/echo"
base_argv = []
timeout_s = 5
""")
        with pytest.raises(PolicyLoadError, match="Invalid command ID"):
            load_policy_file(path)

    def test_rejects_invalid_arg_kind(self, tmp_path):
        path = str(tmp_path / "bad.toml")
        with open(path, "w") as f:
            f.write("""\
[meta]
policy_id = "bad"
version = "0.1"

[commands.echo]
description = "bad arg"
exec_path = "/bin/echo"
base_argv = []
timeout_s = 5

[commands.echo.args.val]
kind = "executable"
""")
        with pytest.raises(PolicyLoadError, match="Invalid arg kind"):
            load_policy_file(path)

    def test_rejects_invalid_regex(self, tmp_path):
        path = str(tmp_path / "bad.toml")
        with open(path, "w") as f:
            f.write("""\
[meta]
policy_id = "bad"
version = "0.1"

[commands.echo]
description = "bad regex"
exec_path = "/bin/echo"
base_argv = []
timeout_s = 5

[commands.echo.args.val]
kind = "string"
regex = "[invalid("
""")
        with pytest.raises(PolicyLoadError, match="Invalid regex"):
            load_policy_file(path)

    def test_rejects_format_string_injection(self, tmp_path):
        path = str(tmp_path / "bad.toml")
        with open(path, "w") as f:
            f.write("""\
[meta]
policy_id = "bad"
version = "0.1"

[commands.echo]
description = "format injection"
exec_path = "/bin/echo"
base_argv = []
timeout_s = 5

[commands.echo.args.value]
kind = "string"

[commands.echo.arg_map]
value = ["{other_field}"]
""")
        with pytest.raises(PolicyLoadError, match="unexpected field"):
            load_policy_file(path)

    def test_rejects_arg_map_referencing_unknown_arg(self, tmp_path):
        path = str(tmp_path / "bad.toml")
        with open(path, "w") as f:
            f.write("""\
[meta]
policy_id = "bad"
version = "0.1"

[commands.echo]
description = "unknown arg ref"
exec_path = "/bin/echo"
base_argv = []
timeout_s = 5

[commands.echo.arg_map]
nonexistent = ["{nonexistent}"]
""")
        with pytest.raises(PolicyLoadError, match="unknown arg"):
            load_policy_file(path)


class TestMergePolicies:
    def test_merge_adds_commands(self, base_policy, valid_toml):
        extension = load_policy_file(valid_toml)
        merged = merge_policies(base_policy, extension)
        assert "mkdir" in merged.commands
        assert "echo" in merged.commands

    def test_merge_preserves_base_workspace(self, base_policy, valid_toml):
        extension = load_policy_file(valid_toml)
        merged = merge_policies(base_policy, extension)
        assert merged.workspace_root == base_policy.workspace_root

    def test_merge_preserves_base_max_steps(self, base_policy, valid_toml):
        extension = load_policy_file(valid_toml)
        merged = merge_policies(base_policy, extension)
        assert merged.max_pipeline_steps == base_policy.max_pipeline_steps

    def test_merge_denies_override_by_default(self, workspace):
        base = EnginePolicy(
            policy_id="base",
            version="0.1",
            workspace_root=workspace,
            commands={
                "echo": CommandSpec(
                    command_id="echo",
                    description="original",
                    exec_path="/bin/echo",
                    base_argv=[],
                    args={},
                    arg_map={},
                ),
            },
        )
        ext = EnginePolicy(
            policy_id="ext",
            version="0.1",
            workspace_root=workspace,
            commands={
                "echo": CommandSpec(
                    command_id="echo",
                    description="override attempt",
                    exec_path="/bin/echo",
                    base_argv=["--evil"],
                    args={},
                    arg_map={},
                ),
            },
        )
        with pytest.raises(PolicyLoadError, match="cannot override"):
            merge_policies(base, ext)

    def test_merge_allows_override_when_explicit(self, workspace):
        base = EnginePolicy(
            policy_id="base",
            version="0.1",
            workspace_root=workspace,
            commands={
                "echo": CommandSpec(
                    command_id="echo",
                    description="original",
                    exec_path="/bin/echo",
                    base_argv=[],
                    args={},
                    arg_map={},
                ),
            },
        )
        ext = EnginePolicy(
            policy_id="ext",
            version="0.1",
            workspace_root=workspace,
            commands={
                "echo": CommandSpec(
                    command_id="echo",
                    description="override",
                    exec_path="/bin/echo",
                    base_argv=["new"],
                    args={},
                    arg_map={},
                ),
            },
        )
        merged = merge_policies(base, ext, allow_override=True)
        assert merged.commands["echo"].base_argv == ["new"]

    def test_merged_policy_id(self, base_policy, valid_toml):
        extension = load_policy_file(valid_toml)
        merged = merge_policies(base_policy, extension)
        assert merged.policy_id == "base+test-ext"


class TestHmacVerification:
    def test_valid_hmac(self, valid_toml):
        secret = b"test-secret-key"
        with open(valid_toml, "rb") as f:
            content = f.read()
        sig = hmac.new(secret, content, hashlib.sha256).hexdigest()
        with open(valid_toml + ".sig", "w") as f:
            f.write(sig)

        assert verify_hmac(valid_toml, secret) is True

    def test_invalid_hmac(self, valid_toml):
        with open(valid_toml + ".sig", "w") as f:
            f.write("0" * 64)

        assert verify_hmac(valid_toml, b"test-secret") is False

    def test_missing_sig_file(self, valid_toml):
        assert verify_hmac(valid_toml, b"test-secret") is False

    def test_load_with_hmac_enforcement(self, valid_toml):
        secret = b"enforce-this"
        with open(valid_toml, "rb") as f:
            content = f.read()
        sig = hmac.new(secret, content, hashlib.sha256).hexdigest()
        with open(valid_toml + ".sig", "w") as f:
            f.write(sig)

        policy = load_policy_file(valid_toml, hmac_secret=secret)
        assert policy.policy_id == "test-ext"

    def test_load_with_bad_hmac_fails(self, valid_toml):
        with open(valid_toml + ".sig", "w") as f:
            f.write("bad" * 20)

        with pytest.raises(PolicyLoadError, match="HMAC verification failed"):
            load_policy_file(valid_toml, hmac_secret=b"some-secret")
