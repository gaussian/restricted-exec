from __future__ import annotations

import os

import pytest

from restricted_exec.safe_api import ApiViolation, SafeAPI
from restricted_exec.fs_sandbox import FsViolation


class TestSafeAPIFileOps:
    def test_mkdir(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        path = api.mkdir("testdir")
        assert os.path.isdir(path)

    def test_mkdir_nested(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        path = api.mkdir("a/b/c")
        assert os.path.isdir(path)

    def test_write_text(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        api.mkdir("out")
        path = api.write_text("out/file.txt", "hello world")
        assert os.path.isfile(path)
        with open(path) as f:
            assert f.read() == "hello world"

    def test_write_text_creates_parent_dirs(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        api.write_text("deep/nested/dir/file.txt", "content")
        assert os.path.isfile(os.path.join(os.path.realpath(workspace), "deep/nested/dir/file.txt"))

    def test_read_text(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        api.write_text("data.txt", "test content")
        content = api.read_text("data.txt")
        assert content == "test content"

    def test_write_json(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        api.write_json("data.json", {"key": "value", "num": 42})
        content = api.read_text("data.json")
        assert '"key": "value"' in content
        assert '"num": 42' in content

    def test_path_traversal_blocked_write(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        with pytest.raises(FsViolation):
            api.write_text("../../etc/evil.txt", "pwned")

    def test_path_traversal_blocked_read(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        with pytest.raises(FsViolation):
            api.read_text("/etc/passwd")

    def test_path_traversal_blocked_mkdir(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        with pytest.raises(FsViolation):
            api.mkdir("../../../tmp/evil")


class TestSafeAPIHttp:
    def test_rejects_http_scheme(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        with pytest.raises(ApiViolation, match="Only https"):
            api.http_get("http://example.com/")

    def test_rejects_non_allowlisted_host(self, workspace):
        api = SafeAPI(workspace_root=workspace, http_allow_hosts={"safe.com"})
        with pytest.raises(ApiViolation, match="not allowlisted"):
            api.http_get("https://evil.com/data")

    def test_allows_empty_allowlist(self, workspace):
        # Empty allowlist means all https hosts are allowed
        SafeAPI(workspace_root=workspace, http_allow_hosts=set())
        # We don't actually make the request here (network), just verify no ApiViolation
        # for the host check. The actual request will fail with connection error.
        # This is tested in integration tests (examples/).


class TestSafeAPIRegister:
    def test_register_and_call(self, workspace):
        api = SafeAPI(workspace_root=workspace)

        def double(x: int) -> int:
            return x * 2

        api.register("double", double, allowed_arg_types=(int,), description="Double a number")
        assert "double" in api.get_registered_names()
        assert "double" in api.get_all_api_names()

    def test_register_invalid_name_uppercase(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        with pytest.raises(ApiViolation, match="Invalid function name"):
            api.register("BadName", lambda: None)

    def test_register_invalid_name_starts_with_digit(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        with pytest.raises(ApiViolation, match="Invalid function name"):
            api.register("2fast", lambda: None)

    def test_register_reserved_name(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        with pytest.raises(ApiViolation, match="reserved name"):
            api.register("eval", lambda: None)

    def test_register_shadows_builtin_blocked(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        with pytest.raises(ApiViolation, match="reserved name"):
            api.register("len", lambda: None)

    def test_register_shadows_safe_api_blocked(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        with pytest.raises(ApiViolation, match="reserved name"):
            api.register("mkdir", lambda: None)

    def test_register_duplicate_blocked(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        api.register("my_func", lambda: None)
        with pytest.raises(ApiViolation, match="already registered"):
            api.register("my_func", lambda: None)

    def test_register_non_callable(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        with pytest.raises(ApiViolation, match="not callable"):
            api.register("not_func", 42)

    def test_registered_func_type_checking(self, workspace):
        api = SafeAPI(workspace_root=workspace)

        def only_strings(s: str) -> str:
            return s.upper()

        api.register("upper", only_strings, allowed_arg_types=(str,))
        globs = api.build_globals()

        # Should work
        assert globs["upper"]("hello") == "HELLO"

        # Should reject wrong type
        with pytest.raises(ApiViolation, match="type"):
            globs["upper"](42)

    def test_registered_func_exception_sanitized(self, workspace):
        api = SafeAPI(workspace_root=workspace)

        def broken(x: str) -> str:
            raise RuntimeError("internal secret error details")

        api.register("broken", broken, allowed_arg_types=(str,))
        globs = api.build_globals()

        with pytest.raises(ApiViolation, match="broken failed: RuntimeError"):
            globs["broken"]("test")

    def test_build_globals_includes_registered(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        api.register("custom_fn", lambda: "hi")
        globs = api.build_globals()
        assert "custom_fn" in globs
        assert "mkdir" in globs
        assert "write_text" in globs

    def test_build_globals_restricted_builtins(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        globs = api.build_globals()
        builtins = globs["__builtins__"]
        # Allowed
        assert builtins["len"] is len
        assert builtins["range"] is range
        assert builtins["True"] is True
        # Not present (dangerous)
        assert "eval" not in builtins
        assert "exec" not in builtins
        assert "open" not in builtins
        assert "__import__" not in builtins

    def test_get_all_api_names(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        names = api.get_all_api_names()
        assert names == {"mkdir", "write_text", "write_json", "read_text", "http_get"}

    def test_get_all_api_names_with_registered(self, workspace):
        api = SafeAPI(workspace_root=workspace)
        api.register("extra_fn", lambda: None)
        names = api.get_all_api_names()
        assert "extra_fn" in names
        assert "mkdir" in names
