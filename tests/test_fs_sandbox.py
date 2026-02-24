from __future__ import annotations

import os

import pytest

from restricted_exec.fs_sandbox import FsViolation, ensure_under_root, mkdir_p


class TestEnsureUnderRoot:
    def test_valid_relative_path(self, workspace):
        result = ensure_under_root(workspace, "subdir/file.txt")
        assert result.startswith(os.path.realpath(workspace))
        assert result.endswith("subdir/file.txt")

    def test_valid_nested_path(self, workspace):
        result = ensure_under_root(workspace, "a/b/c/d.txt")
        assert result.startswith(os.path.realpath(workspace))

    def test_root_itself_is_valid(self, workspace):
        result = ensure_under_root(workspace, ".")
        assert result == os.path.realpath(workspace)

    def test_parent_escape_blocked(self, workspace):
        with pytest.raises(FsViolation, match="escapes workspace root"):
            ensure_under_root(workspace, "../../etc/passwd")

    def test_absolute_escape_blocked(self, workspace):
        with pytest.raises(FsViolation, match="escapes workspace root"):
            ensure_under_root(workspace, "/etc/passwd")

    def test_dotdot_in_middle_blocked(self, workspace):
        with pytest.raises(FsViolation, match="escapes workspace root"):
            ensure_under_root(workspace, "a/b/../../../etc/passwd")

    def test_many_dotdots_blocked(self, workspace):
        with pytest.raises(FsViolation, match="escapes workspace root"):
            ensure_under_root(workspace, "../" * 20 + "etc/passwd")

    def test_absolute_path_under_root_allowed(self, workspace):
        real_root = os.path.realpath(workspace)
        target = os.path.join(real_root, "valid.txt")
        result = ensure_under_root(workspace, target)
        assert result == target

    def test_empty_relative_path_is_root(self, workspace):
        result = ensure_under_root(workspace, "")
        assert result == os.path.realpath(workspace)

    def test_dotdot_that_stays_within_root(self, workspace):
        # a/b/../c resolves to a/c — still under root
        result = ensure_under_root(workspace, "a/b/../c")
        assert result.startswith(os.path.realpath(workspace))
        assert result.endswith("a/c")


class TestMkdirP:
    def test_creates_nested_dirs(self, workspace):
        path = os.path.join(workspace, "a", "b", "c")
        mkdir_p(path)
        assert os.path.isdir(path)

    def test_idempotent(self, workspace):
        path = os.path.join(workspace, "existing")
        mkdir_p(path)
        mkdir_p(path)  # should not raise
        assert os.path.isdir(path)
