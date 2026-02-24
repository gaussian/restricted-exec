from __future__ import annotations

import os


class FsViolation(Exception):
    pass


def ensure_under_root(root: str, path: str) -> str:
    """
    Resolve path and ensure it stays under root. Prevents ../ escapes.
    Note: symlink races are not fully prevented at this layer; OS sandbox should handle that.
    """
    root_real = os.path.realpath(root)
    target = os.path.realpath(os.path.join(root_real, path) if not os.path.isabs(path) else path)

    if not (target == root_real or target.startswith(root_real + os.sep)):
        raise FsViolation(f"Path escapes workspace root: {path} -> {target}")
    return target


def mkdir_p(path: str) -> None:
    os.makedirs(path, exist_ok=True)
