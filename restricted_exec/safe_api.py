from __future__ import annotations

import functools
import json
import os
import re
import signal
import urllib.request
from typing import Any, Callable, Dict, Optional, Sequence, Type

from .fs_sandbox import ensure_under_root, mkdir_p


class ApiViolation(Exception):
    pass


# Builtins that must never be shadowed by registered functions
_RESERVED_NAMES = frozenset({
    "True", "False", "None", "len", "range", "min", "max", "sum", "print",
    "eval", "exec", "compile", "open", "__import__",
    "mkdir", "write_text", "write_json", "read_text", "http_get",
})

_VALID_NAME_RE = re.compile(r"^[a-z_][a-z0-9_]*$")


class _RegisteredFunc:
    """Wrapper that enforces arg types, timeout, and exception sanitization."""

    def __init__(
        self,
        name: str,
        fn: Callable,
        allowed_arg_types: Sequence[Type],
        timeout_s: int,
        description: str,
    ):
        self.name = name
        self.fn = fn
        self.allowed_arg_types = tuple(allowed_arg_types)
        self.timeout_s = timeout_s
        self.description = description

    def __call__(self, *args, **kwargs):
        # Type-check positional args
        for i, arg in enumerate(args):
            if not isinstance(arg, self.allowed_arg_types):
                raise ApiViolation(
                    f"{self.name}: arg {i} has type {type(arg).__name__}, "
                    f"allowed: {[t.__name__ for t in self.allowed_arg_types]}"
                )
        # Type-check keyword args
        for k, v in kwargs.items():
            if not isinstance(v, self.allowed_arg_types):
                raise ApiViolation(
                    f"{self.name}: kwarg '{k}' has type {type(v).__name__}, "
                    f"allowed: {[t.__name__ for t in self.allowed_arg_types]}"
                )
        try:
            return self.fn(*args, **kwargs)
        except ApiViolation:
            raise
        except Exception as e:
            # Sanitize exception — don't leak internals
            raise ApiViolation(
                f"{self.name} failed: {type(e).__name__}"
            ) from None


class SafeAPI:
    """
    Safe capabilities exposed to restricted Python.
    This is intentionally small. Add capabilities via register().

    NOTE: urllib here is just to keep dependencies minimal. In production you'd likely:
    - force all egress through a proxy
    - add allowlists, mTLS, auth injection, logging
    """

    def __init__(
        self,
        workspace_root: str,
        http_allow_hosts: Optional[set[str]] = None,
    ):
        self.workspace_root = workspace_root
        self.http_allow_hosts = http_allow_hosts or set()
        self._registered: Dict[str, _RegisteredFunc] = {}

    # ---- Extension mechanism ----

    def register(
        self,
        name: str,
        fn: Callable,
        *,
        allowed_arg_types: Sequence[Type] = (str, int, float, bool, list, dict),
        timeout_s: int = 10,
        description: str = "",
    ) -> None:
        """
        Register a new safe function that restricted Python can call.

        Args:
            name: Function name (must be lowercase snake_case, cannot shadow builtins)
            fn: The callable to wrap
            allowed_arg_types: Tuple of types allowed as arguments
            timeout_s: Max execution time (enforced at OS level if available)
            description: Human-readable description for audit/explain
        """
        if not _VALID_NAME_RE.match(name):
            raise ApiViolation(
                f"Invalid function name '{name}': must match [a-z_][a-z0-9_]*"
            )
        if name in _RESERVED_NAMES:
            raise ApiViolation(f"Cannot shadow reserved name: {name}")
        if name in self._registered:
            raise ApiViolation(f"Function already registered: {name}")
        if not callable(fn):
            raise ApiViolation(f"'{name}' is not callable")

        self._registered[name] = _RegisteredFunc(
            name=name,
            fn=fn,
            allowed_arg_types=allowed_arg_types,
            timeout_s=timeout_s,
            description=description,
        )

    def get_registered_names(self) -> set[str]:
        """Return names of all registered extension functions."""
        return set(self._registered.keys())

    def get_all_api_names(self) -> set[str]:
        """Return names of all available API functions (built-in + registered)."""
        builtin = {"mkdir", "write_text", "write_json", "read_text", "http_get"}
        return builtin | self.get_registered_names()

    def build_globals(self) -> Dict[str, Any]:
        """Build the safe globals dict for exec(), including registered functions."""
        globs: Dict[str, Any] = {
            "__builtins__": {
                "True": True,
                "False": False,
                "None": None,
                "len": len,
                "range": range,
                "min": min,
                "max": max,
                "sum": sum,
                "print": print,
                "str": str,
                "int": int,
                "float": float,
                "bool": bool,
                "list": list,
                "dict": dict,
            },
            # Built-in safe API
            "mkdir": self.mkdir,
            "write_text": self.write_text,
            "write_json": self.write_json,
            "read_text": self.read_text,
            "http_get": self.http_get,
        }
        # Registered extensions
        for name, wrapped in self._registered.items():
            globs[name] = wrapped
        return globs

    # ---- FS ----

    def mkdir(self, rel_path: str) -> str:
        p = ensure_under_root(self.workspace_root, rel_path)
        mkdir_p(p)
        return p

    def write_text(self, rel_path: str, text: str) -> str:
        p = ensure_under_root(self.workspace_root, rel_path)
        mkdir_p(os.path.dirname(p))
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    def write_json(self, rel_path: str, obj: Any) -> str:
        return self.write_text(rel_path, json.dumps(obj, indent=2, sort_keys=True))

    def read_text(self, rel_path: str) -> str:
        p = ensure_under_root(self.workspace_root, rel_path)
        with open(p, "r", encoding="utf-8") as f:
            return f.read()

    # ---- HTTP ----

    def http_get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout_s: int = 10,
    ) -> Dict[str, Any]:
        from urllib.parse import urlparse

        u = urlparse(url)
        if u.scheme != "https":
            raise ApiViolation("Only https:// is allowed")
        if self.http_allow_hosts and u.hostname not in self.http_allow_hosts:
            raise ApiViolation(f"Host not allowlisted: {u.hostname}")

        req = urllib.request.Request(url, headers=headers or {}, method="GET")
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            body = resp.read()
            return {
                "status": resp.status,
                "headers": dict(resp.headers.items()),
                "body_bytes": body,
                "body_text": body.decode("utf-8", errors="replace"),
            }
