from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


class PolicyError(Exception):
    pass


@dataclass(frozen=True)
class ArgSpec:
    kind: str  # "string" | "enum" | "int"
    required: bool = True
    regex: Optional[str] = None
    values: Optional[List[str]] = None
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    min_len: Optional[int] = None
    max_len: Optional[int] = None
    deny_chars: Optional[str] = None


@dataclass(frozen=True)
class CommandSpec:
    command_id: str
    description: str
    exec_path: str
    base_argv: List[str]
    args: Dict[str, ArgSpec]
    arg_map: Dict[str, List[str]]
    timeout_s: int = 15


@dataclass(frozen=True)
class EnginePolicy:
    policy_id: str
    version: str
    commands: Dict[str, CommandSpec]
    # Workspace constraints at the repo layer. Real enforcement should be OS-level too.
    workspace_root: str = "/tmp/restricted-exec"
    max_pipeline_steps: int = 8
