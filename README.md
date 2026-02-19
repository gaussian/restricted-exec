# restricted-exec

A highly restrictive sanitizer/validator + compiler for:
- **Shell-like input** (bash subset) — parsed, validated, compiled to a no-shell execution plan
- **Python input** (AST-restricted subset) — only allowlisted safe API calls permitted

Outputs a deterministic execution plan and can optionally execute it using `subprocess`
with `shell=False` (no shell parsing).

## Threat model / non-goals

This repo **does not** provide OS-level isolation. For production you must run the executor
inside a sandbox (ECS Fargate / microVM / gVisor / etc.) and enforce network + FS policies
at that layer.

This repo focuses on:
- Deny-by-default parsing + validation
- Compiling to allowlisted primitives
- Auditable "what will it do" plan and structured events
- Output sanitization (ANSI stripping, redaction, truncation)
- **Secure extension** of allowed commands and functions

## Quick start

```bash
uv sync
uv run python examples/run_shell.py
uv run python examples/run_python.py
uv run python examples/extend_policy.py
uv run python examples/extend_python_api.py
```

## Supported shell subset (deny by default)

**Allowed:**
- Simple commands (must be allowlisted in policy)
- Pipelines (`|`)
- Redirections `>` and `>>` to workspace-only paths
- Chaining `&&` and `;` (compiled to step sequencing)
- Quoted strings (no expansions)

**Denied:**
- Command substitution: `$()`, backticks
- Variable expansion: `$FOO`
- Globbing: `*`, `?`
- Process substitution: `<(...)`
- Backgrounding: `&`
- Subshells: `(...)` or `{ ...; }`
- All other shell constructs

## Supported Python subset (deny by default)

**Allowed:**
- Literals, dict/list construction
- `if`/`for`/`while`
- Dict/list indexing and slicing (`d["key"]`, `s[:100]`)
- Calls **only** to provided safe APIs (e.g. `http_get`, `write_text`, `mkdir`)
- Basic builtins: `len`, `range`, `min`, `max`, `sum`, `print`, `str`, `int`, `float`

**Denied:**
- `import` / `from ... import`
- Attribute access (`obj.attr` — blocks `__class__` escape chains)
- `exec`/`eval`/`compile`/`open`/`__import__`
- `getattr`/`setattr`/`delattr`/`globals`/`locals`/`vars`/`dir`
- f-strings (can invoke `format` methods)
- Class/function definitions, lambda, try/except
- Starred expressions, yield, async constructs

## Extending allowed commands

### Shell commands (TOML policy files)

Create a `.toml` policy file:

```toml
[meta]
policy_id = "custom-tools"
version = "0.1"

[commands.jq]
description = "JSON processor"
exec_path = "/usr/bin/jq"
base_argv = []
timeout_s = 10

[commands.jq.args.filter]
kind = "string"
required = true
max_len = 500
regex = "^[A-Za-z0-9_.\\[\\]\\|\\s\"':-]+$"

[commands.jq.arg_map]
filter = ["{filter}"]
```

Load and merge:

```python
from restricted_exec import load_policy_file, merge_policies

extension = load_policy_file("custom-tools.toml")
merged = merge_policies(base_policy, extension)
```

Validation enforced on load:
- `exec_path` must be absolute, exist, and be in an allowed directory
- Format strings are parsed and validated (no injection)
- Regex patterns are validated and length-bounded
- Extensions can only **add** commands, not override existing ones

Optional HMAC-SHA256 signature verification:

```python
extension = load_policy_file("policy.toml", hmac_secret=b"your-secret")
```

### Python functions (SafeAPI.register)

```python
from restricted_exec.safe_api import SafeAPI

api = SafeAPI(workspace_root="/tmp/workspace")
api.register(
    "sha256_hex",
    my_sha256_fn,
    allowed_arg_types=(str,),
    description="Compute SHA-256 hash",
)
```

Registered functions are wrapped with:
- Argument type checking
- Exception sanitization (no leaking internals)
- Name validation (lowercase snake_case, cannot shadow builtins)
