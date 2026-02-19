# Security Architecture

This document describes the defense-in-depth layers in `restricted-exec`, with
particular focus on how the shell and Python execution paths interact and why
each layer exists.

## Execution paths

There are two ways to run code through `restricted-exec`:

1. **Shell path** — `sanitize_shell_to_plan()` → `ShellPlan` → `_execute_shell_plan()`
2. **Python path** — `sanitize_python_to_plan()` → `PythonPlan` → `_execute_python_plan()`

Both paths are deny-by-default: the code is parsed, every element is validated
against explicit allowlists, and only then is it compiled into an execution plan.

### Python-in-shell interception

When a shell command begins with `python` or `python3`, the shell sanitizer
intercepts it **before** the normal command allowlist check. This prevents
Python code from bypassing the AST validator.

**Allowed form:** `python3 -c '<code>'`

The shell sanitizer extracts the code string and stores it as a `PythonStep`.
At execution time, the executor AST-validates the code through
`sanitize_python_to_plan()` and runs it via `exec()` with SafeAPI globals —
exactly the same security boundary as the pure Python path.

**Denied forms:**

| Invocation | Reason |
|---|---|
| `python3` (bare) | Interactive mode — no code to validate |
| `python3 script.py` | File contents unknown at sanitization time |
| `python3 -m module` | Module code unknown at sanitization time |
| `python3 --version` | Only `-c` flag is allowed |
| `python3 -c code extra` | Exactly one code argument required |
| `echo x \| python3 -c '...'` | Piping to/from inline Python not supported |

**Mixed sequences work:** `echo foo && python3 -c 'print(42)' && echo bar`
compiles into `[ShellStep, PythonStep, ShellStep]`. The executor handles each
step type appropriately.

## Shell sanitizer layers

### Layer 1: Raw token denial (`FORBIDDEN_TOKENS`)

Before any parsing, the raw shell string is scanned for injection tokens:

| Token | Purpose |
|---|---|
| `$(` | Command substitution |
| `` ` `` | Backtick command substitution |
| `<(` | Process substitution |
| `>(` | Process substitution |

These are caught early so that even a bashlex parsing bug cannot let them
through.

**Why `*` and `?` are not in `FORBIDDEN_TOKENS`:** Glob characters are handled
at the per-word level (see Layer 3) rather than on the raw string. This is
necessary because `python3 -c 'x = 2 * 3'` must be allowed — the `*` is a
Python multiplication operator inside a quoted argument, not a shell glob. Since
the raw string check runs before bashlex can distinguish quoted from unquoted
content, checking `*` there would block legitimate Python code.

### Layer 2: bashlex parsing

The shell input is parsed into an AST by `bashlex`. Only three constructs are
accepted:

- `command` — a single command with arguments
- `pipeline` — commands connected by `|`
- `list` — commands joined by `&&` or `;`

Everything else (subshells, loops, functions, `case`, `if`, `while`, brace
groups, `||`) is rejected.

### Layer 3: Per-word validation (`_word_to_literal`)

Every word extracted from the bashlex AST goes through `_word_to_literal()`,
which denies:

- **Expansion parts** — if bashlex found parameter expansion, command
  substitution, or arithmetic expansion inside the word
- **`$` and `` ` ``** — final safety check even if bashlex didn't detect them
- **`*` and `?`** — glob characters that are harmless with `shell=False` but
  unexpected in shell arguments

For the Python source string (the argument after `-c`), the dedicated
`_python_source_literal()` extractor is used instead. It applies the same
expansion and `$`/backtick checks but **skips the glob character check**,
allowing `*` and `?` which are valid Python operators.

### Layer 4: Command allowlist

The first word of each command must match an entry in `policy.commands`. Each
`CommandSpec` defines:

- `exec_path` — absolute path to the binary
- `args` — named arguments with type, regex, length, and character deny-lists
- `arg_map` — format strings mapping arguments to argv positions
- `timeout_s` — per-command timeout

`python`/`python3` is intercepted before this check (they don't need to be in
the allowlist).

### Layer 5: Subprocess execution (`shell=False`)

All shell commands are executed via `subprocess.Popen(shell=False)`. The argv
list is constructed programmatically — the shell is never invoked. This means
even if a glob or expansion character somehow reached execution, it would be
treated as a literal string argument, not interpreted by a shell.

### Layer 6: Filesystem sandbox

All file paths (redirects, SafeAPI file operations) are validated through
`ensure_under_root()` which resolves symlinks and rejects any path that escapes
the workspace root.

### Layer 7: Output sanitization

All captured output passes through `sanitize_output()` which:

- Strips ANSI escape codes
- Redacts secrets (Bearer tokens, JWTs, API keys, private keys)
- Truncates to a configurable maximum length

## Python sanitizer layers

### AST validation (primary gate)

The `_Validator` AST walker enforces deny-by-default:

- **Denied syntax:** imports, class/function definitions, `with`, `try/except`,
  `lambda`, `raise`, `assert`, `delete`, `global`, `nonlocal`, `yield`,
  `async`, `*`-expressions
- **Denied calls:** `eval`, `exec`, `compile`, `open`, `__import__`, `getattr`,
  `setattr`, `delattr`, `globals`, `locals`, `vars`, `dir`, `type`, `input`,
  and more
- **All attribute access denied:** blocks `__class__.__subclasses__()` escape
  chains, method calls, and property access
- **All dunder name access denied:** blocks `__builtins__`, `__import__`, etc.
- **f-strings denied:** they invoke `format()` methods (attribute access)
- **Only allowlisted function calls permitted:** calls must be direct name calls
  (no method calls) and must appear in the allowed set

### Restricted `exec()` (second layer)

Even after AST validation, the code runs with severely restricted globals:

- `__builtins__` contains only: `True`, `False`, `None`, `len`, `range`, `min`,
  `max`, `sum`, `print`, `str`, `int`, `float`, `bool`, `list`, `dict`
- Only SafeAPI functions (`mkdir`, `write_text`, `write_json`, `read_text`,
  `http_get`) and registered extensions are in scope

This is defense-in-depth — the AST validator is the primary gate.

### SafeAPI extensions

Functions registered via `SafeAPI.register()` are wrapped with:

- **Argument type checking** — each positional and keyword argument is validated
  against `allowed_arg_types`
- **Exception sanitization** — internal exceptions are caught and re-raised as
  `ApiViolation` without leaking implementation details
- **Name validation** — must be lowercase `snake_case`, cannot shadow builtins

## What this is NOT

This is **not** a sandbox. It does not provide:

- OS-level process isolation
- Network restrictions
- Filesystem-level enforcement (beyond path validation)
- Memory or CPU limits

It is the in-process validation layer that you pair with a real sandbox
(Fargate, microVM, gVisor) in production. Its job is to make sure that only
known-safe operations reach the sandbox.

## Threat model summary

| Threat | Mitigation |
|---|---|
| Shell injection via `$()`, backticks | `FORBIDDEN_TOKENS` + `_word_to_literal` + `shell=False` |
| Glob expansion | `_word_to_literal` glob check + `shell=False` |
| Process substitution | `FORBIDDEN_TOKENS` |
| Python code in shell command bypassing AST validator | Python-in-shell interception (`PythonStep`) |
| Python sandbox escape via `__class__` chains | All attribute access denied in AST |
| Python sandbox escape via `eval`/`exec`/`compile` | Deny-listed calls in AST validator |
| Python sandbox escape via `__import__` | Import syntax denied + `__import__` call denied + not in globals |
| Path traversal | `ensure_under_root()` with symlink resolution |
| Secret leakage in output | Regex-based redaction of tokens, keys, JWTs |
| Policy tampering | Optional HMAC-SHA256 signature verification |
| Extension function abuse | Type checking + exception sanitization + name validation |
