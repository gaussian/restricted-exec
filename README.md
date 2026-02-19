# restricted-exec

## What this does

When you let untrusted code run on your infrastructure — whether it comes from an
AI agent, a user-submitted script, or an automated pipeline — you need to control
exactly what that code is allowed to do. `restricted-exec` is that control layer.

It sits between the untrusted input and the operating system. You give it a shell
command or a Python snippet, and instead of executing it directly (the way `os.system`
or `subprocess.Popen(shell=True)` would), it does three things:

1. **Parses** the input into a structured syntax tree (using `bashlex` for shell,
   Python's built-in `ast` module for Python).
2. **Validates** every element of that tree against a strict deny-by-default policy.
   Only commands, flags, and function calls that you have explicitly allowlisted are
   permitted. Everything else — variable expansion, command substitution, imports,
   attribute access, globbing — is rejected before anything runs.
3. **Compiles** the validated input into a deterministic execution plan: a list of
   concrete steps with resolved arguments, file paths confined to a workspace
   directory, and structured audit metadata. The plan can be inspected, logged, or
   approved before execution.

If you choose to execute the plan, it runs each step using `subprocess.Popen` with
`shell=False` (for shell plans) or a tightly restricted `exec()` with only your
chosen safe APIs in scope (for Python plans). Output is sanitized: ANSI escape codes
are stripped, secrets like API keys and JWTs are redacted, and long output is
truncated.

The allowed set of commands and functions is not fixed. You can extend it securely at
configuration time by loading TOML policy files (with optional HMAC signature
verification), or at runtime by registering new Python functions through a type-checked
wrapper that prevents argument injection and sanitizes exceptions.

This is **not** a sandbox. It does not provide OS-level isolation, network restrictions,
or filesystem-level enforcement. It is the in-process validation layer that you pair
with a real sandbox (Fargate, microVM, gVisor) in production. Its job is to make sure
that only known-safe operations reach the sandbox in the first place.

## Quick start

```bash
uv sync
uv run python examples/run_shell.py
uv run python examples/run_python.py
uv run python examples/extend_policy.py
uv run python examples/extend_python_api.py
uv run pytest tests/ -v                    # 251 tests
```

## Examples: what's allowed and what's denied

### Shell

```bash
# ALLOWED — simple allowlisted command with flags
echo hello                          # ✓ if "echo" is in policy

# ALLOWED — pipeline (stdout wiring, no shell)
echo hello | wc -l                  # ✓ if both "echo" and "wc" are in policy

# ALLOWED — sequencing and redirect to workspace
mkdir --path out && echo done > out/log.txt   # ✓

# DENIED — command substitution
echo $(whoami)                      # ✗ rejected: "Forbidden token: $("

# DENIED — variable expansion
echo $HOME                          # ✗ rejected: "Expansions are not supported"

# DENIED — globbing
ls *.py                             # ✗ rejected: "Glob character not allowed in shell words: *"

# DENIED — command not in policy
rm -rf /                            # ✗ rejected: "Command not allowlisted: rm"

# DENIED — process substitution
diff <(echo a) <(echo b)            # ✗ rejected: "Forbidden token: <("

# DENIED — backgrounding
sleep 999 &                         # ✗ rejected

# DENIED — subshells, loops, functions
(echo hidden)                       # ✗ rejected: "Unsupported shell construct"
for i in 1 2 3; do echo $i; done   # ✗ rejected
```

### Python

```python
# ALLOWED — safe API calls, variables, arithmetic, control flow
mkdir("out")                                    # ✓
write_text("out/data.txt", "hello")             # ✓
content = read_text("out/data.txt")             # ✓
r = http_get("https://example.com/")            # ✓
page = r["body_text"][:2000]                    # ✓ (subscript and slice allowed)
for i in range(3):                              # ✓
    print(i)
x = len("hello") + max(1, 2)                   # ✓

# DENIED — imports
import os                                       # ✗ "Forbidden syntax: Import"

# DENIED — attribute access (blocks __class__ escape chains)
x = ().__class__.__bases__[0].__subclasses__()  # ✗ "Attribute access is not allowed"
"hello".upper()                                 # ✗ (method call = attribute access)

# DENIED — dangerous builtins
eval("1+1")                                     # ✗ "Forbidden call: eval"
exec("import os")                               # ✗ "Forbidden call: exec"
open("/etc/passwd")                             # ✗ "Forbidden call: open"
getattr([], "__class__")                        # ✗ "Forbidden call: getattr"

# DENIED — information gathering
globals()                                       # ✗ "Forbidden call: globals"
dir()                                           # ✗ "Forbidden call: dir"
type(42)                                        # ✗ "Forbidden call: type"

# DENIED — code generation
f"{1+1}"                                        # ✗ "f-strings are not allowed"
def foo(): pass                                 # ✗ "Forbidden syntax: FunctionDef"
class Foo: pass                                 # ✗ "Forbidden syntax: ClassDef"
lambda: 1                                       # ✗ "Forbidden syntax: Lambda"

# DENIED — dunder access
x = __builtins__                                # ✗ "Dunder name access not allowed"
```

### Path traversal (filesystem sandbox)

```python
write_text("out/data.txt", "ok")                # ✓ stays under workspace
write_text("../../etc/passwd", "pwned")         # ✗ "Path escapes workspace root"
read_text("/etc/shadow")                        # ✗ "Path escapes workspace root"
mkdir("a/b/../../../escape")                    # ✗ "Path escapes workspace root"
```

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

## Security

See [SECURITY.md](SECURITY.md) for the full security architecture, defense-in-depth
layers, threat model, and details on how `python`/`python3` commands in shell input
are intercepted and routed through the Python AST validator.
