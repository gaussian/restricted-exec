# Security Audit and Analysis

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 2.0 | 2026-02-19 | Security Audit | Full rewrite as auditor-grade assessment |
| 1.0 | 2026-02-19 | Initial | Developer-facing architecture overview |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Scope and Boundaries](#2-scope-and-boundaries)
3. [Threat Model](#3-threat-model)
4. [Defense-in-Depth Analysis](#4-defense-in-depth-analysis)
5. [Attack Surface Matrix](#5-attack-surface-matrix)
6. [Python Sandbox Security](#6-python-sandbox-security)
7. [Shell Sanitizer Security](#7-shell-sanitizer-security)
8. [Filesystem Security](#8-filesystem-security)
9. [Policy and Configuration Security](#9-policy-and-configuration-security)
10. [Output Security](#10-output-security)
11. [Extension Security](#11-extension-security)
12. [Dependency Analysis](#12-dependency-analysis)
13. [Test Coverage Assessment](#13-test-coverage-assessment)
14. [Known Limitations and Residual Risks](#14-known-limitations-and-residual-risks)
15. [Deployment Requirements](#15-deployment-requirements)
16. [Recommendations](#16-recommendations)

---

## 1. Executive Summary

`restricted-exec` is an in-process validation layer for untrusted shell commands and
Python code. It parses input into a structured AST, validates every element against a
deny-by-default policy, compiles the result into a deterministic execution plan, and
executes it with `subprocess.Popen(shell=False)` or a restricted `exec()`. **It is not
a sandbox.** It is designed to be paired with OS-level isolation (Fargate, microVM,
gVisor) in production. Its job is to ensure only known-safe operations reach the
sandbox.

### Project Metrics

| Metric | Value |
|--------|-------|
| Source code | ~1,607 LOC across 10 modules |
| Test code | ~2,156 LOC across 9 test files (251 tests) |
| Test-to-code ratio | 1.3 : 1 |
| Runtime dependencies | 1 (`bashlex>=0.18`) |
| Python requirement | >=3.11 |
| License | MIT |
| Shell execution mode | `subprocess.Popen(shell=False)` always |
| Python execution mode | `exec()` with restricted builtins |
| Policy format | TOML with optional HMAC-SHA256 signing |

### Key Findings

| ID | Finding | Severity | Status |
|----|---------|----------|--------|
| F-01 | TOCTOU race in `ensure_under_root()` | High | Acknowledged (deferred to OS sandbox) |
| F-02 | No OS-level process isolation | Critical | By Design (not a sandbox) |
| F-03 | Child processes inherit full parent environment | Medium | Unmitigated |
| F-04 | No CPU/memory limits on Python `exec()` | Medium | Unmitigated |
| F-05 | Python `exec()` has no timeout enforcement | Medium | Unmitigated |
| F-06 | Extension `timeout_s` parameter stored but never enforced | Medium | Unmitigated |
| F-07 | ReDoS possible in user-provided policy regex patterns | Low | Partially Mitigated (500-char limit) |
| F-08 | `bool` is subclass of `int` — bypasses type checks | Low | Acknowledged |
| F-09 | Secret redaction is regex-based, not exhaustive | Low | Acknowledged |
| F-10 | No CI/CD pipeline or automated security testing | Medium | Unmitigated |

F-02 is rated Critical in isolation but is by-design: the library explicitly states it
is not a sandbox and must be paired with OS-level isolation.

---

## 2. Scope and Boundaries

### Protection Boundary

| This Library Provides | Operator Must Provide |
|-----------------------|-----------------------|
| Shell command parsing and deny-by-default allowlisting | OS-level process isolation (Fargate / microVM / gVisor) |
| Python AST validation with attribute access denial | Network egress filtering (firewall / proxy) |
| Path traversal prevention via `ensure_under_root()` | Filesystem-level enforcement (mount namespaces) |
| Subprocess execution with `shell=False` | CPU and memory resource limits (cgroups) |
| Output secret redaction (regex-based) | Comprehensive secret management |
| TOML policy loading with optional HMAC verification | Key management infrastructure for HMAC secrets |
| Extension function type checking and exception sanitization | Security auditing of registered extension functions |
| Audit event generation (JSON) | Audit event storage, alerting, and SIEM integration |

### Architecture

```
Untrusted Input (shell or Python string)
        |
        v
 +--------------------+
 |  Sanitizer Layer    |  Parse -> Validate -> Compile
 |  (deny-by-default)  |  Shell: 7 defense layers
 |                      |  Python: 3 defense layers
 +--------------------+
        |
        v
 +--------------------+
 |  Execution Plan     |  Inspectable, loggable, auditable
 +--------------------+
        |
        v
 +--------------------+
 |  Executor           |  shell=False / restricted exec()
 +--------------------+
        |
        v
 +--------------------+
 |  OS Sandbox         |  <-- NOT provided by this library
 |  (Fargate/microVM)  |
 +--------------------+
```

---

## 3. Threat Model

### Adversary Profile

The assumed adversary is an untrusted code author — an AI agent, user-submitted script,
or automated pipeline — with the ability to submit arbitrary shell and Python strings.
The adversary is assumed to have knowledge of Python sandbox escape techniques and shell
injection methods.

### Adversary Capabilities

| Capability | Assumed | Notes |
|-----------|---------|-------|
| Submit arbitrary shell input | Yes | Primary threat vector |
| Submit arbitrary Python input | Yes | Primary threat vector |
| Knowledge of Python sandbox escapes | Yes | `__class__.__subclasses__()`, `eval()`, etc. |
| Knowledge of shell injection techniques | Yes | `$()`, backticks, process substitution |
| Concurrent filesystem access | Possible | Depends on deployment; enables TOCTOU |
| Access to policy files on disk | No | HMAC covers tampering when enabled |
| Access to host process memory | No | Out of scope; requires OS-level isolation |
| Direct network access from child process | Yes (if no OS sandbox) | Library only filters `http_get()` |

### Trust Boundaries

| Boundary | From | To | Enforcement |
|----------|------|----|-------------|
| Shell input entry | Untrusted shell string | Shell sanitizer | `sanitize_shell_to_plan()` in `shell_sanitizer.py` |
| Python input entry | Untrusted Python string | Python sanitizer | `sanitize_python_to_plan()` in `python_sanitizer.py` |
| Plan to execution | Validated Plan object | Executor | `_execute_shell_plan()` / `_execute_python_plan()` in `executor.py` |
| Filesystem access | SafeAPI / redirects | OS filesystem | `ensure_under_root()` in `fs_sandbox.py` |
| Network egress | `http_get()` | External HTTP | HTTPS-only + optional host allowlist in `safe_api.py` |
| Policy loading | TOML file on disk | `EnginePolicy` | Schema validation + optional HMAC in `policy_loader.py` |
| Extension registration | Host application code | SafeAPI | Name validation + type checking in `safe_api.py` |

---

## 4. Defense-in-Depth Analysis

### Shell Defense Layers

| Layer | Location | Function | Blocks | Residual Risk |
|-------|----------|----------|--------|---------------|
| 1. Raw token denial | `shell_sanitizer.py:54-57` | `_deny_if_contains_forbidden_raw()` | `$(`, `` ` ``, `<(`, `>(` | Only 4 tokens; `*`/`?` handled later |
| 2. bashlex AST parsing | `shell_sanitizer.py:66-69` | `bashlex.parse()` | Malformed / unparseable input | Depends on bashlex correctness |
| 3. AST node filtering | `shell_sanitizer.py:94-137` | `_compile_node()` | Subshells, loops, functions, `\|\|`, brace groups, assignments | Only `command`/`pipeline`/`list` allowed |
| 4. Per-word validation | `shell_sanitizer.py:244-265` | `_word_to_literal()` | `$`, `` ` `` in words; `*`/`?` glob chars; expansion parts | Depends on bashlex word parsing accuracy |
| 5. Command allowlist | `shell_sanitizer.py:187-188` | `policy.commands` dict lookup | Any command not in policy | Args validated separately |
| 6. Argument validation | `executor.py:24-55` | `_validate_arg()` | Type mismatches, regex failures, length violations, deny_chars | Default deny_chars: `;&\|`$<>\n\r\0` |
| 7. `shell=False` execution | `executor.py:204-211` | `subprocess.Popen(shell=False)` | All shell interpretation at execution time | Inherits env vars from parent (F-03) |

### Python Defense Layers

| Layer | Location | Function | Blocks | Residual Risk |
|-------|----------|----------|--------|---------------|
| 1. AST validation (primary gate) | `python_sanitizer.py:57-112` | `_Validator` | Imports, attribute access, dunder names, forbidden calls, f-strings, class/func defs, lambda, etc. | Novel CPython AST bypass techniques |
| 2. Restricted `exec()` globals | `safe_api.py:139-169` | `build_globals()` | Access to `eval`, `exec`, `open`, `__import__` via builtins | Not a security boundary on its own |
| 3. SafeAPI function wrapping | `safe_api.py:28-68` | `_RegisteredFunc.__call__()` | Wrong argument types; exception info leakage | `bool` subclass of `int` (F-08) |

### Additional Defense Mechanisms

| Mechanism | Location | Purpose | Limitation |
|-----------|----------|---------|------------|
| Filesystem sandbox | `fs_sandbox.py:10-22` | `realpath()` + prefix check prevents `../` escapes | TOCTOU race (F-01) |
| Output sanitization | `output_sanitize.py:33-76` | Strips ANSI, redacts secrets, truncates to 50K chars | Regex-based; not exhaustive (F-09) |
| HMAC policy verification | `policy_loader.py:206-222` | SHA-256 HMAC on policy file content | Optional; sig file stored alongside |
| Policy merge protection | `policy_loader.py:282-308` | Prevents command override by default | `allow_override=True` bypasses |
| Exec path validation | `policy_loader.py:49-76` | Absolute, exists, executable, in allowed dir | Checked at load time only |
| Python-in-shell interception | `shell_sanitizer.py:174-241` | Routes `python3 -c` through AST validator | Only `-c` form; piped Python denied |
| Audit logging | `audit.py:30-36` | JSON events with request correlation | Default sink prints to stdout |

---

## 5. Attack Surface Matrix

| ID | Attack Vector | Category | Mitigation | Status | Severity if Bypassed |
|----|---------------|----------|------------|--------|---------------------|
| A-01 | Command substitution `$(...)` | Shell injection | FORBIDDEN_TOKENS + `_word_to_literal` + `shell=False` | **Mitigated** (3 layers) | Critical |
| A-02 | Backtick substitution `` `...` `` | Shell injection | FORBIDDEN_TOKENS + `_word_to_literal` + `shell=False` | **Mitigated** (3 layers) | Critical |
| A-03 | Process substitution `<(...)` / `>(...)` | Shell injection | FORBIDDEN_TOKENS | **Mitigated** | High |
| A-04 | Variable expansion `$VAR` / `${VAR}` | Shell injection | `_word_to_literal()` denies `$` + `shell=False` | **Mitigated** (2 layers) | High |
| A-05 | Glob expansion `*` / `?` | Shell injection | `_word_to_literal()` denies globs + `shell=False` | **Mitigated** (2 layers) | Medium |
| A-06 | Subshells `(...)` / brace groups `{...}` | Shell injection | bashlex AST node rejection | **Mitigated** | High |
| A-07 | Loops / conditionals (`for`, `if`, `while`, `case`) | Shell injection | bashlex AST node rejection | **Mitigated** | Medium |
| A-08 | OR operator `\|\|` | Shell injection | Explicit operator deny in `_compile_node()` | **Mitigated** | Medium |
| A-09 | Backgrounding `&` | Shell injection | Word content check for `&` | **Mitigated** | Medium |
| A-10 | Unlisted command execution | Authorization | Policy command allowlist | **Mitigated** | High |
| A-11 | bashlex parsing bug | Shell injection | Defense-in-depth layers 4-7 catch bypass | **Partially Mitigated** | Critical |
| A-12 | Python `__class__` escape chain | Sandbox escape | All attribute access denied in AST | **Mitigated** | Critical |
| A-13 | Python `eval()` / `exec()` / `compile()` | Sandbox escape | DENY_CALL_NAMES + not in builtins | **Mitigated** (2 layers) | Critical |
| A-14 | Python `__import__()` | Sandbox escape | Denied call + import syntax denied + not in globals | **Mitigated** (3 layers) | Critical |
| A-15 | Python `getattr()` / `setattr()` / reflection | Sandbox escape | DENY_CALL_NAMES | **Mitigated** | Critical |
| A-16 | Python f-string `__format__` escape | Sandbox escape | f-strings denied in AST | **Mitigated** | High |
| A-17 | Python method calls (`.upper()`, etc.) | Sandbox escape | All attribute access denied | **Mitigated** | High |
| A-18 | Python `bytes` / `bytearray` / `memoryview` | Sandbox escape | In DENY_CALL_NAMES | **Mitigated** | Medium |
| A-19 | Novel Python AST bypass | Sandbox escape | Restricted builtins as second layer | **Partially Mitigated** | Critical |
| A-20 | Path traversal via `../` | Filesystem escape | `ensure_under_root()` with `realpath()` | **Mitigated** | High |
| A-21 | Symlink race (TOCTOU) | Filesystem escape | Acknowledged; deferred to OS sandbox | **Unmitigated** (F-01) | High |
| A-22 | Environment variable leakage to child processes | Information disclosure | No `env=` passed to `Popen()` | **Unmitigated** (F-03) | Medium |
| A-23 | Secret leakage in output | Information disclosure | Regex-based redaction (5 patterns) | **Partially Mitigated** (F-09) | Medium |
| A-24 | Policy file tampering | Configuration | Optional HMAC-SHA256 | **Mitigated** (when enabled) | High |
| A-25 | Policy override via merge | Configuration | Default deny; `allow_override` flag | **Mitigated** | Medium |
| A-26 | Extension function abuse | Privilege escalation | Type checking + exception sanitization | **Partially Mitigated** | Medium |
| A-27 | ReDoS via policy regex | Denial of service | 500-char regex length limit | **Partially Mitigated** (F-07) | Low |
| A-28 | Python `exec()` infinite loop | Denial of service | No timeout enforcement | **Unmitigated** (F-05) | Medium |
| A-29 | Python `exec()` memory exhaustion | Denial of service | No memory limits | **Unmitigated** (F-04) | Medium |
| A-30 | HTTP SSRF via `http_get()` | Network | HTTPS-only + optional host allowlist | **Partially Mitigated** | Medium |
| A-31 | HTTP header injection | Network | `urllib` validates headers internally | **Mitigated** | Low |
| A-32 | `bool` as `int` in type checks | Type confusion | `isinstance(True, int)` returns `True` | **Acknowledged** (F-08) | Low |
| A-33 | Redirect file creation outside workspace | Filesystem escape | `ensure_under_root()` on redirect path | **Mitigated** | High |
| A-34 | Audit log tampering | Integrity | No integrity protection on default sink | **Unmitigated** | Low |
| A-35 | Extension timeout bypass | Denial of service | `timeout_s` not enforced | **Unmitigated** (F-06) | Medium |

---

## 6. Python Sandbox Security

### Denied AST Node Types

22 AST node types are denied at parse time (`python_sanitizer.py:20-43`):

| Node Type | What It Blocks | Why It's Dangerous |
|-----------|---------------|--------------------|
| `ast.Import` | `import os` | Module loading; arbitrary code access |
| `ast.ImportFrom` | `from os import system` | Module loading; arbitrary code access |
| `ast.With` | `with open(...) as f:` | Context managers can execute arbitrary code |
| `ast.AsyncWith` | `async with ...` | Async context managers |
| `ast.Try` | `try: ... except: ...` | Can catch and suppress security exceptions |
| `ast.TryStar` | `try: ... except* ...` | Python 3.11+ exception groups |
| `ast.Lambda` | `lambda: __import__('os')` | Anonymous function creation |
| `ast.ClassDef` | `class Foo: ...` | Metaclass and dunder method abuse |
| `ast.FunctionDef` | `def foo(): ...` | Function creation with closures |
| `ast.AsyncFunctionDef` | `async def foo(): ...` | Async function creation |
| `ast.Global` | `global x` | Scope modification |
| `ast.Nonlocal` | `nonlocal x` | Scope modification |
| `ast.Delete` | `del x` | Object deletion, dunder method triggers |
| `ast.Raise` | `raise Exception()` | Exception flow control |
| `ast.Assert` | `assert False` | Debug-mode dependent behavior |
| `ast.Yield` | `yield x` | Generator creation |
| `ast.YieldFrom` | `yield from x` | Generator delegation |
| `ast.Await` | `await x` | Async execution |
| `ast.AsyncFor` | `async for x in y:` | Async iteration |
| `ast.Starred` | `*args` | Unpacking; can trigger `__iter__` |
| `ast.MatchMapping` | `match x: case {...}:` | Pattern matching (dict) |
| `ast.MatchClass` | `match x: case Cls():` | Pattern matching (class) |

### Denied Function Calls

22 function names are deny-listed (`python_sanitizer.py:45-54`):

| Function | Category | Why Denied |
|----------|----------|------------|
| `eval` | Code execution | Evaluate arbitrary expressions |
| `exec` | Code execution | Execute arbitrary statements |
| `compile` | Code execution | Compile code objects (bypass AST) |
| `open` | File I/O | Arbitrary file read/write |
| `__import__` | Module loading | Import any module |
| `getattr` | Reflection | Access arbitrary attributes |
| `setattr` | Reflection | Set arbitrary attributes |
| `delattr` | Reflection | Delete arbitrary attributes |
| `hasattr` | Reflection | Probe object structure |
| `globals` | Introspection | Access global scope dict |
| `locals` | Introspection | Access local scope dict |
| `vars` | Introspection | Access object `__dict__` |
| `dir` | Introspection | List object attributes |
| `type` | Metaclass | Create classes dynamically |
| `super` | Metaclass | Access parent classes |
| `object` | Metaclass | Base class constructor |
| `breakpoint` | Debug | Drop to debugger |
| `exit` | Control | Terminate process |
| `quit` | Control | Terminate process |
| `memoryview` | Memory | Raw memory access |
| `bytearray` | Memory | Mutable byte sequences |
| `bytes` | Memory | Byte object creation |
| `classmethod` | Descriptor | Descriptor protocol abuse |
| `staticmethod` | Descriptor | Descriptor protocol abuse |
| `property` | Descriptor | Descriptor protocol abuse |
| `input` | I/O | Read from stdin |

### Critical Defense: Attribute Access Denial

All attribute access is unconditionally denied (`python_sanitizer.py:66-68`):

```python
def visit_Attribute(self, node: ast.Attribute) -> None:
    raise PythonDenied("Attribute access is not allowed")
```

This single rule blocks the most common Python sandbox escape chains.

### Known Escape Techniques and Mitigation

| Technique | Example | Blocked By | Tested |
|-----------|---------|------------|--------|
| `__class__` chain | `().__class__.__bases__[0].__subclasses__()` | Attribute access denial | Yes |
| `format()` method | `"{0.__class__}".format(42)` | Attribute access denial | Yes |
| `bytes.decode()` | `b"os".decode()` | Attribute access denial | Yes |
| `eval()` / `exec()` | `eval("__import__('os')")` | DENY_CALL_NAMES | Yes |
| `__import__()` call | `__import__("os")` | DENY_CALL_NAMES + dunder denial | Yes |
| `getattr()` chain | `getattr(getattr(...), ...)` | DENY_CALL_NAMES | Yes |
| f-string format spec | `f"{x.__class__}"` | f-string denial + attribute denial | Yes |
| `type()` metaclass | `type('X', (object,), {...})` | DENY_CALL_NAMES | Yes |
| `breakpoint()` | `breakpoint()` | DENY_CALL_NAMES | Yes |
| Lambda factory | `lambda: __import__('os')` | Lambda AST denial | Yes |
| Function definition | `def f(): ...` | FunctionDef AST denial | Yes |
| Class definition | `class C: ...` | ClassDef AST denial | Yes |

### Allowed Builtins Exposure Analysis

14 builtins are available in the restricted `exec()` environment
(`safe_api.py:141-158`):

| Builtin | Potential Abuse | Risk |
|---------|----------------|------|
| `True`, `False`, `None` | None | None |
| `len` | None | None |
| `range` | `range(10**18)` creates lazy iterator (not exhaustive) | None |
| `min`, `max`, `sum` | `sum(range(10**9))` is slow but bounded by timeout if enforced | Low |
| `print` | Output large data | Low (output truncation applies) |
| `str` | `str(obj)` — safe since no dangerous objects are in scope | None |
| `int` | `int("0" * 10**6)` — algorithmic complexity | Low |
| `float` | None | None |
| `bool` | None | None |
| `list` | `list(range(10**9))` — memory exhaustion | Medium (F-04) |
| `dict` | `dict.fromkeys(range(10**9))` — memory exhaustion | Medium (F-04) |

---

## 7. Shell Sanitizer Security

### Shell Construct Allow/Deny Matrix

| Construct | Status | Handler | Location |
|-----------|--------|---------|----------|
| Simple command (`cmd args`) | **Allowed** | `_compile_command()` | `shell_sanitizer.py:140` |
| Pipeline (`cmd1 \| cmd2`) | **Allowed** | `_compile_node()` pipeline branch | `shell_sanitizer.py:116-129` |
| Sequence `&&` | **Allowed** | `_compile_node()` list branch | `shell_sanitizer.py:102-114` |
| Sequence `;` | **Allowed** | `_compile_node()` list branch | `shell_sanitizer.py:102-114` |
| Output redirect `>` / `>>` | **Allowed** | `_compile_command()` with `ensure_under_root()` | `shell_sanitizer.py:150-160` |
| `python3 -c '<code>'` | **Intercepted** | Routed to `PythonStep` via `_compile_python_command()` | `shell_sanitizer.py:217-241` |
| `\|\|` operator | **Denied** | Explicit check in list operator | `shell_sanitizer.py:109-110` |
| Subshell `(...)` | **Denied** | bashlex node kind rejection | `shell_sanitizer.py:137` |
| Brace group `{ ...; }` | **Denied** | bashlex node kind rejection | `shell_sanitizer.py:137` |
| `for` / `while` / `if` / `case` | **Denied** | bashlex node kind rejection | `shell_sanitizer.py:137` |
| Function definition | **Denied** | bashlex node kind rejection | `shell_sanitizer.py:137` |
| Variable assignment `x=y` | **Denied** | Explicit check in command parts | `shell_sanitizer.py:162-163` |
| Input redirect `<` | **Denied** | Not in allowed redirect operators | `shell_sanitizer.py:152` |
| Stderr redirect `2>` | **Denied** | Not in allowed redirect operators | `shell_sanitizer.py:152` |
| Backgrounding `&` | **Denied** | Word content `&` check | `shell_sanitizer.py:182-184` |
| `python3 script.py` | **Denied** | Only `-c` allowed | `shell_sanitizer.py:230-233` |
| `python3 -m module` | **Denied** | Only `-c` allowed | `shell_sanitizer.py:230-233` |
| Bare `python3` | **Denied** | Interactive mode not allowed | `shell_sanitizer.py:226-227` |
| Piped Python | **Denied** | PythonStep in pipeline check | `shell_sanitizer.py:124-127` |

### Python-in-Shell Interception

When a shell command begins with `python` or `python3` (`shell_sanitizer.py:175`), the
sanitizer intercepts it **before** the command allowlist check. The code string is
extracted and stored as a `PythonStep`. At execution time, the executor runs it through
`sanitize_python_to_plan()` and executes via the restricted `exec()` path.

Only `python3 -c '<code>'` with exactly one code argument is accepted. All other
invocation forms (scripts, modules, interactive, extra arguments, piped input/output)
are denied.

### bashlex Dependency Risk

| Property | Value |
|----------|-------|
| Package | `bashlex>=0.18` |
| Purpose | Shell command AST parsing |
| Code size | ~3,000 LOC |
| Risk level | Medium — parser bugs could allow bypass of Layer 2 |
| Mitigation | 5 additional defense layers (1, 3, 4, 5, 6, 7) behind it |
| Recommendation | Pin exact version; monitor for CVEs |

The `_word_to_literal()` function performs a second-pass check on every word node
extracted from the bashlex AST, catching `$`, `` ` ``, `*`, and `?` even if bashlex
fails to detect them as expansions. Combined with `shell=False` execution, a bashlex
parsing bug would need to bypass all subsequent layers to cause harm.

### Glob Character Handling

`_word_to_literal()` (`shell_sanitizer.py:261-263`) denies `*` and `?` in shell
arguments. However, `_python_source_literal()` (`shell_sanitizer.py:268-286`)
intentionally allows them because they are valid Python operators (`*` for
multiplication, `**` for power, `?` unlikely but allowed for consistency). This split
is necessary for `python3 -c 'x = 2 * 3'` to work.

---

## 8. Filesystem Security

### Filesystem Operations and Validation

| Operation | Location | Validation | TOCTOU Risk |
|-----------|----------|------------|-------------|
| Shell redirect write (`>`) | `executor.py:204-211` via `shell_sanitizer.py:158` | `ensure_under_root()` at sanitize time | Yes |
| Shell redirect append (`>>`) | `executor.py:204-211` via `shell_sanitizer.py:158` | `ensure_under_root()` at sanitize time | Yes |
| `SafeAPI.mkdir()` | `safe_api.py:173-176` | `ensure_under_root()` at call time | Yes |
| `SafeAPI.write_text()` | `safe_api.py:178-183` | `ensure_under_root()` at call time | Yes |
| `SafeAPI.write_json()` | `safe_api.py:185-186` | Via `write_text()` | Yes |
| `SafeAPI.read_text()` | `safe_api.py:188-191` | `ensure_under_root()` at call time | Yes |
| Policy `exec_path` check | `policy_loader.py:49-76` | `realpath()` + exists + executable + allowed dir | No (load time only) |

### `ensure_under_root()` Implementation

```python
# fs_sandbox.py:10-22
root_real = os.path.realpath(root)
target = os.path.realpath(
    os.path.join(root_real, path) if not os.path.isabs(path) else path
)
if not (target == root_real or target.startswith(root_real + os.sep)):
    raise FsViolation(f"Path escapes workspace root: {path} -> {target}")
return target
```

**Strengths:**
- Resolves symlinks via `os.path.realpath()`
- Handles both relative and absolute paths
- Uses `root_real + os.sep` prefix check (avoids `/rootX` matching `/root`)

**TOCTOU Attack Scenario (F-01):**
1. Attacker (with concurrent filesystem access) creates a legitimate path
   `workspace/out/data.txt`
2. `ensure_under_root()` resolves and validates it
3. Between validation and the actual file operation, attacker replaces
   `workspace/out` with a symlink to `/etc`
4. The file operation follows the symlink and writes to `/etc/data.txt`

**Mitigation:** This requires the attacker to have concurrent filesystem access, which
should be prevented by OS-level mount namespace isolation. The code comment
(`fs_sandbox.py:13`) acknowledges this: "symlink races are not fully prevented at this
layer; OS sandbox should handle that."

---

## 9. Policy and Configuration Security

### Policy Validation Checks

| Check | Location | What It Validates | Failure Mode |
|-------|----------|-------------------|--------------|
| `policy_id` required | `policy_loader.py:257` | Meta section completeness | `PolicyLoadError` |
| `version` required | `policy_loader.py:257` | Meta section completeness | `PolicyLoadError` |
| Command ID format | `policy_loader.py:148-149` | `[a-zA-Z0-9_\-]+`, max 64 chars | `PolicyLoadError` |
| `exec_path` absolute | `policy_loader.py:54-55` | Starts with `/` | `PolicyLoadError` |
| `exec_path` exists | `policy_loader.py:59-60` | `os.path.isfile()` on resolved path | `PolicyLoadError` |
| `exec_path` executable | `policy_loader.py:62-63` | `os.access(X_OK)` | `PolicyLoadError` |
| `exec_path` in allowed dir | `policy_loader.py:66-76` | Prefix check against allowed dirs | `PolicyLoadError` |
| `timeout_s` range | `policy_loader.py:162-164` | 1 to 300 | `PolicyLoadError` |
| Arg kind valid | `policy_loader.py:116-117` | Must be `string`, `enum`, or `int` | `PolicyLoadError` |
| Regex pattern valid | `policy_loader.py:101-110` | Compiles; max 500 chars | `PolicyLoadError` |
| `max_len` cap | `policy_loader.py:124-125` | Max 10,000 | `PolicyLoadError` |
| Format string valid | `policy_loader.py:79-98` | Only expected field name; max 256 chars | `PolicyLoadError` |
| `arg_map` references valid args | `policy_loader.py:183-186` | Key exists in args dict | `PolicyLoadError` |
| HMAC signature | `policy_loader.py:206-222` | SHA-256 HMAC (optional) | `PolicyLoadError` |
| Merge override protection | `policy_loader.py:305-308` | Cannot override unless `allow_override=True` | `PolicyLoadError` |

### HMAC Analysis

- HMAC verification is **optional** — if `hmac_secret` is not passed to
  `load_policy_file()`, policy files are trusted implicitly
- The signature file is stored at `{file_path}.sig` alongside the policy file
- If an attacker can modify the policy file, they may also be able to modify the sig
  file (same directory)
- Uses `hmac.compare_digest()` for constant-time comparison (timing-safe)
- **Recommendation:** Store HMAC secret securely; ensure policy files and sig files are
  read-only in production

### Default Allowed Executable Directories

`policy_loader.py:33-39` defines the default exec path whitelist:

| Directory | Contents |
|-----------|----------|
| `/bin` | Core system binaries |
| `/usr/bin` | Standard user binaries |
| `/usr/local/bin` | Locally installed binaries |
| `/sbin` | System administration binaries |
| `/usr/sbin` | System administration binaries |

These can be overridden via `allowed_exec_dirs` parameter. Note that `/sbin` and
`/usr/sbin` include system administration tools — operators should consider whether
these are needed.

### Policy Limits

| Limit | Value | Location |
|-------|-------|----------|
| `MAX_TIMEOUT_S` | 300 seconds | `policy_loader.py:42` |
| `MAX_ARG_REGEX_LEN` | 500 characters | `policy_loader.py:43` |
| `MAX_ARG_MAX_LEN` | 10,000 characters | `policy_loader.py:44` |
| `MAX_COMMAND_ID_LEN` | 64 characters | `policy_loader.py:45` |
| `MAX_FORMAT_STRING_LEN` | 256 characters | `policy_loader.py:46` |
| `max_pipeline_steps` | 8 (default) | `policy.py:42` |

---

## 10. Output Security

### Redaction Rules

5 regex-based redaction rules are applied to all output
(`output_sanitize.py:8-30`):

| Rule | Pattern Description | Catches | Misses |
|------|-------------------|---------|--------|
| BEARER | `Bearer` followed by token characters | OAuth Bearer tokens | Non-standard bearer formats |
| BASIC | `Basic` followed by base64 | HTTP Basic auth headers | Non-standard basic auth |
| JWT | `eyJ` + 3 base64url segments (10+ chars each) | Standard JWTs | Non-eyJ tokens; opaque tokens |
| PRIVATE_KEY | `-----BEGIN *PRIVATE KEY-----` ... `-----END` | PEM private keys (RSA, ECDSA, etc.) | JSON/binary key formats |
| GENERIC_KV_TOKEN | `(token\|api[_-]?key)\s*[:=]\s*[value]{8+}` | Common `key=value` patterns | Custom names; short values (<8 chars) |

### Output Security Gaps

| Gap | Risk | Example |
|-----|------|---------|
| AWS access keys | Medium | `AKIA[0-9A-Z]{16}` not matched |
| Connection strings | Medium | `postgres://user:pass@host/db` not matched |
| Custom secret names | Medium | `my_password=abc123defgh` not matched |
| Short tokens (< 8 chars) | Low | `key=abc` not matched by GENERIC_KV_TOKEN |
| Binary secrets in output | Low | Non-text secrets in raw binary output |

### Other Output Controls

| Control | Implementation | Location |
|---------|---------------|----------|
| ANSI escape stripping | Regex removal of escape codes | `output_sanitize.py:6,45-46` |
| Truncation | 50,000 character default limit | `output_sanitize.py:72-74` |
| Bytes decoding | UTF-8 with `errors="replace"` | `output_sanitize.py:41` |
| Toggles | `strip_ansi` and `redact` can be disabled | `output_sanitize.py:37-38` |

---

## 11. Extension Security

### Extension Security Controls

| Control | Implementation | Location | Bypass Risk |
|---------|---------------|----------|-------------|
| Name validation | Must match `^[a-z_][a-z0-9_]*$` | `safe_api.py:111-114` | None |
| Reserved name protection | 20 names in `_RESERVED_NAMES` | `safe_api.py:19-23,115-116` | None |
| Duplicate prevention | Dict key check | `safe_api.py:117-118` | None |
| Callable check | `callable(fn)` | `safe_api.py:119-120` | None |
| Argument type checking | `isinstance()` per positional and keyword arg | `safe_api.py:46-58` | `bool` passes as `int` (F-08) |
| Exception sanitization | Catches non-`ApiViolation`; re-raises with type name only | `safe_api.py:60-68` | None |
| **Timeout enforcement** | **`timeout_s` stored but NEVER enforced** | `safe_api.py:36,42,61` | **Extension can block indefinitely (F-06)** |

### Finding: Unused `signal` Import and Unenforced Timeout

`safe_api.py:7` imports `signal` but never uses it. The `_RegisteredFunc` class stores
`timeout_s` (`safe_api.py:42`) and the docstring mentions timeout enforcement
(`safe_api.py:108`), but the actual `__call__` method (`safe_api.py:45-68`) runs the
function with no timeout wrapper:

```python
# safe_api.py:60-61 — no timeout around fn()
try:
    return self.fn(*args, **kwargs)
```

A registered extension function can block the executor indefinitely.

---

## 12. Dependency Analysis

### Runtime Dependencies

| Package | Version | Purpose | Security Risk | Mitigation |
|---------|---------|---------|---------------|------------|
| `bashlex` | `>=0.18` | Shell command AST parsing | Parser bugs could allow injection bypass | 6 defense layers behind it |

### Standard Library Usage

| Module | Purpose | Risk | Mitigation |
|--------|---------|------|------------|
| `ast` | Python AST parsing | CPython bugs in parser | Well-tested; standard library |
| `subprocess` | Process execution | `shell=True` misuse | Always `shell=False` |
| `urllib.request` | HTTP requests in `http_get()` | SSRF; header injection | HTTPS-only + host allowlist; urllib validates headers |
| `tomllib` | TOML policy parsing (3.11+) | Minimal attack surface | Read-only parser |
| `hmac` / `hashlib` | HMAC signature verification | None | Standard usage; `compare_digest` is timing-safe |
| `re` | Pattern matching for redaction and validation | ReDoS if adversary-controlled patterns | 500-char limit on policy regex; redaction patterns are hardcoded |

### Dev Dependencies

| Package | Version | Purpose | Production Risk |
|---------|---------|---------|-----------------|
| `pytest` | `>=8.0.0` | Test runner | None (dev only) |
| `ruff` | `>=0.4.0` | Linter | None (dev only) |

---

## 13. Test Coverage Assessment

### Test Distribution

| Test File | Tests | Module Covered | Assessment |
|-----------|-------|----------------|------------|
| `test_shell_sanitizer.py` | ~96 | `shell_sanitizer.py` | Thorough: allowed/denied constructs, Python interception, edge cases |
| `test_python_sanitizer.py` | ~89 | `python_sanitizer.py` | Thorough: all deny nodes, deny calls, escape attempts |
| `test_executor.py` | ~38 | `executor.py` | Good: shell/Python/inline execution, argument validation |
| `test_policy_loader.py` | ~39 | `policy_loader.py` | Good: load/reject/merge/HMAC validation |
| `test_safe_api.py` | ~33 | `safe_api.py` | Good: file ops, HTTP, registration, type checking |
| `test_output_sanitize.py` | ~18 | `output_sanitize.py` | Good: ANSI, redaction, truncation |
| `test_fs_sandbox.py` | ~13 | `fs_sandbox.py` | Good: traversal attacks, boundary checks |
| `test_audit.py` | ~6 | `audit.py` | Adequate: serialization, emission |
| `conftest.py` | 5 fixtures | Shared test infrastructure | N/A |

### Summary Statistics

| Metric | Value |
|--------|-------|
| Total tests | 251 |
| Test files | 9 |
| Test LOC | ~2,156 |
| Source LOC | ~1,607 |
| Test-to-code ratio | 1.3 : 1 |
| Attack vectors tested | 15 categories |
| Fuzzing coverage | None |
| Property-based testing | None |

### Missing Test Categories

| Category | Why It Matters | Priority |
|----------|---------------|----------|
| Concurrent execution | Race conditions in plan execution; shared state | High |
| Python `exec()` timeout | Infinite loops hang executor | High |
| Resource exhaustion | `list(range(10**9))` memory DoS | High |
| Fuzzing / property-based testing | Discover unknown parser edge cases | High |
| Symlink / TOCTOU | Filesystem race conditions | High |
| Environment variable isolation | Env leakage to child processes | Medium |
| Pipeline timeout edge cases | Timeout in middle of multi-step pipeline | Medium |
| SSRF via `http_get()` | Internal network scanning when no host allowlist | Medium |
| Unicode / encoding bypass | Policy bypass via homographs, RTL override, normalization | Medium |
| Extension timeout enforcement | Extension blocking indefinitely | Medium |
| Large / complex policy files | Performance DoS at load time | Low |

---

## 14. Known Limitations and Residual Risks

| ID | Limitation | Severity | Impact | Recommended Remediation | Effort |
|----|-----------|----------|--------|------------------------|--------|
| L-01 | TOCTOU in `ensure_under_root()` (F-01, A-21) | High | Symlink race allows workspace escape | Use `openat()` with `O_NOFOLLOW` or rely on OS mount namespace | Medium |
| L-02 | No OS process isolation (F-02) | Critical* | Full host compromise if validation bypassed | Deploy with Fargate / microVM / gVisor | High (infra) |
| L-03 | Child processes inherit environment (F-03, A-22) | Medium | Secrets in env vars leak to commands | Pass `env={}` or filtered env dict to `Popen()` | Low |
| L-04 | No CPU/memory limits on `exec()` (F-04, A-29) | Medium | Memory exhaustion via `list(range(10**9))` | Use `resource.setrlimit()` or OS cgroups | Medium |
| L-05 | Python `exec()` has no timeout (F-05, A-28) | Medium | Infinite loop hangs executor | Use `signal.alarm()` or `threading.Timer` | Low |
| L-06 | Extension `timeout_s` not enforced (F-06, A-35) | Medium | Extension function blocks indefinitely | Implement timeout using `signal` or threading | Low |
| L-07 | ReDoS in user-supplied regex (F-07, A-27) | Low | CPU hang during policy argument validation | Add regex compilation timeout or use `re2` | Medium |
| L-08 | `bool` passes `int` type check (F-08, A-32) | Low | `True`/`False` accepted where `int` expected | Document or add explicit `bool` exclusion | Low |
| L-09 | Secret redaction not exhaustive (F-09, A-23) | Low | Some secret formats not caught | Add AWS credential, connection string patterns | Low |
| L-10 | HMAC verification is optional | Medium | Policy tampering if HMAC not enabled | Make HMAC required or warn loudly on load | Low |
| L-11 | No CI/CD pipeline (F-10) | Medium | Regressions not caught automatically | Add GitHub Actions with test + lint + type check | Low |
| L-12 | No code coverage metrics | Low | Unknown coverage gaps | Add `pytest-cov` and enforce threshold | Low |
| L-13 | Audit sink has no integrity protection (A-34) | Low | Audit events can be modified/deleted | Use append-only store; SIEM integration | Medium |
| L-14 | `start_new_session` not set on `Popen()` | Low | Child process shares process group with parent | Add `start_new_session=True` to `Popen()` | Low |
| L-15 | No rate limiting on plan execution | Medium | Resource exhaustion via rapid execution | Add rate limiting at caller layer | Medium |
| L-16 | `/sbin` and `/usr/sbin` in default exec dirs | Low | System admin tools allowed by default | Remove or require explicit opt-in | Low |

*L-02 is Critical in isolation but is by-design when paired with OS sandbox.

---

## 15. Deployment Requirements

### Mandatory Requirements

Without these, the library's security posture is insufficient for production use
with untrusted input.

| ID | Requirement | Why | Consequence if Missing |
|----|------------|-----|----------------------|
| D-01 | OS-level sandbox (Fargate / microVM / gVisor) | Library is NOT a sandbox; validation can have bugs | Full host compromise if any validation layer is bypassed |
| D-02 | Network egress filtering (firewall / proxy) | `http_get()` only filters at application level; child processes have no network restriction | SSRF, data exfiltration via child processes |
| D-03 | Filesystem mount isolation (namespace / chroot) | TOCTOU gap in `ensure_under_root()` | Workspace escape via symlink race |
| D-04 | CPU / memory cgroups | No resource limits in library | Denial of service via resource exhaustion |
| D-05 | Read-only policy file storage | HMAC is optional | Policy tampering gives attacker arbitrary command access |
| D-06 | Filtered environment variables | Library passes full parent env to child processes | Secret leakage to child processes |
| D-07 | Append-only audit log storage | Default sink prints to stdout with no integrity protection | Audit log tampering; non-repudiation failure |
| D-08 | HMAC secret management (if using HMAC) | HMAC sig file stored alongside policy | Both files modifiable if attacker gains write access to dir |

### Recommended (Non-Mandatory) Steps

| ID | Recommendation | Benefit |
|----|---------------|---------|
| R-01 | Enable HMAC policy verification | Detects policy tampering |
| R-02 | Configure `http_allow_hosts` for `http_get()` | Limits SSRF attack surface |
| R-03 | Set restrictive `max_pipeline_steps` | Limits execution complexity |
| R-04 | Audit all registered extension functions | Extensions bypass AST validator — they run arbitrary host code |
| R-05 | Monitor audit events for anomalies | Detect abuse patterns early |
| R-06 | Pin `bashlex` version exactly in lock file | Prevent supply chain changes |
| R-07 | Run with minimal OS user privileges | Limit blast radius |

---

## 16. Recommendations

### Prioritized Recommendations

| Priority | Recommendation | Addresses | Effort | Impact |
|----------|---------------|-----------|--------|--------|
| **P1** | Pass `env={}` or filtered env to `Popen()` | L-03, A-22 | Low | Medium |
| **P1** | Implement `exec()` timeout (`signal.alarm` or threading) | L-05, A-28 | Low | Medium |
| **P1** | Enforce `timeout_s` on registered extensions (unused `signal` import exists) | L-06, A-35 | Low | Medium |
| **P1** | Add CI/CD pipeline (GitHub Actions: test + lint) | L-11 | Low | High |
| **P2** | Add `start_new_session=True` to `Popen()` | L-14 | Low | Low |
| **P2** | Add resource limits to `exec()` (`resource.setrlimit`) | L-04, A-29 | Medium | Medium |
| **P2** | Add concurrent execution tests | Missing test category | Medium | Medium |
| **P2** | Add fuzzing with `hypothesis` for shell/Python parsers | Missing test category | Medium | High |
| **P3** | Consider `openat()` with `O_NOFOLLOW` for TOCTOU hardening | L-01, A-21 | Medium | Medium |
| **P3** | Add AWS credential and connection string redaction patterns | L-09, A-23 | Low | Low |
| **P3** | Make HMAC verification mandatory or warn loudly when disabled | L-10 | Low | Low |
| **P3** | Add `pytest-cov` and enforce coverage threshold | L-12 | Low | Low |
