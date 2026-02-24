from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple, Union

ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

REDACTION_RULES: List[Tuple[str, re.Pattern]] = [
    ("BEARER", re.compile(r"\bBearer\s+[A-Za-z0-9\-\._~\+\/]+=*\b")),
    ("BASIC", re.compile(r"\bBasic\s+[A-Za-z0-9\+\/]+=*\b")),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    (
        "GENERIC_KV_TOKEN",
        re.compile(r"\b(token|api[_-]?key)\b\s*[:=]\s*([^\s'\"\\]{8,})", re.IGNORECASE),
    ),
]


def sanitize_output(
    raw: Union[str, bytes],
    *,
    max_chars: int = 50_000,
    strip_ansi: bool = True,
    redact: bool = True,
) -> Dict[str, Any]:
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = raw

    if strip_ansi:
        text = ANSI_ESCAPE_RE.sub("", text)

    redactions: List[Dict[str, Any]] = []
    if redact:
        for name, pat in REDACTION_RULES:
            matches = list(pat.finditer(text))
            if not matches:
                continue

            def _make_repl(rule_name: str):
                def repl(m: re.Match) -> str:
                    if m.lastindex:
                        s = m.group(0)
                        for gi in range(1, m.lastindex + 1):
                            g = m.group(gi)
                            if g:
                                s = s.replace(g, "[REDACTED]")
                        return s
                    return "[REDACTED]"

                return repl

            text = pat.sub(_make_repl(name), text)
            redactions.append({"rule": name, "count": len(matches)})

    truncated = False
    if len(text) > max_chars:
        text = text[:max_chars] + "\n...[TRUNCATED]..."
        truncated = True

    return {"text": text, "truncated": truncated, "redactions": redactions}
