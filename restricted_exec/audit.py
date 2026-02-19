from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict
import json
import time


@dataclass
class AuditEvent:
    ts: float
    event: str
    request_id: str
    actor: Dict[str, Any]
    details: Dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(
            {
                "ts": self.ts,
                "event": self.event,
                "request_id": self.request_id,
                "actor": self.actor,
                "details": self.details,
            },
            sort_keys=True,
        )


class AuditSink:
    """
    Replace with CloudWatch, SIEM, append-only store, etc.
    """

    def emit(self, ev: AuditEvent) -> None:
        print(ev.to_json())


def now() -> float:
    return time.time()
