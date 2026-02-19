from __future__ import annotations

import json

from restricted_exec.audit import AuditEvent, AuditSink, now


class TestAuditEvent:
    def test_to_json_valid(self):
        ev = AuditEvent(
            ts=1234567890.0,
            event="test_event",
            request_id="req-1",
            actor={"type": "test", "id": "t-1"},
            details={"key": "value"},
        )
        j = ev.to_json()
        parsed = json.loads(j)
        assert parsed["event"] == "test_event"
        assert parsed["request_id"] == "req-1"
        assert parsed["actor"]["type"] == "test"
        assert parsed["details"]["key"] == "value"
        assert parsed["ts"] == 1234567890.0

    def test_to_json_sorted_keys(self):
        ev = AuditEvent(
            ts=0, event="e", request_id="r", actor={}, details={}
        )
        j = ev.to_json()
        parsed = json.loads(j)
        keys = list(parsed.keys())
        assert keys == sorted(keys)

    def test_to_json_nested_details(self):
        ev = AuditEvent(
            ts=0,
            event="e",
            request_id="r",
            actor={},
            details={"nested": {"a": 1, "b": [2, 3]}},
        )
        parsed = json.loads(ev.to_json())
        assert parsed["details"]["nested"]["a"] == 1
        assert parsed["details"]["nested"]["b"] == [2, 3]


class TestAuditSink:
    def test_emit_prints(self, capsys):
        sink = AuditSink()
        ev = AuditEvent(
            ts=0, event="test", request_id="r", actor={}, details={}
        )
        sink.emit(ev)
        captured = capsys.readouterr()
        assert '"event": "test"' in captured.out


class TestNow:
    def test_returns_float(self):
        t = now()
        assert isinstance(t, float)
        assert t > 0

    def test_monotonic_ish(self):
        t1 = now()
        t2 = now()
        assert t2 >= t1
