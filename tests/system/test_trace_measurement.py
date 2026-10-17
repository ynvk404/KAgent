"""Trace checkpoints stay synchronous; export work cannot mask loop stalls."""
from __future__ import annotations

import asyncio
import time
from typing import Any, cast

import pytest

from tests.helpers import scenario_oracle
from tests.helpers.scenario_oracle import TraceRecorder
from tests.helpers.system_runtime import heartbeat


class Checkpoints:
    def __init__(self):
        self.labels = []
        self.boundaries = []

    def boundary(self, runtime, label):
        self.labels.append(label)


def test_deferred_trace_preserves_event_and_transition_before_sanitized_export(tmp_path, monkeypatch):
    oracle = Checkpoints()
    trace = TraceRecorder(None, cast(Any, oracle), defer_redaction=True)
    redactions = []
    original = scenario_oracle.redact_payload
    def redact(value):
        redactions.append(True)
        return original(value)
    monkeypatch.setattr(scenario_oracle, "redact_payload", redact)
    event: dict[str, Any] = {"type": "tool-call", "id": "one", "args": {
        "action": "record_candidate", "nested": ["before"]}}
    trace.record(event)
    event["args"]["nested"].append("after")
    trace.record({"type": "tool-result", "id": "one", "name": "workflow",
                  "result": "Authorization: Bearer fixture-secret-token\nCookie: session=fixture-cookie"})
    assert oracle.labels == ["record_candidate"]
    assert trace.events[0]["args"]["nested"] == ["before"]
    assert not redactions and not trace.errors
    reference = TraceRecorder(None, cast(Any, Checkpoints()))
    for captured in trace.events:
        reference.record(captured)
    path = tmp_path / "trace.json"
    trace.write(path)
    reference_path = tmp_path / "reference.json"
    reference.write(reference_path)
    assert redactions
    saved = path.read_text()
    assert "fixture-secret-token" not in saved and "fixture-cookie" not in saved
    assert saved == reference_path.read_text()
    count = len(redactions)
    trace.sanitize_pending()
    assert len(redactions) == count


def test_deferred_trace_does_not_swallow_checkpoint_failure_or_export_raw_secrets(tmp_path, monkeypatch):
    oracle = Checkpoints()
    def fail(*args):
        raise AssertionError("checkpoint violation")
    monkeypatch.setattr(oracle, "boundary", fail)
    trace = TraceRecorder(None, cast(Any, oracle), defer_redaction=True)
    trace.record({"type": "tool-result", "id": "one", "name": "workflow", "result": "password=fixture-secret"})
    assert trace.errors == ["checkpoint violation"]
    def bad_redactor(value):
        raise ValueError("sanitizer unavailable")
    monkeypatch.setattr(scenario_oracle, "redact_payload", bad_redactor)
    path = tmp_path / "trace.json"
    with pytest.raises(ValueError, match="sanitizer unavailable"):
        trace.write(path)
    assert not path.exists()


async def test_heartbeat_still_detects_blocking_callback_with_deferred_trace():
    trace = TraceRecorder(None, cast(Any, Checkpoints()), defer_redaction=True)
    metrics = {}
    async with heartbeat(metrics):
        await asyncio.sleep(0.02)
        trace.record({"type": "diagnostic", "text": "synthetic"})
        # Positive control: deliberately block the measured callback. This is
        # not a wait inserted into a production scenario to obtain a pass.
        time.sleep(0.16)
        await asyncio.sleep(0.02)
    assert metrics["heartbeat_ticks"] >= 2
    assert metrics["heartbeat_gap_ms"] >= 120
