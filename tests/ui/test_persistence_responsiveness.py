"""Controlled freeze reproductions; no claim about the historical live cause.

Filesystem latency is held independently of the UI loop. Responsiveness and
integrity are both required; these production boundaries no longer use XFAIL.
"""
from dataclasses import dataclass, asdict
import asyncio
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
from typing import Any

import pytest
from textual import events

from src.findings import store as finding_module
from src.findings.store import Store as FindingStore, read_report
from src.llm.core.types import Message
from src.permission.permission import AlwaysAllow
from src.session.store import Store as SessionStore
from src.tools.execution.file import FileWriteTool
from src.ui.core.app import KAgent
from src.workflow.evidence.artifacts import EvidenceArtifact
from src.workflow.evidence import artifacts as evidence_module
from tests.data.test_findings_store import make_finding
from tests.tools.test_finding import _tool, _valid_args
from tests.ui.test_overview import _make_app

DELAY = 0.40
HEARTBEAT = 0.02
RESPONSIVE_LIMIT_MS = 120.0
BOUNDARIES = ("file_write", "session_save", "evidence_snapshot", "finding_post_read", "summary_fsync")


class ResponsivenessFailure(AssertionError):
    """A measured heartbeat or input responsiveness failure."""


@dataclass
class Measurement:
    boundary: str
    control: bool
    operation_ms: float
    heartbeat_gap_ms: float
    heartbeat_ticks: int
    esc_delivery_ms: float
    cancellation_requested_ms: float
    cancellation_completed_ms: float
    recovery_ticks: int
    io_on_ui_thread: bool | None


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    violations = []
    def deny(*args, **kwargs):
        violations.append("network")
        raise AssertionError("network forbidden in persistence reproductions")
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket.socket, "connect_ex", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    # Suppress startup ping, snapshots and integrations, not key handling/rendering.
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    yield
    assert not violations, "offline violation was swallowed by runtime"


@pytest.fixture
def scratch():
    with tempfile.TemporaryDirectory(prefix="tui-persistence-repro-", dir="/tmp") as directory:
        yield Path(directory)


async def measure(boundary: str, control: bool, root: Path, monkeypatch) -> Measurement:
    app: Any = _make_app()
    beats: list[float] = []
    stamps: dict[str, float] = {}
    io_threads: list[int] = []
    entered = threading.Event()
    release = threading.Event()
    stop = threading.Event()
    held_ms: list[float] = []
    errors: list[str] = []
    source = root / "proof.md"
    source.write_text("synthetic proof\n", encoding="utf-8")
    store = FindingStore(project_directory=root)
    tool: Any = None
    if boundary == "summary_fsync":
        tool, store = _tool(root)
        await tool.run(_valid_args(tool), None, AlwaysAllow())
    artifact: EvidenceArtifact | None = None
    path: str | None = None
    original_key = app._process_key

    async def key(event):
        await original_key(event)
        if event.key == "escape":
            assert app.run_abort_event is not None and app.run_abort_event.is_set()
            stamps["cancel_requested"] = time.monotonic()

    app._process_key = key

    def slow(fn, *args, **kwargs):
        io_threads.append(threading.get_ident())
        started = time.monotonic()
        entered.set()
        # Independent thread bounds the hold even while the loop is blocked.
        if not release.wait(2):
            raise TimeoutError("test controller did not release filesystem boundary")
        held_ms.append((time.monotonic() - started) * 1000)
        return fn(*args, **kwargs)

    async def operation(signal):
        nonlocal artifact, path
        with monkeypatch.context() as patcher:
            if boundary == "file_write":
                original = Path.write_text
                destination = root / "output.md"
                if not control:
                    patcher.setattr(Path, "write_text", lambda p, *a, **k:
                                    slow(original, p, *a, **k) if p == destination else original(p, *a, **k))
                await FileWriteTool().run({"path": str(destination), "content": "synthetic"}, signal, AlwaysAllow())
                assert destination.read_text() == "synthetic"
            elif boundary == "session_save":
                original = os.fsync
                if not control:
                    patcher.setattr(os, "fsync", lambda fd: slow(original, fd))
                await SessionStore(root / "session.json").save([Message("user", "synthetic")])
                assert json.loads((root / "session.json").read_text())["messages"][0]["content"] == "synthetic"
                assert not list(root.glob("session.json.tmp.*"))
            elif boundary == "evidence_snapshot":
                original = evidence_module._read_captured_value
                if not control:
                    patcher.setattr(evidence_module, "_read_captured_value", lambda p, *a, **k:
                                    slow(original, p, *a, **k) if p == source else original(p, *a, **k))
                artifact = await EvidenceArtifact.capture_immutable_snapshot_async("cand_synthetic", str(source), root)
                snapshot = (root / artifact.path).read_bytes()
                assert hashlib.sha256(snapshot).hexdigest() == artifact.sha256
                assert artifact.size == len(snapshot) and snapshot == b"synthetic proof\n"
            elif boundary in {"finding_post_read", "finding_worker"}:
                if boundary == "finding_worker":
                    original_write = store._write_once_for_candidate
                    patcher.setattr(store, "_write_once_for_candidate", lambda *a: slow(original_write, *a))
                elif not control:
                    original_read = finding_module.read_report
                    patcher.setattr(finding_module, "read_report", lambda p: slow(original_read, p))
                finding = make_finding()
                path = await store.save(finding)
                # Use imported unpatched reader for independent integrity checks.
                assert read_report(Path(path)) == finding
                assert len(list(store.dir.glob("*.md"))) == 1
            elif boundary == "summary_fsync":
                assert tool is not None
                cid = next(iter(tool.workflow.candidates))
                canonical = store.report_for_candidate(cid)
                before = canonical.read_bytes()
                original = finding_module._fsync_directory
                if not control:
                    patcher.setattr(finding_module, "_fsync_directory", lambda directory: slow(original, directory))
                path = await tool.write_summary(cid)
                assert path and Path(path).read_text()
                assert canonical.read_bytes() == before
                assert not list(Path(path).parent.glob("*.tmp*"))
            else:
                raise AssertionError(boundary)
        if control and boundary != "finding_worker":
            # Complete the normal operation before the cancellable async wait:
            # file_write correctly rejects a signal already cancelled at its gate.
            entered.set()
            await asyncio.sleep(DELAY)

    async def fake_run(value, signal, emit, opts):
        assert asyncio.get_running_loop() is loop
        stamps["start"] = time.monotonic()
        await operation(signal)
        stamps["operation_end"] = time.monotonic()
        # Acknowledge cooperative cancellation separately from I/O completion.
        await asyncio.wait_for(signal.wait(), 2)
        stamps["cancel_complete"] = time.monotonic()

    app.agent.run = fake_run
    async with app.run_test(size=(80, 24)):
        loop = asyncio.get_running_loop()
        ui_thread = threading.get_ident()
        app.set_interval(HEARTBEAT, lambda: beats.append(time.monotonic()))
        await asyncio.sleep(0.08)

        def controller():
            if not entered.wait(2):
                errors.append("operation did not enter measured boundary")
                release.set()
                return
            started = time.monotonic()
            if stop.wait(0.05):
                release.set()
                return
            stamps["esc_sent"] = time.monotonic()
            loop.call_soon_threadsafe(app.post_message, events.Key("escape", None))
            stop.wait(max(0, DELAY - (time.monotonic() - started)))
            release.set()

        sender = threading.Thread(target=controller, daemon=True)
        sender.start()
        try:
            await asyncio.wait_for(app.run_agent_turn("offline reproduction"), 3)
            await asyncio.sleep(0.08)
        finally:
            stop.set()
            release.set()
            await asyncio.to_thread(sender.join, 2)
        assert not sender.is_alive() and not errors
    assert all(key in stamps for key in ("start", "operation_end", "esc_sent", "cancel_requested", "cancel_complete"))
    if not control or boundary == "finding_worker":
        assert len(held_ms) == 1 and held_ms[0] >= DELAY * 900
    assert len(beats) >= 4
    result = Measurement(boundary, control,
        (stamps["operation_end"] - stamps["start"]) * 1000,
        max(b - a for a, b in zip(beats, beats[1:])) * 1000,
        sum(stamps["start"] < b < stamps["operation_end"] for b in beats),
        (stamps["cancel_requested"] - stamps["esc_sent"]) * 1000,
        (stamps["cancel_requested"] - stamps["start"]) * 1000,
        (stamps["cancel_complete"] - stamps["start"]) * 1000,
        sum(b > stamps["cancel_complete"] for b in beats),
        all(t == ui_thread for t in io_threads) if io_threads else None)
    assert result.operation_ms >= DELAY * 900
    print("PERSISTENCE_MEASUREMENT " + json.dumps(asdict(result), sort_keys=True))
    print("PERSISTENCE_TIMELINE " + json.dumps({"stamps": stamps, "beats": beats}, sort_keys=True))
    assert result.recovery_ticks >= 2  # UI resumed, not a permanently stalled harness.
    return result


def assert_responsive(result: Measurement):
    if (result.heartbeat_gap_ms >= RESPONSIVE_LIMIT_MS or result.esc_delivery_ms >= RESPONSIVE_LIMIT_MS
            or result.heartbeat_ticks < 3):
        raise ResponsivenessFailure(json.dumps(asdict(result), sort_keys=True))


@pytest.mark.parametrize("boundary", BOUNDARIES)
async def test_production_boundary_keeps_textual_responsive(boundary, scratch, monkeypatch):
    assert_responsive(await measure(boundary, False, scratch, monkeypatch))


@pytest.mark.parametrize("boundary", BOUNDARIES)
async def test_async_wait_control_keeps_textual_responsive(boundary, scratch, monkeypatch):
    assert_responsive(await measure(boundary, True, scratch, monkeypatch))


async def test_existing_canonical_finding_worker_keeps_textual_responsive(scratch, monkeypatch):
    result = await measure("finding_worker", True, scratch, monkeypatch)
    assert result.io_on_ui_thread is False
    assert_responsive(result)
