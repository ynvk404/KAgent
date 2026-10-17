"""Opt-in diagnostics: pytest -p tests.system.probe --system-probe=full.

Only diagnostic runs may disable a test instrumentation layer. These runs do
not count as correctness verification; the normal tests remain authoritative.
No production permission, redaction, persistence or transport is replaced.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, is_dataclass
import gc
import json
import os
from pathlib import Path
import sys
import threading
import time

import pytest


def pytest_addoption(parser):
    parser.addoption("--system-probe", choices=("full", "no-trace-redaction", "no-oracle", "no-trace"))
    parser.addoption("--system-probe-repeats", type=int, default=1)
    parser.addoption("--system-probe-sampling", action="store_true")
    parser.addoption("--system-probe-inline-trace", action="store_true")


@pytest.fixture(autouse=True)
def _probe_repeat():
    pass


def pytest_generate_tests(metafunc):
    if metafunc.function.__name__ == "test_production_boundary_keeps_textual_responsive":
        metafunc.parametrize("_probe_repeat", range(metafunc.config.getoption("--system-probe-repeats")))


@pytest.fixture(autouse=True)
async def system_probe(request, monkeypatch, tmp_path, record_property):
    mode = request.config.getoption("--system-probe")
    if not mode:
        yield
        return
    from tests.helpers import scenario_oracle as oracle
    from tests.helpers.agent_fakes import ScriptedModel
    from src.agent import agent as agent_module
    from src.findings.store import Store as FindingStore
    from src.session.store import Store as SessionStore
    from src.tools.common.registry import Registry
    from src.tools.http.http_tool import HTTPTool
    from src.tools.workflow.workflow_tool import WorkflowTool
    from src.ui.core.app import KAgent

    spans = []
    callbacks = []
    samples = []
    collections = []
    gc_started = {}
    ui_thread = threading.get_ident()
    stop = threading.Event()
    start = time.monotonic()
    initial_tasks = asyncio.all_tasks()
    if request.config.getoption("--system-probe-inline-trace"):
        original_init = oracle.TraceRecorder.__init__
        def inline_init(self, *args, **kwargs):
            kwargs["defer_redaction"] = False
            original_init(self, *args, **kwargs)
        monkeypatch.setattr(oracle.TraceRecorder, "__init__", inline_init)

    def stack_sampler():
        while not stop.wait(0.005):
            frame = sys._current_frames().get(ui_thread)
            stack = []
            while frame is not None and len(stack) < 12:
                stack.append(f"{frame.f_code.co_filename}:{frame.f_lineno}:{frame.f_code.co_name}")
                frame = frame.f_back
            samples.append((time.monotonic() - start, stack))

    def gc_callback(phase, info):
        key = (threading.get_ident(), info["generation"])
        if phase == "start":
            gc_started[key] = time.monotonic()
        elif key in gc_started:
            began = gc_started.pop(key)
            collections.append((began - start, time.monotonic() - began, key))

    def timed(obj, name, label):
        original = getattr(obj, name)
        def call(*args, **kwargs):
            began, cpu = time.monotonic(), time.thread_time()
            try:
                return original(*args, **kwargs)
            finally:
                spans.append((label, began - start, time.monotonic() - began,
                              time.thread_time() - cpu, threading.get_ident() == ui_thread))
        monkeypatch.setattr(obj, name, call)

    def timed_async(obj, name, label):
        original = getattr(obj, name)
        async def call(*args, **kwargs):
            began = time.monotonic()
            try:
                return await original(*args, **kwargs)
            finally:
                spans.append((label, began - start, time.monotonic() - began, 0, True))
        monkeypatch.setattr(obj, name, call)

    if mode in {"no-oracle", "no-trace"}:
        monkeypatch.setattr(oracle.InvariantOracle, "boundary", lambda *a, **kw: None)
        async def no_outcomes(*args, **kwargs):
            pass
        monkeypatch.setattr(oracle.InvariantOracle, "outcomes", no_outcomes)
        monkeypatch.setattr(oracle.InvariantOracle, "persisted", no_outcomes)
    if mode == "no-trace":
        def raw_record(self, event):
            if is_dataclass(event) and not isinstance(event, type):
                captured = asdict(event)
            elif isinstance(event, dict):
                captured = dict(event)
            else:
                raise TypeError("diagnostic event must be a dict or dataclass instance")
            self.events.append(captured)
        monkeypatch.setattr(oracle.TraceRecorder, "record", raw_record)
    elif mode == "no-trace-redaction":
        monkeypatch.setattr(oracle, "redact_payload", lambda value: value)
        monkeypatch.setattr(oracle, "apply_evidence", lambda value: value)

    timed(oracle.TraceRecorder, "record", "harness.trace")
    timed(oracle.InvariantOracle, "boundary", "harness.oracle")
    timed(oracle, "redact_payload", "harness.redact_payload")
    timed(oracle, "apply_evidence", "harness.apply_evidence")
    timed(KAgent, "dispatch", "ui.dispatch")
    timed(KAgent, "_recompute_view", "ui.render_view")
    timed(agent_module, "safe_tool_text", "runtime.safe_tool_text")
    timed_async(Registry, "execute", "runtime.registry_wall")
    timed_async(HTTPTool, "run", "runtime.http_wall")
    timed_async(WorkflowTool, "run", "runtime.workflow_wall")
    timed_async(ScriptedModel, "chat", "model.fake_wall")
    timed_async(SessionStore, "save", "persistence.session_wall")
    timed_async(FindingStore, "save", "persistence.finding_wall")
    timed(Path, "write_text", "filesystem.write_text")
    timed(os, "fsync", "filesystem.fsync")
    original_submit = ThreadPoolExecutor.submit
    def submit(executor, function, *args, **kwargs):
        queued = time.monotonic()
        def work():
            began = time.monotonic()
            spans.append(("executor.queue", queued - start, began - queued, 0, False))
            return function(*args, **kwargs)
        return original_submit(executor, work)
    monkeypatch.setattr(ThreadPoolExecutor, "submit", submit)
    original_key = KAgent._process_key
    async def key(self, event):
        began = time.monotonic()
        try:
            return await original_key(self, event)
        finally:
            spans.append(("ui.key", began - start, time.monotonic() - began, 0, True))
    monkeypatch.setattr(KAgent, "_process_key", key)

    original_run = asyncio.Handle._run
    def handle_run(handle):
        began, cpu = time.monotonic(), time.thread_time()
        try:
            return original_run(handle)
        finally:
            elapsed = time.monotonic() - began
            if elapsed >= 0.020:
                callback = handle._callback
                owner = getattr(callback, "__self__", None)
                if isinstance(owner, asyncio.Task):
                    coro = owner.get_coro()
                    code = getattr(coro, "cr_code", None)
                    label = code.co_qualname if code is not None else type(coro).__name__
                else:
                    label = getattr(callback, "__qualname__", type(callback).__name__)
                callbacks.append((label, began - start, elapsed, time.thread_time() - cpu))
    monkeypatch.setattr(asyncio.Handle, "_run", handle_run)
    gc.callbacks.append(gc_callback)
    sampler = threading.Thread(target=stack_sampler, name="system-probe-sampler", daemon=True)
    sampling = request.config.getoption("--system-probe-sampling")
    if sampling:
        sampler.start()
    try:
        yield
    finally:
        stop.set()
        if sampling:
            sampler.join(timeout=1)
        gc.callbacks.remove(gc_callback)
        assert not sampler.is_alive()
        groups = {}
        for label, began, elapsed, cpu, on_ui in spans:
            key = label + (".loop" if on_ui else ".worker")
            row = groups.setdefault(key, {"count": 0, "total_ms": 0.0, "max_ms": 0.0, "cpu_ms": 0.0})
            row["count"] += 1
            row["total_ms"] += elapsed * 1000
            row["max_ms"] = max(row["max_ms"], elapsed * 1000)
            row["cpu_ms"] += cpu * 1000
        hottest = Counter(stack[0] for _, stack in samples if stack)
        summary = {"mode": mode, "started_at": start, "spans": groups,
                   "slow_callbacks": sorted(callbacks, key=lambda row: row[2], reverse=True)[:12],
                   "longest_gc": sorted(collections, key=lambda row: row[1], reverse=True)[:5],
                   "sample_tops": hottest.most_common(12),
                   "remaining_tasks": [t.get_name() for t in asyncio.all_tasks() - initial_tasks
                                       if t is not asyncio.current_task() and not t.done()]}
        (tmp_path / "probe.json").write_text(json.dumps({**summary, "timeline": spans,
            "callbacks": callbacks, "samples": samples, "gc": collections}, indent=2))
        record_property("probe", json.dumps(summary))
        print("SYSTEM_PROBE " + json.dumps(summary))
