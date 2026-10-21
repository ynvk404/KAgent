"""Mounted real Agent/TUI lifecycle; providers and MCP peers are deterministic."""
from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import patch

import pytest
from textual import events

from src.llm.core.client import StreamingClient
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.llm.transport.errors import ProviderControlError
from src.ui.core import app as app_module
from src.workflow.evidence import artifacts as evidence_module
from tests.helpers.agent_fakes import FakeClient
from tests.helpers.system_runtime import assert_idle, drain, heartbeat, make_system_app, wait_until
from tests.system.test_local_boundaries import runtime_for


def tool_response(name, args):
    return ChatResponse(Message("assistant", "", tool_calls=[ToolCall("offline-call", FunctionCall(name, args))]), "tool_calls")


@pytest.mark.parametrize("fault", ["timeout", "rate_limit", "exception", "malformed_call", "invalid_schema", "text_only", "entry_exception"])
async def test_provider_failures_cleanup_real_ui(tmp_path, monkeypatch, local_lab, fault, record_property):
    class Failing(FakeClient):
        async def chat(self, request, signal=None):
            self.requests.append(request)
            if fault == "timeout":
                raise TimeoutError("offline provider timeout")
            if fault == "rate_limit":
                raise ProviderControlError("rate-limited", "offline rate limit", 429)
            if fault == "exception":
                raise RuntimeError("offline provider exception")
            if len(self.requests) == 1 and request.tools:
                if fault == "malformed_call":
                    return tool_response("http", "{invalid-json")
                if fault == "invalid_schema":
                    return tool_response("http", json.dumps({"url": ["/public"]}))
            return ChatResponse(Message("assistant", "No HTTP observation collected."), "stop")

    rt = runtime_for(tmp_path, local_lab)
    rt.agent.set_client(Failing([]))
    app = make_system_app(rt)
    metrics = {}
    if fault == "entry_exception":
        original = app._sync_status_bar
        def fail_before_agent():
            if app.state.busy:
                raise RuntimeError("offline UI entry failure")
            return original()
        monkeypatch.setattr(app, "_sync_status_bar", fail_before_agent)
    async with app.run_test(size=(70, 24)) as pilot:
        try:
            async with heartbeat(metrics):
                app.submit("Explain the available local lab tools without sending a request.")
                task = app.run_task
                assert task is not None
                if fault == "entry_exception":
                    with pytest.raises(RuntimeError, match="offline UI entry failure"):
                        await asyncio.wait_for(task, 10)
                else:
                    await asyncio.wait_for(task, 10)
            assert_idle(app)
            assert not local_lab.wire and not rt.policy.observations._items
            assert not rt.workflow.persisted_findings and not rt.workflow.candidates
            assert not rt.bridge._busy and not rt.bridge._waiters
            if fault in {"timeout", "rate_limit", "exception", "entry_exception"}:
                assert any(entry.kind == "error" for entry in app.state.transcript)
            await pilot.press("x")
            assert app.input.value.endswith("x")
            record_property("fault_case", json.dumps({"pre": "idle", "injected": fault,
                "expected": "idle, no HTTP/finding, usable input", "post": metrics}))
        finally:
            await drain(rt)


@pytest.mark.parametrize("boundary", ["reset", "resume", "target"])
async def test_stale_model_response_after_controller_change_is_not_dispatched(tmp_path, local_lab, boundary, record_property):
    entered, cancelled = asyncio.Event(), asyncio.Event()
    stale = tool_response("workflow", json.dumps({"action": "record_candidate", "candidate_class": "sql-injection",
        "endpoint": "/stale", "method": "GET", "parameter": "q", "location": "query"}))
    class Delayed(FakeClient):
        async def chat(self, request, signal=None):
            entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancelled.set()
                return stale  # A provider returning buffered output after cancel.

    rt = runtime_for(tmp_path, local_lab)
    rt.agent.set_client(Delayed([]))
    await rt.agent.save()
    app = make_system_app(rt)
    metrics = {}
    async with app.run_test(size=(70, 24)) as pilot:
        app.submit("Describe the current lab workflow.")
        task = app.run_task
        assert task is not None
        try:
            await asyncio.wait_for(entered.wait(), 2)
            old = rt.workflow.generation
            async with heartbeat(metrics):
                if boundary == "reset":
                    app.submit("/reset")
                elif boundary == "resume":
                    rt.agent.resume_saved()
                else:
                    await rt.agent.clear_target()
                await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 2)
                await wait_until(lambda: not app.state.busy)
            assert cancelled.is_set() and rt.workflow.generation != old
            assert_idle(app)
            assert not rt.workflow.candidates and not rt.policy.observations._items and not local_lab.wire
            assert all("/stale" not in entry.text for entry in app.state.transcript)
            await rt.agent.save()
            assert not rt.store.load().workflow.candidates
            await pilot.press("x")
            assert app.input.value.endswith("x")
            record_property("fault_case", json.dumps({"pre": {"generation": old}, "injected": boundary,
                "expected": "old response cannot dispatch/checkpoint", "post": {"generation": rt.workflow.generation, **metrics}}))
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await drain(rt)


@pytest.mark.parametrize("boundary", ["escape", "reset"])
async def test_ui_cancel_reaches_pending_native_http(tmp_path, local_lab, boundary, record_property):
    rt = runtime_for(tmp_path, local_lab)
    rt.agent.set_client(FakeClient([tool_response("http", json.dumps({"url": "/slow", "phase": "recon"})),
                                   ChatResponse(Message("assistant", "done"), "stop")]))
    app = make_system_app(rt)
    metrics = {}
    async with app.run_test(size=(70, 24)):
        async def operator():
            while True:
                if app.state.pending_perm:
                    await app._process_key(events.Key("y", "y"))
                await asyncio.sleep(0.002)
        controller = asyncio.create_task(operator())
        app.submit("Fetch the local lab's /slow once.")
        task = app.run_task
        assert task is not None
        try:
            await asyncio.wait_for(local_lab.entered.wait(), 3)
            async with heartbeat(metrics):
                start = time.monotonic()
                if boundary == "escape":
                    await app._process_key(events.Key("escape", None))
                    assert app.run_abort_event is not None and app.run_abort_event.is_set()
                else:
                    app.submit("/reset")
                metrics["cancel_delivery_ms"] = (time.monotonic() - start) * 1000
                await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 2)
                metrics["cancel_settled_ms"] = (time.monotonic() - start) * 1000
            assert_idle(app)
            assert not rt.policy.observations._items and not rt.workflow.evidence and not rt.workflow.persisted_findings
            assert rt.policy.active == 0 and not rt.engagement.http_permissions._inflight
            local_lab.release.set()
            await wait_until(lambda: not local_lab.tasks)
            count = len(local_lab.wire)
            await asyncio.sleep(0.03)
            assert len(local_lab.wire) == count == 1
            record_property("fault_case", json.dumps({"pre": "native HTTP pending", "injected": boundary,
                "expected": "cancel reaches transport; no late observation", "post": metrics}))
        finally:
            local_lab.release.set()
            controller.cancel()
            task.cancel()
            await asyncio.gather(task, controller, return_exceptions=True)
            await drain(rt)


@pytest.mark.parametrize("cancel", [False, True])
async def test_streaming_real_agent_large_history_and_delta_oracles(tmp_path, local_lab, cancel, record_property):
    entered, release = asyncio.Event(), asyncio.Event()
    counts = {"deltas": 0, "semantic_delta_calls": 0}
    class Stream(FakeClient, StreamingClient):
        async def chat_stream(self, request, on_delta, signal=None):
            for index in range(600):
                before = (facts.call_count, reads.call_count, estimate.call_count)
                on_delta("bounded synthetic chunk ")
                counts["deltas"] += 1
                after = (facts.call_count, reads.call_count, estimate.call_count)
                counts["semantic_delta_calls"] += sum(b-a for a,b in zip(before, after))
                if index % 10 == 0:
                    await asyncio.sleep(0.002)
            entered.set()
            await release.wait()
            return ChatResponse(Message("assistant", "Bounded stream complete."), "stop")

    rt = runtime_for(tmp_path, local_lab)
    rt.agent.set_client(Stream([]))
    rt.agent.streaming_enabled = True
    rt.agent.history.extend(Message("user" if i % 2 == 0 else "assistant", "old synthetic history " * 4) for i in range(1000))
    app = make_system_app(rt)
    metrics = {}
    async with app.run_test(size=(70, 24)) as pilot:
        with (patch.object(app_module, "runtime_facts", wraps=app_module.runtime_facts) as facts,
              patch.object(evidence_module, "_read_captured_value", wraps=evidence_module._read_captured_value) as reads,
              patch.object(rt.agent, "idle_request_estimate", wraps=rt.agent.idle_request_estimate) as estimate):
            app.submit("Summarize the synthetic conversation.")
            task = app.run_task
            assert task is not None
            try:
                async with heartbeat(metrics):
                    await asyncio.wait_for(entered.wait(), 10)
                    assert app.state.busy and counts["deltas"] == 600
                    assert counts["semantic_delta_calls"] == 0
                    if cancel:
                        start = time.monotonic()
                        await app._process_key(events.Key("escape", None))
                        metrics["esc_delivery_ms"] = (time.monotonic() - start) * 1000
                    release.set()
                    await asyncio.wait_for(task, 5)
                assert_idle(app)
                assert not local_lab.wire and not rt.workflow.persisted_findings
                await pilot.press("x")
                assert app.input.value.endswith("x")
                record_property("streaming", json.dumps({**metrics, **counts, "history_messages": 1000}))
            finally:
                release.set()
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                await drain(rt)
