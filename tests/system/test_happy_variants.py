"""Independent successful routes through different subsystem combinations."""
from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from textual import events

from src.llm.core.client import StreamingClient
from src.llm.core.types import Message
from src.permission.network.grants import HTTPLimits
from src.tools.execution.shell import ShellTool
from src.ui.core import app as app_module
from src.workflow.evidence import artifacts as evidence_module
from tests.helpers.agent_fakes import ScriptedModel
from tests.helpers.agent_fakes import FakeSignal
from tests.helpers.scenarios import dedicated_validation, receipt, record_candidate
from tests.helpers.system_runtime import (
    assert_idle, assert_wire, drain, heartbeat, lab_definition, make_system_app, prepare_lab,
)


def variant_script(variant, original):
    def script(rt, scenario):
        if variant == "retry":
            failed = yield "http", {"url": "/flaky", "phase": "recon"}
            assert "503" in failed and "retry once" in failed
            recovered = yield "http", {"url": "/flaky", "phase": "recon"}
            assert "200" in recovered and "recovered" in recovered
        if variant == "redirect_auth":
            redirected = yield "http", {"url": "/redirect", "phase": "recon", "max_redirects": 1}
            assert "[hop 1]" in redirected and "public lab page" in redirected
            anonymous = yield "http", {"url": "/auth", "phase": "recon"}
            assert "401" in anonymous and "auth required" in anonymous
            authenticated = yield "http", {"url": "/auth", "phase": "recon", "headers": {"X-Lab-User": "alice"}}
            assert "200" in authenticated and "synthetic user" in authenticated
        inner, feedback, cid = original(rt, scenario), None, None
        proof_paths = {}
        while True:
            try:
                name, args = inner.send(feedback)
            except StopIteration:
                return
            args = dict(args)
            if variant == "capture" and name == "workflow" and args["action"] == "record_candidate":
                args["baseline_request_ref"] = rt.lab_capture_ref
            if variant == "capture" and name == "http" and args.get("phase") == "validation":
                value = parse_qs(urlsplit(args["url"]).query)["category"][0]
                args = {"phase": "validation", "candidate_id": cid, "mutation_value": value}
            if variant == "alternate_proof":
                if name == "file_write" and "scenario-proof/" in args["path"]:
                    old = args["path"]
                    args["path"] = old.replace("scenario-proof/", "reviewed-proof/")
                    proof_paths["artifacts/scenario-proof/" + Path(old).name] = "artifacts/reviewed-proof/" + Path(old).name
                if name == "workflow" and args["action"] == "record_evidence":
                    args["evidence_path"] = proof_paths[args["evidence_path"]]
            feedback = yield name, args
            if name == "workflow" and args["action"] == "record_candidate":
                cid = receipt(feedback)["candidate"]["id"]
                if variant == "alternate_proof":
                    duplicate = receipt((yield name, args))
                    assert duplicate["created"] is False and duplicate["candidate"]["id"] == cid
            if variant == "alternate_proof" and name == "workflow" and args["action"] == "record_evidence":
                original_id = receipt(feedback)["evidence"]["id"]
                duplicate = receipt((yield name, args))
                assert duplicate["evidence"]["id"] == original_id
    return script


class StreamingScript(ScriptedModel, StreamingClient):
    deltas = 0
    delta_probe: Any = None
    async def chat_stream(self, request, on_delta, signal=None):
        for index in range(60):
            if self.delta_probe is None:
                on_delta("bounded reasoning text ")
            else:
                self.delta_probe(on_delta, "bounded reasoning text ")
            self.deltas += 1
            if index % 10 == 0:
                await asyncio.sleep(0)
        return await super().chat(request, signal)


@pytest.mark.parametrize("variant", ["approve", "redirect_auth", "retry", "capture", "alternate_proof", "streaming"])
async def test_successful_subsystem_variants(tmp_path, monkeypatch, local_lab, variant, record_property):
    mode = "whole_target" if variant in {"redirect_auth", "retry"} else "direct"
    scenario = lab_definition(local_lab, mode=mode)
    scenario = replace(scenario, id="happy-" + variant, script=variant_script(variant, scenario.script))
    runner, rt, traffic = prepare_lab(tmp_path, monkeypatch, local_lab, scenario)
    extra = []
    if variant == "retry":
        local_lab.failures_left = 1
        extra = [("/flaky", 503, b"retry once"), ("/flaky", 200, b"recovered")]
    elif variant == "redirect_auth":
        extra = [("/redirect", 302, b"redirect"), ("/public", 200, b"public lab page"),
                 ("/auth", 401, b"auth required"), ("/auth", 200, b"synthetic user")]
    if extra:
        traffic.expected[:0] = [({"url": path, "method": "GET"}, (status, body, "text/plain")) for path, status, body in extra]
    # A bounded controller grant, rather than a model-created authorization.
    rt.engagement.http_permissions.activate(local_lab.origin, HTTPLimits(requests=40, rate=1000, burst=40))
    pids = []
    if variant == "approve":
        rt.engagement.http_permissions.reset()
        assert not rt.engagement.http_permissions.grants
    elif variant == "capture":
        result = await rt.registry.execute("http", {"phase": "recon", "url": "/filter?category=Gifts"}, None, rt.prompter)
        assert "fixture products" in result
        row = local_lab.wire[-1]
        imported = rt.capture.ingest({"id": "lab-baseline", "method": row["method"], "url": row["url"],
            "requestHeaders": [{"name": k, "value": v} for k, v in row["headers"].items()],
            "responseStatus": row["status"], "responseBody": row["response"].decode()})
        rt.lab_capture_ref = imported["baseline_request_ref"]
        traffic.expected.insert(0, ({"url": "/filter?category=Gifts", "method": "GET"}, (200, b"fixture products", "text/plain")))
    if variant == "streaming":
        rt.agent.streaming_enabled = True
        rt.agent.history.extend(Message("user" if i % 2 == 0 else "assistant", "synthetic history " * 2) for i in range(1000))
    metrics = {}
    delta_calls = {"facts": 0, "reads": 0, "estimate": 0}
    def model_factory(script, *, prefix):
        model = StreamingScript(script, prefix=prefix) if variant == "streaming" else ScriptedModel(script, prefix=prefix)
        if isinstance(model, StreamingScript):
            def probe(on_delta, text):
                before = sum(delta_calls.values())
                on_delta(text)
                metrics["semantic_delta_calls"] = metrics.get("semantic_delta_calls", 0) + sum(delta_calls.values()) - before
            model.delta_probe = probe
        return model
    if variant == "streaming":
        def counted(key, function):
            def call(*args, **kwargs):
                delta_calls[key] += 1
                return function(*args, **kwargs)
            return call
        monkeypatch.setattr(app_module, "runtime_facts", counted("facts", app_module.runtime_facts))
        monkeypatch.setattr(evidence_module, "_read_captured_value", counted("reads", evidence_module._read_captured_value))
        monkeypatch.setattr(rt.agent, "idle_request_estimate", counted("estimate", rt.agent.idle_request_estimate))
    async def drive(runtime, definition, trace):
        app = make_system_app(runtime, trace)
        async with app.run_test(size=(80, 26)):
            async def operator():
                while True:
                    if app.state.pending_perm:
                        metrics["reviews"] = metrics.get("reviews", 0) + 1
                        await app._process_key(events.Key("y", "y"))
                    await asyncio.sleep(0.002)
            controller = asyncio.create_task(operator())
            try:
                async with heartbeat(metrics):
                    app.submit(definition.user_input)
                    assert app.run_task is not None
                    await app.run_task
                assert_idle(app)
                assert not runtime.bridge._busy and not runtime.bridge._waiters
            finally:
                controller.cancel()
                await asyncio.gather(controller, return_exceptions=True)
    try:
        run = await runner.run(scenario, runtime=rt, transport=traffic,
            drive=drive if variant in {"approve", "streaming"} else None,
            model_factory=model_factory)
        assert_wire(traffic, local_lab.origin)
        await runner.resume(run)
        assert run.oracle.independently_complete(rt)
        assert len(rt.workflow.persisted_findings) == len(rt.workflow.validation_results) == 1
        assert rt.policy.active == 0 and not rt.policy._active_receipts
        if variant in {"approve", "streaming"}:
            assert metrics["reviews"] > 0 and metrics["heartbeat_ticks"] > 0
        if variant == "streaming":
            assert isinstance(run.model, StreamingScript) and run.model.deltas >= 600
            assert metrics["semantic_delta_calls"] == 0 and delta_calls["reads"] > 0
        if variant == "alternate_proof":
            assert len(rt.workflow.candidates) == len(rt.workflow.evidence) == 1
            assert "reviewed-proof" in next(iter(rt.workflow.evidence.values())).source_path
        record_property("happy_path", json.dumps({"variant": variant, "complete": True, "http_requests": len(traffic.sent),
            "functional": "accepted finding, coverage, fresh resume", "state": "owned sources, immutable proof, exact origin", **metrics}))
    finally:
        await drain(rt)
        for pid in pids:
            with pytest.raises(ProcessLookupError):
                os.kill(pid, 0)


async def test_resume_interrupted_validation_then_complete_without_inheriting_authority(tmp_path, monkeypatch, local_lab, record_property):
    base = lab_definition(local_lab, mode="direct")
    pending = asyncio.Event()
    class PauseModel(ScriptedModel):
        async def chat(self, request, signal=None):
            if len(self.calls) == 3:
                pending.set()
                await asyncio.Future()
            return await super().chat(request, signal)
    def pause_script(rt, scenario):
        yield "load_skill", {"name": "sql-injection"}
        candidate = receipt((yield "workflow", record_candidate(scenario)))
        started = receipt((yield "workflow", {"action": "start_validation", "candidate_id": candidate["candidate"]["id"]}))
        assert started["validation_context"]["attempt_id"]
    async def paused(run):
        state = run.runtime.workflow
        assert not run.model.errors and not run.trace.errors and len(run.model.calls) == 3
        assert not run.transport.sent and not state.validation_results and not state.persisted_findings
        assert len(state.attempts) == 1 and next(iter(state.attempts.values()))["status"] == "active"
        assert [event["stop_reason"] for event in run.trace.events if event["type"] == "done"] == ["cancelled"]
    async def interrupt(rt, scenario, trace):
        task = asyncio.create_task(rt.agent.run(scenario.user_input, FakeSignal(), trace.record))
        try:
            await asyncio.wait_for(pending.wait(), 5)
            task.cancel()
            result = await asyncio.gather(task, return_exceptions=True)
            assert isinstance(result[0], asyncio.CancelledError)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    first = replace(base, id="mid-validation", script=pause_script, verify=paused)
    runner, original, traffic = prepare_lab(tmp_path, monkeypatch, local_lab, first)
    fresh = None
    try:
        run = await runner.run(first, runtime=original, transport=traffic, drive=interrupt, model_factory=PauseModel)
        attempt = next(iter(original.workflow.attempts))
        fresh = await runner.resume(run, unchanged=False)
        assert fresh.workflow.attempts[attempt]["status"] == "interrupted"
        assert not fresh.engagement.http_permissions.grants and not fresh.policy.observations._items
        fresh.agent.set_max_steps(80)
        def continue_script(rt, scenario):
            listing = receipt((yield "workflow", {"action": "list"}))
            candidates = listing["candidates"]
            assert len(candidates) == 1
            yield from dedicated_validation(rt, scenario, candidates[0]["id"])
        async def completed(resumed):
            rt = resumed.runtime
            assert resumed.model.consumed and not resumed.model.errors and not resumed.trace.errors
            assert not [event for event in resumed.trace.events if event["type"] == "error"]
            assert len(rt.workflow.validation_results) == len(rt.workflow.persisted_findings) == 1
            assert resumed.oracle.independently_complete(rt)
            assert not rt.agent._validation_completion_blockers()
            assert rt.workflow.latest_result(next(iter(rt.workflow.candidates))).attempt_id != attempt
            assert rt.workflow.attempts[attempt]["status"] == "interrupted"
            assert [event["stop_reason"] for event in resumed.trace.events if event["type"] == "done"] == ["final_response"]
            await resumed.oracle.persisted(resumed, rt)
        continuation = replace(base, id=first.id, script=continue_script, verify=completed,
            user_input="Continue the interrupted assessment from the saved session and finish its existing candidate.")
        resumed = await runner.run(continuation, runtime=fresh, transport=traffic)
        assert_wire(traffic, local_lab.origin)
        assert fresh.operator.requests and not fresh.engagement.http_permissions.grants
        await runner.resume(resumed)
        record_property("happy_path", json.dumps({"variant": "mid-workflow-resume", "old_attempt": attempt,
            "interrupted": True, "complete": True, "new_requests": len(traffic.sent), "inherited_grants": 0}))
    finally:
        await drain(original)
        if fresh is not None:
            await drain(fresh)
