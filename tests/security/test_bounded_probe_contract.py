"""Concrete action contracts with trusted, local fixture endpoint facts only."""
from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from typing import Any, cast
from unittest.mock import AsyncMock

import httpx
import pytest

from src.browser.store import CaptureStore
from src.coverage.store import CoverageStore
from src.findings.store import Store
from src.permission.network.grants import HTTPPending, HTTPLimits
from src.permission.permission import UserControlledRefusal, Decision
from src.permission.runtime.execution import ExecutionBlocked
from src.skills.registry import Registry as Skills
from src.tools.workflow.workflow_tool import WorkflowTool
from src.tools.workflow.finding import ConfirmFindingTool
from src.ui.commands.result_review import review_result
from src.workflow.probe import ProbeProposal
from src.workflow.state import WorkflowState, WorkflowObjective, WorkflowMode
from src.workflow.validation_route import GENERIC_VALIDATOR
from tests.helpers.agent_fakes import FakeSignal, FakeClient
from tests.helpers.workflow import record_completed_phase
from tests.security.test_execution_policy import runtime, ORIGIN
from tests.security.test_generic_validation import app_for, review_args, result, certificate, agent_for, expert


async def custom_env(runtime, tmp_path, shape="json", mode: WorkflowMode="direct") -> Any:
    registry, p, policy, operator, _, _, target = runtime
    skills, state = Skills(), WorkflowState()
    state.objective = WorkflowObjective("custom-objective", mode, ORIGIN)
    if mode == "whole_target":
        for phase in ("recon", "enumeration", "input_analysis"):
            record_completed_phase(state, phase, objective_id=state.objective.id,
                                   target_origin=ORIGIN, artifact_ref="fixture.md")
    tool = WorkflowTool(state, target, skills=skills, evidence_root=tmp_path,
                        coverage=CoverageStore(str(tmp_path / "coverage.json")))
    registry.register(tool)
    http = registry.get("http")
    http.workflow, http.validation_registry = state, skills
    policy.bind_validation_context(state, skills, target)
    shapes = {
        "json": ("response-normalization", "POST", "term", "application/json", '{ "term" : "base", "keep": 7 }'),
        "form": ("input-canonicalization", "POST", "term", "application/x-www-form-urlencoded", "keep=a%20b&term=base&term=untouched"),
        "header": ("header-reflection", "GET", "X-Lab-Compare", "", ""),
        "query": ("search-comparison", "GET", "term", "", ""),
    }
    cls, method, parameter, content_type, body = shapes[shape]
    endpoint = "/lab/compare?keep=%2f&term=base&term=untouched" if shape == "query" else "/lab/compare?keep=%2f"
    capture = CaptureStore()
    headers = [{"name": "User-Agent", "value": "VerifiedLabFixture/1"}, {"name": "X-Keep", "value": "original"}]
    if content_type:
        headers.append({"name": "Content-Type", "value": content_type})
    if shape == "header":
        headers.append({"name": parameter, "value": "base"})
    ingested = capture.ingest({"id": "custom-baseline", "method": method, "url": ORIGIN + endpoint,
                    "requestHeaders": headers, "requestBody": body or None})
    http.capture_store = capture
    recorded = json.loads(await registry.execute("workflow", {
        "action": "record_candidate", "candidate_class": cls, "endpoint": endpoint,
        "method": method, "parameter": parameter, "location": shape,
        "content_type": content_type or None, "baseline_request_ref": ingested["baseline_request_ref"],
        "source_skill": "web-input-analysis"}, None, p))
    c = state.candidates[recorded["candidate"]["id"]]
    assert c.endpoint and c.method and c.location and c.parameter and state.objective.target_origin
    env = registry, p, policy, operator, state, c, tool, recorded
    probe = ProbeProposal(c.id, state.objective.id, state.objective.target_origin,
        c.endpoint, c.method, c.location, c.parameter, ("Lab-A", "Lab-B"), c.baseline_request_ref).to_dict()
    return env, probe


def bind(env, probe):
    env[2].generic_validation.bind_probe_context(env[0].get("http"), env[5].id, probe,
                                               verified_input_only=True)


async def start(env, probe):
    return await env[0].execute("workflow", {"action": "start_validation", "candidate_id": env[5].id,
        "probe": probe}, None, env[1])


def http_args(env, value=None):
    http, c = env[0].get("http"), env[5]
    if value is not None and c.location != "header":
        return {"candidate_id": c.id, "mutation_value": value, "phase": "validation"}
    baseline = env[2].generic_validation.baseline(http, c)
    headers = dict(baseline.headers)
    if value is not None:
        headers[c.parameter.lower()] = value
    return {"url": str(baseline.url), "method": baseline.method, "headers": headers,
            "body": baseline.content.decode(), "phase": "validation"}


@pytest.mark.parametrize("shape", ["json", "form", "header", "query"])
@pytest.mark.parametrize("reviewed_outcome", ["confirmed", "not-confirmed"])
async def test_custom_shapes_native_evidence_human_review_and_result(runtime, tmp_path, shape, reviewed_outcome):
    env, probe = await custom_env(runtime, tmp_path, shape)
    assert env[7]["validator_resolution"] == "generic" and env[5].status == "deferred"
    assert not env[7]["supported"]
    assert (await start(env, probe)).startswith("error:")  # Proposal/capture/grant alone are insufficient.
    bind(env, probe)
    assert json.loads(await start(env, probe))["candidate"]["status"] == "validating"
    outputs = []
    for value in (None, "Lab-A", "Lab-B", "Lab-A"):
        outputs.append(await env[0].execute("http", http_args(env, value), None, env[1]))
    assert all(out.http_status == 200 for out in outputs)
    sent = runtime[4]
    assert len(sent) == 4 and all(r.headers["X-Keep"] == "original" for r in sent)
    if shape == "json":
        assert sent[1].content == b'{ "term" : "Lab-A", "keep": 7 }'
    elif shape == "form":
        assert sent[1].content == b"keep=a%20b&term=Lab-A&term=untouched"
    elif shape == "header":
        assert sent[1].headers["X-Lab-Compare"] == "Lab-A"
    else:
        assert sent[1].url.query == b"keep=%2f&term=Lab-A&term=untouched"
    proof = env[2].generic_validation.proof_path(env[5])
    await env[0].execute("file_write", {"path": str(proof), "content": "\n\n".join(map(str, outputs))
        + "\nAuthorization: Bearer fake-lab-secret\nCookie: session=fake-cookie"}, None, env[1])
    ref = json.loads(await env[0].execute("workflow", {"action": "record_evidence", "candidate_id": env[5].id,
        "evidence_path": str(proof.relative_to(tmp_path))}, None, env[1]))["evidence"]["id"]
    artifact = env[4].evidence[ref]
    original = (tmp_path / artifact.path).read_text()
    assert "fake-lab-secret" not in original and "fake-cookie" not in original
    proof.write_text("changed mutable source")
    assert (tmp_path / artifact.path).read_text() == original
    unverified = json.loads(await result(env, refs=[ref], repeatable=True, force=True))
    assert unverified["result"]["outcome"] == "insufficient-evidence"
    assert not unverified["result"]["mutation_performed"]  # Input variation is not persistent mutation.
    assert await env[6].coverage.list() == [] and certificate(env, ref) is None
    app, output = app_for(env)
    app.agent.save.side_effect = lambda: None
    await review_result(app, review_args(env[5], reviewed_outcome))
    assert output[-1].entry.kind == "system", output[-1]
    assert certificate(env, ref).outcome == reviewed_outcome
    assert [r.tool for r in env[3].requests] == ["review_result"]
    assert env[5].source_skill == "web-input-analysis" and env[5].objective_id == env[4].objective.id
    assert GENERIC_VALIDATOR not in env[4].completed_skills
    env[2].generic_validation.contexts.clear()  # Finalization needs proof, not new probe rights.
    if reviewed_outcome == "confirmed":
        assert agent_for(env)._generic_completion_blockers()
        store = Store(project_directory=tmp_path)
        env[0].register(ConfirmFindingTool(store, workflow=env[4]))
        output = await env[0].execute("confirm_finding", {"candidate_id": env[5].id,
            "url": ORIGIN + env[5].endpoint, "title": "Reviewed bounded fixture comparison",
            "severity": "critical", "observed_impact": "untrusted model claim",
            "potential_impact": "No broader impact tested."}, None, env[1])
        assert "written to" in output and env[4].finding_is_persisted(env[5].id)
        text = next((tmp_path / "artifacts/findings").glob("*.md")).read_text()
        assert "untrusted model claim" not in text and "critical" not in text
    assert agent_for(env)._generic_completion_blockers() == ()
    assert env[2].used > 0 and env[2].active == 0


@pytest.mark.parametrize("raw", [None, {}, "try until vulnerable", [], {"safe": True},
    {"read_only": True, "reversible": True}, {"values": [None]}, {"values": "Lab-A"}])
async def test_missing_malformed_or_model_safety_proposal_never_executes(runtime, tmp_path, raw):
    env, _ = await custom_env(runtime, tmp_path)
    output = await env[6].run({"action": "start_validation", "candidate_id": env[5].id, "probe": raw}, None, env[1])
    assert output.startswith("error:") and env[5].status == "deferred"
    with pytest.raises((ExecutionBlocked, ValueError)):
        await env[0].execute("http", http_args(env, "Lab-A"), None, env[1])
    assert not runtime[4] and not env[3].requests


@pytest.mark.parametrize("field,value", [("candidate_id", "other"), ("objective_id", "other"),
    ("target_origin", "http://other.test:3000"), ("endpoint", "/other"), ("method", "DELETE"),
    ("location", "raw"), ("parameter", "keep"), ("baseline_request_ref", "wr:other"),
    ("auth_context_ref", "other-principal"), ("values", ["not-bound"]), ("occurrence", 1),
    ("stop", "until-vulnerable"), ("safe", True), ("observation", "confirmed")])
async def test_proposal_bindings_cannot_change_via_model_start(runtime, tmp_path, field, value):
    env, probe = await custom_env(runtime, tmp_path)
    bind(env, probe)
    output = await start(env, {**probe, field: value})
    assert output.startswith("error:") and env[5].status == "deferred"
    assert env[2].generic_validation.attempt is None and not runtime[4]


@pytest.mark.parametrize("bad", ["new-value", "other-query", "other-header", "other-body", "other-path",
                                "other-origin", "redirect", "identity", "occurrence"])
async def test_each_custom_http_request_must_match_whole_prepared_contract(runtime, tmp_path, bad):
    env, probe = await custom_env(runtime, tmp_path, "form")
    bind(env, probe)
    await start(env, probe)
    args = http_args(env)
    if bad == "new-value":
        args["body"] = "keep=a%20b&term=not-bound&term=untouched"
    elif bad == "other-query":
        args["url"] += "&new=1"
    elif bad == "other-header":
        args["headers"]["x-keep"] = "changed"
    elif bad == "other-body":
        args["body"] = "keep=changed&term=Lab-A&term=untouched"
    elif bad == "other-path":
        args["url"] = ORIGIN + "/other?keep=%2f"
    elif bad == "other-origin":
        env[2].engagement.add_origin("http://other.test:3000")
        args["url"] = "http://other.test:3000/lab/compare?keep=%2f"
    elif bad == "redirect":
        args["max_redirects"] = 1
    elif bad == "identity":
        args["headers"]["authorization"] = "Bearer forged"
    else:
        args = {**http_args(env, "Lab-A"), "occurrence": 1}
    with pytest.raises((ExecutionBlocked, ValueError)):
        await env[0].execute("http", args, None, env[1])
    assert not runtime[4] and not env[3].requests


@pytest.mark.parametrize("shape", ["query", "header", "form", "json"])
async def test_sensitive_identity_variation_unavailable_even_trusted_context(runtime, tmp_path, shape):
    env, probe = await custom_env(runtime, tmp_path, shape)
    env[5].parameter = "role" if shape != "header" else "Authorization"
    probe["parameter"] = env[5].parameter
    with pytest.raises(ValueError, match="sensitive identity"):
        bind(env, probe)
    assert env[2].generic_validation.contexts == {} and not runtime[4]


@pytest.mark.parametrize("value", ["https://evil.test/callback", "//evil.test/callback", "http://127.0.0.1:9000/callback"])
async def test_url_data_does_not_create_callback_scope(runtime, tmp_path, value):
    env, probe = await custom_env(runtime, tmp_path, "query")
    probe["values"] = [value]
    with pytest.raises(ValueError, match="callback"):
        bind(env, probe)
    assert not runtime[4]


@pytest.mark.parametrize("change", ["baseline", "auth", "proposal", "context", "registry", "objective", "target"])
async def test_custom_state_changes_during_permission_await_stop_send(runtime, tmp_path, monkeypatch, change):
    env, probe = await custom_env(runtime, tmp_path)
    bind(env, probe)
    await start(env, probe)
    http, boundary = env[0].get("http"), env[2].generic_validation
    original = http.permissions.authorize
    async def authorize(*args):
        receipt = await original(*args)
        if change == "baseline":
            http.capture_store.clear()
        elif change == "auth":
            env[5].auth_context_ref = "changed"
        elif change == "proposal":
            boundary.attempt = replace(boundary.attempt,
                proposal=replace(boundary.attempt.proposal, values=("changed",)))
        elif change == "context":
            boundary.contexts.clear()
        elif change == "registry":
            env[6].skills.load_errors.add("changed-metadata")
        elif change == "objective":
            env[4].objective.id = "changed"
        else:
            env[6].target.set_base_url("http://127.0.0.1:3001")
        return receipt
    monkeypatch.setattr(http.permissions, "authorize", authorize)
    with pytest.raises((ValueError, UserControlledRefusal)):
        await env[0].execute("http", http_args(env, "Lab-A"), None, env[1])
    assert not runtime[4] and not boundary.in_flight


async def test_inflight_context_replacement_and_terminal_retest_cannot_bypass(runtime, tmp_path, monkeypatch):
    env, probe = await custom_env(runtime, tmp_path)
    bind(env, probe)
    await start(env, probe)
    entered, release = asyncio.Event(), asyncio.Event()
    original = env[0].get("http").permissions.reserve_when_ready
    async def reserve(*args):
        entered.set()
        await release.wait()
        return await original(*args)
    monkeypatch.setattr(env[0].get("http").permissions, "reserve_when_ready", reserve)
    running = asyncio.create_task(env[0].execute("http", http_args(env, "Lab-A"), None, env[1]))
    await asyncio.wait_for(entered.wait(), 2)
    with pytest.raises(ValueError, match="in-flight"):
        bind(env, probe)
    assert (await env[6].run({"action": "record_result", "candidate_id": env[5].id,
        "skill_name": GENERIC_VALIDATOR, "outcome": "deferred"}, None, env[1])).startswith("error:")
    release.set()
    assert (await running).http_status == 200
    await result(env, "blocked")
    env[4].set_candidate_status(env[5].id, "queued")
    assert (await start(env, probe)).startswith("error:")
    assert (await env[6].run({"action": "start_validation", "candidate_id": env[5].id,
        "probe": probe, "force": True}, None, env[1])).startswith("error:")


async def test_scheduler_pending_preserves_attempt_and_evidence(runtime, tmp_path, monkeypatch):
    env, probe = await custom_env(runtime, tmp_path)
    bind(env, probe)
    await start(env, probe)
    monkeypatch.setattr(env[0].get("http").permissions, "reserve_when_ready",
                        AsyncMock(side_effect=HTTPPending("pending: bounded scheduler pressure")))
    with pytest.raises(HTTPPending):
        await env[0].execute("http", http_args(env, "Lab-A"), None, env[1])
    assert env[5].status == "validating" and env[4].latest_result(env[5].id) is None
    assert env[2].generic_validation.attempt is not None and not runtime[4]


@pytest.mark.parametrize("mode", ["direct", "whole_target"])
async def test_planner_context_and_explicit_start_without_auto_requeue(runtime, tmp_path, mode):
    from src.agent.decision_planner import build_decision_plan
    env, probe = await custom_env(runtime, tmp_path, mode=mode)
    agent = agent_for(env)
    plan = build_decision_plan("continue", [], env[6].target, agent._planner_context())
    assert plan is not None and plan.recommended_skill is None and "context-needed" in plan.guidance
    assert "Call workflow(action=start_validation" not in plan.guidance
    bind(env, probe)
    assert env[5].status == "deferred"
    plan = build_decision_plan("continue", [], env[6].target, agent._planner_context())
    assert plan is not None and plan.candidate_id == env[5].id and plan.recommended_skill is None
    assert "probe=<concrete proposal>" in plan.guidance
    assert json.loads(await start(env, probe))["ok"]


async def test_resume_evidence_review_without_proposal_does_not_restore_execution(runtime, tmp_path):
    env, probe = await custom_env(runtime, tmp_path, "header")
    bind(env, probe)
    await start(env, probe)
    await env[0].execute("http", http_args(env, "Lab-A"), None, env[1])
    from tests.security.test_generic_validation import evidence
    ref = await evidence(env, tmp_path)
    await result(env, refs=[ref])
    raw = json.loads(json.dumps(env[4].to_dict()))
    assert "probe" not in raw and "contexts" not in raw
    restored = WorkflowState.from_dict(raw)
    env[6].state = restored
    env[0].get("http").workflow = restored
    env[2].bind_validation_context(restored, env[6].skills, env[6].target)
    env = cast(Any, (*env[:4], restored, restored.candidates[env[5].id], *env[6:]))
    assert env[2].generic_validation.contexts == {} and env[2].generic_validation.attempt is None
    assert (await start(env, probe)).startswith("error:")
    app, output = app_for(env)
    await review_result(app, review_args(env[5], "not-confirmed"))
    assert output[-1].entry.kind == "system", output[-1]
    assert certificate(env, ref).outcome == "not-confirmed"
    assert agent_for(env)._generic_completion_blockers() == ()
    with pytest.raises((ExecutionBlocked, ValueError)):
        await env[0].execute("http", http_args(env, "Lab-A"), None, env[1])
    assert len(runtime[4]) == 1


@pytest.mark.parametrize("streaming", [False, True])
async def test_direct_model_final_cannot_complete_recorded_unresolved_generic(runtime, tmp_path, streaming):
    from src.llm.core.types import ChatResponse, Message
    env, _ = await custom_env(runtime, tmp_path)
    agent = agent_for(env)
    agent.client = FakeClient([ChatResponse(message=Message(role="assistant", content="All completed."), finish_reason="stop")])
    if streaming:
        from src.llm.core.client import StreamingClient
        class FinalStream(StreamingClient):
            def name(self):
                return "fake-stream"
            def model(self):
                return "fake-model"
            async def chat(self, request, signal=None):
                raise AssertionError("streaming client should use chat_stream")
            async def chat_stream(self, request, on_delta, signal=None):
                on_delta("All ")
                on_delta("completed.")
                return ChatResponse(message=Message(role="assistant", content="All completed."), finish_reason="stop")
        agent.client = FinalStream()
    agent.save = AsyncMock()
    events = []
    await agent.run("continue", FakeSignal(), events.append)
    assert events[-1].stop_reason == "workflow_blocked"
    assert "incomplete" in agent.history[-1].content and "All completed" not in agent.history[-1].content
    assert any("incomplete" in getattr(e, "text", "") for e in events)
    assert not any("completed" in getattr(e, "text", "") for e in events)
    assert agent._objective_has_blocker(env[4].objective)


@pytest.mark.parametrize("cls", ["sql-injection", "cross-site-scripting", "open-redirect", "cors-misconfiguration"])
async def test_unique_expert_does_not_require_generic_proposal_or_context(runtime, tmp_path, cls):
    from tests.security.test_generic_validation import setup, start as expert_start
    skills = Skills()
    skills.add(expert(cls, cls))
    env = await setup(runtime, tmp_path, cls=cls, skills=skills)
    assert json.loads(await expert_start(env))["ok"]
    assert env[2].generic_validation.contexts == {} and env[2].generic_validation.attempt is None


async def test_verified_context_is_not_a_grant_receipt_or_budget_refill(runtime, tmp_path):
    env, probe = await custom_env(runtime, tmp_path)
    policy, rights = env[2], env[2].engagement.http_permissions
    used, grants, receipts = policy.used, dict(rights.grants), dict(rights._receipts)
    bind(env, probe)
    assert policy.used == used and rights.grants == grants and rights._receipts == receipts
    await start(env, probe)
    rights.activate(ORIGIN, HTTPLimits(requests=1, rate=1000, burst=1))
    await env[0].execute("http", http_args(env, "Lab-A"), None, env[1])
    with pytest.raises(UserControlledRefusal):
        await env[0].execute("http", http_args(env, "Lab-A"), None, env[1])
    assert env[4].latest_result(env[5].id).outcome == "blocked"
    env[1].set_yolo(False)
    env[1].set_yolo(True)
    env[4].set_candidate_status(env[5].id, "queued")
    assert (await start(env, probe)).startswith("error:")
    assert len(runtime[4]) == 1 and not env[3].requests


@pytest.mark.parametrize("shape", ["query", "header"])
async def test_get_capture_lab_grant_and_model_claims_do_not_prove_safe_effects(runtime, tmp_path, shape):
    env, probe = await custom_env(runtime, tmp_path, shape)
    assert env[5].method == "GET" and env[5].baseline_request_ref
    with pytest.raises(ValueError, match="effects context"):
        env[2].generic_validation.bind_probe_context(env[0].get("http"), env[5].id, probe,
            verified_input_only=False)  # Controller has not verified endpoint effects.
    assert (await start(env, probe)).startswith("error:")
    assert (await start(env, {**probe, "harmless": True})).startswith("error:")
    assert not runtime[4] and not env[3].requests


@pytest.mark.parametrize("fault", ["multipart", "gzip", "charset", "binary", "truncated", "missing",
                                   "path", "raw", "DELETE", "PATCH", "PUT", "header-framing"])
async def test_unsupported_encoding_and_capabilities_fail_closed(runtime, tmp_path, fault):
    env, probe = await custom_env(runtime, tmp_path, "header" if fault == "header-framing" else "form")
    http = env[0].get("http")
    row = http.capture_store.get_request("wr:custom-baseline")
    assert row is not None
    if fault in {"multipart", "charset"}:
        for header in row.request_headers or []:
            if header.name.lower() == "content-type":
                header.value = "multipart/form-data; boundary=fixture" if fault == "multipart" else "application/x-www-form-urlencoded; charset=latin1"
    elif fault == "gzip":
        from src.browser.store import CapturedHeader
        assert row.request_headers is not None
        row.request_headers.append(CapturedHeader("Content-Encoding", "gzip"))
    elif fault == "binary":
        row.request_body = {"type": "raw", "data": "invalid\ud800"}
    elif fault == "truncated":
        row.request_body = "term=...<truncated 100 bytes>"
    elif fault == "missing":
        http.capture_store.clear()
    elif fault in {"path", "raw"}:
        env[5].location = probe["location"] = fault
    elif fault in {"DELETE", "PATCH", "PUT"}:
        env[5].method = probe["method"] = fault
    else:
        probe["values"] = ["Lab-A\r\nInjected: yes"]
    with pytest.raises(ValueError):
        bind(env, probe)
    assert (await start(env, probe)).startswith("error:")
    assert not env[2].generic_validation.contexts and not runtime[4]


async def test_inplace_session_restore_invalidates_live_action_context(runtime, tmp_path):
    env, probe = await custom_env(runtime, tmp_path)
    bind(env, probe)
    await start(env, probe)
    raw = env[4].to_dict()
    env[4].replace_from(WorkflowState.from_dict(raw))
    assert env[4].candidates[env[5].id].status == "validating"
    with pytest.raises((ExecutionBlocked, ValueError)):
        await env[0].execute("http", http_args(env, "Lab-A"), None, env[1])
    assert not runtime[4]


async def test_record_more_candidates_keeps_bookkeeping_without_probe_authority(runtime, tmp_path):
    env, _ = await custom_env(runtime, tmp_path)
    output = json.loads(await env[0].execute("workflow", {"action": "record_candidate",
        "candidate_class": "another-custom-class", "method": "GET", "endpoint": "/another?term=base",
        "location": "query", "parameter": "term"}, None, env[1]))
    assert output["candidate"]["status"] == "deferred" and not output["supported"]
    assert len(env[4].candidates) == 2 and not env[2].generic_validation.contexts
    with pytest.raises(ExecutionBlocked):
        await env[0].execute("http", {"url": "/another?term=Lab-A", "phase": "validation"}, None, env[1])
    assert not runtime[4]


@pytest.mark.parametrize("outcome", ["blocked", "confirmed"])
async def test_direct_completion_requires_latest_outcome_matching_certificate(runtime, tmp_path, outcome):
    from tests.security.test_generic_validation import evidence
    env, probe = await custom_env(runtime, tmp_path)
    bind(env, probe)
    await start(env, probe)
    ref = await evidence(env, tmp_path)
    await result(env, refs=[ref])
    app, _ = app_for(env)
    await review_result(app, review_args(env[5], "not-confirmed"))
    assert not agent_for(env)._generic_completion_blockers()
    # A raw restored/latest result cannot borrow the older negative certificate.
    env[4].latest_result(env[5].id).outcome = outcome
    assert agent_for(env)._generic_completion_blockers()


@pytest.mark.parametrize("metadata", [False, True])
async def test_native_compatibility_cannot_probe_generic_without_runtime_policy(runtime, tmp_path, metadata):
    env, _ = await custom_env(runtime, tmp_path)
    env[1].execution_policy = None
    env[0].get("http").validation_registry = env[6].skills if metadata else None
    env[5].objective_id = None
    env[4].objective = WorkflowObjective("explicit", "candidate_validation", ORIGIN, env[5].id)
    with pytest.raises(UserControlledRefusal, match="generic runtime policy"):
        await env[0].get("http").run(http_args(env), None, env[1])
    assert not runtime[4]
