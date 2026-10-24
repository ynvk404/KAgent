"""Production Agent finalization with scripted model and isolated mock transport.

No evaluator, benchmark runner, external model or target is executed.
"""
import asyncio
from copy import deepcopy
from dataclasses import replace
import json

import httpx
import pytest

from benchmarks.scenario1.core.canonical import freeze, inspect_export
from benchmarks.scenario1.core.runtime import execute_case, request_fixture, candidate_arguments
from tests.benchmarks.test_scenario1 import isolated_project_environment, op, settings, mock_http
from tests.benchmarks.test_scenario1_closure import active_case, captured_case, StopClient
from tests.helpers.agent_fakes import FakeClient, FakeSignal, collect
from tests.security.test_execution_policy import REAL_CLIENT
from tests.security.test_execution_policy import runtime
from tests.security.test_agent_assessment import setup as assessment_setup
from tests.security.test_evidence_recovery_contract import agent_for
from src.workflow.assessment import seal
from src.workflow.state import WorkflowState, ValidationResult
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from tests.benchmarks.test_scenario1 import ASSESSMENT


@pytest.mark.parametrize("mode", ["stall", "reader", "mixed"])
async def test_owned_stop_without_declaration_records_unknown_not_false(
        tmp_path, monkeypatch, op, settings, mock_http, mode):
    settings = replace(settings, agent_calls=16, timeout_seconds=60)
    from benchmarks.scenario1.core.runtime import HeadlessPermissions
    if mode in {"reader", "mixed"}:
        monkeypatch.setattr(HeadlessPermissions, "_owned_readback", lambda *_: False)
    op = replace(op, vulnerability_class="sql-injection")
    client = StopClient(mode)
    ex = await execute_case(op, settings, tmp_path, "offline", "execution", client)
    assert ex.stop_reason == ("all_tools_refused" if mode == "reader" else "max_steps")
    assert ex.status == ("completed" if mode == "reader" else "budget-exhausted"), ex.error
    if mode != "reader":
        assert client.step == settings.agent_calls == 16
    assert ex.result is not None and not ex.result["accepted_at_freeze"]
    state = ex.result["workflow"]
    result = state["validation_results"][-1]
    assert result["outcome"] in {"blocked", "insufficient-evidence"}
    assert result["mutation_performed"] is None and result["cleanup_state"] == "unknown"
    attempt = state["attempts"][result["attempt_id"]]
    assert attempt["status"] == "unresolved" and attempt["effects"]["declaration"] is None
    assert all(row["status"] == "completed" and row["observation_id"] for row in attempt["effects"]["dispatches"])
    assert not result["evidence_refs"] and not result["evidence_manifest"] and not state["persisted_findings"]
    assert ex.runtime_metadata["closure_diagnostic"] is None
    assert inspect_export(ex.result, run_id="offline", case_id=op.case_id, execution_id="execution",
                          candidate_args=candidate_arguments(op, settings),
                          target=settings.target + settings.context_path) == (result["outcome"], None)


@pytest.mark.parametrize("mutation,flag,cleanup", [
    ("unknown", None, "unknown"), ("possible", None, "not-attempted"),
    ("reported-write", True, "requires-user-action"),
    ("no-mutation-established", False, "not-required")])
async def test_attempt_declaration_is_independent_of_submission_failure(
        tmp_path, op, settings, mock_http, mutation, flag, cleanup):
    agent, policy, cid, aid, oid = await captured_case(op, settings, tmp_path)
    declared = await agent.tools.execute("workflow", {
        "action": "record_attempt_state", "candidate_id": cid, "attempt_id": aid,
        "mutation_state": mutation, "effect_basis": "Controlled fixture observation; bounded interpretation",
        "observation_ids": [oid], "cleanup_state": cleanup,
        "cleanup_status": "Agent cleanup not attempted; operator action required" if flag else None,
    }, None, agent.prompter)
    assert json.loads(declared)["ok"], declared
    assert not agent.workflow.evidence_recovery and not agent.workflow.validation_results
    events = collect()
    await agent._close_terminal_attempt("max_steps", FakeSignal(), events["sink"], agent.history.copy())
    result = agent.workflow.latest_result(cid)
    assert result is not None and result.attempt_id == aid
    assert result.mutation_performed is flag and result.cleanup_state == cleanup
    assert result.assessment_binding == seal(result) and not agent.workflow.eligible_for_finding(cid)
    assert agent.workflow.attempts[aid]["status"] == "unresolved"
    assert len(mock_http) == 1 and not [e for e in events["events"] if e["type"] == "error"]
    assert policy.session_id is not None
    saved = json.loads((tmp_path / ".kagent/sessions" / (policy.session_id + ".json")).read_text())
    assert saved["workflow"]["validation_results"][-1]["result_id"] == result.result_id


async def test_registered_proof_without_explicit_result_is_not_attached_at_hard_stop(runtime, tmp_path):
    state, candidate, tool, args, _ = await assessment_setup(runtime, tmp_path, candidate_class="sqli")
    agent = agent_for(runtime, tool, state, args, max_steps=1)
    client = FakeClient([ChatResponse(Message("assistant", "", tool_calls=[ToolCall("list", FunctionCall(
        "workflow", json.dumps({"action": "list", "candidate_id": candidate.id})))]), "tool_calls"),
        ChatResponse(Message("assistant", "Bounded fixture remains unresolved."), "stop")])
    agent.set_client(client)
    policy = runtime[2]
    evidence = deepcopy(state.evidence)
    attempts = list(state.attempts)
    rights = policy.engagement.http_permissions
    grants, epoch = dict(rights.grants), rights.epoch
    events = collect()
    await agent.run("Continue current validation.", FakeSignal(), events["sink"])
    assert events["events"][-1]["stop_reason"] == "max_steps"
    result = state.latest_result(candidate.id)
    assert result is not None and result.outcome == "insufficient-evidence"
    assert result.attempt_id is not None and result.attempt_id == args["attempt_id"]
    assert state.attempts[result.attempt_id]["status"] == "unresolved"
    assert candidate.status == "deferred" and not state.eligible_for_finding(candidate.id)
    assert result.mutation_performed is None and result.cleanup_state == "unknown"
    assert not result.evidence_refs and not result.evidence_manifest and state.evidence == evidence
    assert args["evidence_refs"] and list(state.attempts) == attempts and len(runtime[4]) == 1
    assert rights.grants == grants and rights.epoch == epoch
    assert len(client.requests) == 2 and client.requests[-1].tools is None


@pytest.mark.parametrize("cancelled", [False, True])
async def test_failed_or_cancelled_send_has_dispatch_without_fake_observation(
        tmp_path, monkeypatch, op, settings, mock_http, cancelled):
    agent, policy, cid, aid = await active_case(op, settings, tmp_path)
    async def fail(request):
        if cancelled:
            raise asyncio.CancelledError()
        raise httpx.ReadError("controlled transport failure")
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(fail), **kw))
    with pytest.raises(asyncio.CancelledError if cancelled else httpx.ReadError):
        await agent.tools.execute("http", request_fixture(op, settings), None, agent.prompter)
    rows = agent.workflow.attempts[aid]["effects"]["dispatches"]
    assert len(rows) == 1 and rows[0]["invocation_id"] and rows[0]["request_hash"]
    assert rows[0]["status"] == ("cancelled" if cancelled else "failed")
    assert rows[0]["observation_id"] is None and not policy.observations._items
    # A later explicit terminal stop reports uncertainty; cancellation itself
    # does not invoke closure or create a result.
    assert not agent.workflow.validation_results
    await agent._close_terminal_attempt("max_steps", FakeSignal(), collect()["sink"], agent.history.copy())
    result = agent.workflow.latest_result(cid)
    assert result is not None and result.mutation_performed is None


@pytest.mark.parametrize("fault", ["missing-ledger", "in-flight", "foreign-owner", "tool-budget"])
async def test_genuine_closure_failure_keeps_incomplete_state(tmp_path, op, settings, mock_http, fault):
    agent, policy, cid, aid = await active_case(op, settings, tmp_path)
    attempt = agent.workflow.attempts[aid]
    if fault == "missing-ledger":
        del attempt["effects"]
    elif fault == "in-flight":
        attempt["effects"]["dispatches"].append({"invocation_id": "controlled-in-flight",
            "request_hash": "a" * 64, "status": "dispatched", "observation_id": None})
    elif fault == "foreign-owner":
        attempt["session_id"] = "foreign-session"
    else:
        policy.max_calls = policy.used
    events = collect()
    await agent._close_terminal_attempt("max_steps", FakeSignal(), events["sink"], agent.history.copy())
    assert attempt["status"] == "active" and not agent.workflow.validation_results
    assert any(e["type"] == "error" for e in events["events"])
    assert mock_http == []


async def test_duplicate_closure_and_historical_round_trip(tmp_path, op, settings, mock_http):
    agent, policy, cid, aid = await active_case(op, settings, tmp_path)
    events = collect()
    await asyncio.gather(*[agent._close_terminal_attempt("max_steps", FakeSignal(),
        events["sink"], agent.history.copy()) for _ in range(2)])
    assert len(agent.workflow.validation_results) == 1
    assert not [e for e in events["events"] if e["type"] == "error"]
    result = agent.workflow.latest_result(cid)
    assert result is not None and result.mutation_performed is False
    before = deepcopy(agent.workflow.to_dict())
    assert freeze("offline", op.case_id, "execution", policy.session_id, cid,
                  agent.workflow, policy, agent.target)["workflow"] == before
    assert WorkflowState.from_dict(before).to_dict() == before
    historical = ValidationResult("historical", "sql-injection", "insufficient-evidence").to_dict()
    assert historical["mutation_performed"] is False
    restored = ValidationResult.from_dict(historical)
    assert restored is not None and restored.to_dict() == historical


async def test_retest_cannot_erase_prior_acknowledged_write(tmp_path, op, settings, mock_http):
    agent, policy, cid, old_attempt, oid = await captured_case(op, settings, tmp_path)
    assert json.loads(await agent.tools.execute("workflow", {"action": "record_attempt_state",
        "candidate_id": cid, "mutation_state": "reported-write", "effect_basis": "Controlled write acknowledgement",
        "observation_ids": [oid], "cleanup_state": "requires-user-action",
        "cleanup_status": "Agent cleanup not performed; operator action required"}, None, agent.prompter))["ok"]
    await agent._close_terminal_attempt("max_steps", FakeSignal(), collect()["sink"], agent.history.copy())
    started = json.loads(await agent.tools.execute("workflow", {"action": "start_validation", "candidate_id": cid}, None, agent.prompter))
    assert started["ok"] and policy.generic_validation.durable_attempt != old_attempt
    denied = await agent.tools.execute("workflow", {"action": "record_result", "candidate_id": cid,
        "skill_name": op.vulnerability_class, "outcome": "insufficient-evidence", "mutation_performed": False,
        "deferred_reason": "No current dispatch"}, None, agent.prompter)
    assert denied.startswith("error:") and len(agent.workflow.validation_results) == 1
    await agent._close_terminal_attempt("max_steps", FakeSignal(), collect()["sink"], agent.history.copy())
    latest = agent.workflow.latest_result(cid)
    assert latest is not None
    assert latest.mutation_performed is True and latest.cleanup_state == "requires-user-action"
    assert latest.attempt_id != old_attempt and not latest.evidence_manifest and len(mock_http) == 1


@pytest.mark.parametrize("cleanup", ["unknown", "not-attempted"])
async def test_unresolved_effect_states_block_whole_target_completion(runtime, tmp_path, cleanup):
    registry, prompter, policy, *_ = runtime
    state, candidate, tool, args, _ = await assessment_setup(runtime, tmp_path)
    result = json.loads(await registry.execute("workflow", {**args, "outcome": "not-confirmed",
        "mutation_performed": None, "cleanup_state": cleanup}, None, prompter))
    assert result["ok"]
    status, _, blockers = state.whole_target_status(target_origin=candidate.target,
        available_phases=frozenset(), validator_classes=frozenset({candidate.candidate_class}),
        coverage_sync_available=True,
        validation_errors={candidate.id: state.validation_completion_error(candidate.id,
            evidence_root=tmp_path, target_origin=candidate.target, policy=policy)})
    assert status != "completed" and any("effects/cleanup unresolved" in b for b in blockers)


@pytest.mark.parametrize("skill", ["sql-injection", "cross-site-scripting"])
async def test_repetition_can_finish_proof_result_within_original_budget(
        tmp_path, monkeypatch, op, settings, mock_http, skill):
    settings = replace(settings, timeout_seconds=60)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: REAL_CLIENT(
        transport=httpx.MockTransport(lambda req: (mock_http.append(req) or httpx.Response(200, content=b"same", request=req))), **kw))
    class Finalize(StopClient):
        def __init__(self):
            super().__init__("stall")
            self.skill = skill
            self.final_step = 0
        async def chat(self, request, signal=None):
            response = await super().chat(request, signal)
            if self.step <= 16:
                return response
            self.final_step += 1
            if self.final_step <= 3:
                assert any(spec["function"]["name"] == "http" for spec in request.tools or [])
            if self.final_step == 1:
                return self.tool("file_write", {"path": str(tmp_path / "artifacts/proof.md"), "content": "Controlled baseline/controls returned identical fixture responses."})
            if self.final_step == 2:
                return self.tool("workflow", {"action": "record_evidence", "candidate_id": self.candidate,
                    "evidence_path": "artifacts/proof.md", "observation_ids": self.observations})
            if self.final_step == 3:
                return self.tool("workflow", {"action": "record_result", "candidate_id": self.candidate,
                    "skill_name": skill, "outcome": "not-confirmed", "mutation_performed": False,
                    "evidence_refs": [self.evidence], "observation_ids": self.observations, "assessment": ASSESSMENT})
            return ChatResponse(Message("assistant", "Bounded fixture negative recorded."), "stop")
    op = replace(op, vulnerability_class=skill)
    client = Finalize()
    ex = await execute_case(op, settings, tmp_path, "offline", "finalize", client)
    assert ex.result is not None
    assert ex.status == "completed" and ex.result["accepted_at_freeze"], ex.error
    result = ex.result["workflow"]["validation_results"][-1]
    attempt = ex.result["workflow"]["attempts"][result["attempt_id"]]
    assert not attempt.get("probing_stopped") and attempt["status"] == "completed"
    assert result["outcome"] == "not-confirmed" and result["evidence_manifest"] and result["evidence_refs"]
    assert len(mock_http) == 14 and client.step == 20 < settings.agent_calls


async def test_owned_inventory_timing_and_foreign_isolation(tmp_path, op, settings, mock_http):
    first, policy, cid, aid, oid = await captured_case(op, settings, tmp_path / "first")
    _, other_policy, _, _, foreign = await captured_case(op, settings, tmp_path / "second")
    policy.observations._items[foreign] = other_policy.observations._items[foreign]
    before = len(mock_http)
    listing = json.loads(await first.tools.execute("workflow", {"action": "list", "candidate_id": cid}, None, first.prompter))
    assert [r["observation_id"] for r in listing["observations"]] == [oid]
    row = listing["observations"][0]
    assert row["attempt_id"] == aid and row["elapsed_ms"] >= 0 and "body" not in row
    read = await first.tools.execute("read_http_observation", {"observation_id": oid, "start_char": 0, "max_chars": 100}, None, first.prompter)
    assert json.loads(read.split("\n", 1)[0])["elapsed_ms"] == row["elapsed_ms"]
    assert len(mock_http) == before


async def test_nonexistent_reference_can_repair_without_http(tmp_path, op, settings, mock_http):
    from src.tools.common.tool_result import HTTPObservationUnavailable
    agent, policy, cid, _, oid = await captured_case(op, settings, tmp_path)
    with pytest.raises(HTTPObservationUnavailable):
        await agent.tools.execute("read_http_observation", {"observation_id": "obs_" + "f" * 32,
            "start_char": 0, "max_chars": 100}, None, agent.prompter)
    listing = json.loads(await agent.tools.execute("workflow", {"action": "list", "candidate_id": cid}, None, agent.prompter))
    assert listing["observations"][0]["observation_id"] == oid
    await agent.tools.execute("read_http_observation", {"observation_id": oid, "start_char": 0, "max_chars": 100}, None, agent.prompter)
    assert len(mock_http) == 1


async def test_headless_unavailable_is_not_operator_denial(tmp_path, op, settings, mock_http):
    ex = await execute_case(op, settings, tmp_path, "offline", "input", StopClient("unavailable"))
    assert ex.result is not None and ex.runtime_metadata is not None
    assert ex.status == "completed" and ex.stop_reason == "workflow_blocked"
    result = ex.result["workflow"]["validation_results"][-1]
    assert result["outcome"] == "blocked" and "operator-input-unavailable" in result["deferred_reason"]
    assert result["mutation_performed"] is False and not mock_http
    session = json.loads((tmp_path / ".kagent/sessions" / (ex.runtime_metadata["session_id"] + ".json")).read_text())
    errors = [m["tool_error_kind"] for m in session["messages"] if m.get("name") == "ask_user"]
    assert errors == ["input_unavailable"] and not ex.result["accepted_at_freeze"]


@pytest.mark.parametrize("tool_budget", [80, 3])
async def test_iteration_budget_closes_only_with_remaining_registry_quota(tmp_path, op, settings, mock_http, tool_budget):
    settings = replace(settings, agent_calls=2, tool_calls=tool_budget)
    client = StopClient("stall")
    ex = await execute_case(op, settings, tmp_path, "offline", "budget", client)
    assert ex.result is not None and ex.runtime_metadata is not None
    assert ex.metrics is not None
    assert ex.status == "budget-exhausted" and ex.stop_reason == "max_steps"
    assert ex.metrics["llm"]["agent_loop_llm_calls"] == 2
    assert ex.metrics["llm"]["final_synthesis_llm_calls"] == 1 and not mock_http
    results = ex.result["workflow"]["validation_results"]
    if tool_budget == 80:
        assert results[-1]["outcome"] == "insufficient-evidence"
        assert ex.result["workflow"]["attempts"][results[-1]["attempt_id"]]["status"] == "unresolved"
    else:
        assert not results and ex.runtime_metadata["closure_diagnostic"] == "active-case-attempt-without-closure"


async def test_candidate_validation_rejects_other_input_without_queue_mutation(tmp_path, op, settings, mock_http):
    agent, _, cid, _ = await active_case(op, settings, tmp_path)
    before = deepcopy(agent.workflow.to_dict())
    result = await agent.tools.execute("workflow", {"action": "record_candidate",
        **{**candidate_arguments(op, settings), "endpoint": "/benchmark/other"}}, None, agent.prompter)
    assert "OBJECTIVE_CANDIDATE_MISMATCH" in result
    assert agent.workflow.to_dict() == before and len(agent.workflow.candidates) == 1 and not mock_http


async def test_reported_verified_write_and_cleanup_need_owned_readback(runtime, tmp_path, monkeypatch):
    registry, prompter, policy, _, sent, _, target = runtime
    rows = {"count": 0}
    def handler(req):
        sent.append(req)
        if req.url.path == "/fixture":
            rows["count"] += 1
            body = "Update complete; created fixture resource"
        elif req.method == "DELETE":
            rows["count"] = 0
            body = "Fixture resource removed"
        else:
            body = json.dumps(rows)
        return httpx.Response(200, content=body.encode(), request=req)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler), **kw))
    state, candidate, tool, args, write = await assessment_setup(runtime, tmp_path, candidate_class="sqli", related=[
        {"role": "cleanup", "method": "DELETE", "url": "/resource", "required": False},
        {"role": "readback", "method": "GET", "url": "/verify"},
    ])
    declaration = {"action": "record_attempt_state", "candidate_id": candidate.id,
        "mutation_state": "reported-write", "effect_basis": "Owned baseline reports successful resource creation",
        "observation_ids": [write], "cleanup_state": "not-attempted", "cleanup_status": "Agent cleanup not attempted"}
    assert json.loads(await registry.execute("workflow", declaration, None, prompter))["ok"]
    before = deepcopy(state.to_dict())
    for update in [{"mutation_state": "no-mutation-established"}, {"mutation_state": "verified-write"},
                   {"cleanup_state": "succeeded", "cleanup_status": "resource deletion verified"}]:
        result = await registry.execute("workflow", {**declaration, **update}, None, prompter)
        assert result.startswith("error:") and state.to_dict() == before
    await registry.execute("http", {"url": "/verify", "phase": "validation"}, None, prompter)
    verify_write = next(reversed(policy.observations._items))
    assert rows["count"] == 1
    declaration.update(mutation_state="verified-write", observation_ids=[write, verify_write],
                       effect_basis="Independent owned readback verifies the created fixture resource")
    assert json.loads(await registry.execute("workflow", declaration, None, prompter))["ok"]
    # This isolated fixture explicitly supplies cleanup intent and its normal
    # per-action runtime authority; an acknowledgement did not grant it.
    await registry.execute("http", {"url": "/resource", "method": "DELETE", "phase": "impact"}, None, prompter)
    cleanup = next(reversed(policy.observations._items))
    await registry.execute("http", {"url": "/verify", "phase": "validation"}, None, prompter)
    verify_cleanup = next(reversed(policy.observations._items))
    assert rows["count"] == 0
    declaration.update(observation_ids=[write, verify_write, cleanup, verify_cleanup],
        cleanup_state="succeeded", cleanup_status="Agent cleanup performed; subsequent owned readback verifies removal")
    assert json.loads(await registry.execute("workflow", declaration, None, prompter))["ok"]
    agent = agent_for(runtime, tool, state, args)
    await agent._close_terminal_attempt("max_steps", FakeSignal(), collect()["sink"], agent.history.copy())
    latest = state.latest_result(candidate.id)
    assert latest is not None
    assert latest.outcome == "insufficient-evidence" and latest.mutation_performed is True
    assert latest.cleanup_state == "succeeded" and latest.assessment_binding == seal(latest)
    assert [e["source"]["id"] for e in latest.evidence_manifest] == declaration["observation_ids"]
    assert not state.persisted_findings and len(sent) == 4


async def test_dispatch_overlap_and_task_cancellation_preserve_uncertainty(tmp_path, monkeypatch, op, settings, mock_http):
    agent, policy, cid, aid, oid = await captured_case(op, settings, tmp_path)
    declaration = {"action": "record_attempt_state", "candidate_id": cid,
        "mutation_state": "no-mutation-established", "effect_basis": "Completed controlled stateless fixture",
        "observation_ids": [oid]}
    assert json.loads(await agent.tools.execute("workflow", declaration, None, agent.prompter))["ok"]
    started, release = asyncio.Event(), asyncio.Event()
    async def held(request):
        started.set()
        await release.wait()
        return httpx.Response(200, content=b"fixture", request=request)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(held), **kw))
    task = asyncio.create_task(agent.tools.execute("http", request_fixture(op, settings), None, agent.prompter))
    try:
        await asyncio.wait_for(started.wait(), 2)
        attempt = agent.workflow.attempts[aid]
        assert attempt["effects"]["declaration"] is None
        fact = attempt["effects"]["dispatches"][-1]
        assert fact["status"] == "dispatched" and fact["observation_id"] is None
        assert fact["admission_id"] in {row["invocation_id"] for row in attempt["effects"]["admissions"]}
        result_args = {"action": "record_result", "candidate_id": cid, "skill_name": op.vulnerability_class,
            "outcome": "insufficient-evidence", "deferred_reason": "Controlled stop", "mutation_performed": False}
        for args in (declaration, result_args):
            assert (await agent.tools.execute("workflow", args, None, agent.prompter)).startswith("error:")
        assert attempt["status"] == "active" and not agent.workflow.validation_results
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert fact["status"] == "cancelled" and fact["observation_id"] is None
    assert len(policy.observations._items) == 1 and policy.active == 0
    for args in (declaration, result_args):
        assert (await agent.tools.execute("workflow", args, None, agent.prompter)).startswith("error:")
    await agent._close_terminal_attempt("max_steps", FakeSignal(), collect()["sink"], agent.history.copy())
    result = agent.workflow.latest_result(cid)
    assert result is not None and result.mutation_performed is None


async def test_adapter_admission_invalidates_prior_no_write_declaration(runtime, tmp_path):
    registry, prompter, policy, _, sent, _, _ = runtime
    state, candidate, _, _, oid = await assessment_setup(runtime, tmp_path)
    assert candidate.target is not None
    assert json.loads(await registry.execute("workflow", {"action": "record_attempt_state",
        "candidate_id": candidate.id, "mutation_state": "no-mutation-established",
        "effect_basis": "Controlled fixture had no persistent effect", "observation_ids": [oid]}, None, prompter))["ok"]
    await registry.execute("web_fetch", {"url": candidate.target + "/fixture"}, None, prompter)
    attempt = state.attempts[policy.generic_validation.durable_attempt]
    assert [row["tool"] for row in attempt["effects"]["admissions"]] == ["http", "web_fetch"]
    assert attempt["effects"]["declaration"] is None
    assert len(sent) == 2


async def test_inventory_pagination_revocation_and_epoch_do_not_dispatch(tmp_path, op, settings, mock_http):
    agent, policy, cid, _, oid = await captured_case(op, settings, tmp_path)
    for _ in range(2):
        await agent.tools.execute("http", request_fixture(op, settings), None, agent.prompter)
    ids = list(policy.observations._items)
    found, offset = [], 0
    while offset is not None:
        page = json.loads(await agent.tools.execute("workflow", {"action": "list", "candidate_id": cid,
            "limit": 1, "observation_offset": offset}, None, agent.prompter))
        assert page["observations_total"] == 3
        found.extend(row["observation_id"] for row in page["observations"])
        offset = page["next_observation_offset"]
    assert found == ids and oid in found and len(mock_http) == 3
    policy.revoked.add("read_http_observation")
    page = json.loads(await agent.tools.execute("workflow", {"action": "list", "candidate_id": cid}, None, agent.prompter))
    assert all(not row["read_available"] for row in page["observations"])
    policy.engagement.http_permissions.epoch = "changed-controller-epoch"
    page = json.loads(await agent.tools.execute("workflow", {"action": "list", "candidate_id": cid}, None, agent.prompter))
    assert not page["observations"] and len(mock_http) == 3


async def test_retry_preserves_effects_when_same_submission_omits_legacy_fields(tmp_path, op, settings, mock_http):
    agent, _, cid, _, oid = await captured_case(op, settings, tmp_path)
    assert json.loads(await agent.tools.execute("workflow", {"action": "record_attempt_state",
        "candidate_id": cid, "mutation_state": "reported-write", "effect_basis": "Controlled write acknowledgement",
        "observation_ids": [oid], "cleanup_state": "requires-user-action",
        "cleanup_status": "Agent cleanup not performed; operator action required"}, None, agent.prompter))["ok"]
    args = {"action": "record_result", "candidate_id": cid, "skill_name": op.vulnerability_class,
        "outcome": "insufficient-evidence", "deferred_reason": "No completed vulnerability proof",
        "observation_ids": [oid]}
    first = json.loads(await agent.tools.execute("workflow", args, None, agent.prompter))
    retry = json.loads(await agent.tools.execute("workflow", args, None, agent.prompter))
    assert first["ok"] and retry["ok"] and not retry["created"]
    assert len(agent.workflow.validation_results) == 1
    result = agent.workflow.latest_result(cid)
    assert result is not None and result.mutation_performed is True and len(mock_http) == 1


async def test_admitted_http_waiting_before_handoff_cannot_be_closed(tmp_path, monkeypatch, op, settings, mock_http):
    agent, policy, cid, aid = await active_case(op, settings, tmp_path)
    held, release = asyncio.Event(), asyncio.Event()
    async def pending(*args, **kwargs):
        held.set()
        await release.wait()
        raise AssertionError("controlled pending admission must be cancelled")
    monkeypatch.setattr(policy.engagement.http_permissions, "reserve_when_ready", pending)
    task = asyncio.create_task(agent.tools.execute("http", request_fixture(op, settings), None, agent.prompter))
    try:
        await asyncio.wait_for(held.wait(), 2)
        attempt = agent.workflow.attempts[aid]
        assert len(attempt["effects"]["admissions"]) == 1 and not attempt["effects"]["dispatches"]
        events = collect()
        await agent._close_terminal_attempt("max_steps", FakeSignal(), events["sink"], agent.history.copy())
        assert attempt["status"] == "active" and not agent.workflow.validation_results
        assert any(e["type"] == "error" for e in events["events"])
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert not mock_http and policy.active == 0
    await agent._close_terminal_attempt("max_steps", FakeSignal(), collect()["sink"], agent.history.copy())
    result = agent.workflow.latest_result(cid)
    assert result is not None and result.mutation_performed is False
