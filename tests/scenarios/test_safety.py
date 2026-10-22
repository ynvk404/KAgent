"""M2 production Agent rejection -> repair/closure; no fabricated authority."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
import socket

import httpx
import pytest

from src.coverage.store import CoverageStore
from src.findings.store import read_report
from tests.helpers.scenarios import (
    dedicated_validation, direct_script, receipt, record_candidate,
)
from tests.scenarios.test_happy_paths import definition


def protected(runtime):
    state = runtime.workflow
    return deepcopy({"attempts": state.attempts, "candidates": [c.to_dict() for c in state.candidates.values()],
        "results": [r.to_dict() for r in state.validation_results], "evidence": state.evidence,
        "sources": state.selected_sources, "parents": state.evidence_sources,
        "findings": state.persisted_findings, "owner": runtime.policy.generic_validation.durable_attempt,
        "observations": runtime.policy.observations._items, "sent": runtime.scenario_transport.sent})


def rejected(runtime, name, args, reason, *, kind="workflow_state", presend_admission=False):
    before = protected(runtime)
    call_id = f"{runtime.scenario_model.prefix}-{len(runtime.scenario_model.calls) + 1}"
    runtime.scenario_errors[call_id] = (name, reason, kind)
    output = yield name, args
    assert reason in output, output
    after = protected(runtime)
    if presend_admission:
        assert name == "http" and kind == "policy_block" and after["owner"] == before["owner"]
        aid = before["owner"]
        old_effects = before["attempts"][aid]["effects"]
        new_effects = after["attempts"][aid]["effects"]
        old_admissions, new_admissions = old_effects["admissions"], new_effects["admissions"]
        assert len(new_admissions) == len(old_admissions) + 1 and new_admissions[:-1] == old_admissions
        assert new_admissions[-1] == {"tool": "http", "invocation_id": runtime.scenario_presend_receipt_id}
        assert not old_effects["dispatches"] and not new_effects["dispatches"]
        assert old_effects["declaration"] == new_effects["declaration"]
        # Normalize only the exactly attested, non-dispatched admission delta;
        # every other ledger, owner, capture and wire field remains protected.
        new_effects["admissions"] = old_admissions
    assert after == before, "rejection changed protected ledger/ownership/HTTP"
    runtime.scenario_snapshots.append((call_id, before))
    return output


def unresolved_closures(run, aid):
    """Bind action, receipt and canonical disposition without opaque ID prefixes."""
    state = run.runtime.workflow
    attempt = state.attempts[aid]
    result = state.latest_result(attempt["candidate_id"])
    assert result and result.attempt_id == aid and result.outcome == "insufficient-evidence"
    assert attempt["status"] == "unresolved" and state.candidates[result.candidate_id].status == "deferred"
    bound = result.to_dict().copy()
    for key in ("assessment_binding", "coverage_synced", "cleanup_state", "cleanup_status"):
        bound.pop(key, None)
    from tests.helpers.scenario_oracle import canonical_hash
    assert result.assessment_binding == canonical_hash(bound)
    calls = {e["id"] for e in run.trace.events if e["type"] == "tool-call" and e["name"] == "workflow"
             and e["args"].get("action") == "record_result" and e["args"].get("attempt_id") == aid
             and e["args"].get("candidate_id") == result.candidate_id
             and e["args"].get("outcome") == "insufficient-evidence"}
    closures = [e for e in run.trace.events if e["type"] == "tool-result" and e["id"] in calls]
    assert len(closures) == 1 and closures[0]["status"] == "success"
    payload = json.loads(closures[0]["result"])
    assert payload["ok"] and payload["result"]["result_id"] == result.result_id
    assert payload["result"]["attempt_id"] == aid and payload["result"]["assessment_binding"] == result.assessment_binding
    return closures


async def safety_outcomes(run):
    """Independent M2 contract; every expected error is attached to one call ID."""
    runtime, expected = run.runtime, run.definition.expected
    assert not run.model.errors, repr(run.model.errors)
    if run.definition.expected_stop is None and run.model.runtime_stop is None:
        assert run.model.consumed
    elif run.definition.expected_stop is not None:
        assert len(run.model.calls) == run.definition.expected_stop[0]
    else:
        count, aid = run.model.runtime_stop
        assert len(run.model.calls) == count
        unresolved_closures(run, aid)
        assert runtime.workflow.validation_results[-1].outcome == "insufficient-evidence"
    assert not run.trace.errors, run.trace.errors
    assert not run.transport.errors, run.transport.errors
    assert len(run.transport.sent) == len(run.transport.expected)
    events = [e for e in run.trace.events if e["type"] == "tool-result"]
    scripted = [e for e in events if e["id"].startswith(run.model.prefix + "-")]
    assert len(scripted) == len(run.model.calls)
    seen = set()
    for event in events:
        wanted = runtime.scenario_errors.get(event["id"])
        if wanted:
            name, reason, kind = wanted
            assert event["name"] == name and reason in event["result"], event
            assert event["status"] in {"error", "pending"}, event
            if kind is not None:
                assert event["error_kind"] == kind, event
            seen.add(event["id"])
        else:
            assert event["status"] in {"success", "observation"} and not event["err"] and not event["error_kind"], event
    assert seen == set(runtime.scenario_errors)
    errors = [e["err"] for e in run.trace.events if e["type"] == "error"]
    assert len(errors) == len(runtime.scenario_agent_errors), errors
    for actual, wanted in zip(errors, runtime.scenario_agent_errors):
        assert wanted in actual
    state = runtime.workflow
    assert state.objective and state.objective.target_origin == run.definition.origin
    assert state.validation_results and state.validation_results[-1].outcome == expected.outcome
    assert run.oracle.independently_complete(runtime) is expected.complete
    reports = list((runtime.policy.root / "artifacts/findings").glob("*.md"))
    assert len(reports) == expected.findings
    for path in reports:
        report = read_report(path)
        result = state.latest_result(report.candidate_id)
        assert result and report.assessment_result_id == result.result_id
        assert report.assessment_attempt_id == result.attempt_id
        assert report.evidence_refs == result.evidence_refs
        assert state.finding_is_persisted(report.candidate_id)
    disk_rows = await CoverageStore(str(runtime.coverage.path)).list()
    terminal = [r for r in state.validation_results if r.outcome in {"confirmed", "not-confirmed"}]
    for result in terminal:
        for entry in result.evidence_manifest:
            source = entry["source"]
            matches = []
            for request, response in run.transport.expected:
                native = httpx.Request(request["method"], run.definition.origin + request["url"], content=request.get("body", ""))
                if source["url"] == str(native.url) and source["method"] == native.method:
                    matches.append(response)
            assert matches and (source["status"], bytes.fromhex(source["body"])) in [(status, body) for status, body, _ in matches]
    assert len(disk_rows) == len({r.candidate_id for r in terminal if r.coverage_synced})
    assert all(row.count == 1 for row in disk_rows)
    done = [e for e in run.trace.events if e["type"] == "done"]
    assert len(done) == 1
    if run.definition.expected_stop is not None:
        assert done[0]["stop_reason"] == run.definition.expected_stop[1]
    assert done[0]["stop_reason"] in ({"final_response", "workflow_completed"} if expected.complete
        else {"workflow_blocked", "workflow_stalled", "max_steps", "all_tools_refused"})
    saved = json.loads(runtime.store.path.read_text())["workflow"]
    # Actual production checkpoints, without a harness save or flush.
    for field in ("attempts", "validation_results", "evidence", "persisted_findings", "candidates", "objective",
                  "selected_sources", "evidence_sources"):
        assert saved[field] == state.to_dict()[field], field
    assert not runtime.agent.running and not runtime.agent._background_tasks
    assert runtime.coverage.saving is None or runtime.coverage.saving.done()
    assert run.elapsed <= run.definition.timeout


def safety_definition(id, script, **kwargs):
    return replace(definition(id=id, **kwargs), script=script, verify=safety_outcomes, checkpoint=False,
                   max_steps=40, max_calls=60)


def close(runtime, cid, aid, reason="Bounded comparison unavailable; keep outstanding work."):
    return receipt((yield "workflow", {"action": "record_result", "candidate_id": cid,
        "attempt_id": aid, "skill_name": "sql-injection", "outcome": "insufficient-evidence",
        "deferred_reason": reason}))


def conflict_script(runtime, scenario):
    yield "load_skill", {"name": "sql-injection"}
    a = receipt((yield "workflow", {**record_candidate(scenario), "endpoint": "/pending-review"}))["candidate"]["id"]
    b = receipt((yield "workflow", record_candidate(scenario)))["candidate"]["id"]
    started = receipt((yield "workflow", {"action": "start_validation", "candidate_id": a}))
    aid = started["validation_context"]["attempt_id"]
    yield from rejected(runtime, "workflow", {"action": "start_validation", "candidate_id": b}, "another validation attempt is active")
    yield from close(runtime, a, aid)
    assert runtime.workflow.attempts[aid]["status"] == "unresolved"
    assert runtime.workflow.candidates[a].status == "deferred"
    yield from dedicated_validation(runtime, scenario, b, skill_loaded=True)
    result = runtime.workflow.latest_result(b)
    assert result.attempt_id != aid
    assert all(e["source"]["candidate_id"] == b for e in result.evidence_manifest)
    assert runtime.workflow.latest_result(a).outcome == "insufficient-evidence"
    assert runtime.agent._validation_completion_blockers()


async def test_s01_conflict_honest_closure_and_independent_owner(scenario_runner):
    scenario = safety_definition("S01", conflict_script)
    scenario = replace(scenario, expected=replace(scenario.expected, complete=False))
    await scenario_runner.run(scenario)


def enrichment_script(runtime, scenario):
    original = direct_script(runtime, scenario)
    feedback = None
    enriched = False
    while True:
        try:
            name, args = next(original) if feedback is None else original.send(feedback)
        except StopIteration:
            return
        feedback = yield name, args
        if name == "workflow" and args["action"] == "start_validation" and not enriched:
            enriched = True
            cid, aid = args["candidate_id"], receipt(feedback)["validation_context"]["attempt_id"]
            repeated = receipt((yield name, args))
            assert repeated["validation_context"]["attempt_id"] == aid and len(runtime.workflow.attempts) == 1
            annotated = receipt((yield "workflow", {**record_candidate(scenario), "signals": ["Annotation only"]}))
            assert annotated["candidate"]["id"] == cid and not annotated["created"]
            change = {**record_candidate(scenario), "request_template": "category={INJECTION_POINT}"}
            yield from rejected(runtime, "workflow", change, "active validation request context cannot change")
            yield from close(runtime, cid, aid)
            receipt((yield "workflow", change))
            restarted = receipt((yield name, args))
            assert restarted["validation_context"]["attempt_id"] != aid
            # The original validation generator consumes the new real receipt.
            feedback = json.dumps(restarted)


async def test_s02_same_binding_repeat_annotations_and_explicit_restart(scenario_runner):
    await scenario_runner.run(safety_definition("S02", enrichment_script))


def misuse_script(runtime, scenario, evidence_fault):
    original = direct_script(runtime, scenario)
    feedback = None
    while True:
        try:
            name, args = next(original) if feedback is None else original.send(feedback)
        except StopIteration:
            return
        if name == "workflow" and args["action"] == "record_candidate":
            yield from rejected(runtime, "unknown_scenario_tool", {}, "unknown tool", kind="tool_exception")
            yield from rejected(runtime, name, '{"action":"record_candidate",', "could not parse arguments", kind="invalid_args")
            yield from rejected(runtime, name, {**args, "objective_id": "model-owner"}, "objective_id is assigned by the runtime", kind="invalid_args")
            yield from rejected(runtime, name, {**args, "status": "validating"}, "validating is runtime-owned")
        if name == "workflow" and args["action"] == "start_validation":
            error = yield from rejected(runtime, name, {**args, "candidate_id": "cand_unknown"}, "unknown candidate", kind="invalid_args")
            diagnostic = json.loads(error.split("\n", 1)[1])["error"]
            assert diagnostic["code"] == "UNKNOWN_CANDIDATE" and diagnostic["category"] == "argument_error"
            assert "list" in diagnostic["next_action"]
        if name == "workflow" and args["action"] == "record_evidence":
            if evidence_fault == "unavailable-source":
                yield from rejected(runtime, name, {**args, "observation_ids": ["obs_" + "f" * 32]}, "primary evidence reference unavailable")
            yield from rejected(runtime, name, {**args, "attempt_id": "model-owner"}, "does not accept attempt_id", kind="invalid_args")
        if name == "workflow" and args["action"] == "record_result":
            if evidence_fault == "wrong-attempt":
                yield from rejected(runtime, name, {**args, "attempt_id": "attempt_unknown"}, "stale/wrong attempt identity")
            elif evidence_fault == "wrong-proof":
                yield from rejected(runtime, name, {**args, "evidence_refs": ["ev_unknown"]}, "evidence references must resolve to this candidate")
        feedback = yield name, args


@pytest.mark.parametrize("cls,method,endpoint,parameter,value,outcome", [
    ("sql-injection", "GET", "/filter", "category", "Gifts", "confirmed"),
    ("cross-site-scripting", "POST", "/preview", "template", "plain-marker", "not-confirmed"),
])
@pytest.mark.parametrize("evidence_fault", ["unavailable-source", "wrong-attempt", "wrong-proof"])
async def test_s03_s15_wrong_ids_raw_json_reserved_fields_then_corrected_proof(
        scenario_runner, cls, method, endpoint, parameter, value, outcome, evidence_fault):
    # Each evidence fault gets its own production attempt and one corrected
    # submission. Multiple rejected repairs in one attempt must exhaust the
    # budget, covered by the recovery contract instead of bypassed here.
    def script(runtime, scenario):
        return misuse_script(runtime, scenario, evidence_fault)
    await scenario_runner.run(safety_definition("S03-S15-" + cls + '-' + evidence_fault, script,
        cls=cls, method=method, endpoint=endpoint, parameter=parameter, value=value, outcome=outcome))


def revoke_script(runtime, scenario):
    original = direct_script(runtime, scenario)
    feedback = None
    revoked = False
    while True:
        try:
            name, args = next(original) if feedback is None else original.send(feedback)
        except StopIteration:
            return
        if name == "http" and not revoked:
            revoked = True
            permissions = runtime.engagement.http_permissions
            grant = next(iter(permissions.grants.values()))
            epoch, revision = permissions.epoch, permissions.revision
            runtime.scenario_trace.record({"type": "controller", "action": "operator-revoke", "origin": scenario.origin})
            permissions.revoke(grant.id)
            assert permissions.epoch == epoch and permissions.revision > revision
            for _ in range(2):
                yield from rejected(runtime, name, args, "revoked", kind="policy_block")
            assert not runtime.operator.requests or all(r.tool != "http" for r in runtime.operator.requests)
            runtime.scenario_trace.record({"type": "controller", "action": "operator-retry", "origin": scenario.origin})
            permissions.retry(scenario.origin)
            from src.permission.network.grants import HTTPLimits
            permissions.activate(scenario.origin, HTTPLimits(requests=7, rate=1000, burst=100))
        feedback = yield name, args


@pytest.mark.parametrize("yolo", [False, True], ids=["review", "yolo"])
async def test_s05_sticky_revoke_model_retry_and_operator_reopening(scenario_runner, yolo):
    await scenario_runner.run(replace(safety_definition("S05-" + str(yolo), revoke_script), yolo=yolo))


async def test_s05_session_denial_never_reopens_from_model_retries(scenario_runner):
    def script(runtime, scenario):
        original = direct_script(runtime, scenario)
        feedback = None
        denied = False
        while True:
            try:
                name, args = next(original) if feedback is None else original.send(feedback)
            except StopIteration:
                return
            if name == "http" and not denied:
                denied = True
                permissions = runtime.engagement.http_permissions
                runtime.scenario_trace.record({"type": "controller", "action": "operator-deny-session"})
                permissions.deny_session()
                for _ in range(2):
                    yield from rejected(runtime, name, args, "network/session-revoked", kind="policy_block")
                    assert permissions.denied and not permissions.grants
                runtime.scenario_trace.record({"type": "controller", "action": "operator-retry", "origin": scenario.origin})
                permissions.retry(scenario.origin)
                from src.permission.network.grants import HTTPLimits
                permissions.activate(scenario.origin, HTTPLimits(requests=7, rate=1000, burst=100))
            feedback = yield name, args

    await scenario_runner.run(safety_definition("S05-session-denial", script))


def goals_script(runtime, scenario):
    yield from direct_script(runtime, replace(scenario, expected=replace(scenario.expected, outcome="confirmed")))
    assert not runtime.agent._whole_target_state()[0] == "completed"
    other = receipt((yield "workflow", {**record_candidate(scenario), "candidate_class": "cross-site-scripting"}))["candidate"]["id"]
    receipt((yield "workflow", {"action": "record_result", "candidate_id": other, "skill_name": "cross-site-scripting",
        "outcome": "insufficient-evidence", "deferred_reason": "No executable rendering context supplied; do not infer a negative."}))
    assert runtime.workflow.latest_result(other).outcome == "insufficient-evidence"
    assert not runtime.workflow.latest_result(other).evidence_manifest


async def test_s13_one_native_terminal_result_does_not_complete_second_goal(scenario_runner):
    scenario = safety_definition("S13", goals_script)
    scenario = replace(scenario, user_input=scenario.user_input + " Also test XSS on this input.",
        expected=replace(scenario.expected, outcome="insufficient-evidence", complete=False))
    run = await scenario_runner.run(scenario)
    assert [g.status for g in run.runtime.workflow.objective.requested_goals] == ["tested_confirmed", "deferred"]


def test_m2_offline_guard_survives_other_fixture_patch_cleanup(offline_scenario, monkeypatch):
    monkeypatch.setenv("KAGENT_M2_ISOLATION_PROBE", "test")
    monkeypatch.undo()
    with pytest.raises(RuntimeError, match="offline boundary: DNS"):
        socket.getaddrinfo("fixture.invalid", 80)
    assert offline_scenario.pop() == "DNS"
