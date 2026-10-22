"""Independent related_requests QA on the existing fail-closed offline harness.

Production Agent/Planner/Registry/Workflow/HTTP capture/Evidence/Finding/Session
execute unchanged. Only model and target transport are scripted. No state seeding.
"""
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from src.permission.network.grants import HTTPLimits
from src.permission.permission import Decision, UserControlledRefusal
from tests.helpers.agent_fakes import FakeSignal
from tests.helpers.burp_selection import ingest
from tests.helpers.scenarios import (
    FixtureApplication, dedicated_validation, finding_arguments,
    http_observation, publish_proof, receipt, record_candidate, whole_target_script,
)
from tests.scenarios.test_safety import rejected, safety_definition

MARKER = "xss-qa-marker"
EXECUTION = "<script>document.title='proof'</script>"


class XSSApplication(FixtureApplication):
    def render(self, value):
        if self.kind == "xss-text":
            return 200, ("Literal text: " + value).encode(), "text/plain"
        return 200, ("<html><body>" + value + "</body></html>").encode(), "text/html"


def xss_script(runtime, scenario):
    yield "load_skill", {"name": "cross-site-scripting"}
    cid = receipt((yield "workflow", record_candidate(scenario)))["candidate"]["id"]
    started = receipt((yield "workflow", {"action": "start_validation", "candidate_id": cid}))
    assert started["validator_resolution"] == "unique"
    aid = started["validation_context"]["attempt_id"]
    ids = []
    for value in scenario.http_values:
        output = yield "http", scenario.application.request(value)
        source = http_observation(output)
        ids.append(source["observation_id"])
        retained = runtime.policy.observations._items[ids[-1]]
        assert retained.body == scenario.application.render(value)[1]
        assert retained.response_headers
    outcome = scenario.expected.outcome
    impact = ("Complete text/html places the intact script in an ordinary HTML body, "
              "with no inert wrapper or CSP; deterministic exploitability, no observed browser execution."
              if outcome == "confirmed" else
              "Both complete responses are text/plain; literal script text establishes no executable HTML context.")
    assessment = {"hypothesis": "The supplied query might produce reflected XSS",
        "criteria": "Inert context marker then one intact HTML-body execution marker; inspect media, encoding and CSP",
        "limitations": "Offline synthetic target; no browser execution or broader absence claim.",
        "completed_attempt": True, "observed_impact": impact,
        "severity": "medium" if outcome == "confirmed" else "info"}
    result = yield from publish_proof(runtime, cid, aid, ids, "cross-site-scripting",
                                     outcome, assessment, ["html-body"])
    if outcome == "confirmed":
        finding = yield "confirm_finding", {
            "candidate_id": cid, "title": "Offline reflected HTML-body XSS",
            "severity": "medium", "url": scenario.origin + scenario.endpoint,
            "method": "GET", "parameter": scenario.parameter, "payload": EXECUTION,
            "response_excerpt": scenario.application.render(EXECUTION)[1].decode(),
            "observed_impact": impact, "potential_impact": "No further impact assessed.",
            "curl": "curl '" + scenario.origin + scenario.application.request(EXECUTION)["url"] + "'",
            "remediation": "Review context-appropriate output encoding; implementation was not inspected.",
            "vuln_class": "xss"}
        assert "written to " in finding and result["eligible_for_confirm_finding"]
    else:
        assert not result["eligible_for_confirm_finding"]
        args = finding_arguments(scenario, cid, impact)
        yield from rejected(runtime, "confirm_finding", args, "confirmed", kind="tool_exception")


@pytest.mark.parametrize("media,outcome", [("xss-html", "confirmed"), ("xss-text", "not-confirmed")])
async def test_b_candidate_only_xss_class_specific_proof(scenario_runner, media, outcome):
    scenario = safety_definition("qa-B-" + media, xss_script, cls="cross-site-scripting", endpoint="/reflect",
                                 parameter="q", value=MARKER, outcome=outcome)
    scenario = replace(scenario, application=XSSApplication(media, scenario.origin, scenario.endpoint, "GET", "q"),
                       http_values=(MARKER, EXECUTION))
    run = await scenario_runner.run(scenario)
    assert len(run.transport.sent) == 2
    result = run.runtime.workflow.validation_results[-1]
    assert len(result.evidence_manifest) == 2 and result.confirmation is None
    assert run.runtime.workflow.attempts[result.attempt_id]["related_requests"] == []
    await scenario_runner.resume(run)


def insufficient_xss_script(runtime, scenario):
    yield "load_skill", {"name": "cross-site-scripting"}
    cid = receipt((yield "workflow", record_candidate(scenario)))["candidate"]["id"]
    aid = receipt((yield "workflow", {"action": "start_validation", "candidate_id": cid}))["validation_context"]["attempt_id"]
    output = yield "http", {**scenario.application.request(MARKER), "max_response_bytes": 3}
    line = next(line for line in output.splitlines() if line.startswith("Runtime HTTP evidence ("))
    captured, _ = json.JSONDecoder().raw_decode(line.split(": ", 1)[1])
    assert not captured["complete"] and captured["truncated"]
    oid = captured["observation_id"]
    path = runtime.policy.root / "artifacts/xss-partial.md"
    yield "file_write", {"path": str(path), "content": f"Candidate {cid}; observation_ids: {oid}\nOnly a three-byte HTML prefix was retained; no executable context is proved."}
    evidence = receipt((yield "workflow", {"action": "record_evidence", "candidate_id": cid,
        "evidence_path": "artifacts/xss-partial.md", "observation_ids": [oid]}))["evidence"]["id"]
    yield from rejected(runtime, "workflow", {"action": "record_result", "candidate_id": cid,
        "attempt_id": aid, "skill_name": "cross-site-scripting", "outcome": "not-confirmed",
        "evidence_refs": [evidence], "observation_ids": [oid], "assessment": {
            "hypothesis": "Reflection may be executable", "criteria": "Complete observed context",
            "limitations": "Response capture is truncated", "completed_attempt": True,
            "observed_impact": "No complete context retained", "severity": "info"}}, "evidence-admissibility:")
    receipt((yield "workflow", {"action": "record_result", "candidate_id": cid, "attempt_id": aid,
        "skill_name": "cross-site-scripting", "outcome": "insufficient-evidence",
        "deferred_reason": "Native bounded capture lacks complete context; no negative or confirmation claim."}))
    assert len(runtime.scenario_transport.sent) == 1


async def test_b_native_incomplete_html_closes_unresolved(scenario_runner):
    scenario = safety_definition("qa-B-partial", insufficient_xss_script, cls="xss", endpoint="/reflect",
                                 parameter="q", value=MARKER, outcome="insufficient-evidence")
    scenario = replace(scenario, application=XSSApplication("xss-html", scenario.origin, scenario.endpoint, "GET", "q"),
                       http_values=(MARKER,))
    run = await scenario_runner.run(scenario)
    assert run.runtime.agent._validation_completion_blockers()
    assert not run.runtime.workflow.validation_results[-1].evidence_manifest


def burp_script(runtime, scenario):
    selected = runtime.agent._turn_capture_selection()
    assert selected is not None
    yield "load_skill", {"name": "sql-injection"}
    cid = receipt((yield "workflow", record_candidate(scenario)))["candidate"]["id"]
    candidate = runtime.workflow.candidates[cid]
    assert candidate.baseline_request_ref == runtime.qa_capture["baseline_request_ref"]
    assert candidate.source_ref == runtime.qa_capture["id"]
    assert not runtime.policy.observations._items, "capture selection must not fabricate native proof"
    yield from dedicated_validation(runtime, scenario, cid, skill_loaded=True)
    result = runtime.workflow.latest_result(cid)
    assert all(entry["source"]["source_kind"] == "native-http" for entry in result.evidence_manifest)
    assert all(entry["source"]["session_id"] == runtime.store.id for entry in result.evidence_manifest)


async def test_c_selected_burp_context_native_validation_and_resume(scenario_runner):
    scenario = safety_definition("qa-C-selected-burp", burp_script)
    runtime, transport = scenario_runner.prepare(scenario)
    # External bridge is replaced at its data boundary; production store ingestion,
    # selection, context admission and Candidate binding run unchanged.
    runtime.qa_capture = ingest(runtime, origin=scenario.origin,
        path=scenario.application.request(scenario.input_value)["url"], status=200,
        requestHeaders=[{"name": "Authorization", "value": "Bearer qa-synthetic-secret"}],
        respBody="fixture products", responseComplete=True)
    runtime.agent.select_burp_captures(runtime.qa_capture["id"])
    run = await scenario_runner.run(scenario, runtime=runtime, transport=transport)
    assert runtime.agent.pending_capture_selection is None and len(transport.sent) == 6
    assert "qa-synthetic-secret" not in runtime.store.path.read_text()
    fresh = await scenario_runner.resume(run)
    assert not fresh.capture.requests and not fresh.policy.observations._items


def mixed_whole_target_script(runtime, scenario):
    primary = replace(scenario, expected=replace(scenario.expected, outcome="confirmed"))
    original = whole_target_script(runtime, primary)
    name, args = next(original)
    other = None
    while True:
        output = yield name, args
        if name == "workflow" and args.get("action") == "record_candidate":
            # Another hypothesis on the observed canonical input, registered by
            # production dispatch before either validator runs. No injected state.
            other = receipt((yield "workflow", {**args, "candidate_class": "cross-site-scripting",
                "signals": ["Same observed input; executable rendering remains an untested hypothesis."]}))["candidate"]["id"]
        try:
            name, args = original.send(output)
        except StopIteration:
            break
    assert other is not None
    yield "load_skill", {"name": "cross-site-scripting"}
    aid = receipt((yield "workflow", {"action": "start_validation", "candidate_id": other}))["validation_context"]["attempt_id"]
    receipt((yield "workflow", {"action": "record_result", "candidate_id": other, "attempt_id": aid,
        "skill_name": "cross-site-scripting", "outcome": "insufficient-evidence",
        "deferred_reason": "No rendering-context probes or proof in this bounded run; outstanding hypothesis."}))


async def test_d_discovery_handoff_confirmed_plus_unresolved_stays_incomplete(scenario_runner):
    scenario = safety_definition("qa-D-mixed-target", mixed_whole_target_script,
                                 mode="whole_target", outcome="insufficient-evidence")
    scenario = replace(scenario, expected=replace(scenario.expected, findings=1), max_steps=55,
        user_input=f"Assess the whole target {scenario.origin} for SQL injection and XSS, "
                   "from recon through enumeration and input analysis. This exact origin is an authorized local lab.")
    run = await scenario_runner.run(scenario)
    state = run.runtime.workflow
    assert state.completed_phases() == {"recon", "enumeration", "input_analysis"}
    assert len(state.attack_surface_inputs) == 1 and len(state.candidates) == 2
    assert {r.outcome for r in state.validation_results} == {"confirmed", "insufficient-evidence"}
    assert run.runtime.agent._whole_target_state()[0] != "completed"
    skills = [e["name"] for e in run.trace.events if e["type"] == "skill-active"]
    assert skills[:4] == ["recon", "web-enumeration", "web-input-analysis", "sql-injection"]
    recommended = {e["recommended_skill"] for e in run.trace.events
                   if e["type"] == "decision" and e.get("recommended_skill")}
    assert {"recon", "web-enumeration", "web-input-analysis", "sql-injection", "cross-site-scripting"} <= recommended
    assert {g.status for g in state.objective.requested_goals} == {"tested_confirmed", "deferred"}


def supplementary_script(runtime, scenario):
    yield "load_skill", {"name": "sql-injection"}
    cid = receipt((yield "workflow", record_candidate(scenario)))["candidate"]["id"]
    path = scenario.endpoint + "/123"
    started = receipt((yield "workflow", {"action": "start_validation", "candidate_id": cid,
        "related_requests": [{"role": "readback", "method": "GET", "url": path}]}))
    aid = started["validation_context"]["attempt_id"]
    original = dedicated_validation(runtime, scenario, cid, skill_loaded=True)
    name, args = next(original)
    while True:
        if name == "workflow" and args.get("action") == "record_result":
            before, revision = deepcopy(runtime.workflow.to_dict()), runtime.workflow.committed_revision
            output = yield from rejected(runtime, name, args, "required request")
            assert runtime.workflow.to_dict() == before and runtime.workflow.committed_revision == revision
            assert runtime.workflow.attempts[aid]["related_requests"][0]["required"] is True
            oid = http_observation((yield "http", {"url": path, "method": "GET", "phase": "validation"}))["observation_id"]
            ids = [*args["observation_ids"], oid]
            # A new parent requires a new immutable proof; dropping the obligation
            # or merely appending an ID to old proof would be invalid.
            result = yield from publish_proof(runtime, cid, aid, ids, "sql-injection", "confirmed",
                args["assessment"], args["techniques"], path="artifacts/readback-proof.md",
                extra={k: args[k] for k in ("repeatable", "confirmation")})
            assert len(runtime.workflow.evidence) == 2
            assert len(result["result"]["evidence_manifest"]) == 7
            finding = yield "confirm_finding", finding_arguments(scenario, cid, args["assessment"]["observed_impact"])
            assert "written to " in finding
            original.close()
            return
        output = yield name, args
        try:
            name, args = original.send(output)
        except StopIteration:
            raise AssertionError("supplementary scenario never reached terminal submission")


async def test_e_required_supplementary_readback_real_proof_and_resume(scenario_runner):
    scenario = safety_definition("qa-E-readback", supplementary_script, method="POST")
    runtime, transport = scenario_runner.prepare(scenario)
    transport.expected.append(({"url": scenario.endpoint + "/123", "method": "GET", "phase": "validation"},
                               (200, b"readback fixture products", "text/plain")))
    runtime.engagement.http_permissions.activate(scenario.origin, HTTPLimits(requests=8, rate=1000, burst=100))
    run = await scenario_runner.run(scenario, runtime=runtime, transport=transport)
    result = runtime.workflow.validation_results[-1]
    assert result.evidence_manifest[-1]["source"]["role"] == "readback"
    fresh = await scenario_runner.resume(run)
    assert fresh.workflow.attempts[result.attempt_id]["related_requests"] == [
        {"role": "readback", "method": "GET", "url": scenario.origin + scenario.endpoint + "/123", "required": True}]
    fresh.operator.decision = Decision.DENY
    with pytest.raises(UserControlledRefusal):
        await fresh.registry.execute("http", {"url": scenario.endpoint + "/123", "method": "DELETE",
            "phase": "impact"}, FakeSignal(), fresh.prompter)
    assert len(transport.sent) == 7 and len(fresh.operator.requests) == 1
    review = fresh.operator.requests[-1]
    assert review.risk_tier == "high-impact" and review.no_session_cache
    assert fresh.workflow.to_dict() == runtime.workflow.to_dict()


def duplicate_script(runtime, scenario):
    yield "load_skill", {"name": "sql-injection"}
    cid = receipt((yield "workflow", record_candidate(scenario)))["candidate"]["id"]
    rows = [{"role": role, "method": scenario.method, "url": scenario.endpoint}
            for role in ("baseline", "trigger")]
    repetitions = 3 if scenario.expected.outcome == "insufficient-evidence" else 1
    for _ in range(repetitions):
        revision = runtime.workflow.committed_revision
        output = yield from rejected(runtime, "workflow", {"action": "start_validation",
            "candidate_id": cid, "related_requests": rows}, "DUPLICATE_REQUEST_ASSOCIATION")
        error = json.loads(output.partition("\n")[2])["error"]
        assert error["indices"] == [0, 1]
        assert "Do not invent URLs" in error["repair_hint"]
        assert not runtime.workflow.attempts and runtime.workflow.committed_revision == revision
        assert not runtime.scenario_transport.sent
    if repetitions == 3:
        # Unstarted unresolved closure is supported; repeated rejection alone
        # supplies no evidence and cannot claim terminal validation.
        receipt((yield "workflow", {"action": "record_result", "candidate_id": cid,
            "skill_name": "sql-injection", "outcome": "insufficient-evidence",
            "deferred_reason": "Association intent remains unresolved; no probes, attempt or proof."}))
        return
    yield from dedicated_validation(runtime, scenario, cid, skill_loaded=True)
    assert len(runtime.workflow.attempts) == 1


@pytest.mark.parametrize("outcome", ["confirmed", "insufficient-evidence"])
async def test_f_duplicate_feedback_grounded_correction_or_honest_stop(scenario_runner, outcome):
    scenario = safety_definition("qa-F-" + outcome, duplicate_script, method="POST", outcome=outcome)
    if outcome == "insufficient-evidence":
        scenario = replace(scenario, http_values=())
    run = await scenario_runner.run(scenario)
    assert len(run.transport.sent) == (6 if outcome == "confirmed" else 0)
    assert len(run.runtime.workflow.attempts) == (1 if outcome == "confirmed" else 0)
    assert len(run.runtime.scenario_errors) == (1 if outcome == "confirmed" else 3)
