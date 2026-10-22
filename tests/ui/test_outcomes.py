import copy
import asyncio
import json
from types import SimpleNamespace
from typing import Any, cast
from src.agent.agent import Agent

import pytest

from src.agent.events import DoneEvent, ToolCallEvent, ToolResultEvent, ErrorEvent, MaxStepsError, AssistantTextEvent
from src.permission.permission import AlwaysAllow
from src.target.target import Target
from src.tools.workflow.workflow_tool import WorkflowTool
from src.ui.core.state import AgentEventAction, Clear, SetAsk, SetBusy, FinalizeDeferredOutcome
from src.workflow.state import Candidate, ValidationResult, WorkflowObjective
from tests.helpers.workflow import adopt_fixture_assessment, record_completed_phase
from tests.tools.test_finding import _tool, _valid_args
from tests.ui.test_app import make_app, timer_app
from src.tools.common.runtime_metadata import RuntimeMetadata, StreamCapture


def dispatch(app, event):
    original = copy.deepcopy(event)
    app.dispatch(AgentEventAction(event))
    assert original == event


def test_repeated_errors_changed_reasons_recovery_and_delivery():
    app = make_app()
    for i in range(100):
        dispatch(app, ToolCallEvent(id=str(i), name="unknown", args={"operation": "fixture"}))
        event = ToolResultEvent(id=str(i), name="unknown", err="connection failed", status="error")
        dispatch(app, event)
        dispatch(app, event)
    assert len(list(app.state.transcript)) == 1
    assert "100 times" in app.state.transcript[0].text
    dispatch(app, ToolCallEvent(id="changed", name="unknown", args={"operation": "fixture"}))
    dispatch(app, ToolResultEvent(id="changed", name="unknown", err="permission denied", status="error"))
    assert len(list(app.state.transcript)) == 2
    dispatch(app, ToolCallEvent(id="recovery", name="unknown", args={"operation": "fixture"}))
    dispatch(app, ToolResultEvent(id="recovery", name="unknown", result="ok"))
    assert all(issue.recovered for issue in app.state.issues)
    assert [entry.text for entry in app.state.transcript] == ['unknown', 'unknown']
    assert [entry.details for entry in app.state.transcript] == [
        ('Recovered after 100 failed attempts',), ('Recovered after 1 failed attempt',)]
    assert [issue.count for issue in app.state.issues] == [100, 1]
    assert [issue.text for issue in app.state.issues] == [
        'unknown: connection failed', 'unknown: permission denied']


def test_recovery_preserves_sanitized_original_error_in_diagnostics():
    app = make_app()
    args = {'operation': 'fixture'}
    dispatch(app, ToolCallEvent(id='failed', name='unknown', args=args))
    dispatch(app, ToolResultEvent(id='failed', name='unknown', status='error',
        err='error: rejected password=short-secret'))
    original = app.state.issues[0].text
    assert 'error: rejected' in original and 'short-secret' not in original
    dispatch(app, ToolCallEvent(id='retry', name='unknown', args=args))
    dispatch(app, ToolResultEvent(id='retry', name='unknown', result='ok'))
    assert app.state.issues[0].recovered
    assert app.state.issues[0].text == original
    from src.ui.widgets.transcript import entry_view
    displayed = '\n'.join(line.text for line in entry_view(app.state.transcript[0]))
    assert 'Recovered after 1 failed attempt' in displayed
    assert 'error:' not in displayed and 'rejected' not in displayed
    assert 'short-secret' not in repr(app.state)


def test_http_retries_group_by_operation_and_keep_target_auth_and_recovery_distinct():
    app = make_app()
    for i in range(10):
        dispatch(app, ToolCallEvent(id=str(i), name="http", args={"url":f"http://juice.lab:3000/search?q={i}"}))
        dispatch(app, ToolResultEvent(id=str(i), name="http", status="error", err="connection failed", error_kind="network"))
    assert len(app.state.transcript) == 1 and "10 times" in app.state.transcript[0].text
    for i, url, auth in [("target", "http://other.lab:3000/search?q=1", "a"),
                         ("auth", "http://juice.lab:3000/search?q=1", "b")]:
        dispatch(app, ToolCallEvent(id=i, name="http", args={"url":url, "headers":{"Authorization":auth}}))
        dispatch(app, ToolResultEvent(id=i, name="http", status="error", err="connection failed"))
    assert len(app.state.transcript) == 3
    dispatch(app, ToolCallEvent(id="recover", name="http", args={"url":"http://juice.lab:3000/search?q=11"}))
    dispatch(app, ToolResultEvent(id="recover", name="http", status="observation", http_status=403, result="HTTP/1.1 403 Forbidden"))
    assert app.state.issues[0].recovered and not app.state.issues[1].recovered


def test_late_or_missing_results_and_unknown_reasons_remain_safe():
    app = make_app()
    dispatch(app, DoneEvent(stop_reason="future_stop_reason"))
    assert "future_stop_reason" in app.state.transcript[0].text
    dispatch(app, ToolResultEvent(id="late", name="unknown", status="error", error_kind="network"))
    assert app.state.phase == "idle" and app.state.transcript[-1].kind == "error"
    dispatch(app, ToolCallEvent(name="shell", args={"command":"rg missing ."}))
    dispatch(app, ToolResultEvent(name="shell", result="exit: 1\nstdout:\n",
        runtime_metadata=RuntimeMetadata(process="exit", exit_code=1,
            stdout=StreamCapture(0, 0, True), stderr=StreamCapture(0, 0, True))))
    assert "exit 1" in app.state.transcript[-1].text


def test_routine_notices_do_not_grow_transcript_but_multiline_warnings_remain():
    app = make_app()
    for i in range(100):
        app._publish_notice(f"Burp bridge: captured request GET http://juice.lab:3000/path/{i}")
        app._publish_notice("Burp bridge: received session snapshot")
    assert not app.state.transcript
    app._publish_notice("Burp bridge: captured request GET /path\nWARNING: bridge integration failed")
    assert "integration failed" in app.state.transcript[0].text


@pytest.mark.parametrize("reason,label", [("final_response", "Turn completed"),
    ("workflow_completed", "Turn ended · workflow completion unavailable"), ("workflow_blocked", "Blocked"),
    ("workflow_stalled", "Stalled"), ("cancelled", "Turn cancelled"), ("max_steps", "Stopped at max steps"),
    ("runtime_error", "Runtime failure"), ("context_capacity", "Context capacity failure")])
def test_truthful_final_outcome_is_once_per_turn(reason, label):
    app = make_app()
    app.dispatch(SetBusy(True))
    dispatch(app, DoneEvent(stop_reason=reason))
    dispatch(app, DoneEvent(stop_reason=reason))
    assert len(app.state.transcript) == 1 and label in app.state.transcript[0].text
    app.dispatch(SetBusy(True))
    dispatch(app, DoneEvent(stop_reason="cancelled"))
    assert len(app.state.transcript) == 2


def test_max_steps_outcome_waits_for_operator():
    app = make_app()
    app.dispatch(SetAsk(cast(Any, object())))
    dispatch(app, DoneEvent(stop_reason="max_steps"))
    assert not app.state.transcript and app.state.phase == "waiting-user"
    app.dispatch(SetAsk(None))
    app.dispatch(FinalizeDeferredOutcome())
    assert len(app.state.transcript) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", ["Stop", "Continue"])
async def test_actual_max_steps_callback_defers_summary_and_preserves_continue(decision):
    app, _, _ = timer_app()
    turns = []
    async def run(value, *, signal, emit, opts=None):
        turns.append(value)
        if len(turns) == 1:
            emit(ErrorEvent(err=MaxStepsError(5)))
            emit(DoneEvent(stop_reason="max_steps"))
        else:
            emit(AssistantTextEvent(text="Finished continued work."))
            emit(DoneEvent(stop_reason="final_response"))
    app.agent = cast(Agent, SimpleNamespace(is_running=lambda:False, run=run))
    await app.run_agent_turn("fixture")
    assert app.state.pending_ask is not None
    assert not any("Stopped at max steps" in entry.text for entry in app.state.transcript)
    app.state.pending_ask.resolve(decision)
    for _ in range(10):
        await asyncio.sleep(0)
    assert app.state.pending_ask is None
    if decision == "Continue":
        assert len(turns) == 2
        assert app.state.transcript[-1].text == "Turn completed."
        assert any("Finished continued work." == entry.text for entry in app.state.transcript)
    else:
        assert len(turns) == 1 and app.state.transcript[-1].text == "Stopped at max steps."


def configure(app, tool, tmp_path):
    workflow = tool.workflow
    assert workflow is not None
    candidate = next(iter(workflow.candidates.values()))
    # This fixture has no declared candidate origin; keep it scoped to the empty target.
    app.agent = SimpleNamespace(workflow=workflow, target=Target(), prompter=AlwaysAllow(),
                                tools={"workflow": WorkflowTool(workflow, evidence_root=tmp_path)})
    return workflow, candidate


@pytest.mark.asyncio
async def test_real_finding_persistence_and_export_warning_are_distinct(tmp_path, monkeypatch):
    tool, store = _tool(tmp_path)
    app = make_app()
    workflow, candidate = configure(app, tool, tmp_path)
    args = _valid_args(tool)
    async def failed_export(*args):
        raise OSError("disk full")
    monkeypatch.setattr(tool, "write_summary", failed_export)
    dispatch(app, ToolCallEvent(id="save", name="confirm_finding", args=args))
    assert not app.state.transcript
    result = await tool.run(args, None, AlwaysAllow())
    snapshot = copy.deepcopy(workflow.to_dict())
    event = ToolResultEvent(id="save", name="confirm_finding", result=result)
    dispatch(app, event)
    dispatch(app, event)
    assert sum(entry.kind == "finding" for entry in app.state.transcript) == 1
    assert "Finding saved ·" in app.state.transcript[-1].text
    assert "(medium)" in app.state.transcript[-1].text
    assert any("export failed" in entry.text for entry in app.state.transcript)
    assert workflow.to_dict() == snapshot and workflow.finding_is_persisted(candidate.id)
    assert len(list(store.dir.glob("*.md"))) == 1


@pytest.mark.asyncio
async def test_historical_persistence_never_overrides_failure_or_changed_evidence(tmp_path):
    tool, _ = _tool(tmp_path)
    app = make_app()
    workflow, candidate = configure(app, tool, tmp_path)
    args = _valid_args(tool)
    result = await tool.run(args, None, AlwaysAllow())
    dispatch(app, ToolCallEvent(id="failed", name="confirm_finding", args=args))
    dispatch(app, ToolResultEvent(id="failed", name="confirm_finding", result=result,
                                  err="candidate evidence changed", status="error"))
    assert not any(entry.kind == "finding" for entry in app.state.transcript)
    workflow.evidence.clear()
    dispatch(app, ToolCallEvent(id="stale", name="confirm_finding", args=args))
    dispatch(app, ToolResultEvent(id="stale", name="confirm_finding", result=result))
    dispatch(app, DoneEvent(stop_reason="workflow_blocked"))
    assert not any(entry.kind == "finding" for entry in app.state.transcript)
    assert "assessment/evidence unavailable" in app.state.transcript[-1].text


def test_scoped_phase_completion_deduplicates_and_boundary_resets(tmp_path):
    tool, _ = _tool(tmp_path)
    app = make_app()
    workflow, _ = configure(app, tool, tmp_path)
    objective = WorkflowObjective("whole", "whole_target", "http://juice.lab:3000")
    workflow.objective = objective
    assert objective.target_origin is not None
    app.agent.target = Target(objective.target_origin)
    record_completed_phase(workflow, "recon", objective_id=objective.id,
                           target_origin=objective.target_origin, artifact_ref="artifacts/recon.md")
    for i in range(2):
        dispatch(app, ToolCallEvent(id=str(i), name="workflow", args={"action":"complete_skill"}))
        dispatch(app, ToolResultEvent(id=str(i), name="workflow", result=json.dumps({"ok": True, "phase":"recon"})))
    assert not any(entry.text.startswith('Workflow ·') for entry in app.state.transcript)
    assert app.state.latest_facts and 'Recon repair' in app.state.latest_facts.overview
    assert 'recon' in workflow.completed_phases()
    snapshot = workflow.to_dict()
    app.agent.target.set_base_url("http://other.lab:3000")
    dispatch(app, DoneEvent(stop_reason="workflow_blocked"))
    assert "active target differs" in app.state.transcript[-1].text
    assert workflow.to_dict() == snapshot
    assert not app.state.milestones
    app.dispatch(Clear())
    assert not app.state.issues and not app.state.milestones and not app.state.pending_calls


def test_final_scoped_residual_work_and_revision_change(tmp_path):
    tool, _ = _tool(tmp_path)
    app = make_app()
    workflow, candidate = configure(app, tool, tmp_path)
    latest = workflow.latest_result(candidate.id)
    assert latest is not None
    latest.coverage_synced = False
    latest.cleanup_state = "requires-user-action"
    # An unrelated origin's candidate must not contaminate this turn's outcome.
    workflow.add_candidate(Candidate(candidate_class="xss", target="http://other.lab:3000"))
    snapshot = copy.deepcopy(workflow.to_dict())
    dispatch(app, DoneEvent(stop_reason="workflow_blocked"))
    final = app.state.transcript[-1].text
    assert "coverage synchronization pending" in final and "cleanup requires-user-action" in final
    assert "validation incomplete" not in final and workflow.to_dict() == snapshot
    replacement = adopt_fixture_assessment(workflow, ValidationResult(candidate.id, "test-skill", "confirmed",
                                            evidence_refs=latest.evidence_refs))
    workflow.add_validation_result(replacement)
    assert replacement.result_id != latest.result_id
    app.dispatch(SetBusy(True))
    dispatch(app, DoneEvent(stop_reason="workflow_blocked"))
    assert "finding persistence pending" in app.state.transcript[-1].text


def test_whole_target_inventory_is_aggregated_and_exact_origin_scoped(tmp_path):
    from src.workflow.state import WorkflowState
    app = make_app()
    workflow = WorkflowState()
    target = Target('http://juice.lab:3000')
    workflow.objective = WorkflowObjective('inventory', 'whole_target', target.base_url())
    assert workflow.objective is not None
    app.agent = cast(Any, SimpleNamespace(workflow=workflow, target=target, prompter=AlwaysAllow(),
                                         tools={'workflow': WorkflowTool(workflow, target, evidence_root=tmp_path)}))
    app.dispatch(SetBusy(True))
    for i in range(30):
        operation = {'action':'record_input', 'method':'GET', 'endpoint':f'/path/{i}', 'parameter':'q',
                     'input_type':'string', 'location':'query'}
        dispatch(app, ToolCallEvent(id=str(i), name='workflow', args=operation))
        result = asyncio.run(app.agent.tools['workflow'].run(operation, None, AlwaysAllow()))
        dispatch(app, ToolResultEvent(id=str(i), name='workflow', result=result))
        inventory = [entry.text for entry in app.state.transcript if entry.text.startswith('Attack surface recorded:')]
        assert len(inventory) == 1 and f'{i+1} input' in inventory[0]
    assert len(app.state.transcript) == 1 and app.state.transcript[0].text.startswith('Attack surface recorded:')
    assert app.state.latest_facts and '0/30 inputs reviewed' in app.state.latest_facts.overview
    from src.workflow.state import AttackSurfaceInput
    foreign = AttackSurfaceInput('foreign', 'http://other.lab:3000', method='GET', endpoint='/outside', parameter='secret', location='query')
    workflow.attack_surface_inputs[foreign.id] = foreign
    snapshot = copy.deepcopy(workflow.to_dict())
    dispatch(app, ToolCallEvent(id='boundary', name='workflow', args={'action':'complete_skill'}))
    dispatch(app, ToolResultEvent(id='boundary', name='workflow', result='{"ok":false,"error":"coverage incomplete"}'))
    rows = [entry.text for entry in app.state.transcript if entry.text.startswith('Attack surface recorded:')]
    assert len(rows) == 1 and '30 endpoints, 30 inputs' in rows[0]
    assert 'other.lab' not in repr(app.state.transcript) and '/outside' not in repr(app.state.transcript)
    dispatch(app, DoneEvent(stop_reason='workflow_blocked'))
    assert sum(entry.text.startswith('Attack surface recorded:') for entry in app.state.transcript) == 1
    assert workflow.to_dict() == snapshot


@pytest.mark.asyncio
async def test_direct_candidate_observation_accepted_result_saved_and_prior_turn_baseline(tmp_path):
    tool, store = _tool(tmp_path)
    app = make_app()
    workflow, candidate = configure(app, tool, tmp_path)
    records = copy.deepcopy(workflow.to_dict())
    from src.workflow.state import WorkflowState
    original = WorkflowState.from_dict(records)
    workflow.clear()
    app.dispatch(SetBusy(True))
    dispatch(app, ToolCallEvent(id='candidate', name='workflow', args={'action':'record_candidate'}))
    workflow.add_candidate(candidate)
    dispatch(app, ToolResultEvent(id='candidate', name='workflow', result='{"ok":true}'))
    dispatch(app, ToolCallEvent(id='http', name='http', args={'method':'POST', 'url':'/rest/user/login', 'parameter':'email'}))
    assert app.state.running_tool is not None
    assert 'POST /rest/user/login' in app.state.running_tool and 'email' in app.state.running_tool
    dispatch(app, ToolResultEvent(id='http', name='http', status='observation', http_status=200, result='fixture response'))
    dispatch(app, AssistantTextEvent(text='The response is an observation; validation still needs evidence.'))
    assert any('Candidate recorded ·' in entry.text for entry in app.state.transcript)
    assert not any('Validation confirmed' in entry.text for entry in app.state.transcript)
    for evidence in original.evidence.values():
        workflow.add_evidence(evidence)
    workflow.attempts.update(original.attempts)
    latest = original.latest_result(candidate.id)
    assert latest is not None
    dispatch(app, ToolCallEvent(id='validation', name='workflow', args={'action':'record_result', 'candidate_id':candidate.id}))
    workflow.add_validation_result(latest)
    dispatch(app, ToolResultEvent(id='validation', name='workflow', result='{"ok":true}'))
    assert any('Validation confirmed' in entry.text for entry in app.state.transcript)
    args = _valid_args(tool)
    dispatch(app, ToolCallEvent(id='save-new', name='confirm_finding', args=args))
    result = await tool.run(args, None, AlwaysAllow())
    dispatch(app, ToolResultEvent(id='save-new', name='confirm_finding', result=result))
    dispatch(app, DoneEvent(stop_reason='final_response'))
    assert '1 finding saved' in app.state.transcript[-1].text
    assert 'accepted-but-unsaved' not in app.state.transcript[-1].text
    before = sum(entry.kind == 'finding' for entry in app.state.transcript)
    app.dispatch(SetBusy(True))
    dispatch(app, DoneEvent(stop_reason='final_response'))
    assert 'findings saved' not in app.state.transcript[-1].text
    assert before == sum(entry.kind == 'finding' for entry in app.state.transcript)
    assert len(list(store.dir.glob('*.md'))) == 1


def test_context_pressure_stable_roots_are_diagnostics_and_capacity_failure_is_visible():
    from src.agent.events import DecisionEvent
    from src.llm.runtime.context_budget import ContextCapacityError, InputBudget
    app = make_app()
    app.dispatch(SetBusy(True))
    for count in range(50):
        dispatch(app, DecisionEvent(summary=f'context guard: reduced {count} characters; unresolved pressure: {count*30} tokens'))
    assert not app.state.transcript and not app.state.issues
    dispatch(app, DecisionEvent(summary='context guard: reduced 100 characters successfully'))
    assert not app.state.transcript
    error = ContextCapacityError(200, InputBudget(input_limit=100), 150)
    app.dispatch(AgentEventAction(ErrorEvent(err=error)))
    assert error.estimate == 200 and error.fixed_floor == 150
    dispatch(app, DoneEvent(stop_reason='context_capacity'))
    assert 'Context capacity failure' in app.state.transcript[-1].text
    assert '1 unresolved operation issue.' in app.state.transcript[-1].text


def test_http_success_cannot_recover_unrelated_authorization_or_workflow_failure():
    app = make_app()
    dispatch(app, ToolCallEvent(id='workflow', name='workflow', args={'action':'record_result', 'candidate_id':'fixture'}))
    dispatch(app, ToolResultEvent(id='workflow', name='workflow', result='error: evidence unavailable'))
    dispatch(app, ToolCallEvent(id='denied', name='http', args={'url':'/write?q=first', 'method':'POST'}))
    dispatch(app, ToolResultEvent(id='denied', name='http', err='permission denied', status='error', error_kind='permission_denied'))
    dispatch(app, ToolCallEvent(id='success', name='http', args={'url':'/write?q=other', 'method':'POST'}))
    dispatch(app, ToolResultEvent(id='success', name='http', status='observation', http_status=200))
    assert all(not issue.recovered for issue in app.state.issues)
    dispatch(app, DoneEvent(stop_reason='workflow_blocked'))
    assert '2 unresolved operation issues' in app.state.transcript[-1].text


def test_selected_burp_requests_are_presented_as_selection_not_validation(tmp_path):
    from src.browser.store import CaptureStore
    from src.browser.selection import CaptureSelection
    from src.engagement.state import EngagementState
    from src.workflow.state import WorkflowState
    origin = 'http://juice.lab:3000'
    target = Target(origin)
    engagement = EngagementState()
    engagement.initialize_target(origin)
    capture = CaptureStore()
    capture.ingest({'kind':'burp', 'id':'selected', 'method':'POST', 'url':origin+'/login', 'requestBody':'password=short-secret'})
    rows = capture.list_requests()
    selection = CaptureSelection.create(rows, target, engagement, None)
    workflow = WorkflowState()
    app = make_app()
    app.agent = cast(Any, SimpleNamespace(workflow=workflow, target=target, engagement_state=engagement,
                                         pending_capture_selection=selection, prompter=AlwaysAllow(),
                                         tools={'workflow':WorkflowTool(workflow, target, evidence_root=tmp_path)}))
    app.dispatch(SetBusy(True))
    dispatch(app, AssistantTextEvent(text='The selected capture still needs input analysis.'))
    assert any('1 captured request' in entry.text and 'POST /login' in entry.text for entry in app.state.transcript)
    assert not any('Validation confirmed' in entry.text for entry in app.state.transcript)
    assert 'short-secret' not in repr(app.state)


def test_progress_boundary_finishes_stream_once_and_clears_raw_chunks():
    from src.agent.events import AssistantDeltaEvent
    from src.ui.core.outcomes import OutcomeFacts, ProgressRecord
    from src.ui.core.state import reducer, initial_state
    from src.ui.widgets.banner import BannerData
    state = initial_state('', BannerData('test','test','.'))
    state = reducer(state, SetBusy(True, facts=OutcomeFacts(scope='fixture')))
    facts = OutcomeFacts(scope='fixture', records=(ProgressRecord('candidate','one','POST /login · input email','queued'),))
    state = reducer(state, AgentEventAction(AssistantDeltaEvent(text='Substantive analysis; password=short-secret'), facts=facts))
    state = reducer(state, AgentEventAction(AssistantTextEvent(text='Substantive analysis; password=short-secret'), facts=facts))
    assert not state.stream_chunks and all(not entry.streaming for entry in state.transcript)
    assert sum(entry.kind == 'assistant' for entry in state.transcript) == 1
    assert 'short-secret' not in repr(state.transcript)
    assert any('Candidate recorded ·' in entry.text for entry in state.transcript)


def test_workflow_rejection_recovers_only_after_bound_accepted_assessment(tmp_path):
    tool, _ = _tool(tmp_path)
    app = make_app()
    workflow, candidate = configure(app, tool, tmp_path)
    latest = workflow.latest_result(candidate.id)
    assert latest is not None
    workflow.validation_results.clear()
    app.dispatch(SetBusy(True))
    args = {'action':'record_result', 'candidate_id':candidate.id, 'attempt_id':latest.attempt_id}
    dispatch(app, ToolCallEvent(id='rejected', name='workflow', args=args | {'assessment':{'criteria':'unattested'}}))
    dispatch(app, ToolResultEvent(id='rejected', name='workflow', result='{"ok":false,"error":"assessment rejected"}'))
    dispatch(app, ToolCallEvent(id='unaccepted', name='workflow', args=args))
    dispatch(app, ToolResultEvent(id='unaccepted', name='workflow', result='{"ok":true}'))
    assert not app.state.issues[0].recovered
    workflow.add_validation_result(latest)
    snapshot = copy.deepcopy(workflow.to_dict())
    dispatch(app, ToolCallEvent(id='accepted', name='workflow', args=args | {'assessment':{'criteria':'fixture attestation'}}))
    dispatch(app, ToolResultEvent(id='accepted', name='workflow', result='{"ok":true}'))
    assert app.state.issues[0].recovered
    assert workflow.to_dict() == snapshot
    dispatch(app, DoneEvent(stop_reason='final_response'))
    assert 'findings saved' not in app.state.transcript[-1].text
    assert '1 accepted-but-unsaved validation;' in app.state.transcript[-1].text


@pytest.mark.parametrize('outcome', ['confirmed', 'not-confirmed'])
@pytest.mark.parametrize('long_impact', [False, True])
def test_contextual_validation_displays_only_accepted_recorded_impact(tmp_path, outcome, long_impact):
    tool, _ = _tool(tmp_path)
    app = make_app()
    workflow, candidate = configure(app, tool, tmp_path)
    latest = workflow.latest_result(candidate.id)
    assert latest is not None
    workflow.validation_results.clear()
    app.dispatch(SetBusy(True))
    hypothesis = 'Authentication bypass hypothesis still requires evidence'
    recorded = 'Only the reviewed fixture behavior was observed; password=short-secret'
    if long_impact:
        recorded = 'Only the reviewed fixture behavior was observed. ' * 12 + 'password=short-secret'
    result = adopt_fixture_assessment(workflow, ValidationResult(candidate.id, 'test-skill', outcome,
        evidence_refs=latest.evidence_refs), assessment={'observed_impact':recorded, 'hypothesis':hypothesis})
    dispatch(app, AssistantTextEvent(text='The hypothesis alone does not establish a result.'))
    assert not any('Validation confirmed' in entry.text for entry in app.state.transcript)
    workflow.add_validation_result(result)
    snapshot = copy.deepcopy(workflow.to_dict())
    dispatch(app, ToolCallEvent(id='accepted-context', name='workflow', args={
        'action':'record_result', 'candidate_id':candidate.id}))
    dispatch(app, ToolResultEvent(id='accepted-context', name='workflow', result='{"ok":true}'))
    from src.ui.widgets.transcript import entry_view
    rows = ['\n'.join(line.text for line in entry_view(entry)) for entry in app.state.transcript if entry.text.startswith('Validation ')]
    assert len(rows) == 1 and outcome.replace('-', ' ') in rows[0]
    assert 'Observed impact · Only the reviewed fixture behavior was observed' in rows[0]
    assert hypothesis not in rows[0] and 'short-secret' not in repr(app.state.transcript)
    assert ('… [shortened]' in rows[0]) is long_impact
    assert rows[0].count('[shortened]') == int(long_impact)
    from src.ui.theme import PRIMARY, MUTED
    entry = next(entry for entry in app.state.transcript if entry.text.startswith('Validation '))
    assert len(entry.details[0].removeprefix('Observed impact · ')) <= 240
    lines = entry_view(entry)
    assert next(line for line in lines if 'Observed impact · ' in line.text).color == PRIMARY
    assert next(line for line in lines if 'Evidence · ' in line.text).color == MUTED
    assert workflow.to_dict() == snapshot


def test_candidate_processing_and_http_observations_cannot_supply_missing_conclusion():
    from src.ui.core.outcomes import OutcomeFacts, ProgressRecord
    from src.ui.core.state import reducer, initial_state
    from src.ui.widgets.banner import BannerData
    state = initial_state('', BannerData('test','test','.'))
    state = reducer(state, SetBusy(True, facts=OutcomeFacts(scope='fixture')))
    facts = OutcomeFacts(scope='fixture', records=(
        ProgressRecord('selection','one','POST /login · input email'),
        ProgressRecord('candidate','one','POST /login · input email · authentication','validated'),))
    state = reducer(state, AgentEventAction(ToolCallEvent(id='first', name='http',
        args={'url':'/login', 'method':'POST', 'parameter':'email'}), facts=facts))
    assert len(state.transcript) == 1 and state.transcript[0].text.startswith('Selected: POST /login')
    assert '1 input)' in state.transcript[0].text and 'captured' not in state.transcript[0].text
    for i in range(30):
        event_id = 'first' if i == 0 else str(i)
        if i:
            state = reducer(state, AgentEventAction(ToolCallEvent(id=event_id, name='http',
                args={'url':'/login', 'method':'POST'}), facts=facts))
        state = reducer(state, AgentEventAction(ToolResultEvent(id=event_id, name='http',
            http_status=200, status='observation'), facts=facts))
    assert len(state.transcript) == 1  # Repeated calls keep one selection row during work.
    state = reducer(state, AgentEventAction(DoneEvent(stop_reason='workflow_blocked'), facts=facts))
    text = '\n'.join(entry.text for entry in state.transcript)
    assert 'Candidate recorded ·' in text and 'validated' not in text and 'finished' not in text
    assert 'HTTP activity (observations only): 30 responses' in text
    assert 'Validation confirmed' not in text and 'authentication bypass' not in text.lower()
    assert sum(entry.text.startswith('HTTP activity') for entry in state.transcript) == 1


def test_validation_without_impact_and_blocked_summary_use_only_available_facts():
    from src.ui.core.outcomes import OutcomeFacts, ProgressRecord
    from src.ui.core.state import reducer, initial_state
    from src.ui.widgets.banner import BannerData
    state = initial_state('', BannerData('test','test','.'))
    state = reducer(state, SetBusy(True, facts=OutcomeFacts(scope='fixture')))
    facts = OutcomeFacts(scope='fixture', records=(ProgressRecord('validation','one','GET /search · input q','confirmed'),),
        incomplete=1, blockers=('POST /login · input email: authorization required; token=short-secret',))
    state = reducer(state, AgentEventAction(DoneEvent(stop_reason='workflow_blocked'), facts=facts))
    rows = [entry.text for entry in state.transcript if entry.text.startswith('Validation ')]
    assert rows == ['Validation confirmed · GET /search · input q']
    final = state.transcript[-1].text
    assert final.startswith('Blocked · POST /login · input email: authorization required')
    assert 'short-secret' not in final and '1 incomplete validation;' in final
