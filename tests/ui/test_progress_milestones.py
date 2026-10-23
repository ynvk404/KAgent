"""Offline runtime/reducer contracts for chronological Smart Progress."""
import asyncio
import copy
import json
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast

import pytest

from src.agent.agent import Agent, _to_agent_event
from src.agent.events import DecisionEvent, SkillActiveEvent, ToolCallEvent, ToolResultEvent, DoneEvent
from src.permission.permission import AlwaysAllow
from src.target.target import Target
from src.tools.workflow.workflow_tool import WorkflowTool
from src.ui.core.state import AgentEventAction, SetBusy, reducer, initial_state
from src.ui.widgets.banner import BannerData
from src.ui.widgets.transcript import entry_view
from src.ui.theme import BOLD_ACCENT, BOLD_SUCCESS, MUTED, PRIMARY
from src.workflow.state import Candidate, WorkflowState, WorkflowObjective
from src.workflow.state import ValidationResult, ValidationOutcome, WorkflowPhase
from src.workflow.assessment import accepted_result, seal
from tests.helpers.workflow import adopt_fixture_assessment, record_completed_phase
from tests.tools.test_finding import _linked_proof
from tests.ui.test_app import make_app, timer_app


ORIGIN = 'https://fixture.test'


def runtime(tmp_path, *, whole=False):
    app = make_app()
    target = Target(ORIGIN)
    workflow = WorkflowState(objective=WorkflowObjective('fixture-objective',
        'whole_target' if whole else 'direct', ORIGIN))
    tool = WorkflowTool(workflow, target=target, evidence_root=tmp_path)
    app.agent = cast(Any, SimpleNamespace(workflow=workflow, target=target,
        prompter=AlwaysAllow(), tools={'workflow':tool}))
    app.dispatch(SetBusy(True))
    return app, workflow, tool


def dispatch(app, event):
    app.dispatch(AgentEventAction(event))


def test_planner_contract_is_additive_and_summary_never_becomes_a_recommendation():
    state = reducer(initial_state('', BannerData('fixture','fixture','.')), SetBusy(True))
    legacy = _to_agent_event({'type':'decision', 'summary':'Planner · imagined · risk: high'})
    state = reducer(state, AgentEventAction(legacy))
    assert not state.transcript
    for skill, candidate in [('alpha','a'), ('alpha','a'), ('alpha','b'), ('beta','b'), ('alpha','a')]:
        event = _to_agent_event({'type':'decision', 'summary':'private text password=secret',
            'recommended_skill':skill, 'candidate_id':candidate, 'reason':'recorded router reason'})
        state = reducer(state, AgentEventAction(event))
    assert [entry.text for entry in state.transcript] == [
        'Planner recommended · alpha', 'Planner recommended · alpha',
        'Planner recommended · beta', 'Planner recommended · alpha']
    assert 'private text' not in repr(state.transcript)


def test_failed_activation_cannot_become_a_skill_milestone_and_duplicates_are_suppressed():
    app = make_app()
    app.dispatch(SetBusy(True))
    dispatch(app, ToolCallEvent(id='denied',name='load_skill',args={'name':'alpha'}))
    dispatch(app, ToolResultEvent(id='denied',name='load_skill',status='error',err='permission denied'))
    dispatch(app, SkillActiveEvent(name='alpha',call_id='denied'))
    assert app.state.active_skill is None
    assert any(entry.kind == 'warning' for entry in app.state.transcript)
    dispatch(app, ToolCallEvent(id='loaded',name='load_skill',args={'name':'alpha'}))
    dispatch(app, ToolResultEvent(id='loaded',name='load_skill',result='offline successful receipt'))
    for _ in range(2):dispatch(app, SkillActiveEvent(name='alpha',call_id='loaded'))
    assert sum(entry.text == 'Skill activated · alpha' for entry in app.state.transcript) == 1
    assert app.state.issues[0].recovered
    assert app.state.active_skill == 'alpha'


@pytest.mark.asyncio
async def test_validation_start_requires_matching_active_workflow_attempt_and_success(tmp_path):
    app, workflow, tool = runtime(tmp_path)
    candidate, _ = workflow.add_candidate(Candidate(candidate_class='xss',target=ORIGIN,
        endpoint='/search',method='GET',parameter='q',objective_id='fixture-objective'))
    args = {'action':'start_validation','candidate_id':candidate.id}
    dispatch(app, ToolCallEvent(id='rejected',name='workflow',args=args))
    dispatch(app, ToolResultEvent(id='rejected',name='workflow',result='{"ok":false,"error":"not started"}'))
    assert not any(entry.text.startswith('Validation started') for entry in app.state.transcript)
    dispatch(app, ToolCallEvent(id='start',name='workflow',args=args))
    assert not any(entry.text.startswith('Validation started') for entry in app.state.transcript)
    receipt = await tool.run(args, None, AlwaysAllow())
    assert json.loads(receipt)['ok'] is True
    snapshot = copy.deepcopy(workflow.to_dict())
    event = ToolResultEvent(id='start',name='workflow',result=receipt)
    dispatch(app, event)
    dispatch(app, event)
    assert sum(entry.text.startswith('Validation started') for entry in app.state.transcript) == 1
    texts = [entry.text for entry in app.state.transcript]
    assert next(i for i, text in enumerate(texts) if text.startswith('Candidate recorded')) < next(
        i for i, text in enumerate(texts) if text.startswith('Validation started'))
    assert workflow.to_dict() == snapshot
    dispatch(app, ToolCallEvent(id='fake',name='workflow',args=args))
    bad = json.loads(receipt)
    bad['validation_context']['attempt_id'] = 'missing'
    dispatch(app, ToolResultEvent(id='fake',name='workflow',result=json.dumps(bad)))
    assert sum(entry.text.startswith('Validation started') for entry in app.state.transcript) == 1


def test_visual_hierarchy_keeps_conclusion_prominent_and_detail_subordinate():
    from src.ui.core.state import TranscriptEntry
    confirmed = entry_view(TranscriptEntry('validation', 'Validation confirmed · GET /search\n  Observed impact · fixture'))
    assert confirmed[0].color == BOLD_SUCCESS and confirmed[1].color == PRIMARY
    negative = entry_view(TranscriptEntry('info', 'Validation not confirmed · GET /search'))
    assert negative[0].color == BOLD_ACCENT


def test_sensitive_field_redaction_preserves_other_milestone_details():
    from src.ui.core.state import TranscriptEntry, Append
    entry = TranscriptEntry('validation','Validation confirmed · fixture',details=(
        'Observed impact · token=[REDACTED]', 'Evidence · baseline',
        '-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----'))
    state = reducer(initial_state('',BannerData('offline','fixture','.')),Append(entry))
    lines = entry_view(state.transcript[0])
    text = '\n'.join(line.text for line in lines)
    assert 'Evidence · baseline' in text and 'token=[REDACTED]' in text
    assert 'private-material' not in text and 'private-material' not in repr(state)


@pytest.mark.asyncio
async def test_previous_turn_callback_cannot_write_into_new_turn():
    app, _, _ = timer_app()
    sinks = []
    async def run(value, *, signal, emit, opts=None):
        sinks.append(emit)
        if len(sinks) == 2:
            sinks[0](DecisionEvent(recommended_skill='stale'))
            sinks[0](SkillActiveEvent(name='stale'))
            sinks[0](DoneEvent(stop_reason='cancelled'))
        emit(DoneEvent(stop_reason='final_response'))
    app.agent = cast(Agent, SimpleNamespace(is_running=lambda:False, run=run))
    await app.run_agent_turn('first')
    await app.run_agent_turn('second')
    assert not any('stale' in entry.text for entry in app.state.transcript)
    assert app.state.transcript[-1].text == 'Turn completed.'


@pytest.mark.asyncio
@pytest.mark.parametrize('operation', ['turn', 'compact'])
async def test_late_run_failure_and_cleanup_cannot_clear_a_new_run(operation):
    from src.ui.core.app import AbortEvent
    app, _, _ = timer_app()
    new_owner = AbortEvent()
    new_task = object()
    async def superseded(*args, **kwargs):
        app.run_abort_event = new_owner
        app.run_task = cast(Any, new_task)
        app.dispatch(SetBusy(True))
        kwargs['emit'](DecisionEvent(recommended_skill='late'))
        raise RuntimeError('old run failed after ownership changed')
    app.agent = cast(Agent, SimpleNamespace(is_running=lambda:False, run=superseded, compact=superseded))
    if operation == 'turn':
        await app.run_agent_turn('fixture')
    else:
        await app._run_agent_compact()
    assert app.run_abort_event is new_owner and app.run_task is new_task
    assert app.state.busy
    assert not any('late' in entry.text or 'old run failed' in entry.text for entry in app.state.transcript)


def test_old_target_event_and_inflight_result_cannot_change_live_context(tmp_path):
    app, _, _ = runtime(tmp_path)
    dispatch(app, ToolCallEvent(id='old',name='http',args={'url':ORIGIN+'/old','method':'GET'}))
    previous = app.state
    app.agent.target.set_base_url('https://other.test')
    dispatch(app, ToolResultEvent(id='old',name='http',result='old traffic',http_status=200))
    assert app.state.transcript == previous.transcript and not app.state.running_tool
    assert not app.state.observed
    dispatch(app, DecisionEvent(recommended_skill='old',target_origin=ORIGIN))
    assert app.state.transcript == previous.transcript and not app.state.running_tool
    dispatch(app, ToolCallEvent(id='new',name='http',args={'url':'https://other.test/new','method':'GET'}))
    assert '/new' in (app.state.running_tool or '') and not app.state.active_skill
    current = app.state
    dispatch(app, SkillActiveEvent(name='old', target_origin=ORIGIN))
    dispatch(app, DecisionEvent(recommended_skill='old',target_origin=ORIGIN))
    assert app.state == current


def accepted_fixture(tmp_path, workflow, candidate, *, outcome: ValidationOutcome='confirmed', role=None):
    proof = _linked_proof(workflow, candidate, tmp_path)
    result = adopt_fixture_assessment(workflow, ValidationResult(candidate.id, 'fixture-validator', outcome,
        evidence_refs=[proof]), assessment={'observed_impact':'Recorded fixture impact; token=short-secret'})
    if role:
        source = result.evidence_manifest[0]['source']
        attempt = workflow.attempts[result.attempt_id]
        attempt['related_requests'] = [{'role':role,'method':source['method'],'url':source['url'],'required':True}]
        source['role'] = role
        source['required'] = True
        result.assessment['attempt'] = {k:v for k,v in attempt.items() if k != 'status'}
        result.assessment_binding = seal(result)
    assert accepted_result(workflow, candidate, result)
    return result


@pytest.mark.parametrize('mode', ['direct','burp-assisted','whole_target'])
@pytest.mark.parametrize('outcome', ['confirmed','not-confirmed'])
def test_accepted_evidence_is_scoped_subordinate_and_read_only(tmp_path, mode, outcome):
    app, workflow, _ = runtime(tmp_path, whole=mode=='whole_target')
    candidate, _ = workflow.add_candidate(Candidate(candidate_class='xss',target=ORIGIN,
        method='GET',endpoint='/search',parameter='q',objective_id='fixture-objective'))
    if mode == 'burp-assisted':
        from src.browser.store import CaptureStore
        from src.browser.selection import CaptureSelection
        from src.engagement.state import EngagementState
        engagement = EngagementState()
        engagement.initialize_target(ORIGIN)
        captures = CaptureStore()
        captures.ingest({'kind':'burp','id':'selected','method':'GET','url':ORIGIN+'/search?q=fixture'})
        app.agent.engagement_state = engagement
        app.agent.pending_capture_selection = CaptureSelection.create(captures.list_requests(), app.agent.target, engagement, None)
        app.dispatch(SetBusy(False))
        app.dispatch(SetBusy(True))
    result = accepted_fixture(tmp_path, workflow, candidate, outcome=outcome, role='baseline')
    dispatch(app, ToolCallEvent(id='accepted',name='workflow',args={
        'action':'record_result','candidate_id':candidate.id,'attempt_id':result.attempt_id}))
    workflow.add_validation_result(result)
    snapshot = copy.deepcopy(workflow.to_dict())
    dispatch(app, ToolResultEvent(id='accepted',name='workflow',result=json.dumps({'ok':True,'result':result.public_dict()})))
    rows = [entry for entry in app.state.transcript if entry.text.startswith('Validation ')]
    assert len(rows) == 1
    assert 'Evidence · 1 HTTP observation' in '\n'.join(line.text for line in entry_view(rows[0]))
    assert rows[0].kind == ('validation' if outcome=='confirmed' else 'info')
    assert 'short-secret' not in repr(app.state.transcript)
    assert result.evidence_manifest[0]['hash'] not in repr(app.state.transcript)
    assert workflow.to_dict() == snapshot
    if mode == 'burp-assisted':
        assert any('captured request' in entry.text for entry in app.state.transcript)
    if mode == 'whole_target':
        assert app.state.latest_facts and app.state.latest_facts.overview
    else:
        assert app.state.latest_facts and not app.state.latest_facts.overview
    assert not any(entry.text.startswith('Workflow ·') for entry in app.state.transcript)


def test_changed_evidence_never_produces_an_accepted_evidence_or_confirmation_row(tmp_path):
    app, workflow, _ = runtime(tmp_path)
    candidate, _ = workflow.add_candidate(Candidate(candidate_class='xss',target=ORIGIN,
        method='GET',endpoint='/search',parameter='q',objective_id='fixture-objective'))
    result = accepted_fixture(tmp_path, workflow, candidate, role='baseline')
    workflow.add_validation_result(result)
    (tmp_path/workflow.evidence[result.evidence_refs[0]].path).write_text('Changed bytes',encoding='utf-8')
    dispatch(app, ToolCallEvent(id='invalid',name='workflow',args={'action':'record_result','candidate_id':candidate.id}))
    dispatch(app, ToolResultEvent(id='invalid',name='workflow',result='{"ok":true}'))
    dispatch(app, DoneEvent(stop_reason='workflow_blocked'))
    text = '\n'.join(entry.text for entry in app.state.transcript)
    assert 'Validation confirmed' not in text and 'Evidence ·' not in text
    assert 'assessment/evidence unavailable' in text


@pytest.mark.asyncio
async def test_real_validation_start_replays_are_deduplicated_but_new_attempt_is_preserved(tmp_path):
    app, workflow, tool = runtime(tmp_path)
    candidate, _ = workflow.add_candidate(Candidate(candidate_class='xss',target=ORIGIN,
        method='GET',endpoint='/search',parameter='q',objective_id='fixture-objective'))
    args = {'action':'start_validation','candidate_id':candidate.id}
    attempts = []
    for event_id in ['first','duplicate','retry']:
        if event_id == 'retry':workflow.attempts[attempts[0]]['status'] = 'completed'
        dispatch(app, ToolCallEvent(id=event_id,name='workflow',args=args))
        receipt = await tool.run(args,None,AlwaysAllow())
        attempts.append(json.loads(receipt)['validation_context']['attempt_id'])
        dispatch(app, ToolResultEvent(id=event_id,name='workflow',result=receipt))
    assert attempts[0] == attempts[1] and attempts[2] != attempts[0]
    assert sum(entry.text.startswith('Validation started') for entry in app.state.transcript) == 2


def test_shared_endpoint_candidates_do_not_share_recovery_or_conclusions(tmp_path):
    app, workflow, _ = runtime(tmp_path)
    candidates = [workflow.add_candidate(Candidate(candidate_class=cls,target=ORIGIN,
        method='GET',endpoint='/search',parameter='q',objective_id='fixture-objective'))[0]
        for cls in ['xss','sqli']]
    for event_id, candidate in zip(['first','second'],candidates):
        dispatch(app, ToolCallEvent(id=event_id,name='http',args={
            'url':ORIGIN+'/search','method':'GET','candidate_id':candidate.id}))
    assert len(app.state.pending_calls) == 2
    dispatch(app, DecisionEvent(recommended_skill='another-skill'))
    assert app.state.phase == 'running-tool' and '/search' in (app.state.running_tool or '')
    dispatch(app, ToolResultEvent(id='first',name='http',err='transient failure',status='error',error_kind='network'))
    assert len(app.state.pending_calls) == 1
    dispatch(app, ToolResultEvent(id='second',name='http',http_status=200,status='observation'))
    assert not app.state.issues[0].recovered
    assert app.state.running_tool is None and app.state.running_skill is None
    for index, candidate in enumerate(candidates):
        result = accepted_fixture(tmp_path,workflow,candidate,outcome='confirmed' if index==0 else 'not-confirmed')
        workflow.add_validation_result(result)
        dispatch(app, ToolCallEvent(id='result'+str(index),name='workflow',args={
            'action':'record_result','candidate_id':candidate.id,'attempt_id':result.attempt_id}))
        dispatch(app, ToolResultEvent(id='result'+str(index),name='workflow',result=json.dumps({'ok':True,'result':result.public_dict()})))
    rows = [entry.text for entry in app.state.transcript if entry.text.startswith('Validation ')]
    assert len(rows) == 2 and 'confirmed' in rows[0] and 'not confirmed' in rows[1]
    assert candidates[0].candidate_class in rows[0] and candidates[1].candidate_class in rows[1]


def test_old_attempt_receipt_cannot_recover_failure_from_a_new_attempt(tmp_path):
    app, workflow, _ = runtime(tmp_path)
    candidate, _ = workflow.add_candidate(Candidate(candidate_class='xss',target=ORIGIN,
        method='GET',endpoint='/search',parameter='q',objective_id='fixture-objective'))
    old = accepted_fixture(tmp_path,workflow,candidate)
    new = accepted_fixture(tmp_path,workflow,candidate)
    workflow.add_validation_result(new)
    args = {'action':'record_result','candidate_id':candidate.id,'attempt_id':old.attempt_id}
    dispatch(app, ToolCallEvent(id='failed',name='workflow',args=args))
    dispatch(app, ToolResultEvent(id='failed',name='workflow',result='{"ok":false,"error":"stale attempt"}'))
    dispatch(app, ToolCallEvent(id='replay',name='workflow',args=args))
    dispatch(app, ToolResultEvent(id='replay',name='workflow',result=json.dumps({'ok':True,'result':old.public_dict()})))
    assert not app.state.issues[0].recovered


@pytest.mark.parametrize('outcome', ['blocked','deferred','browser-required','authorization-required','insufficient-evidence'])
def test_nonterminal_outcome_requires_canonical_record_and_keeps_recorded_reason(tmp_path, outcome):
    app, workflow, _ = runtime(tmp_path)
    candidate, _ = workflow.add_candidate(Candidate(candidate_class='xss',target=ORIGIN,
        method='GET',endpoint='/search',parameter='q',objective_id='fixture-objective'))
    result = ValidationResult(candidate.id,'fixture-validator',outcome,objective_id='fixture-objective',
        deferred_reason='Recorded constraint; password=short-secret')
    workflow.add_validation_result(result)
    dispatch(app, ToolCallEvent(id='pause',name='workflow',args={'action':'record_result','candidate_id':candidate.id}))
    receipt = json.dumps({'ok':True,'result':result.public_dict()})
    dispatch(app, ToolResultEvent(id='pause',name='workflow',result=receipt))
    rows = [entry for entry in app.state.transcript if entry.text.startswith('Validation ')]
    assert len(rows) == 1 and rows[0].kind == 'warning'
    rendered = '\n'.join(line.text for line in entry_view(rows[0]))
    assert outcome.replace('-',' ') in rendered
    assert 'Recorded constraint' in rendered and 'short-secret' not in rendered
    assert 'Validation confirmed' not in repr(app.state.transcript)
    dispatch(app, DoneEvent(stop_reason='workflow_blocked'))
    completion = app.state.transcript[-1]
    assert completion.kind == 'warning'
    assert 'Recorded constraint' in completion.text and 'short-secret' not in completion.text
    assert 'candidate deferred' not in completion.text
    assert '1 active workflow blocker' in completion.text


def test_whole_target_overview_uses_only_recorded_state_and_completion_needs_runtime_outcome(tmp_path):
    from pathlib import Path
    from src.skills.artifacts import completion_artifact_path
    from src.skills.registry import Registry as SkillRegistry

    app, workflow, tool = runtime(tmp_path,whole=True)
    tool.skills = SkillRegistry()
    tool.skills.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    phases: tuple[WorkflowPhase, ...] = ('recon','enumeration','input_analysis')
    for phase, name in zip(phases, ('recon', 'web-enumeration', 'web-input-analysis')):
        skill = tool.skills.get(name)
        assert skill is not None and skill.completion_artifact
        artifact_ref = completion_artifact_path(skill.completion_artifact, ORIGIN)
        artifact = tmp_path / artifact_ref
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text('Explicit offline discovery fixture record.')
        record_completed_phase(workflow,phase,objective_id='fixture-objective',target_origin=ORIGIN,
            artifact_ref=artifact_ref,no_inputs_discovered=phase=='input_analysis')
        dispatch(app, ToolCallEvent(id=phase,name='workflow',args={'action':'complete_skill'}))
        dispatch(app, ToolResultEvent(id=phase,name='workflow',result='{"ok":true}'))
        assert not any(entry.text.startswith('Workflow ·') for entry in app.state.transcript)
        expected = {'recon': 'Enumeration', 'enumeration': 'Input Analysis', 'input_analysis': 'Validation'}[phase]
        assert app.state.latest_facts and app.state.latest_facts.overview == 'Workflow · ' + expected
        assert phase in workflow.completed_phases()  # Detail remains in Workflow.
        assert not any(entry.text.startswith('Workflow completed') for entry in app.state.transcript)
    snapshot = copy.deepcopy(workflow.to_dict())
    dispatch(app, DoneEvent(stop_reason='workflow_completed'))
    assert app.state.transcript[-1].text == 'Workflow completed.'
    assert workflow.to_dict() == snapshot


def test_replayed_planner_and_activation_ids_never_masquerade_as_new_switches():
    app = make_app()
    app.dispatch(SetBusy(True))
    old = DecisionEvent(recommended_skill='alpha',decision_id='old')
    dispatch(app, old)
    dispatch(app, DecisionEvent(recommended_skill='beta',decision_id='new'))
    dispatch(app, old)
    assert [entry.text for entry in app.state.transcript] == [
        'Planner recommended · alpha','Planner recommended · beta']
    for event_id, name in [('a','alpha'),('b','beta')]:
        dispatch(app, ToolCallEvent(id=event_id,name='load_skill',args={'name':name}))
        dispatch(app, ToolResultEvent(id=event_id,name='load_skill',result='offline loaded'))
        dispatch(app, SkillActiveEvent(name=name,call_id=event_id))
    dispatch(app, SkillActiveEvent(name='alpha',call_id='a'))
    assert app.state.active_skill == 'beta'
    assert sum(entry.text.startswith('Skill activated') for entry in app.state.transcript) == 2


@pytest.mark.parametrize('width', [40,60,80,120])
def test_narrow_live_bar_keeps_method_input_and_cancel_affordance(width):
    from src.ui.widgets.status_bar import StatusProps, busy_line
    props = StatusProps(True,True,'long-skill-name',False,0,0,0,0,'running-tool',
        running_tool='http: POST /very/long/path/that/will/not/fit/in/a/small/terminal · input email',elapsed_seconds=65)
    line = busy_line(props,width=width)
    assert line.cell_len <= width and 'POST' in line.plain and 'email' in line.plain
    assert 'Esc' in line.plain and '01:05' in line.plain
    props.running_tool = 'workflow: start validation · GET /search · input q'
    line = busy_line(props,width=width)
    assert line.cell_len <= width and 'GET' in line.plain and 'q' in line.plain
    for activity in ['workflow: start validation · POST /rest/user/login · input email',
                     'workflow: record result · POST /rest/user/login · input email']:
        props.running_tool = activity
        line = busy_line(props,width=width)
        assert line.cell_len <= width and 'POST' in line.plain and 'email' in line.plain
        assert 'Esc' in line.plain and '01:05' in line.plain


def test_permission_wait_survives_other_events_and_cancellation_clears_live_context():
    from src.ui.core.state import SetPerm
    app = make_app()
    props = []
    app.status_bar = cast(Any, SimpleNamespace(apply=props.append, elapsed_seconds=0))
    app.agent = cast(Agent, SimpleNamespace(target=Target(ORIGIN),
        get_memory_stats=lambda:SimpleNamespace(items=0), approx_tokens=lambda:0,
        idle_request_estimate=lambda:SimpleNamespace(estimated_total=0), get_auto_compact_threshold=lambda:0))
    app.dispatch(SetBusy(True))
    dispatch(app, SkillActiveEvent(name='alpha'))
    dispatch(app, ToolCallEvent(id='one',name='http',args={'url':'/search','method':'GET','parameter':'q'}))
    app.dispatch(SetPerm(cast(Any,object())))
    dispatch(app, DecisionEvent(recommended_skill='beta'))
    dispatch(app, ToolCallEvent(id='other',name='http',args={'url':'/health','method':'GET'}))
    assert app.state.phase == 'waiting-approval' and app.state.running_skill is None
    app._sync_status_bar()
    assert props[-1].running_tool is None and props[-1].active_skill is None
    dispatch(app, ToolResultEvent(id='other',name='http',http_status=200))
    assert app.state.phase == 'waiting-approval' and '/search' in (app.state.running_tool or '')
    app._sync_status_bar()
    assert '/search' in (props[-1].running_tool or '')
    app.dispatch(SetPerm(None))
    dispatch(app, DoneEvent(stop_reason='cancelled'))
    assert app.state.transcript[-1].text == 'Turn cancelled.'
    assert app.state.active_skill is None and app.state.running_tool is None
    before = app.state
    dispatch(app, SkillActiveEvent(name='stale'))
    dispatch(app, DecisionEvent(recommended_skill='stale'))
    assert app.state == before


@pytest.mark.asyncio
async def test_actual_richlog_writer_applies_hierarchy_on_a_narrow_screen():
    from io import StringIO
    from rich.style import Style
    from src.ui.core.app import _RichLogWriter
    from src.ui.core.state import TranscriptEntry
    from src.ui.widgets.transcript import Transcript
    from tests.ui.test_transcript_view import _TranscriptHarness
    app = _TranscriptHarness()
    async with app.run_test(size=(50,12)) as pilot:
        app.transcript.clear()
        writer = _RichLogWriter(app.transcript)
        transcript = Transcript(out=StringIO(),width=writer.content_width,clear=app.transcript.clear,
            write_banner=lambda _:None,preserve_viewport=app.transcript.preserve_viewport,write_line=writer.write_line)
        transcript.flush([
            TranscriptEntry('validation','Validation confirmed · GET /search · q', details=(
                'Evidence · 1 HTTP observation',
                'Observed impact · ' + 'Reviewed response behavior. ' * 4 + 'End of impact.')),
            TranscriptEntry('info','Validation not confirmed · GET /other'),
            TranscriptEntry('finding','Finding saved · Fixture\n  artifacts/findings/fixture.md')],
            BannerData('offline','fixture','.'),generation=0)
        await pilot.pause()
        text = '\n'.join(line.text for line in app.transcript.lines)
        assert 'Validation confirmed' in text and 'Evidence · 1 HTTP observation' in text
        assert 'Observed impact' in text and 'End of impact.' in ' '.join(text.split())
        assert 'Validation not confirmed' in text and 'artifacts/findings/fixture.md' in text
        first = app.transcript.lines[0]
        assert any(segment.style and segment.style.color == Style.parse(BOLD_SUCCESS).color
                   and segment.style.bold for segment in first)
        assert any(segment.style and segment.style.color == Style.parse(MUTED).color
                   for segment in app.transcript.lines[1])
        impact_start = next(index for index, line in enumerate(app.transcript.lines)
                            if 'Observed impact' in line.text)
        impact_end = next(index for index in range(impact_start, len(app.transcript.lines))
                          if not app.transcript.lines[index].text.strip())
        impact_lines = app.transcript.lines[impact_start:impact_end]
        assert all(any(segment.style and segment.style.color == Style.parse(PRIMARY).color
                       for segment in line) for line in impact_lines)
        assert all(line.cell_length <= app.transcript.transcript_content_width for line in app.transcript.lines)


@pytest.mark.asyncio
@pytest.mark.parametrize('width',[40,60,80])
async def test_statusbar_compositor_keeps_context_and_cancel_after_padding(width):
    from textual.app import App, ComposeResult
    from src.ui.widgets.status_bar import StatusBar
    class Harness(App):
        def compose(self) -> ComposeResult:
            yield StatusBar()
    app = Harness()
    async with app.run_test(size=(width,8)) as pilot:
        bar = app.query_one(StatusBar)
        bar.busy = True
        bar.phase = 'running-tool'
        bar.running_tool = 'http: POST /long/fixture/path/for/a/narrow/terminal · input email'
        bar.elapsed_seconds = 62
        await pilot.pause()
        row = app.screen._compositor.render_strips()[bar.region.y].text
        assert 'POST' in row and 'email' in row and 'Esc' in row and '01:02' in row


def test_burp_selection_survives_initial_objective_creation(tmp_path):
    from src.browser.store import CaptureStore
    from src.browser.selection import CaptureSelection
    from src.engagement.state import EngagementState
    app, workflow, _ = runtime(tmp_path)
    workflow.objective = None
    engagement = EngagementState()
    engagement.initialize_target(ORIGIN)
    captures = CaptureStore()
    captures.ingest({'kind':'burp','id':'selected','method':'POST','url':ORIGIN+'/login'})
    app.agent.engagement_state = engagement
    app.agent.pending_capture_selection = CaptureSelection.create(captures.list_requests(),app.agent.target,engagement,None)
    app.dispatch(SetBusy(False))
    app.dispatch(SetBusy(True))
    workflow.objective = WorkflowObjective('new-objective','direct',ORIGIN)
    dispatch(app,DecisionEvent(recommended_skill='fixture'))
    from src.agent.events import AssistantTextEvent
    dispatch(app,AssistantTextEvent(text='Recorded input selection.'))
    assert any('POST /login' in entry.text and '1 captured request' in entry.text for entry in app.state.transcript)


@pytest.mark.asyncio
async def test_cancelled_retest_keeps_new_attempt_pending_without_recounting_old_confirmation(tmp_path):
    app, workflow, tool = runtime(tmp_path)
    candidate, _ = workflow.add_candidate(Candidate(candidate_class='xss',target=ORIGIN,
        method='GET',endpoint='/search',parameter='q',objective_id='fixture-objective'))
    old = accepted_fixture(tmp_path,workflow,candidate)
    workflow.add_validation_result(old)
    app.dispatch(SetBusy(False))
    app.dispatch(SetBusy(True))
    args = {'action':'start_validation','candidate_id':candidate.id}
    dispatch(app,ToolCallEvent(id='retest',name='workflow',args=args))
    receipt = await tool.run(args,None,AlwaysAllow())
    assert json.loads(receipt)['ok'] is True
    dispatch(app,ToolResultEvent(id='retest',name='workflow',result=receipt))
    dispatch(app,DoneEvent(stop_reason='cancelled'))
    assert '1 incomplete validation' in app.state.transcript[-1].text
    assert not any(entry.text.startswith('Validation confirmed') for entry in app.state.transcript)


def complete_phase_fixtures(workflow, tool, tmp_path):
    from src.skills.registry import Registry as Skills
    from src.skills.artifacts import completion_artifact_path
    tool.skills = Skills()
    tool.skills.load_dir('skills')
    for phase, name in [('recon', 'recon'), ('enumeration', 'web-enumeration'), ('input_analysis', 'web-input-analysis')]:
        skill = tool.skills.get(name)
        assert skill and skill.completion_artifact
        ref = completion_artifact_path(skill.completion_artifact, ORIGIN)
        path = tmp_path / ref
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('Explicit bounded offline phase fixture.')
        record_completed_phase(workflow, cast(WorkflowPhase, phase), objective_id='fixture-objective',
            target_origin=ORIGIN, artifact_ref=ref, no_inputs_discovered=phase == 'input_analysis' and not workflow.objective_inputs())


def test_planner_same_validator_resolves_scoped_candidate_context_and_keeps_deduplication(tmp_path):
    app, workflow, _ = runtime(tmp_path)
    candidates = [workflow.add_candidate(Candidate(candidate_class='sqli', target=ORIGIN,
        endpoint=endpoint, method=method, parameter=parameter, objective_id='fixture-objective'))[0]
        for method, endpoint, parameter in [('GET', '/search?q=private-query', 'q'),
                                             ('POST', '/login', 'email')]]
    from src.ui.core.outcomes import endpoint_label
    assert endpoint_label('POST', 'https://user:private-credential@fixture.test/login', 'email') == 'POST /login · input email'
    before = copy.deepcopy(workflow.to_dict())
    for candidate in candidates:
        event = DecisionEvent(recommended_skill='sql-injection', candidate_id=candidate.id, decision_id=candidate.id)
        dispatch(app, event)
        dispatch(app, event)
        dispatch(app, replace(event, decision_id=candidate.id + '-new-request'))
    lines = [entry.text for entry in app.state.transcript if entry.text.startswith('Planner recommended')]
    assert len(lines) == 2
    assert 'GET /search' in lines[0] and 'input q' in lines[0]
    assert 'POST /login' in lines[1] and 'input email' in lines[1]
    for line, candidate in zip(lines, candidates):
        assert candidate.id[-8:] not in line
    assert 'private-query' not in repr(lines) and 'private-credential' not in repr(lines)
    assert workflow.to_dict() == before


def test_compact_progress_keeps_counts_negative_acceptance_and_pending_goals(tmp_path):
    from src.ui.core.outcomes import runtime_facts
    from src.ui.widgets.banner import Banner
    from src.workflow.state import AttackSurfaceInput, RequestedGoal
    app, workflow, tool = runtime(tmp_path, whole=True)
    for endpoint in ['/one', '/two']:
        item, _ = workflow.add_attack_surface_input(AttackSurfaceInput('fixture-objective', ORIGIN,
            method='GET', endpoint=endpoint, parameter='q', location='query'))
        workflow.set_input_disposition(item.id, 'analyzed')
        candidate, _ = workflow.add_candidate(Candidate(candidate_class='sqli', target=ORIGIN,
            method='GET', endpoint=endpoint, parameter='q', objective_id='fixture-objective'), input_id=item.id)
        workflow.add_validation_result(accepted_fixture(tmp_path, workflow, candidate, outcome='not-confirmed'))
    complete_phase_fixtures(workflow, tool, tmp_path)
    assert workflow.objective is not None
    workflow.objective.requested_goals.append(RequestedGoal('ssrf'))
    before = copy.deepcopy(workflow.to_dict())
    facts = runtime_facts(app.agent, None, ())
    assert facts.overview == 'Workflow · Validation · 2/2 inputs reviewed · 2 validations accepted · 1 goal pending'
    assert facts.validations == 2 and facts.goals == 1 and not facts.completion_supported
    assert 'confirmed' not in facts.overview and 'completed' not in facts.overview
    lines = Banner(BannerData('fixture', 'fixture', '.'))._detail_lines(assessment_progress=facts.overview)
    assert any(line.plain.startswith('Progress: Validation') for line in lines)
    assert all('Assessment Progress' not in line.plain for line in lines)
    assert workflow.to_dict() == before


@pytest.mark.parametrize('work', ['late-pending', 'blocked', 'artifact-repair', 'owned-recovery'])
def test_progress_uses_actual_work_with_historical_completions_without_mutation(tmp_path, work):
    from src.ui.core.outcomes import runtime_facts
    from src.workflow.state import AttackSurfaceInput, RequestedGoal
    app, workflow, tool = runtime(tmp_path, whole=True)
    candidate, _ = workflow.add_candidate(Candidate(candidate_class='xss', target=ORIGIN,
        method='GET', endpoint='/search', parameter='q', location='query', objective_id='fixture-objective'))
    item, _ = workflow.add_attack_surface_input(AttackSurfaceInput('fixture-objective', ORIGIN,
        method='GET', endpoint='/search', parameter='q', location='query'))
    workflow.link_input_candidate(item.id, candidate.id)
    workflow.set_input_disposition(item.id, 'analyzed')
    complete_phase_fixtures(workflow, tool, tmp_path)
    if work == 'late-pending':
        workflow.add_attack_surface_input(AttackSurfaceInput('fixture-objective', ORIGIN,
            method='GET', endpoint='/late', parameter='q', location='query'))
        expected = 'Input Analysis'
    elif work == 'blocked':
        assert workflow.objective is not None
        workflow.objective.requested_goals.append(RequestedGoal('ssrf', status='blocked'))
        expected = 'Blocked · Validation'
    elif work == 'artifact-repair':
        (tmp_path / workflow.phase_completions['fixture-objective:recon'].artifact_ref).unlink()
        expected = 'Recon repair'
    else:
        from src.workflow.assessment import start_attempt
        from src.workflow.evidence.recovery import current_budget
        assert tool.target is not None
        attempt = start_attempt(workflow, candidate, tool.session_id, tool.evidence_epoch,
            target_origin=ORIGIN, target_revision=tool.target.revision)
        tool.active_attempt = attempt['id']
        workflow.set_candidate_status(candidate.id, 'validating')
        budget = current_budget(workflow, candidate.id, create=True)
        assert budget is not None
        budget.update(rejections=1, repair_turns=2)
        (tmp_path / workflow.phase_completions['fixture-objective:recon'].artifact_ref).unlink()
        expected = 'Validation recovery'
    before = copy.deepcopy(workflow.to_dict())
    facts = runtime_facts(app.agent, None, ())
    assert expected in facts.overview and not facts.completion_supported
    assert ' completed' not in facts.overview
    assert workflow.to_dict() == before
