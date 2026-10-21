"""Offline continuation contracts; scripted compliance is not LLM reliability proof."""
from copy import deepcopy
import json
from urllib.parse import urlencode

import httpx
import pytest

from src.agent.agent import AgentRunOptions, WholeTargetStallTracker
from src.agent.events import MaxStepsError
from src.agent.decision_planner import build_whole_target_plan
from src.agent.validation_guidance import render_validation_guidance
from src.findings.store import Store as FindingStore
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.tools.workflow.finding import ConfirmFindingTool
from src.workflow.assessment import accepted_result
from src.workflow.evidence.recovery import current_budget, MAX_EVIDENCE_REJECTIONS
from src.workflow.discovery.inventory import SourceRecord
from src.workflow.state import WorkflowObjective, WorkflowState
from src.workflow.validation.route import ValidationRoute
from tests.helpers.agent_fakes import FakeClient, FakeSignal, ScriptedModel, collect, seed_compactable_history
from tests.helpers.burp_selection import make_runtime, ORIGIN
from tests.helpers.workflow import prepare_validation_prerequisites
from tests.integration.test_phase2_whole_target_reliability import complete_discovery
from tests.security.test_agent_assessment import ASSESSMENT


PREFIX = 'Runtime validation continuation (current state, not authorization):'


class InspectModel(ScriptedModel):
    def __init__(self, script, check=None):
        super().__init__(script, prefix='continuation')
        self.check = check
        self.requests = []

    async def chat(self, request, signal=None):
        self.requests.append(deepcopy(request))
        if self.check and request.tools:
            self.check(request)
        return await super().chat(request, signal)


def hint(request):
    rows = [m.content for m in request.messages if m.role == 'system' and m.content.startswith(PREFIX)]
    assert len(rows) == 1
    return rows[0]


@pytest.fixture
def offline(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('KAGENT_PROJECT_ROOT', str(tmp_path))
    monkeypatch.setenv('HOME', str(tmp_path))
    sent = []
    real_client = httpx.AsyncClient

    def respond(request):
        sent.append(request)
        truth = request.url.params.get('q') == 'fixture AND 1=1'
        return httpx.Response(200, json={'count': 1 if truth else 0}, request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: real_client(transport=httpx.MockTransport(respond), **kw))
    rt = make_runtime(tmp_path, session_id='offline-continuation')
    rt.workflow.objective = WorkflowObjective('offline-objective', 'whole_target', ORIGIN)
    return rt, sent


async def candidate_for(rt, candidate_class='sqli', *, ready=True):
    result = json.loads(await rt.registry.execute('workflow', {
        'action': 'record_candidate', 'candidate_class': candidate_class, 'endpoint': '/fixture',
        'method': 'GET', 'parameter': 'q', 'location': 'query',
    }, None, rt.prompter))
    cid = result['candidate']['id']
    if ready:
        await prepare_validation_prerequisites(rt.workflow_tool, cid)
        await complete_discovery(rt.workflow_tool, rt.workflow_tool.evidence_root)
    return cid


def workflow(action, **args):
    return 'workflow', {'action': action, **args}


async def execute(rt, model, *, steps):
    rt.agent.set_client(model)
    trace = collect()
    await rt.agent.run('Continue whole-target assessment.', FakeSignal(), trace['sink'], AgentRunOptions(max_steps=steps))
    assert not model.errors
    assert not [e for e in trace['events'] if e.type == 'error' and not isinstance(e.err, MaxStepsError)]
    assert all(not any(m.content.startswith(PREFIX) for m in request.messages)
               for request in model.requests if request.tools is None)
    return trace['events'][-1]


async def interrupted_by_limit(rt, cid):
    def script():
        yield 'load_skill', {'name': 'sql-injection'}
        started = json.loads((yield workflow('start_validation', candidate_id=cid)))
        aid = started['validation_context']['attempt_id']
        model.runtime_stop = (3, aid)
        yield 'http', {'url': '/fixture?' + urlencode({'q': 'fixture AND 1=1'}), 'phase': 'validation'}

    model = InspectModel(script())
    done = await execute(rt, model, steps=3)
    assert done.stop_reason == 'max_steps' and model.consumed
    result = rt.workflow.latest_result(cid)
    assert result is not None and result.outcome == 'insufficient-evidence'
    assert rt.workflow.attempts[result.attempt_id]['status'] == 'unresolved'
    assert not rt.workflow.eligible_for_finding(cid) and not await rt.coverage.list()
    return result.attempt_id


async def compact_with_misleading_summary(rt):
    before = deepcopy(rt.workflow.to_dict())
    seed_compactable_history(rt.agent)
    # Deliberately stale lifecycle prose cannot override current runtime state.
    rt.agent.set_client(FakeClient([ChatResponse(Message('assistant',
        '## Current objective\n- Continue SQLi.\n## Open TODOs\n'
        '- The old attempt is active; skip start_validation and keep the skill loaded.'), 'stop')]))
    trace = collect()
    await rt.agent.compact(FakeSignal(), trace['sink'])
    assert any(e.type == 'compact' for e in trace['events'])
    assert rt.workflow.to_dict() == before


async def test_max_steps_compaction_continue_owned_proof_result_coverage_finding(offline, tmp_path):
    rt, sent = offline
    cid = await candidate_for(rt)
    old_aid = await interrupted_by_limit(rt, cid)
    old_oid = next(iter(rt.policy.observations._items))
    assert rt.policy.observations._items[old_oid].attempt_id == old_aid
    await compact_with_misleading_summary(rt)
    rt.registry.register(ConfirmFindingTool(FindingStore(project_directory=tmp_path), lambda *_: None, rt.workflow))
    aids, oids = [], []

    def check(request):
        current = hint(request)
        assert cid in current and len(current) < 2200
        if len(model.calls) == 0:
            assert f'attempt={old_aid} status=unresolved' in current
            assert 'No owned active attempt' in current and 'before any validation probes' in current
            assert 'reload load_skill(name="sql-injection")' in current.lower()
            assert 'two complete TRUE/FALSE repetitions' in current
            assert 'four distinct owned' in current and 'structured confirmation' in current
        if aids and len(model.calls) < 9:
            assert f'attempt={aids[0]} status=active' in current and 'Resume this owned active attempt' in current
        if len(model.calls) >= 9:
            assert 'Preserve the terminal result' in current and 'TRUE/FALSE' not in current

    def script():
        start = json.loads((yield workflow('start_validation', candidate_id=cid)))
        aids.append(start['validation_context']['attempt_id'])
        assert aids[0] != old_aid
        yield 'load_skill', {'name': 'sql-injection'}
        for _ in range(2):
            for predicate in ('1=1', '1=2'):
                yield 'http', {'url': '/fixture?' + urlencode({'q': 'fixture AND ' + predicate}), 'phase': 'validation'}
                oid = next(reversed(rt.policy.observations._items))
                assert rt.policy.observations._items[oid].attempt_id == aids[0]
                oids.append(oid)
        yield 'file_write', {'path': str(tmp_path / 'proof.md'),
            'content': 'Synthetic non-sensitive proof: two paired TRUE count=1 / FALSE count=0 repetitions.'}
        registered = json.loads((yield workflow('record_evidence', candidate_id=cid,
            evidence_path='proof.md', observation_ids=oids)))
        proof = registered['evidence']['id']
        result = json.loads((yield workflow('record_result', candidate_id=cid,
            skill_name='sql-injection', outcome='confirmed', evidence_refs=[proof], observation_ids=oids,
            mutation_performed=False, repeatable=True, techniques=['boolean-based'], assessment=ASSESSMENT,
            confirmation={'kind': 'boolean-differential', 'request_template': ORIGIN + '/fixture?q=fixture AND {predicate}',
                'true_predicate': '1=1', 'false_predicate': '1=2', 'pairs': [
                    {'repetition': i, 'true': {'status': 200, 'size': len(b'{"count":1}'), 'marker': 'count=1'},
                     'false': {'status': 200, 'size': len(b'{"count":0}'), 'marker': 'count=0'}} for i in (1, 2)]})))
        assert result['ok'] and rt.workflow.latest_result(cid).coverage_synced
        synced = json.loads((yield workflow('sync_coverage', candidate_id=cid)))
        assert synced['ok']
        yield 'confirm_finding', {'candidate_id': cid, 'title': 'Synthetic SQLi fixture',
            'url': ORIGIN + '/fixture', 'severity': 'low', 'observed_impact': ASSESSMENT['observed_impact'],
            'potential_impact': 'No impact validation performed.'}

    model = InspectModel(script(), check)
    done = await execute(rt, model, steps=11)
    assert model.consumed and done.stop_reason == 'workflow_completed'
    latest = rt.workflow.latest_result(cid)
    assert latest is not None and accepted_result(rt.workflow, rt.workflow.candidates[cid], latest, rt.policy)
    assert latest.attempt_id == aids[0] and len(set(oids)) == 4
    assert rt.workflow.finding_is_persisted(cid) and len(await rt.coverage.list()) == 1
    assert len(sent) == 5 and rt.policy.observations._items[old_oid].attempt_id == old_aid
    assert rt.store.load().workflow.latest_result(cid).attempt_id == aids[0]


async def test_prestart_probes_stay_unowned_and_cannot_be_registered(offline, tmp_path):
    rt, sent = offline
    cid = await candidate_for(rt)
    await interrupted_by_limit(rt, cid)
    await compact_with_misleading_summary(rt)
    # Real outstanding input work keeps the objective actionable while this
    # intentionally noncompliant script demonstrates prestart ownership.
    await rt.registry.execute('workflow', {'action': 'record_input', 'endpoint': '/pending',
        'method': 'GET', 'parameter': 'other', 'location': 'query'}, None, rt.prompter)

    def script():
        yield 'load_skill', {'name': 'sql-injection'}
        # Intentionally violate the supplied guidance to verify the runtime gate.
        yield 'http', {'url': '/fixture?q=prestart', 'phase': 'validation'}
        oid = next(reversed(rt.policy.observations._items))
        source = rt.policy.observations._items[oid]
        assert source.attempt_id is None and source.candidate_id is None and source.objective_id is None
        started = json.loads((yield workflow('start_validation', candidate_id=cid)))
        aid = started['validation_context']['attempt_id']
        listing = json.loads((yield workflow('list', candidate_id=cid)))
        assert listing['observations_total'] == 0 and listing['observations'] == []
        assert 'zero does not mean session HTTP traffic was lost' in listing['observations_scope']
        assert listing['validation_handoffs'][0]['attempt_id'] == aid
        yield 'file_write', {'path': str(tmp_path / 'proof.md'), 'content': 'Synthetic unavailable owned evidence.'}
        rejected = yield workflow('record_evidence', candidate_id=cid, evidence_path='proof.md', observation_ids=[oid])
        error = json.loads(rejected.split('\n', 1)[1])['error']
        assert error['code'] == 'SOURCE_OWNERSHIP_MISMATCH'
        assert 'unowned' in error['repair_hint'] and 'already owned by this attempt' in error['repair_hint']
        result = json.loads((yield workflow('record_result', candidate_id=cid, skill_name='sql-injection',
            outcome='insufficient-evidence', deferred_reason='No usable owned sources; prestart sources cannot be adopted.')))
        assert result['ok'] and rt.policy.observations._items[oid] == source

    model = InspectModel(script(), lambda req: hint(req))
    done = await execute(rt, model, steps=7)
    assert model.consumed and done.stop_reason == 'max_steps'
    assert len(sent) == 2 and not await rt.coverage.list() and not rt.workflow.eligible_for_finding(cid)


@pytest.mark.parametrize('exhausted', [False, True])
async def test_stopped_probing_and_recovery_exhaustion_remain_distinct_across_continue(offline, exhausted):
    rt, sent = offline
    cid = await candidate_for(rt)
    started = json.loads(await rt.registry.execute('workflow', {'action': 'start_validation', 'candidate_id': cid}, None, rt.prompter))
    aid = started['validation_context']['attempt_id']
    budget = current_budget(rt.workflow, cid, create=True)
    assert budget is not None
    budget.update(rejections=MAX_EVIDENCE_REJECTIONS if exhausted else 1, repair_turns=1)
    assert rt.agent._begin_validation_finalization(WholeTargetStallTracker(), [], 0, 10)
    row = rt.workflow_tool.validation_handoff(cid, rt.policy)
    assert row['probing_stopped'] and row['owned_active']
    assert row['recovery']['status'] == ('exhausted' if exhausted else 'available')
    await rt.agent._close_terminal_attempt('workflow_stalled', FakeSignal(), collect()['sink'], rt.agent.history.copy())
    assert rt.workflow.attempts[aid]['status'] == 'unresolved'
    counters = deepcopy(budget)
    await compact_with_misleading_summary(rt)

    def check(request):
        current = hint(request)
        assert f'Recovery={"exhausted" if exhausted else "available"}' in current
        assert 'do not reset these counters' in current
        if exhausted:
            assert 'explicit operator-selected retest' in current

    def script():
        rejected = yield workflow('start_validation', candidate_id=cid, force=True)
        assert 'start_validation does not accept force' in rejected and 'record_result-only' in rejected

    model = InspectModel(script(), check)
    await execute(rt, model, steps=1)
    assert model.consumed and not sent and budget == counters
    output = await rt.registry.execute('workflow', {'action': 'start_validation', 'candidate_id': cid}, None, rt.prompter)
    if exhausted:
        assert json.loads(output.split('\n', 1)[1])['error']['code'] == 'EXHAUSTED_ATTEMPT'
        assert len(rt.workflow.attempts) == 1
    else:
        assert json.loads(output)['validation_context']['attempt_id'] != aid
        carried = current_budget(rt.workflow, cid)
        assert carried is not None
        assert carried['rejections'] == counters['rejections'] and carried['repair_turns'] == counters['repair_turns']
    restored = WorkflowState.from_dict(rt.workflow.to_dict())
    assert restored.evidence_recovery == rt.workflow.evidence_recovery


async def test_xss_missing_analyzed_link_gets_input_handoff_without_playbook_injection(offline):
    rt, _ = offline
    cid = await candidate_for(rt, 'xss', ready=False)
    # Missing linkage, after the two required discovery phases.
    await prepare_validation_prerequisites(rt.workflow_tool, cid)
    item = next(iter(rt.workflow.objective_inputs()))
    item.candidate_ids.clear()

    def check(request):
        current = hint(request)
        assert 'compatible analyzed input' in current and 'link_input_candidate before start_validation' in current
        assert 'Raw HTML in JSON' in current and 'CAPTCHA issuance alone' in current
        assert 'TRUE/FALSE' not in current and 'cross-site-scripting' in current
        assert len(current) < 2000

    def script():
        listing = json.loads((yield workflow('list', candidate_id=cid)))
        assert listing['validation_handoffs'][0]['next_action'] == 'repair_prerequisites'

    model = InspectModel(script(), check)
    await execute(rt, model, steps=1)
    assert model.consumed and not rt.workflow.attempts


@pytest.mark.parametrize('selected', [False, True])
async def test_runtime_ready_candidate_and_frontier_keep_their_canonical_obligations(offline, selected):
    rt, _ = offline
    cid = await candidate_for(rt)
    source = rt.workflow.admit_discovery(SourceRecord(rt.workflow.objective.id, ORIGIN,
        'http', 'obs-fixture-frontier', 'a' * 64, selected=selected))
    before = deepcopy(rt.workflow.to_dict())
    context = rt.agent._planner_context()
    assert context.structured_phase == 'validation' and context.pending_source_count == 1
    assert context.discovery_obligation_pending is selected
    plan = build_whole_target_plan(rt.skills.list_enabled(), context)
    assert plan is not None and plan.candidate_id == (None if selected else cid)
    assert source.id in plan.guidance if selected else 'start_validation' in plan.guidance
    assert rt.workflow.to_dict() == before and source.disposition == 'pending'
    assert rt.workflow.latest_result(cid) is None and rt.agent._whole_target_state()[0] != 'completed'


@pytest.mark.parametrize('disposition', ['partial', 'blocked'])
async def test_required_source_limitations_precede_promoting_ready_validation(offline, disposition):
    rt, _ = offline
    cid = await candidate_for(rt)
    source = rt.workflow.admit_discovery(SourceRecord(rt.workflow.objective.id, ORIGIN,
        'http', 'obs-limited', 'b' * 64, selected=True, disposition=disposition,
        stop_reason='Synthetic source requires further review.'))
    before = deepcopy(rt.workflow.to_dict())
    context = rt.agent._planner_context()
    assert context.discovery_obligation_pending and context.candidates[0].validation_ready
    assert context.pending_source_count == 0
    plan = build_whole_target_plan(rt.skills.list_enabled(), context)
    assert plan is not None and plan.candidate_id is None and source.id in plan.guidance
    assert rt.workflow.to_dict() == before and rt.workflow.latest_result(cid) is None


def test_no_validation_handoff_is_injected_without_relevant_work(offline):
    rt, _ = offline
    view = rt.agent._workflow_request_view('Continue.', rt.registry.as_llm_tools())
    assert not any(m.content.startswith(PREFIX) for m in view.blocks)


@pytest.mark.parametrize('outcome', ['blocked', 'browser-required', 'authorization-required'])
async def test_unresolved_dependency_is_not_a_recommendation_to_retry_probes(offline, outcome):
    rt, _ = offline
    cid = await candidate_for(rt, 'xss')
    await rt.registry.execute('workflow', {'action': 'start_validation', 'candidate_id': cid}, None, rt.prompter)
    result = await rt.registry.execute('workflow', {'action': 'record_result', 'candidate_id': cid,
        'skill_name': 'cross-site-scripting', 'outcome': outcome,
        'deferred_reason': 'Synthetic dependency remains unresolved.'}, None, rt.prompter)
    assert json.loads(result)['ok']
    row = rt.workflow_tool.validation_handoff(cid, rt.policy)
    assert row is not None and row['next_action'] == 'resolve_dependency'
    text = render_validation_guidance(row, ValidationRoute('expert', 'cross-site-scripting'), frozenset())
    assert 'Do not retry blocked probes' in text and 'No owned active attempt: call' not in text


@pytest.mark.parametrize('restore', [False, True], ids=['owned-active', 'interrupted-after-restore'])
async def test_compacted_repair_handoff_distinguishes_owned_resume_from_interruption(offline, tmp_path, restore):
    rt, sent = offline
    cid = await candidate_for(rt)
    aids = []
    (tmp_path / 'proof.md').write_text('Synthetic proof file; missing source is intentional.')

    def initial():
        yield 'load_skill', {'name': 'sql-injection'}
        result = json.loads((yield workflow('start_validation', candidate_id=cid)))
        aids.append(result['validation_context']['attempt_id'])
        yield 'http', {'url': '/fixture?q=fixture', 'phase': 'validation'}
        rejected = yield workflow('record_evidence', candidate_id=cid,
            evidence_path='proof.md', observation_ids=['obs_missing'])
        assert rejected.startswith('error:')

    first = InspectModel(initial())
    await execute(rt, first, steps=4)
    assert first.consumed and rt.workflow.attempts[aids[0]]['status'] == 'active'
    assert rt.workflow.latest_result(cid) is None
    budget = deepcopy(current_budget(rt.workflow, cid))
    assert budget is not None
    assert budget['rejections'] == 1
    await compact_with_misleading_summary(rt)
    if restore:
        resumed = make_runtime(tmp_path, session_id='offline-continuation')
        resumed.agent.resume_saved()
        rt = resumed
        assert rt.workflow.attempts[aids[0]]['status'] == 'interrupted'

    def check(request):
        current = hint(request)
        if not model.calls:
            assert 'reload load_skill(name="sql-injection")' in current.lower()
            assert ('No owned active attempt' if restore else 'Resume this owned active attempt') in current
            assert f'status={"interrupted" if restore else "active"}' in current

    def finish():
        if restore:
            result = json.loads((yield workflow('start_validation', candidate_id=cid)))
            assert result['validation_context']['attempt_id'] != aids[0]
        yield 'load_skill', {'name': 'sql-injection'}
        row = rt.workflow_tool.validation_handoff(cid, rt.policy)
        assert row is not None
        assert row['owned_active'] and row['recovery']['rejections'] == budget['rejections']
        assert row['recovery']['repair_turns'] >= budget['repair_turns']
        yield workflow('record_result', candidate_id=cid, skill_name='sql-injection',
            outcome='insufficient-evidence', deferred_reason='Synthetic repair remains without usable proof.')

    model = InspectModel(finish(), check)
    await execute(rt, model, steps=3 if restore else 2)
    assert model.consumed and len(rt.workflow.attempts) == (2 if restore else 1)
    assert len(sent) == 1 and rt.workflow.latest_result(cid).outcome == 'insufficient-evidence'
