"""Offline Phase 2 contracts through production Workflow, HTTP and Agent."""
import asyncio
import json
from pathlib import Path

import pytest

from src.agent.agent import Agent, AgentOptions
from src.coverage.store import CoverageStore
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.permission.permission import AlwaysAllow
from src.skills.registry import Registry as Skills
from src.target.target import Target
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.evidence_recovery import current_budget
from src.workflow.goals import RequestedGoal
from src.workflow.state import Candidate, PHASE_COVERAGE_DIMENSIONS, WorkflowObjective, WorkflowState
from src.tools.common.outcome import ToolOutput
from tests.helpers.agent_fakes import FakeClient, FakeSignal, ScriptedModel, collect
from tests.helpers.workflow import record_phase_coverage_for_test, prepare_validation_prerequisites
from tests.security.test_agent_assessment import ASSESSMENT, setup
from tests.security.test_execution_policy import ORIGIN, runtime  # noqa: F401


def agent_for(runtime, tool: WorkflowTool, state: WorkflowState, client=None, max_steps=10):
    assert tool.skills is not None
    registry, p, policy, *_, target = runtime
    return Agent(AgentOptions(client=client or FakeClient([]), tools=registry, skills=tool.skills,
        prompter=p, store=None, target=target, workflow=state, engagement_state=policy.engagement,
        max_steps=max_steps, auto_compact_threshold=0, streaming_enabled=False))


def result_for(state: WorkflowState, candidate_id: str):
    result = state.latest_result(candidate_id)
    assert result is not None
    return result


def budget_for(state: WorkflowState, candidate_id: str, *, create=False):
    budget = current_budget(state, candidate_id, create=create)
    assert budget is not None
    return budget


async def complete_discovery(tool: WorkflowTool, root: Path):
    assert tool.skills is not None
    for phase, skill in (
        ('recon', 'recon'),
        ('enumeration', 'web-enumeration'),
        ('input_analysis', 'web-input-analysis'),
    ):
        if phase in tool.state.completed_phases():
            continue
        # Use the runtime's canonical target slug, rather than fixture assumptions.
        from src.skills.artifacts import completion_artifact_path
        record = tool.skills.get(skill)
        assert record is not None and record.completion_artifact
        artifact = completion_artifact_path(record.completion_artifact, ORIGIN)
        path = root / artifact
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('Bounded offline discovery review; no additional inputs discovered.')
        await record_phase_coverage_for_test(tool, phase)
        result = json.loads(await tool.run({'action': 'complete_skill', 'skill_name': skill,
            'artifact_ref': artifact, 'no_inputs_discovered': phase == 'input_analysis' and not tool.state.objective_inputs()}, None, AlwaysAllow()))
        assert result['ok']


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['whole_target', 'direct', 'candidate_validation'])
async def test_early_validation_does_not_complete_discovery(runtime, tmp_path, mode):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path, candidate_class='sqli', mode=mode)
    assert state.objective is not None
    # Whole-target now satisfies bounded prerequisites; Direct modes still need no discovery.
    if mode != 'whole_target':
        state.objective.mode = mode
        state.objective.candidate_id = candidate.id if mode == 'candidate_validation' else None
    registry, p, policy, *_ = runtime
    started = json.loads(await registry.execute('workflow', {'action': 'start_validation', 'candidate_id': candidate.id}, None, p))
    assert started['ok'] and started['validation_context']['attempt_id'] == args['attempt_id']
    result = json.loads(await registry.execute('workflow', {**args, 'outcome': 'not-confirmed'}, None, p))
    assert result['ok']
    assert state.completed_phases() == (frozenset({'recon', 'enumeration'}) if mode == 'whole_target' else frozenset())
    assert tool.validation_completion_error(candidate.id, policy) is None
    agent = agent_for(runtime, tool, state)
    assert not agent._validation_completion_blockers()
    if mode == 'whole_target':
        status, actions, _ = agent._whole_target_state()
        assert status == 'actionable' and actions == ('phase:input_analysis',)
    else:
        assert agent._whole_target_state() == ('not_applicable', (), ())


@pytest.mark.asyncio
@pytest.mark.parametrize('fault', ['finding', 'coverage', 'proof', 'pending-input', 'blocked-input',
    'browser-required', 'insufficient-evidence', 'none'])
async def test_completion_uses_all_current_obligations(runtime, tmp_path, fault):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path, candidate_class='sqli')
    assert state.objective is not None
    registry, p, policy, *_ = runtime
    await registry.execute('workflow', {**args, 'outcome': 'confirmed' if fault == 'finding' else 'not-confirmed'}, None, p)
    await complete_discovery(tool, tmp_path)
    latest = state.latest_result(candidate.id)
    assert latest is not None
    if fault == 'coverage':
        latest.coverage_synced = False
    elif fault == 'proof':
        # Tamper with the actual immutable snapshot, not a mocked verdict.
        proof = tmp_path / state.evidence[latest.evidence_refs[0]].path
        proof.chmod(0o600)
        proof.write_text('changed proof')
    elif fault in {'pending-input', 'blocked-input'}:
        receipt = json.loads(await registry.execute('workflow', {'action': 'record_input',
            'endpoint': '/other', 'method': 'GET', 'parameter': 'other', 'location': 'query'}, None, p))
        if fault == 'blocked-input':
            await registry.execute('workflow', {'action': 'set_input_disposition',
                'input_id': receipt['input']['id'], 'disposition': 'blocked',
                'disposition_reason': 'fixture authority unavailable'}, None, p)
    elif fault in {'browser-required', 'insufficient-evidence'}:
        other, _ = state.add_candidate(Candidate('xss', target=ORIGIN, endpoint='/other',
            method='GET', parameter='q', location='query', objective_id=state.objective.id))
        await prepare_validation_prerequisites(tool, other.id)
        started = json.loads(await registry.execute('workflow', {'action': 'start_validation',
            'candidate_id': other.id}, None, p))
        assert started['ok']
        unresolved = json.loads(await registry.execute('workflow', {'action': 'record_result',
            'candidate_id': other.id, 'skill_name': 'cross-site-scripting', 'outcome': fault,
            'deferred_reason': 'fixture missing execution proof'}, None, p))
        assert unresolved['ok'] and not state.eligible_for_finding(other.id)
    agent = agent_for(runtime, tool, state)
    status, actions, blockers = agent._whole_target_state()
    if fault == 'none':
        assert (status, actions, blockers) == ('completed', (), ())
        assert tool.validation_completion_error(candidate.id, policy) is None
    else:
        assert status != 'completed'
        expected = {'finding': 'finding:', 'coverage': 'coverage-sync:', 'proof': 'revalidate:',
            'pending-input': 'input:', 'blocked-input': 'input:', 'browser-required': 'candidate deferred:',
            'insufficient-evidence': 'candidate deferred:'}[fault]
        assert any(item.startswith(expected) for item in (*actions, *blockers)), (actions, blockers)
    assert latest.outcome == ('confirmed' if fault == 'finding' else 'not-confirmed')


@pytest.mark.asyncio
async def test_requested_goal_no_candidate_is_not_tested_negative(runtime, tmp_path):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path, candidate_class='sqli')
    assert state.objective is not None
    state.objective.requested_goals = [RequestedGoal('sqli'), RequestedGoal('xss')]
    registry, p, *_ = runtime
    await registry.execute('workflow', {**args, 'outcome': 'not-confirmed'}, None, p)
    await complete_discovery(tool, tmp_path)
    agent = agent_for(runtime, tool, state)
    sqli, xss = state.objective.requested_goals
    assert agent._whole_target_state()[0] == 'actionable'
    assert sqli.status == 'tested_not_confirmed' and xss.status == 'pending'
    assert f'goal-review:{xss.id}' in agent._whole_target_state()[1]
    review = json.loads(await registry.execute('workflow', {'action': 'review_no_candidate', 'goal_id': xss.id}, None, p))
    assert review['ok']
    status, _, blockers = agent._whole_target_state()
    assert status == 'blocked' and xss.status == 'no_candidate'
    assert xss.candidate_ids == [] and len(state.validation_results) == 1
    assert any('validation was not performed' in item for item in blockers)


@pytest.mark.asyncio
async def test_phase_prerequisites_and_invalid_coverage_are_correctable(tmp_path):
    skills = Skills()
    skills.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    state = WorkflowState(objective=WorkflowObjective('phase2', 'whole_target', ORIGIN))
    tool = WorkflowTool(state, Target(ORIGIN), CoverageStore(str(tmp_path / 'coverage.json')), skills, tmp_path)
    before = state.to_dict()
    for phase, dimension, code in [('recon', 'dns_resolution', 'INVALID_COVERAGE_DIMENSION'),
        ('input_analysis', 'inputs', 'INVALID_COVERAGE_PHASE')]:
        output = await tool.run({'action': 'record_phase_coverage', 'phase': phase,
            'coverage_dimension': dimension, 'coverage_status': 'observed', 'coverage_reason': 'fixture review'}, None, AlwaysAllow())
        assert isinstance(output, ToolOutput) and output.error_kind == 'invalid_args'
        error = json.loads(output.split('\n', 1)[1])['error']
        assert error['code'] == code and error['category'] == 'argument_error' and error['next_action']
        assert state.to_dict() == before
    # An out-of-order completion must retain the existing prerequisite.
    from src.skills.artifacts import completion_artifact_path
    skill = skills.get('web-enumeration')
    assert skill is not None and skill.completion_artifact
    artifact = tmp_path / completion_artifact_path(skill.completion_artifact, ORIGIN)
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text('Offline inventory')
    output = await tool.run({'action': 'complete_skill', 'skill_name': 'web-enumeration'}, None, AlwaysAllow())
    assert 'recon must complete' in output
    error = json.loads(output.split('\n', 1)[1])['error']
    assert error['category'] == 'missing_prerequisite'
    assert not state.completed_phases()
    await complete_discovery(tool, tmp_path)
    assert state.completed_phases() == frozenset({'recon', 'enumeration', 'input_analysis'})
    schema = tool.schema()['properties']
    for phase, dimensions in PHASE_COVERAGE_DIMENSIONS.items():
        assert phase in schema['coverage_dimension']['description']
        assert all(dimension in schema['coverage_dimension']['description'] for dimension in dimensions)


@pytest.mark.asyncio
async def test_attempt_declaration_conflict_and_unknown_candidate_are_diagnostic(runtime, tmp_path):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    assert state.objective is not None
    registry, p, *_ = runtime
    before = state.to_dict()
    output = await registry.execute('workflow', {'action': 'start_validation', 'candidate_id': candidate.id,
        'assessment': {'hypothesis': 'new declaration'}}, None, p)
    error = json.loads(output.split('\n', 1)[1])['error']
    assert error['code'] == 'IMMUTABLE_ATTEMPT_DECLARATION' and error['category'] == 'immutable_state_conflict'
    assert error['attempt_id'] == args['attempt_id']
    assert state.to_dict() == before
    output = await registry.execute('workflow', {'action': 'start_validation', 'candidate_id': 'candidate_missing'}, None, p)
    error = json.loads(output.split('\n', 1)[1])['error']
    assert error['category'] == 'argument_error' and 'list' in error['next_action']
    resumed = json.loads(await registry.execute('workflow', {'action': 'start_validation', 'candidate_id': candidate.id}, None, p))
    assert resumed['validation_context']['attempt_id'] == args['attempt_id']
    closed = json.loads(await registry.execute('workflow', {'action': 'record_result', 'candidate_id': candidate.id,
        'skill_name': 'cross-site-scripting', 'outcome': 'insufficient-evidence', 'deferred_reason': 'declaration needs review'}, None, p))
    assert closed['ok'] and state.candidates[candidate.id].status == 'deferred'


@pytest.mark.asyncio
async def test_xss_distinct_api_dom_stored_hypotheses_use_existing_identity(runtime, tmp_path):
    state, api, tool, args, _ = await setup(runtime, tmp_path)
    assert state.objective is not None
    registry, p, *_ = runtime
    await registry.execute('workflow', {**args, 'outcome': 'not-confirmed'}, None, p)
    records = []
    for test_case, signal in [('dom:location-search-to-innerhtml', 'JS source shows location.search flowing to innerHTML'),
        ('stored:comment-to-review', 'Observed comment persisted and read back at review sink')]:
        request = {'action': 'record_candidate', 'candidate_class': 'xss', 'endpoint': api.endpoint,
            'method': api.method, 'parameter': api.parameter, 'location': api.location,
            'test_case': test_case, 'signals': [signal]}
        record = json.loads(await registry.execute('workflow', request, None, p))
        assert record['created']
        duplicate = json.loads(await registry.execute('workflow', request, None, p))
        assert not duplicate['created'] and duplicate['candidate']['id'] == record['candidate']['id']
        cid = record['candidate']['id']
        await prepare_validation_prerequisites(tool, cid)
        started = json.loads(await registry.execute('workflow', {'action': 'start_validation', 'candidate_id': cid}, None, p))
        assert started['ok']
        closed = json.loads(await registry.execute('workflow', {'action': 'record_result', 'candidate_id': cid,
            'skill_name': 'cross-site-scripting', 'outcome': 'browser-required', 'deferred_reason': signal}, None, p))
        assert closed['ok'] and not state.eligible_for_finding(cid)
        records.append(cid)
    assert len(set([api.id, *records])) == 3
    await complete_discovery(tool, tmp_path)
    agent = agent_for(runtime, tool, state)
    assert agent._whole_target_state()[0] == 'blocked'
    restored = WorkflowState.from_dict(json.loads(json.dumps(state.to_dict())))
    assert len(restored.candidates) == 3
    assert [result_for(restored, cid).outcome for cid in records] == ['browser-required'] * 2


def response(args, identifier='fixture-call'):
    return ChatResponse(Message('assistant', '', tool_calls=[
        ToolCall(identifier, FunctionCall('workflow', json.dumps(args)))]), 'tool_calls')


@pytest.mark.asyncio
@pytest.mark.parametrize('when', ['start', 'batch'])
@pytest.mark.parametrize('mode', ['whole_target', 'direct', 'candidate_validation'])
async def test_exhaustion_continues_only_independent_whole_target_work(runtime, tmp_path, when, mode):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    assert state.objective is not None
    if mode != 'whole_target':
        state.objective.mode = mode
        state.objective.candidate_id = candidate.id if mode == 'candidate_validation' else None
    independent, _ = state.add_candidate(Candidate('sqli', target=ORIGIN, endpoint='/independent',
        method='GET', parameter='q', location='query', objective_id=state.objective.id))
    await prepare_validation_prerequisites(tool, independent.id)
    budget = budget_for(state, candidate.id, create=True)
    budget.update(rejections=3 if when == 'start' else 2, closure_args={'skill_name': 'cross-site-scripting'})
    client = FakeClient(([response({**args, 'observation_ids': []})] if when == 'batch' else []) + [
        response({'action': 'start_validation', 'candidate_id': independent.id}, 'independent-start'),
        response({'action': 'record_result', 'candidate_id': independent.id, 'skill_name': 'sql-injection',
            'outcome': 'insufficient-evidence', 'deferred_reason': 'offline fixture has no primary proof'}, 'independent-close'),
        ChatResponse(Message('assistant', 'Incomplete assessment.'), 'stop')])
    agent = agent_for(runtime, tool, state, client)
    # Keep discovery open but unavailable so only the independent candidate is actionable.
    assert tool.skills is not None
    tool.skills.set_disabled('web-input-analysis', True)
    events = collect()
    await agent.run('Continue current validation.', FakeSignal(), events['sink'])
    assert result_for(state, candidate.id).outcome == 'insufficient-evidence'
    assert budget['closed'] and budget['rejections'] == 3
    if mode == 'whole_target':
        assert result_for(state, independent.id).outcome == 'insufficient-evidence'
        assert any(a['candidate_id'] == independent.id for a in state.attempts.values())
        assert agent._whole_target_state()[0] == 'blocked'
    else:
        assert state.latest_result(independent.id) is None
        assert len(client.requests) == (1 if when == 'batch' else 0)
    assert not state.eligible_for_finding(candidate.id)
    assert len(runtime[4]) == 1  # Only setup's native offline request.


@pytest.mark.asyncio
async def test_exhausted_whole_target_attempt_cannot_reopen_on_continue(runtime, tmp_path):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    assert state.objective is not None
    registry, p, *_ = runtime
    budget = budget_for(state, candidate.id, create=True)
    budget.update(rejections=3, closure_args={'skill_name': 'cross-site-scripting'})
    agent = agent_for(runtime, tool, state)
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    assert budget['closed']
    before = state.to_dict()
    output = await registry.execute('workflow', {'action': 'start_validation', 'candidate_id': candidate.id}, None, p)
    assert 'exhausted' in output and state.to_dict() == before
    restored = WorkflowState.from_dict(json.loads(json.dumps(state.to_dict())))
    tool.state = restored
    output = await registry.execute('workflow', {'action': 'start_validation', 'candidate_id': candidate.id}, None, p)
    assert 'exhausted' in output and budget_for(restored, candidate.id)['rejections'] == 3
    # Explicit operator-selected retest gets the existing separate objective identity.
    restored.objective = WorkflowObjective('explicit-retest', 'candidate_validation', ORIGIN, candidate_id=candidate.id)
    output = json.loads(await registry.execute('workflow', {'action': 'start_validation', 'candidate_id': candidate.id}, None, p))
    assert output['ok']


@pytest.mark.asyncio
@pytest.mark.parametrize('when', ['start', 'batch'])
async def test_independent_candidate_can_finish_with_production_evidence(runtime, tmp_path, when):
    state, exhausted, tool, args, _ = await setup(runtime, tmp_path)
    assert state.objective is not None
    registry, p, policy, *_ = runtime
    other, _ = state.add_candidate(Candidate('sqli', target=ORIGIN, endpoint='/independent',
        method='GET', parameter='q', location='query', objective_id=state.objective.id))
    await prepare_validation_prerequisites(tool, other.id)
    await complete_discovery(tool, tmp_path)
    budget = budget_for(state, exhausted.id, create=True)
    budget.update(rejections=3 if when == 'start' else 2, closure_args={'skill_name': 'cross-site-scripting'})

    def script():
        started = json.loads((yield 'workflow', {'action': 'start_validation', 'candidate_id': other.id}))
        assert started['ok']
        yield 'http', {'url': '/independent?q=fixture', 'method': 'GET', 'phase': 'validation'}
        oid = next(reversed(policy.observations._items))
        assert policy.observations._items[oid].candidate_id == other.id
        yield 'file_write', {'path': str(tmp_path / 'independent.md'), 'content': 'Independent fixture response observed.'}
        registered = json.loads((yield 'workflow', {'action': 'record_evidence', 'candidate_id': other.id,
            'evidence_path': 'independent.md', 'observation_ids': [oid]}))
        result = json.loads((yield 'workflow', {'action': 'record_result', 'candidate_id': other.id,
            'skill_name': 'sql-injection', 'outcome': 'not-confirmed', 'evidence_refs': [registered['evidence']['id']],
            # The mock transport returns fixed bytes and performs no target writes.
            'mutation_performed': False,
            'observation_ids': [oid], 'attempt_id': started['validation_context']['attempt_id'], 'assessment': ASSESSMENT.copy()}))
        assert result['ok']

    model = ScriptedModel(script(), prefix='independent-evidence')

    class LeadingRejectionClient(FakeClient):
        async def chat(self, request, signal=None):
            if self.idx == 0:
                return await super().chat(request, signal)
            return await model.chat(request, signal)

    client = LeadingRejectionClient([response({**args, 'observation_ids': []})]) if when == 'batch' else model
    agent = agent_for(runtime, tool, state, client)
    events = collect()
    await agent.run('Continue current validation.', FakeSignal(), events['sink'])
    assert not model.errors and model.consumed
    assert result_for(state, other.id).outcome == 'not-confirmed'
    assert result_for(state, other.id).mutation_performed is False
    assert result_for(state, other.id).cleanup_state == 'not-required'
    assert tool.validation_completion_error(other.id, policy) is None
    assert result_for(state, exhausted.id).outcome == 'insufficient-evidence'
    assert current_budget(state, exhausted.id) is budget and budget['rejections'] == 3 and budget['closed']
    assert agent._whole_target_state()[0] == 'blocked'
    assert events['events'][-1].stop_reason == 'workflow_blocked'
    assert len(runtime[4]) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize('blocker', ['http-revoked', 'grant-expired', 'grant-exhausted', 'session-denied', 'call-budget',
    'out-of-scope', 'stale-auth', 'cancelled', 'operator-stop', 'closure-failure', 'closure-policy-denial'])
async def test_recovery_continuation_is_fail_closed(runtime, tmp_path, monkeypatch, blocker):
    state, exhausted, tool, _, _ = await setup(runtime, tmp_path)
    assert state.objective is not None
    _, _, policy, *_, target = runtime
    other, _ = state.add_candidate(Candidate('sqli', target=ORIGIN,
        endpoint='https://outside.test/input' if blocker == 'out-of-scope' else '/independent',
        method='GET', parameter='q', location='query', objective_id=state.objective.id,
        auth_context_ref='unavailable-auth' if blocker == 'stale-auth' else None))
    budget = budget_for(state, exhausted.id, create=True)
    budget.update(rejections=3, closure_args={'skill_name': 'cross-site-scripting'})
    client = FakeClient([])
    agent = agent_for(runtime, tool, state, client)
    signal = FakeSignal()
    grant = policy.engagement.http_permissions.grants[target.origin()]
    http_budget = policy.engagement.http_permissions._budgets[grant.id]
    if blocker == 'http-revoked':
        policy.revoke('http')
    elif blocker == 'call-budget':
        policy.max_calls = policy.used + 1  # The required closure uses the last admitted call.
    elif blocker == 'grant-expired':
        http_budget.expires_at = policy.engagement.http_permissions.clock() - 1
    elif blocker == 'grant-exhausted':
        http_budget.used = http_budget.limits.requests
    elif blocker == 'session-denied':
        policy.engagement.http_permissions.deny_session()
    elif blocker == 'cancelled':
        signal.aborted = True
    elif blocker.startswith('closure-'):
        original = tool.run

        async def reject_closure(args, signal, prompter):
            if args.get('action') == 'record_result' and args.get('outcome') == 'insufficient-evidence':
                return ToolOutput('error: fixture closure rejected', status='error',
                    error_kind='policy_block' if blocker == 'closure-policy-denial' else 'workflow_state')
            return await original(args, signal, prompter)

        monkeypatch.setattr(tool, 'run', reject_closure)
    events = collect()
    await agent.run('Stop testing this assessment' if blocker == 'operator-stop' else 'Continue current validation.',
        signal, events['sink'])
    assert not client.requests and len(runtime[4]) == 1
    assert state.latest_result(other.id) is None and other.status in {'new', 'queued'}
    assert not any(a['candidate_id'] == other.id for a in state.attempts.values())
    if blocker in {'cancelled', 'operator-stop', 'closure-failure', 'closure-policy-denial'}:
        assert state.latest_result(exhausted.id) is None and not budget['closed']
    else:
        assert result_for(state, exhausted.id).outcome == 'insufficient-evidence' and budget['closed']
    expected_stop = 'cancelled' if blocker == 'cancelled' else 'runtime_error' if blocker.startswith('closure-') else 'workflow_blocked'
    assert events['events'][-1].stop_reason == expected_stop


@pytest.mark.asyncio
@pytest.mark.parametrize('cancellation', ['operator', 'task'])
async def test_recovery_closure_cancellation_preserves_unresolved_attempt(
        runtime, tmp_path, monkeypatch, cancellation):
    state, candidate, tool, _, _ = await setup(runtime, tmp_path)
    budget = budget_for(state, candidate.id, create=True)
    budget.update(rejections=3, closure_args={'skill_name': 'cross-site-scripting'})
    client = FakeClient([])
    agent = agent_for(runtime, tool, state, client)
    signal = FakeSignal()
    events = collect()
    entered = asyncio.Event()
    original = tool.run
    attempt_ids = set(state.attempts)

    async def interrupt_closure(args, active_signal, prompter):
        if args.get('action') == 'record_result' and args.get('outcome') == 'insufficient-evidence':
            entered.set()
            if cancellation == 'operator':
                active_signal.aborted = True
                raise asyncio.CancelledError()
            await asyncio.Event().wait()
        return await original(args, active_signal, prompter)

    monkeypatch.setattr(tool, 'run', interrupt_closure)
    task = asyncio.create_task(agent.run('Continue current validation.', signal, events['sink']))
    await asyncio.wait_for(entered.wait(), timeout=5)
    if cancellation == 'task':
        # A simultaneous operator abort must not hide real task cancellation.
        signal.aborted = True
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        await task
    assert events['events'][-1].stop_reason == 'cancelled'
    assert not agent.running and not client.requests and len(runtime[4]) == 1
    assert state.latest_result(candidate.id) is None
    assert set(state.attempts) == attempt_ids
    assert not budget['closed'] and budget['rejections'] == 3
    assert current_budget(state, candidate.id) is budget


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['policy_block', 'permission_denied'])
async def test_policy_failure_in_exhausting_batch_prevents_independent_continuation(runtime, tmp_path, failure):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    assert state.objective is not None
    independent, _ = state.add_candidate(Candidate('sqli', target=ORIGIN, endpoint='/independent',
        method='GET', parameter='q', location='query', objective_id=state.objective.id))
    await prepare_validation_prerequisites(tool, independent.id)
    budget = budget_for(state, candidate.id, create=True)
    budget.update(rejections=2, closure_args={'skill_name': 'cross-site-scripting'})
    denied_path = tmp_path.parent / 'outside-fixture.txt'
    if failure == 'permission_denied':
        denied_path = tmp_path / '.env'
        denied_path.write_text('FIXTURE_VALUE=offline')
        runtime[1].set_yolo(False)
    client = FakeClient([ChatResponse(Message('assistant', '', tool_calls=[
        ToolCall('rejection', FunctionCall('workflow', json.dumps({**args, 'observation_ids': []}))),
        ToolCall('policy-denied', FunctionCall('file_read', json.dumps({'path': str(denied_path)}))),
    ]), 'tool_calls')])
    agent = agent_for(runtime, tool, state, client)
    events = collect()
    await agent.run('Continue current validation.', FakeSignal(), events['sink'])
    assert len(client.requests) == 1 and len(runtime[4]) == 1
    assert any(m.role == 'tool' and m.tool_call_id == 'policy-denied' and m.tool_error_kind == failure
        for m in agent.history)
    assert result_for(state, candidate.id).outcome == 'insufficient-evidence' and budget['closed']
    assert state.latest_result(independent.id) is None and events['events'][-1].stop_reason == 'workflow_blocked'


@pytest.mark.asyncio
async def test_api_json_only_negative_is_bounded_without_forcing_browser(runtime, tmp_path, monkeypatch):
    import httpx
    from tests.security.test_execution_policy import REAL_CLIENT

    def json_response(request):
        runtime[4].append(request)
        return httpx.Response(200, json={'q': 'fixture'}, request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: REAL_CLIENT(transport=httpx.MockTransport(json_response), **kwargs))
    state, candidate, tool, args, oid = await setup(runtime, tmp_path)
    assert state.objective is not None
    registry, p, policy, *_ = runtime
    args['assessment'] = {**ASSESSMENT, 'hypothesis': 'API reflection without identified executable sink',
        'criteria': 'Test the supplied API input only', 'limitations': 'DOM/stored execution paths are outside this hypothesis'}
    result = json.loads(await registry.execute('workflow', {**args, 'outcome': 'not-confirmed'}, None, p))
    assert result['ok'] and b'fixture' in policy.observations._items[oid].body
    assert tool.validation_completion_error(candidate.id, policy) is None
    assert len(state.candidates) == 1 and not state.eligible_for_finding(candidate.id)
    assert not any(r.outcome == 'browser-required' for r in state.validation_results)


@pytest.mark.asyncio
async def test_scripted_agent_corrects_coverage_arguments_without_http(runtime, tmp_path):
    state, _, tool, _, _ = await setup(runtime, tmp_path, mode="direct")
    # Legacy owned active Attempt recovery keeps discovery independent.
    assert state.objective is not None
    state.objective.mode = "whole_target"
    before_requests = len(runtime[4])

    def script():
        rejected = yield 'workflow', {'action': 'record_phase_coverage', 'phase': 'recon',
            'coverage_dimension': 'dns_resolution', 'coverage_status': 'observed', 'coverage_reason': 'fixture'}
        error = json.loads(rejected.split('\n', 1)[1])['error']
        assert error['category'] == 'argument_error'
        assert 'target_resolution' in error['allowed_dimensions']
        corrected = json.loads((yield 'workflow', {'action': 'record_phase_coverage', 'phase': 'recon',
            'coverage_dimension': 'target_resolution', 'coverage_status': 'observed',
            'coverage_reason': 'Offline source review; not machine-attested execution'}))
        assert corrected['ok']
        rejected = yield 'workflow', {'action': 'record_phase_coverage', 'phase': 'input_analysis',
            'coverage_dimension': 'inputs', 'coverage_status': 'observed', 'coverage_reason': 'fixture'}
        error = json.loads(rejected.split('\n', 1)[1])['error']
        assert error['code'] == 'INVALID_COVERAGE_PHASE' and 'complete_skill' in error['next_action']
        inventory = json.loads((yield 'workflow', {'action': 'list'}))
        assert inventory['ok'] and inventory['completed_phases'] == []

    client = ScriptedModel(script(), prefix='coverage-correction')
    agent = agent_for(runtime, tool, state, client, max_steps=5)
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    assert not client.errors and client.consumed
    assert len(runtime[4]) == before_requests
    assert not state.completed_phases()
    record = state.phase_coverage_record('recon', 'target_resolution')
    assert record is not None and record.status == 'observed'
