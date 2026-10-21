"""Production workflow/Agent regressions for attempt-scoped submission repair."""
from dataclasses import replace
import json

import pytest

from src.agent.agent import Agent, AgentOptions
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.workflow.assessment import digest, source_row
from src.workflow.evidence.errors import evidence_repair_kind
from src.workflow.evidence.recovery import current_budget
from src.workflow.state import WorkflowObjective, WorkflowState
from tests.helpers.agent_fakes import FakeClient, FakeSignal, ScriptedModel, collect
from tests.security.test_agent_assessment import setup
from tests.security.test_execution_policy import runtime  # noqa: F401


def envelope(result):
    assert result.startswith('error:')
    return json.loads(result.split('\n', 1)[1])['error']


def client_for(args):
    return FakeClient([ChatResponse(Message('assistant', '', tool_calls=[
        ToolCall('submission', FunctionCall('workflow', json.dumps(args)))]), 'tool_calls'),
        ChatResponse(Message('assistant', 'Partial validation state recorded.'), 'stop')])


def agent_for(runtime, workflow, state, args, max_steps=1):
    registry, p, policy, *_, target = runtime
    agent = Agent(AgentOptions(client=client_for(args), tools=registry, skills=workflow.skills,
        prompter=p, store=None, target=target, workflow=state, engagement_state=policy.engagement,
        max_steps=max_steps, auto_compact_threshold=0, streaming_enabled=False))
    agent.active_skills.add('cross-site-scripting')
    return agent


@pytest.mark.parametrize('fault,code', [
    ('missing-primary', 'MISSING_PRIMARY_OBSERVATIONS'),
    ('wrong-reference', 'PRIMARY_REFERENCE_UNAVAILABLE'),
    ('wrong-proof', 'EVIDENCE_REFERENCE_MISMATCH'),
    ('wrong-owner', 'SOURCE_OWNERSHIP_MISMATCH'),
    ('wrong-attempt', 'ATTEMPT_IDENTITY_MISMATCH'),
    ('missing-proof', 'MISSING_REGISTERED_EVIDENCE'),
])
async def test_structured_rejection_does_not_publish_or_echo_references(runtime, tmp_path, fault, code):
    state, candidate, _, args, oid = await setup(runtime, tmp_path)
    registry, p, policy, *_ = runtime
    if fault == 'missing-primary':
        args['observation_ids'] = []
    elif fault == 'wrong-reference':
        args['observation_ids'] = ['private-reference-secret']
    elif fault == 'wrong-proof':
        args['evidence_refs'] = ['private-reference-secret']
    elif fault == 'missing-proof':
        args['evidence_refs'] = []
    elif fault == 'wrong-attempt':
        args['attempt_id'] = 'private-reference-secret'
    else:
        item = replace(policy.observations._items[oid], attempt_id='private-reference-secret')
        policy.observations._items[oid] = replace(item, retained_hash=digest(source_row(item)))
    rejected = await registry.execute('workflow', args, None, p)
    error = envelope(rejected)
    assert error['code'] == code and error['repair_kind'] == 'manifest'
    assert 'private-reference-secret' not in rejected
    assert 'record_evidence' in error['repair_hint'] and 'insufficient-evidence' in error['repair_hint']
    assert evidence_repair_kind('error: wording may change\n' + rejected.split('\n', 1)[1]) == 'manifest'
    assert not state.validation_results and not state.eligible_for_finding(candidate.id)
    unresolved = {**args, 'outcome': 'insufficient-evidence', 'observation_ids': [], 'evidence_refs': []}
    unresolved.pop('attempt_id')
    assert json.loads(await registry.execute('workflow', unresolved, None, p))['ok']


async def test_parent_conflicts_have_specific_repair_codes(runtime, tmp_path):
    state, candidate, _, args, oid = await setup(runtime, tmp_path)
    registry, p, *_ = runtime
    registration = {'action': 'record_evidence', 'candidate_id': candidate.id,
                    'evidence_path': 'proof.md', 'observation_ids': [oid]}
    evidence = json.loads(await registry.execute('workflow', registration, None, p))['evidence']
    original = (tmp_path / evidence['path']).read_bytes()
    result = await registry.execute('workflow', {**registration, 'observation_ids': []}, None, p)
    assert envelope(result)['code'] == 'IMMUTABLE_PARENT_CONFLICT'
    args.update(evidence_refs=[evidence['id']], observation_ids=[])
    # Missing primary takes precedence; no weakened parent/admissibility gate.
    assert envelope(await registry.execute('workflow', args, None, p))['code'] == 'MISSING_PRIMARY_OBSERVATIONS'
    assert (tmp_path / evidence['path']).read_bytes() == original
    assert state.evidence_sources[evidence['id']] == [oid]


@pytest.mark.parametrize('fresh_agent', [False, True])
async def test_continuation_keeps_budget_and_closes_unresolved_without_http(runtime, tmp_path, fresh_agent):
    state, candidate, workflow, args, _ = await setup(runtime, tmp_path)
    registry, p, policy, _, sent, *_ = runtime
    args['observation_ids'] = []
    agent = agent_for(runtime, workflow, state, args)
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    budget = current_budget(state, candidate.id)
    assert budget is not None
    assert budget['rejections'] == 1 and not state.validation_results
    agent.client = client_for(args)
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    assert budget['rejections'] == 2 and not budget['closed'] and not state.validation_results
    serialized = json.loads(json.dumps(state.to_dict()))
    assert WorkflowState.from_dict(serialized).evidence_recovery == state.evidence_recovery
    if fresh_agent:
        # Restore durable state with fresh attempt ownership; retries still carry.
        restored = WorkflowState.from_dict(serialized)
        workflow.state = restored
        state = restored
        policy.bind_validation_context(state, workflow.skills, workflow.target)
        started = json.loads(await registry.execute('workflow', {
            'action': 'start_validation', 'candidate_id': candidate.id}, None, p))
        args['attempt_id'] = started['validation_context']['attempt_id']
        budget = current_budget(state, candidate.id)
        assert budget is not None and budget['rejections'] == 2
        agent = agent_for(runtime, workflow, state, args, max_steps=6)
    else:
        agent.client = client_for(args)
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    latest = state.latest_result(candidate.id)
    assert latest and latest.outcome == 'insufficient-evidence'
    budget = current_budget(state, candidate.id)
    assert budget is not None and budget['rejections'] == 3
    assert budget['closed']
    assert not state.eligible_for_finding(candidate.id) and len(sent) == 1


async def test_explicit_retest_has_independent_budget_and_cannot_borrow_sources(runtime, tmp_path):
    state, candidate, workflow, args, oid = await setup(runtime, tmp_path)
    registry, p, policy, _, sent, *_ = runtime
    invalid = {**args, 'observation_ids': []}
    agent = agent_for(runtime, workflow, state, invalid)
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    old_budget = current_budget(state, candidate.id)
    assert old_budget is not None
    old_aid = args['attempt_id']
    state.objective = WorkflowObjective('explicit-retest', 'candidate_validation', candidate.target, candidate_id=candidate.id)
    candidate.status = 'queued'
    started = json.loads(await registry.execute('workflow', {'action': 'start_validation', 'candidate_id': candidate.id}, None, p))
    aid = started['validation_context']['attempt_id']
    assert aid != old_aid and current_budget(state, candidate.id) is None
    args['attempt_id'] = aid
    agent = agent_for(runtime, workflow, state, args)
    await agent.run('Continue the explicit retest.', FakeSignal(), collect()['sink'])
    budget = current_budget(state, candidate.id)
    assert budget is not None and budget['rejections'] == 1
    assert old_budget['rejections'] == 1 and not state.validation_results
    assert policy.observations._items[oid].attempt_id == old_aid and len(sent) == 1


async def test_repair_missing_ids_reuses_capture_and_succeeds(runtime, tmp_path):
    state, candidate, workflow, args, oid = await setup(runtime, tmp_path)
    _, _, _, _, sent, *_ = runtime
    agent = agent_for(runtime, workflow, state, {**args, 'observation_ids': []})
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    agent.client = client_for(args)
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    latest = state.latest_result(candidate.id)
    assert latest and latest.outcome == 'confirmed'
    assert [e['source']['id'] for e in latest.evidence_manifest] == [oid]
    budget = current_budget(state, candidate.id)
    assert budget is not None and len(sent) == 1 and budget['closed']
    assert budget['rejections'] == 1 and budget['repair_turns'] == 1


@pytest.mark.parametrize('same_batch', [False, True])
@pytest.mark.parametrize('outcome', ['confirmed', 'not-confirmed'])
async def test_successful_repair_persists_final_turn_count(runtime, tmp_path, same_batch, outcome):
    state, candidate, workflow, args, _ = await setup(runtime, tmp_path)
    args['outcome'] = outcome
    _, _, _, _, sent, *_ = runtime
    submissions = [{**args, 'observation_ids': []},
                   {**args, 'evidence_refs': ['ev_unavailable']}, args]
    calls = [ToolCall(f'repair-{n}', FunctionCall('workflow', json.dumps(submission)))
             for n, submission in enumerate(submissions, 1)]
    batches = [calls] if same_batch else [[call] for call in calls]
    responses = [ChatResponse(Message('assistant', '', tool_calls=batch), 'tool_calls')
                 for batch in batches]
    responses.append(ChatResponse(Message('assistant', 'Fixture validation result recorded.'), 'stop'))
    client = FakeClient(responses)
    agent = agent_for(runtime, workflow, state, args, max_steps=len(batches))
    agent.client = client
    trace = collect()
    await agent.run('Continue current validation.', FakeSignal(), trace['sink'])
    assert trace['events'][-1].stop_reason != 'runtime_error'
    assert len(client.requests) == len(responses)
    latest = state.latest_result(candidate.id)
    assert latest is not None and latest.outcome == outcome
    budget = current_budget(state, candidate.id)
    assert budget is not None and budget['closed'] and budget['rejections'] == 2
    assert budget['repair_turns'] == (0 if same_batch else 2)
    restored = WorkflowState.from_dict(json.loads(json.dumps(state.to_dict())))
    assert current_budget(restored, candidate.id) == budget
    assert len(sent) == 1


@pytest.mark.parametrize('schema_retry', [False, True])
@pytest.mark.parametrize('outcome', ['confirmed', 'not-confirmed'])
async def test_two_terminal_repairs_can_rewrite_register_and_submit(runtime, tmp_path, schema_retry, outcome):
    state, candidate, workflow, args, oid = await setup(runtime, tmp_path)
    args['outcome'] = outcome
    _, _, _, _, sent, *_ = runtime

    def script():
        rejected = yield 'workflow', {**args, 'observation_ids': []}
        assert envelope(rejected)['code'] == 'MISSING_PRIMARY_OBSERVATIONS'
        for repair in (1, 2):
            yield 'file_write', {'path': str(tmp_path / 'proof.md'),
                                 'content': f'Corrected fixture proof, revision {repair}.'}
            registered = json.loads((yield 'workflow', {
                'action': 'record_evidence', 'candidate_id': candidate.id,
                'evidence_path': 'proof.md', 'observation_ids': [oid]}))
            submission = {**args, 'evidence_refs': [registered['evidence']['id']]}
            if repair == 1:
                submission.update({'assessment': {}} if schema_retry
                                  else {'evidence_refs': ['ev_unavailable']})
            feedback = yield 'workflow', submission
            if repair == 1:
                assert feedback.startswith('error:')
                budget = current_budget(state, candidate.id)
                assert budget is not None and budget['rejections'] == 2
                assert not budget['closed'] and not state.validation_results
            else:
                assert json.loads(feedback)['ok']

    agent = agent_for(runtime, workflow, state, args, max_steps=8)
    client = ScriptedModel(script(), prefix='two-repairs')
    agent.client = client
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    assert client.consumed and not client.errors
    assert len(client.calls) == 7  # Initial submission + two write/register/submit cycles.
    latest = state.latest_result(candidate.id)
    assert latest is not None and latest.outcome == outcome
    assert [row['source']['id'] for row in latest.evidence_manifest] == [oid]
    budget = current_budget(state, candidate.id)
    assert budget is not None and budget['rejections'] == 2 and budget['closed']
    assert budget['repair_turns'] == 6  # Successful submission at the repair boundary is included.
    assert len(sent) == 1  # Repair did not recapture HTTP or borrow evidence.


@pytest.mark.parametrize('schema_retry', [False, True])
@pytest.mark.parametrize('outcome', ['confirmed', 'not-confirmed'])
async def test_fourth_terminal_submission_is_blocked_within_batch(runtime, tmp_path, monkeypatch, schema_retry, outcome):
    state, candidate, workflow, args, _ = await setup(runtime, tmp_path)
    args['outcome'] = outcome
    _, _, _, _, sent, *_ = runtime
    executed = []
    original = workflow.run

    async def tracked_run(submission, signal, prompter):
        if submission.get('action') == 'record_result':
            executed.append(submission.copy())
        return await original(submission, signal, prompter)

    monkeypatch.setattr(workflow, 'run', tracked_run)
    retry = {**args, **({'assessment': {}} if schema_retry else {'evidence_refs': ['ev_unavailable']})}
    submissions = [{**args, 'observation_ids': []}, retry, retry, args]
    calls = [ToolCall(f'terminal-{n}', FunctionCall('workflow', json.dumps(submission)))
             for n, submission in enumerate(submissions, 1)]
    agent = agent_for(runtime, workflow, state, args, max_steps=2)
    client = FakeClient([ChatResponse(Message('assistant', '', tool_calls=calls), 'tool_calls')])
    agent.client = client
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    assert len([row for row in executed if row['outcome'] == outcome]) == 3
    assert len([row for row in executed if row['outcome'] == 'insufficient-evidence']) == 1
    blocked = next(m for m in agent.history if m.role == 'tool' and m.tool_call_id == 'terminal-4')
    assert 'bounded evidence repair exhausted' in blocked.content
    latest = state.latest_result(candidate.id)
    assert latest is not None and latest.outcome == 'insufficient-evidence'
    budget = current_budget(state, candidate.id)
    assert budget is not None and budget['rejections'] == 3 and budget['closed']
    assert len(client.requests) == 1 and len(sent) == 1
    assert not state.eligible_for_finding(candidate.id)


@pytest.mark.parametrize('fresh_agent', [False, True])
async def test_repair_turn_clock_survives_single_step_continuations(runtime, tmp_path, fresh_agent):
    state, candidate, workflow, args, _ = await setup(runtime, tmp_path)
    registry, p, policy, _, sent, *_ = runtime
    agent = agent_for(runtime, workflow, state, {**args, 'observation_ids': []})
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    for turn in range(6):
        if fresh_agent:
            state = WorkflowState.from_dict(json.loads(json.dumps(state.to_dict())))
            workflow.state = state
            policy.bind_validation_context(state, workflow.skills, workflow.target)
            started = json.loads(await registry.execute('workflow', {
                'action': 'start_validation', 'candidate_id': candidate.id}, None, p))
            assert started['ok']
            agent = agent_for(runtime, workflow, state, args)
        agent.client = FakeClient([ChatResponse(Message('assistant', '', tool_calls=[
            ToolCall(str(turn), FunctionCall('file_write', json.dumps({
                'path': str(tmp_path / 'proof.md'), 'content': 'Repair work in progress.'})))]), 'tool_calls'),
            ChatResponse(Message('assistant', 'Validation remains unresolved.'), 'stop')])
        await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
        budget = current_budget(state, candidate.id)
        assert budget is not None and budget['repair_turns'] == turn + 1
        assert WorkflowState.from_dict(state.to_dict()).evidence_recovery == state.evidence_recovery
        if turn < 5:
            assert not state.validation_results and not budget['closed']
    result = state.latest_result(candidate.id)
    assert result is not None and result.outcome == 'insufficient-evidence'
    assert len(sent) == 1


async def test_registration_errors_alone_have_bounded_unresolved_closure(runtime, tmp_path):
    state, candidate, workflow, _, _ = await setup(runtime, tmp_path)
    _, _, _, _, sent, *_ = runtime
    args = {'action': 'record_evidence', 'candidate_id': candidate.id,
            'evidence_path': 'proof.md', 'observation_ids': ['obs_unavailable']}
    agent = agent_for(runtime, workflow, state, args, max_steps=6)
    responses = [ChatResponse(Message('assistant', '', tool_calls=[
        ToolCall(str(n), FunctionCall('workflow', json.dumps(args)))]), 'tool_calls') for n in range(3)]
    agent.client = FakeClient(responses)
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    result = state.latest_result(candidate.id)
    assert result is not None and result.outcome == 'insufficient-evidence'
    budget = current_budget(state, candidate.id)
    assert budget is not None and budget['rejections'] == 3 and budget['paused'] and budget['closed']
    assert len(sent) == 1


@pytest.mark.parametrize('exhaustion', ['rejections', 'repair_turns'])
async def test_exhausted_restored_budget_stops_before_model_or_http(runtime, tmp_path, exhaustion):
    state, candidate, workflow, args, _ = await setup(runtime, tmp_path)
    _, _, _, _, sent, *_ = runtime
    agent = agent_for(runtime, workflow, state, {**args, 'observation_ids': []})
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    budget = current_budget(state, candidate.id)
    assert budget is not None
    budget[exhaustion] = 3 if exhaustion == 'rejections' else 6  # Before controller closure.
    state = WorkflowState.from_dict(json.loads(json.dumps(state.to_dict())))
    workflow.state = state
    agent.workflow = state
    restored = current_budget(state, candidate.id)
    assert restored is not None and restored[exhaustion] == budget[exhaustion]
    scripted = client_for(args)
    agent.client = scripted
    output = collect()
    await agent.run('Continue current validation.', FakeSignal(), output['sink'])
    assert not scripted.requests and len(sent) == 1
    result = state.latest_result(candidate.id)
    # Hydration interrupted execution ownership. The shared finalizer must not
    # mint a canonical result with a missing/foreign active selector.
    assert result is None and state.attempts[args['attempt_id']]['status'] == 'interrupted'
    assert restored[exhaustion] == budget[exhaustion] and not restored['closed']
    assert any(event['type'] == 'error' for event in output['events'])


@pytest.mark.parametrize('mode', ['whole_target', 'direct', 'candidate_validation'])
async def test_restarting_same_objective_cannot_reset_exhausted_budget(runtime, tmp_path, mode):
    state, candidate, workflow, args, _ = await setup(runtime, tmp_path)
    assert state.objective is not None
    state.objective.mode = mode
    state.objective.candidate_id = candidate.id if mode == 'candidate_validation' else None
    registry, p, _, _, sent, *_ = runtime
    agent = agent_for(runtime, workflow, state, {**args, 'observation_ids': []})
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    budget = current_budget(state, candidate.id)
    assert budget is not None
    budget['rejections'] = 3
    agent.client = FakeClient([])
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    output = await registry.execute('workflow', {'action': 'start_validation', 'candidate_id': candidate.id}, None, p)
    if mode == 'whole_target':
        assert envelope(output)['code'] == 'EXHAUSTED_ATTEMPT'
        assert current_budget(state, candidate.id) is budget and budget['closed']
        assert not agent.client.requests and len(sent) == 1
        assert all(result.outcome == 'insufficient-evidence' for result in state.validation_results)
        return
    started = json.loads(output)
    assert started['validation_context']['attempt_id'] != args['attempt_id']
    carried = current_budget(state, candidate.id)
    assert carried is not None and carried['rejections'] == 3 and not carried['closed']
    agent.client = FakeClient([])
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    assert not agent.client.requests and len(sent) == 1
    assert all(result.outcome == 'insufficient-evidence' for result in state.validation_results)


async def test_operator_stop_keeps_existing_goal_cancellation_priority(runtime, tmp_path):
    from src.workflow.planning.goals import RequestedGoal
    state, candidate, workflow, args, _ = await setup(runtime, tmp_path)
    _, _, _, _, sent, *_ = runtime
    agent = agent_for(runtime, workflow, state, {**args, 'observation_ids': []})
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    budget = current_budget(state, candidate.id)
    assert budget is not None and state.objective is not None
    budget['rejections'] = 3  # Interrupted after rejection, before closure.
    goal = RequestedGoal('cross-site-scripting', status='pending')
    state.objective.requested_goals = [goal]
    client = FakeClient([ChatResponse(Message('assistant', 'Unresolved testing cancelled.'), 'stop')])
    agent.client = client
    await agent.run('Stop testing this assessment', FakeSignal(), collect()['sink'])
    assert goal.status == 'cancelled'
    assert not state.validation_results and not budget['closed']
    assert len(client.requests) == 1 and client.requests[0].tools is None
    assert len(sent) == 1


async def test_invalid_closure_metadata_does_not_reset_saved_accounting(runtime, tmp_path):
    state, candidate, workflow, args, _ = await setup(runtime, tmp_path)
    agent = agent_for(runtime, workflow, state, {**args, 'observation_ids': []})
    await agent.run('Continue current validation.', FakeSignal(), collect()['sink'])
    saved = json.loads(json.dumps(state.to_dict()))
    aid = args['attempt_id']
    saved['evidence_recovery'][aid].update(rejections=2, repair_turns=5)
    saved['evidence_recovery'][aid]['closure_args'] = {'cleanup_status': 'x' * 6001}
    restored = WorkflowState.from_dict(saved)
    budget = current_budget(restored, candidate.id)
    assert budget is not None and budget['rejections'] == 2 and budget['repair_turns'] == 5
    assert budget['closure_args'] == {}  # Unusable metadata cannot grant another retry.
