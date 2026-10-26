"""Candidate-selected Direct runs preserve terminal results and optional retries."""
from copy import deepcopy
import json

import pytest

from src.agent.decision_planner import build_decision_plan
from src.agent.agent import AgentRunOptions
from src.engagement.state import OutOfScopeError
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.permission.permission import Decision, UserControlledRefusal
from src.permission.runtime.execution import ExecutionBlocked
from src.session.store import Store
from tests.helpers.agent_fakes import FakeClient, FakeSignal, collect
from tests.integration.test_runtime_validation_completion import agent_for, persist, validated
from tests.security.test_agent_assessment import setup
from tests.security.test_execution_policy import runtime  # noqa: F401


def request_view(agent, candidate):
    return agent._workflow_request_view(
        f'Validate candidate {candidate.id}', agent.tools.as_llm_tools())


@pytest.mark.parametrize('outcome,saved', [('confirmed', True), ('confirmed', False), ('not-confirmed', False)])
@pytest.mark.parametrize('status', ['validated', 'queued', 'validating'])
async def test_terminal_result_does_not_advertise_or_admit_same_request_reopen(
        runtime, tmp_path, outcome, saved, status):
    state, candidate, tool, _ = await validated(runtime, tmp_path, mode='candidate_validation', outcome=outcome)
    if saved:
        await persist(runtime, tmp_path, state, candidate)
    # Status alone cannot authorize a restart or manufacture an owned attempt.
    state.set_candidate_status(candidate.id, status)
    agent = agent_for(runtime, state, tool)
    plan = build_decision_plan(f'Validate candidate {candidate.id}', agent.skills.list_enabled(),
                               agent.target, agent._planner_context())
    assert plan is not None and plan.candidate_id == candidate.id
    assert plan.recommended_skill is None
    guidance = '\n'.join(m.content for m in request_view(agent, candidate).blocks)
    assert 'Preserve the terminal result' in guidance
    assert 'Then call workflow(action="start_validation"' not in guidance
    # Goal reconciliation above is expected; the rejected tool must be a no-op.
    before = deepcopy(state.to_dict())
    output = await runtime[0].execute('workflow', {
        'action': 'start_validation', 'candidate_id': candidate.id}, None, runtime[1])
    assert output.startswith('error: terminal candidate cannot be reopened'), output
    assert state.to_dict() == before
    assert state.finding_is_persisted(candidate.id) is saved


DECLINE = {'decision': 'decline', 'reason': 'No interpretable alternative remains in the bounded fixture.'}


async def test_decline_survives_resume_and_allows_explicit_reconsideration(runtime, tmp_path):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path, mode='candidate_validation')
    output = await runtime[0].execute('workflow', {
        **args, 'outcome': 'insufficient-evidence', 'retry_decision': DECLINE}, None, runtime[1])
    assert json.loads(output)['ok'], output
    agent = agent_for(runtime, state, tool)
    agent.store = Store.new_with_id(tmp_path / 'sessions', tool.session_id)
    await agent.save()
    state.replace_from(agent.store.load().workflow)
    before = deepcopy(state.to_dict())
    view = request_view(agent, candidate)
    guidance = '\n'.join(m.content for m in view.blocks)
    assert 'Further retry explicitly declined' in guidance
    assert 'Then call workflow(action="start_validation"' not in guidance
    assert state.to_dict() == before and state.retry_decision(candidate.id) == DECLINE
    assert agent._whole_target_state()[0] == 'not_applicable'
    events = collect()
    await agent.run('continue', FakeSignal(), events['sink'])
    assert events['events'][-1]['stop_reason'] == 'workflow_blocked'
    assert len(state.attempts) == len(state.validation_results) == 1
    # A revised strategy may reconsider Decline without creating a new retest mode.
    output = await runtime[0].execute('workflow', {
        'action': 'record_retry_decision', 'candidate_id': candidate.id,
        'retry_decision': {'decision': 'retry', 'reason': 'Compare a newly identified bounded fixture oracle.'}},
        None, runtime[1])
    assert json.loads(output)['ok'], output
    output = await runtime[0].execute('workflow', {
        'action': 'start_validation', 'candidate_id': candidate.id}, None, runtime[1])
    assert json.loads(output)['ok'], output
    assert len(state.attempts) == 2 and len(state.validation_results) == 1
    assert state.retry_decision(candidate.id) is None


async def test_changed_request_identity_does_not_inherit_decline(runtime, tmp_path):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path, mode='candidate_validation')
    output = await runtime[0].execute('workflow', {
        **args, 'outcome': 'insufficient-evidence', 'retry_decision': DECLINE}, None, runtime[1])
    assert json.loads(output)['ok'], output
    candidate.auth_context_ref = 'changed-fixture-identity'
    agent = agent_for(runtime, state, tool)
    assert state.retry_decision(candidate.id) is None
    assert agent._planner_context().candidates[0].validation_action == 'start_validation'


@pytest.mark.parametrize('outcome', ['confirmed', 'not-confirmed'])
async def test_operator_retest_uses_new_objective_and_cannot_borrow_old_proof(runtime, tmp_path, outcome):
    state, candidate, tool, args = await validated(runtime, tmp_path, mode='candidate_validation', outcome=outcome)
    agent = agent_for(runtime, state, tool)
    original = deepcopy(state.validation_results[0].to_dict())
    assert state.objective is not None
    old_objective = state.objective.id
    agent._initialize_request_objective('continue', True)
    assert state.objective is not None
    assert state.objective.id == old_objective
    denied = await runtime[0].execute('workflow', {
        'action': 'start_validation', 'candidate_id': candidate.id}, None, runtime[1])
    assert denied.startswith('error: terminal candidate cannot be reopened')
    agent._initialize_request_objective(f'Retest candidate {candidate.id}', True)
    assert state.objective is not None
    assert state.objective.mode == 'candidate_validation' and state.objective.id != old_objective
    assert agent._planner_context().candidates[0].validation_action == 'start_validation'
    plan = build_decision_plan(f'Retest candidate {candidate.id}', agent.skills.list_enabled(),
                               agent.target, agent._planner_context())
    assert plan is not None and plan.recommended_skill == candidate.candidate_class
    started = json.loads(await runtime[0].execute('workflow', {
        'action': 'start_validation', 'candidate_id': candidate.id}, None, runtime[1]))
    assert started['ok'], started
    rejected = await runtime[0].execute('workflow', {
        **args, 'attempt_id': started['validation_context']['attempt_id']}, None, runtime[1])
    assert rejected.startswith('error:') and 'ownership' in rejected
    assert len(state.attempts) == 2 and len(state.validation_results) == 1
    assert state.validation_results[0].to_dict() == original


@pytest.mark.parametrize('damage', ['missing', 'tampered'])
async def test_evidence_revalidation_and_owned_resume_remain_available(runtime, tmp_path, damage):
    state, candidate, tool, args = await validated(runtime, tmp_path, mode='candidate_validation')
    proof = tmp_path / state.evidence[args['evidence_refs'][0]].path
    if damage == 'missing':
        proof.unlink()
    else:
        proof.chmod(0o600)
        proof.write_text('Changed fixture proof.')
    original = deepcopy(state.validation_results[0].to_dict())
    started = json.loads(await runtime[0].execute('workflow', {
        'action': 'start_validation', 'candidate_id': candidate.id}, None, runtime[1]))
    assert started['ok'], started
    resumed = json.loads(await runtime[0].execute('workflow', {
        'action': 'start_validation', 'candidate_id': candidate.id}, None, runtime[1]))
    assert resumed['ok'] and resumed['validation_context']['attempt_id'] == started['validation_context']['attempt_id']
    assert len(state.attempts) == 2 and len(state.validation_results) == 1
    assert state.validation_results[0].to_dict() == original


def tool_response(name, args):
    return ChatResponse(Message('assistant', '', tool_calls=[
        ToolCall(name + str(args.get('action', '')), FunctionCall(name, json.dumps(args)))]), 'tool_calls')


async def test_confirmed_keeps_local_finalization_and_later_steps(runtime, tmp_path):
    state, candidate, tool, _ = await validated(runtime, tmp_path, mode='candidate_validation')
    await persist(runtime, tmp_path, state, candidate)
    # Repeat idempotent finding persistence through the Agent, then inspect
    # Workflow. A saved finding must not force an early final_response.
    agent = agent_for(runtime, state, tool)
    agent.client = FakeClient([
        tool_response('confirm_finding', {
            'candidate_id': candidate.id, 'title': 'Bounded fixture validation', 'severity': 'low',
            'url': runtime[6].base_url() + '/fixture', 'vuln_class': candidate.candidate_class,
            'observed_impact': 'Fixture response observed.', 'potential_impact': 'Further impact was not assessed.'}),
        tool_response('workflow', {'action': 'list', 'candidate_id': candidate.id}),
        ChatResponse(Message('assistant', 'Recorded validation and finalization are complete.'), 'stop'),
    ])
    original = deepcopy(state.validation_results[0].to_dict())
    events = collect()
    await agent.run('continue', FakeSignal(), events['sink'], AgentRunOptions(max_steps=8))
    assert events['events'][-1]['stop_reason'] == 'final_response'
    assert len(agent.client.requests) == 3
    assert len(state.attempts) == len(state.validation_results) == 1
    assert state.validation_results[0].to_dict() == original and state.finding_is_persisted(candidate.id)


@pytest.mark.parametrize('boundary', ['permission', 'scope', 'tool-budget', 'http-budget'])
async def test_retry_does_not_bypass_execution_gates(runtime, tmp_path, boundary):
    state, candidate, _, args, _ = await setup(runtime, tmp_path, mode='candidate_validation')
    registry, prompter, policy, operator, sent, *_ = runtime
    output = await registry.execute('workflow', {**args, 'outcome': 'insufficient-evidence'}, None, prompter)
    assert json.loads(output)['ok'], output
    output = await registry.execute('workflow', {
        'action': 'start_validation', 'candidate_id': candidate.id}, None, prompter)
    assert json.loads(output)['ok'], output
    http_args = {'url': '/fixture?q=bounded', 'phase': 'validation'}
    if boundary == 'permission':
        policy.revoke('http')
        prompter.set_yolo(False)
        operator.decision = Decision.DENY
    elif boundary == 'scope':
        http_args['url'] = 'https://outside.test/fixture?q=bounded'
    elif boundary == 'tool-budget':
        policy.max_calls = policy.used
    else:
        for budget in policy.engagement.http_permissions._budgets.values():
            budget.used = budget.limits.requests
    count = len(sent)
    with pytest.raises((ExecutionBlocked, UserControlledRefusal, OutOfScopeError)):
        await registry.execute('http', http_args, None, prompter)
    assert len(sent) == count and len(state.validation_results) == 1


async def test_generic_candidate_uses_same_terminal_guard_and_existing_retest(runtime, tmp_path):
    from tests.security.test_generic_validation import (
        agent_for as generic_agent, bind_context, evidence, result,
        setup as generic_setup, start,
    )
    env = await generic_setup(runtime, tmp_path)
    agent = generic_agent(env)
    state, candidate = env[4], env[5]
    agent._initialize_request_objective(f'Validate candidate {candidate.id}', True)
    bind_context(env)
    assert json.loads(await start(env))['ok']
    ref = await evidence(env, tmp_path)
    assert json.loads(await result(env, 'not-confirmed', refs=[ref]))['ok']
    before = deepcopy(state.to_dict())
    rejected = await start(env)
    assert rejected.startswith('error:') and state.to_dict() == before
    agent._initialize_request_objective(f'Retest candidate {candidate.id}', True)
    bind_context(env)
    assert json.loads(await start(env))['ok']
    assert len(state.attempts) == 2 and len(state.validation_results) == 1
