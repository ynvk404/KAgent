"""Offline production regressions for three independently reproduced lan-23 defects."""
import asyncio
from copy import deepcopy
import hashlib
import json

import httpx
import pytest

from src.tools.common.ask import AskUserTool
from src.ui.core.outcomes import runtime_facts
from src.workflow.assessment import accepted_result, attempt_effects, attempt_owner, require_idle_attempt
from src.workflow.discovery.input_view import input_provenance
from src.workflow.state import WorkflowState
from tests.agent.test_validation_continuation import offline, candidate_for  # noqa: F401
from tests.helpers.discovery_calls import execute
from tests.security.test_agent_assessment import setup
from tests.security.test_execution_policy import runtime, REAL_CLIENT, ORIGIN  # noqa: F401
from tests.tools.test_lan2021_input_questions import Operator, dependency


@pytest.mark.parametrize('projection', ['handoff', 'planner', 'progress'])
@pytest.mark.parametrize('completion', ['completed', 'failed', 'cancelled'])
@pytest.mark.parametrize('mutation', ['no-mutation-established', 'reported-write'])
async def test_in_flight_http_is_observable_but_cannot_finalize(offline, monkeypatch, projection, completion, mutation):
    rt, _ = offline
    cid = await candidate_for(rt)
    started = json.loads(await rt.registry.execute('workflow', {
        'action': 'start_validation', 'candidate_id': cid}, None, rt.prompter))
    attempt = rt.workflow.attempts[started['validation_context']['attempt_id']]
    await rt.registry.execute('http', {'url': '/fixture?q=baseline', 'phase': 'validation'}, None, rt.prompter)
    oid = next(reversed(rt.policy.observations._items))
    known_write = mutation == 'reported-write'
    assert json.loads(await rt.registry.execute('workflow', {
        'action': 'record_attempt_state', 'candidate_id': cid, 'mutation_state': mutation,
        'effect_basis': 'Controlled fixture acknowledgement' if known_write else 'Stateless controlled fixture',
        'cleanup_state': 'requires-user-action' if known_write else 'not-required',
        'observation_ids': [oid]}, None, rt.prompter))['ok']
    entered, release = asyncio.Event(), asyncio.Event()

    async def hold(request):
        entered.set()
        await release.wait()
        if completion == 'failed':
            raise httpx.ReadError('Controlled offline failure')
        if completion == 'cancelled':
            raise asyncio.CancelledError()
        return httpx.Response(200, content=b'fixture', request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(hold), **kw))
    pending = asyncio.create_task(rt.registry.execute('http', {
        'url': '/fixture?q=held', 'phase': 'validation'}, None, rt.prompter))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        fact = attempt['effects']['dispatches'][-1]
        assert fact['status'] == 'dispatched' and fact['observation_id'] is None
        before = deepcopy(rt.workflow.to_dict())
        if projection == 'handoff':
            handoff = rt.workflow_tool.validation_handoff(cid, rt.policy)
            assert handoff is not None and handoff['owned_active']
            assert handoff['effects']['completed_dispatches'] == 1
            assert handoff['effects']['mutation_performed'] is (True if known_write else None)
            assert handoff['effects']['cleanup_state'] == ('requires-user-action' if known_write else 'unknown')
            assert handoff['effects']['declaration_current'] is known_write
        elif projection == 'planner':
            context = rt.agent._planner_context()
            assert next(c for c in context.candidates if c.id == cid).validation_action == 'resume_owned'
        else:
            assert 'Validation' in runtime_facts(rt.agent, None, ()).overview
        assert rt.workflow.to_dict() == before
        for policy in (rt.policy, None):
            with pytest.raises(ValueError, match='in flight'):
                require_idle_attempt(attempt, policy)
        for args in (
            {'action': 'record_attempt_state', 'mutation_state': 'unknown', 'effect_basis': 'Pending HTTP'},
            {'action': 'record_result', 'skill_name': 'sql-injection', 'outcome': 'insufficient-evidence',
             'deferred_reason': 'Still pending'},
        ):
            result = await rt.registry.execute('workflow', {**args, 'candidate_id': cid}, None, rt.prompter)
            assert result.startswith('error:') and 'in flight' in result
        assert not rt.workflow.validation_results and list(rt.policy.observations._items) == [oid]
    finally:
        release.set()
        if completion == 'completed':
            await pending
        else:
            with pytest.raises(httpx.ReadError if completion == 'failed' else asyncio.CancelledError):
                await pending
    assert fact['status'] == completion
    assert bool(fact['observation_id']) == (completion == 'completed')
    handoff = rt.workflow_tool.validation_handoff(cid, rt.policy)
    assert handoff is not None
    assert handoff['effects']['completed_dispatches'] == (2 if completion == 'completed' else 1)
    assert handoff['effects']['mutation_performed'] is (True if known_write else None)
    require_idle_attempt(attempt, rt.policy)


async def test_effects_reader_still_rejects_corrupt_bookkeeping(offline):
    rt, _ = offline
    cid = await candidate_for(rt)
    started = json.loads(await rt.registry.execute('workflow', {
        'action': 'start_validation', 'candidate_id': cid}, None, rt.prompter))
    attempt = rt.workflow.attempts[started['validation_context']['attempt_id']]
    attempt['effects']['dispatches'].append({'invocation_id': 'fixture', 'request_hash': 'a' * 64,
                                            'status': 'unexpected', 'observation_id': None})
    with pytest.raises(ValueError, match='bookkeeping unavailable'):
        attempt_effects(rt.workflow, attempt, rt.policy.observations)


@pytest.mark.parametrize('basis', [
    'Operator explicitly reported that the supplied test identity is required for this action.',
    'Documentation supplied by the operator requires authentication for this exact POST operation.',
    'Authentication is unknown; clarify whether a test identity is needed before choosing the next action.',
])
async def test_access_clarification_does_not_require_input_provenance(runtime, basis):
    prompter, policy, state, item = dependency(runtime)
    before = deepcopy(state.to_dict())
    grants = deepcopy(policy.engagement.http_permissions.grants)
    operator = Operator()
    tool = AskUserTool(operator)
    args = {'questions': [{'question': 'Which access context, if any, applies to this input?',
        'input_ids': [item.id], 'dependency_kind': 'access', 'dependency_basis': basis}]}
    result = json.loads(await tool.run(args, None, prompter))
    shown = result['answers'][0]['question']
    assert len(operator.questions) == 1
    assert 'unverified' in shown and 'authentication requirements are unknown' in shown
    assert 'Agent-reported' in shown and basis in shown
    assert 'does not grant execution permission' in shown
    assert json.loads(await tool.run(args, None, prompter)) == result
    assert len(operator.questions) == 1
    assert state.to_dict() == before and policy.engagement.http_permissions.grants == grants


@pytest.mark.parametrize('status', [200, 401])
async def test_linked_source_does_not_verify_authentication(tmp_path, status):
    from tests.helpers.burp_selection import make_runtime, ingest
    from src.workflow.state import WorkflowObjective
    rt = make_runtime(tmp_path)
    rt.workflow.objective = WorkflowObjective('access-question', 'whole_target', ORIGIN)
    capture = ingest(rt, path='/private/order', status=status, responseComplete=True,
                     respBody='Public input form' if status == 200 else 'Authentication required for this operation')
    await execute(rt, 'browser_capture_get', {'id': capture['id']})
    source = next(iter(rt.workflow.discovery_sources.values()))
    row = json.loads((await execute(rt, 'workflow', {'action': 'record_input', 'method': 'GET',
        'endpoint': '/private/order', 'parameter': 'lines', 'location': 'query',
        'source_ref': source.retained_ref})).result)['input']
    rt.workflow.set_input_disposition(row['id'], 'blocked', reason='Access context needs operator clarification.')
    item = rt.workflow.attack_surface_inputs[row['id']]
    provenance = input_provenance(rt.workflow, item)
    assert provenance['kind'] == 'request-linked' and provenance['authentication_requirement'] == 'unknown'
    before = deepcopy(rt.workflow.to_dict())
    operator = Operator()
    rt.registry.register(AskUserTool(operator))
    await rt.registry.execute('ask_user', {'questions': [{
        'question': 'Which test identity, if any, should be used?', 'input_ids': [item.id],
        'dependency_kind': 'access', 'dependency_basis': f'Observed HTTP {status}; asking the operator to clarify access.'}]}, None, rt.prompter)
    shown = operator.questions[0].question
    assert 'authentication requirements are unknown' in shown
    assert 'Agent-reported' in shown
    assert rt.workflow.to_dict() == before


@pytest.mark.parametrize('required', [False, True])
@pytest.mark.parametrize('excerpt', [False, True])
async def test_optional_capture_feedback_matches_terminal_admission(runtime, tmp_path, required, excerpt):
    related = [{'role': 'auxiliary', 'method': 'GET', 'url': ORIGIN + '/optional', 'required': required}]
    state, candidate, tool, args, good = await setup(runtime, tmp_path, related=related)
    registry, p, policy, _, sent, *_ = runtime
    await registry.execute('http', {'url': '/optional', 'phase': 'validation', 'max_response_bytes': 3}, None, p)
    bad = next(reversed(policy.observations._items))
    assert policy.observations._items[bad].truncated
    proof = tmp_path / 'optional-proof.md'
    proof.write_text(f'# Proof\n- candidate_id: {candidate.id}\nObservation ID: {good}\n'
                     f'Historical metadata for {bad} is diagnostic only; no body claim.\n')
    registration = {'action': 'record_evidence', 'candidate_id': candidate.id,
                    'evidence_path': 'optional-proof.md', 'observation_ids': [good, bad]}
    receipt = json.loads(await registry.execute('workflow', registration, None, p))
    readiness = receipt['terminal_readiness']
    assert readiness['status'] == ('unusable-primary-sources' if required else 'usable-primary-sources')
    assert readiness['unusable_sources'] == [{'observation_id': bad, 'reasons': ['truncated', 'incomplete']}]
    assert readiness['usable_observation_ids'] == [good]
    assert not receipt['terminal_assessment_accepted']
    if not required:
        assert 'optional' in readiness['next_action'].lower() and 'excerpt' in readiness['next_action'].lower()
        assert 'Rewrite proof' not in readiness['next_action']
    artifact = receipt['evidence']
    original = (tmp_path / artifact['path']).read_bytes()
    if excerpt:
        body = policy.observations._items[bad].body
        args['assessment']['excerpts'] = [{'source_id': bad, 'start': 0, 'end': len(body),
                                         'sha256': hashlib.sha256(body).hexdigest()}]
    submission = {**args, 'evidence_refs': [artifact['id']], 'observation_ids': [good, bad]}
    result = await registry.execute('workflow', submission, None, p)
    if required or excerpt:
        error = json.loads(result.split('\n', 1)[1])['error']
        assert error['code'] == 'UNUSABLE_PRIMARY_SOURCE' and error['offending_observation_ids'] == [bad]
        assert 'metadata' in error['repair_hint'] and 'If' in error['repair_hint']
        assert 'Replace evidence_refs only after registering a corrected snapshot' in error['message']
        assert not state.validation_results and not state.eligible_for_finding(candidate.id)
        assert tool.coverage is not None and not await tool.coverage.list()
        if excerpt and not required:
            # Removing a proposed excerpt changes no registered proof/parents.
            submission['assessment'] = {k: v for k, v in args['assessment'].items() if k != 'excerpts'}
            assert json.loads(await registry.execute('workflow', submission, None, p))['ok']
    else:
        assert json.loads(result)['ok']
    if not required:
        assert accepted_result(state, candidate, state.latest_result(candidate.id), policy)
        restored = WorkflowState.from_dict(json.loads(json.dumps(state.to_dict())))
        assert accepted_result(restored, restored.candidates[candidate.id], restored.latest_result(candidate.id), policy)
    assert (tmp_path / artifact['path']).read_bytes() == original
    assert state.evidence_sources[artifact['id']] == [good, bad] and len(sent) == 2
    # Existing snapshot parents cannot be rebound, even to remove optional metadata.
    conflict = await registry.execute('workflow', {**registration, 'observation_ids': [good]}, None, p)
    assert 'IMMUTABLE_PARENT_CONFLICT' in conflict


@pytest.mark.parametrize('with_primary', [False, True])
async def test_failed_diagnostic_metadata_cannot_replace_usable_primary(runtime, tmp_path, with_primary):
    state, candidate, tool, args, good = await setup(runtime, tmp_path)
    registry, p, policy, _, sent, _, target = runtime
    owner = attempt_owner(state, args['attempt_id'], policy.engagement.http_permissions.epoch,
                          target.revision, policy.session_id)
    bad = policy.observations.capture_output('fixture-diagnostic', 'Controlled failed diagnostic',
                                            owner=owner, completed=False)
    proof = tmp_path / 'diagnostic-proof.md'
    proof.write_text(f'# Proof\n- candidate_id: {candidate.id}\n'
                     f'Diagnostic metadata for {bad}; its output establishes no target behavior.\n')
    ids = [good, bad] if with_primary else [bad]
    receipt = json.loads(await registry.execute('workflow', {'action': 'record_evidence',
        'candidate_id': candidate.id, 'evidence_path': proof.name, 'observation_ids': ids}, None, p))
    readiness = receipt['terminal_readiness']
    assert readiness['status'] == ('usable-primary-sources' if with_primary else 'unusable-primary-sources')
    assert readiness['unusable_sources'] == [{'observation_id': bad, 'reasons': ['incomplete', 'execution unfinished']}]
    assert 'Rewrite proof' not in readiness['next_action']
    result = await registry.execute('workflow', {**args, 'evidence_refs': [receipt['evidence']['id']],
                                               'observation_ids': ids}, None, p)
    if with_primary:
        assert json.loads(result)['ok'] and accepted_result(state, candidate, state.latest_result(candidate.id), policy)
    else:
        assert result.startswith('error:')
        assert not state.validation_results and not state.eligible_for_finding(candidate.id)
        assert tool.coverage is not None and not await tool.coverage.list()
    assert len(sent) == 1
