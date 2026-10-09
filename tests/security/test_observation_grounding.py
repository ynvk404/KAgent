"""Synthetic native dispatch and evidence admission, without model/target calls."""
from dataclasses import replace
import hashlib
import json

import httpx
import pytest

from src.permission.runtime.observations import ObservationStore
from src.workflow.assessment import accepted_result, digest, source_row
from tests.security.test_agent_assessment import setup
from tests.security.test_execution_policy import runtime, REAL_CLIENT


def envelope(output):
    line = next(line for line in output.splitlines()
                if line.startswith('Runtime HTTP evidence '))
    return json.loads(line.split(': ', 1)[1])


@pytest.mark.asyncio
async def test_effective_requests_statuses_and_roles_stay_with_their_sources(runtime, tmp_path, monkeypatch):
    def respond(req):
        role = req.url.params['q']
        status, body = {'fixture': (201, b'Write accepted; persistence unverified'),
                        'control': (422, b'Expression type mismatch'),
                        'probe': (500, b'Quoted string syntax error')}[role]
        runtime[4].append(req)
        return httpx.Response(status, content=body, headers={'Content-Type': 'text/html'}, request=req)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(
        transport=httpx.MockTransport(respond), **kw))
    state, candidate, _, args, baseline = await setup(runtime, tmp_path, candidate_class='sqli', related=[
        {'role': 'baseline', 'method': 'GET', 'url': '/fixture?q=fixture'},
        {'role': 'control', 'method': 'GET', 'url': '/fixture?q=control'},
    ])
    registry, p, policy, operator, sent, *_ = runtime
    ids = [baseline]
    for value, status, body in [('control', 422, b'Expression type mismatch'),
                                ('probe', 500, b'Quoted string syntax error')]:
        output = await registry.execute('http', {'url': '/fixture?q=' + value, 'phase': 'validation'}, None, p)
        receipt = envelope(output)
        oid = receipt['observation_id']
        item = policy.observations._items[oid]
        assert receipt['status'] == output.http_status == item.status == status
        assert item.body == body
        response_text = output.split('\n\n', 1)[1] if output.startswith('note: private/internal host') else output
        assert response_text.startswith('HTTP/1.1 ' + str(status))
        assert '[End HTTP response; following text is request metadata]' in output
        assert receipt['complete'] and not receipt['truncated']
        assert receipt['execution_status'] == 'completed'
        assert receipt['retained_body_bytes'] == len(body)
        preview = output.split('Effective request preview (redacted):\n', 1)[1].split(
            '\nEnd effective request preview\n', 1)[0]
        assert f'GET {item.url}' in preview
        assert item.source_details == {'request_preview_hex': preview.encode().hex(), **{key: receipt[key] for key in (
            'request_preview_complete', 'request_body_bytes')}}
        ids.append(oid)
    args.update(outcome='insufficient-evidence', observation_ids=ids, mutation_performed=True,
                cleanup_state='pending', repeatable=False)
    assert json.loads(await registry.execute('workflow', args, None, p))['ok']
    result = state.latest_result(candidate.id)
    assert result is not None and result.mutation_performed and result.cleanup_state == 'pending'
    assert [(row['source']['role'], row['source']['status']) for row in result.evidence_manifest] == [
        ('baseline', 201), ('control', 422), ('probe', 500)]
    assert [row['source']['id'] for row in result.evidence_manifest] == ids
    assert not state.eligible_for_finding(candidate.id)
    assert len(sent) == 3 and not operator.requests


@pytest.mark.asyncio
@pytest.mark.parametrize('cap,mode,complete', [(0, 'metadata-only', False), (3, 'body', False), (32, 'body', True)])
async def test_capture_flags_match_presented_and_persisted_observation(runtime, tmp_path, cap, mode, complete):
    await setup(runtime, tmp_path)
    registry, p, policy, *_ = runtime
    output = await registry.execute('http', {'url': '/fixture?q=flags', 'phase': 'validation',
        'max_response_bytes': cap, 'evidence_mode': mode}, None, p)
    receipt = envelope(output)
    item = policy.observations._items[receipt['observation_id']]
    assert receipt['complete'] is item.complete is complete
    assert receipt['truncated'] is item.truncated is (not complete)
    assert receipt['response_cap'] == cap
    assert receipt['retained_body_bytes'] == len(item.body)
    policy.observations.attach_storage(tmp_path / 'observations.json')
    policy.observations.persist()
    restored = ObservationStore()
    restored.attach_storage(tmp_path / 'observations.json')
    assert restored._items[item.id] == item
    assert digest(source_row(item)) == item.retained_hash


@pytest.mark.asyncio
async def test_independent_repeats_have_distinct_ids_and_large_request_is_explicitly_partial(runtime, tmp_path):
    await setup(runtime, tmp_path)
    registry, p, policy, *_ = runtime
    receipts = [envelope(await registry.execute('http', {'url': '/fixture', 'phase': 'validation',
        'method': 'POST', 'body': 'q=' + 'x' * 5000}, None, p)) for _ in range(2)]
    items = [policy.observations._items[row['observation_id']] for row in receipts]
    assert items[0].id != items[1].id and items[0].invocation_id != items[1].invocation_id
    assert items[0].request_hash == items[1].request_hash
    assert all(not row['request_preview_complete'] for row in receipts)
    assert all(row['request_body_bytes'] == 5002 for row in receipts)
    # Distinct captures support counting executions, not SQL semantic repeatability.


@pytest.mark.asyncio
@pytest.mark.parametrize('changes', [{'truncated': True}, {'complete': False}, {'execution_status': 'failed'},
    {'body': b'', 'response_cap': 0, 'complete': False, 'truncated': True}])
async def test_optional_unusable_body_excerpt_cannot_support_terminal_claim(runtime, tmp_path, changes):
    state, candidate, _, args, _ = await setup(runtime, tmp_path, related=[
        {'role': 'auxiliary', 'method': 'GET', 'url': '/fixture?q=optional', 'required': False}])
    registry, p, policy, *_ = runtime
    await registry.execute('http', {'url': '/fixture?q=optional', 'phase': 'validation'}, None, p)
    oid = next(reversed(policy.observations._items))
    item = replace(policy.observations._items[oid], **changes)
    policy.observations._items[oid] = replace(item, retained_hash=digest(source_row(item)))
    args['observation_ids'].append(oid)
    args['assessment']['excerpts'] = [{'source_id': oid, 'start': 0, 'end': len(item.body),
                                      'sha256': hashlib.sha256(item.body).hexdigest()}]
    rejected = await registry.execute('workflow', args, None, p)
    assert rejected.startswith('error: evidence-admissibility:') and oid in rejected
    assert 'record_evidence again' in rejected and 'Replace evidence_refs' in rejected
    assert not state.validation_results
    # Unresolved partial evidence remains honest and available for explanation.
    if not item.body:
        # Metadata-only has no body range, even for an unresolved explanation.
        args['assessment'].pop('excerpts')
    assert json.loads(await registry.execute('workflow', {**args, 'outcome': 'insufficient-evidence'}, None, p))['ok']
    assert not state.eligible_for_finding(candidate.id)


@pytest.mark.asyncio
async def test_optional_metadata_without_body_claim_remains_allowed(runtime, tmp_path):
    state, candidate, _, args, _ = await setup(runtime, tmp_path, related=[
        {'role': 'auxiliary', 'method': 'GET', 'url': '/fixture?q=optional', 'required': False}])
    registry, p, policy, *_ = runtime
    await registry.execute('http', {'url': '/fixture?q=optional', 'phase': 'validation',
        'max_response_bytes': 0, 'evidence_mode': 'metadata-only'}, None, p)
    oid = next(reversed(policy.observations._items))
    args['observation_ids'].append(oid)
    # The full probe supplies the body proof; optional metadata supplies none.
    assert json.loads(await registry.execute('workflow', args, None, p))['ok']
    assert accepted_result(state, candidate, state.latest_result(candidate.id), policy)


@pytest.mark.asyncio
async def test_repair_replaces_immutable_proof_and_parents_without_http(runtime, tmp_path):
    state, candidate, _, args, good = await setup(runtime, tmp_path)
    registry, p, policy, _, sent, *_ = runtime
    await registry.execute('http', {'url': '/fixture?q=partial', 'phase': 'validation',
        'max_response_bytes': 1}, None, p)
    bad = next(reversed(policy.observations._items))
    proof = tmp_path / 'proof.md'
    proof.write_text(f'# Proof\n- candidate_id: {candidate.id}\n- observation_ids: {good}, {bad}\nPartial response claim.\n')
    registration = {'action': 'record_evidence', 'candidate_id': candidate.id,
                    'evidence_path': 'proof.md', 'observation_ids': [good, bad]}
    old = json.loads(await registry.execute('workflow', registration, None, p))['evidence']
    old_bytes = (tmp_path / old['path']).read_bytes()
    args.update(evidence_refs=[old['id']], observation_ids=[good, bad])
    assert (await registry.execute('workflow', args, None, p)).startswith('error: evidence-admissibility:')
    args['observation_ids'] = [good]
    assert 'declared primary source parents' in await registry.execute('workflow', args, None, p)
    # Reparenting the same content-addressed snapshot is forbidden.
    assert 'declared primary parent' in await registry.execute('workflow', {**registration,
        'observation_ids': [good]}, None, p)
    proof.write_text(f'# Proof\n- candidate_id: {candidate.id}\n- observation_ids: {good}\nOnly complete response supports the claim.\n')
    new = json.loads(await registry.execute('workflow', {**registration,
        'observation_ids': [good]}, None, p))['evidence']
    assert new['id'] != old['id'] and state.evidence_sources[new['id']] == [good]
    args['evidence_refs'] = [new['id']]
    assert json.loads(await registry.execute('workflow', args, None, p))['ok']
    result = state.latest_result(candidate.id)
    assert accepted_result(state, candidate, result, policy)
    assert (tmp_path / old['path']).read_bytes() == old_bytes
    assert len(sent) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize('retry', ['same-source', 'stale-parent'])
async def test_agent_closes_exhausted_repair_without_new_probes(runtime, tmp_path, retry):
    from src.agent.agent import Agent, AgentOptions
    from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
    from tests.helpers.agent_fakes import FakeClient, FakeSignal, collect

    state, candidate, workflow, args, good = await setup(runtime, tmp_path)
    registry, p, policy, _, sent, _, target = runtime
    await registry.execute('http', {'url': '/fixture?q=partial', 'phase': 'validation',
        'max_response_bytes': 1}, None, p)
    bad = next(reversed(policy.observations._items))
    (tmp_path / 'proof.md').write_text('Proof derived from complete and partial captures.')
    registration = {'action': 'record_evidence', 'candidate_id': candidate.id,
                    'evidence_path': 'proof.md', 'observation_ids': [good, bad]}
    ref = json.loads(await registry.execute('workflow', registration, None, p))['evidence']['id']
    args.update(evidence_refs=[ref], observation_ids=[good, bad], mutation_performed=True,
                cleanup_state='pending')
    repaired = {**args, 'observation_ids': [good]} if retry == 'stale-parent' else args
    scripted = [ChatResponse(Message('assistant', '', tool_calls=[ToolCall(str(i),
        FunctionCall('workflow', json.dumps(submission)))]), 'tool_calls')
        for i, submission in enumerate([args, repaired])]
    client = FakeClient(scripted)
    assert workflow.skills is not None
    agent = Agent(AgentOptions(client=client, tools=registry, skills=workflow.skills,
        prompter=p, store=None, target=target, workflow=state, engagement_state=policy.engagement,
        max_steps=6, auto_compact_threshold=0))
    agent.active_skills.add('cross-site-scripting')
    events = collect()
    await agent.run('continue', FakeSignal(), events['sink'])
    assert not [event for event in events['events'] if event['type'] == 'error'], [
        message.content for message in agent.history if message.role == 'tool']
    result = state.latest_result(candidate.id)
    assert result is not None and result.outcome == 'insufficient-evidence'
    assert result.mutation_performed and result.cleanup_state == 'pending'
    assert not state.eligible_for_finding(candidate.id)
    assert len(client.requests) == 2 and len(sent) == 2
    assert agent._evidence_recovery_rejections == {} and agent._evidence_recovery == {}
    closures = [message for message in agent.history if message.role == 'tool'
                and (message.tool_call_id or '').startswith('evidence-recovery-')]
    assert len(closures) == 1 and json.loads(closures[0].content)['ok']
