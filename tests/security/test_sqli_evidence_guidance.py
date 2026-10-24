"""Offline captures with an explicitly unresolved assessment, not a SQL classifier."""
import json
from urllib.parse import urlencode

import httpx
import pytest

from tests.security.test_agent_assessment import setup
from tests.security.test_execution_policy import REAL_CLIENT, runtime  # noqa: F401


@pytest.mark.parametrize('technique', ['error-based', 'bounded-union-based'])
async def test_owned_control_and_non_boolean_proof_use_existing_contracts(runtime, tmp_path, monkeypatch, technique):
    registry, prompter, policy, _, sent, *_ = runtime
    status = 500 if technique == 'error-based' else 200
    media = 'text/plain' if technique == 'error-based' else 'application/json'
    proof_body = b'Controlled expression result: proof-49' if status == 500 else b'{"marker":"proof-49"}'

    def handler(request):
        sent.append(request)
        control = request.url.params['q'] == 'benign-control'
        return httpx.Response(200 if control else status,
            content=b'{"items":["moss"]}' if control else proof_body,
            headers={'Content-Type': 'application/json' if control else media}, request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(
        transport=httpx.MockTransport(handler), **kw))
    # Identical request geometry before admission is planning context, not proof.
    await registry.execute('http', {'url': '/fixture?q=benign-control', 'phase': 'recon'}, None, prompter)
    historical = next(reversed(policy.observations._items))
    state, candidate, _, args, control = await setup(runtime, tmp_path,
        candidate_class='sqli', payload='benign-control')
    assert candidate.baseline_request_ref is None  # a captured control exists, no replay template
    assert policy.observations._items[historical].attempt_id is None
    assert policy.observations._items[control].attempt_id == args['attempt_id']
    ids = [control]
    for _ in range(2):
        # Symbolic request, synthetic evaluated output; no SQL target or query
        # reconstruction. The test authors the interpretation, not the runtime.
        await registry.execute('http', {'url': '/fixture?q=computed-proof', 'phase': 'validation'}, None, prompter)
        ids.append(next(reversed(policy.observations._items)))
    proof = tmp_path / 'bounded-proof.md'
    proof.write_text('Owned benign control and repeated synthetic evaluated marker.\n' + '\n'.join(ids))
    before = len(state.evidence)
    rejected = await registry.execute('workflow', {'action': 'record_evidence', 'candidate_id': candidate.id,
        'evidence_path': proof.name, 'observation_ids': [historical, *ids]}, None, prompter)
    assert 'SOURCE_OWNERSHIP_MISMATCH' in rejected and len(state.evidence) == before
    assert policy.observations._items[historical].attempt_id is None
    evidence = json.loads(await registry.execute('workflow', {'action': 'record_evidence',
        'candidate_id': candidate.id, 'evidence_path': proof.name, 'observation_ids': ids}, None, prompter))['evidence']['id']
    output = json.loads(await registry.execute('workflow', {**args, 'evidence_refs': [evidence],
        'observation_ids': ids, 'techniques': ['SQLI-2', technique], 'repeatable': True,
        'assessment': {**args['assessment'], 'criteria': 'Owned control lacks computed marker; two probes reproduce it.',
                       'observed_impact': 'Controlled synthetic evaluation only; no real rows or impact probe.'}}, None, prompter))
    assert output['ok'] and output['eligible_for_confirm_finding']
    result = state.latest_result(candidate.id)
    assert result is not None and result.confirmation is None and result.repeatable
    assert result.outcome == 'confirmed' and len(set(ids)) == 3  # no Boolean observation-count gate
    assert len(sent) == 4 and all(request.method == 'GET' for request in sent)
    assert not state.persisted_findings  # result admission is separate from finding persistence/Phase 3


async def test_equal_pair_and_syntax_errors_can_be_recorded_unresolved(runtime, tmp_path, monkeypatch):
    empty = b'{"status":"success","data":[]}'
    syntax_error = b'SQLITE_ERROR: incomplete input'
    # Symbolic inputs and synthetic responses; no historical endpoint or payload.
    replies = {
        'intended-true': (200, empty),
        'intended-false': (200, empty),
        **{f'syntax-adjustment-{n}': (500, syntax_error) for n in range(1, 4)},
    }

    def handler(request):
        runtime[4].append(request)
        status, body = replies[request.url.params['q']]
        return httpx.Response(status, content=body, request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(
        transport=httpx.MockTransport(handler), **kw))
    state, candidate, _, args, first = await setup(
        runtime, tmp_path, candidate_class='sqli', payload='intended-true')
    registry, prompter, policy, _, sent, *_ = runtime
    ids = [first]
    for value in list(replies)[1:]:
        await registry.execute('http', {
            'url': '/fixture?' + urlencode({'q': value}), 'phase': 'validation',
        }, None, prompter)
        ids.append(next(reversed(policy.observations._items)))
    observations = [policy.observations._items[oid] for oid in ids]
    assert len(sent) == len(set(ids)) == 5
    assert [(o.status, o.body) for o in observations] == list(replies.values())
    assert all(o.complete and not o.truncated and o.execution_status == 'completed'
               and o.candidate_id == candidate.id and o.attempt_id == args['attempt_id']
               for o in observations)

    proof = tmp_path / 'unresolved.md'
    proof.write_text(
        'Observed facts: identical empty 200 responses; three syntax-only 500 errors.\n'
        'Working hypothesis: surrounding SQL syntax may affect these expressions.\n'
        'Unresolved limitation: no full query or established boolean oracle; '
        'controlled SQL evaluation remains unproved.\n', encoding='utf-8')
    evidence = json.loads(await registry.execute('workflow', {
        'action': 'record_evidence', 'candidate_id': candidate.id,
        'evidence_path': proof.name, 'observation_ids': ids,
    }, None, prompter))['evidence']['id']
    # The evaluator selects this outcome; runtime does not interpret the prose.
    output = json.loads(await registry.execute('workflow', {
        **args, 'outcome': 'insufficient-evidence', 'evidence_refs': [evidence],
        'observation_ids': ids, 'techniques': ['boolean-based'],
        'assessment': {**args['assessment'], 'completed_attempt': False,
                       'limitations': 'Oracle unresolved; syntax sensitivity only.',
                       'observed_impact': 'No controlled SQL evaluation established.'},
        'deferred_reason': 'No useful bounded test remains; oracle not established.',
    }, None, prompter))
    assert output['ok'] and not output['eligible_for_confirm_finding']
    result = state.latest_result(candidate.id)
    assert result is not None and result.outcome == 'insufficient-evidence'
    assert result.evidence_refs == [evidence] and not result.assessment['completed_attempt']
    assert not state.eligible_for_finding(candidate.id)
    assert candidate.status == 'deferred' and len(sent) == 5
