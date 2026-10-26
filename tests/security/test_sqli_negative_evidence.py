"""Offline admission contracts; SQL oracle interpretation belongs to the Agent."""
from copy import deepcopy
from dataclasses import replace
import json
from typing import Any

import httpx
import pytest

from src.workflow.assessment import accepted_result, digest, source_row
from src.workflow.state import WorkflowState
from tests.security.test_agent_assessment import setup
from tests.security.test_execution_policy import REAL_CLIENT, runtime  # noqa: F401


def error(output):
    assert output.startswith('error:')
    return json.loads(output.split('\n', 1)[1])['error']


async def proof(runtime, tmp_path, candidate, ids):
    registry, p, *_ = runtime
    (tmp_path / 'comparison.md').write_text('Bounded comparison.\nobservation_ids: ' + ', '.join(ids))
    result = await registry.execute('workflow', {'action': 'record_evidence',
        'candidate_id': candidate.id, 'evidence_path': 'comparison.md', 'observation_ids': ids}, None, p)
    return json.loads(result)['evidence']['id']


async def test_reviews_baseline_admission_retains_request_identity_without_comparison_gate(runtime, tmp_path, monkeypatch):
    registry, p, policy, _, sent, *_ = runtime
    endpoint = '/items/1/reviews'

    def handler(request):
        sent.append(request)
        body = b'{"reviews":["a","b"]}' if request.url.path == endpoint else b'{"reviews":[]}'
        return httpx.Response(200, content=body, request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler), **kw))
    state, candidate, tool, args, baseline = await setup(runtime, tmp_path,
        candidate_class='sqli', endpoint=endpoint, location='path')
    attempt = state.attempts[args['attempt_id']]
    declaration = deepcopy(attempt['related_requests'])
    for value in ("1'", '1 OR 1=1', '1abc'):
        await registry.execute('http', {'url': '/items/' + value + '/reviews', 'phase': 'validation'}, None, p)
        oid = next(reversed(policy.observations._items))
        assert policy.observations._items[oid].attempt_id == attempt['id']
        # Owned traffic still needs a matching immutable request association.
        rejected = await registry.execute('workflow', {'action': 'record_evidence',
            'candidate_id': candidate.id, 'evidence_path': 'proof.md',
            'observation_ids': [baseline, oid]}, None, p)
        assert error(rejected)['code'] == 'SOURCE_REQUEST_MISMATCH'
    changed = await registry.execute('workflow', {'action': 'start_validation',
        'candidate_id': candidate.id, 'related_requests': [
            {'role': 'trigger', 'method': 'GET', 'url': '/items/1abc/reviews'}]}, None, p)
    assert 'active attempt declaration changed' in changed
    assert attempt['related_requests'] == declaration
    ref = await proof(runtime, tmp_path, candidate, [baseline])
    snapshot = (tmp_path / state.evidence[ref].path).read_bytes()
    # Deliberately unsupported oracle interpretation: admission checks the
    # existing declaration/source contract, not the truth of the Agent's SQL
    # reasoning. Removing the gate allows this case; it does not make it sound.
    submitted = json.loads(await registry.execute('workflow', {**args,
        'outcome': 'not-confirmed', 'evidence_refs': [ref]}, None, p))
    assert submitted['ok'] and submitted['coverage_status'] == 'passed'
    assert attempt['status'] == 'completed' and candidate.status == 'validated'
    latest = state.latest_result(candidate.id)
    assert latest is not None and latest.outcome == 'not-confirmed'
    assert [row['source']['id'] for row in latest.evidence_manifest] == [baseline]
    assert accepted_result(state, candidate, latest, policy)
    assert tool.coverage is not None and len(await tool.coverage.list()) == 1
    assert not state.eligible_for_finding(candidate.id) and not state.persisted_findings
    assert len(sent) == 4
    assert (tmp_path / state.evidence[ref].path).read_bytes() == snapshot


@pytest.mark.parametrize('support', ['same-request', 'different-cap', 'outside-proof', 'auxiliary', 'only-controls'])
async def test_sql_negative_admission_does_not_require_distinct_comparison_requests(runtime, tmp_path, support):
    related = [{'role': 'auxiliary', 'method': 'GET', 'url': '/diagnostic', 'required': False}] if support == 'auxiliary' else []
    if support == 'only-controls':
        related = [{'role': role, 'method': 'GET', 'url': '/fixture?q=' + value}
                   for role, value in [('baseline', 'fixture'), ('control', 'control')]]
    state, candidate, tool, args, baseline = await setup(runtime, tmp_path, candidate_class='sqli', related=related)
    registry, p, policy, *_ = runtime
    request: dict[str, Any] = {'url': '/fixture?q=fixture', 'phase': 'validation'}
    if support in {'outside-proof', 'only-controls'}:
        request['url'] = '/fixture?q=control'
    if support == 'different-cap':
        request['max_response_bytes'] = 1024
    if support == 'auxiliary':
        request['url'] = '/diagnostic'
    await registry.execute('http', request, None, p)
    second = next(reversed(policy.observations._items))
    parents = [baseline] if support == 'outside-proof' else [baseline, second]
    ref = await proof(runtime, tmp_path, candidate, parents)
    output = json.loads(await registry.execute('workflow', {**args, 'outcome': 'not-confirmed',
        'observation_ids': [baseline, second], 'evidence_refs': [ref]}, None, p))
    assert output['ok'] and output['coverage_status'] == 'passed'
    latest = state.latest_result(candidate.id)
    assert latest is not None and latest.outcome == 'not-confirmed'
    assert accepted_result(state, candidate, latest, policy)
    assert tool.coverage is not None and len(await tool.coverage.list()) == 1


@pytest.mark.parametrize('fault,code', [
    ('truncated', 'UNUSABLE_PRIMARY_SOURCE'),
    ('ownership', 'SOURCE_OWNERSHIP_MISMATCH'),
    ('identity', 'SOURCE_REQUEST_MISMATCH'),
    ('origin', 'SOURCE_ORIGIN_MISMATCH'),
    ('integrity', 'SOURCE_INTEGRITY_MISMATCH'),
    ('parents', 'DERIVED_PARENT_MISMATCH'),
    ('snapshot', 'EVIDENCE_ARTIFACT_UNAVAILABLE'),
])
async def test_sql_negative_retains_shared_evidence_invariants(runtime, tmp_path, fault, code):
    state, candidate, tool, args, baseline = await setup(runtime, tmp_path, candidate_class='sqli')
    registry, p, policy, *_ = runtime
    request: dict[str, Any] = {'url': '/fixture?q=control', 'phase': 'validation'}
    if fault == 'truncated':
        request['max_response_bytes'] = 1
    await registry.execute('http', request, None, p)
    second = next(reversed(policy.observations._items))
    ids = [baseline, second]
    ref = await proof(runtime, tmp_path, candidate, ids)
    if fault in {'ownership', 'identity', 'origin', 'integrity'}:
        assert candidate.target is not None
        changes = {'ownership': {'attempt_id': 'foreign-attempt'},
                   'identity': {'url': candidate.target + '/undeclared'},
                   'origin': {'url': 'http://outside.test/fixture'},
                   'integrity': {'body': b'substituted'}}[fault]
        item = replace(policy.observations._items[second], **changes)
        if fault != 'integrity':
            item = replace(item, retained_hash=digest(source_row(item)))
        policy.observations._items[second] = item
    elif fault == 'parents':
        ids = [baseline]
    elif fault == 'snapshot':
        snapshot = tmp_path / state.evidence[ref].path
        snapshot.chmod(0o600)
        snapshot.write_text('Changed proof snapshot.')
    rejected = await registry.execute('workflow', {**args, 'outcome': 'not-confirmed',
        'observation_ids': ids, 'evidence_refs': [ref]}, None, p)
    assert error(rejected)['code'] == code
    assert tool.coverage is not None
    assert not state.validation_results and not await tool.coverage.list()
    assert state.attempts[args['attempt_id']]['status'] == 'active'
    assert not state.eligible_for_finding(candidate.id)


@pytest.mark.parametrize('decision', ['retry', 'decline'])
async def test_sql_insufficient_evidence_remains_unresolved_with_retry_disposition(runtime, tmp_path, decision):
    state, candidate, tool, args, baseline = await setup(runtime, tmp_path, candidate_class='sqli')
    registry, p, *_ = runtime
    ref = await proof(runtime, tmp_path, candidate, [baseline])
    submitted = json.loads(await registry.execute('workflow', {**args,
        'outcome': 'insufficient-evidence', 'evidence_refs': [ref],
        'assessment': {**args['assessment'], 'completed_attempt': False, 'oracle_status': 'inconclusive'},
        'deferred_reason': 'Oracle remains unresolved.',
        'retry_decision': {'decision': decision, 'reason': 'Reassessed the bounded fixture evidence.'}}, None, p))
    assert submitted['ok'] and submitted['retry_decision']['decision'] == decision
    latest = state.latest_result(candidate.id)
    assert latest is not None and latest.outcome == 'insufficient-evidence'
    assert candidate.status == 'deferred' and state.attempts[args['attempt_id']]['status'] == 'unresolved'
    assert tool.coverage is not None and not await tool.coverage.list()
    assert not state.eligible_for_finding(candidate.id)


@pytest.mark.parametrize('technique,repetitions', [
    ('boolean-based', 1), ('error-based', 1), ('bounded-union-based', 2), ('time-based', 3)])
async def test_supported_negative_comparisons_remain_accepted_and_resumable(runtime, tmp_path, technique, repetitions):
    state, candidate, tool, args, baseline = await setup(runtime, tmp_path, candidate_class='sqli', method='POST')
    registry, p, policy, _, sent, *_ = runtime
    ids = [baseline]
    for _ in range(repetitions):
        await registry.execute('http', {'url': '/fixture', 'method': 'POST', 'body': 'q=controlled-test',
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'}, 'phase': 'validation'}, None, p)
        ids.append(next(reversed(policy.observations._items)))
    # A negative needs no SQL signal or differing response, and no Boolean pair
    # schema. Technique applicability is a synthetic Agent assessment here.
    assert len({policy.observations._items[oid].body for oid in ids}) == 1
    ref = await proof(runtime, tmp_path, candidate, ids)
    submission = {**args, 'outcome': 'not-confirmed', 'observation_ids': ids,
        'evidence_refs': [ref], 'techniques': [technique],
        'assessment': {**args['assessment'], 'oracle_basis':
            f'Controlled offline {technique} fixture defines the comparison; no live SQL semantics asserted.'}}
    result = json.loads(await registry.execute('workflow', submission, None, p))
    assert result['ok'] and result['coverage_status'] == 'passed'
    assert tool.coverage is not None and len(await tool.coverage.list()) == 1
    latest = state.latest_result(candidate.id)
    assert latest is not None and accepted_result(state, candidate, latest, policy)
    assert not state.eligible_for_finding(candidate.id) and not state.persisted_findings
    before = deepcopy(state.to_dict())
    retry = json.loads(await registry.execute('workflow', submission, None, p))
    assert retry['ok'] and not retry['created'] and state.to_dict() == before
    restored = WorkflowState.from_dict(json.loads(json.dumps(before)))
    assert accepted_result(restored, restored.candidates[candidate.id], restored.latest_result(candidate.id), policy)
    assert len(sent) == repetitions + 1


async def test_predeclared_path_comparison_supports_negative_without_rebinding(runtime, tmp_path):
    endpoint, variant = '/items/1/reviews', '/items/1abc/reviews'
    state, candidate, _, args, baseline = await setup(runtime, tmp_path,
        candidate_class='sqli', endpoint=endpoint, location='path',
        related=[{'role': 'trigger', 'method': 'GET', 'url': variant}])
    registry, p, policy, *_ = runtime
    await registry.execute('http', {'url': variant, 'phase': 'validation'}, None, p)
    ids = [baseline, next(reversed(policy.observations._items))]
    ref = await proof(runtime, tmp_path, candidate, ids)
    output = json.loads(await registry.execute('workflow', {**args, 'outcome': 'not-confirmed',
        'observation_ids': ids, 'evidence_refs': [ref]}, None, p))
    assert output['ok'] and output['coverage_status'] == 'passed'
    latest = state.latest_result(candidate.id)
    assert latest is not None and latest.evidence_manifest[-1]['source']['role'] == 'trigger'


async def test_owned_imported_control_and_test_can_support_negative(runtime, tmp_path):
    from src.browser.store import CaptureStore
    from src.tools.common.browser_capture import BrowserCaptureGetTool
    state, candidate, _, args, _ = await setup(runtime, tmp_path, candidate_class='sqli', method='POST')
    registry, p, policy, *_ = runtime
    captures = CaptureStore()
    registry.register(BrowserCaptureGetTool(captures))
    ids = []
    assert candidate.target is not None
    for value in ('control', 'test'):
        capture = captures.ingest({'id': value, 'kind': 'burp', 'url': candidate.target + '/fixture',
            'method': 'POST', 'reqBody': 'q=' + value, 'status': 200,
            'respBody': 'Same controlled fixture response', 'responseComplete': True})
        imported = json.loads(await registry.execute('browser_capture_get', {'id': capture['id']}, None, p))
        ids.append(imported['runtime_observation_id'])
    assert len({policy.observations._items[oid].request_hash for oid in ids}) == 2
    ref = await proof(runtime, tmp_path, candidate, ids)
    output = json.loads(await registry.execute('workflow', {**args, 'outcome': 'not-confirmed',
        'observation_ids': ids, 'evidence_refs': [ref]}, None, p))
    assert output['ok'] and output['coverage_status'] == 'passed'
    latest = state.latest_result(candidate.id)
    assert latest is not None and accepted_result(state, candidate, latest, policy)
    assert all(entry['source']['source_kind'] == 'imported-capture' for entry in latest.evidence_manifest)
