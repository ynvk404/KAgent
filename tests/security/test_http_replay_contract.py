"""Offline replay argument repair and native recovery correlation; no live I/O."""
import copy
import gzip
import json

import httpx
import pytest

from src.agent.events import DoneEvent
from src.agent.agent import AgentRunOptions
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.llm.providers.openai import OpenAIClient
from src.ui.core.state import AgentEventAction
from src.workflow.state import AttackSurfaceInput, Candidate, WorkflowObjective
from tests.agent.test_native_recovery_receipts import attach, invoke
from tests.agent.test_workflow_request_preparation import SnapshotClient
from tests.helpers.agent_fakes import FakeSignal
from tests.helpers.burp_selection import ORIGIN, make_runtime
from tests.helpers.workflow import prepare_validation_prerequisites

REAL_CLIENT = httpx.AsyncClient


@pytest.fixture(params=['direct', 'whole_target'])
async def replay_contract(tmp_path, monkeypatch, request):
    rt = make_runtime(tmp_path)
    app = attach(rt)
    rt.workflow.objective = WorkflowObjective('replay-contract', request.param, ORIGIN)
    capture = rt.capture.ingest({
        'kind': 'burp', 'id': 'login-fixture', 'method': 'POST', 'url': ORIGIN + '/login',
        'requestHeaders': [
            {'name': 'Content-Type', 'value': 'application/json'},
            {'name': 'Accept-Encoding', 'value': 'gzip'},
            {'name': 'User-Agent', 'value': 'CapturedFixture/1'},
            {'name': 'Cookie', 'value': 'sid=fixture-secret'},
        ],
        'requestBody': '{"email":"benign","password":"fixture-secret"}',
    })
    candidate, _ = rt.workflow.add_candidate(Candidate(
        candidate_class='sqli', target=ORIGIN, method='POST', endpoint='/login',
        parameter='email', location='json', content_type='application/json',
        baseline_request_ref=capture['baseline_request_ref'], source_ref=capture['id'],
        objective_id=rt.workflow.objective.id,
    ))
    if request.param == 'whole_target':
        rt.workflow.add_attack_surface_input(AttackSurfaceInput(
            objective_id=rt.workflow.objective.id, target_origin=ORIGIN,
            method='POST', endpoint='/login', parameter='email', location='json',
            content_type='application/json', candidate_ids=[candidate.id],
            baseline_request_ref=candidate.baseline_request_ref, source_ref=candidate.source_ref,
        ))
    sent = []

    def transport(outbound):
        sent.append(outbound)
        return httpx.Response(500, content=gzip.compress(b'Offline database diagnostic'),
                              headers={'Content-Encoding': 'gzip'}, request=outbound)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(
        transport=httpx.MockTransport(transport), **kw))
    args = {'phase': 'validation', 'candidate_id': candidate.id,
            'mutation_value': "'", 'input_path': '/email'}
    rt.agent.active_skills.add('sql-injection')
    await prepare_validation_prerequisites(rt.workflow_tool, candidate.id)
    started, _ = await invoke(app, 'start', 'workflow', {
        'action': 'start_validation', 'candidate_id': candidate.id})
    assert started.status == 'success' and json.loads(started.result)['ok'], started.result
    return rt, app, args, sent


@pytest.mark.parametrize('replacement', [
    {'headers': {'Accept-Encoding': 'identity', 'Cookie': 'sid=do-not-echo'}},
    {'headers': {}}, {'url': ORIGIN + '/login'}, {'method': 'POST'},
    {'body': '{"email":"replacement","password":"do-not-echo"}'},
])
async def test_replay_rejects_replacements_before_review_and_explains_repair(replay_contract, replacement):
    rt, app, args, sent = replay_contract
    before = copy.deepcopy(rt.workflow.to_dict())
    budget_before = rt.policy.used
    failed, event = await invoke(app, 'invalid', 'http', args | replacement)
    assert failed.status == 'error' and failed.error_kind == 'invalid_args'
    assert event.recovery_receipt is None and not sent and not rt.http.dispatch_attempts
    assert not rt.operator.requests and not rt.policy.observations._items
    assert rt.workflow.to_dict() == before
    assert rt.policy.used == budget_before
    assert not rt.http.permissions._receipts and not rt.http.permissions._inflight
    assert 'captured replay does not accept replacement url/method/headers/body' in failed.result
    assert 'mutation_value' in failed.result and 'Accept-Encoding' in failed.result
    assert 'recapture' in failed.result.lower() and 'do not drop candidate_id' in failed.result.lower()
    assert 'do-not-echo' not in failed.result
    assert not rt.client.requests


async def test_published_schema_explains_modes_and_header_repair(replay_contract):
    rt, _, _, _ = replay_contract
    spec = next(t['function'] for t in rt.registry.as_llm_tools() if t['function']['name'] == 'http')
    fields = spec['parameters']['properties']
    assert 'Direct' in fields['headers']['description']
    assert 'candidate_id' in fields['headers']['description']
    assert 'Accept-Encoding' in fields['headers']['description']
    assert 'recapture' in spec['description'].lower()
    assert 'do not drop candidate_id' in spec['description'].lower()


async def test_first_http_decision_and_repair_receive_projected_contract(replay_contract):
    rt, _, args, sent = replay_contract

    def call(identifier, name, fields):
        return ChatResponse(Message('assistant', '', tool_calls=[
            ToolCall(identifier, FunctionCall(name, json.dumps(fields)))]), 'tool_calls')

    client = SnapshotClient([
        call('load', 'load_skill', {'name': 'sql-injection'}),
        call('invalid', 'http', args | {'headers': {'Accept-Encoding': 'identity'}}),
        call('corrected', 'http', args),
        *[ChatResponse(Message('assistant', 'Fixture diagnostic retained; validation incomplete.'), 'stop')
          for _ in range(3)],
    ])
    rt.agent.client = client
    if rt.workflow.objective.mode == 'direct':
        rt.agent.select_burp_captures(rt.workflow.candidates[args['candidate_id']].source_ref)
    events = []
    await rt.agent.run('Continue the current validation.', FakeSignal(), events.append,
                       AgentRunOptions(max_steps=4))
    assert len(client.requests) >= 3
    # This is the actual admitted request before the first HTTP output, not just schema source.
    first = client.requests[1]
    loaded = next(m for m in first.messages if m.role == 'tool' and m.name == 'load_skill')
    assert loaded.skill_activation and 'Do not drop `candidate_id`' in loaded.content
    encoder = OpenAIClient('https://provider.invalid', model='offline-fixture', provider_name='deepseek')
    for index in (1, 2):
        for stream in (False, True):
            body = encoder.encode_request(client.requests[index], stream)
            spec = next(t['function'] for t in body['tools'] if t['function']['name'] == 'http')
            assert spec['parameters'] == rt.http.schema()
            assert 'strict' not in spec and 'Accept-Encoding' in spec['description']
            guides = [m['content'] for m in body['messages'] if m['role'] == 'system'
                      and m['content'].startswith('Current captured HTTP request contract')]
            assert len(guides) == 1, [m['content'] for m in body['messages']
                                    if m['content'].startswith('Untrusted current validation context')]
            guidance = guides[0]
            assert args['candidate_id'] in guidance and 'Omit url/method/headers/body' in guidance
            assert 'Do not drop candidate_id' in guidance
            templates = json.loads(guidance.split('templates: ', 1)[1].split('. Add ', 1)[0])
            assert templates == [{'phase': 'validation', 'candidate_id': args['candidate_id']}]
            rt.http.validate_args(templates[0])
    rejected = next(m for m in client.requests[2].messages if m.role == 'tool' and m.tool_status == 'error')
    assert 'recapture' in rejected.content and 'do not drop candidate_id' in rejected.content
    results = [e for e in events if e.type == 'tool-result' and e.name == 'http']
    assert [e.status for e in results] == ['error', 'observation']
    assert len(sent) == 1 and sent[0].headers['Cookie'] == 'sid=fixture-secret'
    assert not rt.workflow.persisted_findings
    assert all(result.outcome == 'insufficient-evidence' for result in rt.workflow.validation_results)
    assert events[-1].type == 'done' and events[-1].stop_reason != 'runtime_error'
    assert not rt.client.requests  # SnapshotClient above is the only scripted model.


async def test_stale_capture_does_not_advertise_a_replay_recipe_or_change_state(replay_contract):
    rt, _, args, sent = replay_contract
    rt.capture.clear()
    before = copy.deepcopy(rt.workflow.to_dict())
    grants, used = list(rt.http.permissions.grants), rt.policy.used
    view = rt.agent._workflow_request_view('Continue', rt.agent.tools.as_llm_tools())
    assert not any(m.content.startswith('Current captured HTTP request contract') for m in view.blocks)
    assert rt.workflow.to_dict() == before
    assert list(rt.http.permissions.grants) == grants and rt.policy.used == used and not sent
    assert not rt.client.requests


async def test_valid_repair_preserves_capture_and_reads_retained_body_without_resending(replay_contract):
    rt, app, args, sent = replay_contract
    failed, _ = await invoke(app, 'invalid', 'http', args | {'headers': {'Accept-Encoding': 'identity'}})
    assert failed.status == 'error'
    action, expected = rt.http.prepare(args)
    success, event = await invoke(app, 'corrected', 'http', args)
    assert success.status == 'observation' and event.http_status == 500
    assert event.recovery_receipt and event.recovery_receipt.completed
    assert len(sent) == rt.http.dispatch_attempts == 1
    assert sent[0].method == action.method == expected.method
    assert str(sent[0].url) == action.url == str(expected.url)
    assert tuple(sent[0].headers.raw) == action.headers == tuple(expected.headers.raw)
    assert sent[0].content == action.body == expected.content
    assert sent[0].headers['Accept-Encoding'] == 'gzip'
    assert sent[0].headers['User-Agent'] == 'CapturedFixture/1'
    assert sent[0].headers['Cookie'] == 'sid=fixture-secret'
    assert json.loads(sent[0].content) == {'email': "'", 'password': 'fixture-secret'}
    assert [q.tool for q in rt.operator.requests] == ['http_capture_credentials']
    observation = next(iter(rt.policy.observations._items.values()))
    assert observation.complete and not observation.truncated and observation.status == 500
    assert observation.body == b'Offline database diagnostic'
    assert observation.source_details['baseline_request_ref'] == action.capture_source.baseline_ref
    read, _ = await invoke(app, 'read', 'read_http_observation', {
        'observation_id': observation.id, 'start_char': 0, 'max_chars': 1000})
    assert read.status == 'success' and 'Offline database diagnostic' in read.result
    assert len(sent) == 1 and not rt.workflow.validation_results and not rt.workflow.persisted_findings
    assert not app.state.issues[0].recovered  # Changed args are not an equivalent native retry.
    assert not rt.client.requests


async def test_direct_followup_is_a_distinct_request_and_keeps_original_issue(replay_contract):
    rt, app, args, sent = replay_contract
    failed, _ = await invoke(app, 'invalid', 'http', args | {'headers': {'Accept-Encoding': 'identity'}})
    assert failed.status == 'error'
    direct = {'phase': 'validation', 'method': 'POST', 'url': ORIGIN + '/login',
              'headers': {'Accept-Encoding': 'identity', 'Content-Type': 'application/json'},
              'body': '{"email":"\'","password":"fixture-secret"}'}
    success, event = await invoke(app, 'direct', 'http', direct)
    assert success.status == 'observation' and event.recovery_receipt.completed
    assert len(sent) == 1 and 'cookie' not in sent[0].headers
    assert sent[0].headers['User-Agent'] != 'CapturedFixture/1'
    observation = next(iter(rt.policy.observations._items.values()))
    assert 'baseline_request_ref' not in observation.source_details
    assert not app.state.issues[0].recovered and not app.state.call_history[-1].retry_of
    app.dispatch(AgentEventAction(DoneEvent(stop_reason='final_response')))
    assert '1 unresolved operation issue' in app.state.transcript[-1].text
    assert not rt.client.requests


@pytest.mark.parametrize('variant', ['exact', 'payload', 'capture', 'headers', 'missing-receipt'])
async def test_captured_network_retry_requires_same_args_capture_and_native_receipt(
        replay_contract, monkeypatch, variant):
    rt, app, args, sent = replay_contract

    def transport(outbound):
        sent.append(outbound)
        if len(sent) == 1:
            raise httpx.ConnectError('offline connection failure', request=outbound)
        return httpx.Response(200, content=b'fixture', request=outbound)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(
        transport=httpx.MockTransport(transport), **kw))
    failed, failure = await invoke(app, 'network', 'http', args)
    assert failed.status == 'error' and failure.error_kind == 'network'
    assert failure.recovery_receipt and failure.recovery_receipt.retry_safe
    corrected = dict(args)
    if variant == 'payload':
        corrected['mutation_value'] = 'different'
    elif variant in {'capture', 'headers'}:
        candidate = rt.workflow.candidates[args['candidate_id']]
        row = rt.capture.resolve_baseline(candidate.baseline_request_ref)
        assert row is not None
        # Simulate binding drift to exercise receipt checks; this is not a
        # workflow API for changing immutable active-attempt declarations.
        headers = [{'name': h.name, 'value': h.value} for h in row.request_headers]
        if variant == 'headers':
            headers.append({'name': 'X-Fixture', 'value': 'changed'})
        captured = rt.capture.ingest({
            'kind': 'burp', 'id': row.id if variant == 'headers' else 'different-capture',
            'method': row.method, 'url': row.url,
            'requestHeaders': headers, 'requestBody': row.request_body,
        })
        candidate.baseline_request_ref = captured['baseline_request_ref']
        candidate.source_ref = captured['id']
        for item in rt.workflow.attack_surface_inputs.values():
            item.baseline_request_ref = candidate.baseline_request_ref
            item.source_ref = candidate.source_ref
    elif variant == 'missing-receipt':
        result_event = rt.agent._tool_result_event

        def without_receipt(*args, **kwargs):
            return {**result_event(*args, **kwargs), 'recovery_receipt': None}

        monkeypatch.setattr(rt.agent, '_tool_result_event', without_receipt)
    success, event = await invoke(app, 'retry', 'http', corrected)
    assert success.status == 'observation' and len(sent) == 2
    assert app.state.issues[0].recovered == (variant == 'exact')
    if variant == 'exact':
        assert event.recovery_receipt and event.recovery_receipt.completed
        assert app.state.issues[0].recovered_by == event.invocation.id
        assert failure.recovery_receipt.resource == event.recovery_receipt.resource
    assert not rt.client.requests
