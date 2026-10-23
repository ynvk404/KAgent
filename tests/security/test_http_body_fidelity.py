"""Offline regression coverage for the operator-approved lab storage policy."""
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace
from typing import Any, cast

import pytest

from src.permission.runtime.observations import ObservationStore
from src.workflow.assessment import digest, source_row, check_excerpts
from src.agent.agent import bounded_history_for_compaction, format_history_for_compaction
from src.llm.core.types import Message
from src.session.store import Store
from tests.security.test_execution_policy import runtime, REAL_CLIENT  # noqa: F401
from tests.helpers.agent_fakes import FakeClient, FakeSignal, collect
from src.agent.agent import Agent, AgentOptions, ToolCallResult
from src.llm.core.types import ChatResponse, FunctionCall, ToolCall
from src.tools.common.outcome import ToolOutput
import httpx
from src.skills.registry import Registry as Skills

BODIES = [
    b'{"token":"red"}', b'{"token":"sky"}',
    b'color=blue; Cookie: sid=blue',
    b'public-sha256=' + hashlib.sha256(b'public fixture').hexdigest().encode(),
    b'{"rows":[1],"count":1}', b'{"rows":[],"count":0}',
    b'{"owner":"alice"}', b'{"owner":"bob"}',
    b'<svg onload=alert(7)>REFLECT-7</svg>',
    b'{"csrf_token":"{INJECTION_POINT}-compound","token":"bearer-fixture"}',
    b'{"token":"sk-fixture-abcdefghijklmnopqrstuvwxyz0123456789","password":"AKIA0123456789ABCDEF"}',
    b'<input type="password" value="fixture-password">',
    b'{"token":"broken',
    '{"token":"escaped \\" / Unicode \u2713","q":"%27%20OR%201%3D1--"}'.encode(),
    b'\xff\x00binary decoded response',
]


def body_client(name, args):
    return FakeClient([
        ChatResponse(Message('assistant', '', tool_calls=[ToolCall('fixture-call', FunctionCall(name, json.dumps(args)))]), 'tool_calls'),
        ChatResponse(Message('assistant', 'done'), 'stop'),
    ])


@pytest.mark.parametrize('body', BODIES)
async def test_native_http_to_next_fake_request_and_private_session(runtime, tmp_path, monkeypatch, body):
    registry, prompter, policy, operator, sent, _, target = runtime
    policy.observations.attach_storage(tmp_path / 'observations.json')
    def respond(request):
        sent.append(request)
        return httpx.Response(200, content=body, headers={'Set-Cookie': 'sid=blue; Path=/',
            'Content-Type': 'application/json'}, request=request)
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(respond), **kw))
    client = body_client('http', {'url': '/fixture', 'phase': 'recon', 'headers': {'Cookie': 'sid=blue'}})
    store = Store.new_with_id(tmp_path / 'sessions', 'fidelity')
    agent = Agent(AgentOptions(client=client, tools=registry, skills=Skills(),
        prompter=prompter, target=target, store=store, engagement_state=policy.engagement,
        auto_compact_threshold=0, streaming_enabled=False))
    events = collect()
    await agent.run('Inspect the bounded lab response.', FakeSignal(), events['sink'])
    assert len(sent) == 1 and not operator.requests
    assert len(client.requests) == 2
    message = next(m for m in client.requests[1].messages if m.role == 'tool')
    assert message.http_response_sources
    assert body.decode(errors='replace') in message.content
    observation = policy.observations._items[message.http_response_sources[0]]
    assert observation.body == body
    assert observation.retained_hash == digest(source_row(observation))
    assert body.decode(errors='replace') in store.load().messages[-2].content
    event = next(e for e in events['events'] if e['type'] == 'tool-result')
    assert observation.id in event['result'] and 'Sources:' in event['result']
    assert 'sid=blue' not in message.content.replace(body.decode(errors='replace'), '')
    assert 'sid=blue' not in event['result']
    assert 'bounded-native-decoded-bytes' == observation.source_details['body_representation']


@pytest.mark.parametrize('body', BODIES[:-1])
async def test_scoped_capture_to_next_fake_request_has_exact_aliases(runtime, tmp_path, body):
    from src.browser.store import CaptureStore
    from src.tools.common.browser_capture import BrowserCaptureGetTool
    from src.skills.registry import Registry as Skills
    registry, prompter, policy, _, sent, _, target = runtime
    capture = CaptureStore()
    ref = capture.ingest({'kind': 'burp', 'url': target.base_url() + '/fixture',
        'respBody': body.decode(), 'status': 200, 'responseComplete': True,
        'requestHeaders': {'Cookie': 'sid=blue'}})['id']
    registry.register(BrowserCaptureGetTool(capture))
    client = body_client('browser_capture_get', {'id': ref, 'body_max_chars': 4000})
    agent = Agent(AgentOptions(client=client, tools=registry, skills=Skills(), prompter=prompter,
        target=target, store=Store.new_with_id(tmp_path, 'capture'), engagement_state=policy.engagement,
        auto_compact_threshold=0, streaming_enabled=False))
    await agent.run('Inspect the lab capture.', FakeSignal(), collect()['sink'])
    message = next(m for m in client.requests[1].messages if m.role == 'tool')
    row = json.loads(message.content)
    assert row['response_body'] == row['responseBody'] == body.decode()
    assert not row['response_body_excerpt_truncated']
    assert message.http_response_sources == [row['runtime_observation_id']]
    assert policy.observations._items[row['runtime_observation_id']].body == body
    assert not sent


@pytest.mark.parametrize('change', ['owner', 'origin', 'revoked', 'session', 'tool-spoof'])
async def test_runtime_source_changes_cannot_admit_raw_http(runtime, change):
    from src.skills.registry import Registry as Skills
    from src.permission.runtime.execution import ExecutionBlocked
    registry, prompter, policy, _, _, _, target = runtime
    agent = Agent(AgentOptions(client=FakeClient([]), tools=registry, skills=Skills(), prompter=prompter,
                              target=target, store=None, engagement_state=policy.engagement))
    call = ToolCall('fixture-call', FunctionCall('http', json.dumps({'url': '/fixture', 'phase': 'recon'})))
    parsed = agent.parse_tool_call(call)
    result = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    assert agent._http_analysis_content(call, result) is not None
    assert isinstance(result.result, ToolOutput)
    ref = result.result.http_sources[0][0]
    if change == 'owner':
        policy.observations._items[ref] = replace(policy.observations._items[ref], session_id='wrong-owner')
    elif change == 'origin':
        policy.observations._items[ref] = replace(policy.observations._items[ref], url='https://wrong.test/')
    elif change == 'revoked':
        policy.revoke('http')
    elif change == 'session':
        policy.session_id = 'other-session'
    else:
        call.function.name = 'mcp_http'
    assert agent._http_analysis_content(call, result) is None
    assert result.result.http_sources
    if change == 'revoked':
        with pytest.raises(ExecutionBlocked):
            await registry.execute('http', {'url': '/fixture', 'phase': 'recon'}, None, prompter)


async def test_internal_secret_accessor_failure_withholds_analysis_preserves_execution(runtime):
    registry, prompter, policy, _, sent, _, target = runtime
    agent = Agent(AgentOptions(client=FakeClient([]), tools=registry, skills=Skills(), prompter=prompter,
                              target=target, store=None, engagement_state=policy.engagement))
    call = ToolCall('fixture-call', FunctionCall('http', json.dumps({'url': '/fixture', 'phase': 'recon'})))
    parsed = agent.parse_tool_call(call)
    result = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    def unavailable():
        raise RuntimeError('synthetic-internal-key-not-safe-to-emit')
    policy.internal_secret_values = unavailable
    events, working = [], []
    agent.record_tool_result(call, parsed, result, events.append, working)
    assert result.status == working[0].tool_status == 'observation' and len(sent) == 1
    assert 'withheld' in working[0].content and not working[0].http_response_sources
    assert 'synthetic-internal-key' not in str(events)


async def test_known_actual_internal_secret_omits_outbound_body_without_changing_source(runtime, monkeypatch):
    from src.skills.registry import Registry as Skills
    registry, prompter, policy, _, sent, _, target = runtime
    body = b'{"token":"actual-managed-value","marker":"TRUE-7"}'
    policy.internal_secret_values = lambda: ('actual-managed-value',)
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, content=body, request=req)), **kw))
    client = body_client('http', {'url': '/fixture', 'phase': 'recon'})
    agent = Agent(AgentOptions(client=client, tools=registry, skills=Skills(), prompter=prompter,
                              target=target, store=None, engagement_state=policy.engagement, streaming_enabled=False))
    events = collect()
    await agent.run('Inspect the lab response.', FakeSignal(), events['sink'])
    message = next(m for m in client.requests[1].messages if m.role == 'tool')
    assert 'actual-managed-value' not in message.content
    assert 'body omitted' in message.content and 'not exact' in message.content
    assert next(iter(policy.observations._items.values())).body == body
    assert 'actual-managed-value' not in str(events['events'])




async def test_revoke_before_next_request_withholds_body_without_mutating_original(runtime):
    registry, prompter, policy, _, sent, _, target = runtime
    agent = Agent(AgentOptions(client=FakeClient([]), tools=registry, skills=Skills(), prompter=prompter,
                              target=target, store=None, engagement_state=policy.engagement))
    call = ToolCall('fixture-call', FunctionCall('http', json.dumps({'url': '/fixture', 'phase': 'recon'})))
    parsed = agent.parse_tool_call(call)
    result = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    original = result.result
    working = []
    agent.record_tool_result(call, parsed, result, lambda _: None, working)
    assert working[0].http_response_sources
    before = working[0].content
    policy.revoke('http')
    agent._protect_http_context(working)
    assert 'HTTP analysis omitted' in working[0].content
    assert not working[0].http_response_sources
    assert agent.history[-1].content == before and result.result is original
    assert result.status == 'observation' and len(sent) == 1


async def test_private_context_snapshot_declares_raw_http_content(runtime, tmp_path):
    registry, prompter, policy, _, _, _, target = runtime
    store = Store.new_with_id(tmp_path, 'context')
    agent = Agent(AgentOptions(client=FakeClient([]), tools=registry, skills=Skills(), prompter=prompter,
                              target=target, store=store, engagement_state=policy.engagement))
    call = ToolCall('fixture-call', FunctionCall('http', json.dumps({'url': '/fixture', 'phase': 'recon'})))
    parsed = agent.parse_tool_call(call)
    result = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    agent.record_tool_result(call, parsed, result, lambda _: None, [])
    path = await agent.save_context_snapshot()
    from pathlib import Path
    content = Path(path).read_text()
    assert 'bounded lab HTTP bodies may be raw' in content
    assert agent.history[-1].content in content
    assert Path(path).stat().st_mode & 0o777 == 0o600


async def test_capture_known_internal_secret_omission_is_valid_json_and_source_stays_exact(runtime):
    from src.browser.store import CaptureStore
    from src.tools.common.browser_capture import BrowserCaptureGetTool
    registry, prompter, policy, *_rest, target = runtime
    capture = CaptureStore()
    body = '{"token":"actual-bridge-key","tail":"Unicode \u2713"}'
    ref = capture.ingest({'kind': 'burp', 'url': target.base_url() + '/fixture',
                          'status': 200, 'respBody': body})['id']
    registry.register(BrowserCaptureGetTool(capture))
    policy.internal_secret_values = lambda: ('actual-bridge-key',)
    client = body_client('browser_capture_get', {'id': ref})
    agent = Agent(AgentOptions(client=client, tools=registry, skills=Skills(), prompter=prompter,
        target=target, store=None, engagement_state=policy.engagement, streaming_enabled=False))
    await agent.run('Inspect the lab capture.', FakeSignal(), collect()['sink'])
    content = next(m.content for m in client.requests[1].messages if m.role == 'tool')
    row = json.loads(content)
    assert 'actual-bridge-key' not in content and row['analysis_body_exact'] is False
    assert row['response_body'] == row['responseBody'] == '[HTTP body omitted: known internal secret]'
    assert policy.observations._items[row['runtime_observation_id']].body == body.encode()


@pytest.mark.parametrize('cap', [0, 1, 10, 65536])
async def test_native_truncation_bound_and_metadata_mode_stay_truthful(runtime, monkeypatch, cap):
    registry, prompter, policy, _, _, _, target = runtime
    body = b'{"token":"red"}'
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, content=body, request=req)), **kw))
    agent = Agent(AgentOptions(client=FakeClient([]), tools=registry, skills=Skills(), prompter=prompter,
                              target=target, store=None, engagement_state=policy.engagement))
    args = {'url': '/fixture', 'phase': 'recon', 'max_response_bytes': cap,
            'evidence_mode': 'metadata-only' if cap == 0 else 'body'}
    call = ToolCall('fixture-call', FunctionCall('http', json.dumps(args)))
    result = await agent.run_parsed_tool_call(call, agent.parse_tool_call(call), FakeSignal())
    text = agent._http_analysis_content(call, result)
    assert text is not None
    item = next(iter(policy.observations._items.values()))
    assert item.body == body[:cap]
    assert item.complete is (cap >= len(body))
    assert item.truncated is result.truncated is (cap < len(body))
    assert item.response_cap == cap


async def test_same_origin_redirect_hops_keep_each_exact_body(runtime, monkeypatch):
    registry, prompter, policy, _, sent, _, target = runtime
    def respond(req):
        sent.append(req)
        return httpx.Response(302, content=b'{"token":"red"}', headers={'Location': '/final'}, request=req) if req.url.path == '/redirect' else httpx.Response(200, content=b'{"token":"sky"}', request=req)
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(respond), **kw))
    agent = Agent(AgentOptions(client=FakeClient([]), tools=registry, skills=Skills(), prompter=prompter,
                              target=target, store=None, engagement_state=policy.engagement))
    call = ToolCall('fixture-call', FunctionCall('http', json.dumps({'url': '/redirect', 'phase': 'recon', 'max_redirects': 1})))
    result = await agent.run_parsed_tool_call(call, agent.parse_tool_call(call), FakeSignal())
    text = agent._http_analysis_content(call, result)
    assert text is not None and '{"token":"red"}' in text and '{"token":"sky"}' in text
    assert len(sent) == 2 and len(policy.observations._items) == 2


async def test_raw_primary_manifest_confirmation_and_historical_resume(runtime, tmp_path, monkeypatch):
    from tests.security.test_agent_assessment import setup
    from src.workflow.assessment import accepted_result
    from src.workflow.state import WorkflowState
    body = b'{"token":"red","marker":"REFLECT-7"}'
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, content=body, request=req)), **kw))
    state, candidate, _, args, oid = await setup(runtime, tmp_path)
    registry, prompter, policy, *_ = runtime
    policy.observations.attach_storage(tmp_path / 'observations.json')
    policy.observations.persist()
    args['assessment']['excerpts'] = [{'source_id': oid, 'start': 0, 'end': len(body),
                                      'sha256': hashlib.sha256(body).hexdigest()}]
    assert json.loads(await registry.execute('workflow', args, None, prompter))['ok']
    result = state.latest_result(candidate.id)
    assert result is not None
    assert accepted_result(state, candidate, result, policy)
    assert result.evidence_manifest[0]['source']['body'] == body.hex()
    before = result.assessment_binding
    restored = WorkflowState.from_dict(json.loads(json.dumps(state.to_dict())))
    policy.observations.attach_storage(tmp_path / 'observations.json')
    assert policy.observations._items[oid].body == body
    assert accepted_result(restored, restored.candidates[candidate.id], restored.latest_result(candidate.id), policy)
    restored_result = restored.latest_result(candidate.id)
    assert restored_result is not None and restored_result.assessment_binding == before


@pytest.mark.parametrize('body', BODIES)
def test_retained_http_bytes_hash_ranges_and_resume_are_exact(tmp_path, body):
    store = ObservationStore()
    path = tmp_path / 'observations.json'
    store.attach_storage(path)
    action = SimpleNamespace(epoch='fixture-epoch', method='GET', url='https://fixture.test/',
                             transport_address='fixture', digest='fixture-request', response_cap=65536)
    ref = store.capture(action, 200, body, complete=True, retain_body=True)
    item = store._items[ref]
    assert item.body == body
    assert item.response_hash == hashlib.sha256(body).hexdigest()
    manifest = [{'source': source_row(item), 'hash': item.retained_hash}]
    assert digest(manifest[0]['source']) == item.retained_hash
    excerpt = {'source_id': ref, 'start': 0, 'end': len(body), 'sha256': item.response_hash}
    check_excerpts({'excerpts': [excerpt]}, manifest, terminal=True)
    restored = ObservationStore()
    restored.attach_storage(path)
    assert restored._items[ref] == item
    assert bytes.fromhex(json.loads(path.read_text())['observations'][0]['body']) == body
    assert path.stat().st_mode & 0o777 == 0o600
    store.persist()
    assert restored._items[ref].retained_hash == store._items[ref].retained_hash


def test_legacy_capture_remains_masked_and_historical_hash_is_not_rewritten(tmp_path):
    path = tmp_path / 'observations.json'
    store = ObservationStore()
    store.attach_storage(path)
    action = SimpleNamespace(epoch='fixture', method='GET', url='https://fixture.test/',
                             transport_address='fixture', digest='request')
    ref = store.capture(action, 200, b'{"token":"red"}', complete=True)
    historical = store._items[ref]
    assert b'red' not in historical.body
    store.attach_storage(path)
    store.persist()
    assert store._items[ref] == historical
    assert digest(source_row(historical)) == historical.retained_hash
    assert digest(source_row(replace(historical, body=b'{"token":"red"}'))) != historical.retained_hash


def test_raw_observation_temp_is_private_before_fsync(tmp_path, monkeypatch):
    import os
    store = ObservationStore()
    store.attach_storage(tmp_path / 'observations.json')
    action = SimpleNamespace(epoch='fixture', method='GET', url='https://fixture.test/',
                             transport_address='fixture', digest='request')
    fsync = os.fsync
    checks = []
    def check(fd):
        checks.append(True)
        temporary = tmp_path / 'observations.tmp'
        assert temporary.stat().st_mode & 0o777 == 0o600
        assert bytes.fromhex(json.loads(temporary.read_text())['observations'][0]['body']) == b'{"token":"red"}'
        return fsync(fd)
    monkeypatch.setattr(os, 'fsync', check)
    store.capture(action, 200, b'{"token":"red"}', complete=True, retain_body=True)
    assert checks and not (tmp_path / 'observations.tmp').exists()


@pytest.mark.parametrize('body', BODIES[:-1])
async def test_private_session_resume_and_compaction_preserve_admitted_content(tmp_path, body):
    text = body.decode()
    source = 'obs_' + 'a' * 32
    message = Message('tool', text, name='http', tool_call_id='fixture-call',
                      http_response_sources=[source], http_runtime_stamp=('ephemeral',))
    store = Store.new_with_id(tmp_path, 'fixture')
    for _ in range(3):
        await store.save([message])
        restored = store.load().messages[0]
        assert restored.content == text
        assert restored.http_response_sources == [source]
        assert restored.http_runtime_stamp is None
        assert text in bounded_history_for_compaction([restored])
        assert text in format_history_for_compaction([restored])
        message = restored
    assert store.path.stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.rglob('*.result'))


async def test_provenance_does_not_bypass_user_or_assistant_redaction(tmp_path):
    text = '{"token":"fixture-private"}'
    messages = [Message(role, text, name='http', http_response_sources=['obs_' + 'a' * 32])
                for role in ('user', 'assistant')]
    store = Store.new_with_id(tmp_path, 'untrusted')
    await store.save(messages)
    assert 'fixture-private' not in store.path.read_text()
    assert 'fixture-private' not in bounded_history_for_compaction(messages)


@pytest.mark.parametrize('indent', [None, 2])
def test_recursive_masking_keeps_nested_json_envelope_valid_and_stable(indent):
    from src.redaction.redact import redact_payload
    raw = json.dumps({'content': [{'text': json.dumps({
        'response_body': 'Cookie: sid=fixture-private\nmarker=TRUE-7',
        'token': 'red', 'tail': 'Unicode \u2713',
    }, indent=indent)}], 'tail': True}, indent=indent)
    safe = redact_payload(raw)
    decoded = json.loads(safe)
    inner = json.loads(decoded['content'][0]['text'])
    assert decoded['tail'] is True and inner['tail'] == 'Unicode \u2713'
    assert inner['token'] == '[REDACTED]' and 'fixture-private' not in safe
    assert 'TRUE-7' in inner['response_body']
    assert redact_payload(safe) == safe
