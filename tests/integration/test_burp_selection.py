"""Offline Burp -> selected model context -> native Workflow/HTTP dispatch.

The client derives IDs and request context from the real LLM request, not a
prewritten tool-call script. All target traffic uses httpx.MockTransport.
"""
import base64
from copy import deepcopy
import json
from pathlib import Path
from typing import cast

import httpx
import pytest

from src.llm.core.client import Client
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.permission.permission import Decision
from src.ui.commands.slash_handler import handle_slash
from src.ui.core.app import KAgent
from tests.helpers.agent_fakes import FakeSignal
from tests.helpers.burp_selection import ORIGIN, ingest, make_runtime

REAL_CLIENT = httpx.AsyncClient
SECRET = 'captured-cookie-fixture'
RAW_BODY = '{"q":"first","keep":1,"password":"body-fixture-secret"}'


class CaptureAwareClient(Client):
    def __init__(self, root):
        self.root = root
        self.requests = []
        self.stage = 0
        self.capture = None
        self.candidate = None
        self.attempt = None
        self.observation = None
        self.evidence = None
        self.finished = False

    def name(self):
        return 'fake'

    def model(self):
        return 'fixture-model'

    def tool(self, name, args):
        return ChatResponse(Message('assistant', '', tool_calls=[ToolCall(
            id=f'fixture-{self.stage}', function=FunctionCall(name, json.dumps(args)))]), 'tool_calls')

    def done(self, content):
        self.finished = True
        return ChatResponse(Message('assistant', content), 'stop')

    async def chat(self, request, signal=None):
        self.requests.append(deepcopy(request))
        contents = '\n'.join(m.content for m in request.messages)
        assert SECRET not in contents and 'body-fixture-secret' not in contents
        marker = 'Untrusted selected Burp request metadata (one-turn snapshot):\n'
        selection = next((json.loads(m.content.removeprefix(marker)) for m in request.messages
                          if m.content.startswith(marker)), None)
        if not selection:
            return self.done('No selected request context was supplied; provide bounded context.')
        assert 'source' in selection[0] and selection[0]['source'] == 'burp'
        assert 'request_body' not in selection[0] and 'request_headers' not in selection[0]
        last = next((m for m in reversed(request.messages) if m.role == 'tool'), None)
        self.stage += 1
        if self.stage == 1:
            assert any('browser_capture_get' in m.content and m.role == 'system' for m in request.messages)
            self.capture = selection[0]
            return self.tool('browser_capture_get', {'id': self.capture['id']})
        assert last is not None
        assert self.capture is not None
        if last.content.startswith(('ERROR:', 'error:', 'pending:')):
            return self.done('Capture/permission unavailable; bounded assessment remains incomplete.')
        if self.stage == 2:
            assert last.name == 'browser_capture_get'
            detail = json.loads(last.content)
            assert detail['id'] == self.capture['id']
            assert detail['baseline_request_ref'] == self.capture['baseline_request_ref']
            assert detail['method'] == 'POST' and json.loads(detail['request_body'])['q'] == 'first'
            assert 'raw_request_b64' not in detail
            # Direct mode records the resolved input as a Candidate. It does
            # not misuse record_input as a general-purpose capture repository.
            return self.tool('workflow', {'action': 'record_candidate', 'candidate_class': 'sqli',
                'endpoint': '/search', 'method': detail['method'], 'parameter': 'q', 'location': 'json',
                'content_type': 'application/json', 'source_ref': detail['id'],
                'baseline_request_ref': detail['baseline_request_ref'],
                'signals': ['Operator requested bounded SQLi testing of the captured query input.']})
        if self.stage == 3:
            data = json.loads(last.content)
            assert data['ok']
            self.candidate = data['candidate']['id']
            assert data['candidate']['baseline_request_ref'] == self.capture['baseline_request_ref']
            return self.tool('load_skill', {'name': 'sql-injection'})
        if self.stage == 4:
            assert last.name == 'load_skill' and 'SQL injection' in last.content
            return self.tool('workflow', {'action': 'start_validation', 'candidate_id': self.candidate})
        if self.stage == 5:
            data = json.loads(last.content)
            assert data['ok']
            self.attempt = data['validation_context']['attempt_id']
            return self.tool('http', {'candidate_id': self.candidate, 'phase': 'validation',
                                     'mutation_value': "first'", 'max_response_bytes': 4096})
        if self.stage == 6:
            # Native HTTP returns a JSON envelope followed by the response
            # body. Its producer-issued ID is the primary evidence reference.
            assert last.name == 'http'
            envelope, _ = json.JSONDecoder().raw_decode(last.content.split('Runtime HTTP evidence (redacted capture; not a semantic verdict): ', 1)[1])
            self.observation = envelope['observation_id']
            assert envelope['status'] == 200
            path = self.root / 'artifacts/sql-injection/fixture/results.md'
            return self.tool('file_write', {'path': str(path), 'content': (
                f'# SQL injection bounded validation\nCandidate: {self.candidate}\n'
                f'Observation: {self.observation}\nPOST /search JSON q: one quote probe.\n'
                'Fixture returned the unchanged marker; SQL injection is not confirmed by this probe.\n'
                'Only one bounded case tested; no general absence claim.\n')})
        if self.stage == 7:
            return self.tool('workflow', {'action': 'record_evidence', 'candidate_id': self.candidate,
                'evidence_path': 'artifacts/sql-injection/fixture/results.md',
                'observation_ids': [self.observation]})
        if self.stage == 8:
            data = json.loads(last.content)
            assert data['ok']
            self.evidence = data['evidence']['id']
            return self.tool('workflow', {'action': 'record_result', 'candidate_id': self.candidate,
                'skill_name': 'sql-injection', 'outcome': 'not-confirmed',
                'evidence_refs': [self.evidence], 'observation_ids': [self.observation],
                'attempt_id': self.attempt, 'techniques': ['single quote probe'],
                'assessment': {'hypothesis': 'A quote in q may cause a SQL error.',
                    'criteria': 'Observe the fixture marker/error for this single bounded probe.',
                    'limitations': 'One mocked request; no general absence claim.',
                    'observed_impact': 'Fixture marker unchanged.', 'severity': 'info',
                    'completed_attempt': True}})
        data = json.loads(last.content)
        assert data['ok'] and data['result']['outcome'] == 'not-confirmed'
        return self.done('One selected request tested with one bounded probe; SQLi not confirmed. Other requests were not assessed.')


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    client = CaptureAwareClient(tmp_path)
    runtime = make_runtime(tmp_path, client)
    runtime.sent = []
    def transport(request):
        runtime.sent.append(request)
        return httpx.Response(200, content=b'fixture marker unchanged', request=request)
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: REAL_CLIENT(transport=httpx.MockTransport(transport), **kwargs))
    return runtime


def burp_ingest(runtime, id_='selected', origin=ORIGIN, body=RAW_BODY):
    head = f'POST /search HTTP/1.1\r\nHost: 127.0.0.1:3000\r\nContent-Type: application/json\r\nCookie: sid={SECRET}\r\nContent-Length: {len(body)}\r\n\r\n'
    return ingest(runtime, id_, origin=origin, path='/search', method='POST',
                  requestBody=body, requestHeaders=[{'name': 'Content-Type', 'value': 'application/json'},
                  {'name': 'Cookie', 'value': 'sid=' + SECRET}],
                  rawRequestB64=base64.b64encode((head + body).encode()).decode())


def slash(runtime, text):
    assert handle_slash(cast(KAgent, runtime.app), text)


@pytest.mark.asyncio
@pytest.mark.parametrize('selection', ['latest', 'specific', 'all'])
async def test_offline_capture_handoff_native_workflow_and_replay(runtime, selection):
    other = burp_ingest(runtime, 'other', body=RAW_BODY.replace('first', 'older').replace('"keep":1', '"keep":2'))
    selected = burp_ingest(runtime)
    slash(runtime, '/burp all' if selection == 'all' else '/burp use ' + selected['id'] if selection == 'specific' else '/burp use')
    assert runtime.policy.used == 0 and not runtime.sent and not runtime.workflow.candidates
    await runtime.agent.run('Test only the latest selected request for SQL injection', FakeSignal(), lambda _: None)
    assert runtime.client.finished and runtime.client.stage == 9
    assert len(runtime.sent) == 1
    request = runtime.sent[0]
    assert request.method == 'POST' and str(request.url) == ORIGIN + '/search'
    assert request.headers['cookie'] == 'sid=' + SECRET
    assert json.loads(request.content) == {'q': "first'", 'keep': 1, 'password': 'body-fixture-secret'}
    candidates = list(runtime.workflow.candidates.values())
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.baseline_request_ref == selected['baseline_request_ref']
    assert candidate.baseline_request_ref != other['baseline_request_ref']
    assert (candidate.parameter, candidate.location, candidate.source_ref) == ('q', 'json', selected['id'])
    assert candidate.objective_id == runtime.workflow.objective.id
    result = runtime.workflow.latest_result(candidate.id)
    assert result is not None and result.outcome == 'not-confirmed'
    assert result.assessment_source == 'agent' and result.evidence_refs
    assert not runtime.workflow.eligible_for_finding(candidate.id)
    assert [q.tool for q in runtime.operator.requests] == ['http_capture_credentials']
    assert runtime.operator.requests[0].force_operator and runtime.operator.requests[0].no_session_cache
    assert runtime.policy.used >= 8
    assert runtime.agent.pending_capture_selection is None
    persisted = runtime.agent.store.load()
    assert persisted.workflow.candidates[candidate.id].baseline_request_ref == selected['baseline_request_ref']
    history = '\n'.join(m.content for m in persisted.messages)
    assert SECRET not in history and 'body-fixture-secret' not in history
    assert 'one-turn snapshot' not in history
    # Follow-up needs no repeated endpoint/selection; canonical history and
    # Workflow remain available. A new task has no transient default source.
    await runtime.agent.run('Explain the previous result', FakeSignal(), lambda _: None)
    followup = runtime.client.requests[-1]
    assert not any('one-turn snapshot' in m.content for m in followup.messages)
    assert any(candidate.id in m.content for m in followup.messages)
    # Restore Workflow with a fresh runtime capture store: historical evidence
    # stays readable, but references never resurrect a replay baseline.
    from src.browser.store import CaptureStore
    runtime.http.capture_store = CaptureStore()
    with pytest.raises((ValueError, PermissionError), match='unavailable'):
        runtime.http.prepare({'candidate_id': candidate.id, 'phase': 'validation'})


@pytest.mark.asyncio
@pytest.mark.parametrize('omission', ['missing', 'null'])
async def test_selected_candidate_recovers_omitted_references_and_replays_capture(runtime, monkeypatch, omission):
    row = burp_ingest(runtime)
    slash(runtime, '/burp use')
    original_tool = runtime.client.tool
    proposed = []
    def tool(name, args):
        if name == 'workflow' and args.get('action') == 'record_candidate':
            for field in ('baseline_request_ref', 'source_ref'):
                if omission == 'missing':
                    args.pop(field)
                else:
                    args[field] = None
            proposed.append(deepcopy(args))
        return original_tool(name, args)
    monkeypatch.setattr(runtime.client, 'tool', tool)
    await runtime.agent.run('Test the selected request for SQL injection', FakeSignal(), lambda _: None)
    assert proposed and not proposed[0].get('baseline_request_ref')
    assert runtime.client.finished and runtime.client.stage == 9
    candidate = next(iter(runtime.workflow.candidates.values()))
    assert candidate.baseline_request_ref == row['baseline_request_ref']
    assert candidate.source_ref == row['id']
    assert len(runtime.sent) == 1
    assert runtime.sent[0].headers['cookie'] == 'sid=' + SECRET
    assert json.loads(runtime.sent[0].content)['q'] == "first'"
    assert [q.tool for q in runtime.operator.requests] == ['http_capture_credentials']
    assert runtime.operator.requests[0].force_operator and runtime.operator.requests[0].no_session_cache
    saved = runtime.agent.store.load()
    assert saved.workflow.candidates[candidate.id].baseline_request_ref == row['baseline_request_ref']
    assert SECRET not in '\n'.join(m.content for m in saved.messages)


@pytest.mark.asyncio
async def test_selected_candidate_original_baseline_read_uses_native_replay(runtime):
    class BaselineClient(CaptureAwareClient):
        async def chat(self, request, signal=None):
            if self.stage == 5:
                self.requests.append(deepcopy(request))
                self.stage += 1
                last = next(m for m in reversed(request.messages) if m.role == 'tool')
                assert last.name == 'http' and last.tool_http_status == 200
                assert SECRET not in '\n'.join(m.content for m in request.messages)
                return self.tool('workflow', {'action': 'record_result', 'candidate_id': self.candidate,
                    'skill_name': 'sql-injection', 'outcome': 'insufficient-evidence',
                    'deferred_reason': 'Original baseline read only; no SQL injection probe was performed.'})
            if self.stage == 6:
                self.requests.append(deepcopy(request))
                last = next(m for m in reversed(request.messages) if m.role == 'tool')
                assert json.loads(last.content)['ok']
                return self.done('Original captured baseline read; SQL injection remains unevaluated.')
            response = await super().chat(request, signal)
            if self.stage == 5:
                assert response.message.tool_calls
                tool_call = response.message.tool_calls[0]
                args = json.loads(tool_call.function.arguments)
                args.pop('mutation_value')
                tool_call.function.arguments = json.dumps(args)
            return response
    client = BaselineClient(runtime.client.root)
    runtime.agent.client = client
    row = burp_ingest(runtime)
    slash(runtime, '/burp use')
    await runtime.agent.run('Read the selected baseline for SQL injection assessment', FakeSignal(), lambda _: None)
    assert client.finished and len(runtime.sent) == 1
    request = runtime.sent[0]
    assert request.method == 'POST' and str(request.url) == ORIGIN + '/search'
    assert request.content.decode() == RAW_BODY and request.headers['cookie'] == 'sid=' + SECRET
    candidate = next(iter(runtime.workflow.candidates.values()))
    assert candidate.baseline_request_ref == row['baseline_request_ref']
    assert [q.tool for q in runtime.operator.requests] == ['http_capture_credentials']
    assert runtime.operator.requests[0].force_operator and runtime.operator.requests[0].no_session_cache


@pytest.mark.asyncio
@pytest.mark.parametrize('negative', ['missing', 'wrong_origin', 'stale'])
async def test_offline_handoff_negative_controls(runtime, negative):
    row = burp_ingest(runtime, origin='http://other.test' if negative == 'wrong_origin' else ORIGIN)
    if negative != 'missing':
        slash(runtime, '/burp use ' + row['id'])
    if negative == 'stale':
        runtime.capture.clear()
        burp_ingest(runtime, 'newer')
    await runtime.agent.run('Test the selected request for SQL injection', FakeSignal(), lambda _: None)
    assert not runtime.sent and not runtime.workflow.candidates
    assert runtime.agent.pending_capture_selection is None
    if negative == 'stale':
        assert not runtime.client.requests
    else:
        assert runtime.client.stage == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('during_review', ['deny', 'eviction', 'revoke'])
async def test_credential_review_and_dispatch_recheck_are_preserved(runtime, during_review):
    row = burp_ingest(runtime)
    slash(runtime, '/burp use')
    if during_review == 'deny':
        runtime.operator.decision = Decision.DENY
    else:
        async def review(request):
            assert request.tool == 'http_capture_credentials'
            if during_review == 'eviction':
                runtime.capture.clear()
                burp_ingest(runtime, 'replacement')
            else:
                runtime.policy.revoke('http')
        runtime.operator.review = review
    await runtime.agent.run('Test the selected request for SQL injection', FakeSignal(), lambda _: None)
    assert not runtime.sent
    assert len(runtime.operator.requests) == 1
    assert runtime.operator.requests[0].tool == 'http_capture_credentials'
    assert not runtime.workflow.validation_results
    assert runtime.agent.pending_capture_selection is None


@pytest.mark.asyncio
async def test_followup_retest_uses_recorded_candidate_without_endpoint_or_new_selection(runtime):
    burp_ingest(runtime)
    slash(runtime, '/burp use')
    await runtime.agent.run('Test the selected request for SQL injection', FakeSignal(), lambda _: None)
    assert runtime.client.finished
    candidate = next(iter(runtime.workflow.candidates.values()))
    sent_before = len(runtime.sent)

    class FollowupClient(CaptureAwareClient):
        async def chat(self, request, signal=None):
            self.requests.append(deepcopy(request))
            contents = '\n'.join(m.content for m in request.messages)
            assert 'one-turn snapshot' not in contents
            assert candidate.id in contents and candidate.baseline_request_ref in contents
            assert SECRET not in contents
            self.stage += 1
            if self.stage == 1:
                return self.tool('load_skill', {'name': 'sql-injection'})
            if self.stage == 2:
                return self.tool('workflow', {'action': 'start_validation', 'candidate_id': candidate.id})
            if self.stage == 3:
                last = next(m for m in reversed(request.messages) if m.role == 'tool')
                assert json.loads(last.content)['ok']
                return self.tool('http', {'candidate_id': candidate.id, 'mutation_value': 'second', 'phase': 'validation'})
            if self.stage == 4:
                last = next(m for m in reversed(request.messages) if m.role == 'tool')
                assert 'Runtime HTTP evidence' in last.content
                return self.tool('workflow', {'action': 'record_result', 'candidate_id': candidate.id,
                    'skill_name': 'sql-injection', 'outcome': 'insufficient-evidence',
                    'deferred_reason': 'Follow-up probe alone does not establish reproducible SQL injection.'})
            return self.done('Follow-up probe completed; assessment remains inconclusive.')

    followup = FollowupClient(runtime.client.root)
    runtime.agent.client = followup
    await runtime.agent.run(f'Retest {candidate.id}', FakeSignal(), lambda _: None)
    assert followup.finished and len(runtime.sent) == sent_before + 1
    assert json.loads(runtime.sent[-1].content)['q'] == 'second'
    assert runtime.sent[-1].headers['cookie'] == 'sid=' + SECRET
    assert runtime.agent.pending_capture_selection is None
