"""Offline readback and terminal lifecycle regressions through real gates."""
from dataclasses import asdict, replace
import asyncio
from copy import deepcopy
import hashlib
import json

import pytest

from benchmarks.scenario1.core.runtime import (
    _bind_benchmark_evidence, build_agent, candidate_arguments, prompt, request_fixture,
    case_closure_diagnostic, execute_case, HeadlessPermissions,
)
from benchmarks.scenario1.core.canonical import freeze
from benchmarks.scenario1.core.evaluate import evaluate
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.permission.permission import Decision, PermissionRequest, UserControlledRefusal
from src.workflow.assessment import digest, source_row
from src.workflow.evidence_recovery import current_budget
from src.workflow.state import WorkflowState
from src.tools.http.http_tool import HTTPTool
from src.tools.common.tool_result import ReadHTTPObservation
from tests.helpers.agent_fakes import FakeSignal, collect
from tests.benchmarks.test_scenario1 import (
    ASSESSMENT, ScriptedClient, isolated_project_environment, mock_http, op, settings,
    recorded_run, single_manifest,
)


async def active_case(op, settings, root, *, whole=False):
    agent, policy, _ = build_agent(op, settings, root, ScriptedClient())
    payload = json.loads(await agent.tools.execute('workflow', {
        'action': 'record_candidate', **candidate_arguments(op, settings)}, None, agent.prompter))
    cid = payload['candidate']['id']
    assert isinstance(agent.prompter, HeadlessPermissions)
    agent.prompter.bind_case(agent, op, cid)
    _bind_benchmark_evidence(policy, op)
    agent._initialize_request_objective(prompt(cid, op), True)
    if whole:
        assert agent.workflow.objective is not None
        agent.workflow.objective.mode = 'whole_target'
        agent.workflow.candidates[cid].objective_id = agent.workflow.objective.id
    agent.active_skills.add(op.vulnerability_class)
    started = json.loads(await agent.tools.execute('workflow', {
        'action': 'start_validation', 'candidate_id': cid, 'assessment': ASSESSMENT}, None, agent.prompter))
    assert started['ok'] is True
    return agent, policy, cid, started['validation_context']['attempt_id']


async def captured_case(op, settings, root):
    agent, policy, cid, aid = await active_case(op, settings, root)
    await agent.tools.execute('http', request_fixture(op, settings), None, agent.prompter)
    oid = next(iter(policy.observations._items))
    return agent, policy, cid, aid, oid


async def test_headless_owned_range_is_once_and_sends_no_http(tmp_path, op, settings, mock_http):
    agent, policy, _, _, oid = await captured_case(op, settings, tmp_path)
    http = agent.tools.get('http')
    assert isinstance(http, HTTPTool) and isinstance(agent.prompter, HeadlessPermissions)
    before = (len(mock_http), http.dispatch_attempts,
              sum(b.used for b in policy.engagement.http_permissions._budgets.values()))
    args = {'observation_id': oid, 'start_char': 1, 'max_chars': 4}
    reader = agent.tools.get('read_http_observation')
    assert isinstance(reader, ReadHTTPObservation)
    assert reader.permission_hints(args) == {
        'noSessionCache': True, 'riskTier': 'high-impact',
        'cacheKey': f'observation:{oid}:1:4'}
    for _ in range(2):
        output = await agent.tools.execute('read_http_observation', args, None, agent.prompter)
        header, body = output.split('\n', 1)
        row = json.loads(header)
        assert body == 'html' and row['end_char'] == row['next_start_char'] == 5
        assert row['retained_hash'] == policy.observations._items[oid].retained_hash
    approvals = [d for d in agent.prompter.decisions if d['tool'] == 'read_http_observation']
    assert approvals == [{'tool': 'read_http_observation', 'risk_tier': 'high-impact', 'allowed': True}] * 2
    assert before == (len(mock_http), http.dispatch_attempts,
                      sum(b.used for b in policy.engagement.http_permissions._budgets.values()))
    assert policy.yolo is False and not agent.workflow.validation_results


@pytest.mark.parametrize('fault', [
    'integrity', 'session', 'case', 'candidate', 'attempt', 'epoch', 'revision',
    'revoke-http', 'revoke-reader', 'source-kind', 'secret', 'origin', 'binding',
])
async def test_headless_readback_boundaries(tmp_path, op, settings, mock_http, fault):
    agent, policy, _, aid, oid = await captured_case(op, settings, tmp_path)
    item = policy.observations._items[oid]
    if fault == 'integrity':
        item = replace(item, body=b'tampered')
    elif fault in {'session', 'candidate', 'attempt', 'epoch', 'binding', 'origin', 'source-kind'}:
        field, value = {
            'session': ('session_id', 'foreign-session'), 'candidate': ('candidate_id', 'foreign-candidate'),
            'attempt': ('attempt_id', 'foreign-attempt'), 'epoch': ('epoch', 'foreign-epoch'),
            'binding': ('candidate_binding', 'foreign-binding'), 'origin': ('url', 'http://localhost:3000/benchmark/fixture'),
            'source-kind': ('source_kind', 'imported-capture'),
        }[fault]
        item = replace(item, **{field: value})
    elif fault == 'case':
        assert item.source_details is not None
        details = {**item.source_details, 'scenario1_case_binding': {
            **item.source_details['scenario1_case_binding'], 'case_id': 'foreign-case'}}
        item = replace(item, source_details=details)
    elif fault == 'revision':
        agent.workflow.attempts[aid]['target_revision'] = -1
    elif fault.startswith('revoke-'):
        policy.revoke('http' if fault == 'revoke-http' else 'read_http_observation')
    elif fault == 'secret':
        secret = 'managed-controller-secret'
        item = replace(item, body=secret.encode(), response_hash=hashlib.sha256(secret.encode()).hexdigest())
        policy.internal_secret_values = lambda: (secret,)
    if fault != 'integrity':
        item = replace(item, retained_hash=digest(source_row(item)))
    policy.observations._items[oid] = item
    before = len(mock_http)
    with pytest.raises((ValueError, UserControlledRefusal, PermissionError)):
        await agent.tools.execute('read_http_observation', {
            'observation_id': oid, 'start_char': 0, 'max_chars': 8}, None, agent.prompter)
    assert len(mock_http) == before


@pytest.mark.parametrize('key,current', [
    ('observation:{oid}:0:0', True), ('observation:{oid}:-1:8', True),
    ('observation:{oid}:00:8', True), ('observation:{oid}:0:2001', True),
    ('observation:{oid}:0:8:extra', True), ('result:{oid}:0:8', True),
    ('observation:{oid}:0:8', False), (None, True),
])
async def test_headless_malformed_or_stale_review_denied(tmp_path, op, settings, mock_http, key, current):
    agent, _, _, _, oid = await captured_case(op, settings, tmp_path)
    request = PermissionRequest('read_http_observation', 'range', '{}',
        risk_tier='high-impact', no_session_cache=True,
        cache_key=key.format(oid=oid) if key else None, is_current=lambda: current)
    assert await agent.prompter.ask(request) is Decision.DENY


async def test_readback_revalidates_after_headless_approval(tmp_path, op, settings, mock_http):
    agent, policy, _, _, oid = await captured_case(op, settings, tmp_path)
    original = agent.prompter.ask

    async def revoke(request, signal=None):
        decision = await original(request, signal)
        assert decision is Decision.ALLOW_ONCE
        policy.revoke('http')
        return decision

    agent.prompter.ask = revoke
    with pytest.raises(UserControlledRefusal):
        await agent.tools.execute('read_http_observation', {
            'observation_id': oid, 'start_char': 0, 'max_chars': 8}, None, agent.prompter)
    assert len(mock_http) == 1


@pytest.mark.parametrize('prefix', ['obs_', 'sf_', 'tr_'])
async def test_generic_reader_gains_no_headless_permission(tmp_path, op, settings, mock_http, prefix):
    agent, _, _, _, _ = await captured_case(op, settings, tmp_path)
    request = PermissionRequest('read_tool_result', 'range', '{}', risk_tier='high-impact',
        no_session_cache=True, cache_key=f'result:{prefix + "a" * 32}:0:8', is_current=lambda: True)
    assert await agent.prompter.ask(request) is Decision.DENY
    with pytest.raises((ValueError, UserControlledRefusal)):
        await agent.tools.execute('read_tool_result', {'result_ref': prefix + 'a' * 32,
            'start_char': 0, 'max_chars': 8}, None, agent.prompter)


class StopClient(ScriptedClient):
    def __init__(self, mode):
        super().__init__(skill='sql-injection')
        self.stop_mode = mode

    async def chat(self, request, signal=None):
        if not request.tools:
            self.requests.append(request)
            return ChatResponse(Message('assistant', 'Assessment remains incomplete.'), 'stop')
        response = await super().chat(request, signal)
        if self.step <= 2:
            return response
        if self.stop_mode in {'unavailable', 'no-start'}:
            return self.tool('ask_user', {'questions': [{'question': 'Supply the missing validation input.'}]})
        if self.step <= 4:
            return response
        if self.stop_mode in {'reader', 'mixed'}:
            response = self.tool('read_http_observation', {
                'observation_id': self.observations[0], 'start_char': 0, 'max_chars': 8})
            if self.stop_mode == 'mixed':
                assert response.message.tool_calls is not None
                response.message.tool_calls.append(ToolCall(f'list-{self.step}',
                    FunctionCall('workflow', json.dumps({'action': 'list'}))))
            return response
        if self.stop_mode == 'write' and self.step == 5:
            # A rejected proof submission retains the explicit write/cleanup
            # declaration, but gains no accepted evidence or terminal result.
            return self.tool('workflow', {'action': 'record_result', 'candidate_id': self.candidate,
                'attempt_id': self.attempt, 'skill_name': self.skill, 'outcome': 'confirmed',
                'mutation_performed': True, 'cleanup_state': 'requires-user-action',
                'cleanup_status': 'Agent cleanup not performed; requires user action',
                'assessment': ASSESSMENT})
        if self.stop_mode == 'write':
            return self.tool('workflow', {'action': 'list'})
        return self.tool('http', {'url': 'http://127.0.0.1:3000/benchmark/fixture?q=repeat',
                                  'phase': 'validation'})


@pytest.mark.parametrize('mode,stop,status', [
    ('unavailable', 'all_tools_refused', 'completed'),
    ('reader', 'all_tools_refused', 'runtime-error'),
    ('mixed', 'workflow_stalled', 'runtime-error'),
    ('stall', 'workflow_stalled', 'runtime-error'),
    ('write', 'workflow_stalled', 'completed'),
])
async def test_terminal_stop_closes_safely_or_exports_explicit_failure(
        tmp_path, monkeypatch, op, settings, mock_http, mode, stop, status):
    from benchmarks.scenario1.core.runtime import HeadlessPermissions
    op = replace(op, vulnerability_class='sql-injection')
    monkeypatch.chdir(tmp_path)
    if mode in {'reader', 'mixed'}:
        monkeypatch.setattr(HeadlessPermissions, '_owned_readback', lambda *_: False)
    if mode in {'stall', 'write'}:
        import httpx
        # The imported HTTP fixture already wraps AsyncClient. Use its native
        # class to avoid supplying two transport keyword arguments.
        real = httpx._client.AsyncClient

        def handler(request):
            mock_http.append(request)
            return httpx.Response(200, content=(b'same body' if mode == 'stall'
                else b'{"write_acknowledged":true,"update_count":1}'), request=request)

        monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    client = StopClient(mode)
    ex = await execute_case(op, settings, tmp_path, 'run', 'execution', client)
    assert ex.stop_reason == stop and ex.status == status, ex.error
    assert client.step < settings.agent_calls
    assert ex.result is not None
    state = ex.result['workflow']
    results = state['validation_results']
    assert not state['persisted_findings'] and not ex.result['accepted_at_freeze']
    if status == 'completed':
        result = results[-1]
        assert result['outcome'] == ('blocked' if mode == 'unavailable' else 'insufficient-evidence')
        assert state['attempts'][client.attempt]['status'] == 'unresolved'
        assert result['attempt_id'] == client.attempt
        assert not result['evidence_manifest'] and not result['evidence_refs']
        assert ex.runtime_metadata['closure_diagnostic'] is None
        if mode == 'write':
            assert result['mutation_performed'] is True
            assert result['cleanup_state'] == 'requires-user-action'
            assert result['cleanup_status'] == 'Agent cleanup not performed; requires user action'
            assert len(mock_http) == 2
        else:
            assert not result['mutation_performed'] and len(mock_http) == 0
    else:
        assert not results and state['attempts'][client.attempt]['status'] == 'active'
        assert ex.runtime_metadata['closure_diagnostic'] == 'active-case-attempt-without-closure'
        session = json.loads((tmp_path / '.kagent/sessions' / (ex.runtime_metadata['session_id'] + '.json')).read_text())
        assert any('Workflow closure failed' in m['content'] for m in session['messages'])
        assert not any(tc['function']['name'] == 'workflow'
            and json.loads(tc['function']['arguments']).get('action') == 'record_result'
            for m in session['messages'] for tc in (m.get('tool_calls') or []))
        assert len(mock_http) <= 6  # threshold=4 stops probing; no closure HTTP
    manifest = single_manifest(replace(op, vulnerability_class='cross-site-scripting'), settings)
    manifest = replace(manifest, operational=[asdict(op)], truth=[{
        **manifest.truth[0], 'vulnerability_class': op.vulnerability_class, 'cwe': 89}])
    recorded_run(tmp_path / 'recorded', manifest, ex)
    report = evaluate(tmp_path / 'recorded')
    assert report['records'][0]['partition'] == ('unresolved' if status == 'completed' else 'execution-failed')
    assert report['metrics']['overall']['TP'] == report['metrics']['overall']['TN'] == 0


async def test_worker_catches_active_orphan_when_agent_skips_closure(tmp_path, monkeypatch, op, settings, mock_http):
    from src.agent.agent import Agent

    async def skipped(*args, **kwargs):
        return None

    monkeypatch.setattr(Agent, '_close_terminal_attempt', skipped)
    ex = await execute_case(replace(op, vulnerability_class='sql-injection'), settings, tmp_path,
                            'run', 'execution', StopClient('unavailable'))
    assert ex.status == 'runtime-error' and ex.stop_reason == 'all_tools_refused'
    assert ex.error == 'active-case-attempt-without-closure'
    assert ex.result is not None
    assert ex.result['workflow']['validation_results'] == []


@pytest.mark.parametrize('mode', ['no-start', 'terminal'])
async def test_worker_preserves_no_attempt_or_existing_terminal(tmp_path, monkeypatch, op, settings, mock_http, mode):
    monkeypatch.chdir(tmp_path)
    class NoStart(ScriptedClient):
        async def chat(self, request, signal=None):
            self.step += 1
            return self.tool('ask_user', {'questions': [{'question': 'Supply input.'}]})

    ex = await execute_case(op, settings, tmp_path, 'run', 'execution',
                            NoStart() if mode == 'no-start' else ScriptedClient())
    assert ex.status == 'completed' and ex.runtime_metadata['closure_diagnostic'] is None
    assert ex.result is not None
    if mode == 'no-start':
        assert ex.result['workflow']['attempts'] == {} and ex.result['result_id'] is None
    else:
        assert ex.result['accepted_at_freeze'] and ex.result['result_id'] is not None


async def test_zero_action_closure_is_saved_idempotent_and_freeze_is_pure(tmp_path, op, settings, mock_http):
    agent, policy, cid, aid = await active_case(op, settings, tmp_path)
    events = collect()
    await agent._close_terminal_attempt('workflow_stalled', FakeSignal(), events['sink'], agent.history.copy())
    latest = agent.workflow.latest_result(cid)
    assert latest is not None and policy.session_id is not None
    assert latest.outcome == 'insufficient-evidence' and latest.attempt_id == aid
    assert agent.workflow.attempts[aid]['status'] == 'unresolved'
    saved = json.loads((tmp_path / '.kagent/sessions' / (policy.session_id + '.json')).read_text())
    assert saved['workflow']['validation_results'][-1]['result_id'] == latest.result_id
    before = deepcopy(agent.workflow.to_dict())
    await agent._close_terminal_attempt('all_tools_refused', FakeSignal(), events['sink'], agent.history.copy())
    frozen = freeze('run', op.case_id, 'ex', policy.session_id, cid, agent.workflow, policy, agent.target)
    assert agent.workflow.to_dict() == before and len(agent.workflow.validation_results) == 1
    assert frozen['workflow'] == before and not frozen['accepted_at_freeze']
    assert not events['events'] or all(e['type'] != 'error' for e in events['events'])
    assert mock_http == []


@pytest.mark.parametrize('fault', ['session', 'epoch', 'revision', 'binding', 'selector', 'revoked', 'workflow-state',
                                  'invalid-args', 'timeout', 'persistence', 'pending', 'cancelled'])
async def test_closure_failure_preserves_owned_state_or_reports_unsaved_commit(
        tmp_path, op, settings, mock_http, monkeypatch, fault):
    agent, policy, cid, aid = await active_case(op, settings, tmp_path)
    attempt = agent.workflow.attempts[aid]
    foreign_state = None
    if fault in {'session', 'epoch', 'revision', 'binding'}:
        key = {'session': 'session_id', 'epoch': 'epoch', 'revision': 'target_revision', 'binding': 'candidate_binding'}[fault]
        attempt[key] = 'foreign'
    elif fault == 'selector':
        policy.generic_validation.durable_attempt = 'foreign'
    elif fault == 'revoked':
        policy.revoke('workflow')
    elif fault == 'workflow-state':
        from src.tools.workflow.workflow_tool import WorkflowTool
        tool = agent.tools.get('workflow')
        assert isinstance(tool, WorkflowTool)
        foreign_state = deepcopy(agent.workflow, {id(agent.workflow.mutation_lock): asyncio.Lock()})
        tool.state = foreign_state
    elif fault in {'invalid-args', 'timeout', 'cancelled'}:
        tool = agent.tools.get('workflow')
        assert tool is not None
        original = tool.run

        async def failing(args, signal, prompter):
            if fault == 'timeout':
                raise TimeoutError('secret must not enter diagnostic')
            if fault == 'cancelled':
                raise asyncio.CancelledError()
            return await original({**args, 'cleanup_state': 'invalid'}, signal, prompter)

        monkeypatch.setattr(tool, 'run', failing)
    elif fault == 'persistence':
        async def fail_save(*args, **kwargs):
            raise OSError('credential=secret')

        monkeypatch.setattr(agent.store, 'save', fail_save)
    elif fault == 'pending':
        agent.history.append(Message('tool', 'Review pending', name='http', tool_error_kind='permission_pending'))
    before = deepcopy(agent.workflow.to_dict())
    events = collect()
    if fault == 'cancelled':
        with pytest.raises(asyncio.CancelledError):
            await agent._close_terminal_attempt('workflow_stalled', FakeSignal(), events['sink'], agent.history.copy())
    else:
        await agent._close_terminal_attempt('workflow_stalled', FakeSignal(), events['sink'], agent.history.copy())
        assert any(e['type'] == 'error' for e in events['events'])
        assert any('Workflow closure failed' in str(e) for e in events['events'])
        assert 'secret' not in ''.join(m.content for m in agent.history if m.role == 'assistant')
    if fault == 'persistence':
        assert attempt['status'] == 'unresolved' and agent.workflow.latest_result(cid) is not None
        assert agent._workflow_saved_revision != agent.workflow.committed_revision
    else:
        assert agent.workflow.attempts == before['attempts']
        assert not agent.workflow.validation_results
        if fault == 'workflow-state':
            assert foreign_state is not None
            assert not foreign_state.validation_results and foreign_state.attempts[aid]['status'] == 'active'
    assert mock_http == []


async def test_whole_target_closes_only_current_attempt_and_keeps_pending_candidates(tmp_path, op, settings, mock_http):
    agent, _, cid, aid = await active_case(op, settings, tmp_path, whole=True)
    objective = agent.workflow.objective
    assert objective is not None
    other = json.loads(await agent.tools.execute('workflow', {
        'action': 'record_candidate', **{**candidate_arguments(op, settings), 'endpoint': '/benchmark/other'}}, None, agent.prompter))
    oid = other['candidate']['id']
    before = agent.workflow.candidates[oid].to_dict()
    events = collect()
    await agent._close_terminal_attempt('all_tools_refused', FakeSignal(), events['sink'], agent.history.copy(),
                                        blocker='permission-denied')
    result = agent.workflow.latest_result(cid)
    assert result is not None and result.outcome == 'blocked'
    assert agent.workflow.attempts[aid]['status'] == 'unresolved'
    assert agent.workflow.latest_result(oid) is None and agent.workflow.candidates[oid].to_dict() == before
    assert not agent.workflow.persisted_findings and mock_http == []


async def test_foreign_controller_at_same_origin_cannot_read_owned_observation(tmp_path, op, settings, mock_http):
    first, first_policy, _, _, oid = await captured_case(op, settings, tmp_path / 'first')
    second, second_policy, _, _, _ = await captured_case(
        replace(op, case_id='BenchmarkTest00002'), settings, tmp_path / 'second')
    second_policy.observations._items[oid] = first_policy.observations._items[oid]
    args = {'observation_id': oid, 'start_char': 0, 'max_chars': 8}
    with pytest.raises(UserControlledRefusal):
        await second.tools.execute('read_http_observation', args, None, second.prompter)
    reader = first.tools.get('read_http_observation')
    assert isinstance(reader, ReadHTTPObservation)
    with pytest.raises(UserControlledRefusal):
        reader.validate_rights(args, second.prompter, receipt=False)
    assert len(mock_http) == 2


async def test_concurrent_duplicate_closure_never_overwrites_or_creates_second_result(tmp_path, op, settings, mock_http):
    agent, policy, cid, _ = await active_case(op, settings, tmp_path)
    events = collect()
    await asyncio.gather(*[
        agent._close_terminal_attempt('workflow_stalled', FakeSignal(), events['sink'], agent.history.copy())
        for _ in range(2)])
    latest = agent.workflow.latest_result(cid)
    assert latest is not None and len(agent.workflow.validation_results) == 1
    assert latest.outcome == 'insufficient-evidence'
    assert agent._workflow_saved_revision == agent.workflow.committed_revision
    assert not any(e['type'] == 'error' for e in events['events'])
    assert mock_http == [] and case_closure_diagnostic(agent.workflow, cid) is None


async def test_wrong_name_component_stalls_with_zero_admitted_http_and_honest_unresolved(
        tmp_path, monkeypatch, op, settings, mock_http):
    monkeypatch.chdir(tmp_path)
    op = replace(op, method='POST', query=[], body=[['SafeText', op.case_id]],
                 input_name='SafeText', input_location='body', input_component='name')

    class WrongComponent(ScriptedClient):
        async def chat(self, request, signal=None):
            if not request.tools:
                return ChatResponse(Message('assistant', 'Assessment remains incomplete.'), 'stop')
            response = await super().chat(request, signal)
            if self.step <= 2:
                return response
            return self.tool('http', {**request_fixture(op, settings), 'body': 'SafeText=changed-value'})

    client = WrongComponent()
    ex = await execute_case(op, settings, tmp_path, 'run', 'execution', client)
    assert ex.status == 'completed' and ex.stop_reason == 'workflow_stalled'
    assert mock_http == [] and ex.metrics is not None and ex.metrics['http_admitted'] == 0
    assert client.step < settings.agent_calls and ex.result is not None
    results = ex.result['workflow']['validation_results']
    assert len(results) == 1 and results[0]['outcome'] == 'insufficient-evidence'
    assert not results[0]['mutation_performed'] and not results[0]['evidence_manifest']
    assert not ex.result['accepted_at_freeze'] and not ex.result['workflow']['persisted_findings']


async def test_closure_cannot_repair_stale_controller_binding(tmp_path, op, settings, mock_http):
    agent, _, cid, aid = await active_case(op, settings, tmp_path)
    restored = deepcopy(agent.workflow, {id(agent.workflow.mutation_lock): asyncio.Lock()})
    agent.workflow = restored
    events = collect()
    await agent._close_terminal_attempt('workflow_stalled', FakeSignal(), events['sink'], agent.history.copy())
    assert any(e['type'] == 'error' for e in events['events'])
    assert restored.attempts[aid]['status'] == 'active' and restored.latest_result(cid) is None
    assert mock_http == []


async def test_terminal_closure_leaves_hydrated_interruption_for_existing_resume_path(tmp_path, op, settings, mock_http):
    agent, _, cid, aid = await active_case(op, settings, tmp_path)
    restored = WorkflowState.from_dict(agent.workflow.to_dict())
    agent.workflow = restored
    before = deepcopy(restored.to_dict())
    events = collect()
    await agent._close_terminal_attempt('workflow_stalled', FakeSignal(), events['sink'], agent.history.copy())
    assert restored.to_dict() == before and restored.attempts[aid]['status'] == 'interrupted'
    assert restored.latest_result(cid) is None and mock_http == [] and not events['events']


async def test_terminal_closure_preserves_accepted_result_and_source_seals(tmp_path, op, settings, mock_http):
    agent, policy, cid, aid, oid = await captured_case(op, settings, tmp_path)
    await agent.tools.execute('file_write', {'path': str(tmp_path / 'artifacts/proof.md'),
        'content': 'Bounded captured fixture response assessed without a terminal execution claim.'}, None, agent.prompter)
    evidence = json.loads(await agent.tools.execute('workflow', {'action': 'record_evidence',
        'candidate_id': cid, 'evidence_path': 'artifacts/proof.md', 'observation_ids': [oid]}, None, agent.prompter))
    assert evidence['ok'] is True
    recorded = json.loads(await agent.tools.execute('workflow', {'action': 'record_result',
        'candidate_id': cid, 'attempt_id': aid, 'skill_name': op.vulnerability_class,
        'outcome': 'not-confirmed', 'mutation_performed': False, 'assessment': ASSESSMENT,
        'evidence_refs': [evidence['evidence']['id']], 'observation_ids': [oid]}, None, agent.prompter))
    assert recorded['ok'] is True
    before = deepcopy(agent.workflow.to_dict())
    latest = agent.workflow.latest_result(cid)
    assert latest is not None
    events = collect()
    await agent._close_terminal_attempt('all_tools_refused', FakeSignal(), events['sink'], agent.history.copy(),
                                        blocker='permission-denied')
    assert agent.workflow.to_dict() == before and not events['events']
    assert agent.workflow.latest_result(cid) is latest and len(mock_http) == 1
    frozen = freeze('run', op.case_id, 'ex', policy.session_id, cid, agent.workflow, policy, agent.target)
    assert frozen['accepted_at_freeze'] and frozen['result_id'] == latest.result_id


async def test_cancellation_during_closure_save_joins_without_claiming_persistence(tmp_path, op, settings, mock_http, monkeypatch):
    agent, _, cid, aid = await active_case(op, settings, tmp_path)
    entered, release = asyncio.Event(), asyncio.Event()
    original = agent.save

    async def held_save(*args, **kwargs):
        entered.set()
        await release.wait()
        await original(*args, **kwargs)

    monkeypatch.setattr(agent, 'save', held_save)
    events = collect()
    task = asyncio.create_task(agent._close_terminal_attempt('workflow_stalled', FakeSignal(),
        events['sink'], agent.history.copy()))
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    release.set()
    assert task.done() and not agent._background_tasks
    assert agent.workflow.attempts[aid]['status'] == 'unresolved'  # actual pre-save commit
    assert agent.workflow.latest_result(cid) is not None
    assert agent._workflow_saved_revision != agent.workflow.committed_revision
    assert mock_http == [] and not any(e['type'] == 'assistant-text' for e in events['events'])
