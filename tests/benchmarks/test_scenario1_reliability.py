"""Offline reliability regressions: model/HTTP fakes, production workflow gates."""
from dataclasses import replace
import json

import pytest

from benchmarks.common.contracts import file_hash
from benchmarks.scenario1.core.runner import reproducibility, validate_runtime
from benchmarks.scenario1.core.runtime import build_agent, execute_case, prompt, request_fixture
from src.llm.core.types import ToolCall
from src.tools.common.outcome import ToolOutput
from tests.benchmarks.test_scenario1 import (
    ASSESSMENT, ScriptedClient, isolated_project_environment, make_dataset,
    mock_http, op, settings,
)


@pytest.fixture
def built_agents(monkeypatch):
    from benchmarks.scenario1.core import runtime
    original = runtime.build_agent
    agents = []

    def capture(*args, **kwargs):
        built = original(*args, **kwargs)
        agents.append(built[0])
        return built

    monkeypatch.setattr(runtime, 'build_agent', capture)
    return agents


class RepairClient(ScriptedClient):
    def __init__(self, repair):
        super().__init__(outcome='not-confirmed')
        self.repair = repair

    async def chat(self, request, signal=None):
        response = await super().chat(request, signal)
        if self.step == 2 and self.repair in {'missing-step', 'missing-after-repair'}:
            args = json.loads(response.message.tool_calls[0].function.arguments)
            args['related_requests'] = [{'role': 'readback', 'method': 'GET',
                'url': 'http://127.0.0.1:3000/benchmark/fixture?q=readback'}]
            return self.tool('workflow', args)
        if self.step == 4 and self.repair != 'missing-step':
            args = json.loads(response.message.tool_calls[0].function.arguments)
            args['max_response_bytes'] = 1
            return self.tool('http', args)
        if self.step <= 7:
            return response
        if self.repair == 'missing-after-repair':
            if self.step == 8:
                return self.tool('workflow', {'action': 'record_result', 'candidate_id': self.candidate,
                    'skill_name': self.skill, 'outcome': self.outcome, 'attempt_id': self.attempt,
                    'observation_ids': self.observations[:1], 'evidence_refs': [self.evidence], 'assessment': ASSESSMENT})
            if self.step == 9:
                return self.tool('http', {'url': 'http://127.0.0.1:3000/benchmark/fixture?q=readback',
                    'phase': 'validation'})
            if self.step == 10:
                return self.tool('file_write', {'path': 'artifacts/proof.md',
                    'content': 'Completed independent required readback after repairing unusable manifest.'})
            if self.step == 11:
                return self.tool('workflow', {'action': 'record_evidence', 'candidate_id': self.candidate,
                    'evidence_path': 'artifacts/proof.md',
                    'observation_ids': self.observations[:1] + self.observations[2:]})
            if self.step > 12:
                return response
        if self.repair == 'missing-step':
            if self.step == 8:
                return self.tool('http', {'url': 'http://127.0.0.1:3000/benchmark/fixture?q=readback',
                    'phase': 'validation'})
            if self.step == 9:
                return self.tool('file_write', {'path': 'artifacts/proof.md',
                    'content': 'Completed declared readback step, independent of manifest repair.'})
            if self.step == 10:
                return self.tool('workflow', {'action': 'record_evidence', 'candidate_id': self.candidate,
                    'evidence_path': 'artifacts/proof.md', 'observation_ids': self.observations})
            if self.step > 11:
                return response
        if self.repair == 'usable':
            if self.step == 8:
                return self.tool('file_write', {'path': 'artifacts/proof.md',
                    'content': 'Repaired proof references the already captured complete baseline only.'})
            if self.step == 9:
                return self.tool('workflow', {'action': 'record_evidence', 'candidate_id': self.candidate,
                    'evidence_path': 'artifacts/proof.md', 'observation_ids': self.observations[:1]})
            if self.step > 10:
                return response
        if self.repair == 'probe-loop':
            return self.tool('http', {'url': 'http://127.0.0.1:3000/benchmark/fixture?q=repair',
                'phase': 'validation'})
        submission = self.tool('workflow', {'action': 'record_result', 'candidate_id': self.candidate,
            'skill_name': self.skill, 'outcome': self.outcome, 'attempt_id': self.attempt,
            'observation_ids': (self.observations[:1] if self.repair == 'usable' else
                               self.observations[:1] + self.observations[2:] if self.repair == 'missing-after-repair'
                               else self.observations),
            'evidence_refs': [self.evidence],
            'assessment': {} if self.repair == 'schema-retry' else ASSESSMENT})
        if self.repair == 'batch':
            assert submission.message.tool_calls is not None
            function = submission.message.tool_calls[0].function
            submission.message.tool_calls = [ToolCall(f'{self.step}-{i}', function) for i in range(3)]
        return submission


@pytest.mark.asyncio
@pytest.mark.parametrize('repair,expected,max_calls', [
    ('usable', 'not-confirmed', 11),
    ('identical', 'insufficient-evidence', 8),
    ('batch', 'insufficient-evidence', 8),
    ('schema-retry', 'insufficient-evidence', 8),
    ('probe-loop', 'insufficient-evidence', 10),
    ('missing-step', 'not-confirmed', 12),
    ('missing-after-repair', 'not-confirmed', 13),
])
async def test_agent_terminal_evidence_recovery_is_bounded(
        tmp_path, monkeypatch, op, settings, mock_http, built_agents, repair, expected, max_calls):
    monkeypatch.chdir(tmp_path)
    client = RepairClient(repair)
    ex = await execute_case(op, settings, tmp_path, 'run', 'execution', client)
    assert ex.status == 'completed', ex.error
    assert client.step <= max_calls < settings.agent_calls
    assert ex.result is not None
    result = ex.result['workflow']['validation_results'][-1]
    assert result['outcome'] == expected
    assert ex.result['accepted_at_freeze'] is (repair in {'usable', 'missing-step', 'missing-after-repair'})
    assert ex.stop_reason != 'max_steps'
    assert built_agents[0]._evidence_recovery_rejections == {}
    assert built_agents[0]._evidence_recovery == {}
    if repair == 'usable':
        assert len(mock_http) == 2  # repair uses existing evidence, no new probes
        assert len(result['evidence_manifest']) == 1
        assert result['evidence_manifest'][0]['source']['complete'] is True
    elif repair in {'missing-step', 'missing-after-repair'}:
        assert len(mock_http) == 3
        assert any(row['source']['role'] == 'readback' for row in result['evidence_manifest'])
    else:
        assert ex.stop_reason == 'workflow_blocked'
        assert result['evidence_manifest'] == []
        assert len(mock_http) <= 5
        session = json.loads((tmp_path / '.kagent/sessions' /
            (ex.runtime_metadata['session_id'] + '.json')).read_text())
        calls = {tc['id'] for message in session['messages'] for tc in (message.get('tool_calls') or [])}
        recovery_results = [message for message in session['messages']
                            if str(message.get('tool_call_id') or '').startswith('evidence-recovery-')]
        assert recovery_results
        assert all(message['tool_call_id'] in calls for message in recovery_results)
        if repair == 'batch':
            # Candidate creation is excluded: load/start/2 HTTP/write/evidence/
            # first rejected result/one retry/controller unresolved = 9.
            assert ex.metrics is not None
            assert ex.metrics['tools']['executed'] == 9


@pytest.mark.asyncio
async def test_successful_terminal_repair_clears_gate_within_batch(
        tmp_path, monkeypatch, op, settings, mock_http, built_agents):
    class SuccessfulBatchClient(RepairClient):
        async def chat(self, request, signal=None):
            response = await super().chat(request, signal)
            if self.step == 10:
                assert response.message.tool_calls is not None
                function = response.message.tool_calls[0].function
                response.message.tool_calls = [ToolCall(f'{self.step}-{i}', function) for i in range(2)]
            return response

    monkeypatch.chdir(tmp_path)
    client = SuccessfulBatchClient('usable')
    ex = await execute_case(op, settings, tmp_path, 'run', 'execution', client)
    agent = built_agents[0]
    assert ex.status == 'completed' and client.step == 11
    assert len(mock_http) == 2
    results = [m for m in agent.history if m.role == 'tool' and m.tool_call_id in {'10-0', '10-1'}]
    assert len(results) == 2
    assert all(json.loads(m.content)['ok'] is True for m in results)
    assert len(agent.workflow.validation_results) == 1
    assert agent.workflow.validation_results[0].outcome == 'not-confirmed'
    assert agent._evidence_recovery_rejections == {}
    assert agent._evidence_recovery == {}


class MissingStepSchemaClient(RepairClient):
    def __init__(self, reject_closure=False):
        super().__init__('missing-after-repair')
        self.reject_closure = reject_closure

    async def chat(self, request, signal=None):
        response = await super().chat(request, signal)
        if self.step >= 12:
            return self.tool('workflow', {'action': 'record_result', 'candidate_id': self.candidate,
                'skill_name': self.skill, 'outcome': self.outcome, 'attempt_id': self.attempt,
                'observation_ids': self.observations[:1] + self.observations[2:],
                'evidence_refs': [self.evidence], 'assessment': {},
                **({'cleanup_state': 'invalid-cleanup-state'} if self.reject_closure else {})})
        return response


@pytest.mark.asyncio
@pytest.mark.parametrize('reject_closure', [False, True])
async def test_missing_step_then_schema_error_has_deterministic_closure(
        tmp_path, monkeypatch, op, settings, mock_http, built_agents, capsys, reject_closure):
    monkeypatch.chdir(tmp_path)
    client = MissingStepSchemaClient(reject_closure)
    ex = await execute_case(op, settings, tmp_path, 'run', 'execution', client)
    agent = built_agents[0]
    assert client.step == 12 < settings.agent_calls
    assert ex.stop_reason != 'max_steps'
    assert len(mock_http) == 3
    assert mock_http[-1].url.params['q'] == 'readback'
    assert not agent.workflow.eligible_for_finding(client.candidate)
    messages = agent.history
    results = [message for message in messages if message.role == 'tool']
    assert any(m.content.startswith('error: evidence-admissibility:') for m in results)
    assert any(m.content.startswith('error: declared required request lacks completed evidence;') for m in results)
    recovery_results = [m for m in results if (m.tool_call_id or '').startswith('evidence-recovery-')]
    assert len(recovery_results) == 1
    matching_calls = [tc for m in messages if m.role == 'assistant' for tc in (m.tool_calls or [])
                      if tc.id == recovery_results[0].tool_call_id]
    assert len(matching_calls) == 1
    assert json.loads(matching_calls[0].function.arguments)['outcome'] == 'insufficient-evidence'
    session = json.loads((tmp_path / '.kagent/sessions' /
                         (ex.runtime_metadata['session_id'] + '.json')).read_text())
    assert any(m.get('tool_call_id') == recovery_results[0].tool_call_id for m in session['messages'])
    assert any(tc['id'] == recovery_results[0].tool_call_id for m in session['messages']
               for tc in (m.get('tool_calls') or []))
    latest = agent.workflow.latest_result(client.candidate)
    if reject_closure:
        assert ex.status == 'runtime-error' and ex.stop_reason == 'runtime_error'
        assert 'Bounded evidence recovery closure failed' in capsys.readouterr().err
        assert latest is None
        assert recovery_results[0].content.startswith('error:')
        assert agent._evidence_recovery_rejections[client.candidate] == 2
        assert client.candidate in agent._evidence_recovery
        assert agent._evidence_recovery[client.candidate][1] == 1
        assert not any('Validation stopped with insufficient evidence' in m.content for m in messages)
    else:
        assert ex.status == 'completed' and ex.stop_reason == 'workflow_blocked'
        assert latest is not None and latest.outcome == 'insufficient-evidence'
        assert ex.result is not None
        assert ex.result['workflow']['validation_results'][-1]['outcome'] == 'insufficient-evidence'
        assert json.loads(recovery_results[0].content)['ok'] is True
        assert agent._evidence_recovery_rejections == {}
        assert agent._evidence_recovery == {}


@pytest.mark.asyncio
@pytest.mark.parametrize('max_redirects', [1, 5])
async def test_scenario1_rejects_redirects_before_dispatch(
        tmp_path, op, settings, mock_http, max_redirects):
    agent, _, _ = build_agent(op, settings, tmp_path, ScriptedClient())
    args = {**request_fixture(op, settings), 'max_redirects': max_redirects}
    with pytest.raises(ValueError, match='Scenario 1 does not support follow redirects'):
        await agent.tools.execute('http', args, None, agent.prompter)
    assert mock_http == []


@pytest.mark.asyncio
@pytest.mark.parametrize('max_redirects', [None, 0])
@pytest.mark.parametrize('status', [200, 302])
async def test_scenario1_captures_fixture_response_without_following_redirects(
        tmp_path, monkeypatch, op, settings, max_redirects, status):
    import httpx
    real = httpx.AsyncClient
    dispatched = []

    def handler(request):
        dispatched.append(request)
        return httpx.Response(status, content=b'fixture response', request=request,
                              headers={'Location': '/benchmark/other?username=changed'} if status == 302 else {})

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    agent, policy, _ = build_agent(op, settings, tmp_path, ScriptedClient())
    args = request_fixture(op, settings)
    if max_redirects is not None:
        args['max_redirects'] = max_redirects
    result = await agent.tools.execute('http', args, None, agent.prompter)
    assert isinstance(result, ToolOutput)
    assert len(dispatched) == 1
    assert dispatched[0].url.path == '/benchmark/fixture'
    assert dispatched[0].url.params['q'] == 'bar'
    assert result.http_status == status
    observations = list(policy.observations._items.values())
    assert len(observations) == 1
    assert observations[0].status == status
    assert observations[0].body == b'fixture response'
    assert observations[0].complete and not observations[0].truncated


@pytest.mark.parametrize('location', ['query', 'body', 'header', 'cookie'])
@pytest.mark.parametrize('unrelated', ['query', 'body', 'header', 'cookie'])
def test_fixture_discipline_preserves_unrelated_fields(tmp_path, op, settings, location, unrelated):
    from urllib.parse import urlencode
    from benchmarks.common.contracts import OperationalCaseInput
    fixture = OperationalCaseInput(op.case_id, op.vulnerability_class, 'POST', op.servlet_path,
        [['q', 'bar'], ['keep', 'query']], [['username', 'user'], ['password', 'pass'], ['email', 'user@example.test']],
        {'X-Fixture': 'header'}, {'session': 'cookie'}, location,
        {'query': 'q', 'body': 'email', 'header': 'X-Fixture', 'cookie': 'session'}[location],
        content_type='application/x-www-form-urlencoded')
    agent, _, _ = build_agent(fixture, settings, tmp_path, ScriptedClient())
    tool = agent.tools.get('http')
    from src.tools.http.http_tool import HTTPTool
    assert isinstance(tool, HTTPTool)
    args = request_fixture(fixture, settings)
    tool.prepare(args)  # baseline remains valid
    valid = {**args, 'headers': dict(args['headers'])}
    if location == 'query':
        valid['url'] = valid['url'].replace('q=bar', 'q=marker')
    elif location == 'body':
        valid['body'] = urlencode([('username', 'user'), ('password', 'pass'), ('email', 'marker')])
    elif location == 'header':
        valid['headers']['X-Fixture'] = 'marker'
    else:
        valid['headers']['Cookie'] = 'session=marker'
    tool.prepare(valid)
    invalid = {**valid, 'headers': dict(valid['headers'])}
    if unrelated == 'query':
        invalid['url'] = invalid['url'].replace('keep=query', 'keep=other')
    elif unrelated == 'body':
        invalid['body'] = invalid['body'].replace('username=user', 'username=other')
    elif unrelated == 'header':
        invalid['headers']['X-Unrelated'] = 'other'
    else:
        invalid['headers']['Cookie'] += '; unrelated=other'
    with pytest.raises(ValueError, match='unrelated fields at baseline'):
        tool.prepare(invalid)
    text = prompt('cand_fixture', fixture)
    assert repr(fixture.input_name) in text and repr(location) in text
    assert 'Mutate only the VALUE' in text
    assert 'username, password, email' in text
    assert 'cite requests that mutate another input' in text


def test_known_stateful_runtime_fails_closed_even_with_reset_declaration(tmp_path, settings):
    from benchmarks.scenario1.core.dataset import select
    dataset = make_dataset(tmp_path, 1)
    truth = dataset.truth[0]
    source = tmp_path / f'src/main/java/org/owasp/benchmark/testcode/{truth.case_id}.java'
    source.write_text(source.read_text() + '\nstatement.executeUpdate("INSERT INTO fixture VALUES (1)");')
    manifest = select(dataset, 'run', case_id=truth.case_id)
    assert manifest.dataset['state_mutating_cases'] == [truth.case_id]
    for target_state in ('confirmation-only', 'external-reset'):
        with pytest.raises(ValueError, match='no verified per-case'):
            validate_runtime(manifest, replace(settings, target_state=target_state))


def test_reproducibility_pins_dirty_runtime_without_config_contents(tmp_path, monkeypatch):
    from benchmarks.scenario1.core import runner
    from types import SimpleNamespace
    for name in ('src/agent/runtime.py', 'benchmarks/scenario1/core/runtime.py', 'skills/sql-injection/SKILL.md'):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('original runtime')
    # A credential file must not enter the snapshot even if colocated with source.
    (tmp_path / 'src/config.json').write_text('{"api_key": "fixture-secret"}')
    monkeypatch.setattr(runner, 'REPO', tmp_path)
    monkeypatch.setattr(runner.subprocess, 'run', lambda cmd, **kw: SimpleNamespace(
        returncode=0, stdout=' M src/agent/runtime.py' if 'status' in cmd else 'fixture-commit'))
    first = reproducibility()
    assert first['kagent_dirty'] is True
    path = tmp_path / 'src/agent/runtime.py'
    assert first['runtime_files']['src/agent/runtime.py'] == file_hash(path)
    path.write_text('dirty runtime')
    second = reproducibility()
    assert second['runtime_files']['src/agent/runtime.py'] != first['runtime_files']['src/agent/runtime.py']
    assert 'src/config.json' not in second['runtime_files']
    assert 'fixture-secret' not in json.dumps(second)
    assert first['skills'] == second['skills']
