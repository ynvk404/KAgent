"""S scripted models through real Agent/Planner/Skills/Registry; no provider/API."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from src.agent.agent import Agent, AgentOptions, AgentRunOptions, ExecutedToolCall, ToolCallResult, _exploration_fingerprint
from src.agent.system_prompt import render_workflow
from src.agent.tool_results import source_provenance
from src.llm.core.types import Message
from src.permission.runtime.execution import ExecutionBlocked
from src.session.store import Store
from src.session.tool_results import ResultUnavailable
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry as Skills
from src.tools.execution.file import FileReadTool
from src.tools.http.http_tool import HTTPTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.state import WorkflowObjective, WorkflowState, WorkflowMode
from tests.helpers.agent_fakes import ScriptedModel, FakeSignal, FakeClient
from tests.helpers.workflow import record_completed_phase
from tests.security.test_scanner_end_to_end import runtime, wire, require_binaries

SKILLS = Path(__file__).resolve().parents[2] / 'skills'


class DiscoveryScript(ScriptedModel):
    async def chat(self, request, signal=None):
        if self.consumed:
            # The model deliberately stops before the whole-target prerequisites
            # are complete. The actual Agent must withhold completion and stop
            # the nonproductive summaries through its existing stall bounds.
            self.summaries += 1
            assert self.summaries <= 8
            return self._summary()
        return await super().chat(request, signal)


def agent_runtime(tmp_path, origin, model, *, mode: WorkflowMode = 'whole_target', enumeration=False):
    rt = runtime(tmp_path / 'project', origin, ('hit', 'missing', 'large'))
    skills = Skills()
    skills.load_dir(SKILLS)
    state = WorkflowState(objective=WorkflowObjective('scanner-objective', mode, origin))
    assert state.objective is not None
    rt.registry.register(LoadSkillTool(skills))
    http = HTTPTool(rt.target, rt.state)
    rt.registry.register(http)
    rt.registry.register(FileReadTool())
    workflow = WorkflowTool(state, rt.target, skills=skills, evidence_root=rt.root, http_tool=http)
    rt.registry.register(workflow)
    from src.permission.network.grants import HTTPLimits
    rt.state.http_permissions.activate(origin, HTTPLimits.session())
    if enumeration:
        from src.skills.artifacts import completion_artifact_path
        recon = skills.get('recon')
        assert recon is not None and recon.completion_artifact
        artifact = completion_artifact_path(recon.completion_artifact, origin)
        path = rt.root / artifact
        path.parent.mkdir(parents=True)
        path.write_text('Explicit synthetic recon prerequisite for scanner enumeration fixture.')
        # A fixture prerequisite, never reported as runtime recon acceptance.
        if mode == 'whole_target':
            record_completed_phase(state, 'recon', objective_id=state.objective.id,
                target_origin=origin, artifact_ref=artifact)
        state.completed_skills.add('recon')
        state.completed_artifacts['recon'] = artifact
        state.current_phase = 'enumeration'
    agent = Agent(AgentOptions(client=model, tools=rt.registry, skills=skills, prompter=rt.prompter,
        store=Store.new_with_id(tmp_path / 'sessions', 'scanner-fixture'), target=rt.target,
        engagement_state=rt.state, workflow=state, max_steps=30, auto_compact_threshold=100000,
        prompt_profile='compact', streaming_enabled=False))
    rt.agent, rt.workflow = agent, workflow
    return rt


@pytest.mark.parametrize('first', ['http', 'nmap', 'ffuf', 'none'])
@pytest.mark.parametrize('mode', ['whole_target', 'direct'])
async def test_S_real_agent_choices_and_selective_scanner_handoff(tmp_path, wire, first, mode):
    require_binaries()
    origin, counters = wire
    job_ids = []
    records = []
    def script():
        yield 'load_skill', {'name': 'web-enumeration' if first == 'ffuf' else 'recon'}
        if first in {'http', 'none'}:
            response = yield 'http', {'url': '/', 'phase': 'recon'}
            assert response and not response.startswith('ERROR:')
        if first in {'http', 'nmap'}:
            result = json.loads((yield 'shell', {'scanner': 'nmap', 'target': '127.0.0.1',
                'ports': str(rt.target.origin().port)}))
            assert result['execution']['status'] == 'completed', result
            job_ids.append(result['job_id'])
            assert not rt.agent.workflow.attack_surface_inputs and not rt.agent.workflow.candidates
            # Native HTTP after an Nmap-first call is a valid independent choice.
            if first == 'nmap':
                yield 'http', {'url': '/', 'phase': 'recon'}
        elif first == 'ffuf':
            result = json.loads((yield 'shell', {'scanner': 'ffuf', 'url': origin + '/FUZZ',
                'wordlist_id': 'fixture', 'threads': 1}))
            assert result['execution']['status'] == 'completed', result
            job_ids.append(result['job_id'])
            records.extend(result['records'])
            selected = next(row for row in result['records'] if row['url'].endswith('/hit'))
            assert len(result['artifacts']['result_refs']) == 1
            page = json.loads((yield 'read_tool_result', {'result_ref': result['artifacts']['result_refs'][0],
                'start_char': 0, 'max_chars': 1500}))
            assert page['content'] and page['sha256']
            triage = json.loads((yield 'workflow', {'action': 'triage_scanner_results', 'job_id': result['job_id'],
                'record_ids': [selected['id']], 'scanner_disposition': 'selected',
                'scanner_reason': 'Selected path can improve existing inventory context'}))
            assert triage['ok'] is True
            yield 'http', {'url': '/hit', 'phase': 'recon'}
            yield 'workflow', {'action': 'triage_scanner_results', 'job_id': result['job_id'],
                'record_ids': [selected['id']], 'scanner_disposition': 'handled',
                'scanner_reason': 'Selected native request recorded; no request parameters observed'}
            yield 'workflow', {'action': 'triage_scanner_results', 'job_id': result['job_id'],
                'record_ids': [], 'remaining': True, 'scanner_disposition': 'deferred',
                'scanner_reason': 'Other paths do not improve this bounded input-context task'}
        listed = json.loads((yield 'workflow', {'action': 'list'}))
        assert len(listed['scanner_jobs']) == (0 if first == 'none' else 1)
        assert not rt.agent.workflow.candidates and not rt.agent.workflow.attack_surface_inputs
    model = DiscoveryScript(script(), prefix='scanner-' + first)
    rt = agent_runtime(tmp_path, origin, model, mode=mode, enumeration=first == 'ffuf')
    events = []
    await rt.agent.run('continue the current bounded discovery task', FakeSignal(), events.append)
    assert not model.errors, model.errors
    assert model.consumed
    if mode == 'whole_target':
        assert not any(event.type == 'done' and event.stop_reason == 'workflow_completed' for event in events)
    scanner_calls = [args for name, args in model.calls if name == 'shell']
    assert len(scanner_calls) == (0 if first == 'none' else 1)
    assert len([event for event in events if event.type == 'tool-started']) == len(scanner_calls)
    assert all(event.invocation for event in events if event.type == 'tool-started')
    assert not rt.policy.worker and rt.policy.active == 0
    if first == 'ffuf':
        assert counters['requests'] == 4  # three scanner sends, one selected native request
        job = rt.agent.workflow.scanner_jobs[job_ids[0]]
        assert job.unresolved_selected == 0 and job.remaining['disposition'] == 'deferred'
        assert job.parse['coverage_complete'] is None
        assert 'active_content_discovery' not in str(rt.agent.workflow.phase_coverage.get('scanner-objective:recon', {}))
    if scanner_calls:
        assert job_ids[0] in render_workflow(rt.agent.workflow)
        # Historical save/load/compaction snapshots carry no process/receipt.
        restored = WorkflowState.from_dict(rt.agent.workflow.to_dict())
        assert restored.scanner_jobs[job_ids[0]].to_dict() == rt.agent.workflow.scanner_jobs[job_ids[0]].to_dict()
        await rt.agent.save()
        loaded = rt.agent.store.load()
        assert job_ids[0] in loaded.workflow.scanner_jobs
        assert 'ExecutionReceipt' not in json.dumps(loaded.workflow.to_dict())


async def test_S_scanner_source_reread_rights_integrity_and_no_worker(tmp_path, wire):
    require_binaries()
    origin, _ = wire
    rt = agent_runtime(tmp_path, origin, FakeClient([]))
    from src.llm.core.types import ToolCall, FunctionCall
    tc = ToolCall('scanner', FunctionCall('shell', json.dumps({'scanner': 'nmap', 'target': '127.0.0.1',
        'ports': str(rt.target.origin().port)})))
    parsed = rt.agent.parse_tool_call(tc)
    rt.agent._tool_call_event(tc, parsed)
    result = await rt.agent.run_parsed_tool_call(tc, parsed, FakeSignal())
    assert not result.err_str, result.result
    ref = next(iter(rt.agent.result_retention.references.values()))
    assert ref.source_kind == 'scanner' and source_provenance(rt.agent, 'shell', parsed.args) is None
    args = {'result_ref': ref.result_ref, 'start_char': 0, 'max_chars': 500}
    rt.policy.scanner_binding.capabilities.mark_unavailable('nmap')
    # Historical reads do not require the old binary or grant identity.
    from src.permission.network.grants import HTTPLimits
    rt.state.http_permissions.activate(origin, HTTPLimits())
    response = await rt.agent.tools.execute('read_tool_result', args, FakeSignal(), rt.prompter)
    assert json.loads(response)['content'] and not rt.policy.worker
    rt.policy.revoke('shell')
    with pytest.raises(ExecutionBlocked):
        await rt.agent.tools.execute('read_tool_result', args, FakeSignal(), rt.prompter)
    rt.policy.restore_tool('shell')
    job = next(iter(rt.agent.workflow.scanner_jobs.values()))
    dataset = rt.root / job.artifacts['normalized']
    dataset.write_text('corrupt')
    with pytest.raises(ResultUnavailable):
        await rt.agent.tools.execute('read_tool_result', args, FakeSignal(), rt.prompter)
    assert len(rt.agent.workflow.scanner_jobs) == 1


async def test_S_scanner_tcp_source_read_denied_after_scope_removal(tmp_path, wire):
    require_binaries()
    origin, _ = wire
    rt = agent_runtime(tmp_path, origin, FakeClient([]))
    rt.state.add_tcp('127.0.0.1', str(rt.target.origin().port))
    from src.llm.core.types import ToolCall, FunctionCall
    tc = ToolCall('tcp-source', FunctionCall('shell', json.dumps({'scanner': 'nmap', 'target': '127.0.0.1',
        'ports': str(rt.target.origin().port)})))
    parsed = rt.agent.parse_tool_call(tc)
    rt.agent._tool_call_event(tc, parsed)
    result = await rt.agent.run_parsed_tool_call(tc, parsed, FakeSignal())
    assert result.status == 'observation'
    ref = next(iter(rt.agent.result_retention.references.values()))
    args = {'result_ref': ref.result_ref, 'start_char': 0, 'max_chars': 500}
    assert await rt.agent.tools.execute('read_tool_result', args, FakeSignal(), rt.prompter)
    rt.state.remove_tcp('127.0.0.1')
    with pytest.raises(ExecutionBlocked):
        await rt.agent.tools.execute('read_tool_result', args, FakeSignal(), rt.prompter)


async def test_scanner_in_another_phase_keeps_observations_without_cross_attestation(tmp_path, wire):
    require_binaries()
    origin, _ = wire
    rt = agent_runtime(tmp_path, origin, FakeClient([]))
    rt.agent.workflow.current_phase = 'validation'
    from src.llm.core.types import ToolCall, FunctionCall
    tc = ToolCall('phase-observation', FunctionCall('shell', json.dumps({'scanner': 'nmap',
        'target': '127.0.0.1', 'ports': str(rt.target.origin().port)})))
    parsed = rt.agent.parse_tool_call(tc)
    rt.agent._tool_call_event(tc, parsed)
    result = await rt.agent.run_parsed_tool_call(tc, parsed, FakeSignal())
    assert result.status == 'observation' and rt.agent.workflow.scanner_jobs
    assert not rt.agent.workflow.phase_coverage and not rt.agent.workflow.phase_completions


def test_semantic_scan_and_bounded_page_fingerprints_ignore_random_refs():
    def fingerprint(name, args, result):
        return _exploration_fingerprint(ExecutedToolCall(name, args, True, ToolCallResult(result, '', 0)), 'http://127.0.0.1:43210')
    assert fingerprint('shell', {'scanner': 'nmap', 'target': '127.0.0.1', 'ports': '80'}, '')
    one = json.dumps({'sha256': 'same', 'actual_start': 1, 'actual_end': 100})
    two = json.dumps({'sha256': 'same', 'actual_start': 2, 'actual_end': 101})
    assert fingerprint('read_tool_result', {'result_ref': 'random1'}, one) == fingerprint('read_tool_result', {'result_ref': 'random2'}, two)


async def test_S_managed_secret_redaction_before_artifact_session_prompt_or_event(tmp_path, wire):
    require_binaries()
    origin, _ = wire
    rt = agent_runtime(tmp_path, origin, FakeClient([]))
    secret = 'scanner-fixture-provider-canary-424242'
    source = dict(rt.binding.wordlists)['fixture']
    source.write_text(secret + '\n')
    rt.policy.internal_secret_values = lambda: (secret,)
    from src.llm.core.types import ToolCall, FunctionCall
    tc = ToolCall('canary', FunctionCall('shell', json.dumps({'scanner': 'ffuf', 'url': origin + '/FUZZ',
        'wordlist_id': 'fixture', 'threads': 1})))
    parsed = rt.agent.parse_tool_call(tc)
    events = [rt.agent._tool_call_event(tc, parsed)]
    result = await rt.agent.run_parsed_tool_call(tc, parsed, FakeSignal(), emit=events.append)
    rt.agent.record_tool_result(tc, parsed, result, events.append, list(rt.agent.history))
    await rt.agent.save()
    assert result.status == 'observation', result.result
    assert secret not in str(result.result) and secret not in repr(events)
    assert secret not in render_workflow(rt.agent.workflow)
    assert secret not in json.dumps(rt.agent.workflow.to_dict())
    for path in (rt.root / '.kagent/scanners').rglob('*'):
        if path.is_file():
            assert secret.encode() not in path.read_bytes()
    for ref in rt.agent.result_retention.references.values():
        text, _ = rt.agent.result_retention.store.resolve(ref, rt.agent.result_retention.scope['generation'])
        assert secret not in text


async def test_S_cache_full_retains_unrelated_results_and_reset_invalidates_refs_but_keeps_scope(tmp_path, wire):
    require_binaries()
    origin, _ = wire
    rt = agent_runtime(tmp_path, origin, FakeClient([]))
    rt.state.add_tcp('127.0.0.1', str(rt.target.origin().port))
    retention = rt.agent.result_retention
    store = retention.store
    preserved = store.put('unrelated retained text', generation=retention.scope['generation'],
        provenance={'kind': 'file'}, tool_name='file_read', tool_call_id='unrelated', status='observation',
        error_kind=None, http_status=None, truncated=False)
    assert preserved is not None
    retention.references[preserved.result_ref] = preserved
    store.max_results = 1
    from src.llm.core.types import ToolCall, FunctionCall
    tc = ToolCall('limited', FunctionCall('shell', json.dumps({'scanner': 'nmap', 'target': '127.0.0.1',
        'ports': str(rt.target.origin().port)})))
    parsed = rt.agent.parse_tool_call(tc)
    rt.agent._tool_call_event(tc, parsed)
    result = await rt.agent.run_parsed_tool_call(tc, parsed, FakeSignal())
    envelope = json.loads(result.result)
    assert envelope['artifacts']['retrieval'] == 'retrieval_limited'
    assert not envelope['artifacts']['result_refs']
    assert store.resolve(preserved, retention.scope['generation'])[0] == 'unrelated retained text'
    assert retention.references == {preserved.result_ref: preserved}
    scopes = (rt.state.allowed_origins, rt.state.allowed_tcp)
    generation = retention.scope['generation']
    await rt.agent.reset()
    assert (rt.state.allowed_origins, rt.state.allowed_tcp) == scopes
    assert not rt.agent.workflow.scanner_jobs and not retention.references and not rt.state.http_permissions.grants
    retention.refresh_scope()
    assert generation != retention.scope['generation']


async def test_missing_private_publication_does_not_publish_unreadable_cache_refs(tmp_path, wire, monkeypatch):
    require_binaries()
    origin, _ = wire
    rt = agent_runtime(tmp_path, origin, FakeClient([]))
    def unavailable(*_args, **_kwargs):
        raise OSError('controlled fixture publication failure')
    monkeypatch.setattr('src.tools.execution.scanner_runner.publish', unavailable)
    from src.llm.core.types import ToolCall, FunctionCall
    tc = ToolCall('publication-unavailable', FunctionCall('shell', json.dumps({'scanner': 'nmap',
        'target': '127.0.0.1', 'ports': str(rt.target.origin().port)})))
    parsed = rt.agent.parse_tool_call(tc)
    rt.agent._tool_call_event(tc, parsed)
    result = await rt.agent.run_parsed_tool_call(tc, parsed, FakeSignal())
    envelope = json.loads(result.result)
    assert envelope['execution']['status'] == 'completed'
    assert envelope['artifacts']['retrieval'] == 'unavailable' and not envelope['artifacts']['result_refs']
    assert not rt.agent.result_retention.references


async def test_S_selected_scanner_context_to_actual_input_candidate_and_honest_validation_handoff(tmp_path, wire):
    require_binaries()
    origin, counters = wire
    input_ids, candidate_ids = [], []
    def fixture_phase(phase, skill):
        # Explicit synthetic prerequisite coverage, as in the existing workflow
        # consumer harness. It does not claim a complete real assessment.
        from src.skills.artifacts import completion_artifact_path
        artifact = completion_artifact_path(rt.agent.skills.get(skill).completion_artifact, origin)
        path = rt.root / artifact
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('Fixture prerequisite; selected observed request context is retained separately.')
        record_completed_phase(rt.agent.workflow, phase, objective_id='scanner-objective',
            target_origin=origin, artifact_ref=artifact)
        rt.agent.workflow.completed_skills.add(skill)
        rt.agent.workflow.completed_artifacts[skill] = artifact
    def script():
        yield 'load_skill', {'name': 'web-enumeration'}
        scanned = json.loads((yield 'shell', {'scanner': 'ffuf', 'url': origin + '/FUZZ', 'wordlist_id': 'fixture', 'threads': 1}))
        selected = next(row for row in scanned['records'] if row['url'].endswith('/context'))
        context = yield 'http', {'url': '/context', 'phase': 'recon'}
        assert 'query_parameter' in context
        observed = json.loads((yield 'workflow', {'action': 'record_input', 'method': 'GET', 'endpoint': '/search',
            'parameter': 'q', 'location': 'query', 'input_type': 'string',
            'source_ref': f"scanner:{scanned['job_id']}:{selected['id']}; selected native documentation /context"}))
        assert observed['ok'] is True
        input_ids.append(observed['input']['id'])
        fixture_phase('enumeration', 'web-enumeration')
        yield 'load_skill', {'name': 'web-input-analysis'}
        yield 'http', {'url': '/search?q=plain', 'phase': 'validation'}
        yield 'http', {'url': '/search?q=%27', 'phase': 'validation'}
        candidate = json.loads((yield 'workflow', {'action': 'record_candidate', 'input_id': input_ids[0],
            'candidate_class': 'sql-injection', 'source_skill': 'web-input-analysis',
            'signals': ['Selected documentation identifies query q; plain baseline 200, harmless single quote 400 query syntax rejected. Fixture signal only; not confirmation.']}))
        assert candidate['ok'] is True and candidate['supported'] is True
        candidate_ids.append(candidate['candidate']['id'])
        yield 'workflow', {'action': 'set_input_disposition', 'input_id': input_ids[0], 'disposition': 'analyzed'}
        fixture_phase('input_analysis', 'web-input-analysis')
        yield 'load_skill', {'name': 'sql-injection'}
        started = json.loads((yield 'workflow', {'action': 'start_validation', 'candidate_id': candidate_ids[0]}))
        assert started['ok'] is True, started
        result = yield 'workflow', {'action': 'record_result', 'candidate_id': candidate_ids[0],
            'skill_name': 'sql-injection', 'outcome': 'insufficient-evidence',
            'deferred_reason': 'Synthetic syntax signal only; no dedicated validation proof performed.'}
        assert json.loads(result)['ok'] is True
    model = DiscoveryScript(script(), prefix='selected-handoff')
    rt = agent_runtime(tmp_path, origin, model, enumeration=True)
    dict(rt.binding.wordlists)['fixture'].write_text('context\nmissing\n')
    events = []
    await rt.agent.run('continue the current selected input-context task', FakeSignal(), events.append)
    assert not model.errors, model.errors
    assert input_ids and candidate_ids
    assert len(rt.agent.workflow.scanner_jobs) == 1 and len(rt.agent.workflow.attack_surface_inputs) == 1
    assert len(rt.agent.workflow.candidates) == 1 and not rt.agent.workflow.eligible_for_finding(candidate_ids[0])
    assert rt.agent.workflow.latest_result(candidate_ids[0]).outcome == 'insufficient-evidence'
    assert counters['requests'] == 5  # two scanner words + one selected document + two harmless native signals


async def test_P_failed_job_valid_observations_have_scanner_refs_without_global_error_success(tmp_path, monkeypatch):
    require_binaries()
    origin = 'http://127.0.0.1:43210'
    rt = agent_runtime(tmp_path, origin, FakeClient([]))
    from src.llm.core.types import ToolCall, FunctionCall
    from tests.security.test_scanner_end_to_end import xml
    import asyncio
    original = asyncio.create_subprocess_exec
    async def fail_with_valid_output(*command, **kwargs):
        output = command[command.index('-oX') + 1]
        code = f'from pathlib import Path;Path({output!r}).write_bytes({xml()!r});raise SystemExit(3)'
        divider = command.index('--')
        return await original(*command[:divider + 1], '/usr/bin/python3', '-I', '-S', '-c', code, **kwargs)
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', fail_with_valid_output)
    tc = ToolCall('partial-observations', FunctionCall('shell', json.dumps({'scanner': 'nmap',
        'target': '127.0.0.1', 'ports': '43210'})))
    parsed = rt.agent.parse_tool_call(tc)
    rt.agent._tool_call_event(tc, parsed)
    result = await rt.agent.run_parsed_tool_call(tc, parsed, FakeSignal())
    envelope = json.loads(result.result)
    assert result.status == 'error' and envelope['execution']['status'] == 'failed'
    assert envelope['execution']['exit_code'] == 3 and envelope['parse']['partial'] is True
    assert len(envelope['records']) == 1 and envelope['artifacts']['result_refs']
    ref = next(iter(rt.agent.result_retention.references.values()))
    assert ref.status == 'observation' and ref.source_kind == 'scanner'
    reread = await rt.agent.tools.execute('read_tool_result', {'result_ref': ref.result_ref, 'start_char': 0,
        'max_chars': 1000}, FakeSignal(), rt.prompter)
    assert '43210' in json.loads(reread)['content']
    assert next(iter(rt.agent.workflow.scanner_jobs.values())).execution['status'] == 'failed'


async def test_S_completed_result_reuse_then_changed_wordlist_requires_fresh_job_review(tmp_path, wire):
    require_binaries()
    origin, _ = wire
    keys = []
    def script():
        yield 'load_skill', {'name': 'web-enumeration'}
        args = {'scanner': 'ffuf', 'url': origin + '/FUZZ', 'wordlist_id': 'fixture', 'threads': 1}
        first = json.loads((yield 'shell', args))
        assert first['execution']['status'] == 'completed'
        keys.append(first['semantic_key'])
        reused = json.loads((yield 'workflow', {'action': 'list'}))
        assert reused['scanner_jobs'][0]['job_id'] == first['job_id']
        # Controller fixture changes its approved tiny resource; the model has
        # no arbitrary wordlist file capability. A new plan/review is required.
        dict(rt.binding.wordlists)['fixture'].write_text('hit\ncontext\n')
        second = json.loads((yield 'shell', args))
        assert second['execution']['status'] == 'completed' and second['job_id'] != first['job_id']
        keys.append(second['semantic_key'])
    model = DiscoveryScript(script(), prefix='reuse-retest')
    rt = agent_runtime(tmp_path, origin, model, enumeration=True)
    events = []
    await rt.agent.run('continue bounded discovery and retain observations', FakeSignal(), events.append)
    assert not model.errors and model.consumed
    assert len(set(keys)) == 2 and len(rt.agent.workflow.scanner_jobs) == 2
    reviews = [call.args[0] for call in rt.operator.ask.call_args_list if call.args[0].tool == 'shell']
    assert len(reviews) == 2 and reviews[0].cache_key != reviews[1].cache_key
