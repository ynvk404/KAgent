"""Phase B admission, representation, persistence, UI and gated rereads."""
import asyncio
from dataclasses import asdict, replace
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from src.agent.agent import (Agent, AgentOptions, AgentRunOptions, ParsedToolCall, ToolCallResult,
                             approximate_message_tokens, bounded_history_for_compaction, MIDTURN_ELISION_PREFIX)
from src.agent.tool_results import source_provenance
from src.engagement.state import EngagementState
from src.llm.core.types import Message, ToolCall, FunctionCall, ChatResponse
from src.permission.permission import AlwaysAllow, AlwaysDeny, Decision, YoloPrompter, UserControlledRefusal
from src.permission.runtime.execution import default_execution_policy, ExecutionBlocked
from src.session.store import Store
from src.session.tool_results import ResultUnavailable, ToolResultStore
from src.skills.registry import Registry as Skills, Skill
from src.target.target import Target
from src.tools.common.registry import Registry
from src.tools.common.outcome import ToolStatus
from src.tools.execution.file import FileReadTool
from src.tools.execution.shell import ShellTool
from src.tools.execution.search import GrepTool
from src.tools.http.http_tool import HTTPTool
from src.ui.render.tool_result_format import build_tool_result_view
from tests.agent.test_output_pipeline import source, assert_anchors, PAYLOADS, SECRET
from tests.state.test_tool_result_store import artifact
from tests.helpers.agent_fakes import FakeClient, FakeSignal, collect


@pytest.fixture
def make(tmp_path, monkeypatch):
    import src.agent.tool_results as module
    monkeypatch.setattr(module, 'project_root', lambda: tmp_path)
    def factory(*, session='session', threshold=3000, bound=False, client=None, prompter=None):
        tools = Registry()
        tools.register(FileReadTool())
        tools.register(ShellTool())
        state = EngagementState()
        p: Any = prompter or AlwaysAllow()
        if bound:
            policy = default_execution_policy(state, tmp_path)
            p.execution_policy = policy
        agent = Agent(AgentOptions(client=client or FakeClient([]), tools=tools, skills=Skills(),
            prompter=p, target=Target('https://target.test'), store=Store.new_with_id(tmp_path/'sessions', session),
            engagement_state=state, prompt_profile='compact', auto_compact_threshold=threshold))
        return agent
    return factory


def record(agent, text=None, *, name='file_read', args=None, working=None, call_id='call', status: ToolStatus='success'):
    working = working if working is not None else list(agent.history)
    events = []
    path = agent.result_retention.store.project / 'source.txt'
    parsed = ParsedToolCall(args or {'path': str(path)}, '{}')
    result = ToolCallResult(text if text is not None else source(40000), '', 0, status=status)
    agent.result_retention.refresh_scope()
    result.retention_generation = agent.result_retention.scope['generation']
    result.retention_provenance = source_provenance(agent, name, parsed.args)
    agent.record_tool_result(ToolCall(call_id, FunctionCall(name, '{}')), parsed, result, events.append, working)
    return working[-1], working, events, result


def reference(agent):
    return next(iter(agent.result_retention.references.values()))


@pytest.mark.parametrize('size,threshold,offloaded', [(100, 3000, False), (40000, 50000, False),
                                                      (40000, 3000, True), (10000, 2500, True),
                                                      (4096, 20000, False)])
def test_selective_pressure_admission(make, size, threshold, offloaded):
    agent = make(threshold=threshold)
    msg, working, events, raw = record(agent, source(size))
    assert bool(msg.tool_result_refs) == offloaded
    assert events[0]['result'] == raw.result
    if offloaded:
        ref = reference(agent)
        assert ref.char_length == len(raw.result)
        assert len(msg.content) < len(raw.result)
        assert agent.result_retention.store.resolve(ref, agent.result_retention.scope['generation'])[0] == raw.result
    else:
        assert msg.content == raw.result


def test_admission_exact_guard_boundary_and_meaningful_saving(make):
    for pressured in (False, True):
        agent = make(threshold=0)
        text = source(10000)
        working = list(agent.history)
        call = Message(role='tool', name='file_read', content=text)
        estimate = approximate_message_tokens([*working, call]) + agent.tools_token_estimate()
        agent.set_auto_compact_threshold(estimate if pressured else estimate + 1)
        msg, _, _, _ = record(agent, text, working=working)
        # Threshold alone does not force storage when envelope cost outweighs
        # the small guard safety-margin reduction.
        assert msg.tool_result_refs is None
    agent = make(threshold=3000)
    msg, _, _, _ = record(agent, source(10000))
    assert msg.tool_result_refs


@pytest.mark.parametrize('name', ['workflow', 'validate', 'read_evidence', 'confirm_finding', 'review',
                                  'permissions_status', 'requested_goals', 'coverage', 'load_skill',
                                  'ask_user', 'mcp_fixture', 'unknown'])
def test_semantic_names_never_generic_offloaded(make, name):
    agent = make()
    class Semantic:
        def name(self): return name
        def description(self): return 'semantic receipt'
        def schema(self): return {'type':'object','properties':{}}
        def requires_permission(self): return False
        async def run(self, args, signal, prompter): return '{}'
        def context_reduction_policy(self): return 'preserve'
    agent.tools.tools[name] = Semantic()
    msg, _, _, _ = record(agent, name=name)
    assert msg.tool_result_refs is None and not agent.result_retention.references
    assert msg.content == source(40000)


def test_adaptive_does_not_imply_eligibility_and_no_history_backfill(make):
    agent = make()
    agent.tools.register(GrepTool())
    assert source_provenance(agent, 'GrepTool', {'path': '.'}) is None
    old = Message(role='tool', name='file_read', tool_call_id='old', content=source(40000))
    agent.history.append(old)
    working = list(agent.history)
    agent.guard_working_context(working, lambda _: None)
    assert not agent.result_retention.references
    assert old.tool_result_refs is None


def test_http_validation_and_candidate_receipts_excluded(make):
    agent = make()
    tool = HTTPTool(agent.target, agent.engagement_state)
    agent.tools.register(tool)
    for args in ({'phase':'validation', 'url':'/'}, {'phase':'impact', 'url':'/'},
                 {'phase':'recon', 'candidate_id':'candidate'}):
        assert source_provenance(agent, 'http', args) is None
    provenance = source_provenance(agent, 'http', {'phase':'recon', 'url':'/'})
    assert provenance is not None and provenance['kind'] == 'http'


@pytest.mark.asyncio
async def test_distributed_preview_gap_reread_and_live_visibility(make):
    agent = make()
    raw = source(100000)
    raw = raw[:12500] + 'GAP-EVIDENCE' + raw[12511:]
    msg, working, events, execution = record(agent, raw)
    assert_anchors(msg.content)
    assert 'GAP-EVIDENCE' not in msg.content
    assert events[0]['result'] == raw == execution.result
    assert build_tool_result_view(events[0]['result']).full == raw
    ref = reference(agent)
    response = json.loads(await agent.tools.execute('read_tool_result', {
        'result_ref':ref.result_ref, 'start_char':12500, 'max_chars':100}, FakeSignal(), agent.prompter))
    assert response['content'].startswith('GAP-EVIDENCE')
    assert response['actual_start'] == 12500 and response['actual_end'] == 12600
    assert response['total_length'] == len(raw) == ref.char_length
    assert len(agent.result_retention.references) == 1
    assert agent.history[-1] is msg
    for extra in (4000, 8000):
        working.insert(1, Message(role='assistant', content='x'*extra))
        agent.guard_working_context(working, lambda _:None, AgentRunOptions(tools=False))
        assert working[-1].content.count(MIDTURN_ELISION_PREFIX) == 4
        assert_anchors(working[-1].content)
        assert working[-1].tool_result_refs == msg.tool_result_refs
    assert '/.kagent/' not in working[-1].content


@pytest.mark.parametrize('payload', PAYLOADS)
@pytest.mark.asyncio
async def test_large_sanitized_artifact_ui_and_reread(make, payload):
    agent = make()
    msg, _, events, execution = record(agent, source(40000) + '\n' + payload)
    ref = reference(agent)
    full, _ = agent.result_retention.store.resolve(ref, agent.result_retention.scope['generation'])
    assert SECRET not in full + msg.content + events[0]['result']
    assert '{INJECTION_POINT}' in full
    assert execution.result.endswith(payload)
    assert events[0]['result'] == full
    await agent.save()
    assert SECRET not in agent.store.path.read_text()
    assert SECRET.encode() not in artifact(agent.result_retention.store, ref).read_bytes()


@pytest.mark.asyncio
async def test_sanitizer_failure_no_artifact_no_raw_secret(make, monkeypatch):
    import src.agent.agent as module
    monkeypatch.setattr(module, 'redact_payload', lambda _: (_ for _ in ()).throw(ValueError(SECRET)))
    agent = make()
    msg, _, events, execution = record(agent, SECRET*3000)
    assert msg.tool_result_refs is None
    assert 'unavailable' in msg.content
    assert SECRET not in msg.content + events[0]['result']
    assert execution.status == 'success' and execution.result == SECRET*3000
    assert not agent.result_retention.references


@pytest.mark.parametrize('failure', ['quota_result', 'quota_session', 'disk'])
def test_storage_failure_fallback_inline_and_phase_a_bounds(make, monkeypatch, failure):
    agent = make()
    store = agent.result_retention.store
    if failure == 'quota_result': store.per_result = 100
    elif failure == 'quota_session': store.per_session = 100
    else:
        monkeypatch.setattr(store, 'put', lambda *a, **k: (_ for _ in ()).throw(OSError('disk full')))
    msg, working, events, execution = record(agent)
    assert msg.tool_result_refs is None and msg.tool_status == 'success'
    assert msg.content == source(40000) == events[0]['result']
    agent.guard_working_context(working, lambda _:None)
    assert len(working[-1].content) < len(msg.content)
    assert execution.result == source(40000) and execution.err_str == ''
    assert not agent.result_retention.references


@pytest.mark.asyncio
async def test_http_200_unsafe_cache_checkpoint_preserves_output_and_continues(make, tmp_path, monkeypatch):
    calls = [ChatResponse(Message('assistant', '', tool_calls=[ToolCall('http-result', FunctionCall(
        'http', json.dumps({'url': '/output', 'method': 'GET', 'phase': 'recon',
                            'max_response_bytes': 65536})))]), 'tool_calls'),
        ChatResponse(Message('assistant', 'HTTP result inspected; done.'), 'stop')]
    client = FakeClient(calls)
    agent = make(client=client, threshold=0)
    agent.tools.register(HTTPTool(agent.target, agent.engagement_state))
    directory = tmp_path / '.kagent'
    directory.mkdir(mode=0o700)
    directory.chmod(0o777)  # Reproduce a Windows mount's reported mode.
    payload = source(40000)
    sent = []
    real_client = httpx.AsyncClient
    def transport(request):
        sent.append(request)
        return httpx.Response(200, text=payload, request=request)
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: real_client(
        transport=httpx.MockTransport(transport), **kwargs))
    original_chat = client.chat
    async def chat(request, signal=None):
        if client.requests:
            saved = agent.store.load()
            full = next(m for m in saved.messages if m.name == 'http')
            assert payload in full.content and full.tool_http_status == 200
            assert full.tool_result_refs is None
            assert not agent._tool_results_unsaved
        response = await original_chat(request, signal)
        agent.set_auto_compact_threshold(3000)
        return response
    monkeypatch.setattr(client, 'chat', chat)
    events = []
    await agent.run('Read the bounded HTTP response', FakeSignal(), events.append)
    assert len(sent) == 1 and len(client.requests) == 2
    result = next(e for e in events if e.get('type') == 'tool-result')
    assert result['http_status'] == 200 and payload in result['result']
    represented = next(m for m in client.requests[1].messages if m.name == 'http')
    assert len(represented.content) < len(result['result'])
    assert not agent.result_retention.references and not agent.result_retention.pending
    assert not any(e.get('type') == 'error' for e in events)
    assert any(e.get('type') == 'decision' and 'cache unavailable' in e.get('summary', '')
               and 'session history' in e['summary'] for e in events)
    assert not (directory / 'tool-results').exists()
    assert directory.stat().st_mode & 0o777 == 0o777
    restored = make(threshold=0)
    restored.resume_saved()
    assert payload in next(m.content for m in restored.history if m.name == 'http')


@pytest.mark.asyncio
async def test_unsafe_cache_terminal_checkpoint_and_session_save_failure(make, tmp_path, monkeypatch):
    agent = make()
    directory = tmp_path / '.kagent'
    directory.mkdir(mode=0o700)
    directory.chmod(0o777)
    msg, working, _, _ = record(agent)
    agent._tool_checkpoint_request = agent._request_for_messages(working, agent.tools.as_llm_tools())
    save = agent.store.save
    monkeypatch.setattr(agent.store, 'save', AsyncMock(side_effect=OSError('session save failed')))
    with pytest.raises(OSError, match='session save failed'):
        await agent._finish_tool_results()
    assert agent._tool_results_unsaved
    assert next(iter(agent.result_retention.pending.values())).original == msg.content
    assert not agent.result_retention.references
    monkeypatch.setattr(agent.store, 'save', save)
    await agent._finish_tool_results()
    assert not agent._tool_results_unsaved
    assert next(m.content for m in agent.store.load().messages if m.role == 'tool') == msg.content
    assert not (directory / 'tool-results').exists()


@pytest.mark.parametrize('failure', ['normal', 'missing', 'corrupt'])
@pytest.mark.asyncio
async def test_resume_uses_preview_without_hydration_and_ref_survives(make, failure, monkeypatch):
    agent = make()
    msg, _, _, _ = record(agent)
    ref = reference(agent)
    await agent.save()
    serialized = agent.store.path.read_text()
    assert source(40000) not in serialized
    if failure == 'missing': artifact(agent.result_retention.store, ref).unlink()
    elif failure == 'corrupt':
        path = artifact(agent.result_retention.store, ref)
        path.write_bytes(path.read_bytes() + b'corrupt')
    restored = make()
    monkeypatch.setattr(restored.result_retention.store, 'resolve', lambda *a: pytest.fail('resume hydrated artifact'))
    restored.resume_saved()
    assert restored.history[-1].content == msg.content
    assert restored.history[-1].tool_result_refs == msg.tool_result_refs
    assert ref.result_ref in restored.sys_prompt
    monkeypatch.undo()
    if failure == 'normal':
        response = await restored.tools.execute('read_tool_result', {
            'result_ref':ref.result_ref, 'start_char':0, 'max_chars':50}, FakeSignal(), restored.prompter)
        assert 'HEAD-CANARY' in response
    else:
        with pytest.raises(ResultUnavailable):
            await restored.tools.execute('read_tool_result', {
                'result_ref':ref.result_ref, 'start_char':0, 'max_chars':50}, FakeSignal(), restored.prompter)
        assert restored.history[-1].content == msg.content


@pytest.mark.asyncio
async def test_old_session_compatibility(make):
    agent = make()
    agent.store.path.parent.mkdir()
    agent.store.path.write_text(json.dumps({'messages':[{'role':'user','content':'legacy'}]}))
    agent.resume_saved()
    assert agent.history[-1].content == 'legacy' and not agent.result_retention.references


@pytest.mark.asyncio
async def test_structured_reference_survives_compaction_without_prose_or_hydration(make, monkeypatch):
    agent = make()
    agent.history.append(Message(role='user', content='old request' + 'x'*40000))
    msg, _, _, _ = record(agent)
    ref = reference(agent)
    private = Message(role='assistant', content='short final', reasoning_content='private-state',
                      provider_state_provider='deepseek', provider_state_model='model')
    agent.history.append(private)
    monkeypatch.setattr(agent.result_retention.store, 'resolve', lambda *a: pytest.fail('compaction hydrated artifact'))
    monkeypatch.setattr(agent, 'learn_intelligence', AsyncMock())
    compact_input = bounded_history_for_compaction(agent.history[1:])
    assert source(40000) not in compact_input
    await agent.apply_compaction_summary('## Current objective\n- Continue offline inspection',
                                         list(agent.history), 'test')
    assert not any(m.role == 'tool' for m in agent.history)
    assert ref.result_ref in agent.sys_prompt
    assert agent.history[0].tool_result_refs == [asdict(ref)]
    assert agent.history[-1].reasoning_content == 'private-state'
    resumed = make()
    resumed.resume_saved()
    assert reference(resumed) == ref
    assert ref.result_ref in resumed.sys_prompt
    assert source(40000) not in ''.join(m.content for m in resumed.history)


@pytest.mark.parametrize('args', [(-100, 20), (999999, 100), (0, 999999), (2, -5), (2, 3)])
@pytest.mark.asyncio
async def test_reread_character_ranges_bounded_and_no_recursive_chain(make, args):
    agent = make()
    text = '雨🙂\n"\\' * 8000
    record(agent, text)
    ref = reference(agent)
    start, maximum = args
    reply = await agent.tools.execute('read_tool_result', {'result_ref':ref.result_ref,
        'start_char':start, 'max_chars':maximum}, FakeSignal(), agent.prompter)
    result = json.loads(reply)
    assert len(reply) <= 2000
    assert result['content'] == text[result['actual_start']:result['actual_end']]
    assert result['offset_unit'] == 'unicode_characters'
    msg, _, _, _ = record(agent, reply, name='read_tool_result')
    assert msg.content == reply and msg.tool_result_refs is None
    assert len(agent.result_retention.references) == 1


@pytest.mark.parametrize('attack', ['session', 'project', 'target', 'target_back', 'revoked', 'protected', 'no_policy', 'adapter'])
@pytest.mark.asyncio
async def test_reread_current_rights_and_scope(make, tmp_path, attack):
    agent = make(bound=True)
    record(agent)
    ref = reference(agent)
    if attack == 'session':
        reader = make(session='other', bound=True)
    else: reader = agent
    if attack == 'project':
        reader.prompter.execution_policy.root = tmp_path / 'other'
    elif attack in {'target', 'target_back'}:
        reader.target.set_base_url('https://another.test')
        reader.result_retention.refresh_scope()
        if attack == 'target_back': reader.target.set_base_url('https://target.test')
    elif attack == 'revoked': reader.prompter.execution_policy.revoke('file_read')
    elif attack == 'protected': reader.prompter.execution_policy.protected += (tmp_path/'source.txt',)
    elif attack == 'no_policy': reader.prompter.execution_policy = None
    elif attack == 'adapter': reader.tools.tools['file_read'] = ShellTool(tool_name='file_read')
    with pytest.raises((ResultUnavailable, ExecutionBlocked)):
        await reader.tools.execute('read_tool_result', {'result_ref':ref.result_ref,
            'start_char':0,'max_chars':100}, FakeSignal(), reader.prompter)


@pytest.mark.asyncio
async def test_sensitive_read_requires_fresh_source_gate_and_receipt(make, tmp_path):
    class Operator(AlwaysAllow):
        def __init__(self):
            super().__init__()
            self.requests = []
        async def ask(self, request, signal=None):
            self.requests.append(request)
            return Decision.DENY if request.tool == 'file' else Decision.ALLOW_ONCE
    operator = Operator()
    agent = make(bound=True, prompter=operator)
    sensitive = tmp_path / '.env'
    record(agent, args={'path':str(sensitive)})
    ref = reference(agent)
    reader = agent.tools.get('read_tool_result')
    args = {'result_ref':ref.result_ref, 'start_char':0, 'max_chars':100}
    with pytest.raises(ExecutionBlocked, match='receipt'):
        await reader.run(args, FakeSignal(), operator)
    for _ in range(2):
        with pytest.raises(UserControlledRefusal):
            await agent.tools.execute('read_tool_result', args, FakeSignal(), operator)
    assert [r.tool for r in operator.requests] == ['read_tool_result','file','read_tool_result','file']
    assert all(r.no_session_cache for r in operator.requests)
    assert agent.prompter.execution_policy.active == 0


@pytest.mark.asyncio
async def test_denied_reread_no_original_execution_or_history_hydration(make, monkeypatch):
    agent = make()
    msg, _, _, _ = record(agent)
    ref = reference(agent)
    monkeypatch.setattr(agent.tools.get('file_read'), 'run', AsyncMock(side_effect=AssertionError('rerun')))
    with pytest.raises(UserControlledRefusal):
        await agent.tools.execute('read_tool_result', {'result_ref':ref.result_ref,'start_char':0,'max_chars':100},
                                  FakeSignal(), AlwaysDeny())
    assert agent.history[-1] is msg
    assert not agent.tools.get('file_read').run.called


@pytest.mark.asyncio
async def test_save_failure_keeps_published_ref_and_safe_orphan(make, monkeypatch):
    agent = make()
    msg, _, _, _ = record(agent)
    ref = reference(agent)
    monkeypatch.setattr(agent.store, 'save', AsyncMock(side_effect=OSError('save failed')))
    with pytest.raises(OSError): await agent.save()
    assert msg.tool_result_refs and artifact(agent.result_retention.store, ref).exists()
    assert not agent.store.path.exists()
    count = agent.result_retention.store.cleanup(live_refs={ref.result_ref}, saved_refs=set(), stale_before=1e20)
    assert count == 0
    agent.result_retention.references.clear()
    agent.history.clear()
    assert agent.result_retention.store.cleanup(live_refs=set(), saved_refs=set(), stale_before=1e20) == 1


@pytest.mark.asyncio
async def test_real_file_execution_full_ui_preview_history_and_resume(make, tmp_path):
    raw = source(100000) + '\nAuthorization: Bearer ' + SECRET
    path = tmp_path/'source.txt'
    path.write_text(raw)
    call = ToolCall('real-file', FunctionCall('file_read', json.dumps({'path':str(path)})))
    client = FakeClient([ChatResponse(Message(role='assistant',content='',tool_calls=[call]), 'tool_calls'),
                         ChatResponse(Message(role='assistant',content='done'), 'stop')])
    agent = make(client=client)
    collector = collect()
    await agent.run('inspect local output', FakeSignal(), collector['sink'])
    full = next(e.result for e in collector['events'] if e.type == 'tool-result')
    request = next(m for m in client.requests[1].messages if m.role == 'tool')
    assert len(full) > 100000 and SECRET not in full
    assert len(request.content) < len(full) and request.tool_result_refs
    assert_anchors(request.content)
    assert agent.result_retention.pending == {} and agent._bounded_results == {}
    restored = make()
    restored.resume_saved()
    assert next(m.content for m in restored.history if m.role == 'tool') == request.content


@pytest.mark.asyncio
async def test_generic_validation_boundary_and_active_skill_unchanged(make):
    agent = make(bound=True)
    record(agent)
    ref = reference(agent)
    policy = agent.prompter.execution_policy
    original = policy.generic_validation
    class Restricted:
        def validate_tool(self, tool, args):
            if tool.name() == 'read_tool_result':
                raise ValueError('generic capability unavailable: read_tool_result')
    policy.generic_validation = Restricted()
    args = {'result_ref':ref.result_ref, 'start_char':0, 'max_chars':100}
    with pytest.raises(ExecutionBlocked, match='generic capability'):
        await agent.tools.execute('read_tool_result', args, FakeSignal(), agent.prompter)
    assert not agent.is_tool_allowed('read_tool_result', args).ok
    policy.generic_validation = original
    agent.skills.add(Skill(name='fixture', description='fixture', tools=['file_read'],
        disable_model_invocation=False, path='/fixture/SKILL.md', body=''))
    agent.active_skills.add('fixture')
    assert agent.is_tool_allowed('read_tool_result', args).ok
    assert agent.tools.context_reduction_policy('read_tool_result') == 'preserve'


@pytest.mark.asyncio
async def test_shell_profile_changes_and_http_origin_revocation(make):
    agent = make(bound=True)
    policy = agent.prompter.execution_policy
    policy.worker = SimpleNamespace(summary=lambda: 'fixture isolated resource profile')
    msg, _, _, _ = record(agent, name='shell', args={'command':'fixture'})
    ref = reference(agent)
    policy.protected += (policy.root/'new-protected',)
    with pytest.raises(ExecutionBlocked, match='profile changed'):
        await agent.tools.execute('read_tool_result', {'result_ref':ref.result_ref,'start_char':0,'max_chars':100},
                                  FakeSignal(), agent.prompter)
    network = make(session='http', bound=True)
    network.tools.register(HTTPTool(network.target, network.engagement_state))
    record(network, name='http', args={'phase':'recon','url':'/fixture'})
    http_ref = reference(network)
    from src.permission.network.grants import HTTPLimits
    rights = network.engagement_state.http_permissions
    grant = rights.activate(network.target.base_url(), HTTPLimits())
    rights.revoke(grant.id)
    with pytest.raises(ExecutionBlocked, match='origin-revoked'):
        await network.tools.execute('read_tool_result', {'result_ref':http_ref.result_ref,'start_char':0,'max_chars':100},
                                    FakeSignal(), network.prompter)


@pytest.mark.asyncio
async def test_sequential_live_results_survive_rebound_and_reset(make):
    agent = make()
    working = list(agent.history)
    originals = [source(40000), source(100000)]
    for index, text in enumerate(originals):
        record(agent, text, working=working, call_id=str(index))
    agent.guard_working_context(working, lambda _:None)
    refs = list(agent.result_retention.references.values())
    assert len(refs) == len({ref.result_ref for ref in refs}) == 2
    for msg in working[-2:]:
        assert_anchors(msg.content)
        assert msg.content.count(MIDTURN_ELISION_PREFIX) == 4
    for ref, original in zip(refs, originals):
        assert agent.result_retention.store.resolve(ref, agent.result_retention.scope['generation'])[0] == original
    await agent.reset()
    with pytest.raises(ResultUnavailable): agent.result_retention.lookup(refs[0].result_ref)
    assert artifact(agent.result_retention.store, refs[0]).exists()


@pytest.mark.asyncio
async def test_no_ref_before_publication_and_authoritative_evidence_unchanged(make, monkeypatch, tmp_path):
    agent = make()
    evidence = tmp_path/'artifacts/proof.md'
    evidence.parent.mkdir()
    evidence.write_text('authoritative fixture')
    original = evidence.read_bytes()
    store = agent.result_retention.store
    def fail(*args, **kwargs):
        assert not agent.result_retention.references
        assert not any(msg.tool_result_refs for msg in agent.history)
        raise OSError('publication failure')
    monkeypatch.setattr(store, 'put', fail)
    msg, _, _, _ = record(agent)
    await agent.save()
    assert msg.tool_result_refs is None
    assert 'tr_' not in agent.store.path.read_text()
    assert evidence.read_bytes() == original


@pytest.mark.parametrize('mutation', ['target', 'source', 'missing_identity'])
def test_execution_snapshot_cannot_be_rebound_at_record_time(make, mutation):
    agent = make()
    path = agent.result_retention.store.project / 'source.txt'
    args = {'path':str(path)}
    captured = source_provenance(agent, 'file_read', args)
    generation = agent.result_retention.scope['generation']
    result = ToolCallResult(source(40000), '', 0, retention_generation=generation,
                            retention_provenance=captured)
    if mutation == 'target':
        agent.target.set_base_url('https://another.test')
    elif mutation == 'source':
        args = {'path':str(path.with_name('different.txt'))}
    else:
        result.retention_generation = None
        result.retention_provenance = None
    events, working = [], list(agent.history)
    agent.record_tool_result(ToolCall('snapshot', FunctionCall('file_read','{}')),
        ParsedToolCall(args,'{}'), result, events.append, working)
    assert working[-1].tool_result_refs is None
    assert working[-1].content == events[0]['result'] == source(40000)
    assert not agent.result_retention.references


@pytest.mark.asyncio
async def test_real_concurrent_calls_keep_distinct_execution_snapshots(make, tmp_path):
    agent = make(bound=True)
    paths = [tmp_path/f'concurrent-{i}.txt' for i in range(2)]
    for i,path in enumerate(paths): path.write_text(source(40000+i*10000))
    calls = [ToolCall(str(i),FunctionCall('file_read',json.dumps({'path':str(path)})))
             for i,path in enumerate(paths)]
    working = list(agent.history)
    batch = await agent.execute_tool_calls(calls,FakeSignal(),lambda _:None,working)
    assert len(batch.calls) == 2
    refs = list(agent.result_retention.references.values())
    assert len(refs) == len({ref.result_ref for ref in refs}) == 2
    for ref in refs:
        text, provenance = agent.result_retention.store.resolve(ref,agent.result_retention.scope['generation'])
        assert text == paths[int(ref.tool_call_id)].read_text()
        assert provenance['path'] == str(paths[int(ref.tool_call_id)])


def test_compaction_retains_pointer_without_nested_preview_markers(make):
    agent = make()
    msg, _, _, _ = record(agent)
    ref = reference(agent)
    rendered = bounded_history_for_compaction([msg])
    assert ref.result_ref in rendered and MIDTURN_ELISION_PREFIX not in rendered
    assert 'not evidence or authorization' in rendered
    assert source(40000) not in rendered


def test_target_rotation_during_turn_keeps_old_preview_without_rebounding(make):
    agent = make()
    msg, working, _, _ = record(agent)
    ref = reference(agent)
    before = msg.content
    # Trusted originals may still be in the mid-turn cache when scope changes.
    assert id(msg) in agent._bounded_results
    agent.apply_target_base_url('https://other.test')
    working.insert(1, Message(role='assistant', content='x'*40000))
    agent.guard_working_context(working, lambda _:None)
    assert working[-1].content == before
    assert working[-1].tool_result_refs == msg.tool_result_refs
    with pytest.raises(ResultUnavailable):
        agent.result_retention.lookup(ref.result_ref)


@pytest.mark.asyncio
async def test_missing_token_artifact_keeps_independent_authoritative_evidence(make, tmp_path):
    agent = make()
    record(agent)
    ref = reference(agent)
    evidence = tmp_path/'artifacts/proof.md'
    evidence.parent.mkdir()
    evidence.write_text('independent authoritative proof')
    from src.workflow.evidence import EvidenceArtifact
    proof = EvidenceArtifact.capture('fixture',str(evidence.relative_to(tmp_path)),tmp_path)
    before = agent.workflow.to_dict()
    artifact(agent.result_retention.store,ref).unlink()
    with pytest.raises(ResultUnavailable):
        await agent.tools.execute('read_tool_result',{'result_ref':ref.result_ref,'start_char':0,'max_chars':10},
                                  FakeSignal(),agent.prompter)
    assert proof.is_resolvable(tmp_path) and agent.workflow.to_dict() == before


@pytest.mark.parametrize('relative', ['.kagent/control.json', 'artifacts/findings/confirmed.md',
                                      'artifacts/generic-validation/proof.md', 'findings/legacy.md',
                                      'ordinary-known-proof.md'])
def test_authoritative_and_managed_file_sources_excluded(make, relative):
    agent = make()
    root = agent.result_retention.store.project
    path = root / relative
    if relative == 'ordinary-known-proof.md':
        path.write_text('proof')
        from src.workflow.evidence import EvidenceArtifact
        proof = EvidenceArtifact.capture('candidate', relative, root)
        agent.workflow.evidence[proof.id] = proof
    msg, _, _, _ = record(agent, args={'path':str(path)})
    assert not msg.tool_result_refs and msg.content == source(40000)
    assert source_provenance(agent, 'file_read', {'path':str(path)}) is None
