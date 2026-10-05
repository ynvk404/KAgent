"""Independent audit: assert missing Phase B invariants through real execution.

These tests reproduce the audited failures and exercise their fixes. No synthetic
execution provenance or controller-created authorization is supplied.
"""
from dataclasses import asdict
import io
import json
import os

import pytest

from src.agent.agent import Agent, AgentOptions
from src.llm.core.types import FunctionCall, ToolCall
from src.permission.permission import AlwaysAllow, Decision
from src.permission.permission import UserControlledRefusal
from src.session.store import Store
from src.session.tool_results import ResultReference, ResultUnavailable
from src.skills.registry import Skill
from src.target.target import Target
from src.tools.common.registry import InvalidToolArguments
from tests.agent.test_output_pipeline import source
from tests.agent.test_tool_result_offloading import make
from tests.agent.test_output_pipeline import SECRET
from tests.helpers.agent_fakes import FakeClient, FakeSignal


async def execute_file(agent, path):
    call = ToolCall('audit-file', FunctionCall('file_read', json.dumps({'path': str(path)})))
    working = list(agent.history)
    batch = await agent.execute_tool_calls([call], FakeSignal(), lambda _: None, working)
    assert batch.calls[0].result.status == 'success'
    assert working[-1].tool_result_refs
    return next(iter(agent.result_retention.references.values()))


@pytest.mark.asyncio
@pytest.mark.parametrize('direction', ['own', 'foreign'])
async def test_shared_registry_keeps_first_agent_reader_binding(make, tmp_path, direction):
    first = make(bound=True)
    path = tmp_path / 'source.txt'
    text = source(40000)
    path.write_text(text)
    ref = await execute_file(first, path)
    args = {'result_ref': ref.result_ref, 'start_char': 0, 'max_chars': 100}
    # Establish that the actual execution-produced reference is readable.
    before = await first.tools.execute('read_tool_result', args, FakeSignal(), first.prompter)
    assert json.loads(before)['content'] == text[:100]
    second = Agent(AgentOptions(client=FakeClient([]), tools=first.tools, skills=first.skills,
        prompter=AlwaysAllow(), target=Target('https://other.test'),
        store=Store.new_with_id(tmp_path / 'sessions', 'second'),
        prompt_profile='compact', auto_compact_threshold=3000))
    if direction == 'foreign':
        foreign_path = tmp_path / 'second-source.txt'
        foreign_path.write_text('SECOND-SESSION-ONLY\n' + text)
        foreign_ref = await execute_file(second, foreign_path)
        args['result_ref'] = foreign_ref.result_ref
        call = ToolCall('foreign-reader', FunctionCall('read_tool_result', json.dumps(args)))
        result = await first.run_parsed_tool_call(call, first.parse_tool_call(call), FakeSignal())
        assert result.status == 'error', (
            f'first Agent must reject another session/target; returned: {result.result}'
        )
        return
    # Constructing another Agent must not redirect the first Agent's capability.
    after = await first.tools.execute('read_tool_result', args, FakeSignal(), first.prompter)
    assert json.loads(after)['content'] == text[:100]


@pytest.mark.parametrize('field', ['status', 'source_kind'])
@pytest.mark.asyncio
async def test_malformed_descriptor_does_not_make_session_unreadable(make, tmp_path, field):
    agent = make(bound=True)
    path = tmp_path / 'source.txt'
    path.write_text(source(40000))
    ref = await execute_file(agent, path)
    document = json.loads(agent.store.path.read_text())
    invalid = asdict(ref)
    invalid[field] = []
    document['messages'][0]['tool_result_refs'] = [invalid]
    agent.store.path.write_text(json.dumps(document))
    loaded = agent.store.load()
    assert loaded.messages[0].tool_result_refs is None
    assert any(message.role == 'tool' for message in loaded.messages)


@pytest.mark.asyncio
@pytest.mark.parametrize('bound', [True, False])
@pytest.mark.parametrize('change_skill', [True, False])
async def test_source_skill_rights_rechecked_after_reader_approval(make, tmp_path, bound, change_skill):
    class Operator(AlwaysAllow):
        agent: Agent | None = None
        reviews = 0

        async def ask(self, request, signal=None):
            if request.tool == 'read_tool_result':
                self.reviews += 1
                assert self.agent is not None
                if change_skill:
                    self.agent.active_skills = {'restricted'}
            return Decision.ALLOW_ONCE

    operator = Operator()
    agent = make(prompter=operator, bound=bound)
    if bound:
        from src.permission.worker.worker import OfflineWorker
        policy = agent.prompter.execution_policy
        policy.worker = await OfflineWorker.available(policy.root, policy.protected)
        assert policy.worker is not None, 'this regression requires the configured real Linux worker'
    operator.agent = agent
    path = tmp_path / 'source.txt'
    path.write_text(source(40000))
    command_path = '/work/source.txt' if bound else str(path)
    call = ToolCall('audit-shell', FunctionCall('shell', json.dumps({'command': f"cat '{command_path}'"})))
    working = list(agent.history)
    batch = await agent.execute_tool_calls([call], FakeSignal(), lambda _: None, working)
    assert batch.calls[0].result.status == 'success', batch.calls[0].result.result
    assert working[-1].tool_result_refs
    for name, tools in [('allowed', ['shell']), ('restricted', ['http'])]:
        agent.skills.add(Skill(name=name, description=name, tools=tools,
            disable_model_invocation=False, path='/fixture/SKILL.md', body=''))
    agent.active_skills = {'allowed'}
    ref = next(iter(agent.result_retention.references.values()))
    args = {'result_ref': ref.result_ref, 'start_char': 0, 'max_chars': 100}
    assert agent.is_tool_allowed('read_tool_result', args).ok
    read_call = ToolCall('audit-reader', FunctionCall('read_tool_result', json.dumps(args)))
    result = await agent.run_parsed_tool_call(read_call, agent.parse_tool_call(read_call), FakeSignal())
    if change_skill:
        assert not agent.is_tool_allowed('read_tool_result', args).ok
        assert result.status == 'error', 'source capability revoked during approval must block payload retrieval'
        from src.permission.runtime.execution import ExecutionBlocked
        reviewed = operator.reviews
        with pytest.raises(ExecutionBlocked):
            await agent.tools.execute('read_tool_result', args, FakeSignal(), agent.prompter)
        assert operator.reviews == reviewed, 'already unavailable source must be checked before review'
    else:
        assert agent.is_tool_allowed('read_tool_result', args).ok
        assert result.status == 'success', result.err_str
        assert json.loads(result.result)['content'] == batch.calls[0].result.result[:100]
    if bound:
        assert policy.active == 0


@pytest.mark.asyncio
async def test_provenance_header_does_not_prefetch_payload_before_sensitive_gate(make, tmp_path, monkeypatch):
    class Operator(AlwaysAllow):
        deny_sensitive = False

        async def ask(self, request, signal=None):
            if self.deny_sensitive and request.tool == 'file':
                return Decision.DENY
            return Decision.ALLOW_ONCE

    operator = Operator()
    agent = make(bound=True, prompter=operator)
    path = tmp_path / '.env'
    marker = 'AUDIT-PAYLOAD-MUST-NOT-BE-READ-BEFORE-SENSITIVE-GATE'
    path.write_text(marker + '\n' + source(40000))
    ref = await execute_file(agent, path)
    operator.deny_sensitive = True
    reads = []
    original_fdopen = os.fdopen
    original_read = os.read

    class ObservedFile(io.FileIO):
        def readinto(self, buffer):
            count = super().readinto(buffer)
            reads.append(bytes(buffer[:count]))
            return count

    def observed_fdopen(fd, mode):
        if mode == 'rb':
            return io.BufferedReader(ObservedFile(fd, 'rb'))
        return original_fdopen(fd, mode)

    monkeypatch.setattr(os, 'fdopen', observed_fdopen)
    def observed_read(fd, size):
        data = original_read(fd, size)
        reads.append(data)
        return data
    monkeypatch.setattr(os, 'read', observed_read)
    with pytest.raises(UserControlledRefusal):
        await agent.tools.execute('read_tool_result', {'result_ref': ref.result_ref,
            'start_char': 0, 'max_chars': 100}, FakeSignal(), agent.prompter)
    assert marker.encode() not in b''.join(reads), 'header-only authorization path must not read protected payload'
    assert reads and b'"provenance"' in b''.join(reads)


@pytest.mark.asyncio
@pytest.mark.parametrize('shared', [True, False])
@pytest.mark.parametrize('reverse', [True, False])
async def test_reader_ownership_in_both_construction_orders(make, tmp_path, shared, reverse):
    early = make(bound=True)
    later = Agent(AgentOptions(client=FakeClient([]), tools=early.tools if shared else make().tools,
        skills=early.skills, prompter=AlwaysAllow(), target=Target('https://other.test'),
        store=Store.new_with_id(tmp_path / 'sessions', 'later'), prompt_profile='compact',
        auto_compact_threshold=3000))
    agents = [later, early] if reverse else [early, later]
    refs = []
    for index, agent in enumerate(agents):
        path = tmp_path / f'owned-{index}.txt'
        path.write_text(f'OWNER-{index}\n' + source(40000))
        refs.append(await execute_file(agent, path))
    for index, agent in enumerate(agents):
        args = {'result_ref': refs[index].result_ref, 'start_char': 0, 'max_chars': 8}
        reply = await agent.tools.execute('read_tool_result', args, FakeSignal(), agent.prompter)
        assert json.loads(reply)['content'] == f'OWNER-{index}\n'
        args['result_ref'] = refs[1-index].result_ref
        with pytest.raises((ResultUnavailable, InvalidToolArguments)):
            await agent.tools.execute('read_tool_result', args, FakeSignal(), agent.prompter)
        assert agent.tools.get('read_tool_result').retention is agent.result_retention
    if shared:
        # CLI/plugin registration after Agent construction remains visible;
        # source adapters are shared objects, not cloned/frozen substitutes.
        from src.tools.execution.file import FileReadToolAlias
        late = FileReadToolAlias()
        early.tools.register(late)
        assert later.tools.get(late.name()) is late
        assert early.tools.get('file_read') is later.tools.get('file_read')
        for agent in agents:
            names = [spec['function']['name'] for spec in agent.tools.as_llm_tools()]
            assert names.count('read_tool_result') == 1 and late.name() in names
    # Resume or reset one controller cannot redirect the other's capability.
    agents[0].resume_saved()
    await agents[0].reset()
    args = {'result_ref': refs[1].result_ref, 'start_char': 0, 'max_chars': 8}
    reply = await agents[1].tools.execute('read_tool_result', args, FakeSignal(), agents[1].prompter)
    assert json.loads(reply)['content'] == 'OWNER-1\n'
    with pytest.raises((ResultUnavailable, InvalidToolArguments)):
        await agents[0].tools.execute('read_tool_result', args, FakeSignal(), agents[0].prompter)


@pytest.mark.asyncio
async def test_shared_registry_controller_without_store_cannot_inherit_reader(make, tmp_path):
    first = make(bound=True)
    path = tmp_path / 'source.txt'
    path.write_text(source(40000))
    ref = await execute_file(first, path)
    second = Agent(AgentOptions(client=FakeClient([]), tools=first.tools, skills=first.skills,
        prompter=AlwaysAllow(), store=None, target=Target('https://other.test'), prompt_profile='compact'))
    assert second.result_retention.store is None
    assert second.tools.get('read_tool_result') is None
    assert 'read_tool_result' not in second.tools.names()
    assert all(spec['function']['name'] != 'read_tool_result' for spec in second.tools.as_llm_tools() if isinstance(spec, dict))
    args = {'result_ref': ref.result_ref, 'start_char': 0, 'max_chars': 100}
    call = ToolCall('no-store', FunctionCall('read_tool_result', json.dumps(args)))
    result = await second.run_parsed_tool_call(call, second.parse_tool_call(call), FakeSignal())
    assert result.status == 'error'
    assert json.loads(await first.tools.execute('read_tool_result', args, FakeSignal(), first.prompter))['content'] == path.read_text()[:100]


@pytest.mark.asyncio
@pytest.mark.parametrize('bound', [True, False])
@pytest.mark.parametrize('review', ['range', 'sensitive', 'unchanged'])
async def test_live_file_skill_capability_after_each_review(make, tmp_path, monkeypatch, bound, review):
    class Operator(AlwaysAllow):
        reviewing = False
        agent = None
        async def ask(self, request, signal=None):
            if self.reviewing and request.tool == ('file' if review == 'sensitive' else 'read_tool_result'):
                assert self.agent is not None
                if review != 'unchanged':
                    self.agent.active_skills = {'restricted'}
            return Decision.ALLOW_ONCE
    operator = Operator()
    agent = make(bound=bound, prompter=operator)
    operator.agent = agent
    path = tmp_path / '.env'
    path.write_text(source(40000))
    ref = await execute_file(agent, path)
    for name, tools in [('allowed', ['file_read']), ('restricted', ['http'])]:
        agent.skills.add(Skill(name=name, description=name, tools=tools,
            disable_model_invocation=False, path='/fixture/SKILL.md', body=''))
    agent.active_skills = {'allowed'}
    operator.reviewing = True
    store = agent.result_retention.store
    resolve = store.resolve
    reads, checked_skills = [], []
    validate_source = agent.result_retention.validate_source
    def observe_rights(*args, **kwargs):
        checked_skills.append(set(agent.active_skills))
        return validate_source(*args, **kwargs)
    monkeypatch.setattr(agent.result_retention, 'validate_source', observe_rights)
    def observe_resolve(*args):
        reads.append(1)
        return resolve(*args)
    monkeypatch.setattr(store, 'resolve', observe_resolve)
    args = {'result_ref': ref.result_ref, 'start_char': 0, 'max_chars': 100}
    call = ToolCall('skill-review', FunctionCall('read_tool_result', json.dumps(args)))
    result = await agent.run_parsed_tool_call(call, agent.parse_tool_call(call), FakeSignal())
    # FileReadTool is non-permissioned and intentionally usable by all active
    # skills. A changed list must be rechecked without weakening that existing
    # semantic. Shell's permissioned capability has separate denial cases.
    assert result.status == 'success' and json.loads(result.result)['content'] == path.read_text()[:100]
    assert reads == [1]
    assert checked_skills[-1] == ({'allowed'} if review == 'unchanged' else {'restricted'})
    if bound:
        assert agent.prompter.execution_policy.active == 0


@pytest.mark.parametrize('field', ['status', 'source_kind'])
@pytest.mark.parametrize('value', [[], {}, None, True, False, 0, 1.5, 'invalid'])
def test_descriptor_enums_are_total_for_json(field, value):
    raw = {'result_ref': 'tr_' + '0'*32, 'sha256': '0'*64, 'byte_length': 1,
        'char_length': 1, 'tool_name': 'file_read', 'tool_call_id': 'call',
        'status': 'success', 'error_kind': None, 'http_status': None, 'truncated': False,
        'source_kind': 'file', 'provenance_sha256': '0'*64}
    assert ResultReference.from_dict(raw) is not None
    raw[field] = value
    assert ResultReference.from_dict(raw) is None


@pytest.mark.asyncio
async def test_mixed_descriptors_preserve_actual_resume_and_workflow(make, tmp_path):
    agent = make(bound=True)
    from src.workflow.state import Candidate, WorkflowObjective
    path = tmp_path / 'source.txt'
    path.write_text(source(40000))
    ref = await execute_file(agent, path)
    agent.workflow.objective = WorkflowObjective(id='resume-control', mode='direct', target_origin='https://target.test')
    agent.workflow.add_candidate(Candidate(candidate_class='sql-injection', target='https://target.test',
        endpoint='/search', objective_id='resume-control'))
    await agent.save()
    document = json.loads(agent.store.path.read_text())
    invalid = asdict(ref)
    invalid['status'] = {'untrusted': []}
    document['messages'][0]['tool_result_refs'] = [invalid, asdict(ref), None, []]
    before = [(message['role'], message['content']) for message in document['messages']]
    agent.store.path.write_text(json.dumps(document))
    restored = make(bound=True)
    restored.resume_saved()
    assert [(message.role, message.content) for message in restored.history[1:]] == before[1:]
    assert restored.workflow.to_dict() == agent.workflow.to_dict()
    assert restored.history[0].tool_result_refs == [asdict(ref)]
    assert restored.result_retention.lookup(ref.result_ref) == ref


@pytest.mark.asyncio
async def test_actual_agent_directory_retention_failure_keeps_sanitized_success(make, tmp_path, monkeypatch):
    agent = make(bound=True)
    path = tmp_path / 'source.txt'
    path.write_text(source(40000) + '\nAuthorization: Bearer ' + SECRET)
    store = agent.result_retention.store
    original_link = os.link
    detached = tmp_path / 'detached-result-session'
    def replace_directory(*args, **kwargs):
        parent = store.project / '.kagent/tool-results' / store.session_id
        parent.rename(detached)
        parent.mkdir(mode=0o700)
        return original_link(*args, **kwargs)
    monkeypatch.setattr(os, 'link', replace_directory)
    call = ToolCall('fallback-file', FunctionCall('file_read', json.dumps({'path': str(path)})))
    working, events = list(agent.history), []
    batch = await agent.execute_tool_calls([call], FakeSignal(), events.append, working)
    assert batch.calls[0].result.status == 'success' and batch.calls[0].result.err_str == ''
    tool_message = working[-1]
    assert tool_message.tool_status == 'success' and tool_message.tool_result_refs is None
    assert not agent.result_retention.references
    event = next(event for event in events if event['type'] == 'tool-result')
    assert event['status'] == 'success' and len(event['result']) > 40000
    assert SECRET not in event['result'] + tool_message.content + agent.store.path.read_text()
    assert 'tr_' not in tool_message.content
    from src.ui.render.tool_result_format import build_tool_result_view
    assert build_tool_result_view(event['result']).full == event['result']
    assert not list(detached.glob('*.result')) and not list(detached.glob('.tmp-*'))
