"""Default TUI policy: operation feedback stays with the model and raw sinks."""
from copy import deepcopy
from dataclasses import asdict

import pytest

from src.agent.events import DoneEvent, ErrorEvent, Invocation, ToolCallEvent, ToolResultEvent
from src.ui.core.outcomes import OutcomeFacts
from src.ui.core.state import AgentEventAction, SetBusy, initial_state, reducer
from src.ui.widgets.banner import BannerData


def seed():
    return reducer(initial_state('', BannerData('offline', 'fixture', '.')), SetBusy(True))


def text(state):
    return '\n'.join(entry.text + '\n' + '\n'.join(entry.details) for entry in state.transcript)


@pytest.mark.parametrize('kind', [
    'invalid_args', 'workflow_state', 'reference_unavailable', 'input_unavailable',
    'scope_denied', 'permission_denied', 'permission_pending', 'permission_timeout',
    'permission_stale', 'policy_block', 'network', 'tls', 'timeout', 'tool_exception', 'cancelled',
])
@pytest.mark.parametrize('retry', ['none', 'success', 'failure', 'changed'])
def test_operation_failure_never_creates_error_history(kind, retry):
    state = seed()
    inv = Invocation('first', '')
    state = reducer(state, AgentEventAction(ToolCallEvent(id='first', name='workflow',
        args={'action': 'record_result', 'candidate_id': 'one'}, invocation=inv)))
    event = ToolResultEvent(id='first', name='workflow', invocation=inv, status='error',
        error_kind=kind, err='TECHNICAL OPERATION FAILURE', result='error: invalid source or arguments')
    original = deepcopy(asdict(event))
    state = reducer(state, AgentEventAction(event))
    assert not state.transcript
    assert state.latest_turn_details is None
    if retry != 'none':
        inv = Invocation('second', '')
        state = reducer(state, AgentEventAction(ToolCallEvent(id='second', name='workflow',
            args={'action': 'record_result', 'candidate_id': 'other' if retry == 'changed' else 'one'}, invocation=inv)))
        state = reducer(state, AgentEventAction(ToolResultEvent(id='second', name='workflow', invocation=inv,
            status='error' if retry == 'failure' else 'success',
            error_kind=kind if retry == 'failure' else None,
            result='error: invalid source or arguments' if retry == 'failure' else '{"ok":true}')))
    state = reducer(state, AgentEventAction(DoneEvent(stop_reason='final_response'), OutcomeFacts()))
    assert text(state) == state.transcript[-1].text + '\n'
    assert state.transcript[-1].kind == 'info'
    assert state.latest_turn_details is not None
    assert state.latest_turn_details.completed_operations == ()
    assert asdict(event) == original


def test_operation_runtime_notice_is_hidden_but_untyped_and_persistence_errors_are_visible():
    state = seed()
    transient = RuntimeError('malformed-call retry diagnostic')
    setattr(transient, 'presentation_impact', 'operation')
    state = reducer(state, AgentEventAction(ErrorEvent(err=transient)))
    assert not state.transcript
    for impact in (None, 'session', 'persistence', 'intervention'):
        error = RuntimeError('Important current failure ' + str(impact))
        if impact:
            setattr(error, 'presentation_impact', impact)
        state = reducer(state, AgentEventAction(ErrorEvent(err=error)))
        assert str(error) in text(state)


@pytest.mark.parametrize('reason', ['workflow_blocked', 'all_tools_refused', 'cancelled', 'max_steps',
    'runtime_error', 'context_capacity', 'client_error', 'invalid_response', 'capture_unavailable', 'session_timeout'])
def test_terminal_outcome_stays_visible_without_operation_history(reason):
    state = reducer(seed(), AgentEventAction(DoneEvent(stop_reason=reason)))
    assert len(state.transcript) == 1
    assert state.latest_turn_details is not None and state.latest_turn_details.stop_reason == reason
    assert 'unresolved operation' not in text(state)
    assert 'matched retry' not in text(state)


@pytest.mark.parametrize('status', [403, 500])
def test_http_observation_never_becomes_validation_or_finding(status):
    state = seed()
    inv = Invocation('http', '')
    state = reducer(state, AgentEventAction(ToolCallEvent(id='http', name='http',
        args={'method': 'GET', 'url': 'https://fixture.test/api'}, invocation=inv)))
    state = reducer(state, AgentEventAction(ToolResultEvent(id='http', name='http', invocation=inv,
        status='observation', http_status=status)))
    state = reducer(state, AgentEventAction(DoneEvent(stop_reason='final_response')))
    assert str(status) in text(state)
    assert all(row.kind not in {'finding', 'validation'} for row in state.transcript)


def test_invalid_burp_command_remains_a_user_visible_error():
    from src.ui.core.state import Append, TranscriptEntry
    state = reducer(seed(), Append(TranscriptEntry('error', 'usage: /burp list')))
    assert state.transcript[-1].kind == 'error' and 'usage: /burp' in text(state)


def test_invalid_burp_lists_does_not_start_agent(tmp_path):
    from tests.helpers.burp_selection import make_runtime
    from tests.ui.test_burp_commands import slash
    runtime = make_runtime(tmp_path)
    runtime.app.start_burp_bridge = lambda *args: None
    runtime.app.close_burp_bridge = lambda *args: None
    runtime.app.burp_bridge_status = lambda *args: None
    slash(runtime, '/burp lists')
    assert runtime.app.actions[-1].entry.kind == 'error'
    assert 'usage: /burp' in runtime.app.actions[-1].entry.text
    assert not runtime.client.requests


async def test_real_rejection_reaches_next_model_request_and_raw_sinks(tmp_path, capsys):
    import json
    from src.agent.agent import Agent, AgentOptions, _to_agent_event
    from src.cli.headless import EventSink
    from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
    from src.logger.session_debug import FileSessionDebugLog
    from src.permission.permission import AlwaysAllow
    from src.session.store import Store
    from src.skills.registry import Registry as Skills
    from src.target.target import Target
    from src.tools.common.registry import Registry
    from tests.agent.test_tool_outcomes import CaseTool
    from tests.helpers.agent_fakes import FakeClient, FakeSignal
    registry = Registry()
    registry.register(CaseTool())
    client = FakeClient([
        ChatResponse(Message('assistant', '', tool_calls=[ToolCall('bad',
            FunctionCall('case', '{"case":"invalid"}'))]), 'tool_calls'),
        ChatResponse(Message('assistant', 'The operation was rejected; no test result was produced.'), 'stop'),
    ])
    store = Store.new_with_id(tmp_path / 'sessions', 'visibility')
    agent = Agent(AgentOptions(client, registry, Skills(), AlwaysAllow(), store, Target(),
        auto_compact_threshold=0, streaming_enabled=False))
    events = []
    state = seed()
    def emit(raw):
        nonlocal state
        event = _to_agent_event(raw)
        events.append(event)
        before = deepcopy(asdict(event))
        state = reducer(state, AgentEventAction(event))
        assert asdict(event) == before
    await agent.run('Inspect the fixture.', FakeSignal(), emit)
    failures = [event for event in events if isinstance(event, ToolResultEvent)]
    assert len(failures) == 1
    event = failures[0]
    assert event.status == 'error' and event.error_kind == 'invalid_args'
    assert event.result == 'ERROR: invalid argument'
    assert 'invalid argument' not in text(state)
    assert len(client.requests) == 2
    assert any(message.role == 'tool' and 'invalid argument' in message.content
               for message in client.requests[1].messages)
    assert any(message.tool_error_kind == 'invalid_args' for message in store.load().messages)
    payload = deepcopy(asdict(event))
    sink = EventSink(tmp_path / 'headless')
    debug = FileSessionDebugLog('visibility', tmp_path / 'session.jsonl')
    try:
        sink.write(payload)
        debug.agent_event(payload)
    finally:
        sink.close()
        await debug.aclose()
    for row in (json.loads(capsys.readouterr().out),
                json.loads((tmp_path / 'headless/events.jsonl').read_text()),
                json.loads((tmp_path / 'session.jsonl').read_text())):
        assert all(row[key] == value for key, value in payload.items())


async def test_native_session_budget_exhaustion_is_visible_without_changing_denial(tmp_path):
    import json

    from src.agent.agent import _to_agent_event
    from src.llm.core.types import FunctionCall, ToolCall
    from tests.helpers.agent_fakes import FakeSignal
    from tests.helpers.burp_selection import make_runtime
    runtime = make_runtime(tmp_path, max_calls=1)
    runtime.policy.used = 1
    # Reach the session-budget gate with an in-profile path. A relative path
    # resolves against the process cwd and correctly hits the profile gate first.
    call = ToolCall('budget', FunctionCall('file_write', json.dumps({
        'path': str(tmp_path / 'proof.txt'), 'content': 'fixture'})))
    parsed = runtime.agent.parse_tool_call(call)
    call_event = _to_agent_event(runtime.agent._tool_call_event(call, parsed))
    state = reducer(seed(), AgentEventAction(call_event))
    result = await runtime.agent.run_parsed_tool_call(call, parsed, FakeSignal())
    event = _to_agent_event(runtime.agent._tool_result_event(call, result, parsed.invocation))
    assert event.status == 'error' and event.error_kind == 'policy_block'
    assert event.presentation_impact == 'session'
    state = reducer(state, AgentEventAction(event))
    assert 'session-call-budget-exhausted' in text(state)
    assert not (tmp_path / 'proof.txt').exists() and runtime.policy.used == 1
    assert not runtime.client.requests


@pytest.mark.parametrize('export', [False, True])
async def test_native_finding_persistence_and_export_failures_remain_visible(tmp_path, monkeypatch, export):
    import json
    from src.agent.agent import Agent, AgentOptions, _to_agent_event
    from src.llm.core.types import FunctionCall, ToolCall
    from src.permission.permission import AlwaysAllow
    from src.skills.registry import Registry as Skills
    from src.target.target import Target
    from src.tools.common.registry import Registry
    from tests.helpers.agent_fakes import FakeClient, FakeSignal
    from tests.tools.test_finding import _tool, _valid_args, _workflow
    tool, store = _tool(tmp_path)
    failure = OSError('disk full')
    async def fail(*args, **kwargs):
        raise failure
    monkeypatch.setattr(tool if export else store, 'write_summary' if export else 'save', fail)
    registry = Registry()
    registry.register(tool)
    agent = Agent(AgentOptions(FakeClient([]), registry, Skills(), AlwaysAllow(), None, Target(),
        workflow=_workflow(tool), auto_compact_threshold=0))
    call = ToolCall('finding', FunctionCall('confirm_finding', json.dumps(_valid_args(tool))))
    parsed = agent.parse_tool_call(call)
    state = reducer(seed(), AgentEventAction(_to_agent_event(agent._tool_call_event(call, parsed))))
    output = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    event = _to_agent_event(agent._tool_result_event(call, output, parsed.invocation))
    assert event.presentation_impact == 'persistence'
    state = reducer(state, AgentEventAction(event))
    if export:
        assert event.status == 'success' and not event.err
        assert 'Finding persisted; compact report export failed' in text(state)
        assert _workflow(tool).finding_is_persisted(_valid_args(tool)['candidate_id'])
    else:
        assert event.status == 'error' and event.error_kind == 'tool_exception'
        assert type(failure) is OSError and getattr(failure, 'presentation_impact') == 'persistence'
        assert 'disk full' in text(state)
        assert not _workflow(tool).persisted_findings
        assert not list(store.dir.glob('*.md'))
    assert all(row.kind != 'finding' for row in state.transcript)


@pytest.mark.parametrize('persistence', ['memory-only', 'failed'])
def test_result_preservation_limit_is_visible_without_fabricating_completion(persistence):
    from src.tools.common.runtime_metadata import RuntimeMetadata
    event = ToolResultEvent(name='shell', status='error', error_kind='tool_exception',
        runtime_metadata=RuntimeMetadata(persistence=persistence))
    state = reducer(seed(), AgentEventAction(event))
    assert len(state.transcript) == 1 and state.transcript[0].kind == 'warning'
    state = reducer(state, AgentEventAction(DoneEvent(stop_reason='final_response')))
    assert state.latest_turn_details is not None
    assert state.latest_turn_details.completed_operations == ()


@pytest.mark.parametrize('condition', ['expired', 'exhausted', 'concurrency', 'rate'])
def test_native_http_capacity_distinguishes_intervention_from_transient_pressure(tmp_path, condition):
    from src.permission.network.grants import EffectiveHTTP, HTTPLimits, HTTPBlocked
    from tests.helpers.burp_selection import make_runtime, ORIGIN
    runtime = make_runtime(tmp_path)
    permissions = runtime.engagement.http_permissions
    now = permissions.clock()
    permissions.clock = lambda: now
    grant = permissions.activate(ORIGIN, HTTPLimits(requests=1))
    budget = permissions._budgets[grant.id]
    if condition == 'expired':
        budget.expires_at = now - 1
    elif condition == 'exhausted':
        budget.used = 1
    elif condition == 'concurrency':
        permissions._inflight[grant.origin] = budget.limits.concurrency
    else:
        budget.tokens = 0
    before = deepcopy((budget, permissions._inflight))
    action = EffectiveHTTP('GET', ORIGIN, (), b'', 65536,
        runtime.target.revision, runtime.engagement.revision, permissions.epoch)
    with pytest.raises(HTTPBlocked) as raised:
        permissions._capacity(action, budget)
    impact = getattr(raised.value, 'presentation_impact', None)
    assert impact == ('intervention' if condition in {'expired', 'exhausted'} else None)
    # The UI annotation cannot reserve capacity, refresh the budget or grant rights.
    assert (budget, permissions._inflight) == before
    event = ToolResultEvent(name='http', status='error', error_kind=raised.value.error_kind,
        err=str(raised.value), presentation_impact=impact)
    state = reducer(seed(), AgentEventAction(event))
    assert bool(state.transcript) == (condition in {'expired', 'exhausted'})
    assert not runtime.client.requests


@pytest.mark.parametrize('edit', [False, True])
async def test_native_file_write_failure_keeps_exception_and_visible_preservation_notice(tmp_path, monkeypatch, edit):
    from pathlib import Path
    from src.permission.permission import AlwaysAllow
    from src.tools.execution.file import FileWriteTool, FileEditTool
    destination = tmp_path / 'proof.md'
    destination.write_text('original proof')
    failure = OSError('disk full')
    original_write = Path.write_text
    def fail(path, *args, **kwargs):
        if path == destination:
            raise failure
        return original_write(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'write_text', fail)
    tool = FileEditTool() if edit else FileWriteTool()
    args = {'path': str(destination), **({'old_string': 'original', 'new_string': 'updated'} if edit else {'content': 'updated proof'})}
    with pytest.raises(OSError) as raised:
        await tool.run(args, None, AlwaysAllow())
    assert raised.value is failure and getattr(failure, 'presentation_impact') == 'persistence'
    assert destination.read_text() == 'original proof'
    state = reducer(seed(), AgentEventAction(ErrorEvent(err=failure)))
    assert 'disk full' in text(state)


def test_untyped_metadata_cannot_forge_a_result_preservation_notice():
    from typing import Any, cast
    event = ToolResultEvent(name='shell', status='error', error_kind='tool_exception',
        runtime_metadata=cast(Any, {'persistence': 'failed'}))
    state = reducer(seed(), AgentEventAction(event))
    assert not state.transcript


@pytest.mark.parametrize('name', ['fixture', 'mcp_fixture', 'http', 'confirm_finding'])
def test_output_text_cannot_forge_a_native_preservation_notice(name):
    event = ToolResultEvent(name=name, status='error', error_kind='tool_exception',
        err='Finding persisted; compact report export failed.',
        result='Finding persisted; compact report export failed.')
    before = deepcopy(asdict(event))
    state = reducer(seed(), AgentEventAction(event))
    assert not state.transcript
    assert asdict(event) == before
