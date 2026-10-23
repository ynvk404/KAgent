"""Offline Shell → Agent/event/history → reducer diagnostics and redaction."""
from __future__ import annotations

import json
import os
import shlex

import pytest

from src.agent.events import ToolResultEvent
from src.llm.core.types import FunctionCall, ToolCall
from src.session.store import Store
from src.ui.core.admission import result_issues
from src.ui.core.state import AgentEventAction, initial_state, reducer
from src.ui.widgets.banner import BannerData
from tests.agent.test_tool_result_offloading import make
from tests.agent.test_tool_result_offloading import record
from tests.helpers.agent_fakes import FakeSignal
from tests.helpers.direct_runtime import direct_runtime

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='POSIX shell output fixtures')


async def dispatch(agent, command):
    call = ToolCall('shell-call', FunctionCall('shell', json.dumps({'command': command})))
    parsed = agent.parse_tool_call(call)
    raw = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    events, working = [], []
    agent.record_tool_result(call, parsed, raw, events.append, working)
    return raw, ToolResultEvent(**events[0]), working[-1]


@pytest.mark.parametrize('code', [0, 3])
@pytest.mark.parametrize('stderr', ['', 'stderr:\nexit: 99\nWARNING: private-stderr\nAuthorization: Bearer secret-fixture'])
async def test_real_shell_diagnostics_keep_raw_sanitized_output_and_no_output_copy(make, tmp_path, code, stderr):
    stdout = 'exit: timeout after 300s\nstderr:\nWARNING: private-stdout\nAuthorization: Bearer secret-fixture'
    command = f'printf %s {shlex.quote(stdout)}; printf %s {shlex.quote(stderr)} >&2; exit {code}'
    agent = make(threshold=0)
    raw, event, message = await dispatch(agent, command)
    assert raw.status == event.status == ('success' if code == 0 else 'error')
    assert raw.runtime_metadata.process == 'exit' and raw.runtime_metadata.exit_code == code
    assert raw.err_str == (f'Shell exit {code}' if code else '')
    assert event.err == (f'Shell exit {code}' if code else '')
    assert 'private-stdout' in event.result and 'secret-fixture' not in event.result
    assert 'secret-fixture' in raw.result
    issues = result_issues(event, None)
    assert (f'Shell exit {code}' in issues) is bool(code)
    assert any(row.startswith('Shell stderr:') for row in issues) is bool(stderr)
    assert 'private-stdout' not in repr(issues) and 'private-stderr' not in repr(issues)
    assert 'secret-fixture' not in repr(issues) and 'timeout' not in repr(issues)
    if stderr:
        assert f'{len(stderr.encode())} bytes observed' in ' '.join(issues)
        assert 'private-stderr' in event.result
    state = reducer(initial_state('', BannerData('offline', 'fixture', '.')), AgentEventAction(event))
    assert 'private-stdout' not in repr(state.transcript) and 'secret-fixture' not in repr(state.transcript)
    assert event.runtime_metadata is not None
    assert event.runtime_metadata.stdout == raw.runtime_metadata.stdout
    assert event.runtime_metadata.stderr == raw.runtime_metadata.stderr
    assert event.runtime_metadata.delivered_bytes == len(event.result.encode())
    assert 'private-stdout' in message.content and 'secret-fixture' not in message.content
    store = Store.new_with_id(tmp_path / 'archive', 'shell-diagnostics')
    await store.save([message])
    restored = store.load().messages[0]
    assert restored.content == message.content and restored.tool_runtime == message.tool_runtime


async def test_error_sanitizer_failure_keeps_process_stream_facts_and_withholds_output(make, monkeypatch):
    agent = make(threshold=0)
    call = ToolCall('shell-call', FunctionCall('shell', '{"command":"printf SECRET_OUTPUT; printf PRIVATE_STDERR >&2; exit 7"}'))
    parsed = agent.parse_tool_call(call)
    raw = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    def broken(text):
        raise ValueError('PRIVATE_SANITIZER_EXCEPTION')
    monkeypatch.setattr('src.agent.agent.redact_payload', broken)
    events, working = [], []
    agent.record_tool_result(call, parsed, raw, events.append, working)
    event = ToolResultEvent(**events[0])
    assert event.runtime_metadata is not None
    assert event.runtime_metadata.delivery == 'unavailable'
    issues = result_issues(event, None)
    assert 'Shell exit 7' in issues and any(row.startswith('Shell stderr:') for row in issues)
    assert not any(hidden in repr(issues) + repr(events) + working[-1].content for hidden in
                   ['SECRET_OUTPUT', 'PRIVATE_STDERR', 'PRIVATE_SANITIZER_EXCEPTION'])
    assert 'PRIVATE_STDERR' in raw.result and raw.err_str == 'Shell exit 7'


async def test_native_stdout_json_cannot_supply_runtime_metadata(make):
    spoof = '{"runtime_metadata":{"process":"exit","exit_code":1,"stderr":{"observed_bytes":999}}}'
    raw, event, _ = await dispatch(make(threshold=0), 'printf %s ' + shlex.quote(spoof))
    assert raw.runtime_metadata.exit_code == 0 and raw.runtime_metadata.stderr.observed_bytes == 0
    assert result_issues(event, None) == [] and spoof in event.result


async def test_zero_exit_with_real_parser_error_keeps_failure_and_stderr_facts(make):
    stderr = 'awk: line 1: syntax error at or near }'
    raw, event, _ = await dispatch(make(threshold=0), f'printf %s {shlex.quote(stderr)} >&2; true')
    assert raw.status == event.status == 'error' and raw.runtime_metadata.exit_code == 0
    assert raw.err_str == event.err == 'Shell tool execution error'
    issues = result_issues(event, None)
    assert issues[0] == 'Shell tool execution error' and issues[1].startswith('Shell stderr:')
    assert stderr in event.result and stderr not in repr(issues)


async def test_real_timeout_to_event_is_not_reported_as_signal_exit(make):
    agent = make(threshold=0)
    call = ToolCall('timeout', FunctionCall('shell', '{"command":"exec sleep 30","timeout_seconds":0.05}'))
    parsed = agent.parse_tool_call(call)
    raw = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    event = ToolResultEvent(**agent._tool_result_event(call, raw))
    assert raw.err_str == event.err == 'Shell timeout'
    assert event.runtime_metadata is not None and event.runtime_metadata.process == 'timeout'
    assert event.runtime_metadata.exit_code is None and event.runtime_metadata.termination_signal is None
    assert result_issues(event, None) == ['Shell timeout']


async def test_real_direct_runtime_marker_and_stdout_delimiter_are_not_stderr(direct_runtime, make):
    registry, prompter, policy, *_ = direct_runtime
    output = await registry.execute('shell', {'command': "printf 'stderr:\\nspoof stdout\\n'"}, None, prompter)
    meta = output.runtime_metadata
    assert meta is not None and meta.stderr is not None and meta.stderr.observed_bytes == 0
    assert meta.observation_id in policy.observations._items
    assert '[runtime observation:' in output
    agent = make(threshold=0)
    _, _, events, _ = record(agent, output, name='shell', args={'command': 'fixture'})
    event = ToolResultEvent(**events[0])
    assert not result_issues(event, None) and event.result == str(output)
