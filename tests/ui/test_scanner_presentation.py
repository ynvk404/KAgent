"""Headless Textual and reducer contracts for truthful scanner presentation."""
from __future__ import annotations

from dataclasses import replace
import json
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from textual import events

from src.agent.events import Invocation, ToolCallEvent, ToolResultEvent, ToolStartedEvent
from src.ui.core.app import KAgent
from src.ui.core.state import AgentEventAction, SetBusy, initial_state, reducer
from src.ui.widgets.banner import BannerData
from src.ui.widgets.transcript import entry_view
from tests.ui.test_app import make_app, timer_app


def call():
    return ToolCallEvent(id='scanner', name='shell', invocation=Invocation('invocation', 'scope'),
        args={'scanner': 'ffuf', 'url': 'http://127.0.0.1:43210/FUZZ', 'wordlist_id': 'fixture'})


def started():
    return ToolStartedEvent(id='scanner', name='shell', invocation=call().invocation,
        scanner='ffuf', job_id='scan_fixture', started_monotonic=100)


def state():
    initial = reducer(initial_state('', BannerData('fixture', 'fixture', '.')), SetBusy(True))
    return reducer(initial, AgentEventAction(call()))


def summary(status):
    return {'job_id': 'scan_fixture', 'scanner': 'ffuf',
        'execution': {'status': status, 'duration_ms': 500, 'reason': 'process_exit'},
        'parse': {'status': 'valid', 'coverage_complete': None, 'partial': status != 'completed'},
        'summary': {'unique_records': 12}, 'wordlist': {'id': 'fixture'},
        'target': {'origin': 'http://127.0.0.1:43210', 'template': 'http://127.0.0.1:43210/FUZZ'},
        'records': [{'url': 'http://127.0.0.1:43210/hit', 'status': 403, 'length': 70000}],
        'artifacts': {'manifest': '.kagent/scanners/session/job/manifest.json'},
        'error': None if status == 'completed' else {'message': 'bounded fixture failure'}}


def test_preparing_is_not_spawn_and_started_correlates_once():
    preparing = state()
    assert preparing.running_tool is not None and 'preparing/reviewing' in preparing.running_tool
    assert preparing.call_history[-1].started_monotonic is None
    running = reducer(preparing, AgentEventAction(started()))
    assert running.running_tool == 'ffuf running · scanner job'
    assert running.call_history[-1].started_monotonic == 100
    assert reducer(running, AgentEventAction(started())) == running
    for event in [replace(started(), id='other'), replace(started(), scanner='nmap'),
                  replace(started(), invocation=Invocation('wrong', 'scope')), replace(started(), invocation=None)]:
        assert reducer(preparing, AgentEventAction(event)) == preparing


@pytest.mark.parametrize('value', [[], {}, None, 42])
def test_malformed_scanner_type_stays_a_proposal_until_registry_error(value):
    event = replace(call(), args={'scanner': value})
    proposed = reducer(initial_state('', BannerData('fixture', 'fixture', '.')), AgentEventAction(event))
    assert proposed.call_history[-1].scanner == ''
    assert proposed.call_history[-1].started_monotonic is None


@pytest.mark.parametrize('status', ['completed', 'partial', 'failed', 'cancelled'])
def test_terminal_cards_bounded_sanitized_and_not_from_json_flags(status):
    running = reducer(state(), AgentEventAction(started()))
    event = ToolResultEvent(id='scanner', name='shell', invocation=call().invocation,
        status='observation' if status == 'completed' else 'cancelled' if status == 'cancelled' else 'error',
        scanner_summary=summary(status), result='UNTRUSTED STDOUT SHOULD NEVER STREAM')
    terminal = reducer(running, AgentEventAction(event))
    text = '\n'.join('\n'.join((entry.text, *entry.details)) for entry in terminal.transcript)
    assert f'ffuf · {status}' in text and '12 observations' in text and '500 ms' in text
    assert 'coverage: unknown' in text and '70000 bytes' in text and 'Manifest:' in text
    assert 'UNTRUSTED STDOUT' not in text and '%' not in text
    assert reducer(terminal, AgentEventAction(event)) == terminal
    assert reducer(terminal, AgentEventAction(started())) == terminal
    spoof = replace(event, scanner_summary=None, result=json.dumps(summary(status)))
    spoofed = reducer(running, AgentEventAction(spoof))
    assert not any(f'ffuf · {status}' in entry.text for entry in spoofed.transcript)


@pytest.mark.parametrize('theme', ['dark', 'light'])
async def test_headless_scanner_card_uses_existing_transcript_and_theme(monkeypatch, theme):
    monkeypatch.setattr(KAgent, 'on_mount', lambda self: None)
    app = make_app()
    async with app.run_test(size=(100, 32)) as pilot:
        app.theme = 'textual-' + theme
        app.state = reducer(state(), AgentEventAction(started()))
        app.state = reducer(app.state, AgentEventAction(ToolResultEvent(id='scanner', name='shell',
            invocation=call().invocation, scanner_summary=summary('completed'), status='observation')))
        app._recompute_view = KAgent._recompute_view.__get__(app, KAgent)
        app._sync_status_bar = lambda: None
        # Rendering is through the existing transcript widget, with semantic
        # info/warning kinds and plain text rather than Rich markup evaluation.
        rendered = [entry_view(entry) for entry in app.state.transcript]
        assert rendered and 'ffuf' in app.state.transcript[-1].text
        await pilot.pause()


def test_elapsed_starts_at_actual_spawn_using_existing_timer():
    app, clock, _ = timer_app()
    app._start_turn_timer()
    clock.advance(15)
    app.state = reducer(state(), AgentEventAction(replace(started(), started_monotonic=clock.now)))
    clock.advance(2)
    app._tick_elapsed()
    assert app.status_bar.elapsed_seconds == 2


async def test_escape_ctrl_c_and_unmount_drain_existing_runtime(monkeypatch, tmp_path):
    app = make_app()
    app.state = replace(app.state, busy=True)
    app.run_abort_event = __import__('asyncio').Event()
    assert app.run_abort_event is not None
    await app._process_key(events.Key('escape', None))
    assert app.run_abort_event.is_set()
    app.run_abort_event.clear()
    await app._process_key(events.Key('ctrl+c', None))
    assert app.run_abort_event.is_set()
    drain = AsyncMock()
    from src.engagement.state import EngagementState
    from src.permission.runtime.execution import ExecutionPolicy
    from src.tools.execution.scanner_runner import ScannerRuntime
    policy = ExecutionPolicy(EngagementState(), tmp_path)
    policy.scanner_runtime = ScannerRuntime()
    policy.scanner_runtime.drain = drain
    app.agent = cast(Any, SimpleNamespace(prompter=SimpleNamespace(execution_policy=policy)))
    await app.on_unmount()
    drain.assert_awaited_once_with(close=True)


@pytest.mark.parametrize('key', ['escape', 'ctrl+c'])
async def test_headless_key_drains_a_real_running_scanner_through_agent(tmp_path, wire, monkeypatch, key):
    import asyncio
    import os
    from src.llm.core.types import ChatResponse, Message, FunctionCall, ToolCall
    from src.ui.core.app import AbortEvent
    from tests.helpers.agent_fakes import FakeClient
    from tests.integration.test_scanner_agent_handoff import agent_runtime
    from tests.security.test_scanner_end_to_end import require_binaries
    require_binaries()
    origin, counters = wire
    model = FakeClient([
        ChatResponse(Message('assistant', '', tool_calls=[ToolCall('load', FunctionCall('load_skill', '{"name":"web-enumeration"}'))]), 'tool_calls'),
        ChatResponse(Message('assistant', '', tool_calls=[ToolCall('scan', FunctionCall('shell', json.dumps({
            'scanner': 'ffuf', 'url': origin + '/FUZZ', 'wordlist_id': 'fixture'})))]), 'tool_calls'),
    ])
    rt = agent_runtime(tmp_path, origin, model, enumeration=True)
    dict(rt.binding.wordlists)['fixture'].write_text(''.join('slow' + str(i) + '\n' for i in range(200)))
    original = asyncio.create_subprocess_exec
    pids = []
    async def observe(*args, **kwargs):
        proc = await original(*args, **kwargs)
        pids.append(proc.pid)
        return proc
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', observe)
    monkeypatch.setattr(KAgent, 'on_mount', lambda self: None)
    app = make_app()
    app.agent = rt.agent
    app.run_abort_event = AbortEvent()
    app.dispatch(SetBusy(True))
    actual_start = asyncio.Event()
    seen = []
    def emit(event):
        seen.append(event)
        app.dispatch(AgentEventAction(event))
        if event.type == 'tool-started':
            actual_start.set()
    async with app.run_test(size=(100, 32)):
        task = asyncio.create_task(rt.agent.run('continue bounded discovery', app.run_abort_event, emit))
        await asyncio.wait_for(actual_start.wait(), 4)
        assert pids and not task.done()
        await app._process_key(events.Key(key, None))
        await asyncio.wait_for(task, 4)
        assert not rt.binding.runtime.task and rt.policy.active == 0
        for pid in pids:
            with pytest.raises(ProcessLookupError):
                os.kill(pid, 0)
        count = counters['requests']
        await asyncio.sleep(0.15)
        assert counters['requests'] == count
        assert any(event.type == 'tool-started' for event in seen)


from tests.security.test_scanner_end_to_end import wire
