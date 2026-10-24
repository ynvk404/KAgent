"""Offline presentation boundaries: structured progress, intact text and receipts."""
from copy import deepcopy
from dataclasses import asdict
import json

import pytest

from src.agent.agent import Agent, AgentOptions, AgentRunOptions, _to_agent_event
from src.agent.events import (
    AssistantDeltaEvent, AssistantTextEvent, DecisionEvent, DoneEvent, ErrorEvent,
    ToolCallEvent, ToolResultEvent,
)
from src.cli.headless import EventSink
from src.llm.core.client import StreamingClient
from src.llm.core.reasoning import ReasoningLevel
from src.llm.core.types import ChatResponse, Message
from src.logger.session_debug import FileSessionDebugLog
from src.permission.permission import AlwaysAllow
from src.session.store import Store
from src.skills.registry import Registry as Skills
from src.target.target import Target
from src.tools.common.registry import Registry
from src.ui.core.outcomes import OutcomeFacts, ProgressRecord
from src.ui.core.state import AgentEventAction, SetBusy, initial_state, reducer
from src.ui.widgets.banner import BannerData
from src.ui.widgets.permission_modal import PermissionModal
from src.ui.widgets.transcript import entry_view
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from tests.ui.test_permission_modal import make_req, rendered


def seed(facts=None):
    return reducer(initial_state('', BannerData('offline', 'fixture', '.')), SetBusy(True, facts=facts))


def transcript(state):
    return '\n'.join(line.text for entry in state.transcript for line in entry_view(entry))


def test_planner_keeps_reference_only_when_candidate_labels_are_ambiguous():
    rows = tuple(ProgressRecord('candidate', identifier, 'GET /search · input q · xss')
                 for identifier in ('cand_0123456789abcdef', 'cand_fedcba9876543210'))
    facts = OutcomeFacts(records=rows)
    state = seed()
    for row in rows:
        event = DecisionEvent(recommended_skill='cross-site-scripting', candidate_id=row.key,
                              decision_id=row.key, summary='runtime internals obs_fixture ds_fixture')
        before = asdict(event)
        state = reducer(state, AgentEventAction(event, facts=facts))
        assert asdict(event) == before
    labels = [entry.text for entry in state.transcript]
    assert len(set(labels)) == 2
    assert all(row.key[-8:] in label for row, label in zip(rows, labels))
    assert 'obs_fixture' not in transcript(state) and 'ds_fixture' not in transcript(state)


def test_runtime_progress_and_summary_use_labels_without_dumping_receipts():
    candidate = 'cand_0123456789abcdef'
    attempt = 'attempt_fedcba9876543210'
    facts = OutcomeFacts(scope='fixture', records=(
        ProgressRecord('candidate', candidate, 'GET /orders/ORDER-42 · input order_id · access-control'),
        ProgressRecord('observation', 'obs_fixture', 'http · GET /orders/ORDER-42 · 403', '403'),
    ), pending=('validation incomplete',), incomplete=1)
    state = reducer(seed(OutcomeFacts(scope='fixture')), AgentEventAction(ToolCallEvent(id='call', name='workflow', args={
        'action': 'list', 'candidate_id': candidate, 'attempt_id': attempt}), facts=facts))
    event = ToolResultEvent(id='call', name='workflow', result=json.dumps({
        'ok': True, 'candidate_id': candidate, 'attempt_id': attempt,
        'observation_id': 'obs_fixture', 'source_id': 'ds_fixture',
        'state_path': '.kagent/state/internal.json', 'temporary_path': '/tmp/kagent-capture',
    }))
    before = deepcopy(asdict(event))
    state = reducer(state, AgentEventAction(event, facts=facts))
    state = reducer(state, AgentEventAction(DoneEvent(stop_reason='final_response'), facts=facts))
    text = transcript(state)
    assert 'Candidate recorded' in text and 'ORDER-42' in text and 'order_id' in text
    assert 'HTTP activity (observations only)' in text and '403' in text
    assert 'work remains' in text and '1 incomplete validation' in text
    assert not any(value in text for value in (candidate, attempt, 'obs_fixture', 'ds_fixture',
                                              '.kagent/state/internal.json', '/tmp/kagent-capture'))
    assert asdict(event) == before


def test_errors_keep_actionable_ids_business_ids_and_diagnostic_paths():
    detail = ('Cannot read obs_0123456789abcdef for cand_0123456789abcdef '
              'attempt_0123456789abcdef; ds_0123456789abcdef; ORDER-42; '
              'artifacts/findings/ORDER-42.md; .kagent/state/repair.json')
    event = ToolResultEvent(name='workflow', status='error', error_kind='evidence', err=detail)
    before = asdict(event)
    state = reducer(seed(), AgentEventAction(event))
    assert not state.transcript
    assert asdict(event) == before
    state = reducer(state, AgentEventAction(ErrorEvent(err=RuntimeError(detail))))
    assert detail in state.transcript[-1].text


def test_permission_review_preserves_exact_references_and_paths():
    detail = ('candidate_id=cand_0123456789abcdef\nattempt_id=attempt_0123456789abcdef\n'
              'observation_id=obs_fixture\nsource_id=ds_fixture\n'
              'path: .kagent/state/repair.json\nReport: artifacts/findings/ORDER-42.md')
    request = make_req(tool='workflow', summary='Review evidence repair for ORDER-42', detail=detail)
    original = request.summary, request.detail
    frame = rendered(PermissionModal(request), width=160)
    assert all(line in frame for line in detail.splitlines())
    assert (request.summary, request.detail) == original
    request.resolve.assert_not_called()
    request.reject.assert_not_called()


@pytest.mark.parametrize('terminal', ['text', 'done'])
@pytest.mark.parametrize('chunk_size', [1, 5, 1000])
def test_model_text_and_split_id_streams_remain_byte_for_byte(terminal, chunk_size):
    text = ('Summary: obs_0123456789abcdef ds_0123456789abcdef\n'
            'Candidate cand_0123456789abcdef Attempt attempt_0123456789abcdef\n'
            'ORDER-42 → artifacts/findings/ORDER-42.md\n/tmp/example .kagent/state/example.json')
    chunks = [text[index:index + chunk_size] for index in range(0, len(text), chunk_size)]
    state = seed()
    for index, chunk in enumerate(chunks):
        event = AssistantDeltaEvent(text=chunk)
        state = reducer(state, AgentEventAction(event))
        assert event.text == chunk
        assert state.stream_chunks == tuple(chunks[:index + 1])
    event = AssistantTextEvent(text=text) if terminal == 'text' else DoneEvent(stop_reason='final_response')
    state = reducer(state, AgentEventAction(event))
    answer = next(entry for entry in state.transcript if entry.kind == 'assistant')
    assert answer.text.encode('utf-8') == text.encode('utf-8')
    assert not state.stream_chunks
    buffered = []
    Agent._emit_buffered_response_text(ChatResponse(Message('assistant', text), 'stop'), True, chunks, buffered.append)
    assert [row['text'] for row in buffered] == chunks


@pytest.mark.parametrize('profile', ['full', 'compact'])
@pytest.mark.parametrize('synthesis', [False, True])
async def test_summary_guidance_reaches_model_without_rewriting_answer(profile, synthesis):
    answer = 'Unverified: obs_fixture ds_fixture cand_fixture attempt_fixture; artifacts/findings/ORDER-42.md'
    client = FakeClient([ChatResponse(Message('assistant', answer), 'stop')])
    agent = Agent(AgentOptions(client=client, tools=Registry(), skills=Skills(), prompter=AlwaysAllow(),
                               target=Target(), store=None, prompt_profile=profile, streaming_enabled=False))
    events = []
    if synthesis:
        await agent._whole_target_synthesis(agent.history.copy(), FakeSignal(), events.append,
            thinking_enabled=False, reasoning_level=ReasoningLevel.OFF,
            requested_reasoning_level=ReasoningLevel.OFF, stop_reason='workflow_blocked',
            instruction='Summarize the existing observations.', max_steps=1)
    else:
        await agent.run('Summarize the existing observations.', FakeSignal(), events.append,
                        AgentRunOptions(tools=False))
    guidance = next(message.content for message in client.requests[0].messages if message.role == 'system')
    assert '# Presentation' in guidance
    presentation = guidance.split('# Presentation\n', 1)[1].split('\n# ', 1)[0]
    assert all(term in presentation for term in ('phase', 'endpoint', 'status', 'findings', 'coverage',
                                                'errors', 'limitations', 'actionable', 'troubleshooting',
                                                'temporary', 'report', 'finding'))
    assert next(row['text'] for row in events if row['type'] == 'assistant-text') == answer
    assert agent.history[-1].content == answer


@pytest.mark.parametrize('synthesis', [False, True])
async def test_fake_llm_stream_survives_tui_and_session_persistence(tmp_path, synthesis):
    chunks = ['Unverified: obs', '_01234567', '89abcdef ds_', '0123456789abcdef\n',
              'Candidate cand_', '0123456789abcdef Attempt attempt', '_0123456789abcdef\n',
              'Report: artifacts/findings/ORDER-42.md']
    answer = ''.join(chunks)

    class ChunkClient(FakeClient, StreamingClient):
        async def chat_stream(self, request, on_delta, signal=None):
            for chunk in chunks:
                on_delta(chunk)
            return await self.chat(request, signal)

    client = ChunkClient([ChatResponse(Message('assistant', answer), 'stop')])
    store = Store.new_with_id(tmp_path / 'sessions', 'fixture')
    agent = Agent(AgentOptions(client=client, tools=Registry(), skills=Skills(), prompter=AlwaysAllow(),
                               target=Target(), store=store))
    events = []
    if synthesis:
        await agent._whole_target_synthesis(agent.history.copy(), FakeSignal(), events.append,
            thinking_enabled=False, reasoning_level=ReasoningLevel.OFF,
            requested_reasoning_level=ReasoningLevel.OFF, stop_reason='workflow_blocked',
            instruction='Summarize.', max_steps=1)
    else:
        await agent.run('Summarize.', FakeSignal(), events.append, AgentRunOptions(tools=False))
    assert [event['text'] for event in events if event['type'] == 'assistant-delta'] == chunks
    stored = store.path.read_bytes()
    history = deepcopy(agent.history)
    state = seed()
    for event in events:
        state = reducer(state, AgentEventAction(_to_agent_event(event)))
    state = reducer(state, AgentEventAction(DoneEvent(stop_reason='final_response')))
    assert next(entry.text for entry in state.transcript if entry.kind == 'assistant') == answer
    assert store.load().messages[-1].content == answer
    assert store.path.read_bytes() == stored and agent.history == history


async def test_tui_projection_leaves_headless_and_debug_payloads_intact(tmp_path, capsys):
    event = ToolResultEvent(id='call_123', name='fixture', result=json.dumps({
        'observation_id': 'obs_fixture', 'source_id': 'ds_fixture',
        'candidate_id': 'cand_0123456789abcdef', 'attempt_id': 'attempt_0123456789abcdef',
        'path': '.kagent/state/internal.json', 'report': 'artifacts/findings/ORDER-42.md',
    }))
    payload = asdict(event)
    reducer(seed(), AgentEventAction(event))
    sink = EventSink(tmp_path / 'headless')
    debug = FileSessionDebugLog('fixture-session', tmp_path / 'debug.jsonl')
    try:
        sink.write(payload)
        debug.agent_event(payload)
    finally:
        sink.close()
        await debug.aclose()
    stdout = json.loads(capsys.readouterr().out)
    headless = json.loads((tmp_path / 'headless/events.jsonl').read_text())
    logged = json.loads((tmp_path / 'debug.jsonl').read_text())
    for row in (stdout, headless, logged):
        assert all(row[key] == value for key, value in payload.items())
    assert headless == stdout
    assert asdict(event) == payload
