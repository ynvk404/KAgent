"""Context reduction must retain exact handles, without retaining old traffic."""
from copy import deepcopy
from dataclasses import replace
import re

import httpx
import pytest

from src.agent.agent import MIDTURN_RECENT_TOOL_RESULT_CHAR_FLOOR
from src.llm.core.types import ChatRequest, ChatResponse, Message
from src.llm.runtime.context_budget import ContextCapacityError
from src.workflow.state import WorkflowMode, WorkflowObjective
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from tests.helpers.burp_selection import ingest, make_runtime, ORIGIN
from tests.helpers.discovery_calls import execute


def test_old_http_elision_preserves_controller_observation_references(tmp_path):
    rt = make_runtime(tmp_path)
    agent = rt.agent
    agent.set_auto_compact_threshold(1000)
    sources = ['obs_' + f'{index:032x}' for index in range(7)]
    messages = [Message('system', 'Fixed skill and controller context. ' * 2000)]
    messages.extend(Message('tool', 'HTTP evidence ' + source + '\n' + 'old response ' * 1000,
        name='http', tool_call_id=f'http-{index}', tool_status='observation',
        http_response_sources=[source]) for index, source in enumerate(sources))
    messages.insert(1, Message('tool', 'Untrusted output mentions obs_' + 'f' * 32,
                              name='http', tool_call_id='no-controller-source'))
    before = deepcopy(messages)
    request = ChatRequest(agent.client.model(), messages)
    events = []
    agent.guard_working_context(messages, events.append, request=request)
    # Four recent results keep bounded windows; the three older results are
    # retired. Their existing IDs must remain copyable for the owned ledger.
    assert len(messages) == len(before)
    assert 'obs_' not in messages[1].content
    for index, source in enumerate(sources[:3], 2):
        assert source in messages[index].content
        assert 'metadata only' in messages[index].content
        assert 'old response' not in messages[index].content
        assert len(messages[index].content) < 500
        assert messages[index].http_response_sources == before[index].http_response_sources
        assert messages[index].tool_call_id == before[index].tool_call_id
    assert not rt.workflow.evidence and not rt.workflow.validation_results
    assert not rt.policy.observations._items  # No source created or adopted.
    assert len(messages[0].content) == len(before[0].content)
    reduced = deepcopy(messages)
    agent.guard_working_context(messages, events.append, request=request)
    assert messages == reduced  # No growing metadata chain on repeated admission.


@pytest.mark.parametrize('mode', ['direct', 'whole_target'])
@pytest.mark.parametrize('producer,source_count', [('http', 1), ('http', 6), ('browser_capture_get', 1)])
@pytest.mark.parametrize('old', [False, True])
async def test_http_handles_survive_actual_dispatch(tmp_path, monkeypatch,
        mode: WorkflowMode, producer, source_count, old):
    """Real producer/admission, mocked HTTP and model; include redirect sources."""
    monkeypatch.chdir(tmp_path)
    sent = []
    real_client = httpx.AsyncClient

    def respond(request):
        sent.append(request)
        hop = int(request.url.path.rsplit('/', 1)[-1])
        return httpx.Response(302 if hop + 1 < source_count else 200,
            headers={'location': f'/hop/{hop + 1}'} if hop + 1 < source_count else {},
            text=f'RESPONSE-{hop} ' * 1000, request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: real_client(
        transport=httpx.MockTransport(respond), **kw))
    client = FakeClient([ChatResponse(Message('assistant', 'Offline summary.'), 'stop')] * 3)
    rt = make_runtime(tmp_path, client)
    rt.workflow.objective = WorkflowObjective('context-audit', mode, ORIGIN)
    await execute(rt, 'load_skill', {'name': 'recon'})
    if producer == 'http':
        await execute(rt, 'http', {'url': '/hop/0', 'max_redirects': source_count - 1, 'phase': 'recon'})
    else:
        row = ingest(rt, respBody='IMPORTED RESPONSE ' * 600, responseComplete=True, status=200)
        await execute(rt, producer, {'id': row['id']})
    wire_calls = source_count if producer == 'http' else 0
    original = next(m for m in reversed(rt.agent.history) if m.name == producer)
    sources = list(original.http_response_sources or ())
    assert len(sources) == source_count and len(sent) == wire_calls
    assert set(sources) == set(rt.policy.observations._items)
    history_before = deepcopy(original)
    state_before = deepcopy(rt.workflow.to_dict())
    working = [Message('system', 'Fixed controller context. ' * 3000), *deepcopy(rt.agent.history)]
    if old:
        working.extend(Message('tool', 'Later result', name='workflow', tool_call_id=f'later-{i}')
                       for i in range(4))
    rt.agent.set_auto_compact_threshold(1000)
    request = ChatRequest(client.model(), working, tools=rt.agent.tools.as_llm_tools())
    await rt.agent._chat_for_turn(request, FakeSignal(), lambda _: None)
    delivered = next(m for m in client.requests[-1].messages if m.name == producer
                     and m.tool_call_id == original.tool_call_id)
    assert set(re.findall(r'obs_[0-9a-f]{32}', delivered.content)) == set(sources), delivered.content
    assert len(delivered.content) <= MIDTURN_RECENT_TOOL_RESULT_CHAR_FLOOR
    assert len(delivered.content) < len(original.content) / 3
    assert replace(delivered, content='') == replace(original, content='')
    assert next(m for m in rt.agent.history if m.name == producer) == history_before
    assert rt.workflow.to_dict() == state_before
    reduced = deepcopy(delivered)
    await rt.agent._chat_for_turn(request, FakeSignal(), lambda _: None)
    assert next(m for m in request.messages if m.name == producer) == reduced
    assert len(sent) == wire_calls and len(client.requests) == 2
    rt.policy.revoke(producer)
    await rt.agent._chat_for_turn(request, FakeSignal(), lambda _: None)
    revoked = next(m for m in request.messages if m.name == producer)
    assert not revoked.http_response_sources
    assert not set(sources).intersection(re.findall(r'obs_[0-9a-f]{32}', revoked.content))
    assert len(sent) == wire_calls  # Preserved handles cannot bypass revocation.


@pytest.mark.parametrize('mode', ['direct', 'whole_target'])
async def test_many_retained_handles_still_obey_hard_input_limit(tmp_path, mode: WorkflowMode):
    rt = make_runtime(tmp_path)
    rt.workflow.objective = WorkflowObjective('context-budget', mode, ORIGIN)
    # No source is needed: exercise the reducer directly, then use the same
    # request's measured floor to prove final admission still refuses overflow.
    messages = [Message('user', 'Summarize existing evidence.')]
    for index in range(64):
        messages.append(Message('tool', 'response body ' * 1000, name='http',
            tool_call_id=str(index), http_response_sources=['obs_' + f'{index:032x}']))
    request = ChatRequest(rt.client.model(), messages)
    rt.agent.set_auto_compact_threshold(1000)
    rt.agent.guard_working_context(messages, lambda _: None, request=request)
    bounded = deepcopy(messages)
    assert all(len(m.content) < 500 for m in messages[1:-4])
    assert all(len(m.content) <= MIDTURN_RECENT_TOOL_RESULT_CHAR_FLOOR for m in messages[-4:])
    rt.agent.guard_working_context(messages, lambda _: None, request=request)
    assert messages == bounded
    # Strip sources so an intentionally invalid test fixture cannot test access
    # rights. The equal-length reduced text is ordinary untrusted tool output.
    request.messages[:] = [replace(m, http_response_sources=None) for m in messages]
    setattr(rt.client, 'input_token_limit', 1000)
    with pytest.raises(ContextCapacityError):
        await rt.agent._chat_for_turn(request, FakeSignal(), lambda _: None)
    assert not rt.client.requests and not rt.policy.observations._items
