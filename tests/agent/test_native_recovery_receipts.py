"""Native controller/Burp/HTTP fixtures. No provider or network transport."""
import json
from typing import Any

import httpx
import pytest

from src.agent.agent import _TurnContext, _to_agent_event
from src.agent.events import ToolResultEvent
from src.llm.core.types import FunctionCall, ToolCall
from src.ui.core.state import AgentEventAction, SetBusy
from src.workflow.state import WorkflowObjective
from tests.helpers.agent_fakes import FakeSignal
from tests.helpers.burp_selection import ORIGIN, make_runtime, ingest
from tests.ui.test_app import make_app

REAL_CLIENT = httpx.AsyncClient


def attach(runtime):
    runtime.workflow.objective = WorkflowObjective('offline-objective', 'direct', ORIGIN)
    app = make_app()
    app.agent = runtime.agent
    app.dispatch(SetBusy(True))
    return app


async def invoke(app, identifier, name, args):
    agent = app.agent
    call = ToolCall(identifier, FunctionCall(name, json.dumps(args)))
    parsed = agent.parse_tool_call(call)
    event = _to_agent_event(agent._tool_call_event(call, parsed))
    app.dispatch(AgentEventAction(event))
    output = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    event = _to_agent_event(agent._tool_result_event(call, output, parsed.invocation))
    app.dispatch(AgentEventAction(event))
    return output, event


@pytest.mark.parametrize('association', ['trusted', 'missing', 'other_capture', 'changed_baseline', 'changed_hypothesis'])
async def test_selected_observation_repair_requires_trusted_current_association(tmp_path, association):
    runtime = make_runtime(tmp_path)
    capture = ingest(runtime)
    other = ingest(runtime, 'other', path='/other')
    app = attach(runtime)
    selection, _ = runtime.agent.select_burp_captures(capture['id'])
    runtime.agent._pending_context = _TurnContext(None, None, False, None, capture_selection=selection)
    detail, _ = await invoke(app, 'read', 'browser_capture_get', {'id':
        other['id'] if association == 'other_capture' else capture['id']})
    observation = json.loads(detail.result)['runtime_observation_id']
    args = {'action': 'record_candidate', 'candidate_class': 'sqli', 'method': 'GET',
            'endpoint': '/search', 'parameter': 'q', 'location': 'query', 'test_case': 'predicate',
            'source_ref': 'obs_' + 'f' * 32 if association == 'missing' else observation}
    if association == 'changed_baseline':
        args['baseline_request_ref'] = other['baseline_request_ref']
    bad, _ = await invoke(app, 'bad', 'workflow', args)
    assert bad.status == 'error' and bad.error_kind == 'invalid_args'
    assert 'source_ref' in bad.result and 'retrieval ID' in bad.result
    assert not runtime.workflow.candidates
    corrected = {key: value for key, value in args.items() if key not in {'source_ref', 'baseline_request_ref'}}
    if association == 'changed_hypothesis':
        corrected['test_case'] = 'different'
    good, _ = await invoke(app, 'retry', 'workflow', corrected)
    assert json.loads(good.result)['ok'] is True
    candidate = next(iter(runtime.workflow.candidates.values()))
    assert candidate.source_ref == capture['id']
    assert candidate.baseline_request_ref == capture['baseline_request_ref']
    assert app.state.issues[-1].recovered == (association == 'trusted')
    assert not runtime.client.requests  # No model invocation.


@pytest.mark.parametrize('variant', ['exact', 'query', 'body', 'auth', 'timeout', 'read_error', 'redirects'])
async def test_native_network_retry_needs_no_send_and_same_effective_request(tmp_path, monkeypatch, variant):
    runtime = make_runtime(tmp_path)
    app = attach(runtime)
    sent = []
    def transport(request):
        sent.append(request)
        if len(sent) == 1:
            error = httpx.ConnectError if variant not in {'timeout', 'read_error'} else (
                httpx.ReadTimeout if variant == 'timeout' else httpx.ReadError)
            raise error('offline transport failure', request=request)
        return httpx.Response(200, content=b'fixture', request=request)
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs:
        REAL_CLIENT(transport=httpx.MockTransport(transport), **kwargs))
    args: dict[str, Any] = {'phase': 'recon', 'method': 'POST', 'url': ORIGIN + '/form?q=A', 'body': 'mode=A',
            'auth_context_ref': 'fixture-identity'}
    if variant == 'redirects':
        args['max_redirects'] = 1
    failed, failure_event = await invoke(app, 'bad', 'http', args)
    assert failed.status == 'error'
    assert failure_event.recovery_receipt is not None if variant in {'exact', 'query', 'body', 'auth'} else failure_event.recovery_receipt is None
    repaired = dict(args)
    if variant == 'query':
        repaired['url'] = ORIGIN + '/form?q=B'
    elif variant == 'body':
        repaired['body'] = 'mode=B'
    elif variant == 'auth':
        runtime.http.context_store._authorization[(runtime.target.origin(), 'fixture-identity')] = 'Bearer changed-fixture'
    success, event = await invoke(app, 'retry', 'http', repaired)
    assert success.status == 'observation' and len(sent) == 2
    assert app.state.issues[0].recovered == (variant == 'exact')
    if variant == 'exact':
        assert event.recovery_receipt and event.recovery_receipt.completed
        assert app.state.issues[0].recovered_by == event.invocation.id
    assert not runtime.client.requests
