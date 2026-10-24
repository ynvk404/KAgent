"""Candidate-local mode guidance before dispatch, with no target/provider I/O."""
from copy import deepcopy
import json
from typing import Any

import httpx
import pytest

from src.agent.agent import AgentRunOptions
from src.llm.core.types import ChatRequest, ChatResponse, FunctionCall, Message, ToolCall
from src.workflow.state import AttackSurfaceInput, Candidate, WorkflowMode, WorkflowObjective
from tests.agent.test_workflow_request_preparation import SnapshotClient
from tests.helpers.agent_fakes import FakeSignal, seed_compactable_history
from tests.helpers.burp_selection import ORIGIN, make_runtime
from tests.helpers.workflow import prepare_validation_prerequisites

REAL_CLIENT = httpx.AsyncClient
CONTEXT = 'Untrusted current validation context observations;'
RECIPE = 'Current captured HTTP request contract'


def call(name, args):
    return ChatResponse(Message('assistant', '', tool_calls=[
        ToolCall(name, FunctionCall(name, json.dumps(args)))]), 'tool_calls')


def stop():
    return ChatResponse(Message('assistant', 'Offline fixture; assessment unresolved.'), 'stop')


def capture(rt, *, incomplete=False):
    payload: dict[str, Any] = {'kind': 'burp', 'id': 'mode-baseline', 'method': 'POST',
               'url': ORIGIN + '/login', 'requestBody': '{"email":"benign","keep":1}'}
    if not incomplete:
        payload['requestHeaders'] = [{'name': 'Content-Type', 'value': 'application/json'},
                                     {'name': 'Cookie', 'value': 'sid=offline-capture'}]
    return rt.capture.ingest(payload)


def candidate(rt, row=None, **fields):
    return rt.workflow.add_candidate(Candidate(
        candidate_class='sqli', target=ORIGIN, objective_id=rt.workflow.objective.id,
        method='POST', endpoint='/login', parameter='email', location='json',
        content_type='application/json',
        baseline_request_ref=row['baseline_request_ref'] if row else None,
        source_ref=row['id'] if row else None, **fields))[0]


async def start(rt, cand, skill='sql-injection'):
    rt.agent.active_skills.add(skill)
    if rt.workflow.objective.mode == 'whole_target':
        rt.workflow.add_attack_surface_input(AttackSurfaceInput(
            objective_id=rt.workflow.objective.id, target_origin=ORIGIN,
            method=cand.method, endpoint=cand.endpoint, parameter=cand.parameter,
            location=cand.location, content_type=cand.content_type, candidate_ids=[cand.id],
            baseline_request_ref=cand.baseline_request_ref, source_ref=cand.source_ref))
    await prepare_validation_prerequisites(rt.workflow_tool, cand.id)
    result = await rt.registry.execute('workflow', {
        'action': 'start_validation', 'candidate_id': cand.id}, None, rt.prompter)
    assert json.loads(result)['ok'], result


async def runtime(tmp_path, mode: WorkflowMode = 'direct', skill='sql-injection', *, bound=True, incomplete=False):
    rt = make_runtime(tmp_path)
    rt.workflow.objective = WorkflowObjective('mode-guidance', mode, ORIGIN)
    row = capture(rt, incomplete=incomplete) if bound else None
    # Both expert routes can validate this established JSON input. These tests
    # exercise request selection, not either class's confirmation threshold.
    cls = 'sqli' if skill == 'sql-injection' else 'xss'
    cand = rt.workflow.add_candidate(Candidate(
        candidate_class=cls, target=ORIGIN, objective_id=rt.workflow.objective.id,
        method='POST', endpoint='/login', parameter='email', location='json',
        content_type='application/json',
        baseline_request_ref=row['baseline_request_ref'] if row else None,
        source_ref=row['id'] if row else None))[0]
    await start(rt, cand, skill)
    return rt, cand


@pytest.fixture
def sent(monkeypatch):
    requests = []

    def transport(request):
        requests.append(request)
        return httpx.Response(200, content=b'Offline inert response', request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: REAL_CLIENT(
        transport=httpx.MockTransport(transport), **kw))
    return requests


def contexts(request):
    blocks = [m.content for m in request.messages if m.content.startswith(CONTEXT)]
    assert len(blocks) == 1
    return json.loads(blocks[0].split('\n', 1)[1])


def contract(request):
    return next(s['function']['description'] for s in request.tools
                if s['function']['name'] == 'http')


async def snapshot(rt, client, request=None):
    rt.agent.set_client(client)
    request = request or ChatRequest(client.model(), [Message('user', 'Continue')],
                                    tools=rt.registry.as_llm_tools())
    await rt.agent._chat_for_turn(request, FakeSignal(), lambda event: None)
    return client.requests[-1]


@pytest.mark.parametrize('mode', ['direct', 'whole_target'])
async def test_owned_candidate_outside_first_eight_has_first_context_and_recipe(tmp_path, mode):
    rt = make_runtime(tmp_path)
    rt.workflow.objective = WorkflowObjective('priority', mode, ORIGIN)
    row = capture(rt)
    candidates = sorted([candidate(rt, row, test_case=f'case-{i}') for i in range(9)], key=lambda c: c.id)
    current = candidates[-1]
    await start(rt, current)
    # Historical flags must not supersede the canonical owned attempt.
    candidates[0].status = 'validating'
    before = deepcopy(rt.workflow.to_dict())
    used, grants = rt.policy.used, list(rt.http.permissions.grants)
    request = await snapshot(rt, SnapshotClient([stop()]))
    rows = contexts(request)
    assert len(rows) == 8 and rows[0]['candidate_id'] == current.id
    assert rows[0]['baseline_request_ref'] == current.baseline_request_ref
    assert rows[0]['baseline']['available'] is True
    guidance = next(m.content for m in request.messages if m.content.startswith(RECIPE))
    templates = json.loads(guidance.split('templates: ', 1)[1].split('. Add ', 1)[0])
    assert templates[0] == {'phase': 'validation', 'candidate_id': current.id}
    rt.http.validate_args(templates[0])
    handoff = next(m.content for m in request.messages if m.content.startswith('Runtime validation continuation'))
    assert f'Candidate {current.id};' in handoff and 'owned_active=True' in handoff
    assert rt.workflow.to_dict() == before and rt.policy.used == used
    assert list(rt.http.permissions.grants) == grants and not rt.operator.requests
    assert rt.http.dispatch_attempts == 0


@pytest.mark.parametrize('profile', ['full', 'compact'])
@pytest.mark.parametrize('mode', ['direct', 'whole_target'])
@pytest.mark.parametrize('skill', ['sql-injection', 'cross-site-scripting'])
async def test_both_skills_get_mode_guidance_before_baseline_and_mutation(tmp_path, sent, profile, mode, skill):
    rt, cand = await runtime(tmp_path, mode, skill)
    rt.agent.set_prompt_profile(profile)
    baseline = {'phase': 'validation', 'candidate_id': cand.id}
    mutation = baseline | {'mutation_value': 'inert-marker', 'input_path': '/email'}
    client = SnapshotClient([call('load_skill', {'name': skill}), call('http', baseline),
                             call('http', mutation), *[stop() for _ in range(3)]])
    rt.agent.set_client(client)
    await rt.agent.run('Continue the current validation.', FakeSignal(), lambda event: None,
                       AgentRunOptions(max_steps=4))
    for request in client.requests[1:3]:
        assert contexts(request)[0]['candidate_id'] == cand.id
        description = contract(request)
        assert 'prefer Captured Replay' in description and 'supported input mutations' in description
        assert 'no bound capture or an independent request' in description
        assert 'stale/incomplete/unavailable capture is a blocker' in description
        guides = [m.content for m in request.messages if m.content.startswith(RECIPE)]
        assert len(guides) == 1 and cand.id in guides[0]
        assert 'For unchanged baseline replay omit mutation_value and all selectors' in guides[0]
        assert 'mutation_value must differ from the baseline' in guides[0]
        loaded = next(m for m in request.messages if m.name == 'load_skill' and m.role == 'tool')
        playbook = ' '.join(loaded.content.split())
        assert 'shared `http` tool contract and current Candidate validation context' in playbook
        if skill == 'cross-site-scripting':
            assert 'no bound capture, or an independent request' in playbook
    assert len(sent) == 2
    assert json.loads(sent[0].content) == {'email': 'benign', 'keep': 1}
    assert json.loads(sent[1].content) == {'email': 'inert-marker', 'keep': 1}
    assert all(request.headers['Cookie'] == 'sid=offline-capture' for request in sent)
    assert [q.tool for q in rt.operator.requests] == ['http_capture_credentials']
    observations = list(rt.policy.observations._items.values())
    assert len(observations) == 2
    assert all(o.source_details['request_mode'] == 'captured-replay' and
               o.source_details['baseline_request_ref'] == cand.baseline_request_ref for o in observations)
    assert observations[0].request_hash != observations[1].request_hash


@pytest.mark.parametrize('mode', ['direct', 'whole_target'])
@pytest.mark.parametrize('skill', ['sql-injection', 'cross-site-scripting'])
@pytest.mark.parametrize('unrelated_capture', [False, True])
async def test_no_bound_capture_keeps_direct_http_with_or_without_unrelated_capture(
        tmp_path, sent, mode, skill, unrelated_capture):
    rt, cand = await runtime(tmp_path, mode, skill, bound=False)
    if unrelated_capture:
        capture(rt)  # Even the same URL/input is not a Candidate baseline binding.
    request = await snapshot(rt, SnapshotClient([stop()]))
    row = contexts(request)[0]
    assert row['candidate_id'] == cand.id and row['baseline']['state'] == 'missing'
    assert row['baseline_request_ref'] is None and not row['baseline']['available']
    assert not any(m.content.startswith(RECIPE) for m in request.messages)
    assert 'no bound capture or an independent request' in contract(request)
    # Execute the fake model's explicit Direct request through normal admission.
    client = SnapshotClient([call('http', {'phase': 'validation', 'url': '/login', 'method': 'POST',
        'headers': {'Content-Type': 'application/json'}, 'body': '{"email":"inert-marker","keep":1}'})])
    rt.agent.set_client(client)
    response, _ = await rt.agent._chat_for_turn(ChatRequest(client.model(), [Message('user', 'Continue')],
        tools=rt.registry.as_llm_tools()), FakeSignal(), lambda event: None)
    tool_call = response.message.tool_calls[0]
    result = await rt.agent.run_parsed_tool_call(tool_call, rt.agent.parse_tool_call(tool_call), FakeSignal())
    assert result.status == 'observation', result.result
    assert len(sent) == 1 and 'cookie' not in sent[0].headers and 'authorization' not in sent[0].headers
    observation = next(iter(rt.policy.observations._items.values()))
    assert observation.candidate_id == cand.id
    assert observation.source_details['request_mode'] == 'direct'
    assert 'baseline_request_ref' not in observation.source_details
    assert not any(q.tool == 'http_capture_credentials' for q in rt.operator.requests)


@pytest.mark.parametrize('mode', ['direct', 'whole_target'])
@pytest.mark.parametrize('fault', ['stale', 'incomplete'])
async def test_bound_unavailable_capture_is_a_blocker_without_replay_recipe(tmp_path, mode, fault):
    rt, cand = await runtime(tmp_path, mode, incomplete=fault == 'incomplete')
    if fault == 'stale':
        rt.capture.clear()
    before = deepcopy(rt.workflow.to_dict())
    request = await snapshot(rt, SnapshotClient([stop()]))
    row = contexts(request)[0]
    assert row['candidate_id'] == cand.id and row['baseline_request_ref'] == cand.baseline_request_ref
    assert row['baseline']['state'] == ('stale_or_unbound' if fault == 'stale' else 'incomplete_or_unsupported')
    assert not row['baseline']['available']
    assert not any(m.content.startswith(RECIPE) for m in request.messages)
    assert any('do not reconstruct that request as Direct HTTP' in m.content for m in request.messages)
    assert rt.workflow.to_dict() == before and not rt.operator.requests and not rt.http.dispatch_attempts


@pytest.mark.parametrize('transition', ['continue', 'compaction', 'resume'])
@pytest.mark.parametrize('profile', ['full', 'compact'])
async def test_continuation_rederives_capture_availability_and_replaces_old_guidance(tmp_path, transition, profile):
    rt, cand = await runtime(tmp_path)
    rt.agent.set_prompt_profile(profile)
    client = SnapshotClient([stop(), stop()])
    req = ChatRequest(client.model(), [Message('user', 'Continue')], tools=rt.registry.as_llm_tools())
    first = await snapshot(rt, client, req)
    assert contexts(first)[0]['baseline']['available']
    assert any(m.content.startswith(RECIPE) for m in first.messages)
    if transition == 'compaction':
        frozen = rt.agent._workflow_request_view('Continue', rt.registry.as_llm_tools())
        rt.agent._pending_context = rt.agent._snapshot_context('Continue', req, frozen.blocks)
    rt.capture.clear()
    if transition == 'compaction':
        seed_compactable_history(rt.agent, 20000)
        rt.agent.history.extend([Message('user', 'Continue'), Message('assistant', 'Unresolved fixture')])
        await rt.agent.apply_compaction_summary('## Objectives\n- Continue bounded validation\n## Completed\n- Fixture handoff',
                                               deepcopy(rt.agent.history), 'offline mode fixture')
        req = ChatRequest(client.model(), deepcopy(rt.agent.history), tools=rt.registry.as_llm_tools())
    elif transition == 'resume':
        await rt.agent.save()
        rt = make_runtime(tmp_path)
        rt.agent.set_prompt_profile(profile)
        rt.agent.resume_saved()
        req = ChatRequest(client.model(), deepcopy(rt.agent.history), tools=rt.registry.as_llm_tools())
        # Skill activation expires on resume. First inspect the fresh context
        # with HTTP hidden, then reload through normal dispatch before HTTP.
        resumed = await snapshot(rt, client, req)
        assert contexts(resumed)[0]['baseline']['state'] == 'stale_or_unbound'
        assert not any(m.content.startswith(RECIPE) for m in resumed.messages)
        assert not any(s['function']['name'] == 'http' for s in resumed.tools)
        response = call('load_skill', {'name': 'sql-injection'})
        assert response.message.tool_calls
        load = response.message.tool_calls[0]
        parsed = rt.agent.parse_tool_call(load)
        loaded = await rt.agent.run_parsed_tool_call(load, parsed, FakeSignal())
        assert loaded.status == 'success'
        rt.agent.history.append(response.message)
        req.messages.append(response.message)
        rt.agent.record_tool_result(load, parsed, loaded, lambda event: None, req.messages,
                                    defer_admission=True)
        client.scripted.append(stop())
        req.tools = rt.registry.as_llm_tools()
    before = deepcopy(rt.agent.workflow.to_dict())
    latest = await snapshot(rt, client, req)
    row = contexts(latest)[0]
    assert row['candidate_id'] == cand.id and row['baseline']['state'] == 'stale_or_unbound'
    assert not row['baseline']['available']
    assert not any(m.content.startswith(RECIPE) for m in latest.messages)
    assert any('do not reconstruct that request as Direct HTTP' in m.content for m in latest.messages)
    assert rt.agent.workflow.to_dict() == before and not rt.http.dispatch_attempts
