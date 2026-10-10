"""One-shot capture context, admission, revision and cancellation invariants."""
import asyncio
from copy import deepcopy
import json

import pytest

from src.agent.agent import AgentRunOptions
from src.agent.context_estimate import estimate_request
from src.agent.decision_planner import build_decision_plan
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.permission.runtime.execution import ExecutionBlocked
from src.workflow.state import Candidate, WorkflowObjective
from tests.helpers.agent_fakes import FakeClient, FakeSignal, seed_compactable_history
from tests.helpers.burp_selection import ORIGIN, ingest, make_runtime


def answer(text='Analysis only; no testing performed.'):
    return ChatResponse(Message('assistant', text), 'stop')


def call(name, args, id_='read'):
    return ChatResponse(Message('assistant', '', tool_calls=[ToolCall(id=id_, function=FunctionCall(name, json.dumps(args)))]), 'tool_calls')


@pytest.fixture
def runtime(tmp_path):
    return make_runtime(tmp_path, FakeClient([answer(), answer()]))


@pytest.mark.asyncio
async def test_snapshot_frozen_consumed_once_and_not_persisted(runtime):
    first = ingest(runtime)
    selected, _ = runtime.agent.select_burp_captures()
    ingest(runtime, 'later')
    await runtime.agent.run('Analyze this request', FakeSignal(), lambda _: None)
    data = '\n'.join(m.content for m in runtime.client.requests[0].messages)
    assert selected.observation() in data
    assert first['id'] in data and 'burp:later' not in data
    assert runtime.agent.pending_capture_selection is None
    assert runtime.agent._pending_context is None
    assert not any('one-turn snapshot' in m.content for m in runtime.agent.history)
    saved = runtime.agent.store.load()
    assert not any('one-turn snapshot' in m.content for m in saved.messages)
    assert not saved.workflow.candidates
    await runtime.agent.run('Analyze a new task', FakeSignal(), lambda _: None)
    assert not any('one-turn snapshot' in m.content for m in runtime.client.requests[1].messages)


@pytest.mark.asyncio
async def test_consume_precedes_first_await_and_busy_reentry_does_not_steal(runtime, monkeypatch):
    ingest(runtime)
    selected, _ = runtime.agent.select_burp_captures()
    started, release = asyncio.Event(), asyncio.Event()
    async def finish(*args):
        assert runtime.agent.pending_capture_selection is None
        assert runtime.agent._turn_capture_selection() is selected
        started.set()
        await release.wait()
    monkeypatch.setattr(runtime.agent, '_finish_tool_results', finish)
    task = asyncio.create_task(runtime.agent.run('Analyze', FakeSignal(), lambda _: None))
    await started.wait()
    with pytest.raises(ValueError, match='already running'):
        runtime.agent.select_burp_captures()
    await runtime.agent.run('Rejected concurrent turn', FakeSignal(), lambda _: None)
    assert runtime.agent._turn_capture_selection() is selected
    release.set()
    await task
    assert len(runtime.client.requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['error', 'cancel'])
async def test_failed_or_cancelled_turn_does_not_requeue(runtime, monkeypatch, kind):
    ingest(runtime)
    selected, _ = runtime.agent.select_burp_captures()
    async def fail(request, signal=None):
        assert selected.observation() in '\n'.join(m.content for m in request.messages)
        raise asyncio.CancelledError() if kind == 'cancel' else RuntimeError('offline error')
    monkeypatch.setattr(runtime.client, 'chat', fail)
    if kind == 'cancel':
        with pytest.raises(asyncio.CancelledError):
            await runtime.agent.run('Analyze', FakeSignal(), lambda _: None)
    else:
        await runtime.agent.run('Analyze', FakeSignal(), lambda _: None)
    assert runtime.agent.pending_capture_selection is None and runtime.agent._pending_context is None


@pytest.mark.asyncio
async def test_tools_false_drops_pending_and_notifies_without_capture_tools(runtime):
    ingest(runtime)
    runtime.agent.select_burp_captures()
    events = []
    await runtime.agent.run('Plan only', FakeSignal(), events.append, AgentRunOptions(tools=False))
    assert runtime.agent.pending_capture_selection is None
    assert not runtime.client.requests[0].tools
    assert not any('one-turn snapshot' in m.content for m in runtime.client.requests[0].messages)
    assert any('tools=False' in e.get('summary', '') for e in events)
    assert runtime.policy.used == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('change', ['scope', 'target_path', 'target', 'deny', 'revoke_restore', 'http_revoke_retry'])
async def test_revision_change_invalidates_old_binding_even_after_restore(runtime, change):
    ingest(runtime)
    selected, _ = runtime.agent.select_burp_captures()
    if change == 'scope':
        runtime.engagement.add_origin('http://secondary.test')
    elif change == 'target_path':
        runtime.target.set_base_url(ORIGIN + '/other')
    elif change == 'target':
        runtime.target.set_base_url('http://other.test')
    elif change == 'deny':
        runtime.engagement.http_permissions.deny_session()
    elif change == 'revoke_restore':
        runtime.policy.revoke('browser_capture_get')
        runtime.policy.restore_tool('browser_capture_get')
    else:
        rights = runtime.engagement.http_permissions
        rights.revoke(next(iter(rights.grants.values())).id)
        rights.retry(ORIGIN)
    with pytest.raises(ExecutionBlocked, match='invalidated'):
        selected.validate(runtime.capture, runtime.target, runtime.engagement, runtime.policy)
    events = []
    await runtime.agent.run('Analyze selected request', FakeSignal(), events.append)
    assert not runtime.client.requests
    assert runtime.agent.pending_capture_selection is None
    assert any(e.get('stop_reason') == 'capture_unavailable' for e in events)


@pytest.mark.asyncio
async def test_target_prompt_invalidates_consumed_selection_before_planner(runtime):
    ingest(runtime)
    runtime.agent.select_burp_captures()
    await runtime.agent.run('Test http://other.test for SQL injection', FakeSignal(), lambda _: None)
    assert runtime.target.origin().as_url() == 'http://other.test'
    assert not runtime.client.requests and not runtime.workflow.candidates


def test_scope_noop_preserves_selection_real_changes_and_target_command_cancel(runtime):
    ingest(runtime)
    selected, _ = runtime.agent.select_burp_captures()
    _, changed = runtime.agent.add_scope_origin(ORIGIN + '/same')
    assert not changed and runtime.agent.pending_capture_selection is selected
    selected.validate(runtime.capture, runtime.target, runtime.engagement, runtime.policy)
    runtime.agent.add_scope_origin('http://secondary.test')
    assert runtime.agent.pending_capture_selection is None
    runtime.agent.select_burp_captures()
    runtime.agent.apply_target_base_url(ORIGIN + '/different')
    assert runtime.agent.pending_capture_selection is None


@pytest.mark.parametrize('change', ['evict', 'clear_reuse', 'mutate', 'ref', 'restart'])
def test_stale_capture_never_falls_back(runtime, change):
    row = ingest(runtime)
    selected, _ = runtime.agent.select_burp_captures()
    ingest(runtime, 'newer')
    if change == 'evict':
        runtime.capture.requests.pop(row['id'])
    elif change == 'clear_reuse':
        runtime.capture.clear()
        ingest(runtime)
    elif change == 'mutate':
        runtime.capture.requests[row['id']].url = ORIGIN + '/changed'
    elif change == 'ref':
        runtime.capture.requests[row['id']].baseline_request_ref = 'baseline:changed'
    else:
        from src.browser.store import CaptureStore
        new_store = CaptureStore()
        new_store.ingest({'kind': 'burp', 'id': 'one', 'url': ORIGIN + '/search?q=first'})
        runtime.capture = new_store
    with pytest.raises(ExecutionBlocked, match='unavailable|binding changed'):
        selected.validate(runtime.capture, runtime.target, runtime.engagement, runtime.policy)


def test_response_update_keeps_binding_but_request_variant_does_not_retarget(runtime):
    row = ingest(runtime, requestHeaders=[{'name': 'X-Fixture', 'value': 'stable'}])
    selected, _ = runtime.agent.select_burp_captures()
    update = ingest(runtime, status=201, respBody='updated response')
    assert update['id'] == row['id'] and update['baseline_request_ref'] == row['baseline_request_ref']
    selected.validate(runtime.capture, runtime.target, runtime.engagement, runtime.policy)
    variant = ingest(runtime, requestHeaders=[{'name': 'X-Fixture', 'value': 'changed'}])
    assert variant['id'] != row['id']
    assert selected.requests[0].retrieval_id == row['id']
    selected.validate(runtime.capture, runtime.target, runtime.engagement, runtime.policy)


@pytest.mark.asyncio
async def test_incomplete_baseline_readable_for_analysis_but_replay_blocked(runtime):
    row = ingest(runtime, method='POST', path='/upload', rawRequestB64='invalid', requestBody='text')
    runtime.agent.select_burp_captures()
    runtime.client.scripted = [call('browser_capture_get', {'id': row['id']}), answer()]
    await runtime.agent.run('Analyze metadata only', FakeSignal(), lambda _: None)
    assert any(m.name == 'browser_capture_get' and row['baseline_request_ref'] in m.content
               for m in runtime.agent.history)
    candidate, _ = runtime.workflow.add_candidate(Candidate(candidate_class='sqli', method='POST',
        target=ORIGIN, endpoint='/upload', parameter='q', location='body', baseline_request_ref=row['baseline_request_ref']))
    with pytest.raises((ValueError, PermissionError), match='raw|capture|baseline'):
        runtime.http.prepare({'candidate_id': candidate.id, 'phase': 'validation'})


@pytest.mark.asyncio
async def test_retry_and_compaction_keep_same_context_and_count_its_cost(runtime):
    ingest(runtime)
    selected, _ = runtime.agent.select_burp_captures()
    runtime.agent.auto_compact_threshold = runtime.agent.idle_request_estimate().estimated_total + 4000
    seed_compactable_history(runtime.agent, size=80000)
    runtime.client.scripted = [answer('Earlier history summarized.'), answer('<tool_calls><invoke name="browser_capture_get"><arguments>{}</arguments></invoke></tool_calls>'), answer()]
    events = []
    await runtime.agent.run('Analyze selected context only', FakeSignal(), events.append)
    assert any(e['type'] == 'compact' for e in events)
    main_requests = [r for r in runtime.client.requests if r.tools]
    assert len(main_requests) == 2
    for req in main_requests:
        assert selected.observation() in '\n'.join(m.content for m in req.messages)
        without = deepcopy(req)
        without.messages = [m for m in without.messages if 'one-turn snapshot' not in m.content]
        assert estimate_request(req, runtime.client.name()).estimated_total > estimate_request(without, runtime.client.name()).estimated_total
    assert runtime.agent.pending_capture_selection is None


def test_planner_and_bounded_context_share_selection_and_ignore_unrelated_candidate(runtime):
    ingest(runtime)
    old = WorkflowObjective('old-objective', 'direct', ORIGIN)
    runtime.workflow.objective = old
    old_candidate, _ = runtime.workflow.add_candidate(Candidate(candidate_class='sqli', target=ORIGIN,
        endpoint='/old', parameter='old', location='query', objective_id=old.id))
    selected, _ = runtime.agent.select_burp_captures()
    from src.agent.agent import _TurnContext
    runtime.agent._pending_context = _TurnContext(None, None, False, None, capture_selection=selected)
    runtime.agent._initialize_request_objective('Continue testing for SQL injection', True)
    objective = runtime.workflow.objective
    assert objective is not None and objective.id != old.id
    assert runtime.workflow.candidates[old_candidate.id].objective_id == old.id
    assert runtime.agent._has_bounded_goal_context(objective, 'Test SQL injection')
    planner = runtime.agent._planner_context()
    assert planner.selected_capture_ids == ('burp:one',) and not planner.candidates
    plan = build_decision_plan('Test SQL injection', runtime.agent.skills.list_enabled(), runtime.target, planner)
    assert plan is not None and 'browser_capture_get' in plan.guidance
    assert old_candidate.id not in plan.guidance
    working = [Message('system', plan.guidance), Message('user', selected.observation())]
    runtime.agent._refresh_requested_goal_guidance(working, 'Test SQL injection')
    assert selected.observation() in '\n'.join(m.content for m in working)
    assert runtime.agent._turn_capture_selection() is selected


@pytest.mark.asyncio
async def test_resume_does_not_restore_pending_or_transient_selection(runtime):
    ingest(runtime)
    runtime.agent.select_burp_captures()
    await runtime.agent.save()
    runtime.agent.resume_saved()
    assert runtime.agent.pending_capture_selection is None
    assert not any('one-turn snapshot' in m.content for m in runtime.agent.history)


@pytest.mark.asyncio
async def test_midturn_revocation_prevents_dispatch_even_after_llm_started(runtime, monkeypatch):
    row = ingest(runtime)
    runtime.agent.select_burp_captures()
    async def chat(request, signal=None):
        runtime.policy.revoke('browser_capture_get')
        return call('browser_capture_get', {'id': row['id']})
    monkeypatch.setattr(runtime.client, 'chat', chat)
    await runtime.agent.run('Analyze', FakeSignal(), lambda _: None)
    assert runtime.policy.used == 0
    assert not any(m.name == 'browser_capture_get' and 'baseline_request_ref' in m.content
                   for m in runtime.agent.history)
    assert runtime.agent.pending_capture_selection is None


@pytest.mark.asyncio
async def test_selection_context_is_included_in_hard_admission(runtime, monkeypatch):
    from src.llm.runtime.context_budget import InputBudget
    from src.agent.agent import ContextCapacityError
    from src.browser.selection import CAPTURE_GUIDANCE
    ingest(runtime)
    selected, _ = runtime.agent.select_burp_captures()
    original = runtime.agent._admit_request
    async def admit(request, emit):
        without = deepcopy(request)
        without.messages = [m for m in without.messages if 'one-turn snapshot' not in m.content
                            and m.content != CAPTURE_GUIDANCE]
        low = estimate_request(without, runtime.client.name()).estimated_total
        full = estimate_request(request, runtime.client.name()).estimated_total
        assert full > low
        assert selected.observation() in '\n'.join(m.content for m in request.messages)
        monkeypatch.setattr(runtime.agent, 'input_budget', lambda: InputBudget(low, 'fixture'))
        await original(request, emit)
    monkeypatch.setattr(runtime.agent, '_admit_request', admit)
    events = []
    await runtime.agent.run('Analyze selected context', FakeSignal(), events.append)
    assert not runtime.client.requests
    assert any(isinstance(e.get('err'), ContextCapacityError) for e in events)
    assert runtime.agent.pending_capture_selection is None


@pytest.mark.asyncio
async def test_new_selection_does_not_reuse_old_whole_target_objective(runtime):
    ingest(runtime)
    runtime.workflow.objective = WorkflowObjective('old-whole', 'whole_target', ORIGIN)
    runtime.agent.select_burp_captures()
    await runtime.agent.run('Analyze selected request only', FakeSignal(), lambda _: None)
    assert runtime.workflow.objective is not None
    assert runtime.workflow.objective.mode == 'direct' and runtime.workflow.objective.id != 'old-whole'
    assert not runtime.workflow.candidates


def test_repeat_selection_of_same_direct_source_preserves_ownership_without_parameter_inference(runtime):
    row = ingest(runtime)
    objective = WorkflowObjective('owned-source', 'direct', ORIGIN)
    runtime.workflow.objective = objective
    candidate, _ = runtime.workflow.add_candidate(Candidate(candidate_class='sqli', target=ORIGIN,
        endpoint='/search', method='GET', parameter='q', location='query',
        baseline_request_ref=row['baseline_request_ref'], objective_id=objective.id))
    selection, _ = runtime.agent.select_burp_captures()
    from src.agent.agent import _TurnContext
    runtime.agent._pending_context = _TurnContext(None, None, False, None, capture_selection=selection)
    runtime.agent._initialize_request_objective('Test the selected request for SQL injection', True)
    assert runtime.workflow.objective is objective
    assert len(runtime.workflow.candidates) == 1
    assert candidate.objective_id == objective.id
    assert runtime.agent._planner_context().candidates[0].id == candidate.id
    runtime.agent._initialize_request_objective('Analyze the request only', True)
    assert runtime.workflow.objective is not objective
    assert not runtime.agent._planner_context().candidates


@pytest.mark.asyncio
async def test_id_reuse_between_controller_check_and_native_get_never_reads_replacement(runtime, monkeypatch):
    row = ingest(runtime)
    runtime.agent.select_burp_captures()
    runtime.client.scripted = [call('browser_capture_get', {'id': row['id']}), answer()]
    execute = runtime.agent.tools.execute
    async def replace_before_get(name, args, signal, prompter):
        if name == 'browser_capture_get':
            assert args['baseline_request_ref'] == row['baseline_request_ref']
            runtime.capture.clear()
            ingest(runtime, path='/replacement?q=new')
        return await execute(name, args, signal, prompter)
    monkeypatch.setattr(runtime.agent.tools, 'execute', replace_before_get)
    await runtime.agent.run('Analyze', FakeSignal(), lambda _: None)
    reads = [m.content for m in runtime.agent.history if m.name == 'browser_capture_get']
    assert reads and 'binding changed' in reads[0]
    assert '/replacement' not in reads[0]
    assert not runtime.workflow.candidates and runtime.agent.pending_capture_selection is None


@pytest.mark.asyncio
async def test_cancelled_goals_still_recheck_consumed_capture_before_planning(runtime):
    ingest(runtime)
    runtime.workflow.objective = WorkflowObjective('old-request', 'direct', ORIGIN)
    runtime.workflow.objective.add_requested_goal('sql-injection')
    runtime.agent.select_burp_captures()
    runtime.policy.revoke('browser_capture_get')
    await runtime.agent.run('cancel', FakeSignal(), lambda _: None)
    assert not runtime.client.requests and runtime.agent.pending_capture_selection is None


@pytest.mark.asyncio
@pytest.mark.parametrize('mismatch', ['baseline', 'source', 'endpoint', 'method', 'origin', 'ambiguous'])
async def test_selected_candidate_rejects_conflicting_or_ambiguous_binding(runtime, mismatch):
    row = ingest(runtime)
    other = ingest(runtime, 'other', path='/search?q=second')
    if mismatch == 'ambiguous':
        runtime.agent.select_burp_captures(all_recent=True)
    else:
        runtime.agent.select_burp_captures(row['id'])
    args = {'action': 'record_candidate', 'candidate_class': 'sqli', 'endpoint': '/search',
            'method': 'GET', 'parameter': 'q', 'location': 'query'}
    if mismatch == 'baseline':
        args['baseline_request_ref'] = other['baseline_request_ref']
    elif mismatch == 'source':
        args['source_ref'] = other['id']
    elif mismatch == 'endpoint':
        args['endpoint'] = '/different'
    elif mismatch == 'method':
        args['method'] = 'POST'
    elif mismatch == 'origin':
        args['target'] = 'http://other.test'
    runtime.client.scripted = [call('workflow', args), answer()]
    await runtime.agent.run('Analyze this selected request', FakeSignal(), lambda _: None)
    result = next(m for m in runtime.agent.history if m.name == 'workflow')
    assert result.tool_status == 'error'
    assert not runtime.workflow.candidates


@pytest.mark.asyncio
async def test_selected_candidate_source_disambiguates_same_endpoint_and_preserves_shorthand(runtime):
    first = ingest(runtime)
    second = ingest(runtime, 'second', path='/search?q=second')
    runtime.agent.select_burp_captures(all_recent=True)
    runtime.client.scripted = [call('workflow', {'action': 'record_candidate', 'candidate_class': 'sqli',
        'endpoint': 'GET /search', 'parameter': 'q', 'location': 'query', 'source_ref': first['id']}), answer()]
    await runtime.agent.run('Analyze the first selected request', FakeSignal(), lambda _: None)
    candidate = next(iter(runtime.workflow.candidates.values()))
    assert candidate.baseline_request_ref == first['baseline_request_ref']
    assert candidate.baseline_request_ref != second['baseline_request_ref']
    assert (candidate.method, candidate.endpoint, candidate.parameter) == ('GET', '/search', 'q')


@pytest.mark.asyncio
async def test_selected_capture_cannot_validate_unbound_old_candidate(runtime):
    ingest(runtime)
    candidate, _ = runtime.workflow.add_candidate(Candidate(candidate_class='sqli', target=ORIGIN,
        endpoint='/search', method='GET', parameter='q', location='query'))
    runtime.agent.select_burp_captures()
    runtime.client.scripted = [call('workflow', {'action': 'start_validation', 'candidate_id': candidate.id}), answer()]
    await runtime.agent.run('Analyze selected capture', FakeSignal(), lambda _: None)
    result = next(m for m in runtime.agent.history if m.name == 'workflow')
    assert result.tool_status == 'error' and 'not bound' in result.content
    assert candidate.baseline_request_ref is None and candidate.status != 'validating'


@pytest.mark.asyncio
async def test_real_provider_transport_retry_retains_redacted_frozen_selection(runtime, monkeypatch):
    import httpx
    from src.llm.providers.openai import OpenAIClient
    row = ingest(runtime, path='/search?q=provider-capture-secret',
                 requestHeaders=[{'name': 'Authorization', 'value': 'Bearer provider-capture-secret'}])
    selected, _ = runtime.agent.select_burp_captures()
    payloads = []
    def transport(request):
        data = json.loads(request.content)
        payloads.append(data)
        contents = '\n'.join(m['content'] for m in data['messages'])
        assert selected.observation() in contents
        assert row['id'] in contents and 'burp:later' not in contents
        assert 'provider-capture-secret' not in contents
        assert runtime.agent.pending_capture_selection is None
        assert runtime.agent._turn_capture_selection() is selected
        if len(payloads) == 1:
            ingest(runtime, 'later')
            return httpx.Response(503, json={'error': {'message': 'temporary fixture error'}})
        return httpx.Response(200, json={'choices': [{'message': {'role': 'assistant',
                              'content': 'Analysis only; no testing performed.'}, 'finish_reason': 'stop'}]})
    monkeypatch.setattr('src.llm.providers.openai.new_provider_async_client',
                        lambda: httpx.AsyncClient(transport=httpx.MockTransport(transport)))
    runtime.agent.client = OpenAIClient('https://provider.fixture/v1', model='fixture-model')
    await runtime.agent.run('Analyze selected request', FakeSignal(), lambda _: None)
    assert len(payloads) == 2 and payloads[0] == payloads[1]
    assert runtime.agent.request_metrics.records[-1].retry_count == 1
    assert runtime.agent.pending_capture_selection is None
