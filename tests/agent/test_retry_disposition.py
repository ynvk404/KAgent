"""Offline lifecycle contracts, not a claim about unscripted model reliability."""
from copy import deepcopy
import json

import pytest

from src.agent.decision_planner import build_whole_target_plan
from src.workflow.evidence.recovery import current_budget, MAX_TERMINAL_REPAIR_TURNS
from src.workflow.state import WorkflowState
from tests.agent.test_validation_continuation import (
    InspectModel, candidate_for, compact_with_misleading_summary, execute, offline, workflow,
)


DECLINE = {'decision': 'decline', 'reason': 'The retained responses leave the oracle unresolved; no useful bounded alternative was identified.'}
RETRY = {'decision': 'retry', 'reason': 'Existing parser diagnostics support reassessing the expression boundary before testing a harmless computed marker.'}


async def call(rt, action, **args):
    result = await rt.registry.execute('workflow', {'action': action, **args}, None, rt.prompter)
    assert not result.startswith('error:'), result
    return json.loads(result)


async def inconclusive(rt, decision=None):
    cid = await candidate_for(rt)
    await call(rt, 'start_validation', candidate_id=cid)
    await call(rt, 'record_result', candidate_id=cid, skill_name='sql-injection',
               outcome='insufficient-evidence', deferred_reason='Parser sensitivity without an interpretable output oracle.',
               **({'retry_decision': decision} if decision else {}))
    return cid


async def other_discovery(rt):
    cid = await candidate_for(rt, 'xss')
    await call(rt, 'record_candidate', candidate_class='xss', endpoint='/fixture', method='GET',
               parameter='q', location='query', status='deferred',
               deferred_reason='The request shape remains uncertain.',
               discovery_next_step='Review retained documentation for a compatible request shape.')
    return cid


def close_discovery(cid):
    return workflow('record_candidate', candidate_class='xss', endpoint='/fixture', method='GET',
                    parameter='q', location='query', status='deferred', discovery_next_step=None,
                    deferred_reason='Operator excluded this unresolved request from further work.')


@pytest.mark.parametrize('retry', [False, True])
async def test_last_discovery_does_not_hide_undecided_retry(offline, retry):
    rt, sent = offline
    cid = await inconclusive(rt)
    other = await other_discovery(rt)
    assert rt.agent._whole_target_state()[0] == 'actionable'
    old_attempt = rt.workflow.latest_result(cid).attempt_id

    def script():
        yield close_discovery(other)
        status, actions, blockers = rt.agent._whole_target_state()
        assert status == 'decision_pending' and not actions and blockers
        assert rt.workflow.retry_decision(cid) is None
        if retry:
            yield 'load_skill', {'name': 'sql-injection'}
            started = json.loads((yield workflow('start_validation', candidate_id=cid,
                assessment={'hypothesis': RETRY['reason']})))
            new_attempt = started['validation_context']['attempt_id']
            assert new_attempt != old_attempt
            assert rt.workflow.attempts[new_attempt]['criteria']['hypothesis'] == RETRY['reason']
            yield workflow('record_result', candidate_id=cid, skill_name='sql-injection',
                           outcome='insufficient-evidence', retry_decision=DECLINE)
        else:
            yield workflow('record_retry_decision', candidate_id=cid, retry_decision=DECLINE)

    model = InspectModel(script())
    done = await execute(rt, model, steps=9)
    assert model.consumed and done.stop_reason == 'workflow_blocked'
    assert len([r for r in model.requests if r.tools]) == (4 if retry else 2)
    assert rt.workflow.retry_decision(cid) == DECLINE and not sent
    assert not rt.workflow.eligible_for_finding(cid)


async def test_decline_on_closure_needs_no_extra_decision_turn(offline):
    rt, sent = offline
    cid = await candidate_for(rt)

    def script():
        yield workflow('start_validation', candidate_id=cid)
        yield workflow('record_result', candidate_id=cid, skill_name='sql-injection',
                       outcome='insufficient-evidence', retry_decision=DECLINE)

    model = InspectModel(script())
    assert (await execute(rt, model, steps=8)).stop_reason == 'workflow_blocked'
    assert len([r for r in model.requests if r.tools]) == 2
    assert rt.agent._whole_target_state()[0] == 'blocked'
    assert rt.workflow_tool.validation_handoff(cid, rt.policy)['next_action'] == 'retry_declined'
    assert build_whole_target_plan(rt.skills.list_enabled(), rt.agent._planner_context()) is None
    assert not sent


async def test_decline_persists_compaction_resume_and_allows_revised_strategy(offline):
    rt, sent = offline
    cid = await inconclusive(rt, DECLINE)
    budget = current_budget(rt.workflow, cid, create=True)
    assert budget is not None
    budget.update(rejections=1, closed=True)
    await compact_with_misleading_summary(rt)
    await rt.agent.save()
    restored = rt.store.load().workflow
    assert restored.retry_decision(cid) == DECLINE
    rt.workflow.replace_from(restored)
    assert rt.agent._whole_target_state()[0] == 'blocked'
    assert rt.workflow_tool.validation_handoff(cid, rt.policy)['next_action'] == 'retry_declined'
    await call(rt, 'record_retry_decision', candidate_id=cid, retry_decision=RETRY)
    assert rt.agent._whole_target_state()[0] == 'actionable'
    plan = build_whole_target_plan(rt.skills.list_enabled(), rt.agent._planner_context())
    assert plan and plan.candidate_id == cid and 'Retry is optional' in plan.guidance
    old_attempt = rt.workflow.latest_result(cid).attempt_id
    started = await call(rt, 'start_validation', candidate_id=cid)
    assert started['validation_context']['attempt_id'] != old_attempt
    assert rt.workflow.retry_decision(cid) is None  # The new active attempt supersedes the closed-attempt decision.
    continued = current_budget(rt.workflow, cid)
    assert continued is not None and continued['rejections'] == 1
    await call(rt, 'record_result', candidate_id=cid, skill_name='sql-injection', outcome='insufficient-evidence')
    assert rt.workflow.retry_decision(cid) is None  # A different attempt/result is a new decision.
    assert rt.agent._whole_target_state()[0] == 'decision_pending' and not sent
    rt.workflow.clear()
    assert not rt.workflow.retry_decisions


async def test_legacy_sessions_and_changed_identity_do_not_invent_decline(offline):
    rt, _ = offline
    cid = await inconclusive(rt, DECLINE)
    raw = rt.workflow.to_dict()
    raw.pop('retry_decisions')
    assert WorkflowState.from_dict(raw).retry_decision(cid) is None
    candidate = rt.workflow.candidates[cid]
    candidate.request_template = 'Changed request context'
    assert rt.workflow.retry_decision(cid) is None
    # Malformed optional metadata cannot stop historical session loading.
    raw['retry_decisions'] = {cid: {'decision': 'decline', 'reason': None}}
    assert WorkflowState.from_dict(raw).retry_decisions == {}
    raw['retry_decisions'] = {cid: {'decision': [], 'reason': 'Malformed optional metadata'}}
    assert WorkflowState.from_dict(raw).retry_decisions == {}


async def test_decision_reason_is_bounded_redacted_session_state(offline):
    rt, _ = offline
    cid = await inconclusive(rt)
    receipt = await call(rt, 'record_retry_decision', candidate_id=cid,
        retry_decision={'decision': 'decline', 'reason': 'No useful oracle; password=secret-for-fixture'})
    assert 'secret-for-fixture' not in json.dumps(receipt)
    assert 'secret-for-fixture' not in json.dumps(rt.workflow.retry_decisions)
    decision = rt.workflow.retry_decision(cid)
    assert decision is not None and len(decision['reason']) <= 1000


@pytest.mark.parametrize('limit', ['rejections', 'repair_turns', 'prerequisite', 'dependency'])
async def test_retry_disposition_cannot_bypass_existing_gates(offline, limit):
    rt, sent = offline
    cid = await inconclusive(rt)
    await call(rt, 'record_retry_decision', candidate_id=cid, retry_decision=RETRY)
    if limit in {'rejections', 'repair_turns'}:
        budget = current_budget(rt.workflow, cid, create=True)
        assert budget is not None
        budget.update(closed=True, **{limit: 3 if limit == 'rejections' else MAX_TERMINAL_REPAIR_TURNS})
    elif limit == 'prerequisite':
        next(item for item in rt.workflow.objective_inputs() if cid in item.candidate_ids).candidate_ids.clear()
    else:
        rt.workflow.candidates[cid].deferred_reason = 'Authentication is still unavailable.'
    before = deepcopy(rt.workflow.to_dict())
    assert rt.agent._whole_target_state()[0] == 'blocked'
    result = await rt.registry.execute('workflow', {'action': 'start_validation', 'candidate_id': cid}, None, rt.prompter)
    assert result.startswith('error:')
    assert rt.workflow.to_dict() == before and not sent


async def test_undecided_model_is_bounded_by_existing_step_limit(offline):
    rt, sent = offline
    cid = await inconclusive(rt)

    def script():
        for _ in range(3):
            yield workflow('list', candidate_id=cid)

    model = InspectModel(script())
    assert (await execute(rt, model, steps=3)).stop_reason == 'max_steps'
    assert rt.workflow.retry_decision(cid) is None and not sent


async def test_repeated_closure_keeps_decline_without_reopening_decision(offline):
    rt, sent = offline
    cid = await inconclusive(rt, DECLINE)
    first = rt.workflow.latest_result(cid).result_id
    repeated = await call(rt, 'record_result', candidate_id=cid, skill_name='sql-injection',
                          outcome='insufficient-evidence')
    assert not repeated['created'] and repeated['result']['result_id'] == first
    assert repeated['retry_decision'] == DECLINE
    assert rt.agent._whole_target_state()[0] == 'blocked' and not sent


@pytest.mark.parametrize('decision', [{'decision': 'decline', 'reason': ''}, {'decision': 'maybe', 'reason': 'Unknown'}])
async def test_invalid_disposition_does_not_close_or_mutate_attempt(offline, decision):
    rt, _ = offline
    cid = await candidate_for(rt)
    await call(rt, 'start_validation', candidate_id=cid)
    before = deepcopy(rt.workflow.to_dict())
    result = await rt.registry.execute('workflow', {'action': 'record_result', 'candidate_id': cid,
        'skill_name': 'sql-injection', 'outcome': 'insufficient-evidence', 'retry_decision': decision}, None, rt.prompter)
    assert result.startswith('error:') and rt.workflow.to_dict() == before


@pytest.mark.parametrize('boundary', ['budget', 'denial', 'scope', 'cancellation'])
async def test_reconsideration_grants_no_execution_rights(offline, boundary):
    import asyncio
    from src.permission.permission import Decision, UserControlledRefusal
    from src.permission.runtime.execution import ExecutionBlocked
    from src.engagement.state import OutOfScopeError
    from tests.helpers.agent_fakes import FakeSignal

    rt, sent = offline
    cid = await inconclusive(rt, DECLINE)
    await call(rt, 'record_retry_decision', candidate_id=cid, retry_decision=RETRY)
    await call(rt, 'start_validation', candidate_id=cid)
    signal = FakeSignal()
    args = {'url': '/fixture?q=bounded-fixture', 'phase': 'validation'}
    if boundary == 'budget':
        rt.policy.max_calls = rt.policy.used
    elif boundary == 'denial':
        rt.prompter.set_yolo(False)
        rt.operator.decision = Decision.DENY
    elif boundary == 'scope':
        args['url'] = 'https://outside.test/fixture?q=bounded-fixture'
    else:
        signal.aborted = True
    before = deepcopy(rt.workflow.to_dict())
    with pytest.raises((ExecutionBlocked, UserControlledRefusal, OutOfScopeError, asyncio.CancelledError)):
        await rt.registry.execute('http', args, signal, rt.prompter)
    after = rt.workflow.to_dict()
    assert after['validation_results'] == before['validation_results']
    assert after['retry_decisions'] == before['retry_decisions']
    assert after['evidence_recovery'] == before['evidence_recovery']
    # Permission review can journal an admission; it must never dispatch HTTP.
    assert all(not row['effects']['dispatches'] for row in rt.workflow.attempts.values())
    assert not sent


@pytest.mark.parametrize('disposition', ['partial', 'blocked'])
async def test_selected_source_prerequisite_does_not_become_retry_decision_loop(offline, disposition):
    from src.workflow.discovery.inventory import SourceRecord
    from tests.helpers.burp_selection import ORIGIN

    rt, sent = offline
    await inconclusive(rt)
    rt.workflow.admit_discovery(SourceRecord(rt.workflow.objective.id, ORIGIN,
        'http', 'obs-prerequisite', 'a' * 64, selected=True, disposition=disposition,
        stop_reason='Selected source review is blocked.'))
    assert rt.agent._whole_target_state()[0] == 'blocked'
    plan = build_whole_target_plan(rt.skills.list_enabled(), rt.agent._planner_context())
    assert plan and plan.candidate_id is None and 'source' in plan.guidance.lower() and not sent
