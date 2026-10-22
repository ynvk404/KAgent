"""Offline selection regressions for mixed expert and blocked generic work."""
from copy import deepcopy
from dataclasses import replace
from itertools import permutations
import json

import pytest

from src.agent.decision_planner import build_whole_target_plan
from src.workflow.discovery.inventory import SourceRecord
from src.workflow.evidence.recovery import MAX_TERMINAL_REPAIR_TURNS
from src.workflow.state import ValidationResult
from src.workflow.validation.route import GENERIC_VALIDATOR
from tests.agent.test_review_p2_guidance import budget_for, deferred_pair
from tests.agent.test_validation_continuation import PREFIX, candidate_for, offline
from tests.helpers.burp_selection import ORIGIN


async def generic_blocked(rt):
    cid = await candidate_for(rt, 'review-custom-class')
    # Explicit restored/synthetic unresolved record; no generic proposal or
    # execution authority is fabricated to arrange the selection regression.
    rt.workflow.add_validation_result(ValidationResult(
        cid, GENERIC_VALIDATOR, 'blocked', objective_id=rt.workflow.objective.id,
        deferred_reason='Synthetic browser dependency remains unresolved.'))
    assert rt.agent._validation_routes()[cid].kind == 'generic'
    assert not rt.agent._generic_startable(rt.workflow.candidates[cid])
    assert rt.workflow_tool.validation_handoff(cid, rt.policy)['next_action'] == 'resolve_dependency'
    return cid


def view_for(rt):
    return rt.agent._workflow_request_view('Continue.', rt.registry.as_llm_tools())


@pytest.mark.parametrize('order', list(permutations('ABC')))
async def test_recoverable_expert_precedes_generic_blocker_in_every_insertion_order(offline, order):
    rt, sent = offline
    exhausted, recoverable = await deferred_pair(rt)
    blocked = await generic_blocked(rt)
    ids = dict(zip('ABC', (exhausted, recoverable, blocked)))
    rt.workflow.candidates = {ids[key]: rt.workflow.candidates[ids[key]] for key in order}
    context = rt.agent._planner_context()
    assert context.workflow_status == 'blocked'
    assert rt.workflow_tool.validation_handoff(exhausted, rt.policy)['next_action'] == 'stop_recovery'
    assert rt.workflow_tool.validation_handoff(recoverable, rt.policy)['next_action'] == 'start_validation'
    before = deepcopy(rt.workflow.to_dict())

    plan = build_whole_target_plan(rt.skills.list_enabled(), context)
    assert plan is not None and plan.candidate_id == recoverable
    view = view_for(rt)
    assert view.decision is not None and view.decision.candidate_id == recoverable
    hints = [m.content for m in view.blocks if m.content.startswith(PREFIX)]
    assert len(hints) == 1 and f'Candidate {recoverable};' in hints[0]
    assert hints[0].index('load_skill') < hints[0].index('Then call workflow(action="start_validation"')
    assert 'prepare the primary request' in hints[0] and 'before any validation probes' in hints[0]
    assert rt.workflow.to_dict() == before and not sent
    assert rt.workflow.candidates[blocked].status == 'deferred'
    assert not rt.workflow.eligible_for_finding(blocked)
    assert any(blocked in blocker for blocker in context.workflow_blockers)
    observations = '\n'.join(m.content for m in view.blocks if m.role == 'user')
    assert blocked in observations and 'blocked' in observations

    # A selected hint must agree with real admission and carry the old budget.
    started = await rt.registry.execute('workflow', {
        'action': 'start_validation', 'candidate_id': recoverable}, None, rt.prompter)
    assert json.loads(started)['ok']
    assert budget_for(rt, recoverable)['rejections'] == 1
    assert budget_for(rt, exhausted)['rejections'] == 3
    assert rt.workflow.latest_result(blocked).outcome == 'blocked' and not sent


@pytest.mark.parametrize('experts', [False, True])
@pytest.mark.parametrize('exhaustion', ['rejections', 'repair_turns'])
async def test_only_blocked_or_exhausted_work_keeps_generic_dependency(offline, experts, exhaustion):
    rt, sent = offline
    if experts:
        for cid in await deferred_pair(rt):
            budget_for(rt, cid).update(
                rejections=3 if exhaustion == 'rejections' else 1,
                repair_turns=MAX_TERMINAL_REPAIR_TURNS if exhaustion == 'repair_turns' else 0)
    blocked = await generic_blocked(rt)
    context = rt.agent._planner_context()
    before = deepcopy(rt.workflow.to_dict())
    view = view_for(rt)
    assert view.decision is not None and view.decision.candidate_id == blocked
    assert 'unresolved' in view.decision.guidance and 'Do not restart/probe' in view.decision.guidance
    text = next(m.content for m in view.blocks if m.content.startswith(PREFIX))
    assert f'Candidate {blocked};' in text and 'Do not retry blocked probes' in text
    assert 'No owned active attempt: call' not in text
    assert any(blocked in blocker for blocker in context.workflow_blockers)
    assert rt.workflow.to_dict() == before and not sent


@pytest.mark.parametrize('requested', [False, True])
@pytest.mark.parametrize('reverse', [False, True])
async def test_multiple_recoverable_experts_are_deterministic_and_keep_requested_goals(offline, requested, reverse):
    rt, sent = offline
    first, second = await deferred_pair(rt, exhausted=False)
    blocked = await generic_blocked(rt)
    if requested:
        # User order deliberately opposes canonical Candidate ID order, and
        # the generic requested class itself remains an unresolved obligation.
        for cid in (blocked, second, first):
            rt.workflow.objective.add_requested_goal(rt.workflow.candidates[cid].candidate_class)
    if reverse:
        rt.workflow.candidates = dict(reversed(list(rt.workflow.candidates.items())))
    context = rt.agent._planner_context()
    before = deepcopy(rt.workflow.to_dict())
    expected = second if requested else first
    plan = build_whole_target_plan(rt.skills.list_enabled(), context)
    assert plan is not None and plan.candidate_id == expected
    assert view_for(rt).decision.candidate_id == expected
    assert rt.workflow.to_dict() == before

    # When one independent budget is exhausted, the sibling still gets a turn.
    budget_for(rt, expected)['rejections'] = 3
    other = first if requested else second
    assert view_for(rt).decision.candidate_id == other
    budget_for(rt, other)['rejections'] = 3
    assert view_for(rt).decision.candidate_id == blocked
    for goal in rt.workflow.objective.requested_goals:
        assert goal.candidate_ids and goal.status == 'deferred'
    assert rt.workflow.latest_result(blocked).outcome == 'blocked' and not sent


@pytest.mark.parametrize('priority', ['active', 'recovery', 'coverage', 'finding', 'revalidation', 'cleanup', 'artifact'])
async def test_mixed_selection_preserves_higher_priority_work(offline, priority):
    rt, sent = offline
    first, _ = await deferred_pair(rt, exhausted=False)
    await generic_blocked(rt)
    if priority == 'active':
        assert json.loads(await rt.registry.execute('workflow', {
            'action': 'start_validation', 'candidate_id': first}, None, rt.prompter))['ok']
    elif priority == 'recovery':
        budget_for(rt, first)['closed'] = False
    context = rt.agent._planner_context()
    # Project pending accepted-result and artifact obligations independently;
    # their real persistence/admission contracts are covered by security tests.
    if priority == 'artifact':
        context = replace(context, phase_completion_readiness={'phase': 'enumeration',
            'historically_completed': True, 'artifact_valid': False, 'reason': 'missing artifact'})
    elif priority not in {'active', 'recovery'}:
        field = {'coverage': 'coverage_sync_candidate_ids', 'finding': 'pending_finding_candidate_ids',
                 'revalidation': 'revalidation_candidate_ids', 'cleanup': 'pending_cleanup_candidate_ids'}[priority]
        context = replace(context, **{field: (first,)})
    before = deepcopy(rt.workflow.to_dict())
    plan = build_whole_target_plan(rt.skills.list_enabled(), context)
    assert plan is not None and plan.candidate_id == (None if priority == 'artifact' else first)
    if priority == 'artifact':
        assert plan.recommended_skill == 'web-enumeration'
    elif priority in {'active', 'recovery'}:
        assert plan.reason == 'current attempt recovery precedes discovery'
    else:
        assert {'coverage': 'sync_coverage', 'finding': 'confirm_finding',
                'revalidation': 'Revalidate candidate', 'cleanup': 'Mutation cleanup'}[priority] in plan.guidance
    assert rt.workflow.to_dict() == before and not sent


@pytest.mark.parametrize('disposition', ['partial', 'blocked'])
async def test_mixed_selection_preserves_selected_discovery_obligations(offline, disposition):
    rt, sent = offline
    await deferred_pair(rt)
    await generic_blocked(rt)
    source = rt.workflow.admit_discovery(SourceRecord(rt.workflow.objective.id, ORIGIN,
        'http', 'obs-mixed-review', 'c' * 64, selected=True, disposition=disposition,
        stop_reason='Synthetic selected source dependency.'))
    rt.agent._planner_context()
    before = deepcopy(rt.workflow.to_dict())
    view = view_for(rt)
    assert view.decision is not None and view.decision.candidate_id is None
    assert source.id in view.decision.guidance and 'Do not retry' in view.decision.guidance
    assert not any(m.content.startswith(PREFIX) for m in view.blocks)
    assert rt.workflow.to_dict() == before and not sent


@pytest.mark.parametrize('limitation', ['blocked', 'browser-required', 'authorization-required', 'deferred', 'prerequisite'])
async def test_budget_alone_cannot_make_an_expert_startable(offline, limitation):
    rt, sent = offline
    dependent, exhausted = await deferred_pair(rt,
        first_outcome='insufficient-evidence' if limitation == 'prerequisite' else limitation, exhausted=False)
    budget_for(rt, exhausted)['rejections'] = 3
    blocked = await generic_blocked(rt)
    if limitation == 'prerequisite':
        item = next(item for item in rt.workflow.objective_inputs() if dependent in item.candidate_ids)
        item.candidate_ids.remove(dependent)
    context = rt.agent._planner_context()
    row = rt.workflow_tool.validation_handoff(dependent, rt.policy)
    assert row['next_action'] == ('repair_prerequisites' if limitation == 'prerequisite' else 'resolve_dependency')
    before = deepcopy(rt.workflow.to_dict())
    plan = build_whole_target_plan(rt.skills.list_enabled(), context)
    assert plan is not None and plan.candidate_id == blocked
    text = next(m.content for m in view_for(rt).blocks if m.content.startswith(PREFIX))
    assert 'No owned active attempt: call' not in text
    assert rt.workflow.to_dict() == before and not sent
