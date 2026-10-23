"""Offline regressions for the independent review's two guidance findings."""
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from src.agent.decision_planner import PlannerCandidate, build_whole_target_plan
from src.workflow.discovery.inventory import SourceRecord
from src.workflow.evidence.recovery import current_budget, MAX_TERMINAL_REPAIR_TURNS
from src.workflow.state import WorkflowState
from src.workflow.validation.route import ValidationRoute
from tests.agent.test_validation_continuation import (
    PREFIX, candidate_for, compact_with_misleading_summary, execute, hint,
    InspectModel, offline, workflow,
)
from tests.helpers.burp_selection import ORIGIN


def continuation(rt):
    view = rt.agent._workflow_request_view('Continue.', rt.registry.as_llm_tools())
    rows = [m.content for m in view.blocks if m.content.startswith(PREFIX)]
    assert len(rows) == 1
    return rows[0]


def budget_for(rt, cid):
    budget = current_budget(rt.workflow, cid)
    assert budget is not None
    return budget


async def deferred_pair(rt, *, first_outcome='insufficient-evidence', exhausted=True):
    # Arrange the exhausted/dependent candidate first in canonical ID order too.
    ids = sorted([await candidate_for(rt), await candidate_for(rt, 'xss')])
    for index, cid in enumerate(ids):
        started = await rt.registry.execute('workflow', {
            'action': 'start_validation', 'candidate_id': cid}, None, rt.prompter)
        assert json.loads(started)['ok']
        route = rt.agent._validation_routes()[cid]
        result = await rt.registry.execute('workflow', {
            'action': 'record_result', 'candidate_id': cid, 'skill_name': route.skill_name,
            'outcome': first_outcome if index == 0 else 'insufficient-evidence',
            'deferred_reason': 'Synthetic unresolved dependency or unavailable proof.',
        }, None, rt.prompter)
        assert json.loads(result)['ok']
        budget = current_budget(rt.workflow, cid, create=True)
        assert budget is not None
        budget.update(rejections=3 if index == 0 and exhausted else 1, closed=True)
        assert rt.workflow.candidates[cid].status == 'deferred'
    return ids


@pytest.mark.parametrize('reverse', [False, True])
async def test_recoverable_fallback_precedes_exhausted_in_either_store_order(offline, reverse):
    rt, sent = offline
    exhausted, recoverable = await deferred_pair(rt)
    if reverse:
        rt.workflow.candidates = dict(reversed(list(rt.workflow.candidates.items())))
    before = deepcopy(rt.workflow.to_dict())
    text = continuation(rt)
    assert f'Candidate {recoverable};' in text and 'Recovery=available rejections=1/3' in text
    assert 'No owned active attempt:' in text and f'Candidate {exhausted};' not in text
    assert text.index('load_skill') < text.index('Then call workflow(action="start_validation"')
    assert rt.workflow.to_dict() == before and not sent
    # Guidance selection does not change start_validation's admission semantics.
    rejected = await rt.registry.execute('workflow', {
        'action': 'start_validation', 'candidate_id': exhausted}, None, rt.prompter)
    assert json.loads(rejected.split('\n', 1)[1])['error']['code'] == 'EXHAUSTED_ATTEMPT'
    started = await rt.registry.execute('workflow', {
        'action': 'start_validation', 'candidate_id': recoverable}, None, rt.prompter)
    assert json.loads(started)['ok']
    assert budget_for(rt, recoverable)['rejections'] == 1


@pytest.mark.parametrize('outcome', ['blocked', 'browser-required', 'authorization-required'])
async def test_fallback_uses_dependency_policy_even_with_budget_remaining(offline, outcome):
    rt, sent = offline
    dependent, recoverable = await deferred_pair(rt, first_outcome=outcome, exhausted=False)
    before = deepcopy(rt.workflow.to_dict())
    assert rt.workflow_tool.validation_handoff(dependent, rt.policy)['next_action'] == 'resolve_dependency'
    assert f'Candidate {recoverable};' in continuation(rt)
    assert rt.workflow.to_dict() == before and not sent


async def test_fallback_requires_canonical_prerequisites_as_well_as_recovery_budget(offline):
    rt, sent = offline
    dependent, recoverable = await deferred_pair(rt, exhausted=False)
    item = next(item for item in rt.workflow.objective_inputs() if dependent in item.candidate_ids)
    item.candidate_ids.remove(dependent)
    before = deepcopy(rt.workflow.to_dict())
    assert rt.workflow_tool.validation_handoff(dependent, rt.policy)['next_action'] == 'repair_prerequisites'
    assert f'Candidate {recoverable};' in continuation(rt)
    assert rt.workflow.to_dict() == before and not sent


@pytest.mark.parametrize('exhaustion', ['rejections', 'repair_turns'])
async def test_all_exhausted_fallback_does_not_offer_a_fresh_attempt(offline, exhaustion):
    rt, sent = offline
    ids = await deferred_pair(rt)
    for cid in ids:
        budget = budget_for(rt, cid)
        budget.update(rejections=3 if exhaustion == 'rejections' else 1,
                      repair_turns=MAX_TERMINAL_REPAIR_TURNS if exhaustion == 'repair_turns' else 0)
    before = deepcopy(rt.workflow.to_dict())
    text = continuation(rt)
    assert 'Recovery exhausted' in text and 'No owned active attempt: call' not in text
    assert rt.workflow.to_dict() == before and not sent


@pytest.mark.parametrize('repair', [False, True])
async def test_owned_active_or_ongoing_repair_precedes_recoverable_fallback(offline, repair):
    rt, sent = offline
    first, second = await deferred_pair(rt, exhausted=False)
    if repair:
        budget_for(rt, first)['closed'] = False
    else:
        assert json.loads(await rt.registry.execute('workflow', {
            'action': 'start_validation', 'candidate_id': first}, None, rt.prompter))['ok']
    before = deepcopy(rt.workflow.to_dict())
    assert f'Candidate {first};' in continuation(rt)
    assert f'Candidate {second};' not in continuation(rt)
    assert rt.workflow.to_dict() == before and not sent


async def test_continue_compaction_and_serialization_refresh_selection_without_budget_reset(offline):
    rt, sent = offline
    first, second = await deferred_pair(rt)
    assert f'Candidate {second};' in continuation(rt)
    budget_snapshot = deepcopy(rt.workflow.evidence_recovery)
    await compact_with_misleading_summary(rt)
    restored = WorkflowState.from_dict(json.loads(json.dumps(rt.workflow.to_dict())))
    assert restored.evidence_recovery == budget_snapshot

    def check(request):
        text = hint(request)
        assert f'Candidate {second};' in text and 'rejections=1/3' in text

    def script():
        yield workflow('list', candidate_id=second)

    model = InspectModel(script(), check)
    await execute(rt, model, steps=1)
    assert model.consumed and rt.workflow.evidence_recovery == budget_snapshot
    # The next view must use current state, even after a different candidate was selected.
    budget_for(rt, second)['rejections'] = 3
    budget_for(rt, first)['rejections'] = 1
    assert f'Candidate {first};' in continuation(rt)
    assert not sent and len(rt.workflow.attempts) == 2


async def limited_source(rt, disposition):
    cid = await candidate_for(rt)
    source = rt.workflow.admit_discovery(SourceRecord(rt.workflow.objective.id, ORIGIN,
        'http', 'obs-selected-review', 'a' * 64, selected=True, disposition=disposition,
        stop_reason='Synthetic browser/authorization dependency remains unresolved.'))
    return cid, source


@pytest.mark.parametrize('disposition', ['partial', 'blocked'])
async def test_selected_limited_source_without_pending_frontier_precedes_every_candidate_branch(offline, disposition):
    rt, sent = offline
    cid, source = await limited_source(rt, disposition)
    before = deepcopy(rt.workflow.to_dict())
    for _ in range(2):
        context = rt.agent._planner_context()
        assert context.pending_source_count == 0 and context.discovery_obligation_pending
        assert context.candidates[0].id == cid and context.candidates[0].validation_ready
        plan = build_whole_target_plan(rt.skills.list_enabled(), context)
        assert plan is not None and plan.candidate_id is None
        assert source.id in plan.guidance and disposition in plan.guidance
        assert 'get_source' in plan.guidance and 'start_validation' not in plan.guidance
        assert 'Do not retry' in plan.guidance
    assert rt.workflow.to_dict() == before and not sent


@pytest.mark.parametrize('resolution', ['processed', 'bounded-partial', 'unselected'])
async def test_resolved_selected_obligations_allow_ready_validation(offline, resolution):
    rt, sent = offline
    cid, source = await limited_source(rt, 'partial')
    changes = ({'selected': False, 'disposition': 'pending', 'stop_reason': None} if resolution == 'unselected' else
               {'disposition': 'processed', 'stop_reason': None} if resolution == 'processed' else
               {'bounded_stop': True, 'limitations': ('Retained prefix only.',),
                'processing_bounds': (('max_bytes', 128),)})
    rt.workflow.discovery_sources[source.id] = replace(source, **changes)
    before = deepcopy(rt.workflow.to_dict())
    context = rt.agent._planner_context()
    assert not context.discovery_obligation_pending
    plan = build_whole_target_plan(rt.skills.list_enabled(), context)
    assert plan is not None and plan.candidate_id == cid
    assert plan.guidance.index('load_skill') < plan.guidance.index('Then call workflow(action="start_validation"')
    assert 'prepare the primary request' in plan.guidance and 'related_requests' in plan.guidance
    assert rt.workflow.to_dict() == before and not sent


@pytest.mark.parametrize('priority', ['active', 'recovery', 'coverage', 'finding', 'revalidation', 'artifact'])
async def test_selected_source_keeps_existing_higher_priorities(offline, priority):
    rt, _ = offline
    cid, _ = await limited_source(rt, 'blocked')
    context = rt.agent._planner_context()
    if priority == 'active':
        context = replace(context, candidates=(replace(context.candidates[0], status='validating'),))
    elif priority == 'recovery':
        context = replace(context, repair_candidate_ids=(cid,))
    elif priority == 'artifact':
        context = replace(context, phase_completion_readiness={'phase': 'enumeration',
            'historically_completed': True, 'artifact_valid': False, 'reason': 'missing artifact'})
    else:
        field = {'coverage': 'coverage_sync_candidate_ids', 'finding': 'pending_finding_candidate_ids',
                 'revalidation': 'revalidation_candidate_ids'}[priority]
        context = replace(context, **{field: (cid,)})
    plan = build_whole_target_plan(rt.skills.list_enabled(), context)
    assert plan is not None
    assert plan.candidate_id == (None if priority == 'artifact' else cid)
    if priority == 'artifact':
        assert plan.recommended_skill == 'web-enumeration'
    else:
        assert 'get_source' not in plan.guidance


async def test_blocked_workflow_does_not_route_generic_validation_past_selected_source(offline):
    rt, _ = offline
    _, source = await limited_source(rt, 'blocked')
    context = replace(rt.agent._planner_context(), workflow_status='blocked',
        candidates=(PlannerCandidate('cand_generic', 'custom-class', 'queued', generic_startable=True),))
    context = replace(context, validation_routes={'cand_generic': ValidationRoute('generic')})
    plan = build_whole_target_plan(rt.skills.list_enabled(), context)
    assert plan is not None and plan.candidate_id is None and source.id in plan.guidance


async def test_selected_dependency_does_not_get_a_conflicting_fallback_handoff(offline):
    rt, sent = offline
    await deferred_pair(rt)
    rt.workflow.admit_discovery(SourceRecord(rt.workflow.objective.id, ORIGIN,
        'http', 'obs-blocked-review', 'b' * 64, selected=True, disposition='blocked',
        stop_reason='Synthetic authorization dependency.'))
    before = deepcopy(rt.workflow.to_dict())
    view = rt.agent._workflow_request_view('Continue.', rt.registry.as_llm_tools())
    assert view.decision is not None and view.decision.candidate_id is None
    assert not any(m.content.startswith(PREFIX) for m in view.blocks)
    assert 'Do not retry' in view.decision.guidance
    assert rt.workflow.to_dict() == before and not sent
