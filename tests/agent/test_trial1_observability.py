"""Real offline Agent stop branches export counters without extra requests."""
import json

import pytest

from src.agent.agent import AgentRunOptions
from src.agent.decision_planner import build_whole_target_plan
from src.agent.events import WorkflowProgressEvent
from src.workflow.state import WorkflowObjective, WorkflowState
from tests.agent.test_workflow_request_preparation import setup, call, ORIGIN
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from src.llm.core.types import ChatResponse, Message
from tests.state.test_discovery_inventory import source


def whole_agent(tmp_path, responses):
    state = WorkflowState(objective=WorkflowObjective('objective', 'whole_target', ORIGIN))
    return setup(tmp_path, FakeClient(responses), state)


def summary():
    return ChatResponse(Message('assistant', 'Bounded offline summary.'), 'stop')


@pytest.mark.parametrize('limit', [16, 2])
async def test_budget_exports_outer_iterations_independently_of_llm(tmp_path, limit):
    count = limit
    agent = whole_agent(tmp_path, [call('list') for _ in range(count)] + [summary()])
    events = []
    await agent.run('Continue whole-target assessment.', FakeSignal(), events.append, AgentRunOptions(max_steps=limit))
    done = events[-1]
    assert done.stop_reason == 'max_steps'
    assert done.workflow_metrics['outer_iterations'] == count
    assert done.agent_loop_llm_calls == count and done.final_synthesis_llm_calls == 1
    rows = [e for e in events if isinstance(e, WorkflowProgressEvent) and e.stage == 'iteration_evaluated']
    assert [e.metrics['outer_iterations'] for e in rows] == list(range(1, count + 1))
    assert all(e.metrics['workflow_status'] == 'actionable' for e in rows)
    assert not {'no_progress', 'progress_kind', 'stall_threshold', 'phase_exploration_cap',
                'credited_new_facts', 'novel_activities', 'validation_finalizations'} & done.workflow_metrics.keys()
    assert done.workflow_metrics['required_phase'] == 'recon'
    assert done.workflow_metrics['planner_recommended_phase'] == 'recon'
    assert isinstance(agent.client, FakeClient)
    assert len(agent.client.requests) == count + 1


async def test_workflow_status_and_frontier_are_precise_without_text(tmp_path):
    agent = whole_agent(tmp_path, [call('record_input', endpoint='/search', method='GET',
        parameter='q', location='query'), call('list'), summary()])
    src = source(target_origin=ORIGIN, document_url=ORIGIN + '/docs')
    agent.workflow.admit_discovery(src)
    before = agent.workflow.to_dict()
    context = agent._planner_context()
    plan = build_whole_target_plan(agent.skills.list_enabled(), context)
    assert plan and plan.recommended_skill == 'recon'
    assert 'select_source' not in plan.guidance and src.id not in plan.guidance
    assert context.pending_source_count == 1 and context.selected_pending_source_count == 0
    assert agent.workflow.to_dict() == before  # Advice never selects or processes.
    events = []
    await agent.run('Continue whole-target assessment.', FakeSignal(), events.append, AgentRunOptions(max_steps=2))
    rows = [e.metrics for e in events if isinstance(e, WorkflowProgressEvent) and e.stage == 'iteration_evaluated']
    assert [r['outer_iterations'] for r in rows] == [1, 2]
    assert all(r['workflow_status'] == 'actionable' and r['actionable_count'] > 0 for r in rows)
    assert len(agent.workflow.objective_inputs()) == 1
    assert rows[1]['frontier_pending'] == rows[1]['frontier_unselected_pending'] == 1
    assert rows[1]['frontier_selected'] == rows[1]['frontier_processed'] == 0
    assert src.id not in json.dumps(rows) and 'http' not in json.dumps(rows)


async def test_cancel_exports_last_counters_in_done(tmp_path):
    agent = whole_agent(tmp_path, [call('list')])
    signal = FakeSignal()
    events = []
    def sink(event):
        events.append(event)
        if isinstance(event, WorkflowProgressEvent) and event.stage == 'iteration_evaluated':
            signal.aborted = True
    await agent.run('Continue whole-target assessment.', signal, sink, AgentRunOptions(max_steps=8))
    done = events[-1]
    assert done.stop_reason == 'cancelled'
    assert done.workflow_metrics['stop_reason'] == 'cancelled'
    assert done.workflow_metrics['outer_iterations'] == 1
    assert isinstance(agent.client, FakeClient)
    assert len(agent.client.requests) == 1


async def test_metrics_cannot_query_reconcilers_or_change_workflow(tmp_path, monkeypatch):
    agent = whole_agent(tmp_path, [])
    before = agent.workflow.to_dict()
    def forbidden(*args, **kwargs):
        raise AssertionError('telemetry queried a workflow reconciler')
    monkeypatch.setattr(agent, '_planner_context', forbidden)
    monkeypatch.setattr(agent, '_whole_target_state', forbidden)
    events = []
    agent._workflow_progress(events.append, 'iteration_evaluated', outer_iterations=2)
    assert events and agent.workflow.to_dict() == before
    agent._workflow_progress(forbidden, 'iteration_evaluated', outer_iterations=3)
    assert agent.workflow.to_dict() == before


async def test_telemetry_does_not_add_requests_or_reset_absent_recommendations(tmp_path):
    agent = whole_agent(tmp_path, [call('list'), summary()])
    events = []
    await agent.run('Continue whole-target assessment.', FakeSignal(), events.append, AgentRunOptions(max_steps=1))
    assert isinstance(agent.client, FakeClient) and len(agent.client.requests) == 2
    assert any(e.stage == 'request_admitted' for e in events if isinstance(e, WorkflowProgressEvent))
    # A direct informational request has no recommendation; no stale Recon value is retained.
    assert agent.workflow.objective is not None
    agent.workflow.objective.mode = 'direct'
    agent.client = FakeClient([summary()])
    await agent.run('Explain this report.', FakeSignal(), events.append, AgentRunOptions(tools=False))
    assert events[-1].workflow_metrics['planner_recommended_phase'] is None


def test_active_receipt_phase_does_not_overwrite_event_stage(tmp_path):
    agent = whole_agent(tmp_path, [])
    agent.active_skills.add('recon')
    agent._new_skill_activation('recon', 'model')
    events = []
    agent._workflow_progress(events.append, 'iteration_evaluated')
    assert events[0]['stage'] == 'iteration_evaluated'
    assert events[0]['metrics']['active_skill_phases'] == ['recon']
