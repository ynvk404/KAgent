"""Real offline Agent stop branches export counters without extra requests."""
from dataclasses import asdict
import json

import pytest

from src.agent.agent import AgentRunOptions, WholeTargetStallTracker
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


@pytest.mark.parametrize('limit,reason,count', [(8, 'workflow_stalled', 4), (2, 'max_steps', 2)])
async def test_stall_and_budget_export_outer_iterations_independently_of_llm(tmp_path, limit, reason, count):
    agent = whole_agent(tmp_path, [call('list') for _ in range(count)] + [summary()])
    events = []
    await agent.run('Continue whole-target assessment.', FakeSignal(), events.append, AgentRunOptions(max_steps=limit))
    done = events[-1]
    assert done.stop_reason == reason
    assert done.workflow_metrics['outer_iterations'] == count
    assert done.workflow_metrics['no_progress'] == count
    assert done.agent_loop_llm_calls == count and done.final_synthesis_llm_calls == 1
    rows = [e for e in events if isinstance(e, WorkflowProgressEvent) and e.stage == 'iteration_evaluated']
    assert [e.metrics['no_progress'] for e in rows] == list(range(1, count + 1))
    assert rows[-1].metrics['stall_threshold_reached'] == (reason == 'workflow_stalled')
    assert done.workflow_metrics['required_phase'] == 'recon'
    assert done.workflow_metrics['planner_recommended_phase'] == 'recon'
    assert isinstance(agent.client, FakeClient)
    assert len(agent.client.requests) == count + 1


async def test_structured_progress_resets_and_frontier_is_precise_without_text(tmp_path):
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
    assert rows[0]['progress_kind'] == 'structured_progress' and rows[0]['no_progress'] == 0
    assert rows[0]['credited_new_facts'] > 0
    assert rows[1]['progress_kind'] == 'no_progress' and rows[1]['no_progress'] == 1
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
    assert done.workflow_metrics['outer_iterations'] == 1 and done.workflow_metrics['no_progress'] == 1
    assert isinstance(agent.client, FakeClient)
    assert len(agent.client.requests) == 1


def test_tracker_novelty_and_phase_change_semantics_are_unchanged():
    tracker = WholeTargetStallTracker(exploration_cap=1)
    assert tracker.record_iteration(new_facts=frozenset(), activity_fingerprints=['one']) == 'novel_exploration'
    assert tracker.consecutive_no_progress == 0
    assert tracker.record_iteration(new_facts=frozenset(), activity_fingerprints=['two']) == 'no_progress'
    tracker.set_phase('enumeration')
    assert tracker.consecutive_no_progress == 1  # Phase text alone does not reset.
    assert tracker.record_iteration(new_facts=frozenset({'fact'}), activity_fingerprints=[]) == 'structured_progress'
    assert tracker.consecutive_no_progress == 0
    assert tracker.record_iteration(new_facts=frozenset({'fact'}), activity_fingerprints=[]) == 'no_progress'
    assert tracker.last_credit['credited_new_facts'] == 0


async def test_metrics_cannot_query_reconcilers_or_change_workflow(tmp_path, monkeypatch):
    agent = whole_agent(tmp_path, [])
    before = agent.workflow.to_dict()
    def forbidden(*args, **kwargs):
        raise AssertionError('telemetry queried a workflow reconciler')
    monkeypatch.setattr(agent, '_planner_context', forbidden)
    monkeypatch.setattr(agent, '_whole_target_state', forbidden)
    events = []
    agent._workflow_progress(events.append, 'iteration_evaluated', no_progress=2)
    assert events and agent.workflow.to_dict() == before
    agent._workflow_progress(forbidden, 'iteration_evaluated', no_progress=3)
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


def test_reader_progress_exports_zero_credit_instead_of_previous_iteration():
    from src.agent.agent import ExecutedToolCall, ToolCallResult
    tracker = WholeTargetStallTracker()
    tracker.record_iteration(new_facts=frozenset({'first'}), activity_fingerprints=[])
    result = ToolCallResult(json.dumps({'sha256': 'fixture-content', 'actual_start': 0,
        'actual_end': 10, 'total_length': 20}), '', 0)
    call = ExecutedToolCall('read_tool_result', {}, True, result)
    kind = tracker.record_validation_batch([call], new_facts=frozenset(), target_base_url=None)
    assert kind == 'reader_progress' and tracker.last_credit['credited_new_facts'] == 0
    assert tracker.consecutive_no_progress == 0


def test_active_receipt_phase_does_not_overwrite_event_stage(tmp_path):
    agent = whole_agent(tmp_path, [])
    agent.active_skills.add('recon')
    agent._new_skill_activation('recon', 'model')
    events = []
    agent._workflow_progress(events.append, 'iteration_evaluated')
    assert events[0]['stage'] == 'iteration_evaluated'
    assert events[0]['metrics']['active_skill_phases'] == ['recon']
