"""Mounted offline reproductions of stale progress and constrained layouts."""
from dataclasses import replace

import pytest

from src.agent.agent import _to_agent_event
from src.agent.events import AssistantDeltaEvent, ToolCallEvent, ToolResultEvent
from src.agent.decision_planner import build_decision_plan
from src.permission.permission import AlwaysAllow
from src.ui.core.app import KAgent
from src.ui.core.state import AgentEventAction, Append, SetPerm, TranscriptEntry
from src.ui.widgets.permission_modal import PermissionModal
from tests.ui.test_overview import _make_app
from tests.ui.test_permission_modal import make_req
from tests.ui.test_progress_milestones import runtime, dispatch
from tests.agent.test_agent import whole_target_agent
from tests.ui.test_app import make_app
from src.workflow.state import Candidate, WorkflowObjective


@pytest.mark.parametrize('action', ['record_input', 'set_input_disposition', 'record_candidate', 'link_input_candidate'])
async def test_workflow_mutations_project_progress_at_result(tmp_path, action):
    app, workflow, tool = runtime(tmp_path, whole=True)
    args = {'action': 'record_input', 'endpoint': '/search', 'method': 'GET', 'parameter': 'q', 'location': 'query'}
    if action == 'record_input':
        expected = 'Attack surface recorded'
    else:
        await tool.run(args, None, AlwaysAllow())
        item = next(iter(workflow.attack_surface_inputs.values()))
        if action == 'set_input_disposition':
            args = {'action': action, 'input_id': item.id, 'disposition': 'analyzed', 'analysis_complete': True}
            expected = '1 analyzed'
        elif action == 'record_candidate':
            args = {'action': action, 'candidate_class': 'xss', 'endpoint': '/search', 'method': 'GET', 'parameter': 'q'}
            expected = 'Candidate recorded'
        else:
            await tool.run({'action': 'record_candidate', 'candidate_class': 'xss', 'endpoint': '/search',
                            'method': 'GET', 'parameter': 'q'}, None, AlwaysAllow())
            args = {'action': action, 'input_id': item.id, 'candidate_id': next(iter(workflow.candidates))}
            expected = 'Selected:'
    dispatch(app, ToolCallEvent(id='mutation', name='workflow', args=args))
    result = await tool.run(args, None, AlwaysAllow())
    dispatch(app, ToolResultEvent(id='mutation', name='workflow', result=result))
    assert any(expected in entry.text for entry in app.state.transcript), result


@pytest.mark.parametrize('size', [(40, 18), (32, 14)])
@pytest.mark.parametrize('streaming', [False, True])
async def test_small_terminal_keeps_transcript_and_controls_usable(monkeypatch, size, streaming):
    monkeypatch.setattr(KAgent, 'on_mount', lambda self: None)
    app = _make_app()
    async with app.run_test(size=size) as pilot:
        app.dispatch(Append(TranscriptEntry('assistant', 'Previous evidence remains visible.')))
        if streaming:
            app.dispatch(AgentEventAction(AssistantDeltaEvent(text='Progress evidence ' * 100)))
        await pilot.pause()
        assert app.transcript_log.size.height >= 2
        assert app.input_static.region.bottom <= size[1]
        assert app.status_bar.region.bottom <= size[1]
        if streaming:
            assert app.live_entry_static.size.height >= 1


@pytest.mark.parametrize('follow_tail', [False, True])
async def test_existing_transcript_reflows_and_preserves_scroll_intent(monkeypatch, follow_tail):
    monkeypatch.setattr(KAgent, 'on_mount', lambda self: None)
    app = _make_app()
    async with app.run_test(size=(100, 30)) as pilot:
        for index in range(25):
            app.dispatch(Append(TranscriptEntry('assistant', f'Paragraph {index}: ' + 'observed evidence ' * 8)))
        await pilot.pause()
        if not follow_tail:
            app.transcript_log.scroll_to(y=18, animate=False, immediate=True, force=True)
            await pilot.pause()
        old_count = len(app.transcript_log.lines)
        old_top = app.transcript_log.render_line(0).text.strip()
        await pilot.resize_terminal(50, 30)
        await pilot.pause()
        assert len(app.transcript_log.lines) > old_count
        assert app.transcript_log.is_vertical_scroll_end == follow_tail
        if not follow_tail:
            # The entry being read remains in the viewport after rewrapping.
            label = old_top.split(':')[0]
            assert label.startswith('Paragraph')
            assert label in '\n'.join(app.transcript_log.render_line(y).text
                                      for y in range(app.transcript_log.size.height))


async def test_existing_table_reflows_without_losing_content(monkeypatch):
    monkeypatch.setattr(KAgent, 'on_mount', lambda self: None)
    app = _make_app()
    async with app.run_test(size=(100, 30)) as pilot:
        app.dispatch(Append(TranscriptEntry('assistant', '| Name | Value |\n| --- | --- |\n| alpha | beta |')))
        await pilot.pause()
        await pilot.resize_terminal(32, 18)
        await pilot.pause()
        lines = [line.text for line in app.transcript_log.lines if line.text]
        assert all(len(line) <= app.transcript_log.transcript_content_width for line in lines)
        assert all(line.startswith('  ') for line in lines)
        assert 'alpha' in '\n'.join(lines) and 'beta' in '\n'.join(lines)


@pytest.mark.parametrize('offset', [40, 41, 43])
async def test_resize_keeps_reading_position_inside_a_long_paragraph(monkeypatch, offset):
    monkeypatch.setattr(KAgent, 'on_mount', lambda self: None)
    app = _make_app()
    async with app.run_test(size=(90, 30)) as pilot:
        app.dispatch(Append(TranscriptEntry('assistant', ' '.join(f'word{i:04d}' for i in range(1000)))))
        await pilot.pause()
        app.transcript_log.scroll_to(y=offset, animate=False, immediate=True, force=True)
        await pilot.pause()
        first_word = app.transcript_log.render_line(0).text.strip().split()[0]
        await pilot.resize_terminal(55, 30)
        await pilot.pause()
        assert not app.transcript_log.is_vertical_scroll_end
        visible = '\n'.join(app.transcript_log.render_line(y).text for y in range(app.transcript_log.size.height))
        assert first_word in visible
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        assert not app.transcript_log.is_vertical_scroll_end
        visible = '\n'.join(app.transcript_log.render_line(y).text for y in range(app.transcript_log.size.height))
        assert first_word in visible


@pytest.mark.parametrize('size', [(40, 18), (32, 14)])
@pytest.mark.parametrize('reusable', [False, True])
async def test_permission_hints_remain_outside_long_scrollable_detail(monkeypatch, size, reusable):
    monkeypatch.setattr(KAgent, 'on_mount', lambda self: None)
    app = _make_app()
    async with app.run_test(size=size) as pilot:
        app.dispatch(SetPerm(make_req(detail='\n'.join(f'command {i}' for i in range(100)),
            cache_key='fixture' if reusable else None, session_scope_display='fixture' if reusable else None)))
        await pilot.pause()
        visible = '\n'.join(strip.text for strip in app.screen._compositor.render_strips())
        visible = ' '.join(visible.replace('│', ' ').split())
        assert 'Esc cancel' in visible and 'y allow once' in visible
        assert app.overlay_content_static.max_scroll_y > 0
        assert app.transcript_log.size.height >= 2


async def test_permission_scroll_resets_only_for_new_request(monkeypatch):
    monkeypatch.setattr(KAgent, 'on_mount', lambda self: None)
    app = _make_app()
    async with app.run_test(size=(80, 30)) as pilot:
        req = make_req(detail='\n'.join(f'first {i}' for i in range(100)))
        app.dispatch(SetPerm(req))
        await pilot.pause()
        app.overlay_content_static.scroll_to(y=10, animate=False, immediate=True, force=True)
        await pilot.pause()
        app.dispatch(SetPerm(req))
        await pilot.pause()
        assert app.overlay_content_static.scroll_y == 10
        new = replace(req, detail='\n'.join(f'second {i}' for i in range(100)))
        app.dispatch(SetPerm(new))
        await pilot.pause()
        assert app.overlay_content_static.scroll_y == 0
        modal = app._get_active_modal()
        assert isinstance(modal, PermissionModal) and modal.req is new


@pytest.mark.parametrize('whole', [False, True])
def test_real_planner_recommendations_deduplicate_without_losing_candidate_changes(whole):
    agent, _ = whole_target_agent([], [])
    agent.workflow.objective = WorkflowObjective('planner-fixture', 'whole_target' if whole else 'direct',
                                                'https://target.test')
    app = make_app()
    app.agent = agent
    first, _ = agent.workflow.add_candidate(Candidate('sql-injection', target='https://target.test',
        endpoint='/one', method='GET', parameter='q', objective_id='planner-fixture'))
    request = 'Test SQL injection in the recorded candidates'
    def recommend():
        context = agent._planner_context()
        if whole:
            # Planner-only fixture: discovery is closed and validation remains.
            # Runtime admission/phase evidence is covered by integration tests.
            context = replace(context, completed_phases=frozenset({'recon', 'enumeration', 'input_analysis'}),
                              workflow_status='in_progress')
        plan = build_decision_plan(request, agent.skills.list_enabled(), agent.target, context)
        assert plan is not None and plan.candidate_id
        dispatch(app, _to_agent_event(agent._planner_event(plan)))
        return plan
    assert recommend().candidate_id == first.id
    assert recommend().candidate_id == first.id
    assert sum(e.text.startswith('Planner recommended') for e in app.state.transcript) == 1
    first.status = 'deferred'
    second, _ = agent.workflow.add_candidate(Candidate('sql-injection', target='https://target.test',
        endpoint='/two', method='GET', parameter='q', objective_id='planner-fixture'))
    assert recommend().candidate_id == second.id
    assert sum(e.text.startswith('Planner recommended') for e in app.state.transcript) == 2
