from unittest.mock import Mock

import pytest

from src.agent.events import DoneEvent, ToolCallEvent, ToolResultEvent
from src.permission.permission import Decision
from src.tools.execution.file import FileEditTool, FileWriteTool
from src.ui.bridges.perm_bridge import BridgedPermissionRequest
from src.ui.core.app import KAgent
from src.ui.core.state import SetBusy, SetPerm
from src.ui.core.state import AgentEventAction, initial_state, reducer
from src.ui.core.outcomes import OutcomeFacts
from src.ui.widgets.banner import BannerData
from src.ui.widgets.permission_modal import PermissionModal
from tests.ui.test_app import make_app
from tests.ui.test_permission_modal import make_req, rendered
from tests.ui.test_permission_review import _content_text
from tests.ui.test_progress_milestones import dispatch


@pytest.mark.parametrize('offer', [
    {'cache_key': 'artifact-root', 'session_scope_display': 'writes under artifact-root'},
    {'offer_http_lab': True, 'session_scope_display': 'bounded exact-origin HTTP grant'},
    {'offer_browser_grant': 'routine', 'session_scope_display': 'bounded Browser grant'},
])
def test_reusable_shortcut_tracks_current_request_without_changing_authority(offer):
    current = [True]
    req = make_req(**offer, is_current=lambda: current[0])
    modal = PermissionModal(req)
    assert 'a trust for session' in rendered(modal)
    modal.handle_key('a')
    req.resolve.assert_called_once_with(Decision.ALLOW_SESSION)
    req.resolve.reset_mock()
    current[0] = False
    text = rendered(modal)
    assert 'a trust for session' not in text and 'a unavailable' not in text
    modal.handle_key('a')
    req.resolve.assert_not_called()
    assert req.supports_session  # Presentation does not mutate backend metadata.


def test_broken_lifecycle_callback_cannot_offer_reusable_approval():
    req = make_req(cache_key='fixture', session_scope_display='fixture scope',
                   is_current=Mock(side_effect=RuntimeError('fixture lifecycle ended')))
    modal = PermissionModal(req)
    assert 'a trust for session' not in rendered(modal)
    modal.handle_key('a')
    req.resolve.assert_not_called()


@pytest.mark.parametrize('size', [(80, 40), (40, 18)])
@pytest.mark.parametrize('tool,args,tail', [
    (FileWriteTool(), {'path': 'report.txt', 'content': 'head\n' + 'x\n' * 300 + 'WRITE_TAIL'}, 'WRITE_TAIL'),
    (FileEditTool(), {'path': 'report.txt', 'old_string': 'old\n' + 'x\n' * 300 + 'OLD_TAIL',
                     'new_string': 'new\n' + 'y\n' * 300 + 'EDIT_TAIL'}, 'EDIT_TAIL'),
])
async def test_real_file_summary_has_reachable_tail_and_working_controls(monkeypatch, size, tool, args, tail):
    monkeypatch.setattr(KAgent, 'on_mount', lambda self: None)
    app = make_app()
    app._sync_overlay = KAgent._sync_overlay.__get__(app, KAgent)
    resolve = Mock()
    req = BridgedPermissionRequest(tool=tool.name(), **tool.summarize(args),
                                   no_session_cache=True, resolve=resolve, reject=Mock())
    async with app.run_test(size=size) as pilot:
        app.dispatch(SetPerm(req))
        app._sync_overlay()
        await pilot.pause()
        assert tail in _content_text(app)
        assert 'OLD_TAIL' in _content_text(app) if tool.name() == 'file_edit' else True
        assert 'truncated' not in _content_text(app)
        await pilot.press('end')
        await pilot.pause()
        assert tail in _content_text(app, visible_only=True)
        assert 'y allow once' in _content_text(app, visible_only=True)
        assert app.overlay_static.region.bottom <= size[1]
        await pilot.press('a')
        resolve.assert_not_called()
        await pilot.press('y')
        resolve.assert_called_once_with(Decision.ALLOW_ONCE)


def test_default_transcript_summarizes_successes_and_preserves_pending_and_failure():
    app = make_app()
    app.dispatch(SetBusy(True))
    for index in range(30):
        event = ToolResultEvent(id=str(index), name='file_write', result='PRIVATE RAW OUTPUT')
        dispatch(app, ToolCallEvent(id=str(index), name='file_write', args={'path': 'report.txt'}))
        dispatch(app, event)
        dispatch(app, event)  # No duplicated completion count.
    dispatch(app, ToolCallEvent(id='wait', name='http', args={'url': 'https://fixture.test/api'}))
    dispatch(app, ToolResultEvent(id='wait', name='http', status='pending',
                                 error_kind='permission_timeout', err='Permission review timed out; request was not sent'))
    dispatch(app, ToolCallEvent(id='fail', name='shell', args={'command': 'fixture'}))
    dispatch(app, ToolResultEvent(id='fail', name='shell', status='error',
                                 error_kind='tool_exception', err='Fixture execution failed'))
    dispatch(app, DoneEvent(stop_reason='stop'))
    text = '\n'.join(row.text for row in app.state.transcript)
    assert text.count('Operations completed:') == 1 and '(30)' in text
    assert 'PRIVATE RAW OUTPUT' not in text
    assert 'Permission review timed out' in text and 'Fixture execution failed' in text
    assert 'Unrecognized tool outcome' not in text and 'user refused' not in text.lower()
    assert 'unresolved permission outcome' in text
    assert len(app.state.transcript) <= 5


def test_completion_presents_its_current_cause_once():
    facts = OutcomeFacts(pending=('input review incomplete',))
    state = initial_state('', BannerData('fixture', 'fixture', '.'))
    state = reducer(state, AgentEventAction(DoneEvent(stop_reason='workflow_stalled'), facts=facts))
    assert state.transcript[-1].text.count('input review incomplete') == 1
    assert state.transcript[-1].kind == 'warning'
