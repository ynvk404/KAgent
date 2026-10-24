"""Actual adapters through Registry, Agent events and the UI, offline only."""
import json

import httpx
import pytest

from src.agent.agent import Agent, AgentOptions, _to_agent_event
from src.agent.events import DoneEvent
from src.engagement.state import EngagementState
from src.llm.core.types import FunctionCall, ToolCall
from src.permission.permission import Decision, PermissionPolicyBlocked
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.common.registry import Registry
from src.tools.execution.file import FileReadTool
from src.tools.http.http_tool import HTTPTool
from src.ui.core.state import SetBusy
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from tests.ui.test_app import make_app
from tests.ui.test_progress_milestones import dispatch


@pytest.mark.parametrize('adapter', ['file', 'http'])
async def test_stale_nested_review_is_not_user_refusal_and_never_executes(tmp_path, monkeypatch, adapter):
    target = Target('http://127.0.0.1:3000')
    engagement = EngagementState()
    engagement.initialize_target(target.base_url())
    secret_file = tmp_path / '.ssh' / 'id_ed25519'
    secret_file.parent.mkdir()
    secret_file.write_text('PRIVATE-FIXTURE-MATERIAL')
    sent = []
    real_client = httpx.AsyncClient

    async def transport(request):
        sent.append(request)
        return httpx.Response(200, content=b'fixture', request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: real_client(
        **kw, transport=httpx.MockTransport(transport)))

    class Operator:
        async def ask(self, request, signal=None):
            if adapter == 'file':
                # The independently sensitive review must reject a new file
                # version even when the callback returns allow once.
                secret_file.write_text('REPLACED-PRIVATE-FIXTURE')
            elif 'private/internal URL' in request.summary:
                target.set_base_url('http://127.0.0.1:3001')
            return Decision.ALLOW_ONCE

    registry = Registry()
    if adapter == 'file':
        tool, args = FileReadTool(), {'path': str(secret_file)}
    else:
        tool, args = HTTPTool(target, engagement), {'phase': 'recon', 'url': '/fixture'}
    registry.register(tool)
    agent = Agent(AgentOptions(client=FakeClient([]), tools=registry, skills=SkillRegistry(),
                               prompter=Operator(), store=None, target=target, engagement_state=engagement))
    app = make_app()
    app.dispatch(SetBusy(True))
    events = []

    def emit(event):
        events.append(event)
        dispatch(app, _to_agent_event(event))

    working = []
    batch = await agent.execute_tool_calls([ToolCall(id='fixture', function=FunctionCall(
        name=tool.name(), arguments=json.dumps(args)))], FakeSignal(), emit, working)
    assert not batch.all_refused and not sent
    assert working[0].tool_status == 'error'
    assert working[0].tool_error_kind == 'permission_stale'
    assert not batch.calls[0].result.terminal_user_controlled_refusal
    assert 'PRIVATE-FIXTURE' not in working[0].content
    result = next(event for event in events if event['type'] == 'tool-result')
    assert result['error_kind'] == 'permission_stale'
    assert working[0].role == 'tool' and working[0] is agent.history[-1]
    assert 'stale' in working[0].content and 'stale' in result['result']
    assert not app.state.pending_perm and not app.state.pending_calls
    assert not any(row.kind in {'error', 'warning'} for row in app.state.transcript)
    dispatch(app, DoneEvent(stop_reason='stop'))
    text = '\n'.join(row.text for row in app.state.transcript)
    # Plan B keeps intermediate feedback in model history and raw events.
    assert 'stale' not in text and 'unresolved permission outcome' not in text
    assert 'Permission denied by user' not in text and 'PRIVATE-FIXTURE' not in text


def test_policy_block_keeps_legacy_refusal_base_but_is_not_operator_denial():
    from src.permission.permission import UserControlledRefusal
    error = PermissionPolicyBlocked('blocked: missing receipt')
    assert isinstance(error, UserControlledRefusal)
    assert error.explicit_denial is False and error.error_kind == 'policy_block'
