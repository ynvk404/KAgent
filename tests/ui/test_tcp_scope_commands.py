"""Operator-only TCP scope through the existing command handler and real Agent."""
import asyncio
from types import SimpleNamespace
from typing import Any, cast

import pytest

from src.agent.agent import Agent, AgentOptions
from src.engagement.state import EngagementState
from src.llm.core.types import Message
from src.permission.network.grants import HTTPBlocked, HTTPLimits
from src.permission.permission import AlwaysAllow
from src.session.store import Store
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.common.registry import Registry
from src.tools.http.http_tool import HTTPTool
from src.ui.commands.slash_handler import handle_slash
from tests.helpers.agent_fakes import FakeClient


@pytest.fixture
def app():
    state = EngagementState()
    state.add_origin('http://127.0.0.1:8080')
    agent = Agent(AgentOptions(client=FakeClient([]), tools=Registry(), skills=SkillRegistry(),
        target=Target('http://127.0.0.1:8080'), engagement_state=state, prompter=AlwaysAllow(), store=None))
    entries = []
    def dispatch(action):
        entry = getattr(action, 'entry', None)
        if entry is not None:
            entries.append(entry)
    return cast(Any, SimpleNamespace(agent=agent, entries=entries, dispatch=dispatch))


async def test_operator_add_show_partial_revoke_and_reset(app):
    assert handle_slash(app, '/scope tcp-add 192.0.2.10 80,443,8000-8100')
    assert app.agent.engagement_state.tcp_allows('192.0.2.10', '80,443,8000-8100')
    assert not app.agent.engagement_state.is_in_scope('http://192.0.2.10')
    assert not app.agent.engagement_state.http_permissions.grants
    assert 'Explicit TCP scope' in app.agent.history[-1].content
    revision = app.agent.engagement_state.revision
    assert handle_slash(app, '/scope tcp-add 192.0.2.10 80')
    assert app.agent.engagement_state.revision == revision
    assert handle_slash(app, '/scope show')
    assert '192.0.2.10 ports 80,443,8000-8100' in app.entries[-1].text
    assert handle_slash(app, '/scope tcp-remove 192.0.2.10 443')
    assert not app.agent.engagement_state.tcp_allows('192.0.2.10', '443')
    assert app.agent.engagement_state.tcp_allows('192.0.2.10', '80')
    assert handle_slash(app, '/scope reset')
    assert not app.agent.engagement_state.allowed_tcp
    await asyncio.sleep(0)


async def test_remove_all_and_target_change_clear_tcp_authority(app):
    handle_slash(app, '/scope tcp-add 192.0.2.10 1-65535')
    handle_slash(app, '/scope tcp-remove 192.0.2.10')
    assert not app.agent.engagement_state.allowed_tcp
    handle_slash(app, '/scope tcp-add 192.0.2.10 80')
    app.agent.apply_target_base_url('http://127.0.0.1:8081')
    assert not app.agent.engagement_state.allowed_tcp
    handle_slash(app, '/scope tcp-add 192.0.2.10 80')
    app.agent.apply_target_clear()
    assert not app.agent.engagement_state.allowed_tcp
    await asyncio.sleep(0)


@pytest.mark.parametrize('command', ['/scope tcp-add', '/scope tcp-add 192.0.2.10',
    '/scope tcp-add example.test 80', '/scope tcp-add 192.0.2.0/24 80',
    '/scope tcp-add 192.0.2.10 0', '/scope tcp-remove', '/scope tcp-remove 192.0.2.10 bad'])
def test_invalid_operator_commands_do_not_grant_tcp_scope(app, command):
    assert handle_slash(app, command)
    assert not app.agent.engagement_state.allowed_tcp
    assert app.entries[-1].kind == 'error'


def test_tcp_commands_require_active_engagement(app):
    app.agent.apply_target_clear()
    assert handle_slash(app, '/scope tcp-add 192.0.2.10 80')
    assert not app.agent.engagement_state.allowed_tcp
    assert 'No active engagement' in app.entries[-1].text


async def test_session_reset_preserves_http_and_tcp_scope_but_invalidates_permissions(app):
    app.agent.add_scope_origin('http://127.0.0.1:8081')
    handle_slash(app, '/scope tcp-add 192.0.2.10 80')
    state = app.agent.engagement_state
    scope = state.to_dict()
    rights = state.http_permissions
    tool = HTTPTool(app.agent.target, state)
    rights.activate('http://127.0.0.1:8080', HTTPLimits.session())
    action, _ = tool.prepare({'url': '/', 'phase': 'recon'})
    receipt = await rights.authorize(action, AlwaysAllow(), None, lambda: app.agent.target.revision)
    epoch, revision = rights.epoch, rights.revision
    await app.agent.reset()
    assert state.to_dict() == scope
    assert rights.epoch != epoch and rights.revision > revision
    assert not rights.grants and not rights._receipts
    with pytest.raises(HTTPBlocked):
        rights.reserve(action, receipt, None, app.agent.target.revision)
    assert state.tcp_allows('192.0.2.10', '80')
    assert state.is_in_scope('http://127.0.0.1:8081')
    assert 'Explicit TCP scope' in app.agent.history[0].content
    handle_slash(app, '/scope reset')
    assert not state.allowed_tcp
    assert state.is_in_scope('http://127.0.0.1:8080')
    assert not state.is_in_scope('http://127.0.0.1:8081')
    await asyncio.sleep(0)


@pytest.mark.parametrize('prompt_profile', ['full', 'compact'])
async def test_compaction_and_restore_render_current_tcp_scope_from_state(app, tmp_path, prompt_profile):
    agent = app.agent
    agent.prompt_profile = prompt_profile
    agent.store = Store.new_with_id(tmp_path, 'tcp-compaction-restore')
    agent.update_tcp_scope('192.0.2.10', '80,443')
    agent.update_tcp_scope('2001:db8::1', '8000-8100')
    agent.update_tcp_scope('192.0.2.10', '443', remove=True)
    state = agent.engagement_state
    state.http_permissions.activate(agent.target.base_url(), HTTPLimits.session())
    agent.history += [Message(role='user', content='older bounded request'),
                      Message(role='assistant', content='prior observations ' * 12000),
                      Message(role='user', content='continue')]
    # The summary intentionally contains no scope, and compaction drops the old
    # scope messages. Only authoritative EngagementState can supply these rows.
    await agent.apply_compaction_summary('## Current Objective\n- Continue bounded review.\n',
                                         list(agent.history), 'tcp-scope-test')
    prompt = agent.history[0].content
    assert 'Explicit TCP scope' in prompt
    assert '192.0.2.10 ports 80\n' in prompt
    assert '2001:db8::1 ports 8000-8100\n' in prompt
    assert '192.0.2.10 ports 80,443' not in prompt
    assert not state.is_in_scope('http://192.0.2.10')
    restored_state = EngagementState()
    restored = Agent(AgentOptions(client=FakeClient([]), tools=Registry(), skills=SkillRegistry(),
        target=Target(), engagement_state=restored_state, prompter=AlwaysAllow(), store=agent.store,
        prompt_profile=prompt_profile))
    restored.resume_saved()
    assert restored_state.allowed_tcp == state.allowed_tcp
    assert not restored_state.http_permissions.grants and not restored_state.http_permissions._receipts
    assert '192.0.2.10 ports 80\n' in restored.history[0].content
    await restored.reset()
    await restored.save()
    assert restored.store is not None
    assert restored.store.load().engagement_state.allowed_tcp == state.allowed_tcp
