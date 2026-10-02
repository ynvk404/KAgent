"""Current-code characterization. Passing gap cases are audit evidence, not acceptance.

All process/MCP/HTTP dispatches are fake; no model calls or external traffic.
"""
from unittest.mock import AsyncMock

import httpx
import pytest

from src.config.config import PluginConfig
from src.engagement.state import EngagementState
from src.permission.permission import Decision, UserControlledRefusal, YoloPrompter
from src.tools.capabilities import CapabilityInventory
from src.tools.content_discovery import ContentDiscoveryTool
from src.tools.file import FileReadTool
from src.tools.http import HTTPTool
from src.tools.mcp_integration import MCPTool
from src.tools.plugin import CommandPluginTool
from src.tools.registry import Registry
from src.tools.shell import ShellTool
from src.tools.web import WebFetchTool, WebSearchTool
from src.target.target import Target

ORIGIN = 'http://fixture.lab:3000'


class Recorder:
    def __init__(self, decision=Decision.DENY):
        self.requests = []
        self.decision = decision

    async def ask(self, request, signal=None):
        self.requests.append(request)
        return self.decision


class Session:
    server_name = 'fixture-server'

    def __init__(self):
        self.calls = []

    async def call_tool(self, name, args, cancel_event=None):
        self.calls.append((name, args))
        return {'isError': False, 'content': []}


def engagement():
    state = EngagementState()
    state.initialize_target(ORIGIN)
    return state


@pytest.fixture
def network(monkeypatch):
    from src.tools import web

    sent = []

    def transport(request):
        sent.append(request)
        return httpx.Response(200, content=b'fixture observation', request=request)

    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: real_client(transport=httpx.MockTransport(transport), **kw))
    for module in ['src.tools.http', 'src.tools.web', 'src.tools.content_discovery']:
        monkeypatch.setattr(module + '.gate_private_request', AsyncMock(return_value=''))
    monkeypatch.setattr('src.tools.content_discovery.sleep_or_abort', AsyncMock(return_value=True))
    web._result_cache.clear()
    yield sent
    web._result_cache.clear()


@pytest.mark.asyncio
@pytest.mark.parametrize('phase', ['recon', 'validation', 'impact'])
async def test_control_http_operator_yolo_accepts_mutation_without_dialog(phase, network):
    state = engagement()
    tool = HTTPTool(Target(ORIGIN), state)
    registry = Registry()
    registry.register(tool)
    operator = Recorder()
    await registry.execute('http', {'url': '/new', 'method': 'POST', 'phase': phase,
                                  'body': "<script>alert(1)</script>' OR 1=1--"}, None, YoloPrompter(operator, True))
    assert len(network) == 1 and not operator.requests
    assert network[0].content == b"<script>alert(1)</script>' OR 1=1--"


@pytest.mark.asyncio
async def test_control_http_session_deny_wins_over_yolo(network):
    state = engagement()
    registry = Registry()
    registry.register(HTTPTool(Target(ORIGIN), state))
    state.http_permissions.deny_session()
    operator = Recorder()
    with pytest.raises(UserControlledRefusal):
        await registry.execute('http', {'url': '/', 'phase': 'recon'}, None, YoloPrompter(operator, True))
    assert not network and not operator.requests


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['shell', 'mcp', 'plugin'])
async def test_gap_generic_yolo_repeated_denial_still_asks_each_call(kind, monkeypatch):
    process = AsyncMock(return_value='fixture')
    plugin = AsyncMock(return_value='fixture')
    monkeypatch.setattr('src.tools.shell.run_with_capture', process)
    monkeypatch.setattr('src.tools.plugin.run_plugin', plugin)
    remote = Session()
    if kind == 'shell':
        tool, args = ShellTool(), {'command': 'printf fixture'}
    elif kind == 'mcp':
        tool, args = MCPTool(remote, 'mcp_fixture', 'operation', 'fixture', {}), {'url': ORIGIN}
    else:
        tool, args = CommandPluginTool(PluginConfig(name='plugin_fixture', command='fixture')), {}
    registry = Registry()
    registry.register(tool)
    operator = Recorder()
    prompter = YoloPrompter(operator, True)
    for _ in range(2):
        with pytest.raises(UserControlledRefusal):
            await registry.execute(tool.name(), args, None, prompter)
    assert len(operator.requests) == 2
    process.assert_not_called()
    plugin.assert_not_called()
    assert not remote.calls


@pytest.mark.asyncio
async def test_gap_sensitive_read_yolo_still_asks_and_denial_protects_fake_file(tmp_path):
    fake = tmp_path / '.env'
    fake.write_text('FAKE_AUDIT_SECRET=fixture-only')
    tool = FileReadTool()
    registry = Registry()
    registry.register(tool)
    operator = Recorder()
    prompter = YoloPrompter(operator, True)
    for _ in range(2):
        with pytest.raises(UserControlledRefusal):
            await registry.execute(tool.name(), {'path': str(fake)}, None, prompter)
    assert len(operator.requests) == 2


@pytest.mark.asyncio
async def test_gap_http_session_deny_does_not_control_fetch_or_search(network):
    state = engagement()
    state.http_permissions.deny_session()
    operator = Recorder()
    registry = Registry()
    fetch = WebFetchTool(state, Target(ORIGIN))
    search = WebSearchTool()
    registry.register(fetch)
    registry.register(search)
    prompter = YoloPrompter(operator, True)
    await registry.execute(fetch.name(), {'url': ORIGIN + '/fetch'}, None, prompter)
    await registry.execute(search.name(), {'query': 'FAKE_LOCAL_CANARY_20261002'}, None, prompter)
    assert len(network) == 2 and not operator.requests
    assert 'FAKE_LOCAL_CANARY_20261002' in str(network[1].url)
    assert network[1].url.host == 'html.duckduckgo.com'


@pytest.mark.asyncio
async def test_gap_http_session_deny_does_not_control_discovery(network):
    state = engagement()
    state.http_permissions.deny_session()
    tool = ContentDiscoveryTool(Target(ORIGIN), state, CapabilityInventory(which=lambda _: None), lambda: 'minimal')
    registry = Registry()
    registry.register(tool)
    operator = Recorder()
    await registry.execute(tool.name(), {'paths': ['new-endpoint'], 'max_requests': 5,
                                        'rate_limit': 10}, None, YoloPrompter(operator, True))
    assert network and not operator.requests


@pytest.mark.asyncio
async def test_gap_plugin_configuration_is_not_frozen_with_approved_args(monkeypatch):
    dispatch = AsyncMock(return_value='fixture')
    monkeypatch.setattr('src.tools.plugin.run_plugin', dispatch)
    cfg = PluginConfig(name='plugin_fixture', command='fixture-before', args=['before'])
    tool = CommandPluginTool(cfg)
    registry = Registry()
    registry.register(tool)

    class ChangeWhileReviewing(Recorder):
        async def ask(self, request, signal=None):
            self.requests.append(request)
            assert 'fixture-before' in request.detail
            cfg.command = 'fixture-after'
            cfg.args = ['after']
            return Decision.ALLOW_ONCE

    operator = ChangeWhileReviewing()
    await registry.execute(tool.name(), {'input': 'unchanged'}, None, operator)
    assert dispatch.await_args.args[:2] == ('fixture-after', ['after'])
    assert dispatch.await_args.args[2] == {'input': 'unchanged'}


@pytest.mark.asyncio
async def test_gap_direct_shell_executor_has_no_permission_gate(monkeypatch):
    dispatch = AsyncMock(return_value='fixture')
    monkeypatch.setattr('src.tools.shell.run_with_capture', dispatch)
    operator = Recorder()
    await ShellTool().run({'command': 'printf fixture'}, None, operator)
    assert dispatch.await_count == 1 and not operator.requests
