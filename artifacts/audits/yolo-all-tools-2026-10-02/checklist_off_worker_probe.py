"""Actual ordinary-mode ALLOW through worker/broker, not just mocked dispatch."""
import pytest

from tests.security.test_repair_runtime import lab, worker_for, MCP_SERVER
from src.config.config import PluginConfig, MCPServerConfig
from src.permission.permission import Decision
from src.tools.shell import ShellTool
from src.tools.plugin import CommandPluginTool
from src.tools.mcp_integration import discover_mcp_tools


@pytest.mark.asyncio
@pytest.mark.parametrize('group', ['shell', 'plugin', 'mcp'])
async def test_off_operator_approval_preserves_real_scoped_worker_http(lab, group):
    registry, prompter, policy, operator, origin, requests = lab
    await worker_for(policy)
    prompter.set_yolo(False)
    operator.decision = Decision.ALLOW_ONCE
    url = origin + '/ordinary?q=1%3D1'
    session = None
    if group == 'shell':
        tool = ShellTool()
        args = {'command': 'curl -fsS --max-time 10 "' + url + '"'}
    elif group == 'plugin':
        code = 'import json,sys,urllib.request; print(urllib.request.urlopen(json.load(sys.stdin)["url"],timeout=10).read().decode())'
        tool = CommandPluginTool(PluginConfig(name='fixture_plugin', command='/usr/bin/python3', args=['-c', code]))
        args = {'url': url}
    else:
        discovery = await discover_mcp_tools(MCPServerConfig(name='fixture', command='/usr/bin/python3',
                args=['-u', '-c', MCP_SERVER]), execution_policy=policy)
        tool = discovery['tools'][0]
        session = discovery['session']
        args = {'url': url}
    registry.register(tool)
    try:
        result = await registry.execute(tool.name(), args, None, prompter)
        assert 'TEST_ONLY' in result
        assert len(requests) == 1 and operator.calls == 1
        assert policy.active == 0 and not policy.engagement.http_permissions._inflight
        assert not policy.engagement.http_permissions.grants  # no manual/autonomous grant
    finally:
        if session is not None:
            await session.close()
