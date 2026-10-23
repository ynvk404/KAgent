"""Removed MCP adapters cannot launch local processes, even without a policy."""
from unittest.mock import AsyncMock
import asyncio
import pytest
from src.config.config import MCPServerConfig
from src.permission.runtime.execution import ExecutionBlocked
from src.tools.mcp.integration import MCPSession, discover_mcp_tools, MCPTool

@pytest.mark.parametrize('server', [MCPServerConfig('browser','node',[]), MCPServerConfig('custom','python',[])])
async def test_removed_executor_rejects_discovery_and_open_before_spawn(monkeypatch, server):
    spawn = AsyncMock(side_effect=AssertionError('must not spawn'))
    monkeypatch.setattr(asyncio,'create_subprocess_exec',spawn)
    for operation in (MCPSession.open, discover_mcp_tools):
        with pytest.raises(ExecutionBlocked,match='unavailable'):
            await operation(server)
    spawn.assert_not_called()

async def test_manually_constructed_mcp_cannot_dispatch_remote_call():
    session = AsyncMock()
    tool = MCPTool(session,'legacy','remote','',{})
    with pytest.raises(ExecutionBlocked,match='unavailable'):
        await tool.run({},None,None)
    session.call_tool.assert_not_called()
