"""Malformed mutations stay actionable invalid_args through Agent events/history."""
import json
from unittest.mock import AsyncMock

import pytest

from src.agent.agent import AgentRunOptions
from src.agent.events import ToolResultEvent
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.tools.common.registry import Registry
from src.tools.execution.file import FileWriteTool, FileWriteToolAlias, FileEditTool, FileEditToolAlias
from tests.agent.test_token_accounting_independent_verify import make_agent
from tests.helpers.agent_fakes import FakeClient, FakeSignal


@pytest.mark.parametrize("factory,missing", [(FileWriteTool, "content"), (FileWriteToolAlias, "content"),
    (FileEditTool, "new_string"), (FileEditToolAlias, "new_string")])
async def test_bad_file_mutation_is_not_success_or_user_refusal(factory, missing, tmp_path):
    path = tmp_path / "existing.txt"
    path.write_bytes(b"original\r\n")
    tool = factory()
    registry = Registry()
    registry.register(tool)
    args = {"path": str(path), "old_string": "original"}
    client = FakeClient([
        ChatResponse(Message("assistant", "", tool_calls=[
            ToolCall("malformed", FunctionCall(tool.name(), json.dumps(args)))]), "tool_calls"),
        ChatResponse(Message("assistant", "The required string was missing."), "stop"),
    ])
    agent = make_agent(tools=registry, client=client)
    prompt = AsyncMock()
    agent.prompter.ask = prompt
    events = []
    await agent.run("Prepare an offline note", FakeSignal(), events.append, AgentRunOptions(max_steps=2))
    results = [event for event in events if isinstance(event, ToolResultEvent)]
    assert len(results) == 1
    assert results[0].status == "error" and results[0].error_kind == "invalid_args"
    assert missing in results[0].err and "string" in results[0].err
    history = [message for message in agent.history if message.role == "tool"]
    assert len(history) == 1 and history[0].tool_error_kind == "invalid_args"
    assert missing in history[0].content
    assert events[-1].stop_reason == "final_response"
    assert path.read_bytes() == b"original\r\n"
    prompt.assert_not_called()
