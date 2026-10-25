"""A blocked inventory still gets a bounded operator/artifact handoff."""
import json

import pytest

from src.agent.agent import AgentRunOptions
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.tools.common.ask import AskUserTool
from src.tools.execution.file import FileWriteTool
from tests.agent.test_workflow_request_preparation import SnapshotClient, call, setup
from tests.helpers.agent_fakes import FakeSignal
from tests.integration.test_trial1_phase_admission import action, phases, runtime


class Operator:
    def __init__(self):
        self.questions = []

    async def ask(self, q, signal=None):
        self.questions.append(q)
        return "Keep blocked; no credential available."


@pytest.mark.parametrize("max_steps,expected_questions", [(1, 0), (6, 1)])
async def test_last_blocked_disposition_allows_question_and_canonical_handoff(tmp_path, monkeypatch,
                                                                          max_steps, expected_questions):
    tool = runtime(tmp_path)
    await phases(tool)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KAGENT_PROJECT_ROOT", str(tmp_path))
    item = json.loads(await action(tool, "record_input", method="POST", endpoint="/private/order",
        parameter="lines", location="json", input_type="array"))["input"]
    path = tool.phase_completion_readiness("web-input-analysis")["artifact_ref"]
    client = SnapshotClient([
        call("set_input_disposition", input_id=item["id"], disposition="blocked",
             disposition_reason="Required credential unavailable."),
        ChatResponse(Message("assistant", "", tool_calls=[ToolCall("question", FunctionCall("ask_user",
            json.dumps({"questions": [{"question": "Provide the missing credential or keep this input blocked?"}]})))]), "tool_calls"),
        ChatResponse(Message("assistant", "", tool_calls=[ToolCall("handoff", FunctionCall("file_write",
            json.dumps({"path": path, "content": "No candidates. Private lines input blocked; untested. Operator keeps it blocked."})))]), "tool_calls"),
        ChatResponse(Message("assistant", "Assessment incomplete: credential unavailable."), "stop"),
    ])
    if max_steps == 1:
        client.scripted = [client.scripted[0], client.scripted[-1]]
    agent = setup(tmp_path, client, tool.state)
    assert tool.target is not None
    agent.target = tool.target
    agent.tools.tools["workflow"] = tool
    operator = Operator()
    agent.tools.register(AskUserTool(operator))
    agent.tools.register(FileWriteTool())
    events = []
    await agent.run("continue", FakeSignal(), events.append, AgentRunOptions(max_steps=max_steps))
    assert len(operator.questions) == expected_questions
    if expected_questions:
        assert (tmp_path / path).is_file()
        assert any(m.role == "tool" and m.name == "ask_user" and "Keep blocked" in m.content
                   for m in agent.history)
    assert tool.state.attack_surface_inputs[item["id"]].disposition == "blocked"
    assert "input_analysis" not in tool.state.completed_phases()
    assert not tool.state.candidates and not tool.state.attempts and not tool.state.validation_results
    assert events[-1]["stop_reason"] == "workflow_blocked"
    assert len(client.requests) <= max_steps + 1
