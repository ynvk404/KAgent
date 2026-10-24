"""Counterexamples against published contracts and executable correction feedback."""
from copy import deepcopy
import json

from jsonschema import Draft202012Validator
import pytest

from src.permission.permission import AlwaysAllow
from src.tools.common.outcome import ToolOutput
from src.target.target import Target
from src.tools.http.http_tool import HTTPTool
from src.engagement.state import EngagementState
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.discovery.inventory import SourceRecord
from src.workflow.state import WorkflowObjective, WorkflowState


def tool_state():
    origin = "https://fixture.test"
    state = WorkflowState(objective=WorkflowObjective("objective", "whole_target", origin))
    return WorkflowTool(state, Target(origin)), state


def test_record_input_required_contract_preserves_method_shorthand():
    tool, _ = tool_state()
    props = tool.schema()["properties"]
    action = props["action"]["description"]
    row = next(line for line in action.splitlines() if line.startswith("record_input("))
    for field in ("endpoint", "parameter", "location"):
        assert field + "*" in row
        assert "record_input" in props[field]["description"].partition("Required for: ")[2]
    assert "method*" not in row  # GET /path already supplies the method.
    assert "method prefix" in props["endpoint"]["description"]


@pytest.mark.parametrize("field,value", [
    ("discovery_source_id", "ds_" + "a" * 32),
    ("discovery_source_id", "obs_" + "a" * 32),
    ("endpoint_id", "ds_" + "a" * 64),
    ("source_bounds", {"made_up_limit": 1}),
    ("source_bounds", {"max_bytes": 16 * 1024**2 + 1}),
])
def test_discovery_field_contract_prevents_runtime_counterexamples(field, value):
    tool, _ = tool_state()
    assert list(Draft202012Validator(tool.schema()["properties"][field]).iter_errors(value))


async def test_discovery_rejection_keeps_binding_and_provides_corrected_retry():
    tool, state = tool_state()
    source = SourceRecord("objective", "https://fixture.test", "http", "fixture",
        "a" * 64, document_url="https://fixture.test/document")
    state.discovery_sources[source.id] = source
    before = deepcopy(state.to_dict())
    invalid = await tool.run({"action": "get_source", "discovery_source_id": "obs_" + "a" * 32},
                             None, AlwaysAllow())
    assert isinstance(invalid, ToolOutput)
    assert invalid.status == "error" and invalid.error_kind == "workflow_state"
    payload = json.loads(invalid.partition("\n")[2])
    assert "sources" in payload["error"]["next_action"]
    assert state.to_dict() == before
    corrected = json.loads(await tool.run({"action": "get_source", "discovery_source_id": source.id},
                                          None, AlwaysAllow()))
    assert corrected["discovery_source"]["id"] == source.id
    assert state.to_dict() == before
    # A well-shaped foreign ID must still fail; a schema match is no authority.
    foreign = await tool.run({"action": "get_source", "discovery_source_id": "ds_" + "b" * 64},
                             None, AlwaysAllow())
    assert isinstance(foreign, ToolOutput)
    assert foreign.status == "error" and state.to_dict() == before


async def test_record_input_missing_fields_reject_then_shorthand_corrects_without_mutation():
    tool, state = tool_state()
    before = deepcopy(state.to_dict())
    rejected = await tool.run({"action": "record_input", "endpoint": "GET /search"},
                              None, AlwaysAllow())
    assert isinstance(rejected, ToolOutput)
    assert rejected.status == "error" and rejected.error_kind == "invalid_args"
    assert "parameter" in rejected and "location" in rejected and state.to_dict() == before
    output = json.loads(await tool.run({"action": "record_input", "endpoint": "GET /search",
                                        "parameter": "q", "location": "query"}, None, AlwaysAllow()))
    assert output["input"]["method"] == "GET"
    assert output["input"]["source_ref"] is None and not state.attempts


def test_http_fields_explain_direct_replay_dependencies():
    target = Target("https://fixture.test")
    tool = HTTPTool(target, EngagementState())
    props = tool.schema()["properties"]
    assert "required" in props["url"]["description"].lower()
    assert "headers" in props["candidate_id"]["description"]
    assert "mutation_value" in props["occurrence"]["description"]
    assert "mutation_value" in props["input_path"]["description"]

async def test_next_agent_request_retains_feedback_and_exact_lookup_for_retry(tmp_path, monkeypatch):
    from src.agent.agent import AgentRunOptions, elide_persisted_workflow_results
    from src.llm.core.types import ChatResponse, Message
    from tests.agent.test_workflow_request_preparation import SnapshotClient, setup, call
    from tests.helpers.agent_fakes import FakeSignal

    def no_network(*args, **kwargs):
        raise AssertionError("Argument correction must remain offline.")
    monkeypatch.setattr("httpx.AsyncClient", no_network)
    tool, state = tool_state()
    source = SourceRecord("objective", "https://fixture.test", "http", "fixture",
        "a" * 64, document_url="https://fixture.test/document")
    state.discovery_sources[source.id] = source
    client = SnapshotClient([
        call("get_source", discovery_source_id="obs_" + "a" * 32),
        call("list", view="sources"),
        call("get_source", discovery_source_id=source.id),
        ChatResponse(Message("assistant", "Metadata read; assessment remains incomplete."), "stop"),
    ])
    agent = setup(tmp_path, client, state)
    events = []
    await agent.run("Continue the current whole-target assessment.", FakeSignal(), events.append,
                    AgentRunOptions(max_steps=3))
    rejected = next(m for m in client.requests[1].messages
                    if m.role == "tool" and m.tool_status == "error")
    error = json.loads(rejected.content.partition("\n")[2])["error"]
    assert error["code"] == "DISCOVERY_ACTION_REJECTED" and "sources" in error["next_action"]
    assert source.id in str(client.requests[2].messages[-1].content)
    results = [e for e in events if e.type == "tool-result"]
    assert [e.status for e in results] == ["error", "success", "success"]
    assert not state.candidates and not state.evidence and not state.validation_results
    elide_persisted_workflow_results(agent.history)
    saved_error = next(m for m in agent.history if m.role == "tool" and m.tool_status == "error")
    assert json.loads(saved_error.content.partition("\n")[2])["error"] == error

@pytest.mark.parametrize("bounds", [{"made_up_limit": 1}, {"max_bytes": 0},
                                   {"max_bytes": 16 * 1024**2 + 1}, {"max_bytes": True}])
async def test_bounds_rejection_and_boundary_correction_preserve_source_identity(bounds):
    tool, state = tool_state()
    source = SourceRecord("objective", "https://fixture.test", "http", "fixture",
        "a" * 64, document_url="https://fixture.test/document")
    state.discovery_sources[source.id] = source
    args = {"action": "set_source_disposition", "discovery_source_id": source.id,
            "source_disposition": "partial", "source_reason": "Only the retained prefix was inspected.",
            "source_limitations": ["Bounded prefix"], "acknowledge_bounded_stop": True}
    before = deepcopy(state.to_dict())
    rejected = await tool.run({**args, "source_bounds": bounds}, None, AlwaysAllow())
    assert isinstance(rejected, ToolOutput) and rejected.status == "error"
    error = json.loads(rejected.partition("\n")[2])["error"]
    assert "max_bytes" in error["allowed_source_bounds"]
    assert state.to_dict() == before
    accepted = json.loads(await tool.run({**args, "source_bounds": {"max_bytes": 16 * 1024**2}},
                                        None, AlwaysAllow()))
    assert accepted["discovery_source"]["id"] == source.id and not accepted["unresolved"]
