"""Execution outcomes stay distinct from security observations."""

import asyncio
import json

import pytest

from src.agent.agent import Agent, AgentOptions, ParsedToolCall
from src.engagement.state import EngagementState, OutOfScopeError
from src.llm.types import FunctionCall, ToolCall
from src.permission.permission import AlwaysAllow, AlwaysDeny, UserControlledRefusal
from src.session.store import Store
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.outcome import ToolOutput
from src.tools.registry import Registry
from src.tools.http import HTTPTool
from tests.helpers.agent_fakes import FakeClient, FakeSignal


class CaseTool:
    def name(self):
        return "case"

    def description(self):
        return "case"

    def schema(self):
        return {"type": "object", "properties": {}}

    def requires_permission(self):
        return False

    def validate_args(self, args):
        if args.get("case") == "invalid":
            raise ValueError("invalid argument")

    async def run(self, args, signal, prompter):
        case = args["case"]
        if case == "success":
            return "ok"
        if case in ("200", "403"):
            return ToolOutput(
                f"HTTP/1.1 {case}", status="observation", http_status=int(case),
            )
        if case == "403_truncated":
            return ToolOutput(
                "HTTP/1.1 403\n[response body truncated at 65536 bytes]",
                status="observation", http_status=403, truncated=True,
            )
        if case == "fetch_network":
            return ToolOutput(
                "URL: https://example.test\nERROR: fetch failed",
                status="error", error_kind="network",
            )
        errors = {
            "timeout": asyncio.TimeoutError,
            "scope": lambda: OutOfScopeError("outside scope"),
            "permission": lambda: UserControlledRefusal("permission denied"),
            "crash": lambda: RuntimeError("tool crashed"),
            "value_crash": lambda: ValueError("tool crashed"),
        }
        raise errors[case]()


def make_agent():
    registry = Registry()
    registry.register(CaseTool())
    return Agent(AgentOptions(
        client=FakeClient([]), tools=registry, skills=SkillRegistry(),
        prompter=AlwaysAllow(), store=None, target=Target(),
    ))


@pytest.mark.asyncio
@pytest.mark.parametrize("case,status,kind,http_status", [
    ("success", "success", None, None),
    ("200", "observation", None, 200),
    ("403", "observation", None, 403),
    ("403_truncated", "observation", None, 403),
    ("timeout", "error", "timeout", None),
    ("scope", "error", "scope_denied", None),
    ("permission", "error", "permission_denied", None),
    ("invalid", "error", "invalid_args", None),
    ("crash", "error", "tool_exception", None),
    ("value_crash", "error", "tool_exception", None),
    ("fetch_network", "error", "network", None),
])
async def test_dispatch_event_and_history_keep_outcome(case, status, kind, http_status):
    agent = make_agent()
    call = ToolCall(id="call-1", function=FunctionCall(name="case", arguments="{}"))
    parsed = ParsedToolCall(args={"case": case}, args_json="{}")
    result = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    events = []
    working = []
    agent.record_tool_result(call, parsed, result, events.append, working)

    assert result.status == status
    assert result.error_kind == kind
    assert result.http_status == http_status
    assert events[0]["status"] == status
    assert events[0]["error_kind"] == kind
    assert events[0]["truncated"] is (case == "403_truncated")
    assert events[0]["id"] == "call-1"
    message = working[0]
    assert message.tool_status == status
    assert message.tool_error_kind == kind
    assert message.tool_http_status == http_status
    assert message.tool_truncated is (case == "403_truncated")
    assert message.tool_call_id == "call-1"
    if case in ("success", "200", "403", "403_truncated"):
        assert result.err_str == ""
    elif case == "fetch_network":
        assert "ERROR: fetch failed" in result.result
    else:
        assert result.result.startswith("ERROR:")


@pytest.mark.asyncio
async def test_tool_outcome_persists_and_legacy_message_loads(tmp_path):
    store = Store.new_with_id(tmp_path, "outcome")
    agent = make_agent()
    call = ToolCall(id="call-1", function=FunctionCall(name="case", arguments="{}"))
    parsed = ParsedToolCall(args={"case": "403_truncated"}, args_json="{}")
    result = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    agent.record_tool_result(call, parsed, result, lambda _: None, [])
    await store.save(agent.get_history())

    loaded = next(m for m in store.load().messages if m.tool_call_id == "call-1")
    assert loaded.content.startswith("HTTP/1.1 403")
    assert loaded.tool_status == "observation"
    assert loaded.tool_http_status == 403
    assert loaded.tool_error_kind is None
    assert loaded.tool_truncated is True

    store.path.write_text(json.dumps({"messages": [{
        "role": "tool", "content": "legacy", "tool_call_id": "old",
    }]}), encoding="utf-8")
    legacy = store.load().messages[0]
    assert legacy.content == "legacy"
    assert legacy.tool_call_id == "old"
    assert legacy.tool_status is None
    assert legacy.tool_truncated is False


@pytest.mark.asyncio
async def test_registry_denial_and_scope_preflight_have_distinct_categories():
    call = ToolCall(id="call-1", function=FunctionCall(name="http", arguments="{}"))
    target = Target("https://example.test")
    engagement = EngagementState()
    engagement.initialize_target(target.base_url())
    registry = Registry()
    registry.register(HTTPTool(target, engagement))
    agent = Agent(AgentOptions(
        client=FakeClient([]), tools=registry, skills=SkillRegistry(),
        prompter=AlwaysDeny(), store=None, target=target,
        engagement_state=engagement,
    ))
    scope = await agent.run_parsed_tool_call(
        call, ParsedToolCall({"url": "https://other.test"}, "{}"), FakeSignal(),
    )
    denied = await agent.run_parsed_tool_call(
        call, ParsedToolCall({"url": "https://example.test"}, "{}"), FakeSignal(),
    )
    assert (scope.status, scope.error_kind) == ("error", "scope_denied")
    assert (denied.status, denied.error_kind) == ("error", "permission_denied")


@pytest.mark.asyncio
async def test_malformed_tool_call_json_is_invalid_args():
    agent = make_agent()
    call = ToolCall(id="bad", function=FunctionCall(name="case", arguments="{"))
    parsed = agent.parse_tool_call(call)
    result = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    assert result.status == "error"
    assert result.error_kind == "invalid_args"


@pytest.mark.asyncio
async def test_preaborted_tool_call_has_cancelled_outcome():
    agent = make_agent()
    call = ToolCall(id="aborted", function=FunctionCall(name="case", arguments="{}"))
    signal = FakeSignal()
    signal.aborted = True
    result = await agent.run_parsed_tool_call(
        call, ParsedToolCall({"case": "success"}, "{}"), signal,
    )
    assert result.status == "cancelled"
    assert result.error_kind == "cancelled"
    assert result.result == "ERROR: aborted"
