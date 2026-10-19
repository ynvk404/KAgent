"""Characterize existing gates with an unavailable operator; no headless CLI added."""
from types import SimpleNamespace

import httpx
import pytest

from src.agent.agent import Agent, AgentOptions
from src.engagement.state import EngagementState, OutOfScopeError
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.permission.network.grants import HTTPBlocked, HTTPLimits
from src.permission.permission import OperatorInputUnavailable, PermissionRequest, YoloPrompter
from src.permission.runtime.execution import ExecutionPolicy
from src.skills.registry import Registry as Skills
from src.target.target import Target
from src.tools.common.ask import AskUserTool
from src.tools.common.registry import Registry
from src.tools.http.http_tool import HTTPTool
from tests.helpers.agent_fakes import FakeClient, FakeSignal

ORIGIN = "http://127.0.0.1:8081"


class UnavailableOperator:
    """Test-only stand-in for the proposed frontend; no approval logic."""
    def __init__(self):
        self.events = []

    async def ask(self, request, signal=None):
        self.events.append({"event": "operator_input_unavailable", "tool": getattr(request, "tool", "ask_user")})
        raise OperatorInputUnavailable("headless fixture has no operator input")


@pytest.fixture
def rig(tmp_path, monkeypatch):
    state, target = EngagementState(), Target(ORIGIN)
    state.initialize_target(ORIGIN)
    tool = HTTPTool(target, state)
    registry = Registry()
    registry.register(tool)
    operator = UnavailableOperator()
    prompter = YoloPrompter(operator, True)
    policy = ExecutionPolicy(state, tmp_path)
    policy.vetted_ips[ORIGIN] = ("127.0.0.1",)
    prompter.bind_execution_policy(policy)
    # Explicit finite operator constraint replaces implicit session autonomy.
    state.http_permissions.activate(ORIGIN, HTTPLimits(requests=1, rate=1, burst=1, concurrency=1))
    sent = []
    real = httpx.AsyncClient
    def respond(request):
        sent.append(request)
        return httpx.Response(200, content=b"offline fixture", request=request)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: real(transport=httpx.MockTransport(respond), **kwargs))
    return SimpleNamespace(state=state, target=target, registry=registry, operator=operator,
                           prompter=prompter, policy=policy, sent=sent, root=tmp_path)


async def test_existing_agent_run_and_yolo_need_no_operator_for_governed_http(rig):
    call = ToolCall("fixture-http", FunctionCall("http", '{"method":"GET","url":"/","phase":"recon"}'))
    client = FakeClient([
        ChatResponse(message=Message("assistant", "", tool_calls=[call]), finish_reason="tool_calls"),
        ChatResponse(message=Message("assistant", "fixture complete"), finish_reason="stop"),
    ])
    agent = Agent(AgentOptions(client=client, tools=rig.registry, skills=Skills(),
                              prompter=rig.prompter, target=rig.target, store=None,
                              engagement_state=rig.state, streaming_enabled=False, max_steps=3))
    await agent.run("Inspect the explicitly declared local fixture once.", FakeSignal(), lambda _: None)
    assert len(rig.sent) == 1 and not rig.operator.events
    assert not agent.workflow.candidates and not agent.workflow.evidence
    assert rig.policy.active == 0 and not rig.policy._active_receipts


async def test_finite_http_quota_is_not_bypassed_by_yolo_without_operator(rig):
    await rig.registry.execute("http", {"url": "/", "phase": "recon"}, None, rig.prompter)
    rig.prompter.set_yolo(False)
    rig.prompter.set_yolo(True)
    with pytest.raises(HTTPBlocked, match="budget exhausted"):
        await rig.registry.execute("http", {"url": "/second", "phase": "recon"}, None, rig.prompter)
    assert len(rig.sent) == 1 and not rig.operator.events


@pytest.mark.parametrize("url", ["http://localhost:8081/", "http://127.0.0.1:8082/", "https://127.0.0.1:8081/"])
async def test_exact_origin_is_not_extended_by_headless_style_operator(rig, url):
    with pytest.raises(OutOfScopeError):
        await rig.registry.execute("http", {"url": url, "phase": "recon"}, None, rig.prompter)
    assert not rig.sent and not rig.operator.events


async def test_forced_capture_review_reaches_unavailable_operator_and_grants_nothing(rig):
    before = dict(rig.state.http_permissions._capture_grants)
    with pytest.raises(OperatorInputUnavailable):
        await rig.prompter.ask(PermissionRequest(
            tool="http_capture_credentials", summary="fixture", detail="fixture",
            force_operator=True, no_session_cache=True, risk_tier="high-impact"))
    assert rig.operator.events == [{"event": "operator_input_unavailable", "tool": "http_capture_credentials"}]
    assert rig.state.http_permissions._capture_grants == before and not rig.sent


async def test_ask_user_is_not_answered_by_yolo(rig):
    rig.registry.register(AskUserTool(rig.operator))
    with pytest.raises(OperatorInputUnavailable):
        await rig.registry.execute("ask_user", {"questions": [{"question": "Which test identity is available?"}]}, None, rig.prompter)
    assert rig.operator.events == [{"event": "operator_input_unavailable", "tool": "ask_user"}]
    assert not rig.sent and rig.policy.active == 0
