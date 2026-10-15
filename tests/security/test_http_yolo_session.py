"""YOLO session limits through production admission, HTTP dispatch and journals."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.agent.agent import Agent, AgentOptions
from src.engagement.state import EngagementState
from src.llm.core.types import FunctionCall, ToolCall
from src.permission.network.grants import HTTPBlocked, HTTPLimits
from src.permission.permission import YoloPrompter
from src.permission.runtime.execution import default_execution_policy
from src.skills.registry import Registry as Skills
from src.target.target import Target
from src.tools.common.registry import Registry
from src.tools.http.http_tool import HTTPTool
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from tests.security.test_http_grants import ORIGIN, Operator, args, runtime


@pytest.fixture
def session_runtime(runtime, tmp_path):
    tool, registry, sent, responses = runtime
    now = [100.0]
    policy = default_execution_policy(tool.engagement, tmp_path)
    policy.clock = tool.permissions.clock = lambda: now[0]
    policy.vetted_ips[ORIGIN] = ("127.0.0.1",)
    operator = Operator()
    prompter = YoloPrompter(operator, False)
    prompter.bind_execution_policy(policy)
    agent = Agent(AgentOptions(
        client=FakeClient([]), tools=registry, skills=Skills(), prompter=prompter,
        store=None, target=tool.target, engagement_state=tool.engagement,
    ))
    return SimpleNamespace(tool=tool, registry=registry, sent=sent, responses=responses,
                           now=now, policy=policy, operator=operator, prompter=prompter, agent=agent)


@pytest.mark.parametrize("toggle", [False, True])
async def test_yolo_session_dispatch_exceeds_old_caps_without_losing_gates(session_runtime, toggle):
    env = session_runtime
    rights = env.tool.permissions
    assert not rights.grants
    env.prompter.set_yolo(True)
    original = next(iter(rights.grants.values()))
    assert original.activation == "yolo" and original.limits == HTTPLimits.session()
    assert original.expires_at is None

    call = ToolCall("yolo-session", FunctionCall("http", '{"url":"/session","phase":"recon"}'))
    for index in range(510):
        env.now[0] += 5
        if toggle and index == 255:
            action, _ = env.tool.prepare(args())
            receipt = await rights.authorize(action, env.prompter, None, lambda: env.tool.target.revision)
            env.prompter.set_yolo(False)
            assert not rights.grants
            env.prompter.set_yolo(True)
            with pytest.raises(HTTPBlocked, match="unknown/replayed"):
                rights.reserve(action, receipt, None, env.tool.target.revision)
        result = await env.agent.run_parsed_tool_call(call, env.agent.parse_tool_call(call), FakeSignal())
        assert result.status == "observation" and result.http_status == 200
        assert result.error_kind is None and not result.terminal_user_controlled_refusal

    current = next(iter(rights.grants.values()))
    assert current.limits == HTTPLimits.session() and current.expires_at is None
    assert rights._budgets[current.id].used == 510
    assert env.now[0] - original.created_at > 1200
    assert len(env.sent) == 510 and all(response.is_closed for response in env.responses)

    # Scheme, hostname and effective port remain independent scope boundaries.
    for url in ("https://juice.lab:3000/", "http://outside.lab:3000/", "http://juice.lab:3001/"):
        blocked = ToolCall("outside", FunctionCall("http", '{"url":"' + url + '","phase":"recon"}'))
        result = await env.agent.run_parsed_tool_call(blocked, env.agent.parse_tool_call(blocked), FakeSignal())
        assert result.error_kind == "scope_denied" and not result.terminal_user_controlled_refusal

    rights.revoke(current.id)
    env.prompter.set_yolo(False)
    env.prompter.set_yolo(True)
    result = await env.agent.run_parsed_tool_call(call, env.agent.parse_tool_call(call), FakeSignal())
    assert result.error_kind == "policy_block" and not result.terminal_user_controlled_refusal
    assert not rights.grants and len(env.sent) == 510 and not env.operator.requests
    assert not rights._inflight and not rights._receipts
    assert env.policy.active == 0 and not env.policy._active_receipts and not env.policy._receipts


async def test_yolo_session_keeps_short_one_shot_receipts(session_runtime):
    env = session_runtime
    rights = env.tool.permissions
    env.prompter.set_yolo(True)
    action, _ = env.tool.prepare(args())
    stale = await rights.authorize(action, env.prompter, None, lambda: env.tool.target.revision)
    env.now[0] += 61
    with pytest.raises(HTTPBlocked, match="expired"):
        rights.reserve(action, stale, None, env.tool.target.revision)
    fresh = await rights.authorize(action, env.prompter, None, lambda: env.tool.target.revision)
    reservation = rights.reserve(action, fresh, None, env.tool.target.revision)
    reservation.start()
    reservation.release()
    with pytest.raises(HTTPBlocked, match="unknown/replayed"):
        rights.reserve(action, fresh, None, env.tool.target.revision)
    assert not rights._inflight and not env.sent and not env.operator.requests


@pytest.mark.parametrize("enabled_before_restore", [False, True])
@pytest.mark.parametrize("limits", [
    HTTPLimits(),  # Legacy journals cannot distinguish the old default from operator limits.
    HTTPLimits(seconds=30, requests=None, rate=0.5, burst=1, concurrency=1,
               request_bytes=4096, response_bytes=16384),
    HTTPLimits(seconds=None, requests=7, rate=0.5, burst=1, concurrency=1,
               request_bytes=4096, response_bytes=16384),
    HTTPLimits.session(rate=0.5, burst=1, concurrency=1,
                       request_bytes=4096, response_bytes=16384),
])
async def test_yolo_restore_preserves_constraints_and_needs_current_activation(
    session_runtime, tmp_path, limits, enabled_before_restore,
):
    env = session_runtime
    rights = env.tool.permissions
    journal = tmp_path / "permissions" / "session.json"
    env.policy.load_journal(journal)
    rights.activate(ORIGIN, limits)
    await env.registry.execute("http", args(), None, env.prompter)
    assert len(env.sent) == 1 and not env.operator.requests

    state = EngagementState()
    state.initialize_target(ORIGIN)
    tool = HTTPTool(Target(ORIGIN), state)
    restored = default_execution_policy(state, tmp_path)
    restored.clock = state.http_permissions.clock = lambda: env.now[0]
    restored.vetted_ips[ORIGIN] = ("127.0.0.1",)
    prompter = YoloPrompter(env.operator, enabled_before_restore)
    prompter.bind_execution_policy(restored)
    restored.load_journal(journal)
    assert not restored._receipts and not state.http_permissions._receipts
    if not enabled_before_restore:
        assert not state.http_permissions.grants
        prompter.set_yolo(True)  # New operator activation, never journal-derived authority.

    grant = next(iter(state.http_permissions.grants.values()))
    assert grant.activation == "yolo" and grant.limits == limits
    budget = state.http_permissions._budgets[grant.id]
    assert budget.used == 1
    assert (grant.expires_at is None) == (limits.seconds is None)
    prompter.set_yolo(False)
    prompter.set_yolo(True)
    current = next(iter(state.http_permissions.grants.values()))
    assert current.limits == limits and current.expires_at == grant.expires_at
    assert state.http_permissions._budgets[current.id] is budget

    registry = Registry()
    registry.register(tool)
    if limits.requests is not None:
        budget.used = limits.requests
        with pytest.raises(HTTPBlocked, match="budget exhausted"):
            await registry.execute("http", args(), None, prompter)
    elif limits.seconds is not None:
        env.now[0] += limits.seconds + 1
        with pytest.raises(HTTPBlocked, match="expired"):
            await registry.execute("http", args(), None, prompter)
    else:
        env.now[0] += 1300
        result = await registry.execute("http", args(), None, prompter)
        assert getattr(result, "http_status", None) == 200 and budget.used == 2
    assert not env.operator.requests and not state.http_permissions._inflight
