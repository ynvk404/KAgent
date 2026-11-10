"""Real Agent/registry/review bridge; only DNS and socket I/O are replaced."""
import asyncio
import json
import re
from typing import Any, cast
from copy import deepcopy

import pytest

from src.tools.common.ask import TCP_SCOPE_ALLOW as ALLOW, TCP_SCOPE_DENY as DENY
from src.llm.core.types import FunctionCall, ToolCall
from src.permission.permission import Decision
from src.session.store import Store
from src.tools.common.ask import AskUserTool, FirstOptionPrompter
from src.ui.bridges.ask_bridge import BridgedAskPrompter
from src.ui.widgets.ask_modal import AskModal
from tests.helpers.agent_fakes import FakeSignal, ScriptedModel
from tests.runtime.test_terminal_input import tty  # noqa: F401
from tests.integration.test_discovery_service_policy import boundary, runtime_factory  # noqa: F401


@pytest.fixture
def review(runtime_factory):
    def make(**kwargs):
        runtime = runtime_factory(**kwargs)
        runtime.published = []
        runtime.question_shown = asyncio.Event()

        def publish(request):
            runtime.published.append(request)
            if request is not None:
                runtime.question_shown.set()

        runtime.bridge = BridgedAskPrompter(publish)
        runtime.registry.register(AskUserTool(
            runtime.bridge, tcp_scope_review=runtime.agent._ask_tcp_scope))
        return runtime
    return make


async def execute(runtime, name, args, signal=None, *, working=None):
    call = ToolCall(f"scope-{name}", FunctionCall(name, json.dumps(args)))
    if working is not None:
        batch = await runtime.agent.execute_tool_calls([call], signal or FakeSignal(), lambda _: None, working)
        return batch.calls[0].result
    return await runtime.agent.run_parsed_tool_call(call, runtime.agent.parse_tool_call(call), signal or FakeSignal())


async def missing(runtime, ports=(80, 443)):
    result = await execute(runtime, "service_discovery", {"ports": list(ports)})
    assert result.error_kind == "scope_denied"
    match = re.search(r"tcp_[0-9a-f]{32}", result.result)
    assert match, result.result
    return match.group()


def args(request_id):
    return {"questions": [{"question": "LLM text must not replace the runtime scope review",
                            "tcp_scope_request_id": request_id}]}


async def open_question(runtime, request_id, **kwargs):
    task = asyncio.create_task(execute(runtime, "ask_user", args(request_id), **kwargs))
    await asyncio.wait_for(runtime.question_shown.wait(), 2)
    request = runtime.published[-1]
    assert request is not None
    assert [option.label for option in request.question.options] == [ALLOW, DENY]
    assert "LLM text" not in request.question.question
    return task, request


@pytest.mark.parametrize("yolo", [False, True])
@pytest.mark.parametrize("choice", [ALLOW, DENY])
async def test_ab_exact_multiport_scope_and_separate_execution_review(review, boundary, yolo, choice):
    rt = review(yolo=yolo)
    rt.agent.update_tcp_scope("127.0.0.1", "80")
    original_http = rt.engagement.allowed_origins
    before = deepcopy(rt.workflow.to_dict())
    request_id = await missing(rt, (8080, 80, 443, 443, 8443))
    assert not boundary.connects
    task, request = await open_question(rt, request_id)
    assert "127.0.0.1" in request.question.question and "443,8443" in request.question.question
    assert not task.done()
    modal = AskModal(request)
    if choice == DENY:
        modal.handle_key("down")
    modal.handle_key("enter")
    result = await asyncio.wait_for(task, 2)
    payload = json.loads(result.result)["tcp_scope"]
    assert payload["ports"] == [443, 8443] and payload["execution_approved"] is False
    assert rt.engagement.allowed_origins == original_http
    assert rt.workflow.to_dict() == before and not boundary.connects
    assert rt.engagement.http_permissions._budgets[rt.grant.id].used == 0
    assert len(rt.operator.requests) == 1  # The original scan review precedes its DNS/scope check.

    if choice == ALLOW:
        assert payload["status"] == "updated" and payload["session_saved"]
        assert rt.engagement.tcp_allows("127.0.0.1", "80,443,8443")
        restored = rt.store.load()
        assert restored.engagement_state.tcp_allows("127.0.0.1", "443,8443")
        rt.operator.decision = Decision.DENY
        denied = await execute(rt, "service_discovery", {"ports": [443, 8443]})
        assert denied.error_kind == "permission_denied" and not boundary.connects
        assert len(rt.operator.requests) == 2
        rt.operator.decision = Decision.ALLOW_ONCE
        success = await execute(rt, "service_discovery", {"ports": [443, 8443]})
        assert success.status == "observation"
        assert sorted(boundary.connects) == [("127.0.0.1", 443), ("127.0.0.1", 8443)]
        assert len(rt.operator.requests) == 3
        for execution_request in rt.operator.requests:
            assert execution_request.force_operator and not execution_request.yolo_auto_approve
    else:
        assert payload["status"] == "denied"
        assert not rt.engagement.tcp_allows("127.0.0.1", "443")
        repeated = await execute(rt, "service_discovery", {"ports": [443, 8443]})
        assert repeated.error_kind == "scope_denied" and not boundary.connects
        assert "tcp_scope_request_id" not in repeated.result

    replay = await execute(rt, "ask_user", args(request_id))
    assert replay.error_kind == "policy_block"
    request.resolve(ALLOW)  # Late/duplicate UI callback cannot apply an old answer.
    assert len([q for q in rt.published if q is not None]) == 1


def mutate(runtime, change, tmp_path):
    if change == "target":
        runtime.agent.apply_target_base_url("http://other.test:8080")
    elif change == "target-away-back":
        runtime.target.set_base_url("http://other.test:8080")
        runtime.target.set_base_url("http://target.test:8080")
    elif change == "session":
        runtime.policy.session_id = "different-session"
    elif change == "store":
        runtime.agent.store = Store.new_with_id(tmp_path / "other-sessions", "another")
    elif change == "reset":
        runtime.engagement.http_permissions.reset()
    elif change == "scope":
        runtime.agent.update_tcp_scope("127.0.0.1", "80")
    elif change == "http-scope":
        runtime.agent.add_scope_origin("http://target.test:443")
    elif change == "yolo":
        runtime.prompter.set_yolo(False)
    elif change == "expired":
        expires = max(q.expires for q in runtime.agent.tcp_scope_requests.requests.values())
        runtime.policy.clock = lambda: expires + 1


@pytest.mark.parametrize("when", ["before", "during"])
@pytest.mark.parametrize("change", ["target", "target-away-back", "session", "store", "reset", "scope",
                                   "http-scope", "yolo", "expired"])
async def test_stale_reviews_never_grant_scope(review, boundary, tmp_path, change, when):
    rt = review(yolo=True)
    request_id = await missing(rt)
    if when == "before":
        mutate(rt, change, tmp_path)
        result = await execute(rt, "ask_user", args(request_id))
        assert not rt.published
    else:
        task, request = await open_question(rt, request_id)
        mutate(rt, change, tmp_path)
        request.resolve(ALLOW)
        result = await asyncio.wait_for(task, 2)
        assert rt.published[-1] is None
    assert result.error_kind == "policy_block"
    assert not rt.engagement.tcp_allows("127.0.0.1", "443") and not boundary.connects


@pytest.mark.parametrize("cancel", ["reject", "task", "signal"])
async def test_cancellation_closes_review_and_late_ui_answer_cannot_grant(review, boundary, cancel):
    rt = review(yolo=True)
    request_id = await missing(rt)
    signal = FakeSignal()
    task, request = await open_question(rt, request_id, signal=signal)
    if cancel == "task":
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    elif cancel == "signal":
        signal.aborted = True
        result = await asyncio.wait_for(task, 2)
        assert result.status == "cancelled"
    else:
        request.reject(Exception("cancelled"))
        result = await asyncio.wait_for(task, 2)
        assert result.status == "cancelled"
        assert json.loads(result.result)["tcp_scope"]["status"] == "cancelled"
    request.resolve(ALLOW)
    assert rt.published[-1] is None
    assert not rt.engagement.allowed_tcp and not boundary.connects
    replay = await execute(rt, "ask_user", args(request_id))
    assert replay.error_kind == "policy_block"


async def test_watchdog_expires_and_closes_unanswered_review(review):
    rt = review(yolo=True)
    request_id = await missing(rt)
    task, request = await open_question(rt, request_id)
    rt.policy.clock = lambda: rt.agent.tcp_scope_requests.requests[request_id].expires + 1
    result = await asyncio.wait_for(task, 2)
    assert result.error_kind == "policy_block" and rt.published[-1] is None
    request.resolve(ALLOW)
    assert not rt.engagement.allowed_tcp


@pytest.mark.parametrize("extra", [{"answer": "A"}, {"options": [{"label": ALLOW}, {"label": DENY}]},
                                   {"input_ids": ["invented"]}, {"address": "127.0.0.2"}])
async def test_model_cannot_supply_decision_destinations_or_scope_options(review, extra):
    rt = review(yolo=True)
    request_id = await missing(rt)
    forged = args(request_id)
    forged["questions"][0].update(extra)
    result = await execute(rt, "ask_user", forged)
    assert result.error_kind == "invalid_args" and not rt.published and not rt.engagement.allowed_tcp


async def test_unknown_request_and_synthetic_prompter_cannot_grant(review):
    rt = review(yolo=True)
    result = await execute(rt, "ask_user", args("tcp_" + "0" * 32))
    assert result.error_kind == "policy_block" and not rt.published
    request_id = await missing(rt)
    rt.agent.tools = rt.agent.tools.scoped_tool("ask_user", AskUserTool(
        FirstOptionPrompter(), tcp_scope_review=rt.agent._ask_tcp_scope))
    result = await execute(rt, "ask_user", args(request_id))
    assert result.error_kind == "input_unavailable" and not rt.engagement.allowed_tcp


async def test_a_returned_label_without_operator_callback_does_not_grant(review):
    class CachedAnswer:
        async def ask(self, q, signal=None):
            return ALLOW

        async def ask_tcp_scope(self, q, on_response, signal=None):
            return ALLOW  # No live operator event: this label grants nothing.

    rt = review(yolo=True)
    request_id = await missing(rt)
    rt.agent.tools = rt.agent.tools.scoped_tool("ask_user", AskUserTool(
        CachedAnswer(), tcp_scope_review=rt.agent._ask_tcp_scope))
    result = await execute(rt, "ask_user", args(request_id))
    assert result.error_kind == "input_unavailable" and not rt.engagement.allowed_tcp


async def test_parallel_and_replayed_reviews_do_not_reuse_approval(review):
    rt = review(yolo=True)
    request_id = await missing(rt)
    task, request = await open_question(rt, request_id)
    duplicate = await execute(rt, "ask_user", args(request_id))
    assert duplicate.error_kind == "policy_block"
    request.resolve(ALLOW)
    assert (await task).status == "success"
    rt.agent.update_tcp_scope("127.0.0.1", "80,443", remove=True)
    replay = await execute(rt, "ask_user", args(request_id))
    assert replay.error_kind == "policy_block" and not rt.engagement.allowed_tcp
    assert len([q for q in rt.published if q is not None]) == 1


async def test_scope_save_failure_reports_live_state_without_reusable_answer(review, monkeypatch):
    rt = review(yolo=True)
    request_id = await missing(rt)
    task, request = await open_question(rt, request_id)

    async def fail_save(**kwargs):
        raise OSError("fixture disk failure")

    monkeypatch.setattr(rt.agent, "save", fail_save)
    request.resolve(ALLOW)
    payload = json.loads((await task).result)["tcp_scope"]
    assert payload["status"] == "updated" and payload["session_saved"] is False
    assert rt.engagement.tcp_allows("127.0.0.1", "80,443")
    assert (await execute(rt, "ask_user", args(request_id))).error_kind == "policy_block"


@pytest.mark.parametrize("ports", [None, [8080], [80, 443]])
async def test_default_and_already_scoped_service_calls_do_not_create_reviews(review, ports):
    rt = review(yolo=True)
    rt.agent.update_tcp_scope("127.0.0.1", "80,443")
    result = await execute(rt, "service_discovery", {} if ports is None else {"ports": ports})
    assert result.status == "observation"
    assert not rt.agent.tcp_scope_requests.requests and not rt.published


async def test_permission_denial_does_not_create_scope_request(review):
    rt = review(yolo=True)
    rt.operator.decision = Decision.DENY
    result = await execute(rt, "service_discovery", {"ports": [443]})
    assert result.error_kind == "permission_denied" and not rt.agent.tcp_scope_requests.requests


@pytest.mark.parametrize("ports", [[443, 80], [443], [22, 443]])
async def test_declined_ports_cannot_be_reasked_by_reordering_or_splitting(review, boundary, ports):
    rt = review(yolo=True)
    request_id = await missing(rt)
    task, question = await open_question(rt, request_id)
    question.resolve(DENY)
    assert json.loads((await task).result)["tcp_scope"]["status"] == "denied"
    again = await execute(rt, "service_discovery", {"ports": ports})
    assert again.error_kind == "scope_denied" and "tcp_scope_request_id" not in again.result
    assert not boundary.connects and not rt.engagement.allowed_tcp


async def test_reordered_pending_ports_share_one_scope_review(review):
    rt = review(yolo=True)
    first = await missing(rt, (443, 80))
    second = await missing(rt, (80, 443, 80))
    assert first == second


async def test_dns_change_after_scope_update_requires_another_exact_ip_review(review, boundary, monkeypatch):
    import socket

    rt = review(yolo=True)
    request_id = await missing(rt, (443,))
    task, question = await open_question(rt, request_id)
    question.resolve(ALLOW)
    assert json.loads((await task).result)["tcp_scope"]["status"] == "updated"
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.2", 0))])
    new_request = await missing(rt, (443,))
    assert new_request != request_id
    assert rt.agent.tcp_scope_requests.requests[new_request].address == "127.0.0.2"
    assert not rt.engagement.tcp_allows("127.0.0.2", "443") and not boundary.connects


async def test_startup_binds_ask_to_the_agent_without_mutating_shared_tool(review):
    from src.agent.agent import Agent, AgentOptions

    rt = review(yolo=True)
    old_request = await missing(rt)
    shared_ask = rt.registry.get("ask_user")
    new_agent = Agent(AgentOptions(
        client=rt.client, tools=rt.registry, skills=rt.skills, prompter=rt.prompter,
        store=rt.store, target=rt.target, workflow=rt.workflow, engagement_state=rt.engagement))
    ask = new_agent.tools.get("ask_user")
    assert type(ask) is AskUserTool and ask is not shared_ask
    assert ask.tcp_scope_review == new_agent._ask_tcp_scope
    assert rt.registry.get("ask_user") is shared_ask
    rt.agent = new_agent
    replay = await execute(rt, "ask_user", args(old_request))
    assert replay.error_kind == "policy_block" and not rt.published
    new_request = await missing(rt)
    task, question = await open_question(rt, new_request)
    question.resolve(ALLOW)
    assert json.loads((await task).result)["tcp_scope"]["status"] == "updated"


async def test_context_change_during_actual_service_failure_does_not_mint_review(review, monkeypatch):
    rt = review(yolo=True)
    resolve = rt.service._resolve_execution_addresses

    async def change_session(*values):
        result = await resolve(*values)
        rt.policy.session_id = "replaced-during-DNS"
        return result

    monkeypatch.setattr(rt.service, "_resolve_execution_addresses", change_session)
    result = await execute(rt, "service_discovery", {"ports": [443]})
    assert result.error_kind == "scope_denied"
    assert "tcp_scope_request_id" not in result.result and not rt.agent.tcp_scope_requests.requests


async def test_asyncio_signal_set_before_ui_callback_cannot_grant(review):
    rt = review(yolo=True)
    request_id = await missing(rt)
    signal = asyncio.Event()
    tool = rt.agent.tools.get("ask_user")
    task = asyncio.create_task(rt.agent._ask_tcp_scope(request_id, tool, signal))
    await asyncio.wait_for(rt.question_shown.wait(), 2)
    signal.set()
    rt.published[-1].resolve(ALLOW)
    result = await task
    assert json.loads(result)["tcp_scope"]["status"] == "cancelled"
    assert not rt.engagement.allowed_tcp


@pytest.mark.parametrize("answer,expected", [(b"1\n", True), (b"2\n", False)])
async def test_real_terminal_selection_updates_only_tcp_scope(review, tty, answer, expected):
    import os
    from src.cli.terminal_input import TerminalInput
    from tests.runtime.test_terminal_input import wait_reading

    rt = review(yolo=True)
    request_id = await missing(rt)
    frontend = TerminalInput(lambda: ())
    bridge = BridgedAskPrompter(frontend.publish_ask)
    rt.agent.tools = rt.agent.tools.scoped_tool("ask_user", AskUserTool(
        bridge, tcp_scope_review=rt.agent._ask_tcp_scope))
    task = asyncio.create_task(execute(rt, "ask_user", args(request_id)))
    master, slave, _ = tty
    try:
        await wait_reading(slave)
        os.write(master, answer)
        result = await asyncio.wait_for(task, 2)
        assert json.loads(result.result)["tcp_scope"]["status"] == ("updated" if expected else "denied")
        assert rt.engagement.tcp_allows("127.0.0.1", "80,443") is expected
        assert len(rt.operator.requests) == 1
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await frontend.close()


async def test_headless_tcp_scope_question_needs_operator_and_never_grants(review):
    from src.cli.headless import UnavailableInput

    rt = review(yolo=True)
    request_id = await missing(rt)
    headless = UnavailableInput()
    rt.agent.tools = rt.agent.tools.scoped_tool("ask_user", AskUserTool(
        cast(Any, headless), tcp_scope_review=rt.agent._ask_tcp_scope))
    result = await execute(rt, "ask_user", args(request_id))
    assert result.error_kind == "input_unavailable"
    assert headless.needed.is_set() and not rt.engagement.allowed_tcp


async def test_agent_reset_invalidates_the_pending_request_and_late_callback(review):
    rt = review(yolo=True)
    request_id = await missing(rt)
    task, question = await open_question(rt, request_id)
    await rt.agent.reset()
    question.resolve(ALLOW)
    assert (await asyncio.wait_for(task, 2)).error_kind == "policy_block"
    assert not rt.engagement.allowed_tcp
    assert (await execute(rt, "ask_user", args(request_id))).error_kind == "policy_block"


async def test_ipv6_scope_uses_only_the_resolved_numeric_address(review, boundary, monkeypatch):
    import socket

    rt = review(yolo=True)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: [
        (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", 0, 0, 0))])
    request_id = await missing(rt, (443,))
    task, question = await open_question(rt, request_id)
    question.resolve(ALLOW)
    payload = json.loads((await task).result)["tcp_scope"]
    assert payload["address"] == "::1" and payload["ports"] == [443]
    assert rt.engagement.tcp_allows("::1", "443")
    assert not rt.engagement.tcp_allows("127.0.0.1", "443") and not boundary.connects


async def test_full_agent_turn_refreshes_scope_and_retries_through_registry(review, boundary):
    rt = review(yolo=True, coverage="no-workflow")

    def script():
        denied = yield "service_discovery", {"ports": [80, 443]}
        matched = re.search(r"tcp_[0-9a-f]{32}", denied)
        assert matched is not None
        request_id = matched.group()
        answered = yield "ask_user", args(request_id)
        assert json.loads(answered)["tcp_scope"]["status"] == "updated"
        completed = yield "service_discovery", {"ports": [80, 443]}
        assert json.loads(completed)["completed_ports"] == 2

    client = ScriptedModel(script(), prefix="tcp-scope")
    rt.agent.client = client
    snapshots = []
    chat = client.chat

    async def capture(request, signal=None):
        snapshots.append(deepcopy(request.messages))
        return await chat(request, signal)

    client.chat = capture
    task = asyncio.create_task(rt.agent.run("Check the active target TCP ports 80 and 443.",
                                          signal=FakeSignal(), emit=lambda _: None))
    await asyncio.wait_for(rt.question_shown.wait(), 3)
    rt.published[-1].resolve(ALLOW)
    await asyncio.wait_for(task, 5)
    assert not client.errors
    assert [name for name, _ in client.calls] == ["service_discovery", "ask_user", "service_discovery"]
    assert "Explicit TCP scope" in snapshots[2][0].content
    assert "127.0.0.1 ports 80,443" in snapshots[2][0].content
    assert len(rt.operator.requests) == 2  # Scope review is separate from both execution reviews.
    assert sorted(boundary.connects) == [("127.0.0.1", 80), ("127.0.0.1", 443)]
