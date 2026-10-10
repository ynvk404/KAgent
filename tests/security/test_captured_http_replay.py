"""Offline captured-credential authority, isolation and dispatch regressions."""
import asyncio
import base64
import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest

from src.browser.store import CaptureStore
from src.engagement.state import EngagementState
from src.permission.network.grants import HTTPBlocked, HTTPLimits
from src.permission.permission import Decision, YoloPrompter
from src.permission.runtime.execution import default_execution_policy
from src.target.target import Target
from src.tools.common.registry import Registry
from src.tools.http.http_tool import HTTPTool
from src.workflow.state import Candidate, WorkflowState

ORIGIN = "http://127.0.0.1:3000"
REAL_CLIENT = httpx.AsyncClient


def assert_pending(result):
    assert result.status == 'error' and result.error_kind == 'permission_denied'
    assert result.startswith('pending:') and result.http_status is None


@pytest.fixture
def replay(tmp_path, monkeypatch):
    engagement, target = EngagementState(), Target(ORIGIN)
    engagement.initialize_target(ORIGIN)
    workflow, capture = WorkflowState(), CaptureStore()
    tool = HTTPTool(target, engagement, workflow, capture)
    registry = Registry()
    registry.register(tool)
    policy = default_execution_policy(engagement, tmp_path)
    control = SimpleNamespace(questions=[], sent=[], review=None, response=None, deny=False)

    class Operator:
        async def ask(self, request, signal=None):
            control.questions.append(request)
            if control.review:
                await control.review(request)
            return Decision.DENY if control.deny else Decision.ALLOW_ONCE

    prompter = YoloPrompter(Operator(), True)
    prompter.bind_execution_policy(policy)

    async def transport(request):
        control.sent.append(request)
        if control.response:
            return await control.response(request)
        return httpx.Response(200, content=b"fixture", request=request)

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(transport), **kw))

    async def private_gate(*args, **kwargs):
        return ""

    monkeypatch.setattr("src.tools.http.http_tool.gate_private_request", private_gate)

    def baseline(headers=None, identity=None, id_="capture", task=False, origin=ORIGIN, cls="sql-injection"):
        headers = headers or {}
        payload = {"kind": "burp", "id": id_, "method": "POST", "url": origin + "/api",
                   "requestHeaders": [{"name": "Content-Type", "value": "application/json"},
                                      *({"name": k, "value": v} for k, v in headers.items())],
                   "requestBody": '{"q":"old","keep":1}'}
        if identity:
            payload["authContextRef"] = identity
        if task:
            body = payload["requestBody"].encode()
            head = ("POST /api HTTP/1.1\r\nHost: " + httpx.URL(origin).netloc.decode() + "\r\n"
                    + "\r\n".join(h["name"] + ": " + h["value"] for h in payload["requestHeaders"])
                    + "\r\nContent-Length: " + str(len(body)) + "\r\n\r\n").encode()
            payload["rawRequestB64"] = base64.b64encode(head + body).decode()
            payload["action"] = "scan"
            ref = capture.ingest_burp_task(payload)["baseline_request_ref"]
        else:
            ref = capture.ingest(payload)["baseline_request_ref"]
        candidate, _ = workflow.add_candidate(Candidate(candidate_class=cls, target=origin,
            endpoint="/api", method="POST", parameter="q", location="json", content_type="application/json",
            baseline_request_ref=ref, auth_context_ref=identity))
        return candidate, {"phase": "validation", "candidate_id": candidate.id}

    async def send(args):
        return await registry.execute("http", args, None, prompter)

    return SimpleNamespace(tool=tool, registry=registry, policy=policy, prompter=prompter,
                           control=control, baseline=baseline, send=send, capture=capture)


@pytest.mark.parametrize("headers", [{}, {"Cookie": "sid=capture-cookie"},
    {"Authorization": "Bearer capture-token"},
    {"Cookie": "sid=capture-cookie", "Authorization": "Bearer capture-token"},
    {"X-API-Key": "capture-api-key"}])
@pytest.mark.parametrize("cls", ["sql-injection", "cross-site-scripting"])
async def test_baseline_and_mutations_use_capture_without_context(replay, headers, cls):
    _, args = replay.baseline(headers, cls=cls)
    for extra in ({}, {"mutation_value": "first"}, {"mutation_value": "second"}):
        result = await replay.send(args | extra)
        assert result.http_status == 200
    assert len(replay.control.sent) == 3
    for request in replay.control.sent:
        for key, value in headers.items():
            assert request.headers[key] == value
    assert [q.tool for q in replay.control.questions] == (["http_capture_credentials"] if headers else [])
    if headers:
        question = replay.control.questions[0]
        assert question.force_operator and question.no_session_cache
        assert "capture-cookie" not in question.detail and "capture-token" not in question.detail
    assert not replay.tool.context_store._cookies and not replay.tool.context_store._authorization
    assert not replay.tool.permissions._receipts and not replay.tool.permissions._inflight


async def test_yolo_off_retains_exact_http_approval(replay):
    replay.prompter.set_yolo(False)
    _, args = replay.baseline({"Cookie": "sid=capture-cookie"})
    await replay.send(args | {"mutation_value": "first"})
    await replay.send(args | {"mutation_value": "second"})
    assert [q.tool for q in replay.control.questions] == ["http_capture_credentials", "http", "http"]


async def test_manual_http_grant_and_yolo_do_not_authorize_unreviewed_credentials(replay):
    replay.tool.permissions.activate(ORIGIN, HTTPLimits())
    _, args = replay.baseline({"Authorization": "Bearer never-approved"})
    replay.control.deny = True
    result = await replay.send(args | {"mutation_value": "first"})
    assert_pending(result)
    assert 'declined captured credential' in result
    assert not replay.control.sent and not replay.tool.permissions._capture_grants
    assert len(replay.control.questions) == 1
    replay.control.deny = False
    await replay.send(args | {"mutation_value": "first"})
    assert len(replay.control.sent) == 1  # A later invocation can obtain operator review.


async def test_capture_response_and_runtime_context_are_isolated(replay):
    identity = "user"
    native = httpx.Request("GET", ORIGIN + "/api", headers={"Authorization": "Bearer native-token"})
    replay.tool.context_store.extract(native, httpx.Response(200, headers={"Set-Cookie": "sid=native-cookie; Path=/"}, request=native), identity)
    _, args = replay.baseline({"Authorization": "Bearer capture-token"}, identity)

    async def respond(request):
        return httpx.Response(302, headers={"Location": "/next", "Set-Cookie": "sid=rotated-cookie; Path=/"}, request=request)

    replay.control.response = respond
    result = await replay.send(args | {"mutation_value": "first", "max_redirects": 3})
    assert len(replay.control.sent) == 1
    assert replay.control.sent[0].headers["authorization"] == "Bearer capture-token"
    assert "cookie" not in replay.control.sent[0].headers
    assert "captured redirect not followed" in result
    assert replay.tool.context_store.authorization_for(native, identity) == "Bearer native-token"
    assert replay.tool.context_store.cookie_for(native, identity) == "sid=native-cookie"
    replay.control.response = None
    await replay.send({"url": "/api", "auth_context_ref": identity, "phase": "recon"})
    assert replay.control.sent[-1].headers["authorization"] == "Bearer native-token"
    assert replay.control.sent[-1].headers["cookie"] == "sid=native-cookie"


@pytest.mark.parametrize("headers", [{"Cookie": "sid=capture-cookie"}, {"Authorization": "Bearer capture-token"}, {}])
@pytest.mark.parametrize("location", ["/next", "http://outside.test/next"])
async def test_capture_redirect_never_dispatches_followup(replay, headers, location):
    _, args = replay.baseline(headers)

    async def respond(request):
        return httpx.Response(307, headers={"Location": location}, request=request)

    replay.control.response = respond
    result = await replay.send(args | {"max_redirects": 3})
    assert len(replay.control.sent) == 1 and "captured redirect not followed" in result


@pytest.mark.parametrize("change", ["clear", "evict", "cookie", "body", "candidate-binding", "identity", "reset", "scope", "target"])
@pytest.mark.parametrize("stage", ["review", "scheduler"])
async def test_changes_while_waiting_cannot_dispatch_old_receipt(replay, monkeypatch, change, stage):
    candidate, args = replay.baseline({"Cookie": "sid=capture-cookie"})

    def mutate():
        row = replay.capture.get_request("burp:capture")
        assert row is not None
        if change == "clear":
            replay.capture.clear()
        elif change == "evict":
            replay.capture.requests.pop(row.id)
        elif change == "cookie":
            row.request_headers[-1].value = "sid=unapproved-cookie"
        elif change == "body":
            row.request_body = '{"q":"changed"}'
        elif change == "candidate-binding":
            other, _ = replay.baseline({"Cookie": "sid=other-cookie"}, id_="other")
            candidate.baseline_request_ref = other.baseline_request_ref
        elif change == "identity":
            candidate.auth_context_ref = "different-principal"
        elif change == "reset":
            replay.tool.permissions.reset()
        elif change == "scope":
            replay.tool.engagement.add_origin("http://other.test")
        else:
            replay.tool.target.set_base_url("http://different.test")

    if stage == "review":
        async def review(_):
            mutate()
        replay.control.review = review
    else:
        reserve = replay.tool.permissions.reserve_when_ready
        async def wait_then_reserve(*positional):
            mutate()
            return await reserve(*positional)
        monkeypatch.setattr(replay.tool.permissions, "reserve_when_ready", wait_then_reserve)
    if change in {'reset', 'scope', 'target'}:
        with pytest.raises(PermissionError):
            await replay.send(args | {"mutation_value": "first"})
    else:
        assert_pending(await replay.send(args | {"mutation_value": "first"}))
    assert not replay.control.sent
    assert not replay.tool.permissions._receipts and not replay.tool.permissions._inflight


@pytest.mark.parametrize("change", ["request", "capture-revoke", "http-revoke", "expire", "exhaust"])
async def test_authorized_request_still_rechecks_every_gate(replay, monkeypatch, change):
    candidate, args = replay.baseline({"Authorization": "Bearer approved-token"})
    await replay.send(args | {"mutation_value": "first"})
    authorize = replay.tool.permissions.authorize

    async def intercept(action, *rest):
        receipt = await authorize(action, *rest)
        if change == "capture-revoke":
            replay.tool.permissions.revoke_capture(candidate.baseline_request_ref)
        elif change == "http-revoke":
            grant = next(iter(replay.tool.permissions.grants.values()))
            replay.tool.permissions.revoke(grant.id)
        elif change in {"expire", "exhaust"}:
            budget = replay.tool.permissions._capture_grants[action.capture_source]
            if change == "expire":
                budget.expires_at = 0
            else:
                budget.used = budget.limits.requests
        return receipt

    if change == "request":
        dispatch = replay.tool._dispatch
        async def change_request(action, request, *rest):
            request.headers["authorization"] = "Bearer changed-after-receipt"
            return await dispatch(action, request, *rest)
        monkeypatch.setattr(replay.tool, "_dispatch", change_request)
    else:
        monkeypatch.setattr(replay.tool.permissions, "authorize", intercept)
    if change in {'capture-revoke', 'http-revoke'}:
        with pytest.raises(PermissionError):
            await replay.send(args | {"mutation_value": "second"})
    else:
        assert_pending(await replay.send(args | {"mutation_value": "second"}))
    assert len(replay.control.sent) == 1
    assert not replay.tool.permissions._inflight


async def test_capture_fingerprint_and_effective_digest_use_real_credentials(replay):
    first, args = replay.baseline({"Cookie": "sid=first-cookie"})
    second, other = replay.baseline({"Cookie": "sid=second-cookie"}, id_="second")
    action, _ = replay.tool.prepare(args | {"mutation_value": "payload"})
    variant, _ = replay.tool.prepare(args | {"mutation_value": "other-payload"})
    other_action, _ = replay.tool.prepare(other | {"mutation_value": "payload"})
    assert first.baseline_request_ref != second.baseline_request_ref
    assert action.capture_source == variant.capture_source
    assert action.digest != variant.digest and action.digest != other_action.digest
    altered = replace(action, headers=tuple((k, b"sid=changed" if k.lower() == b"cookie" else v) for k, v in action.headers))
    assert action.digest != altered.digest
    await replay.send(args)
    assert not replay.tool.permissions._capture_grants.get(other_action.capture_source)
    await replay.send(other)
    assert len(replay.control.questions) == 2


async def test_new_capture_credential_requires_review_and_preserves_original(replay):
    _, args = replay.baseline({"Cookie": "sid=first-cookie"})
    await replay.send(args | {"mutation_value": "first"})
    _, changed = replay.baseline({"Cookie": "sid=rotated-cookie"})
    replay.control.deny = True
    assert_pending(await replay.send(changed | {"mutation_value": "second"}))
    assert len(replay.control.sent) == 1
    replay.control.deny = False
    await replay.send(args | {"mutation_value": "second"})
    assert replay.control.sent[-1].headers["cookie"] == "sid=first-cookie"
    await replay.send(changed | {"mutation_value": "second"})
    assert replay.control.sent[-1].headers["cookie"] == "sid=rotated-cookie"
    assert len(replay.control.questions) == 3


@pytest.mark.parametrize("identity", [None, "user"])
async def test_burp_task_raw_baseline_has_safe_identity_binding(replay, identity):
    _, args = replay.baseline({"Cookie": "sid=task-cookie"}, identity, task=True)
    result = await replay.send(args | {"mutation_value": "first"})
    assert result.http_status == 200 and replay.control.sent[0].headers["cookie"] == "sid=task-cookie"
    assert "task-cookie" not in result
    candidate = replay.tool.workflow.candidates[args["candidate_id"]]
    candidate.baseline_request_ref = "burp-task-1"
    with pytest.raises(ValueError, match="unavailable or unbound"):
        replay.tool.prepare(args)


async def test_capture_cannot_move_origin_or_identity(replay):
    _, args = replay.baseline({"Cookie": "sid=capture-cookie"}, "user")
    for extra in ({"auth_context_ref": "admin"}, {"url": "http://outside.test/api"}):
        with pytest.raises(ValueError):
            replay.tool.prepare(args | extra)
    _, outside = replay.baseline({"Cookie": "sid=capture-cookie"}, origin="http://outside.test")
    with pytest.raises(PermissionError):
        await replay.send(outside)
    assert not replay.control.sent


async def test_rate_and_concurrency_wait_without_repeated_capture_dialog(replay):
    replay.tool.permissions.activate(ORIGIN, HTTPLimits(rate=20, burst=1, concurrency=1))
    _, args = replay.baseline({"Cookie": "sid=capture-cookie"})
    entered, release = asyncio.Event(), asyncio.Event()

    async def respond(request):
        if not entered.is_set():
            entered.set()
            await release.wait()
        return httpx.Response(200, content=b"fixture", request=request)

    replay.control.response = respond
    first = asyncio.create_task(replay.send(args | {"mutation_value": "first"}))
    await asyncio.wait_for(entered.wait(), 2)
    second = asyncio.create_task(replay.send(args | {"mutation_value": "second"}))
    await asyncio.sleep(0.1)
    assert len(replay.control.sent) == 1
    release.set()
    await asyncio.wait_for(asyncio.gather(first, second), 2)
    assert len(replay.control.sent) == 2 and len(replay.control.questions) == 1


async def test_cancelled_capture_review_leaves_no_authority(replay):
    _, args = replay.baseline({"Cookie": "sid=capture-cookie"})
    entered = asyncio.Event()
    async def review(_):
        entered.set()
        await asyncio.Event().wait()
    replay.control.review = review
    task = asyncio.create_task(replay.send(args))
    await asyncio.wait_for(entered.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not replay.tool.permissions._capture_pending and not replay.tool.permissions._capture_grants
    assert not replay.control.sent and replay.policy.active == 0


async def test_credential_echo_is_redacted_in_output_evidence_and_session(replay, tmp_path):
    from src.session.store import Store
    _, args = replay.baseline({"Cookie": "sid=capture-cookie", "Authorization": "Bearer capture-token"})
    body = b"echo capture-cookie capture-token"
    async def respond(request):
        return httpx.Response(200, content=body, headers={"Set-Cookie": "sid=new-secret-cookie; Path=/"}, request=request)
    replay.control.response = respond
    replay.policy.observations.attach_storage(tmp_path / "observations.json")
    output = await replay.send(args | {"mutation_value": "first"})
    observation = next(iter(replay.policy.observations._items.values()))
    assert observation.response_hash == hashlib.sha256(body).hexdigest()
    assert observation.source_details["baseline_request_ref"]
    session = Store.new_with_id(tmp_path, "capture-session")
    await session.save([], workflow=replay.tool.workflow, target=replay.tool.target)
    retained = output + observation.body.decode() + json.dumps(observation.source_details)
    retained += session.path.read_text() + (tmp_path / "observations.json").read_text()
    for secret in ("capture-cookie", "capture-token", "new-secret-cookie"):
        assert secret not in retained


async def test_imported_burp_response_without_completeness_is_not_terminal_evidence(replay):
    candidate, _ = replay.baseline({"Cookie": "sid=capture-cookie"})
    row = replay.capture.get_request("burp:capture")
    row.status, row.response_body = 200, "fixture response"
    observations = replay.policy.observations
    ref = observations.import_capture(row, owner={"candidate_id": candidate.id})
    item = observations._items[ref]
    assert not item.complete and item.truncated
    assert item.source_kind == "imported-capture"
    assert item.source_details["completeness"] == "unknown"
    assert item.source_details["receipt_id"] is None and item.source_details["original_owner"] is None


@pytest.mark.parametrize("limit", ["expiry", "quota", "bytes"])
async def test_http_limits_remain_enforced_for_capture(replay, limit):
    _, args = replay.baseline({"Cookie": "sid=capture-cookie"})
    await replay.send(args)
    grant = next(iter(replay.tool.permissions.grants.values()))
    budget = replay.tool.permissions._budgets[grant.id]
    if limit == "expiry":
        budget.expires_at = 0
    elif limit == "quota":
        budget.used = budget.limits.requests
    else:
        budget.limits = replace(budget.limits, request_bytes=1)
    with pytest.raises(HTTPBlocked):
        await replay.send(args | {"mutation_value": "second"})
    assert len(replay.control.sent) == 1 and len(replay.control.questions) == 1


async def test_expired_capture_can_be_reviewed_after_explicit_operator_retry(replay):
    _, args = replay.baseline({"Cookie": "sid=capture-cookie"})
    await replay.send(args)
    budget = next(iter(replay.tool.permissions._capture_grants.values()))
    budget.expires_at = 0
    assert_pending(await replay.send(args))
    replay.tool.permissions.retry(ORIGIN)
    await replay.send(args)
    assert len(replay.control.questions) == 2 and len(replay.control.sent) == 2


async def test_last_permitted_capture_request_is_sent_once(replay):
    replay.tool.permissions.activate(ORIGIN, HTTPLimits(requests=1))
    _, args = replay.baseline({"Cookie": "sid=capture-cookie"})
    await replay.send(args)
    assert len(replay.control.sent) == 1
    assert next(iter(replay.tool.permissions._capture_grants.values())).used == 1
    with pytest.raises(HTTPBlocked):
        await replay.send(args | {"mutation_value": "second"})
    assert len(replay.control.sent) == 1


async def test_private_gate_decline_still_blocks_captured_replay(replay, monkeypatch):
    from src.tools.http.private_host import PrivateHostDeclined
    _, args = replay.baseline({"Cookie": "sid=capture-cookie"})
    async def decline(*args, **kwargs):
        raise PrivateHostDeclined("fixture private-host denied")
    monkeypatch.setattr("src.tools.http.http_tool.gate_private_request", decline)
    with pytest.raises(PrivateHostDeclined):
        await replay.send(args)
    with pytest.raises(HTTPBlocked, match="private-host permission declined"):
        await replay.send(args)
    assert not replay.control.sent and not replay.tool.permissions._receipts


async def test_capture_denial_suppresses_other_payload_reviews_in_same_turn(replay):
    from src.permission.runtime.invocations import review_turn
    _, args = replay.baseline({"Cookie": "sid=capture-cookie"})
    replay.control.deny = True
    with review_turn():
        for value in ("first", "second", "third"):
            assert_pending(await replay.send(args | {"mutation_value": value}))
    assert len(replay.control.questions) == 1 and not replay.control.sent


def test_permission_preview_hides_credential_echoes_and_keeps_digest(replay):
    _, args = replay.baseline({"Authorization": "Bearer fixture-private-token"})
    action, _ = replay.tool.prepare(args | {"mutation_value": "fixture-private-token"})
    before = action.digest
    assert "fixture-private-token" not in action.preview()
    assert "fixture-private-token" not in replay.tool.summarize(args | {"mutation_value": "fixture-private-token"})['detail']
    assert action.digest == before and b"fixture-private-token" in action.body


async def test_short_capture_cookie_redaction_keeps_evidence_ids_retrievable(replay):
    candidate, args = replay.baseline({"Cookie": "sid=a"})
    async def respond(request):
        return httpx.Response(200, content=b'echo a', request=request)
    replay.control.response = respond
    output = await replay.send(args)
    line = next(line for line in output.splitlines() if line.startswith('Runtime HTTP evidence '))
    envelope = json.loads(line.split(': ', 1)[1])
    observation = replay.policy.observations._items[envelope['observation_id']]
    assert observation.body == b'echo [REDACTED]'
    assert observation.source_details['baseline_request_ref'] == candidate.baseline_request_ref
    assert f'[runtime observation: {observation.id}]' in output


async def test_capture_pending_is_not_a_terminal_agent_refusal(replay):
    from src.agent.agent import Agent, AgentOptions
    from src.llm.core.types import FunctionCall, ToolCall
    from src.skills.registry import Registry as Skills
    from tests.helpers.agent_fakes import FakeClient, FakeSignal
    candidate, args = replay.baseline({'Cookie': 'sid=capture-cookie'})
    agent = Agent(AgentOptions(client=FakeClient([]), tools=replay.registry, skills=Skills(),
        prompter=replay.prompter, store=None, target=replay.tool.target,
        workflow=replay.tool.workflow, engagement_state=replay.tool.engagement))
    replay.control.deny = True
    call = ToolCall(id='capture-review', function=FunctionCall(name='http', arguments=json.dumps(args)))
    result = await agent.run_parsed_tool_call(call, agent.parse_tool_call(call), FakeSignal())
    assert result.status == 'error' and result.error_kind == 'permission_denied'
    assert not result.terminal_user_controlled_refusal and not replay.control.sent
    assert agent.workflow.latest_result(candidate.id) is None
    replay.control.deny = False
    retry = await agent.run_parsed_tool_call(call, agent.parse_tool_call(call), FakeSignal())
    assert retry.status == 'observation' and retry.http_status == 200
    assert len(replay.control.sent) == 1
