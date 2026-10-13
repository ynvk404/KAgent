"""Readback uses existing captured traffic and the production admission gates."""
import json
from dataclasses import replace

import pytest

from src.agent.agent import Agent, AgentOptions
from src.permission.permission import Decision
from src.permission.permission import UserControlledRefusal
from src.engagement.state import OutOfScopeError
from src.workflow.assessment import digest, source_row
from src.llm.core.types import ToolCall, FunctionCall, Message
from src.agent.agent import ToolCallResult
from src.workflow.state import WorkflowState, WorkflowObjective
import hashlib
from tests.helpers.agent_fakes import FakeClient
from tests.security.test_agent_assessment import setup
from tests.security.test_execution_policy import runtime  # noqa: F401


async def reader_runtime(runtime, tmp_path):
    state, candidate, workflow, args, oid = await setup(runtime, tmp_path)
    registry, prompter, policy, operator, sent, _, target = runtime
    assert workflow.skills is not None
    agent = Agent(AgentOptions(client=FakeClient([]), tools=registry, skills=workflow.skills,
        prompter=prompter, store=None, target=target, workflow=state,
        engagement_state=policy.engagement, streaming_enabled=False))
    agent.active_skills.add("cross-site-scripting")
    return agent, state, candidate, args, oid


async def test_reader_returns_bounded_existing_body_without_http(runtime, tmp_path):
    agent, state, candidate, _, oid = await reader_runtime(runtime, tmp_path)
    assert agent.tools.get("read_http_observation") is not None
    _, prompter, policy, _, sent, *_ = runtime
    before = len(sent)
    args = {"observation_id": oid, "start_char": 0, "max_chars": 2000}
    assert agent.is_tool_allowed("read_http_observation", args).ok
    output = await agent.tools.execute("read_http_observation", args, None, prompter)
    header, body = output.split("\n", 1)
    row = json.loads(header)
    assert body == "fixture" and row["next_start_char"] is None
    assert row["observation_id"] == oid and len(output) <= 2000
    assert len(sent) == before and not state.validation_results
    assert policy.observations._items[oid].candidate_id == candidate.id


@pytest.mark.parametrize("fault", ["integrity", "owner", "epoch", "scope", "http-revoked", "unowned", "wrong-id"])
async def test_reader_refuses_invalid_source_without_network(runtime, tmp_path, fault):
    agent, state, candidate, _, oid = await reader_runtime(runtime, tmp_path)
    _, prompter, policy, _, sent, *_ = runtime
    item = policy.observations._items[oid]
    if fault == "integrity":
        policy.observations._items[oid] = replace(item, body=b"tampered")
    elif fault in {"owner", "unowned"}:
        item = replace(item, candidate_id="another-candidate" if fault == "owner" else None)
        policy.observations._items[oid] = replace(item, retained_hash=digest(source_row(item)))
    elif fault == "epoch":
        policy.engagement.http_permissions.epoch = "different-epoch"
    elif fault == "scope":
        policy.engagement.remove_origin(candidate.target)
    elif fault == "http-revoked":
        policy.revoke("http")
    args = {"observation_id": "tr_wrong" if fault == "wrong-id" else oid,
            "start_char": 0, "max_chars": 2000}
    before = len(sent)
    with pytest.raises((ValueError, UserControlledRefusal, OutOfScopeError)):
        await agent.tools.execute("read_http_observation", args, None, prompter)
    assert len(sent) == before


async def test_range_permission_denial_and_revocation_during_review(runtime, tmp_path):
    agent, _, _, _, oid = await reader_runtime(runtime, tmp_path)
    _, prompter, policy, operator, sent, *_ = runtime
    prompter.set_yolo(False)
    args = {"observation_id": oid, "start_char": 0, "max_chars": 2000}
    before = len(sent)
    with pytest.raises(UserControlledRefusal):
        await agent.tools.execute("read_http_observation", args, None, prompter)
    assert len(sent) == before
    assert operator.requests[-1].no_session_cache
    operator.decision = Decision.ALLOW_ONCE
    policy.retry()
    async def revoke(request, signal=None):
        policy.revoke("http")
        return Decision.ALLOW_ONCE
    operator.ask = revoke
    with pytest.raises(UserControlledRefusal):
        await agent.tools.execute("read_http_observation", args, None, prompter)
    assert len(sent) == before


async def test_unicode_readback_resume_and_outbound_revocation(runtime, tmp_path):
    agent, state, _, result_args, oid = await reader_runtime(runtime, tmp_path)
    registry, prompter, policy, _, sent, *_ = runtime
    text = "Unicode é\n" * 600
    item = replace(policy.observations._items[oid], body=text.encode(),
                   response_hash=hashlib.sha256(text.encode()).hexdigest())
    policy.observations._items[oid] = replace(item, retained_hash=digest(source_row(item)))
    assert json.loads(await registry.execute("workflow", result_args, None, prompter))["ok"]
    path = tmp_path / "readback-observations.json"
    policy.observations.attach_storage(path)
    policy.observations.persist()
    policy.observations._items.clear()
    policy.observations.attach_storage(path)
    agent.workflow = WorkflowState.from_dict(json.loads(json.dumps(state.to_dict())))
    # The reader never repairs or reassigns controller ownership on hydration.
    policy.bind_validation_context(agent.workflow, agent.skills, agent.target)
    before = len(sent)
    args = {"observation_id": oid, "start_char": 0, "max_chars": 2000}
    chunks = []
    while True:
        output = await agent.tools.execute("read_http_observation", args, None, prompter)
        header, body = output.split("\n", 1)
        row = json.loads(header)
        assert len(output) <= 2000 and body == text[row["start_char"]:row["end_char"]]
        chunks.append(body)
        if row["next_start_char"] is None:
            break
        assert row["next_start_char"] > args["start_char"]
        args["start_char"] = row["next_start_char"]
    assert "".join(chunks) == text and len(sent) == before
    call = ToolCall("readback", FunctionCall("read_http_observation", json.dumps(args)))
    admitted = agent._http_analysis_content(call, ToolCallResult(output, "", 0))
    assert admitted is not None and admitted == str(output)
    working = [Message("tool", admitted, name="read_http_observation", http_response_sources=[oid])]
    agent._protect_http_context(working)
    assert working[0].content == admitted
    policy.revoke("http")
    agent._protect_http_context(working)
    assert "HTTP analysis omitted" in working[0].content


async def test_readback_internal_secret_is_withheld_from_agent_context(runtime, tmp_path):
    agent, _, _, _, oid = await reader_runtime(runtime, tmp_path)
    _, prompter, policy, *_ = runtime
    secret = "known-controller-secret"
    item = replace(policy.observations._items[oid], body=secret.encode(),
                   response_hash=hashlib.sha256(secret.encode()).hexdigest())
    policy.observations._items[oid] = replace(item, retained_hash=digest(source_row(item)))
    policy.internal_secret_values = lambda: (secret,)
    args = {"observation_id": oid, "start_char": 0, "max_chars": 2000}
    with pytest.raises(UserControlledRefusal, match="internal secret"):
        await agent.tools.execute("read_http_observation", args, None, prompter)


async def test_partial_ranges_cannot_reconstruct_known_internal_secret(runtime, tmp_path):
    agent, _, _, _, oid = await reader_runtime(runtime, tmp_path)
    _, prompter, policy, *_ = runtime
    secret = "known-controller-secret"
    item = replace(policy.observations._items[oid], body=secret.encode(),
                   response_hash=hashlib.sha256(secret.encode()).hexdigest())
    policy.observations._items[oid] = replace(item, retained_hash=digest(source_row(item)))
    policy.internal_secret_values = lambda: (secret,)
    for start in (0, 8):
        with pytest.raises(UserControlledRefusal, match="internal secret"):
            await agent.tools.execute("read_http_observation", {"observation_id": oid,
                "start_char": start, "max_chars": 8}, None, prompter)


async def test_previous_attempt_cannot_be_read_during_retest(runtime, tmp_path):
    agent, state, candidate, result_args, oid = await reader_runtime(runtime, tmp_path)
    registry, prompter, _, _, sent, *_ = runtime
    assert json.loads(await registry.execute("workflow", result_args, None, prompter))["ok"]
    args = {"observation_id": oid, "start_char": 0, "max_chars": 2000}
    assert await agent.tools.execute("read_http_observation", args, None, prompter)
    state.objective = WorkflowObjective("operator-retest", "candidate_validation", candidate.target,
                                        candidate_id=candidate.id)
    candidate.status = "queued"
    assert json.loads(await registry.execute("workflow", {"action": "start_validation",
        "candidate_id": candidate.id}, None, prompter))["ok"]
    before = len(sent)
    with pytest.raises(UserControlledRefusal):
        await agent.tools.execute("read_http_observation", args, None, prompter)
    assert len(sent) == before
