"""Production Agent finalization with scripted model and isolated mock transport.

No evaluator, benchmark runner, external model or target is executed.
"""
from copy import deepcopy
import json

import httpx
import pytest

from tests.helpers.agent_fakes import FakeClient, FakeSignal, collect
from tests.security.test_execution_policy import REAL_CLIENT
from tests.security.test_execution_policy import runtime
from tests.security.test_agent_assessment import setup as assessment_setup
from tests.security.test_evidence_recovery_contract import agent_for
from src.workflow.assessment import seal
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall


async def test_registered_proof_without_explicit_result_is_not_attached_at_hard_stop(runtime, tmp_path):
    state, candidate, tool, args, _ = await assessment_setup(runtime, tmp_path, candidate_class="sqli")
    agent = agent_for(runtime, tool, state, args, max_steps=1)
    client = FakeClient([ChatResponse(Message("assistant", "", tool_calls=[ToolCall("list", FunctionCall(
        "workflow", json.dumps({"action": "list", "candidate_id": candidate.id})))]), "tool_calls"),
        ChatResponse(Message("assistant", "Bounded fixture remains unresolved."), "stop")])
    agent.set_client(client)
    policy = runtime[2]
    evidence = deepcopy(state.evidence)
    attempts = list(state.attempts)
    rights = policy.engagement.http_permissions
    grants, epoch = dict(rights.grants), rights.epoch
    events = collect()
    await agent.run("Continue current validation.", FakeSignal(), events["sink"])
    assert events["events"][-1]["stop_reason"] == "max_steps"
    result = state.latest_result(candidate.id)
    assert result is not None and result.outcome == "insufficient-evidence"
    assert result.attempt_id is not None and result.attempt_id == args["attempt_id"]
    assert state.attempts[result.attempt_id]["status"] == "unresolved"
    assert candidate.status == "deferred" and not state.eligible_for_finding(candidate.id)
    assert result.mutation_performed is None and result.cleanup_state == "unknown"
    assert not result.evidence_refs and not result.evidence_manifest and state.evidence == evidence
    assert args["evidence_refs"] and list(state.attempts) == attempts and len(runtime[4]) == 1
    assert rights.grants == grants and rights.epoch == epoch
    assert len(client.requests) == 2 and client.requests[-1].tools is None


@pytest.mark.parametrize("cleanup", ["unknown", "not-attempted"])
async def test_unresolved_effect_states_block_whole_target_completion(runtime, tmp_path, cleanup):
    registry, prompter, policy, *_ = runtime
    state, candidate, tool, args, _ = await assessment_setup(runtime, tmp_path)
    result = json.loads(await registry.execute("workflow", {**args, "outcome": "not-confirmed",
        "mutation_performed": None, "cleanup_state": cleanup}, None, prompter))
    assert result["ok"]
    status, _, blockers = state.whole_target_status(target_origin=candidate.target,
        available_phases=frozenset(), validator_classes=frozenset({candidate.candidate_class}),
        coverage_sync_available=True,
        validation_errors={candidate.id: state.validation_completion_error(candidate.id,
            evidence_root=tmp_path, target_origin=candidate.target, policy=policy)})
    assert status != "completed" and any("effects/cleanup unresolved" in b for b in blockers)


async def test_reported_verified_write_and_cleanup_need_owned_readback(runtime, tmp_path, monkeypatch):
    registry, prompter, policy, _, sent, _, target = runtime
    rows = {"count": 0}
    def handler(req):
        sent.append(req)
        if req.url.path == "/fixture":
            rows["count"] += 1
            body = "Update complete; created fixture resource"
        elif req.method == "DELETE":
            rows["count"] = 0
            body = "Fixture resource removed"
        else:
            body = json.dumps(rows)
        return httpx.Response(200, content=body.encode(), request=req)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler), **kw))
    state, candidate, tool, args, write = await assessment_setup(runtime, tmp_path, candidate_class="sqli", related=[
        {"role": "cleanup", "method": "DELETE", "url": "/resource", "required": False},
        {"role": "readback", "method": "GET", "url": "/verify"},
    ])
    declaration = {"action": "record_attempt_state", "candidate_id": candidate.id,
        "mutation_state": "reported-write", "effect_basis": "Owned baseline reports successful resource creation",
        "observation_ids": [write], "cleanup_state": "not-attempted", "cleanup_status": "Agent cleanup not attempted"}
    assert json.loads(await registry.execute("workflow", declaration, None, prompter))["ok"]
    before = deepcopy(state.to_dict())
    for update in [{"mutation_state": "no-mutation-established"}, {"mutation_state": "verified-write"},
                   {"cleanup_state": "succeeded", "cleanup_status": "resource deletion verified"}]:
        result = await registry.execute("workflow", {**declaration, **update}, None, prompter)
        assert result.startswith("error:") and state.to_dict() == before
    await registry.execute("http", {"url": "/verify", "phase": "validation"}, None, prompter)
    verify_write = next(reversed(policy.observations._items))
    assert rows["count"] == 1
    declaration.update(mutation_state="verified-write", observation_ids=[write, verify_write],
                       effect_basis="Independent owned readback verifies the created fixture resource")
    assert json.loads(await registry.execute("workflow", declaration, None, prompter))["ok"]
    # This isolated fixture explicitly supplies cleanup intent and its normal
    # per-action runtime authority; an acknowledgement did not grant it.
    await registry.execute("http", {"url": "/resource", "method": "DELETE", "phase": "impact"}, None, prompter)
    cleanup = next(reversed(policy.observations._items))
    await registry.execute("http", {"url": "/verify", "phase": "validation"}, None, prompter)
    verify_cleanup = next(reversed(policy.observations._items))
    assert rows["count"] == 0
    declaration.update(observation_ids=[write, verify_write, cleanup, verify_cleanup],
        cleanup_state="succeeded", cleanup_status="Agent cleanup performed; subsequent owned readback verifies removal")
    assert json.loads(await registry.execute("workflow", declaration, None, prompter))["ok"]
    agent = agent_for(runtime, tool, state, args)
    await agent._close_terminal_attempt("max_steps", FakeSignal(), collect()["sink"], agent.history.copy())
    latest = state.latest_result(candidate.id)
    assert latest is not None
    assert latest.outcome == "insufficient-evidence" and latest.mutation_performed is True
    assert latest.cleanup_state == "succeeded" and latest.assessment_binding == seal(latest)
    assert [e["source"]["id"] for e in latest.evidence_manifest] == declaration["observation_ids"]
    assert not state.persisted_findings and len(sent) == 4


async def test_adapter_admission_invalidates_prior_no_write_declaration(runtime, tmp_path):
    registry, prompter, policy, _, sent, _, _ = runtime
    state, candidate, _, _, oid = await assessment_setup(runtime, tmp_path)
    assert candidate.target is not None
    assert json.loads(await registry.execute("workflow", {"action": "record_attempt_state",
        "candidate_id": candidate.id, "mutation_state": "no-mutation-established",
        "effect_basis": "Controlled fixture had no persistent effect", "observation_ids": [oid]}, None, prompter))["ok"]
    await registry.execute("web_fetch", {"url": candidate.target + "/fixture"}, None, prompter)
    attempt = state.attempts[policy.generic_validation.durable_attempt]
    assert [row["tool"] for row in attempt["effects"]["admissions"]] == ["http", "web_fetch"]
    assert attempt["effects"]["declaration"] is None
    assert len(sent) == 2
