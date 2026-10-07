"""Regression checks from the generic fallback trust-boundary audit."""
import asyncio
import json

import pytest

from src.permission.runtime.execution import ExecutionBlocked
from src.permission.permission import UserControlledRefusal
from src.permission.runtime.observations import ObservationStore, VerifiedResult
from src.skills.registry import Registry as Skills
from src.ui.commands.result_review import review_result
from src.workflow.state import WorkflowState
from src.agent.decision_planner import PlannerCandidate, PlannerContext, build_decision_plan
from src.target.target import Target
from src.workflow.validation_route import ValidationRoute
from pathlib import Path
from tests.security.test_execution_policy import runtime
from tests.security.test_generic_validation import (
    agent_for, app_for, bind_context, certificate, evidence, expert, request,
    result, review_args, setup, start,
)


@pytest.mark.parametrize("source", ["tool-status", "restore"])
async def test_expert_status_alone_cannot_release_generic_boundary(runtime, tmp_path, source):
    skills = Skills()
    skills.add(expert("expert", "header-reflection"))
    env = await setup(runtime, tmp_path, mode="whole_target", skills=skills)
    args = {"action": "record_candidate", "candidate_class": "header-reflection",
            "endpoint": "/expert", "method": "GET", "parameter": "X-Test",
            "location": "header", "status": "validating"}
    recorded = json.loads(await env[0].execute("workflow", args, None, env[1]))
    cid = recorded["candidate"]["id"]
    if source == "restore":
        env[4].replace_from(WorkflowState.from_dict(env[4].to_dict()))
    with pytest.raises(ExecutionBlocked, match="generic"):
        await env[0].execute("http", {"url": "/outside-proposal", "phase": "validation"}, None, env[1])
    assert not runtime[4] and not env[3].requests
    # A real structured expert start still selects independent expert work.
    assert json.loads(await env[0].execute("workflow", {
        "action": "start_validation", "candidate_id": cid}, None, env[1]))["ok"]
    assert (await env[0].execute("http", {"url": "/expert", "phase": "validation"}, None, env[1])).http_status == 200
    assert len(runtime[4]) == 1


@pytest.mark.parametrize("field,value", [
    ("baseline_request_ref", "wr:different-baseline"),
    ("auth_context_ref", "different-identity"),
    ("content_type", "application/json"),
    ("request_template", '{"term":"{INJECTION_POINT}"}'),
])
async def test_review_certificate_does_not_survive_request_context_change(runtime, tmp_path, field, value):
    env = await setup(runtime, tmp_path)
    await start(env)
    await env[0].execute("http", request(env[5]), None, env[1])
    ref = await evidence(env, tmp_path)
    await result(env, refs=[ref])
    app, _ = app_for(env)
    await review_result(app, review_args(env[5], "not-confirmed"))
    assert certificate(env, ref) is not None
    setattr(env[5], field, value)
    assert certificate(env, ref) is None


async def selected_expert(runtime, tmp_path):
    skills = Skills()
    skills.add(expert("expert", "header-reflection"))
    env = await setup(runtime, tmp_path, mode="whole_target", skills=skills)
    recorded = json.loads(await env[0].execute("workflow", {
        "action": "record_candidate", "candidate_class": "header-reflection",
        "endpoint": "/expert", "method": "GET", "parameter": "X-Test",
        "location": "header"}, None, env[1]))
    cid = recorded["candidate"]["id"]
    assert json.loads(await env[0].execute("workflow", {
        "action": "start_validation", "candidate_id": cid}, None, env[1]))["ok"]
    return env, cid


async def test_finished_expert_cannot_release_boundary_by_requeued_status(runtime, tmp_path):
    env, cid = await selected_expert(runtime, tmp_path)
    assert json.loads(await env[0].execute("workflow", {
        "action": "record_result", "candidate_id": cid, "skill_name": "expert",
        "outcome": "blocked"}, None, env[1]))["ok"]
    env[4].set_candidate_status(cid, "validating")
    with pytest.raises(ExecutionBlocked, match="generic"):
        await env[0].execute("http", {"url": "/outside-proposal", "phase": "validation"}, None, env[1])
    assert not runtime[4]


async def test_matching_generic_observations_still_verify_and_persist(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    await start(env)
    await env[0].execute("http", request(env[5]), None, env[1])
    ids = list(env[2].observations._items)
    binding = env[2].generic_validation.probe_identity()
    item = env[2].observations._items[ids[0]]
    assert (item.candidate_id, item.probe_binding) == (env[5].id, binding)
    storage = tmp_path / "observations.json"
    env[2].observations.attach_storage(storage)
    env[2].observations.persist()
    restored = ObservationStore()
    restored.attach_storage(storage)
    assert restored._items[ids[0]].probe_binding == binding
    ref = await evidence(env, tmp_path)
    env[2].observations.register_verifier(env[5].candidate_class, lambda _, items: VerifiedResult(
        "not-confirmed", "Fixture comparison", "info", tuple(i.id for i in items)))
    payload = json.loads(await result(env, "not-confirmed", refs=[ref], observation_ids=ids))
    assert payload["result"]["outcome"] == "not-confirmed"
    trusted = certificate(env, ref)
    assert trusted is not None and trusted.observation_ids == tuple(ids)
    # Old observation records remain readable, but lack attempt attestation.
    raw = json.loads(storage.read_text())
    for row in raw["observations"]:
        row.pop("candidate_id")
        row.pop("probe_binding")
    storage.write_text(json.dumps(raw))
    legacy = ObservationStore()
    legacy.attach_storage(storage)
    legacy.register_verifier(env[5].candidate_class, lambda _, items: VerifiedResult(
        "not-confirmed", "Fixture", "info", tuple(i.id for i in items)))
    assert legacy.verify(env[5], (ref,), ids, env[2].engagement.http_permissions.epoch,
                         validation_binding=(env[5].id, binding)) is None


async def test_cancelled_generic_wait_releases_guards_without_sending(runtime, tmp_path, monkeypatch):
    env = await setup(runtime, tmp_path)
    await start(env)
    entered = asyncio.Event()

    async def reserve(*args):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(env[0].get("http").permissions, "reserve_when_ready", reserve)
    task = asyncio.create_task(env[0].execute("http", request(env[5]), None, env[1]))
    await asyncio.wait_for(entered.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not runtime[4] and not env[2].generic_validation.in_flight
    assert env[2].active == 0 and not env[0].get("http").permissions._receipts
    assert env[4].latest_result(env[5].id) is None


async def test_new_attempt_does_not_depend_on_legacy_certificate_invalidation(runtime, tmp_path, monkeypatch):
    env = await setup(runtime, tmp_path)
    await start(env)
    ref = await evidence(env, tmp_path)
    await result(env, refs=[ref])
    app, _ = app_for(env)
    await review_result(app, review_args(env[5], "not-confirmed"))
    previous = certificate(env, ref)
    agent_for(env)._initialize_request_objective(f"Retest candidate {env[5].id}", True)
    bind_context(env)
    monkeypatch.setattr(env[2].observations, "persist", lambda: (_ for _ in ()).throw(OSError("fixture failure")))
    response = await start(env)
    assert json.loads(response)["ok"]
    assert env[4].latest_result(env[5].id).assessment_source == "operator"
    assert certificate(env, ref) is None  # prior objective remains historical
    assert env[5].status == "validating" and env[2].generic_validation.attempt is not None
    assert env[4].objective.id not in env[2].generic_validation.retest_objectives
    assert len(runtime[4]) == 1


@pytest.mark.parametrize("candidate_class", ["input-canonicalization", "new-future-class"])
def test_explicit_unrecorded_class_is_not_routed_from_authorization_prose(candidate_class):
    skills = Skills()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    plan = build_decision_plan(
        f"Record one candidate_class={candidate_class} at /search?q=apple. "
        "Target authorization never establishes endpoint safety.",
        skills.list_enabled(), Target("http://juice.lab:8081"), PlannerContext())
    assert plan is not None and plan.recommended_skill is None
    assert plan.candidate_id is None and "record_candidate" in plan.guidance
    assert "generic bounded validation" not in plan.guidance  # Full registry has not yet routed a stored candidate.


def test_explicit_unrecorded_class_does_not_select_an_unrelated_queued_expert():
    skills = Skills()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    context = PlannerContext(candidates=(PlannerCandidate("cand_other", "access-control", "queued"),),
        validation_routes={"cand_other": ValidationRoute("expert", "access-control")})
    plan = build_decision_plan("Record candidate_class=input-canonicalization; target authorization is present.",
                               skills.list_enabled(), Target("http://juice.lab:8081"), context)
    assert plan is not None and plan.recommended_skill is None and plan.candidate_id is None


async def test_generic_restriction_activating_during_expert_await_prevents_send(runtime, tmp_path, monkeypatch):
    env, cid = await selected_expert(runtime, tmp_path)
    tool = env[0].get("http")
    original = tool.permissions.authorize

    async def authorize(*args):
        receipt = await original(*args)
        assert json.loads(await env[6].run({
            "action": "record_result", "candidate_id": cid, "skill_name": "expert",
            "outcome": "blocked"}, None, env[1]))["ok"]
        return receipt

    monkeypatch.setattr(tool.permissions, "authorize", authorize)
    with pytest.raises((UserControlledRefusal, ValueError)):
        await env[0].execute("http", {"url": "/expert", "phase": "validation"}, None, env[1])
    assert not runtime[4] and not env[2].generic_validation.in_flight


async def test_generic_verifier_cannot_borrow_another_attempt_observations(runtime, tmp_path):
    env, cid = await selected_expert(runtime, tmp_path)
    await env[0].execute("http", {"url": env[5].endpoint, "phase": "validation"}, None, env[1])
    ids = list(env[2].observations._items)
    await env[0].execute("workflow", {"action": "record_result", "candidate_id": cid,
        "skill_name": "expert", "outcome": "blocked"}, None, env[1])
    await start(env)
    ref = await evidence(env, tmp_path)
    env[2].observations.register_verifier(env[5].candidate_class, lambda _, items: VerifiedResult(
        "confirmed", "Fixture comparison", "low", tuple(i.id for i in items)))
    rejected = await result(env, refs=[ref], observation_ids=ids)
    assert rejected.startswith("error:")
    assert not env[4].eligible_for_finding(env[5].id)
    assert len(runtime[4]) == 2  # Earlier expert response and current owned fixture response remain distinct.


async def test_explicit_generic_retest_cannot_reuse_old_certificate_or_complete_early(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    await start(env)
    ref = await evidence(env, tmp_path)
    await result(env, refs=[ref])
    app, _ = app_for(env)
    await review_result(app, review_args(env[5], "not-confirmed"))
    agent = agent_for(env)
    assert not agent._generic_completion_blockers()
    agent._initialize_request_objective(f"Retest candidate {env[5].id}", True)
    assert agent._generic_completion_blockers()
    bind_context(env)
    assert json.loads(await start(env))["ok"]
    assert certificate(env, ref) is None
    rejected = await result(env, "not-confirmed", refs=[ref])
    assert rejected.startswith("error:")
    assert agent._generic_completion_blockers()
    assert len(runtime[4]) == 1
