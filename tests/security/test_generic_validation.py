"""Offline generic lifecycle and executor boundaries; fixtures grant no proof."""
from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from src.agent.decision_planner import PlannerCandidate, PlannerContext, build_decision_plan
from src.agent.agent import Agent, AgentOptions
from src.coverage.store import CoverageStore
from src.findings.store import Store
from src.permission.permission import AlwaysAllow, Decision, UserControlledRefusal
from src.permission.runtime.execution import ExecutionBlocked
from src.permission.network.grants import HTTPLimits, HTTPBlocked
from src.permission.runtime.observations import VerifiedResult
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry as Skills, Skill, SkillMetadataError
from src.tools.common.ask import AskUserTool
from src.tools.execution.shell import ShellTool
from src.tools.workflow.finding import ConfirmFindingTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.ui.commands.result_review import review_result
from src.workflow.assessment import accepted_result
from tests.security.test_agent_assessment import ASSESSMENT
from src.workflow.state import AttackSurfaceInput, Candidate, ValidationResult, WorkflowMode, WorkflowObjective, WorkflowState
from src.workflow.validation_route import GENERIC_VALIDATOR, resolve_validation_route
from src.workflow.probe import ProbeProposal
from tests.helpers.workflow import record_completed_phase
from tests.helpers.agent_fakes import FakeClient
from tests.helpers.agent_fakes import FakeSignal, collect
from src.llm.core.client import StreamingClient
from src.llm.core.types import ChatResponse, Message
from src.workflow.goals import RequestedGoal
from tests.security.test_execution_policy import runtime, ORIGIN, REAL_CLIENT


def expert(name="expert", cls="open-redirect", manual=False):
    return Skill(name, "fixture", ["http", "shell"], manual, f"/tmp/{name}/SKILL.md", "",
                 stage="validation", candidate_classes=[cls])


async def setup(runtime, tmp_path, cls="open-redirect", mode: WorkflowMode="direct", skills=None,
                phase_artifact_ref="fixture.md") -> Any:
    registry, prompter, policy, operator, sent, responses, target = runtime
    skills = skills if skills is not None else Skills()
    state = WorkflowState()
    state.objective = WorkflowObjective("current-objective", mode, ORIGIN)
    if mode == "whole_target":
        for phase in ("recon", "enumeration", "input_analysis"):
            record_completed_phase(state, phase, objective_id=state.objective.id,
                                   target_origin=ORIGIN, artifact_ref=phase_artifact_ref)
    coverage = CoverageStore(str(tmp_path / "coverage.json"))
    tool = WorkflowTool(state, target, skills=skills, coverage=coverage, evidence_root=tmp_path)
    registry.register(tool)
    registry.get("http").workflow = state
    policy.bind_validation_context(state, skills, target)
    args = {"action": "record_candidate", "candidate_class": cls, "method": "GET",
            "endpoint": "/return?next=%2Fhome&keep=1" if cls == "open-redirect" else "/fixture?keep=1",
            "parameter": "next" if cls == "open-redirect" else "Origin",
            "location": "query" if cls == "open-redirect" else "header",
            "source_skill": "web-input-analysis"}
    if mode == "whole_target":
        item, _ = state.add_attack_surface_input(AttackSurfaceInput(
            objective_id="current-objective", target_origin=ORIGIN, method="GET",
            endpoint=args["endpoint"], parameter=args["parameter"], location=args["location"]))
        args["input_id"] = item.id
    response = json.loads(await registry.execute("workflow", args, None, prompter))
    candidate = state.candidates[response["candidate"]["id"]]
    if mode == "whole_target":
        state.set_input_disposition(args["input_id"], "analyzed")
    env = registry, prompter, policy, operator, state, candidate, tool, response
    if resolve_validation_route(skills, cls).kind == "generic":
        bind_context(env)
    return env


def proposal(env):
    c, objective = env[5], env[4].objective
    return ProbeProposal(c.id, objective.id, objective.target_origin, c.endpoint, c.method,
        c.location, c.parameter, ("https://example.com/" if c.location == "query" else "https://example.com",),
        c.baseline_request_ref, c.auth_context_ref).to_dict()


def bind_context(env):
    # Controller owns this local mock endpoint and has verified both exact
    # requests only return fixture responses. Capture/model flags grant nothing.
    env[2].generic_validation.bind_probe_context(env[0].get("http"), env[5].id,
        proposal(env), verified_input_only=True)


async def start(env):
    registry, p, _, _, _, c, _, _ = env
    return await registry.execute("workflow", {"action": "start_validation", "candidate_id": c.id, "assessment": ASSESSMENT}, None, p)


def request(candidate, marker=False):
    if candidate.candidate_class == "open-redirect":
        return {"url": "/return?next=https%3A%2F%2Fexample.com%2F&keep=1" if marker else candidate.endpoint,
                "method": "GET", "phase": "validation"}
    return {"url": candidate.endpoint, "method": "GET", "phase": "validation",
            **({"headers": {"Origin": "https://example.com"}} if marker else {})}


async def evidence(env, tmp_path):
    registry, p, policy, _, _, c, _, _ = env
    # Optional review fixtures now retain a genuine native response before
    # writing derived interpretation; a proof file alone has no authority.
    if policy.generic_validation.started_candidate == c.id and not any(
            item.attempt_id == policy.generic_validation.durable_attempt for item in policy.observations._items.values()):
        baseline = policy.generic_validation.baseline(registry.get("http"), c)
        await registry.execute("http", {"url": str(baseline.url), "method": baseline.method,
            "headers": dict(baseline.headers), "body": baseline.content.decode(), "phase": "validation"}, None, p)
    path = policy.generic_validation.proof_path(c)
    await registry.execute("file_write", {"path": str(path), "content":
        "HTTP 302 Location: https://example.com/\nAuthorization: Bearer fake-secret-token\nCookie: session=secret-session-value"}, None, p)
    return json.loads(await registry.execute("workflow", {"action": "record_evidence", "candidate_id": c.id,
        "evidence_path": str(path.relative_to(tmp_path))}, None, p))["evidence"]["id"]


async def result(env, outcome="confirmed", refs=(), **extra):
    registry, p, policy, _, state, c, _, _ = env
    extra.setdefault("assessment", ASSESSMENT.copy())
    if refs and "observation_ids" not in extra:
        extra["observation_ids"] = [item.id for item in policy.observations._items.values()
                                   if item.attempt_id == policy.generic_validation.durable_attempt]
    return await registry.execute("workflow", {"action": "record_result", "candidate_id": c.id,
        "skill_name": GENERIC_VALIDATOR, "outcome": outcome, "evidence_refs": list(refs), **extra}, None, p)


def app_for(env):
    registry, p, _, operator, state, _, tool, _ = env
    output = []
    operator.decision = Decision.ALLOW_ONCE
    app = SimpleNamespace(agent=SimpleNamespace(prompter=p, workflow=state, tools=registry,
        skills=tool.skills, save=AsyncMock()), dispatch=output.append)
    return app, output


def review_args(candidate, outcome="confirmed"):
    return [candidate.id, outcome, "low", "Observed bounded fixture response."]


def certificate(env, ref):
    _, _, policy, _, state, c, _, _ = env
    result = state.latest_result(c.id)
    if not accepted_result(state, c, result, policy):
        return None
    if result.assessment_contract_version < 2:
        return policy.observations.result(c.id, (ref,), policy.engagement.http_permissions.epoch, c)
    return SimpleNamespace(outcome=result.outcome, observed_impact=result.assessment['observed_impact'],
        severity=result.assessment['severity'], observation_ids=tuple(e['source']['id'] for e in result.evidence_manifest),
        verification_source='operator-reviewed' if result.assessment_source == 'operator' else 'agent')



@pytest.mark.parametrize("mapping,expected", [("none", "generic"), ("unique", "expert"),
    ("multiple", "ambiguous"), ("disabled", "unavailable"), ("manual", "unavailable"),
    ("registry-missing", "unavailable")])
def test_full_registry_resolution(mapping, expected):
    skills = Skills()
    if mapping not in {"none", "registry-missing"}:
        skills.add(expert(manual=mapping == "manual"))
    if mapping == "multiple":
        skills.add(expert("second"))
    if mapping == "disabled":
        skills.set_disabled("expert", True)
    route = resolve_validation_route(None if mapping == "registry-missing" else skills, "open-redirect")
    assert route.kind == expected
    assert resolve_validation_route(Skills(), "unknown-class").kind == "generic"


def test_registry_load_failure_is_not_missing_mapping(tmp_path):
    broken = tmp_path / "open-redirect"
    broken.mkdir()
    (broken / "SKILL.md").write_text("---\nname: open-redirect\nallowed-tools: invalid\n---\nfixture")
    skills = Skills()
    skills.load_dir(tmp_path)
    assert skills.load_errors
    route = resolve_validation_route(skills, "open-redirect")
    assert route.kind == "unavailable" and "load failure" in route.reason
    skills.add(expert("sqli-expert", "sql-injection"))
    assert resolve_validation_route(skills, "sql-injection").kind == "expert"


@pytest.mark.asyncio
@pytest.mark.parametrize("mapping", ["disabled", "manual", "multiple", "unsupported"])
async def test_unavailable_mapping_and_missing_mapping_keep_distinct_routes(runtime, tmp_path, mapping):
    skills = Skills()
    if mapping != "unsupported":
        skills.add(expert(manual=mapping == "manual"))
    if mapping == "disabled":
        skills.set_disabled("expert", True)
    if mapping == "multiple":
        skills.add(expert("another"))
    env = await setup(runtime, tmp_path, cls="unknown-class" if mapping == "unsupported" else "open-redirect", skills=skills)
    assert env[5].status == "deferred"
    if mapping == "unsupported":
        assert env[7]["validator_resolution"] == "generic" and env[7]["supported"] is False
        assert json.loads(await start(env))["ok"]
    else:
        assert env[7]["validator_resolution"] != "generic"
        assert (await start(env)).startswith("error:")
    assert not runtime[4] and not env[3].requests


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", ["sql-injection", "cross-site-scripting"])
async def test_unique_experts_keep_existing_route_start_and_result(runtime, tmp_path, cls):
    skills = Skills()
    skills.add(expert(cls, cls))
    env = await setup(runtime, tmp_path, cls=cls, skills=skills)
    assert env[7]["validator_resolution"] == "unique"
    assert env[5].objective_id == env[4].objective.id
    assert json.loads(await start(env))["ok"]
    output = json.loads(await env[0].execute("workflow", {"action": "record_result", "candidate_id": env[5].id,
        "skill_name": cls, "outcome": "blocked"}, None, env[1]))
    assert output["result"]["skill_name"] == cls and output["result"]["outcome"] == "blocked"
    # Failed expert proof/start is never represented as generic fallback.
    assert (await env[6].run({"action": "record_result", "candidate_id": env[5].id,
        "skill_name": GENERIC_VALIDATOR, "outcome": "blocked"}, None, env[1])).startswith("error:")


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", ["open-redirect", "cors-misconfiguration"])
async def test_generic_lifecycle_preserves_native_limits_and_zero_extra_questions(runtime, tmp_path, cls):
    env = await setup(runtime, tmp_path, cls)
    registry, p, policy, operator, state, candidate, _, response = env
    assert response["validator_resolution"] == "generic" and candidate.status == "deferred"
    assert candidate.objective_id == state.objective.id and candidate.source_skill == "web-input-analysis"
    assert GENERIC_VALIDATOR not in state.completed_skills
    assert json.loads(await start(env))["candidate"]["status"] == "validating"
    for _ in range(2):  # Repetition for reproducibility is permitted.
        for marker in (False, True):
            assert (await registry.execute("http", request(candidate, marker), None, p)).http_status == 200
    ref = await evidence(env, tmp_path)
    artifact = state.evidence[ref]
    assert artifact.candidate_id == candidate.id and artifact.is_resolvable(tmp_path)
    proof = (tmp_path / artifact.path).read_text()
    assert "fake-secret-token" not in proof and "secret-session-value" not in proof
    rejected = await result(env, refs=[ref], repeatable=True, force=True, observation_ids=["obs_forged"])
    assert rejected.startswith("error:") and not state.validation_results
    await result(env, "insufficient-evidence", refs=[ref])
    assert candidate.status == "deferred" and not state.eligible_for_finding(candidate.id)
    assert await env[6].coverage.list() == []
    assert not operator.requests
    assert policy.used > 0 and len(runtime[4]) == 4
    assert not policy.generic_validation.in_flight
    assert (await start(env)).startswith("error:")
    with pytest.raises(ExecutionBlocked):
        await registry.execute("http", request(candidate), None, p)


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["confirmed", "not-confirmed"])
async def test_both_terminal_outcomes_require_linked_trusted_proof(runtime, tmp_path, outcome):
    env = await setup(runtime, tmp_path)
    await start(env)
    rejected = await result(env, outcome, force=True, repeatable=True, confirmation={"kind": "model-claim"})
    assert rejected.startswith("error:") and not env[4].validation_results
    assert await env[6].coverage.list() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["objective", "origin", "endpoint", "input", "method", "policy", "registry"])
async def test_generic_admission_fails_closed(runtime, tmp_path, change):
    env = await setup(runtime, tmp_path)
    _, p, policy, _, state, c, tool, _ = env
    if change == "objective":
        state.objective.id = "another"
    elif change == "origin":
        tool.target.set_base_url("http://127.0.0.1:3001")
    elif change == "endpoint":
        c.endpoint = "http://other.test/return?next=/"
    elif change == "input":
        c.parameter = "absent"
    elif change == "method":
        c.method = "DELETE"
    elif change == "policy":
        p.execution_policy = None
    else:
        tool.skills = None
    output = await tool.run({"action": "start_validation", "candidate_id": c.id, "assessment": ASSESSMENT}, None, p)
    assert output.startswith("error:") and c.status == "deferred"
    assert not runtime[4]


@pytest.mark.asyncio
async def test_old_candidate_requires_explicit_candidate_objective(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    _, _, _, _, state, c, _, _ = env
    c.objective_id = None
    assert (await start(env)).startswith("error:")
    state.objective = WorkflowObjective("explicit", "candidate_validation", ORIGIN, c.id)
    bind_context(env)
    assert json.loads(await start(env))["ok"]
    state.objective.candidate_id = "another"
    output = await env[6].run({"action": "record_result", "candidate_id": c.id,
        "skill_name": GENERIC_VALIDATOR, "outcome": "blocked"}, None, env[1])
    assert output.startswith("error:") and state.latest_result(c.id) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [{"url": "/other?next=%2Fhome"}, {"url": ORIGIN + "/return?next=%2Fhome&keep=2"},
    {"phase": "impact"}, {"profile": "browser-like"}, {"max_redirects": 1}, {"method": "POST"},
    {"body": "mutation"}, {"headers": {"Authorization": "Bearer forged"}},
    {"url": "/return?next=https%3A%2F%2Fevil.test%2F&keep=1"}, {"auth_context_ref": "different"}])
async def test_prepared_http_rejects_scope_input_identity_and_impact_changes(runtime, tmp_path, bad):
    env = await setup(runtime, tmp_path)
    await start(env)
    with pytest.raises((ExecutionBlocked, ValueError)):
        await env[0].execute("http", {**request(env[5]), **bad}, None, env[1])
    assert not runtime[4] and not env[3].requests


@pytest.mark.asyncio
@pytest.mark.parametrize("name,args", [("file_read", {"path": "proof.md"}), ("web_search", {"query": "fixture"}),
    ("web_fetch", {"url": ORIGIN}), ("content_discovery", {"paths": ["fixture"]}),
    ("shell", {"command": "echo fixture"}), ("file_write", {"path": "artifacts/findings/fake.md", "content": "fake"}),
    ("file_write", {"path": ".kagent/config.json", "content": "fake"})])
async def test_runtime_capability_allowlist_even_yolo(runtime, tmp_path, name, args):
    env = await setup(runtime, tmp_path)
    await start(env)
    if name == "shell":
        env[0].register(ShellTool())
    if name == "content_discovery":
        name = next(n for n in env[0].names() if "discover" in n and "content" in n)
    with pytest.raises(ExecutionBlocked, match="generic"):
        await env[0].execute(name, args, None, env[1])
    assert not env[3].requests and not runtime[4]


@pytest.mark.asyncio
async def test_proof_symlink_and_hardlink_still_blocked(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    await start(env)
    path = env[2].generic_validation.proof_path(env[5])
    path.parent.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("fixture")
    path.symlink_to(outside)
    with pytest.raises(ExecutionBlocked):
        await env[0].execute("file_write", {"path": str(path), "content": "fake"}, None, env[1])
    path.unlink()
    path.hardlink_to(outside)
    with pytest.raises(ExecutionBlocked, match="hardlink"):
        await env[0].execute("file_write", {"path": str(path), "content": "fake"}, None, env[1])
    assert outside.read_text() == "fixture"


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["missing", "wrong-candidate", "tampered"])
async def test_evidence_ownership_and_integrity(runtime, tmp_path, fault):
    env = await setup(runtime, tmp_path)
    await start(env)
    ref = await evidence(env, tmp_path)
    artifact = env[4].evidence[ref]
    if fault == "missing":
        ref = "ev_nonexistent"
    elif fault == "wrong-candidate":
        env[4].evidence[ref] = replace(artifact, candidate_id="other")
    else:
        (tmp_path / artifact.path).chmod(0o600)
        (tmp_path / artifact.path).write_text("tampered")
    output = await result(env, refs=[ref])
    assert output.startswith("error:") and env[4].latest_result(env[5].id) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["confirmed", "not-confirmed"])
async def test_human_review_commit_precedes_certificate_even_yolo(runtime, tmp_path, outcome):
    env = await setup(runtime, tmp_path)
    await start(env)
    ref = await evidence(env, tmp_path)
    await result(env, refs=[ref])
    app, output = app_for(env)
    async def save(*, workflow_override=None, _workflow_locked=False):
        latest = env[4].latest_result(env[5].id)
        assert latest is not None and latest.assessment_source == "agent"
        assert workflow_override is not None
        staged_result = workflow_override.latest_result(env[5].id)
        assert staged_result is not None and staged_result.outcome == outcome
        assert env[5].id not in env[2].observations._results
    app.agent.save.side_effect = save
    await review_result(app, review_args(env[5], outcome))
    assert output[-1].entry.kind == "system", output[-1]
    trusted = certificate(env, ref)
    assert trusted is not None
    assert trusted.outcome == outcome
    assert [r.tool for r in env[3].requests] == ["review_result"]
    assert env[3].requests[0].no_session_cache
    assert (await env[6].coverage.list())[0].status == ("failed" if outcome == "confirmed" else "passed")


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["declined", "cancelled", "save", "objective", "registry", "record-error", "persist"])
async def test_failed_review_never_publishes_certificate(runtime, tmp_path, monkeypatch, fault):
    env = await setup(runtime, tmp_path)
    await start(env)
    ref = await evidence(env, tmp_path)
    await result(env, refs=[ref])
    app, output = app_for(env)
    if fault == "declined":
        env[3].decision = Decision.DENY
    elif fault == "cancelled":
        env[3].ask = AsyncMock(side_effect=asyncio.CancelledError)
    elif fault == "save":
        app.agent.save.side_effect = OSError("fixture save failure")
    elif fault == "record-error":
        monkeypatch.setattr("src.ui.commands.result_review.accepted_result", lambda *args: False)
    elif fault == "persist":
        app.agent.save.side_effect = OSError("canonical workflow persistence failure")
    else:
        async def ask(*_):
            if fault == "objective":
                env[4].objective.id = "changed"
            else:
                env[6].skills.add(expert())
            return Decision.ALLOW_ONCE
        env[3].ask = ask
    if fault == "cancelled":
        with pytest.raises(asyncio.CancelledError):
            await review_result(app, review_args(env[5]))
    else:
        await review_result(app, review_args(env[5]))
        assert output[-1].entry.kind == "error"
        if fault == "record-error":
            assert "inadmissible primary evidence" in output[-1].entry.text
    assert env[4].latest_result(env[5].id).assessment_source == "agent"
    assert not env[2].observations._reviews
    assert env[2].active == 0


@pytest.mark.asyncio
async def test_inflight_probe_blocks_start_result_and_stale_send(runtime, tmp_path, monkeypatch):
    env = await setup(runtime, tmp_path)
    await start(env)
    entered, release = asyncio.Event(), asyncio.Event()
    rights = env[2].engagement.http_permissions
    original = rights.reserve_when_ready
    async def reserve(*args):
        entered.set()
        await release.wait()
        return await original(*args)
    monkeypatch.setattr(rights, "reserve_when_ready", reserve)
    probe = asyncio.create_task(env[0].execute("http", request(env[5]), None, env[1]))
    await asyncio.wait_for(entered.wait(), 2)
    for args in ({"action": "start_validation", "candidate_id": env[5].id},
                 {"action": "record_result", "candidate_id": env[5].id, "skill_name": GENERIC_VALIDATOR, "outcome": "blocked"}):
        with pytest.raises(ExecutionBlocked, match="in-flight"):
            await env[0].execute("workflow", args, None, env[1])
    env[4].objective.id = "changed"
    release.set()
    with pytest.raises(ValueError, match="provenance"):
        await probe
    assert not runtime[4] and not env[2].generic_validation.in_flight


@pytest.mark.asyncio
async def test_grant_budget_and_execution_budget_cannot_refill(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    await start(env)
    rights = env[2].engagement.http_permissions
    rights.activate(ORIGIN, HTTPLimits(requests=1, rate=1000, burst=1))
    await env[0].execute("http", request(env[5]), None, env[1])
    env[1].set_yolo(False)
    env[1].set_yolo(True)
    with pytest.raises(HTTPBlocked, match="budget"):
        await env[0].execute("http", request(env[5], True), None, env[1])
    assert len(runtime[4]) == 1 and not env[3].requests
    await result(env, "blocked", deferred_reason="native budget exhausted")
    assert (await start(env)).startswith("error:")
    env[2].max_calls = env[2].used
    with pytest.raises(ExecutionBlocked, match="budget"):
        await env[0].execute("workflow", {"action": "list"}, None, env[1])


@pytest.mark.asyncio
async def test_questions_only_collect_missing_input_and_reuse_answers(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    await start(env)
    ask: Any = SimpleNamespace(ask=AsyncMock(return_value="fixture account"))
    env[0].register(AskUserTool(ask))
    args = {"questions": [{"question": "Which account should supply the read context?"}]}
    for _ in range(2):
        assert "fixture account" in await env[0].execute("ask_user", args, None, env[1])
    assert ask.ask.await_count == 1
    with pytest.raises(ExecutionBlocked, match="duplicate"):
        await env[0].execute("ask_user", {"questions": [{"question": "Do I have permission to test this target?"}]}, None, env[1])
    assert ask.ask.await_count == 1 and not env[3].requests


@pytest.mark.asyncio
async def test_reserved_identifier_not_a_skill_or_completion(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    with pytest.raises(SkillMetadataError, match="reserved"):
        env[6].skills.add(expert(GENERIC_VALIDATOR))
    with pytest.raises(ValueError, match="unknown skill"):
        await LoadSkillTool(env[6].skills).run({"name": GENERIC_VALIDATOR})
    assert (await env[6].run({"action": "complete_skill", "skill_name": GENERIC_VALIDATOR}, None, env[1])).startswith("error:")
    assert GENERIC_VALIDATOR not in env[4].completed_skills


@pytest.mark.asyncio
async def test_unknown_ids_and_invalid_observation_arguments_are_tool_errors(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    assert (await env[6].run({"action": "start_validation", "candidate_id": "unknown"}, None, env[1])).startswith("error: unknown candidate")
    await start(env)
    ref = await evidence(env, tmp_path)
    output = await result(env, refs=[ref], observation_ids=[{}])
    assert output.startswith("error: observation_ids")


@pytest.mark.asyncio
async def test_planner_whole_target_feedback_and_resume(runtime, tmp_path):
    env = await setup(runtime, tmp_path, mode="whole_target")
    state, c = env[4], env[5]
    routes = {c.id: resolve_validation_route(env[6].skills, c.candidate_class)}
    context = PlannerContext(objective_mode="whole_target", objective_id=state.objective.id,
        completed_phases=frozenset({"recon", "enumeration", "input_analysis"}),
        workflow_status="actionable", candidates=(PlannerCandidate(c.id, c.candidate_class, "queued", generic_startable=True),),
        validation_routes=routes)
    plan = build_decision_plan("continue", [], env[6].target, context)
    assert plan is not None
    assert plan.candidate_id == c.id and plan.recommended_skill is None
    assert "start_validation" in plan.guidance and "insufficient-evidence" in plan.guidance
    kwargs: dict[str, Any] = dict(target_origin=ORIGIN, available_phases=frozenset(), validator_classes=frozenset(),
                  coverage_sync_available=True, generic_eligible_candidate_ids=frozenset({c.id}))
    assert state.whole_target_status(**kwargs)[0] == "actionable"
    await start(env)
    ref = await evidence(env, tmp_path)
    await result(env, refs=[ref])
    assert state.whole_target_status(**kwargs)[0] == "actionable"  # confirmed Finding remains pending
    before = state.completed_phases()
    output = await env[0].execute("workflow", {"action": "record_input", "endpoint": "/new", "method": "GET",
        "parameter": "q", "location": "query", "source": "validation-feedback"}, None, env[1])
    assert json.loads(output)["ok"] and state.completed_phases() == before
    restored = WorkflowState.from_dict(json.loads(json.dumps(state.to_dict())))
    restored_result = restored.latest_result(c.id)
    assert restored_result is not None and restored_result.skill_name == GENERIC_VALIDATOR
    assert restored.evidence[ref].is_resolvable(tmp_path)
    assert restored.candidates[c.id].status == "validated"
    legacy = Candidate.from_dict({"candidate_class": "sqli", "target": ORIGIN})
    assert legacy is not None and legacy.objective_id is None
    assert ValidationResult.from_dict({"candidate_id": legacy.id, "skill_name": "sql-injection", "outcome": "blocked"})


def agent_for(env):
    registry, p, policy, _, state, _, tool, _ = env
    return Agent(AgentOptions(client=FakeClient([]), tools=registry, skills=tool.skills,
        prompter=p, store=None, target=tool.target, workflow=state, engagement_state=policy.engagement))


class ReviewCompletionStream(StreamingClient):
    def name(self):
        return "offline-review-stream"

    def model(self):
        return "offline-review-stream"

    async def chat(self, request, signal=None):
        return ChatResponse(Message(role="assistant", content="All complete."), finish_reason="stop")

    async def chat_stream(self, request, on_delta, signal=None):
        on_delta("All complete.")
        return await self.chat(request, signal)


@pytest.mark.asyncio
async def test_f11_registry_allows_no_candidate_review_with_generic_records(runtime, tmp_path):
    env = await setup(runtime, tmp_path, mode="whole_target", phase_artifact_ref="artifacts/input-review.md")
    goal = env[4].objective.add_requested_goal("xss")
    marker = env[4].phase_completions[f"{env[4].objective.id}:input_analysis"]
    path = tmp_path / marker.artifact_ref
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("Reviewed whole-target input inventory; no XSS candidate.")
    assert env[2].generic_validation.restricted()
    payload = json.loads(await env[0].execute("workflow", {
        "action": "review_no_candidate", "goal_id": goal.id,
        "artifact_ref": marker.artifact_ref,
    }, None, env[1]))
    assert payload["ok"]
    assert goal.status == "no_candidate"
    assert payload["class_specific_validation_performed"] is False
    assert env[4].validation_results == []
    assert env[4].persisted_findings == {}
    rejected = await env[0].execute("workflow", {
        "action": "review_no_candidate", "goal_id": "goal_missing",
    }, None, env[1])
    assert rejected.startswith("error:")
    assert env[4].validation_results == []


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["target", "phase", "inventory", "artifact", "conflict", "inflight", "cancelled"])
async def test_f11_registry_review_keeps_existing_prerequisite_gates(runtime, tmp_path, fault):
    env = await setup(runtime, tmp_path, mode="whole_target", phase_artifact_ref="artifacts/input-review.md")
    state = env[4]
    goal = state.objective.add_requested_goal("xss")
    marker = state.phase_completions[f"{state.objective.id}:input_analysis"]
    path = tmp_path / marker.artifact_ref
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("Completed input-analysis inventory.")
    if fault == "target":
        env[6].target.set_base_url("https://other.test")
    elif fault == "phase":
        state.phase_completions.pop(marker.key)
    elif fault == "inventory":
        item, _ = state.add_attack_surface_input(AttackSurfaceInput(
            state.objective.id, ORIGIN, endpoint="/unreviewed", parameter="q",
        ))
        state.set_input_disposition(item.id, "blocked", reason="operator action required")
    elif fault == "artifact":
        path.write_text("")
    elif fault == "conflict":
        state.add_candidate(Candidate("xss", target=ORIGIN, endpoint="/search", objective_id=state.objective.id))
    elif fault == "inflight":
        env[2].generic_validation.in_flight[env[5].id] = 1
    elif fault == "cancelled":
        state.set_requested_goal_status(goal, "cancelled")
    try:
        rejected = await env[0].execute("workflow", {
            "action": "review_no_candidate", "goal_id": goal.id, "artifact_ref": marker.artifact_ref,
        }, None, env[1])
        assert rejected.startswith("error:")
    except ExecutionBlocked:
        assert fault == "inflight"
    assert goal.status != "no_candidate"
    assert state.validation_results == []
    assert state.persisted_findings == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("pending,synthesis", [
    ("finding", False), ("coverage", False), ("none", False), ("finding", True),
])
async def test_f02_direct_stream_respects_generic_completion_obligations(runtime, tmp_path, monkeypatch, pending, synthesis):
    env = await setup(runtime, tmp_path)
    if synthesis:
        env[6].skills.add(expert("disabled-xss", "cross-site-scripting"))
        env[6].skills.set_disabled("disabled-xss", True)
        assert resolve_validation_route(env[6].skills, "xss").kind == "unavailable"
    await start(env)
    ref = await evidence(env, tmp_path)
    await result(env, refs=[ref])
    app, _ = app_for(env)
    await review_result(app, review_args(env[5]))
    assert certificate(env, ref) is not None
    if pending != "finding":
        finding = ConfirmFindingTool(Store(project_directory=tmp_path), workflow=env[4])
        env[0].register(finding)
        await env[0].execute("confirm_finding", {
            "candidate_id": env[5].id, "title": "bounded redirect", "severity": "low",
            "url": ORIGIN + env[5].endpoint, "observed_impact": "bounded response",
            "potential_impact": "No additional impact assessed.",
        }, None, env[1])
    if pending == "coverage":
        monkeypatch.setattr(env[6].coverage, "ensure_validation_mark",
                            AsyncMock(side_effect=OSError("offline coverage write failure")))
        env[4].latest_result(env[5].id).coverage_synced = False
        recorded = json.loads(await env[0].execute("workflow", {"action": "sync_coverage", "candidate_id": env[5].id}, None, env[1]))
        assert recorded["coverage_sync"] == "pending"
        assert env[4].latest_result(env[5].id).coverage_synced is False
    goal = env[4].objective.add_requested_goal(env[5].candidate_class)
    env[4].link_requested_goal_candidate(goal.id, env[5].id)
    agent = agent_for(env)
    agent.client = ReviewCompletionStream()
    agent.streaming_enabled = True
    agent._reconcile_requested_goals()
    assert goal.status == "tested_confirmed"
    if synthesis:
        env[4].objective.add_requested_goal("xss")
    collector = collect()
    await agent.run("continue", FakeSignal(), collector["sink"])
    visible = "".join(e.get("text", "") for e in collector["events"]
                      if e["type"] in {"assistant-text", "assistant-delta"})
    if pending == "none":
        assert visible == "All complete."
        assert collector["events"][-1]["stop_reason"] == "final_response"
    else:
        assert "All complete." not in visible
        assert "incomplete" in visible
        assert collector["events"][-1]["stop_reason"] == "workflow_blocked"
        assert agent.history[-1].content == visible
        assert all(m.content != "All complete." for m in agent.history if m.role == "assistant")


@pytest.mark.asyncio
async def test_goal_metadata_does_not_invalidate_verified_generic_context(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    boundary = env[2].generic_validation
    before = boundary.admit_probe(env[0].get("http"), env[5].id)
    goal = env[4].objective.add_requested_goal(env[5].candidate_class)
    env[4].link_requested_goal_candidate(goal.id, env[5].id)
    env[4].set_requested_goal_status(goal, "in_progress", reason="Updated goal summary.")
    assert boundary.admit_probe(env[0].get("http"), env[5].id) == before
    assert json.loads(await start(env))["ok"]
    env[5].endpoint = "/return?next=%2Fhome&keep=2"
    with pytest.raises(ValueError, match="proposal.*mismatch"):
        boundary.admit_probe(env[0].get("http"), env[5].id)


@pytest.mark.asyncio
@pytest.mark.parametrize("active", [False, True])
async def test_agent_allowlist_precedes_active_skills(runtime, tmp_path, active):
    env = await setup(runtime, tmp_path)
    env[0].register(ShellTool())
    agent = agent_for(env)
    await start(env)
    if active:
        env[6].skills.add(expert("other", "sqli"))
        agent.active_skills.add("other")
    assert not agent.is_tool_allowed("shell", {"command": "echo fixture"}).ok
    assert not agent.is_tool_allowed("web_search", {"query": "fixture"}).ok
    assert agent.is_tool_allowed("http", request(env[5])).ok
    assert GENERIC_VALIDATOR not in agent.active_skills


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["missing", "duplicate", "stale", "truncated", "wrong-outcome"])
async def test_fixture_verifier_cannot_use_forged_or_incomplete_observations(runtime, tmp_path, fault):
    env = await setup(runtime, tmp_path)
    await start(env)
    await env[0].execute("http", request(env[5]), None, env[1])
    ref = await evidence(env, tmp_path)
    ids = list(env[2].observations._items)
    store = env[2].observations
    # Test-only contract; no generic production adapter is installed.
    store.register_verifier("open-redirect", lambda _, items: VerifiedResult(
        "not-confirmed" if fault == "wrong-outcome" else "confirmed", "fixture", "info",
        tuple(i.id for i in items)))
    if fault == "missing":
        ids = ["obs_forged"]
    elif fault == "duplicate":
        ids *= 2
    elif fault == "stale":
        store._items[ids[0]] = replace(store._items[ids[0]], epoch="old")
    elif fault == "truncated":
        store._items[ids[0]] = replace(store._items[ids[0]], complete=False)
    response = await result(env, refs=[ref], observation_ids=ids)
    if fault == "wrong-outcome":
        assert json.loads(response)["result"]["outcome"] == "confirmed"  # diagnostic callback has no authority
        assert env[4].eligible_for_finding(env[5].id)
    else:
        assert response.startswith("error:") and not env[4].validation_results
        assert await env[6].coverage.list() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["none", "save", "objective-during-save", "policy-missing", "registry-missing"])
async def test_verified_finding_pipeline_and_save_failures(runtime, tmp_path, monkeypatch, fault):
    env = await setup(runtime, tmp_path, mode="whole_target")
    await start(env)
    ref = await evidence(env, tmp_path)
    await result(env, refs=[ref])
    app, output = app_for(env)
    await review_result(app, review_args(env[5]))
    assert certificate(env, ref) is not None
    store = Store(project_directory=tmp_path)
    finding = ConfirmFindingTool(store, workflow=env[4])
    env[0].register(finding)
    if fault == "save":
        monkeypatch.setattr(store, "save", AsyncMock(side_effect=OSError("fixture save failure")))
    elif fault == "objective-during-save":
        async def save(_):
            env[4].objective.id = "changed"
            return "fixture.md"
        monkeypatch.setattr(store, "save", save)
    elif fault == "policy-missing":
        env[1].execution_policy = None
    elif fault == "registry-missing":
        env[2].generic_validation.skills = None
    args = {"candidate_id": env[5].id, "title": "bounded redirect", "severity": "critical",
            "url": ORIGIN + env[5].endpoint, "observed_impact": "model claim", "potential_impact": "No additional impact assessed."}
    if fault == "none":
        output = await env[0].execute("confirm_finding", args, None, env[1])
        assert "written to" in output and env[4].finding_is_persisted(env[5].id)
        assert agent_for(env)._whole_target_state()[0] == "completed"
        reports = list((tmp_path / "artifacts/findings").glob("*.md"))
        assert len(reports) == 1
        text = reports[0].read_text()
        assert "**Assessment source:** operator" in text and "critical" not in text and "model claim" not in text
    else:
        with pytest.raises((ValueError, ExecutionBlocked, OSError)):
            await env[0].execute("confirm_finding", args, None, env[1])
        assert not env[4].finding_is_persisted(env[5].id)


@pytest.mark.asyncio
async def test_restored_generic_result_is_not_a_certificate_or_execution_right(runtime, tmp_path):
    env = await setup(runtime, tmp_path, mode="whole_target")
    await start(env)
    ref = await evidence(env, tmp_path)
    await result(env, refs=[ref])
    app, _ = app_for(env)
    await review_result(app, review_args(env[5], "not-confirmed"))
    raw = json.loads(json.dumps(env[4].to_dict()))
    restored = WorkflowState.from_dict(raw)
    env[4].replace_from(restored)
    env[2].observations._results.clear()
    agent = agent_for(env)
    assert agent._whole_target_state()[0] == "completed"
    assert (await start(env)).startswith("error:")
    env[1].execution_policy = None
    assert not agent.is_tool_allowed("shell", {"command": "echo fixture"}).ok
    assert agent._whole_target_state()[0] == "blocked"
    assert restored.evidence[ref].is_resolvable(tmp_path)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["registry", "target", "objective", "candidate"])
async def test_recheck_generic_after_native_permission_await(runtime, tmp_path, monkeypatch, change):
    env = await setup(runtime, tmp_path)
    await start(env)
    rights = env[2].engagement.http_permissions
    original = rights.authorize
    async def authorize(*args):
        receipt = await original(*args)
        if change == "registry":
            env[6].skills.add(expert())
        elif change == "target":
            env[6].target.set_base_url("http://127.0.0.1:3001")
        elif change == "objective":
            env[4].objective.id = "another"
        else:
            env[5].parameter = "other"
        return receipt
    monkeypatch.setattr(rights, "authorize", authorize)
    with pytest.raises((ValueError, UserControlledRefusal)):
        await env[0].execute("http", request(env[5]), None, env[1])
    assert not runtime[4] and not env[2].generic_validation.in_flight


@pytest.mark.asyncio
async def test_bounded_rate_concurrency_wait_and_decoded_byte_cap(runtime, tmp_path, monkeypatch):
    env = await setup(runtime, tmp_path)
    await start(env)
    sent = []
    def handler(request):
        sent.append(request)
        return httpx.Response(302, headers={"Location": ORIGIN + "/other"}, content=b"x" * 100, request=request)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: REAL_CLIENT(transport=httpx.MockTransport(handler), **kwargs))
    env[2].engagement.http_permissions.activate(ORIGIN, HTTPLimits(requests=4, rate=100, burst=1, concurrency=1))
    outputs = await asyncio.gather(*[env[0].execute("http", {**request(env[5]), "max_response_bytes": 8}, None, env[1]) for _ in range(3)])
    assert all(output.truncated for output in outputs)
    assert len(sent) == 3 and all(r.url.path == "/return" for r in sent)
    assert not env[3].requests and not env[2].generic_validation.in_flight


@pytest.mark.asyncio
async def test_yolo_off_retains_exact_native_permission_behavior(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    await start(env)
    env[2].engagement.http_permissions.activate(ORIGIN, HTTPLimits(), "confirm-each")
    env[1].set_yolo(False)
    with pytest.raises(HTTPBlocked):
        await env[0].execute("http", request(env[5]), None, env[1])
    assert len(env[3].requests) == 1 and not runtime[4]
    # Native denial is suppressed; rewording cannot open another dialog.
    with pytest.raises((HTTPBlocked, ExecutionBlocked)):
        await env[0].execute("http", request(env[5]), None, env[1])
    assert len(env[3].requests) == 1
    assert env[5].status == "deferred" and env[4].latest_result(env[5].id).outcome == "blocked"


@pytest.mark.asyncio
async def test_multiple_generic_starts_and_reserved_expert_override_rejected(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    other, _ = env[4].add_candidate(Candidate(candidate_class="cors-misconfiguration", target=ORIGIN,
        endpoint="/fixture", method="GET", parameter="Origin", location="header", objective_id=env[4].objective.id, status="queued"))
    await start(env)
    output = await env[6].run({"action": "start_validation", "candidate_id": other.id}, None, env[1])
    assert output.startswith("error:") and other.status == "queued"
    assert (await env[6].run({"action": "record_result", "candidate_id": env[5].id, "skill_name": "expert", "outcome": "blocked"}, None, env[1])).startswith("error:")


@pytest.mark.asyncio
async def test_file_receipt_rechecks_objective_after_permission_review(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    await start(env)
    tool = env[0].get("file_write")
    args = {"path": str(env[2].generic_validation.proof_path(env[5])), "content": "fixture"}
    receipt = env[2].prepare(tool, args)
    env[4].objective = WorkflowObjective("new", "direct", ORIGIN)
    with pytest.raises(ExecutionBlocked, match="provenance"):
        env[2].start(receipt, tool, args, None)
    assert not Path(args["path"]).exists()


@pytest.mark.asyncio
async def test_requeued_or_restored_result_does_not_authorize_probe_retry(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    await start(env)
    await result(env, "blocked", deferred_reason="native policy blocked")
    env[4].set_candidate_status(env[5].id, "queued")
    assert (await start(env)).startswith("error:")
    agent = agent_for(env)
    plan = build_decision_plan("continue", [], env[6].target, agent._planner_context())
    assert plan is not None and plan.recommended_skill is None and "unresolved" in plan.guidance
    assert "Call workflow(action=start_validation" not in plan.guidance
    env[4].set_candidate_status(env[5].id, "validating")
    with pytest.raises(ExecutionBlocked, match="saved/requeued"):
        await env[0].execute("http", request(env[5]), None, env[1])
    assert not runtime[4] and not env[3].requests
    agent._initialize_request_objective(f"Retest candidate {env[5].id}", True)
    assert env[4].objective.mode == "candidate_validation"
    bind_context(env)
    plan = build_decision_plan(f"Retest candidate {env[5].id}", [], env[6].target, agent._planner_context())
    assert plan is not None and "start_validation" in plan.guidance
    assert json.loads(await start(env))["ok"]
    assert (await env[0].execute("http", request(env[5]), None, env[1])).http_status == 200


@pytest.mark.asyncio
async def test_generic_context_missing_does_not_auto_requeue_old_deferred(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    candidate = env[5]
    env[4].set_candidate_status(candidate.id, "deferred")
    output = json.loads(await env[6].run({"action": "record_candidate", "candidate_class": candidate.candidate_class,
        "endpoint": candidate.endpoint, "method": candidate.method, "parameter": candidate.parameter,
        "location": candidate.location}, None, env[1]))
    assert not output["created"] and candidate.status == "deferred"
    assert json.loads(await start(env))["ok"]  # Explicit start resolves context, never auto-requeues.


@pytest.mark.asyncio
async def test_overlapping_generic_reviews_only_publish_current_ticket(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    await start(env)
    ref = await evidence(env, tmp_path)
    await result(env, refs=[ref])
    app, output = app_for(env)
    entered, release = asyncio.Event(), asyncio.Event()
    calls = 0
    async def ask(*_):
        nonlocal calls
        calls += 1
        if calls == 1:
            entered.set()
            await release.wait()
        return Decision.ALLOW_ONCE
    env[3].ask = ask
    first = asyncio.create_task(review_result(app, review_args(env[5])))
    await asyncio.wait_for(entered.wait(), 2)
    # Different exact outcome avoids registry's equivalent-invocation review
    # suppression, exercising the independent candidate review ticket.
    await review_result(app, review_args(env[5], "not-confirmed"))
    release.set()
    await first
    trusted = certificate(env, ref)
    assert trusted is not None
    assert trusted.outcome == "not-confirmed"
    assert env[4].latest_result(env[5].id).outcome == "not-confirmed"
    assert any(item.entry.kind == "error" for item in output)
    assert not env[2].observations._reviews and env[2].active == 0


@pytest.mark.asyncio
async def test_auth_context_missing_or_changed_before_send_is_blocked(runtime, tmp_path, monkeypatch):
    env = await setup(runtime, tmp_path)
    env[5].auth_context_ref = "fixture-principal"
    assert (await start(env)).startswith("error:")
    args = {**request(env[5]), "auth_context_ref": "fixture-principal"}
    with pytest.raises(ExecutionBlocked):
        await env[0].execute("http", args, None, env[1])
    tool = env[0].get("http")
    from src.target.origin import HTTPOrigin
    identity_key = (HTTPOrigin.from_url(ORIGIN), "fixture-principal")
    tool.context_store._authorization[identity_key] = "Bearer fixture-first"
    bind_context(env)
    assert json.loads(await start(env))["ok"]
    original = tool.permissions.authorize
    async def authorize(*args):
        receipt = await original(*args)
        tool.context_store._authorization[identity_key] = "Bearer fixture-changed"
        return receipt
    monkeypatch.setattr(tool.permissions, "authorize", authorize)
    with pytest.raises(ValueError, match="baseline/auth"):
        await env[0].execute("http", args, None, env[1])
    assert not runtime[4]


@pytest.mark.asyncio
async def test_generic_logical_origin_survives_native_dns_pinning(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    origin = "http://lab.test:3000"
    env[6].target.set_base_url(origin)
    env[2].engagement.reset_to_origin(origin)
    env[4].objective.target_origin = origin
    env[5].target = origin
    env[2].vetted_ips[origin] = ("127.0.0.1",)
    env[2].engagement.http_permissions.activate(origin, HTTPLimits())
    bind_context(env)
    await start(env)
    assert (await env[0].execute("http", request(env[5], True), None, env[1])).http_status == 200
    assert runtime[4][0].url.host == "127.0.0.1" and runtime[4][0].headers["host"] == "lab.test:3000"
    assert not env[3].requests


@pytest.mark.asyncio
async def test_workflow_cannot_read_arbitrary_source_or_list_old_objective(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    await start(env)
    (tmp_path / "arbitrary.txt").write_text("unrelated project content")
    output = await env[0].execute("workflow", {"action": "record_evidence", "candidate_id": env[5].id,
        "evidence_path": "arbitrary.txt"}, None, env[1])
    assert output.startswith("error:") and not env[4].evidence
    old, _ = env[4].add_candidate(Candidate(candidate_class="sql-injection", target=ORIGIN,
        endpoint="/old", method="GET", objective_id="old-objective"))
    listed = json.loads(await env[0].execute("workflow", {"action": "list"}, None, env[1]))
    assert env[5].id in [c["id"] for c in listed["candidates"]]
    assert old.id not in [c["id"] for c in listed["candidates"]]


@pytest.mark.asyncio
async def test_generic_captured_replay_uses_existing_input_builder(runtime, tmp_path):
    from src.browser.store import CaptureStore
    env = await setup(runtime, tmp_path)
    capture = CaptureStore()
    ingested = capture.ingest({"id": "redirect-baseline", "method": "GET", "url": ORIGIN + env[5].endpoint,
        "requestHeaders": [{"name": "User-Agent", "value": "Fixture/1"}, {"name": "X-Keep", "value": "unchanged"}]})
    tool = env[0].get("http")
    tool.capture_store = capture
    env[5].baseline_request_ref = ingested["baseline_request_ref"]
    bind_context(env)
    await start(env)
    output = await env[0].execute("http", {"candidate_id": env[5].id, "mutation_value": "https://example.com/",
        "phase": "validation"}, None, env[1])
    assert output.http_status == 200
    assert runtime[4][0].url.params["next"] == "https://example.com/"
    assert runtime[4][0].url.params["keep"] == "1" and runtime[4][0].headers["X-Keep"] == "unchanged"
    assert not env[3].requests


@pytest.mark.parametrize("headers", [{"Cookie": "sid=generic-cookie"},
    {"Authorization": "Bearer generic-token"},
    {"Cookie": "sid=generic-cookie", "Authorization": "Bearer generic-token"}])
async def test_generic_capture_uses_same_bounded_credential_gate(runtime, tmp_path, headers):
    from src.browser.store import CaptureStore
    env = await setup(runtime, tmp_path)
    capture = CaptureStore()
    ingested = capture.ingest({"kind": "burp", "id": "generic", "method": "GET",
        "url": ORIGIN + env[5].endpoint, "requestHeaders": headers})
    tool = env[0].get("http")
    tool.capture_store = capture
    env[5].baseline_request_ref = ingested["baseline_request_ref"]
    bind_context(env)
    await start(env)
    args = {"candidate_id": env[5].id, "phase": "validation"}
    pending = await env[0].execute("http", args, None, env[1])
    assert pending.status == 'error' and pending.error_kind == 'permission_denied'
    assert pending.startswith('pending:') and pending.http_status is None
    assert not runtime[4] and env[4].latest_result(env[5].id) is None
    assert env[2].generic_validation.started_candidate == env[5].id
    env[3].decision = Decision.ALLOW_ONCE
    for extra in ({}, {"mutation_value": "https://example.com/"}, {"mutation_value": "https://example.com/"}):
        assert (await env[0].execute("http", args | extra, None, env[1])).http_status == 200
    assert len(runtime[4]) == 3 and len(env[3].requests) == 2  # Denial then one bounded review.
    assert all(question.force_operator for question in env[3].requests)
    assert not tool.context_store._cookies and not tool.context_store._authorization
    for actual in runtime[4]:
        for key, value in headers.items():
            assert actual.headers[key] == value
    # Raw/native reconstruction cannot import this capture into the shared context.
    baseline = env[2].generic_validation.baseline(tool, env[5])
    with pytest.raises(ExecutionBlocked, match="isolated replay"):
        await env[0].execute("http", {"phase": "validation", "url": str(baseline.url),
            "headers": dict(baseline.headers)}, None, env[1])


@pytest.mark.asyncio
@pytest.mark.parametrize("loss", ["fresh", "clear", "legacy"])
async def test_generic_baseline_cannot_resurrect_from_reused_external_id(runtime, tmp_path, loss):
    from src.browser.store import CaptureStore
    env = await setup(runtime, tmp_path)
    capture = CaptureStore()
    payload = {"id": "reused", "method": "GET", "url": ORIGIN + env[5].endpoint,
               "requestHeaders": [{"name": "X-Keep", "value": "original"}]}
    ingested = capture.ingest(payload)
    tool = env[0].get("http")
    tool.capture_store = capture
    candidate = env[5]
    candidate.baseline_request_ref = ingested["baseline_request_ref"]
    boundary = env[2].generic_validation
    assert boundary.baseline(tool, candidate).headers["X-Keep"] == "original"
    if loss == "fresh":
        tool.capture_store = CaptureStore()
    elif loss == "clear":
        capture.clear()
    else:
        candidate.baseline_request_ref = ingested["id"]
    # Same geometry and external ID cannot prove a replayable baseline binding.
    tool.capture_store.ingest({**payload, "requestHeaders": [{"name": "X-Keep", "value": "changed"}]})
    with pytest.raises(ValueError, match="baseline unavailable or unbound; recapture required"):
        boundary.baseline(tool, candidate)
    assert not runtime[4] and not env[3].requests
