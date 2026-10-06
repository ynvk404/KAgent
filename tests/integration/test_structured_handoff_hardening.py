"""Offline regressions for structured handoff F1–F4 through runtime boundaries."""
from __future__ import annotations

import base64
import json
from copy import deepcopy
from pathlib import Path

import pytest

from src.browser.store import CaptureStore, CapturedRequest
from src.engagement.state import EngagementState
from src.permission.permission import AlwaysAllow
from src.session.store import Store
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.common.browser_capture import BrowserCaptureGetTool, BrowserCaptureBurpTasksTool
from src.tools.common.registry import Registry
from src.tools.http.http_tool import HTTPTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.evidence import EvidenceArtifact
from src.workflow.goals import RequestedGoal
from src.workflow.state import AttackSurfaceInput, Candidate, ValidationResult, WorkflowObjective, WorkflowState
from tests.helpers.workflow import record_completed_phase

ORIGIN = "https://target.test"


def runtime(tmp_path):
    state = WorkflowState(objective=WorkflowObjective(
        "handoff", "whole_target", ORIGIN, requested_goals=[RequestedGoal("xss")],
    ))
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    registry = Registry()
    registry.register(WorkflowTool(state, Target(ORIGIN), skills=skills, evidence_root=tmp_path))
    return state, registry


async def execute(registry, action, **args):
    return await registry.execute("workflow", {"action": action, **args}, None, AlwaysAllow())


async def record(registry, action, **args):
    result = json.loads(await execute(registry, action, **args))
    assert result["ok"], result
    return result["input" if action == "record_input" else "candidate"]


def capture_payload(body='{"q":"old","other":"original"}'):
    return {"id": "reused", "method": "POST", "url": ORIGIN + "/api",
            "requestHeaders": [{"name": "Content-Type", "value": "application/json"}],
            "requestBody": body}


def http_tool(state, capture):
    engagement = EngagementState()
    engagement.initialize_target(ORIGIN)
    return HTTPTool(Target(ORIGIN), engagement, state, capture)


def replay_args(candidate_id):
    return {"phase": "validation", "candidate_id": candidate_id, "mutation_value": "new"}


@pytest.mark.asyncio
@pytest.mark.parametrize("replacement", ['{"q":"different","other":"original"}',
                                           '{"q":"old","other":"different"}'])
async def test_f1_restored_candidate_cannot_alias_reused_capture_id(tmp_path, replacement):
    state = WorkflowState()
    capture = CaptureStore()
    ingested = capture.ingest(capture_payload())
    view = json.loads(await BrowserCaptureGetTool(capture).run({"id": ingested["id"]}))
    candidate, _ = state.add_candidate(Candidate(
        "xss", target=ORIGIN, method="POST", endpoint="/api", parameter="q", location="body",
        baseline_request_ref=view["baseline_request_ref"], content_type="application/json",
    ))
    _, request = http_tool(state, capture).prepare(replay_args(candidate.id))
    assert request.content == b'{"q":"new","other":"original"}'
    session = Store.new_with_id(tmp_path, "baseline-restore")
    await session.save([], target=Target(ORIGIN), workflow=state)
    persisted = session.path.read_text()
    assert "requestHeaders" not in persisted and '"other"' not in persisted
    restored = session.load().workflow
    fresh = CaptureStore()
    assert fresh.ingest(capture_payload(replacement))["id"] == ingested["id"]
    with pytest.raises(ValueError, match="unavailable.*recapture required"):
        http_tool(restored, fresh).prepare(replay_args(candidate.id))


@pytest.mark.parametrize("operation", ["clear", "evict", "mutate", "fresh_same_request"])
def test_f1_old_binding_never_resurrects(operation):
    capture = CaptureStore(max_entries=100)
    payload = capture_payload()
    result = capture.ingest(payload)
    ref = result["baseline_request_ref"]
    assert capture.resolve_baseline(ref) is not None
    if operation == "clear":
        capture.clear()
    elif operation == "evict":
        for number in range(101):
            capture.ingest({**payload, "id": str(number)})
    elif operation == "mutate":
        row = capture.get_request(result["id"])
        assert row is not None
        row.request_body = '{"q":"old","other":"tampered"}'
        assert capture.resolve_baseline(ref) is None
        return
    else:
        capture = CaptureStore()
    current = capture.ingest(payload)
    assert current["baseline_request_ref"] != ref
    assert capture.resolve_baseline(ref) is None
    assert capture.resolve_baseline(current["baseline_request_ref"]) is not None


def test_f1_response_only_updates_preserve_replay_identity():
    capture = CaptureStore()
    result = capture.ingest(capture_payload())
    ref = result["baseline_request_ref"]
    for update in ({**capture_payload(), "respBody": "first", "status": 200},
                   {"id": "reused", "url": ORIGIN + "/api", "respBody": "second", "status": 201}):
        assert capture.ingest(update)["baseline_request_ref"] == ref
        resolved = capture.resolve_baseline(ref)
        assert isinstance(resolved, CapturedRequest) and resolved.request_body == capture_payload()["requestBody"]
    assert [row.method for row in capture.list_endpoints()] == ["POST"]


@pytest.mark.asyncio
async def test_f1_burp_task_binding_survives_session_but_not_fresh_store(tmp_path):
    state = WorkflowState()
    capture = CaptureStore()
    raw = b'POST /api HTTP/1.1\r\nHost: target.test\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{"q":"old"}'
    payload = {"action": "scan", "method": "POST", "url": ORIGIN + "/api",
               "rawRequestB64": base64.b64encode(raw).decode()}
    result = capture.ingest_burp_task(payload)
    view = json.loads(await BrowserCaptureBurpTasksTool(capture).run())[0]
    candidate, _ = state.add_candidate(Candidate(
        "xss", target=ORIGIN, method="POST", endpoint="/api", parameter="q", location="body",
        content_type="application/json", baseline_request_ref=view["baseline_request_ref"],
    ))
    assert http_tool(state, capture).prepare(replay_args(candidate.id))[1].content == b'{"q":"new"}'
    session = Store.new_with_id(tmp_path, "burp-restore")
    await session.save([], workflow=state)
    assert payload["rawRequestB64"] not in session.path.read_text()
    fresh = CaptureStore()
    assert fresh.ingest_burp_task(payload)["id"] == result["id"]
    with pytest.raises(ValueError, match="unavailable"):
        http_tool(session.load().workflow, fresh).prepare(replay_args(candidate.id))
    capture.clear()
    capture.ingest_burp_task(payload)
    assert capture.resolve_baseline(result["baseline_request_ref"]) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("ref", ["wr:reused", "burp-task-1", "tool-result:retained", "evidence_legacy"])
async def test_f1_legacy_refs_round_trip_but_never_bind_by_external_id(tmp_path, ref):
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate("xss", target=ORIGIN, method="POST", endpoint="/api",
                                                parameter="q", location="body", baseline_request_ref=ref))
    session = Store.new_with_id(tmp_path, "legacy-ref")
    await session.save([], workflow=state)
    restored = session.load().workflow
    assert restored.candidates[candidate.id].baseline_request_ref == ref
    capture = CaptureStore()
    capture.ingest(capture_payload())
    capture.ingest_burp_task({"action": "scan", "method": "POST", "url": ORIGIN + "/api"})
    with pytest.raises(ValueError, match="unavailable or unbound"):
        http_tool(restored, capture).prepare(replay_args(candidate.id))


@pytest.mark.asyncio
@pytest.mark.parametrize("rich", [False, True])
async def test_f2_media_shapes_are_distinct_through_workflow(tmp_path, rich):
    state, registry = runtime(tmp_path)
    inputs, candidates = [], []
    for media, sample in (("application/json", '{"q":"{INJECTION_POINT}"}'),
                          ("application/x-www-form-urlencoded", "q={INJECTION_POINT}"), (None, None)):
        inputs.append(await record(registry, "record_input", method="POST", endpoint="/api", parameter="q",
                                   location="body", content_type=media,
                                   **({"sample_payload": sample} if rich else {})))
        candidates.append(await record(registry, "record_candidate", candidate_class="xss", input_id=inputs[-1]["id"],
                                       **({"request_template": sample} if rich else {})))
    assert len({row["id"] for row in inputs}) == 3
    assert len({row["id"] for row in candidates}) == 3
    assert [row["content_type"] for row in inputs] == ["application/json", "application/x-www-form-urlencoded", None]
    assert [row["identity_media_type"] for row in candidates] == ["application/json", "application/x-www-form-urlencoded", ""]
    assert state.objective is not None
    assert len(state.objective.requested_goals[0].candidate_ids) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("left,right", [
    (" Application/JSON ; charset=utf-8 ", "application/json"),
    ("MULTIPART/FORM-DATA; boundary=one", "multipart/form-data; boundary=two"),
    ("Application/X-WWW-Form-Urlencoded", "application/x-www-form-urlencoded; charset=UTF-8"),
])
async def test_f2_normalized_media_identity_preserves_original_context(tmp_path, left, right):
    state, registry = runtime(tmp_path)
    first = await record(registry, "record_input", method="post", endpoint="/api", parameter="q", location="body", content_type=left)
    second = await record(registry, "record_input", method="POST", endpoint="/api", parameter="q", location="body", content_type=right)
    assert first["id"] == second["id"]
    assert second["content_type"] == left.strip()
    first_c = await record(registry, "record_candidate", candidate_class="xss", input_id=first["id"], content_type=left)
    second_c = await record(registry, "record_candidate", candidate_class="xss", input_id=first["id"], content_type=right)
    assert first_c["id"] == second_c["id"]
    assert second_c["content_type"] == left.strip()
    assert len(state.attack_surface_inputs) == len(state.candidates) == 1


@pytest.mark.asyncio
async def test_f2_anchored_enrichment_keeps_ids_links_and_session_context(tmp_path):
    state, registry = runtime(tmp_path)
    args = {"method": "POST", "endpoint": "/api", "parameter": "q", "location": "body", "baseline_request_ref": "baseline:opaque"}
    item = await record(registry, "record_input", **args)
    candidate = await record(registry, "record_candidate", candidate_class="xss", input_id=item["id"])
    rich_item = await record(registry, "record_input", **args, content_type="application/json", sample_payload='{"q":"old"}')
    rich_candidate = await record(registry, "record_candidate", candidate_class="xss", input_id=item["id"], request_template='{"q":"{INJECTION_POINT}"}')
    assert rich_item["id"] == item["id"] and rich_candidate["id"] == candidate["id"]
    assert rich_candidate["content_type"] == "application/json"
    assert rich_candidate["identity_media_type"] == ""  # identity remains explicitly unknown
    session = Store.new_with_id(tmp_path, "enriched")
    await session.save([], workflow=state)
    restored = session.load().workflow
    assert restored.to_dict() == state.to_dict()
    assert restored.attack_surface_inputs[item["id"]].candidate_ids == [candidate["id"]]
    assert restored.objective is not None
    assert restored.objective.requested_goals[0].candidate_ids == [candidate["id"]]
    # Redoing the same rich record uses the enriched canonical record.
    assert (await record(registry, "record_candidate", candidate_class="xss", input_id=item["id"], request_template='{"q":"{INJECTION_POINT}"}'))["id"] == candidate["id"]


@pytest.mark.asyncio
async def test_f2_legacy_session_preserves_result_evidence_goal_and_input_links(tmp_path):
    state, registry = runtime(tmp_path)
    item = await record(registry, "record_input", method="POST", endpoint="/api", parameter="q", location="body")
    candidate = await record(registry, "record_candidate", candidate_class="xss", input_id=item["id"])
    (tmp_path / "proof.md").write_text("Reproducible bounded proof")
    evidence = EvidenceArtifact.capture(candidate["id"], "proof.md", tmp_path)
    state.add_evidence(evidence)
    state.add_validation_result(ValidationResult(candidate["id"], "cross-site-scripting", "confirmed", evidence_refs=[evidence.id], objective_id="handoff"))
    session = Store.new_with_id(tmp_path, "legacy-media")
    await session.save([], workflow=state)
    data = json.loads(session.path.read_text())
    for key in ("candidates", "attack_surface_inputs"):
        for row in data["workflow"][key]:
            row.pop("identity_media_type")
            row["content_type"] = "application/json"  # prior schema had context but no media identity
    session.path.write_text(json.dumps(data))
    restored = session.load().workflow
    assert set(restored.candidates) == {candidate["id"]}
    assert restored.candidates[candidate["id"]].identity_media_type == ""
    assert restored.attack_surface_inputs[item["id"]].candidate_ids == [candidate["id"]]
    assert restored.objective is not None
    assert restored.objective.requested_goals[0].candidate_ids == [candidate["id"]]
    result = restored.latest_result(candidate["id"])
    assert result is not None and result.evidence_refs == [evidence.id]
    assert restored.eligible_for_finding(candidate["id"])
    await session.save([], workflow=restored)
    assert session.load().workflow.to_dict() == restored.to_dict()
    # An explicit legacy ID cannot swallow a conflicting supplied media type.
    before = deepcopy(restored.to_dict())
    conflict = Candidate.from_dict({**restored.candidates[candidate["id"]].to_dict(), "content_type": "application/x-www-form-urlencoded"})
    assert conflict is not None
    with pytest.raises(ValueError, match="conflicts"):
        restored.add_candidate(conflict)
    assert restored.to_dict() == before


CONFLICTS = [
    {"method": "GET"}, {"endpoint": "/other"}, {"parameter": "other"}, {"location": "query"},
    {"content_type": "application/x-www-form-urlencoded"}, {"baseline_request_ref": "baseline:other"},
    {"auth_context_ref": "admin"}, {"baseline_request_ref": ""}, {"auth_context_ref": ""},
    {"target": "https://other.test"}, {"objective_id": "other-objective"},
    {"endpoint": "https://other.test/api"},
]


@pytest.mark.asyncio
@pytest.mark.parametrize("override", CONFLICTS)
@pytest.mark.parametrize("duplicate", [False, True])
async def test_f3_failed_create_or_duplicate_is_atomic(tmp_path, override, duplicate):
    state, registry = runtime(tmp_path)
    item = await record(registry, "record_input", method="POST", endpoint="/api", parameter="q", location="body",
                        content_type="application/json", baseline_request_ref="baseline:one", auth_context_ref="user")
    if duplicate:
        await record(registry, "record_candidate", candidate_class="xss", input_id=item["id"], signals=["original"])
    before = json.dumps(state.to_dict(), sort_keys=True)
    result = await execute(registry, "record_candidate", candidate_class="xss", input_id=item["id"],
                           signals=["must not merge"], current_phase="must-not-change", **override)
    assert str(result).startswith("error:"), result
    assert json.dumps(state.to_dict(), sort_keys=True) == before


@pytest.mark.parametrize("override", [*CONFLICTS[:7], {"objective_id": "other-objective"}, {"target": "https://other.test"}])
def test_f3_canonical_add_and_link_cannot_bypass_compatibility(tmp_path, override):
    state, _ = runtime(tmp_path)
    item, _ = state.add_attack_surface_input(AttackSurfaceInput("handoff", ORIGIN, method="POST", endpoint="/api", parameter="q", location="body",
                                                                content_type="application/json", baseline_request_ref="baseline:one", auth_context_ref="user"))
    args = dict(candidate_class="xss", objective_id="handoff", target=ORIGIN, method="POST", endpoint="/api", parameter="q", location="body",
                content_type="application/json", baseline_request_ref="baseline:one", auth_context_ref="user")
    candidate = Candidate(**{**args, **override})
    before = deepcopy(state.to_dict())
    with pytest.raises(ValueError):
        state.add_candidate(candidate, input_id=item.id)
    assert state.to_dict() == before
    state.add_candidate(candidate)  # direct creation is still possible
    before = deepcopy(state.to_dict())
    with pytest.raises(ValueError):
        state.link_input_candidate(item.id, candidate.id)
    assert state.to_dict() == before


@pytest.mark.asyncio
async def test_f3_compatible_normalized_context_and_omitted_inheritance(tmp_path):
    state, registry = runtime(tmp_path)
    item = await record(registry, "record_input", method="post", endpoint="/api?q=old", parameter="q", location="body",
                        content_type="Application/JSON; charset=UTF-8", baseline_request_ref="baseline:one", auth_context_ref="user")
    inherited = await record(registry, "record_candidate", candidate_class="xss", input_id=item["id"])
    explicit = await record(registry, "record_candidate", candidate_class="xss", input_id=item["id"],
                            target="https://TARGET.test:443", method="pOsT", endpoint="https://target.test/api?q=old",
                            parameter="q", location="BODY", content_type="application/json", baseline_request_ref="baseline:one", auth_context_ref="user")
    for row in (inherited, explicit):
        assert row["method"] == "POST"
        assert row["baseline_request_ref"] == "baseline:one" and row["auth_context_ref"] == "user"
        assert row["id"] in state.attack_surface_inputs[item["id"]].candidate_ids
    direct = await record(registry, "record_candidate", candidate_class="sqli", endpoint="/direct", parameter="id")
    assert direct["id"] in state.candidates


@pytest.mark.asyncio
async def test_f3_failed_duplicate_context_merge_leaves_signals_goals_unchanged(tmp_path):
    state, registry = runtime(tmp_path)
    item = await record(registry, "record_input", method="POST", endpoint="/api", parameter="q", location="body", content_type="application/json", source_ref="shared")
    await record(registry, "record_candidate", candidate_class="xss", input_id=item["id"], request_template='{"q":"{INJECTION_POINT}","other":"one"}')
    before = deepcopy(state.to_dict())
    result = await execute(registry, "record_candidate", candidate_class="xss", input_id=item["id"],
                           request_template='{"q":"{INJECTION_POINT}","other":"two"}', signals=["new signal"], status="deferred")
    assert "conflicts" in str(result)
    assert state.to_dict() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("disposition,reason", [("analyzed", None), ("dropped", "Reviewed and excluded as out of scope")])
async def test_f4_late_inventory_review_and_session_semantics(tmp_path, disposition, reason):
    state, registry = runtime(tmp_path)
    for phase in ("recon", "enumeration", "input_analysis"):
        ref = f"artifacts/{phase}.md"
        path = tmp_path / ref
        path.parent.mkdir(exist_ok=True)
        path.write_text("Completed bounded inventory pass")
        record_completed_phase(state, phase, objective_id="handoff", target_origin=ORIGIN,
                               artifact_ref=ref, no_inputs_discovered=phase == "input_analysis")
    marker = deepcopy(state.phase_completions["handoff:input_analysis"].to_dict())
    assert state.objective is not None
    goal = state.objective.requested_goals[0]
    review = json.loads(await execute(registry, "review_no_candidate", goal_id=goal.id))
    assert review["goal"]["status"] == "no_candidate"
    original_binding = goal.review_binding
    item = await record(registry, "record_input", endpoint="/late", parameter="q", location="query")
    assert goal.status == "pending" and goal.review_binding is None
    assert "remains pending" in str(await execute(registry, "review_no_candidate", goal_id=goal.id))
    await execute(registry, "set_input_disposition", input_id=item["id"], disposition="blocked", disposition_reason="dependency unavailable")
    assert "remains blocked" in str(await execute(registry, "review_no_candidate", goal_id=goal.id))
    await execute(registry, "set_input_disposition", input_id=item["id"], disposition="pending")
    await execute(registry, "set_input_disposition", input_id=item["id"], disposition=disposition, disposition_reason=reason)
    review = json.loads(await execute(registry, "review_no_candidate", goal_id=goal.id))
    assert review["goal"]["status"] == "no_candidate" and goal.review_binding != original_binding
    assert not review["class_specific_validation_performed"]
    assert state.validation_results == [] and state.evidence == {}
    assert state.phase_completions["handoff:input_analysis"].to_dict() == marker
    session = Store.new_with_id(tmp_path, "late-input")
    await session.save([], workflow=state)
    restored = session.load().workflow
    assert restored.to_dict() == state.to_dict()
    assert restored.input_inventory_review_error() is None
    # Re-recording identical inventory is a semantic no-op.
    binding = goal.review_binding
    await record(registry, "record_input", endpoint="/late", parameter="q", location="query")
    assert goal.review_binding == binding
    # Disposition reason enrichment changes the inventory/review binding.
    await execute(registry, "set_input_disposition", input_id=item["id"], disposition=disposition, disposition_reason="Reviewed late input again")
    assert goal.status == "pending" and goal.review_binding is None
    json.loads(await execute(registry, "review_no_candidate", goal_id=goal.id))
    await record(registry, "record_candidate", candidate_class="xss", input_id=item["id"])
    assert "matching candidate exists" in str(await execute(registry, "review_no_candidate", goal_id=goal.id))
    assert state.phase_completions["handoff:input_analysis"].to_dict() == marker


def test_f4_other_objective_inventory_does_not_change_review_binding(tmp_path):
    state, _ = runtime(tmp_path)
    record_completed_phase(state, "input_analysis", objective_id="handoff", target_origin=ORIGIN,
                           artifact_ref="artifacts/review.md", no_inputs_discovered=True)
    objective = state.objective
    assert objective is not None
    goal = objective.requested_goals[0]
    binding = state.no_candidate_review_binding(goal, "a" * 64)
    state.mark_goal_no_candidate(goal.id, artifact_ref="artifacts/review.md", review_binding=binding)
    state.objective = WorkflowObjective("other", "whole_target", "https://other.test")
    item, _ = state.add_attack_surface_input(AttackSurfaceInput("other", "https://other.test", endpoint="/new"))
    state.set_input_disposition(item.id, "analyzed")
    state.objective = objective
    assert state.no_candidate_review_binding(goal, "a" * 64) == binding
    assert goal.status == "no_candidate" and goal.review_binding == binding
