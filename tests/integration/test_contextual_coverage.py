"""F7: offline production sync, persistence, query and completion regressions."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
from typing import Any

import pytest
from tests.helpers.workflow import run_workflow_fixture

from src.agent.agent import Agent, AgentOptions
from src.coverage.context import CoverageContext
from src.coverage.store import CoverageEntry, CoverageStore
from src.findings.store import Store as FindingsStore
from src.permission.permission import AlwaysAllow
from src.session.store import Store as SessionStore
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.common.registry import Registry as ToolRegistry
from src.tools.workflow.coverage import CoverageTool
from src.tools.workflow.finding import ConfirmFindingTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.state import (
    AttackSurfaceInput, Candidate, ValidationResult, WorkflowObjective, WorkflowState,
    validation_result_fingerprint, WorkflowMode,
)
from tests.helpers.workflow import record_completed_phase
from tests.helpers.agent_fakes import FakeClient

ORIGIN = "https://target.test"


def runtime(tmp_path: Path, *, mode: WorkflowMode = "direct", objective_id="f7"):
    state = WorkflowState(objective=WorkflowObjective(objective_id, mode, ORIGIN))
    coverage = CoverageStore(str(tmp_path / "coverage.json"))
    return state, coverage, WorkflowTool(state, Target(ORIGIN), coverage=coverage, evidence_root=tmp_path)


def add(state: WorkflowState, **overrides) -> Candidate:
    values: dict[str, Any] = dict(candidate_class="xss", target=ORIGIN, method="POST", endpoint="/search",
                  parameter="q", location="body", content_type="application/json",
                  objective_id=state.objective.id if state.objective else None)
    values.update(overrides)
    return state.add_candidate(Candidate(**values))[0]


def media(entry: CoverageEntry) -> str | None:
    assert entry.context is not None
    return entry.context.media_type


async def call(tool, action, **args):
    output = await run_workflow_fixture(tool, {"action": action, **args}, None, AlwaysAllow())
    return {"ok": False, "error": output} if output.startswith("error:") else json.loads(output)


async def record(tool: WorkflowTool, candidate: Candidate, outcome="not-confirmed", expect_error=False, **args):
    refs = []
    if outcome in {"confirmed", "not-confirmed"}:
        path = tool.evidence_root / (candidate.id + ".txt")
        path.write_text("Reproducible bounded offline fixture evidence", encoding="utf8")
        artifact = await call(tool, "record_evidence", candidate_id=candidate.id, evidence_path=path.name)
        assert artifact["ok"], artifact
        refs = [artifact["evidence"]["id"]]
    response = await call(tool, "record_result", candidate_id=candidate.id, skill_name="cross-site-scripting",
                          outcome=outcome, evidence_refs=refs, repeatable=True, **args)
    assert response["ok"] is not expect_error, response
    return response


@pytest.mark.asyncio
@pytest.mark.parametrize("left,right", [
    ({"location": "query"}, {"location": "body"}),
    ({"location": "header"}, {"location": "path"}),
    ({"location": "cookie"}, {"location": "query"}),
    ({"method": "GET"}, {"method": "POST"}),
    ({"method": "GET", "location": "query"}, {"method": "POST", "location": "body"}),
    ({"content_type": "application/json"}, {"content_type": "application/x-www-form-urlencoded"}),
    ({"auth_context_ref": "auth-A"}, {"auth_context_ref": "auth-B"}),
    ({"test_case": "one"}, {"test_case": "two"}),
    ({"content_type": None}, {"content_type": "application/json"}),
    ({"auth_context_ref": None}, {"auth_context_ref": "auth-A"}),
])
async def test_workflow_variants_do_not_collapse(tmp_path, left, right):
    state, store, tool = runtime(tmp_path)
    a, b = add(state, **left), add(state, **right)
    assert a.id != b.id
    assert (await record(tool, a))["coverage_sync"] == "synced"
    assert (await record(tool, b, "confirmed"))["coverage_sync"] == "synced"
    entries = await store.list()
    assert len(entries) == 2
    assert sorted(e.status for e in entries) == ["failed", "passed"]
    assert all(e.count == 1 for e in entries)
    assert {tuple(e.observationIds or []) for e in entries} == {
        (f"candidate:{a.id}",), (f"candidate:{b.id}",),
    }
    assert (await store.summary()).total == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("media1,media2", [
    ("application/json", " Application/JSON ; charset=utf-8 "),
    ("multipart/form-data; boundary=one", "MULTIPART/FORM-DATA; boundary=two"),
    ("application/x-www-form-urlencoded", "application/x-www-form-urlencoded; charset=UTF-8"),
])
async def test_canonical_media_normalization_projects_same_variant(tmp_path, media1, media2):
    state, store, tool = runtime(tmp_path)
    # Different persisted candidates (capture bindings) for one validation variant.
    a = add(state, content_type=media1, baseline_request_ref="capture-A")
    b = add(state, content_type=media2, baseline_request_ref="capture-B")
    assert a.id != b.id
    await record(tool, a)
    await record(tool, b)
    entries = await store.list()
    assert len(entries) == 1 and entries[0].count == 2
    assert entries[0].context is not None
    assert entries[0].context.media_type == media1.split(";", 1)[0]
    assert len(entries[0].observationIds or []) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("target,endpoint", [
    ("HTTPS://TARGET.TEST:443/base", "https://TARGET.TEST:443/search?q=x"),
    ("https://target.test", "/search?q=other"),
    ("https://target.test", "//TARGET.TEST:443/search"),
])
async def test_effective_port_absolute_relative_and_query_normalization(tmp_path, target, endpoint):
    state, store, tool = runtime(tmp_path)
    a = add(state, target=target, endpoint=endpoint, method=" post ", parameter=" q ", location=" BODY ")
    b = add(state, baseline_request_ref="different-capture")
    await record(tool, a)
    await record(tool, b)
    rows = await store.list()
    assert len(rows) == 1
    assert rows[0].endpoint == "POST /search" and rows[0].param == "q"
    assert rows[0].context == CoverageContext(objective_id="f7", target_origin=ORIGIN,
                                           method="POST", location="body", media_type="application/json")


@pytest.mark.asyncio
async def test_origin_and_objective_isolation_in_shared_projection(tmp_path):
    store = CoverageStore(str(tmp_path / "coverage.json"))
    for owner, origin in [("one", "https://a.test"), ("one", "https://b.test"),
                          ("two", "https://a.test"), ("one", "https://a.test:8443")]:
        state = WorkflowState(objective=WorkflowObjective(owner, "direct", origin))
        candidate = add(state, target=origin)
        tool = WorkflowTool(state, Target(origin), coverage=store, evidence_root=tmp_path)
        assert (await record(tool, candidate))["coverage_sync"] == "synced"
    rows = await store.list()
    assert len(rows) == 4
    assert {(e.context.objective_id, e.context.target_origin) for e in rows if e.context} == {
        ("one", "https://a.test"), ("one", "https://b.test"), ("two", "https://a.test"),
        ("one", "https://a.test:8443"),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("foreign", ["https://foreign.test/search", "//foreign.test/search"])
async def test_cross_origin_absolute_endpoint_fails_before_projection_mutation(tmp_path, foreign):
    state, store, tool = runtime(tmp_path)
    c = add(state, endpoint=foreign)
    response = await record(tool, c, expect_error=True)
    assert "origin mismatch" in response["error"]
    assert await store.list() == []
    assert state.latest_result(c.id) is None  # invalid identity publishes nothing


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome,dimension", [
    ("confirmed", "media"), ("not-confirmed", "media"), ("confirmed", "location"),
])
async def test_pending_sibling_remains_outstanding_and_exact_queries_do_not_overclaim(tmp_path, outcome, dimension):
    state, store, tool = runtime(tmp_path, mode="whole_target")
    a = add(state)
    b = add(state, **({"content_type": "application/x-www-form-urlencoded"}
                     if dimension == "media" else {"location": "query"}))
    for c in (a, b):
        item, _ = state.add_attack_surface_input(AttackSurfaceInput(
            objective_id="f7", target_origin=ORIGIN, method=c.method, endpoint=c.endpoint,
            parameter=c.parameter, location=c.location, content_type=c.content_type,
        ))
        state.link_input_candidate(item.id, c.id)
    await record(tool, a, outcome)
    # Also add an aggregate claim: canonical pending work must survive it.
    await store.mark(endpoint="POST /search", param="q", vulnClass="xss", status="failed")
    before = state.to_dict()
    status, actions, _ = state.whole_target_status(target_origin=ORIGIN,
        available_phases=frozenset({"recon", "enumeration", "input_analysis"}),
        validator_classes=frozenset({"cross-site-scripting"}), coverage_sync_available=True)
    assert status == "actionable" and f"candidate:{b.id}" in actions
    assert b.status == "new" and state.latest_result(b.id) is None
    context = dict(objective_id="f7", target_origin=ORIGIN, method="POST", location=b.location,
                   media_type=b.content_type)
    assert await store.get(endpoint="POST /search", param="q", vulnClass="xss",
                           context=CoverageContext.parse(context)) is None
    result = await call(CoverageTool(store), "untested", candidates=[{
        "endpoint": "POST /search", "param": "q", "context": context,
    }], vuln_classes=["xss"])
    assert result["total_count"] == 1 and result["items"][0]["context"]["location"] == b.location
    assert state.to_dict() == before


@pytest.mark.asyncio
async def test_retest_and_repeated_sync_leave_sibling_history_unchanged(tmp_path):
    state, store, tool = runtime(tmp_path)
    a = add(state)
    b = add(state, content_type="application/x-www-form-urlencoded")
    await record(tool, a, "confirmed")
    await record(tool, b)
    sibling = deepcopy(next(e for e in await store.list() if media(e) != "application/json"))
    await record(tool, a, "not-confirmed")
    latest = state.latest_result(a.id)
    assert latest is not None
    for _ in range(3):
        await tool._sync_coverage(a, latest)
    rows = await store.list()
    assert len(rows) == 2
    assert next(e for e in rows if media(e) != "application/json") == sibling
    updated = next(e for e in rows if media(e) == "application/json")
    assert updated.status == "passed" and updated.count == 1
    assert updated.observationIds == [f"candidate:{a.id}"]
    assert len(updated.resultIds or []) == 2
    assert len([r for r in state.validation_results if r.candidate_id == a.id]) == 2


@pytest.mark.asyncio
async def test_context_round_trips_actual_session_and_store_then_resyncs(tmp_path):
    state, store, tool = runtime(tmp_path)
    a = add(state, auth_context_ref="auth-A", test_case="variant")
    b = add(state, content_type="application/x-www-form-urlencoded", auth_context_ref="auth-B")
    await record(tool, a, "confirmed")
    await record(tool, b)
    legacy = await store.mark(endpoint="POST /search", param="q", vulnClass="xss", status="tried")
    await store.flush()
    persisted_rows = deepcopy(await store.list())
    session = SessionStore.new_with_id(tmp_path, "contextual-coverage")
    await session.save([], workflow=state, target=Target(ORIGIN))
    loaded = session.load()
    assert loaded.workflow.to_dict() == state.to_dict()
    resumed_store = CoverageStore(str(store.path))
    assert await resumed_store.list() == persisted_rows
    resumed = WorkflowTool(loaded.workflow, loaded.target, coverage=resumed_store, evidence_root=tmp_path)
    for c in loaded.workflow.candidates.values():
        result = loaded.workflow.latest_result(c.id)
        assert result is not None
        await resumed._sync_coverage(c, result)
    rows = await resumed_store.list()
    assert len(rows) == 3 and next(e for e in rows if e.context is None) == legacy
    assert all(e.count == 1 for e in rows)
    assert {e.context for e in rows} == {e.context for e in persisted_rows}
    assert loaded.workflow.candidates.keys() == state.candidates.keys()
    assert "validation_context" not in session.path.read_text()


@pytest.mark.asyncio
async def test_failed_persistence_and_resume_retry_do_not_double_count(tmp_path, monkeypatch):
    state, store, tool = runtime(tmp_path)
    a, b = add(state), add(state, content_type="application/x-www-form-urlencoded")
    await record(tool, b)
    sibling = deepcopy((await store.list())[0])
    persist = store._persist
    async def fail():
        raise OSError("offline injected write failure")
    monkeypatch.setattr(store, "_persist", fail)
    response = await record(tool, a, "confirmed")
    assert response["coverage_sync"] == "pending"
    latest = state.latest_result(a.id)
    assert latest is not None and latest.coverage_synced is False
    assert not state.eligible_for_finding(a.id)
    session = SessionStore.new_with_id(tmp_path, "retry")
    await session.save([], workflow=state, target=Target(ORIGIN))
    loaded = session.load()
    # Retry in-process: the failed in-memory row already exists.
    monkeypatch.setattr(store, "_persist", persist)
    assert (await call(tool, "sync_coverage", candidate_id=a.id))["coverage_sync"] == "synced"
    assert (await call(tool, "sync_coverage", candidate_id=a.id))["coverage_sync"] == "not-pending"
    # Retry saved pending session against the already durable coverage row.
    fresh = CoverageStore(str(store.path))
    resumed = WorkflowTool(loaded.workflow, loaded.target, coverage=fresh, evidence_root=tmp_path)
    assert (await call(resumed, "sync_coverage", candidate_id=a.id))["coverage_sync"] == "synced"
    rows = await fresh.list()
    assert len(rows) == 2 and all(e.count == 1 and len(e.observationIds or []) == 1 for e in rows)
    assert next(e for e in rows if media(e) != "application/json") == sibling
    assert loaded.workflow.eligible_for_finding(a.id)


@pytest.mark.asyncio
async def test_legacy_aggregate_keeps_identity_and_never_satisfies_context(tmp_path):
    state, store, tool = runtime(tmp_path)
    legacy = await store.mark(endpoint="POST /search", param="q", vulnClass="xss", status="failed")
    legacy_snapshot = deepcopy(legacy)
    await store.flush()
    c = add(state)
    context = CoverageContext(objective_id="f7", target_origin=ORIGIN, method="POST", location="body",
                              media_type="application/json")
    assert await store.get(endpoint="POST /search", param="q", vulnClass="xss", context=context) is None
    assert len(await store.untested([{"endpoint": "POST /search", "param": "q",
                                     "context": asdict(context)}], ["xss"])) == 1
    await record(tool, c)
    assert len(await store.list()) == 2
    assert await store.get(endpoint="POST /search", param="q", vulnClass="xss") == legacy_snapshot
    fresh = CoverageStore(str(store.path))
    assert await fresh.get(endpoint="POST /search", param="q", vulnClass="xss") == legacy_snapshot
    await fresh.mark(endpoint="GET /other", param="id", vulnClass="xss", status="tried")
    await fresh.flush()
    assert await CoverageStore(str(store.path)).get(endpoint="POST /search", param="q", vulnClass="xss") == legacy_snapshot


@pytest.mark.asyncio
async def test_known_legacy_result_mirror_is_counted_once_without_rewriting_legacy(tmp_path):
    state, store, tool = runtime(tmp_path)
    c = add(state)
    result = ValidationResult(c.id, "cross-site-scripting", "not-confirmed", coverage_synced=False,
                              objective_id="f7")
    state.add_validation_result(result)
    legacy = await store.mark(endpoint="POST /search", param="q", vulnClass="xss", status="passed",
                              observation_id=validation_result_fingerprint(result))
    before = deepcopy(legacy)
    assert not (await call(tool, "sync_coverage", candidate_id=c.id))["ok"]
    assert await store.list() == [before]
    assert (await store.summary()).total == 1


@pytest.mark.asyncio
async def test_direct_unknowns_stay_unknown_without_fake_inventory(tmp_path):
    state, store, tool = runtime(tmp_path)
    c = add(state, method=None, location=None, content_type=None, auth_context_ref=None)
    await record(tool, c)
    rows = await store.list()
    assert not state.attack_surface_inputs
    assert rows[0].endpoint == "/search"
    assert rows[0].context == CoverageContext(objective_id="f7", target_origin=ORIGIN)
    # An active Target alone never supplies missing canonical identity.
    bare = WorkflowState()
    unknown = add(bare, target=None, method=None, location=None, content_type=None)
    bare_store = CoverageStore(str(tmp_path / "unknown.json"))
    bare_tool = WorkflowTool(bare, Target(ORIGIN), coverage=bare_store, evidence_root=tmp_path)
    await record(bare_tool, unknown)
    assert (await bare_store.list())[0].context == CoverageContext()


@pytest.mark.asyncio
async def test_whole_target_projection_enriches_from_compatible_reverse_links(tmp_path):
    state, store, tool = runtime(tmp_path, mode="whole_target")
    c = add(state, method=None, location=None, content_type=None, endpoint=None, parameter=None,
            auth_context_ref="auth-A", test_case="json")
    for media in ("application/json", "Application/JSON; charset=utf-8"):
        item, _ = state.add_attack_surface_input(AttackSurfaceInput(
            objective_id="f7", target_origin=ORIGIN, method="POST", endpoint="/search", parameter="q",
            location="body", content_type=media, auth_context_ref="auth-A"))
        state.link_input_candidate(item.id, c.id)
    assert (await record(tool, c))["coverage_sync"] == "synced"
    row = (await store.list())[0]
    assert row.endpoint == "POST /search" and row.param == "q [subcase: json]"
    assert row.context == CoverageContext(objective_id="f7", target_origin=ORIGIN, method="POST",
                                          location="body", media_type="application/json",
                                          auth_context_ref="auth-A", test_case="json")
    assert c.method is None and c.endpoint is None and c.content_type is None


@pytest.mark.asyncio
@pytest.mark.parametrize("dimension,values", [
    ("content_type", ["application/json", "application/x-www-form-urlencoded"]),
    ("location", ["query", "body"]), ("method", ["GET", "POST"]),
    ("endpoint", ["/one", "/two"]),
])
async def test_ambiguous_compatible_inputs_fail_closed(tmp_path, dimension, values):
    state, store, tool = runtime(tmp_path, mode="whole_target")
    c = add(state, **{dimension: None})
    for value in values:
        fields: dict[str, Any] = dict(objective_id="f7", target_origin=ORIGIN, method="POST", endpoint="/search",
                      parameter="q", location="body", content_type="application/json")
        fields[dimension] = value
        item, _ = state.add_attack_surface_input(AttackSurfaceInput(**fields))
        state.link_input_candidate(item.id, c.id)
    response = await record(tool, c)
    assert response["coverage_sync"] == "pending" and "ambiguous" in response["coverage_error"]
    assert await store.list() == []
    latest = state.latest_result(c.id)
    assert latest is not None and latest.outcome == "not-confirmed"


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["objective", "origin", "active_target"])
async def test_foreign_ownership_sync_is_rejected(tmp_path, change):
    state, store, tool = runtime(tmp_path)
    c = add(state)
    result = ValidationResult(c.id, "cross-site-scripting", "not-confirmed", coverage_synced=False,
                              objective_id="f7")
    state.add_validation_result(result)
    if change == "active_target":
        tool.target = Target("https://foreign.test")
    else:
        state.objective = WorkflowObjective("other" if change == "objective" else "f7", "direct",
                                            "https://foreign.test" if change == "origin" else ORIGIN)
    payload = await run_workflow_fixture(tool, {"action": "sync_coverage", "candidate_id": c.id}, None, AlwaysAllow())
    assert "error" in payload
    assert await store.list() == [] and result.coverage_synced is False


@pytest.mark.asyncio
async def test_sparse_retry_preserves_richer_entry_and_conflict_creates_sibling(tmp_path):
    store = CoverageStore(str(tmp_path / "coverage.json"))
    rich = CoverageContext(target_origin=ORIGIN, method="POST", location="body", media_type="application/json")
    args: dict[str, Any] = dict(endpoint="/search", param="q", vulnClass="xss", status="passed", notes="result",
                observation_id="candidate:stable")
    first = await store.ensure_validation_mark(**args, context=rich)
    await store.ensure_validation_mark(**args, context=CoverageContext())
    assert len(await store.list()) == 1
    assert (await store.list())[0].context == rich and first.count == 1
    await store.ensure_validation_mark(**args, context=CoverageContext(target_origin=ORIGIN,
        method="POST", location="query", media_type="application/json"))
    assert len(await store.list()) == 2 and first.context == rich


@pytest.mark.asyncio
async def test_privacy_and_instance_fields_excluded_from_coverage(tmp_path):
    state, store, tool = runtime(tmp_path)
    for capture in ("capture-one", "capture-two"):
        c = add(state, baseline_request_ref=capture, auth_context_ref="auth-A", source_skill="web-input-analysis",
                source_ref="source-private", request_template="Authorization: Bearer secret-token\nCookie: sid=secret-cookie\n\nq={INJECTION_POINT}")
        await record(tool, c)
    raw = store.path.read_text()
    rows = await store.list()
    assert len(rows) == 1 and rows[0].count == 2
    for forbidden in ("secret-token", "secret-cookie", "Authorization", "Cookie", "baseline_request_ref",
                      "capture-one", "capture-two", "source-private", "source_skill", "request_template",
                      "sample_payload", "validation_context", '"baseline"', '"auth"', "permission", "available"):
        assert forbidden not in raw
    assert rows[0].context is not None and rows[0].context.auth_context_ref == "auth-A"


@pytest.mark.asyncio
@pytest.mark.parametrize("context", [{"cookies": "secret"}, {"auth": {"available": True}},
    {"baseline_request_ref": "capture"}, {"method": 1}, {"target_origin": "file:///tmp"}, None])
async def test_tool_rejects_non_identity_context(tmp_path, context):
    store = CoverageStore(str(tmp_path / "coverage.json"))
    tool = CoverageTool(store)
    response = await call(tool, "mark", endpoint="/search", param="q", vuln_class="xss", context=context)
    assert response["ok"] is False and await store.list() == []


@pytest.mark.asyncio
async def test_tool_mark_list_and_untested_use_the_same_exact_context(tmp_path):
    store = CoverageStore(str(tmp_path / "coverage.json"))
    tool = CoverageTool(store)
    context = dict(target_origin="HTTPS://TARGET.TEST:443", method=" post ", location=" BODY ",
                   media_type="Application/JSON; charset=utf-8", auth_context_ref="auth-A")
    mark = await call(tool, "mark", endpoint="/search?q=x", param="q", vuln_class="xss", context=context)
    assert mark["created"] and mark["entry"]["context"]["media_type"] == "application/json"
    listed = await call(tool, "list", context=context)
    assert listed["total_count"] == 1 and listed["items"][0]["view"] == "contextual"
    different = {**context, "auth_context_ref": "auth-B"}
    assert (await call(tool, "list", context=different))["total_count"] == 0
    tested = await call(tool, "untested", candidates=[{"endpoint": "/search", "param": "q", "context": context}],
                        vuln_classes=["xss"])
    assert tested["total_count"] == 0
    unspecified = await call(tool, "untested", candidates=[{"endpoint": "POST /search", "param": "q"}],
                             vuln_classes=["xss"])
    assert unspecified["total_count"] == 1
    summary = await call(tool, "summary")
    assert summary["variant_proof"] is False
    await store.flush()


@pytest.mark.asyncio
async def test_corrupt_context_record_is_skipped_without_losing_legacy(tmp_path):
    path = tmp_path / "coverage.json"
    legacy = dict(endpoint="POST /search", param="q", vulnClass="cross-site-scripting", status="passed",
                  count=1, firstSeen=1, lastSeen=2)
    path.write_text(json.dumps({"version": 1, "entries": [legacy, {**legacy, "context": {"cookies": "secret"}}]}))
    store = CoverageStore(str(path))
    assert len(await store.list()) == 1 and (await store.list())[0].context is None
    await store.mark(endpoint="GET /other", param="id", vulnClass="xss", status="tried")
    await store.flush()
    assert "secret" not in path.read_text()


@pytest.mark.asyncio
async def test_no_candidate_review_semantics_remain_distinct(tmp_path):
    state, store, tool = runtime(tmp_path, mode="whole_target")
    objective = state.objective
    assert objective is not None
    goal = objective.add_requested_goal("sql-injection")
    for phase in ("recon", "enumeration", "input_analysis"):
        record_completed_phase(state, phase, objective_id="f7", target_origin=ORIGIN,
                               artifact_ref=f"{phase}.md", no_inputs_discovered=phase == "input_analysis")
    state.mark_goal_no_candidate(goal.id, artifact_ref="input_analysis.md",
                                 review_binding=state.no_candidate_review_binding(goal, "fixture-digest"))
    before = deepcopy(goal.to_dict())
    await store.mark(endpoint="POST /search", param="q", vulnClass="sqli", status="passed")
    await call(CoverageTool(store), "summary")
    await store.flush()
    assert goal.status == "no_candidate" and goal.to_dict() == before
    assert not state.validation_results


@pytest.mark.asyncio
async def test_candidate_retest_preserves_result_objective_ownership(tmp_path):
    state, store, tool = runtime(tmp_path)
    c = add(state)
    await record(tool, c)
    state.objective = WorkflowObjective("explicit-retest", "candidate_validation", ORIGIN, candidate_id=c.id)
    assert (await record(tool, c, "confirmed"))["coverage_sync"] == "synced"
    rows = await store.list()
    assert len(rows) == 2
    assert {e.context.objective_id for e in rows if e.context} == {"f7", "explicit-retest"}
    assert c.objective_id == "f7" and c.id in state.candidates


async def linked_whole_target_retest(tmp_path):
    state, store, tool = runtime(tmp_path, mode="whole_target")
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    tool.skills = skills
    registry = ToolRegistry()
    registry.register(tool)
    client = FakeClient([])
    assert tool.target is not None
    agent = Agent(AgentOptions(client=client, tools=registry, skills=skills,
        prompter=AlwaysAllow(), store=None, target=tool.target, workflow=state))
    candidates = []
    for content_type in ("application/json", "application/x-www-form-urlencoded"):
        geometry = dict(method="POST", endpoint="/search", parameter="q",
                        location="body", content_type=content_type)
        item = (await call(tool, "record_input", **geometry))["input"]
        response = await call(tool, "record_candidate", candidate_class="xss",
                              input_id=item["id"], **geometry)
        c = state.candidates[response["candidate"]["id"]]
        assert (await call(tool, "start_validation", candidate_id=c.id))["ok"]
        assert (await record(tool, c))["coverage_sync"] == "synced"
        candidates.append(c)
    c = candidates[0]
    historical_inputs = deepcopy(state.attack_surface_inputs)
    historical_rows = deepcopy(await store.list())
    historical_results = deepcopy(state.validation_results)
    agent._initialize_request_objective("New objective: retest " + c.id, True)
    assert state.objective is not None
    assert state.objective.mode == "candidate_validation" and state.objective.candidate_id == c.id
    assert state.objective.id != "f7"
    assert (await call(tool, "start_validation", candidate_id=c.id))["ok"]
    return state, store, tool, c, client, historical_inputs, historical_rows, historical_results


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["confirmed", "not-confirmed"])
@pytest.mark.parametrize("fail_write", [False, True], ids=["durable", "pending-resume"])
async def test_linked_whole_target_explicit_retest_sync_and_finding(tmp_path, monkeypatch, outcome, fail_write):
    state, store, tool, c, client, inputs, historical, initial_results = await linked_whole_target_retest(tmp_path)
    cid = c.id
    assert state.objective is not None
    retest_owner = state.objective.id
    persist = store._persist
    writes = []

    async def checked_persist():
        latest = state.latest_result(cid)
        assert latest is not None and latest.objective_id == retest_owner
        assert latest.coverage_synced is False
        writes.append(latest.objective_id)
        # The failed write must leave only historical rows on disk.
        assert await CoverageStore(str(store.path)).list() == historical
        if fail_write:
            raise OSError("offline retest write failure")
        await persist()
        assert latest.coverage_synced is False
        assert len(await CoverageStore(str(store.path)).list()) == 3

    monkeypatch.setattr(store, "_persist", checked_persist)
    response = await record(tool, c, outcome)
    latest = state.latest_result(cid)
    assert latest is not None and latest.objective_id == retest_owner
    assert writes  # Projection reached the actual persistence boundary.
    assert response["coverage_sync"] == ("pending" if fail_write else "synced")
    assert latest.coverage_synced is (not fail_write)
    if fail_write:
        assert not state.eligible_for_finding(cid)
        assert await CoverageStore(str(store.path)).list() == historical
        session = SessionStore.new_with_id(tmp_path / "sessions", "linked-retest")
        await session.save([], workflow=state, target=tool.target)
        loaded = session.load()
        assert loaded.workflow.to_dict() == state.to_dict()
        monkeypatch.setattr(store, "_persist", persist)
        # First retry resumes from disk with no retest coverage row.
        resumed_store = CoverageStore(str(store.path))
        resumed = WorkflowTool(loaded.workflow, loaded.target, coverage=resumed_store,
                               skills=tool.skills, evidence_root=tmp_path)
        assert (await call(resumed, "sync_coverage", candidate_id=cid))["coverage_sync"] == "synced"
        resumed_result = loaded.workflow.latest_result(cid)
        assert resumed_result is not None and resumed_result.coverage_synced is True
        durable = deepcopy(await resumed_store.list())
        # The failed in-process row and the saved pending session adopt the
        # now-durable observation without increasing its count or row count.
        assert (await call(tool, "sync_coverage", candidate_id=cid))["coverage_sync"] == "synced"
        loaded_again = session.load()
        store = CoverageStore(str(store.path))
        tool = WorkflowTool(loaded_again.workflow, loaded_again.target, coverage=store,
                            skills=tool.skills, evidence_root=tmp_path)
        state = loaded_again.workflow
        c = state.candidates[cid]
        assert (await call(tool, "sync_coverage", candidate_id=cid))["coverage_sync"] == "synced"
        assert {e.context for e in await store.list()} == {e.context for e in durable}
    else:
        monkeypatch.setattr(store, "_persist", persist)

    latest = state.latest_result(cid)
    assert latest is not None and latest.coverage_synced is True
    for _ in range(3):
        assert (await call(tool, "sync_coverage", candidate_id=cid))["coverage_sync"] == "not-pending"
        await tool._sync_coverage(c, latest)
    rows = await CoverageStore(str(store.path)).list()
    assert len(rows) == 3
    assert [e for e in rows if e.context and e.context.objective_id == "f7"] == historical
    retest = next(e for e in rows if e.context and e.context.objective_id == retest_owner)
    assert retest.context == CoverageContext(objective_id=retest_owner, target_origin=ORIGIN,
        method="POST", location="body", media_type="application/json")
    assert retest.endpoint == "POST /search" and retest.param == "q"
    assert retest.status == ("failed" if outcome == "confirmed" else "passed")
    assert retest.count == 1 and retest.observationIds == [f"candidate:{cid}"]
    # Identical negative outcomes share a fingerprint across objectives; the
    # context still separates their rows and the aliases remain deduplicated.
    assert len(retest.resultIds or []) == len(set(retest.resultIds or [])) == 2  # distinct durable attempts never collapse by outcome
    assert c.id == cid and c.objective_id == "f7"
    assert state.attack_surface_inputs == inputs
    assert state.validation_results[:2] == initial_results
    assert latest.objective_id == retest_owner
    assert state.eligible_for_finding(cid) is (outcome == "confirmed")
    finding = ConfirmFindingTool(FindingsStore(project_directory=tmp_path), workflow=state)
    args = dict(candidate_id=cid, title="Offline linked retest", severity="medium",
        url=ORIGIN + "/search", parameter="q", vuln_class="xss",
        observed_impact="Only deterministic offline fixture evidence was exercised.",
        potential_impact="No additional impact assessed.")
    if outcome == "confirmed":
        assert state.evidence_matches(cid, latest.evidence_refs)
        assert "written to" in await finding.run(args, None, AlwaysAllow())
        reports = list((tmp_path / "artifacts" / "findings").glob("*.md"))
        assert len(reports) == 1 and cid in reports[0].read_text()
        assert all(ref in reports[0].read_text() for ref in latest.evidence_refs)
        assert state.finding_is_persisted(cid)
    else:
        with pytest.raises(Exception, match="not eligible"):
            await finding.run(args, None, AlwaysAllow())
        assert not state.finding_is_persisted(cid)
    assert client.requests == []


@pytest.mark.asyncio
async def test_linked_whole_target_explicit_retest_missing_endpoint_stays_pending(tmp_path):
    state, store, tool, c, client, inputs, historical, _ = await linked_whole_target_retest(tmp_path)
    # A persisted sparse Candidate cannot borrow the historical inventory's
    # endpoint under the new objective; no separate historical resolver exists.
    c.endpoint = None
    rejected = await tool.run({"action":"record_result", "candidate_id":c.id,
        "skill_name":"cross-site-scripting", "outcome":"not-confirmed"}, None, AlwaysAllow())
    assert "stale active attempt" in rejected
    assert len(state.validation_results) == len(_)
    assert await CoverageStore(str(store.path)).list() == historical
    assert state.attack_surface_inputs == inputs and c.objective_id == "f7"
    assert client.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize("change,error", [
    ("owner", "must belong to the active objective"),
    ("geometry", "content_type conflicts with input"),
])
async def test_whole_target_reverse_link_guard_still_rejects(tmp_path, change, error):
    state, store, tool = runtime(tmp_path, mode="whole_target")
    c = add(state)
    item, _ = state.add_attack_surface_input(AttackSurfaceInput(
        objective_id="f7", target_origin=ORIGIN, method="POST", endpoint="/search",
        parameter="q", location="body", content_type="application/json"))
    state.link_input_candidate(item.id, c.id)
    # Simulate incompatible restored canonical linkage, without weakening the
    # creation/link guard in order to manufacture the invalid state.
    if change == "owner":
        item.objective_id = "foreign-objective"
    else:
        item.content_type = "application/x-www-form-urlencoded"
    before = deepcopy(state.attack_surface_inputs)
    response = await record(tool, c)
    assert response["coverage_sync"] == "pending" and error in response["coverage_error"]
    assert await store.list() == []
    latest = state.latest_result(c.id)
    assert latest is not None and latest.coverage_synced is False
    assert state.attack_surface_inputs == before


@pytest.mark.asyncio
async def test_contextual_list_normalizes_endpoint_and_does_not_substring_match(tmp_path):
    state, store, workflow = runtime(tmp_path)
    c = add(state)
    await record(workflow, c)
    row_context = (await store.list())[0].context
    assert row_context is not None
    context = asdict(row_context)
    tool = CoverageTool(store)
    listed = await call(tool, "list", endpoint=ORIGIN + "/search?q=x", context=context)
    assert listed["total_count"] == 1
    assert (await call(tool, "list", endpoint="/sear", context=context))["total_count"] == 0
    assert (await call(tool, "list", endpoint="https://foreign.test/search", context=context))["ok"] is False
    unknown = {**context, "media_type": "application/x-www-form-urlencoded"}
    response = await call(tool, "untested", context=unknown,
                          candidates=[{"endpoint": "/search", "param": "q"}], vuln_classes=["xss"])
    assert response["total_count"] == 1 and response["items"][0]["context"] == unknown


@pytest.mark.asyncio
async def test_cancelled_sync_keeps_pending_then_retries_one_observation(tmp_path, monkeypatch):
    import asyncio
    state, store, tool = runtime(tmp_path)
    c = add(state)
    entered = asyncio.Event()
    release = asyncio.Event()
    persist = store._persist
    async def suspended():
        entered.set()
        await release.wait()
        await persist()
    monkeypatch.setattr(store, "_persist", suspended)
    task = asyncio.create_task(record(tool, c))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    result = state.latest_result(c.id)
    assert result is not None and result.coverage_synced is False
    monkeypatch.setattr(store, "_persist", persist)
    assert (await call(tool, "sync_coverage", candidate_id=c.id))["coverage_sync"] == "synced"
    rows = await store.list()
    assert len(rows) == 1 and rows[0].count == 1
    assert rows[0].observationIds == [f"candidate:{c.id}"]


@pytest.mark.asyncio
async def test_changed_canonical_context_during_flush_cannot_be_marked_synced(tmp_path, monkeypatch):
    state, store, tool = runtime(tmp_path)
    persist = store._persist
    async def enrich_during_write():
        # Compatible runtime enrichment pins the existing candidate ID (Phase 1).
        state.add_candidate(Candidate(candidate_class="xss", target=ORIGIN, method="POST",
            endpoint="/search", parameter="q", location="body", content_type="application/json",
            objective_id="f7", baseline_request_ref="same-capture"))
        await persist()
    # Start sparse so enrichment actually changes the projection while flushing.
    sparse = WorkflowState(objective=WorkflowObjective("f7", "direct", ORIGIN))
    c = add(sparse, content_type=None, baseline_request_ref="same-capture")
    tool.state = sparse
    state = sparse
    monkeypatch.setattr(store, "_persist", enrich_during_write)
    response = await record(tool, c)
    assert response["coverage_sync"] == "pending"
    assert c.content_type == "application/json"
    result = state.latest_result(c.id)
    assert result is not None and result.coverage_synced is False
    monkeypatch.setattr(store, "_persist", persist)
    assert not (await call(tool, "sync_coverage", candidate_id=c.id))["ok"]
    await record(tool, c, force=True)
    rows = await store.list()
    # The invalid in-flight projection was rolled back; only the fresh
    # assessment for the enriched identity can remain tested.
    assert {media(e) for e in rows} == {"application/json"}
    assert all(e.count == 1 for e in rows)
