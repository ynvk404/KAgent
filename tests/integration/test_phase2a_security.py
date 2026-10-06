"""Phase 2A canonical reads remain outside generic execution/proof authority."""
from __future__ import annotations

import json
from copy import deepcopy

import pytest

from src.browser.scoped_store import ScopedCaptureStore
from src.browser.store import CaptureStore
from src.permission.permission import UserControlledRefusal
from src.permission.runtime.execution import ExecutionBlocked
from src.workflow.state import AttackSurfaceInput, Candidate
from src.workflow.validation_context import resolve_validation_context
from tests.security.test_execution_policy import runtime, ORIGIN
from tests.security.test_generic_validation import setup, proposal, request


@pytest.mark.asyncio
async def test_get_input_remains_available_during_admitted_generic_validation(runtime, tmp_path):
    env = await setup(runtime, tmp_path, mode="whole_target")
    registry, prompter, policy, _, state, candidate, _, _ = env
    item = next(iter(state.attack_surface_inputs.values()))
    output = json.loads(await registry.execute("workflow", {
        "action": "record_input", "method": item.method, "endpoint": item.endpoint,
        "parameter": item.parameter, "location": item.location,
        "sample_payload": "q=safe&context=" + "A" * 1000,
    }, None, prompter))
    assert output["ok"]
    before = dict(policy.generic_validation.contexts)
    started = json.loads(await registry.execute("workflow", {
        "action": "start_validation", "candidate_id": candidate.id,
    }, None, prompter))
    assert started["validation_context"]["sample_payload"] == "q=safe&context=" + "A" * 1000
    assert started["validation_context"]["probe_intent"] == {
        "observation": "compare-response", "capture": "native-http+candidate-proof",
        "stop": "after-comparison", "input_path": None, "occurrence": 0,
    }
    result = json.loads(await registry.execute("workflow", {
        "action": "get_input", "input_id": item.id,
    }, None, prompter))
    assert result["input"]["sample_payload"] == "q=safe&context=" + "A" * 1000
    assert result["input"]["candidate_ids"] == [candidate.id]
    assert policy.generic_validation.contexts == before
    assert not state.evidence and not state.validation_results
    assert not runtime[4] and not runtime[3].requests
    assert policy.active == 0


@pytest.mark.asyncio
async def test_derived_context_cannot_restore_controller_admission(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    registry, prompter, policy, _, state, candidate, _, _ = env
    policy.generic_validation.contexts.clear()
    context = resolve_validation_context(state, candidate.id, target=ORIGIN, http_tool=registry.get("http")).to_dict()
    assert context["method"] == "GET" and context["parameter"] == "next"
    assert policy.generic_validation.contexts == {}
    result = await registry.execute("workflow", {
        "action": "start_validation", "candidate_id": candidate.id, "probe": proposal(env),
    }, None, prompter)
    assert result.startswith("error:") and "context" in result
    assert candidate.status != "validating"
    assert policy.generic_validation.attempt is None
    assert not runtime[4] and not runtime[3].requests


@pytest.mark.asyncio
async def test_generic_lookup_keeps_objective_and_origin_guards(runtime, tmp_path):
    env = await setup(runtime, tmp_path, mode="whole_target")
    registry, prompter, _, _, state, _, _, _ = env
    for objective_id, origin, expected in (("old", ORIGIN, "active objective"),
                                          (state.objective.id, "https://other.test", "active target origin")):
        foreign = AttackSurfaceInput(objective_id, origin, sample_payload="foreign-sample")
        state.attack_surface_inputs[foreign.id] = foreign
        result = await registry.execute("workflow", {"action": "get_input", "input_id": foreign.id}, None, prompter)
        assert result.startswith("error:") and expected in result
        assert "foreign-sample" not in result
    assert not runtime[4]


@pytest.mark.asyncio
async def test_saved_handoff_cannot_execute_after_live_admission_is_cleared(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    registry, prompter, policy, _, state, candidate, _, _ = env
    started = json.loads(await registry.execute("workflow", {
        "action": "start_validation", "candidate_id": candidate.id,
    }, None, prompter))
    assert started["validation_context"]["probe_intent"]
    policy.generic_validation.contexts.clear()
    # Even a validating status, complete Candidate and a retained handoff do
    # not replace trusted controller admission for the existing attempt.
    before = deepcopy(state.to_dict())
    with pytest.raises(ExecutionBlocked, match="context"):
        await registry.execute("http", request(candidate), None, prompter)
    assert state.to_dict() == before
    assert not runtime[4] and not runtime[3].requests
    assert policy.active == 0


@pytest.mark.asyncio
async def test_get_input_is_canonical_read_without_bookkeeping_mutation(runtime, tmp_path):
    env = await setup(runtime, tmp_path, mode="whole_target")
    registry, prompter, policy, _, state, candidate, _, _ = env
    item = next(iter(state.attack_surface_inputs.values()))
    before = deepcopy(state.to_dict())
    boundary = policy.generic_validation
    attempt, contexts = boundary.attempt, dict(boundary.contexts)
    response = json.loads(await registry.execute("workflow", {
        "action": "get_input", "input_id": item.id,
    }, None, prompter))
    assert response["input"] == item.to_dict()
    assert state.to_dict() == before
    assert boundary.attempt is attempt and boundary.contexts == contexts
    assert boundary.started_candidate is None and candidate.status != "validating"
    assert not runtime[4]


@pytest.mark.asyncio
async def test_scoped_baseline_inspection_requires_existing_receipt(runtime, tmp_path):
    env = await setup(runtime, tmp_path)
    registry, prompter, policy, _, state, candidate, tool, _ = env
    source = CaptureStore()
    bound = source.ingest({"id": "scoped", "method": candidate.method, "url": ORIGIN + candidate.endpoint,
                           "requestHeaders": {"User-Agent": "fixture"}})
    candidate.baseline_request_ref = bound["baseline_request_ref"]
    http = registry.get("http")
    http.capture_store = ScopedCaptureStore(source, policy)
    # This test examines the existing capability boundary itself. A context
    # read outside any invocation must not unwrap the scoped store.
    context = resolve_validation_context(state, candidate.id, target=ORIGIN, http_tool=http).to_dict()
    assert context["baseline"] == {"state": "unavailable", "available": False, "reason": "capture_access_denied"}
    assert policy.active == 0
    with pytest.raises(UserControlledRefusal, match="current-receipt"):
        http.capture_store.resolve_baseline(bound["baseline_request_ref"])
    assert not runtime[4]
