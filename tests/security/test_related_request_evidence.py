"""Association declarations retain evidence and Generic admission boundaries offline."""
from copy import deepcopy
import json

import pytest

from src.workflow.assessment import accepted_result
from src.workflow.state import WorkflowState
from tests.security.test_agent_assessment import setup
from tests.security.test_assessment_review_fixes import collect, declaration
from tests.security.test_execution_policy import runtime, ORIGIN
from tests.security.test_generic_validation import setup as generic_setup, proposal, bind_context
from tests.tools.test_related_request_associations import error_envelope


@pytest.mark.parametrize("candidate_class", ["sqli", "xss"])
async def test_primary_payload_and_identity_variations_are_observations(runtime, tmp_path, candidate_class):
    state, candidate, tool, args, first_oid = await setup(
        runtime, tmp_path, candidate_class=candidate_class, method="POST")
    registry, p, policy, _, sent, *_ = runtime
    # setup supplies the empty-list legacy equivalent. An omitted declaration
    # is the same active Candidate handoff, without modifying the attempt.
    result = json.loads(await registry.execute("workflow", {
        "action": "start_validation", "candidate_id": candidate.id}, None, p))
    assert result["validation_context"]["attempt_id"] == args["attempt_id"]
    for payload, principal in [("fixture-control", "fixture-owner"), ("fixture-variant", "fixture-other")]:
        await registry.execute("http", {"url": "/fixture", "method": "POST", "phase": "validation",
            "headers": {"Content-Type": "application/x-www-form-urlencoded", "X-Fixture-Principal": principal},
            "body": "q=" + payload}, None, p)
        args["observation_ids"].append(next(reversed(policy.observations._items)))
    assert len(set(args["observation_ids"])) == 3 and first_oid in args["observation_ids"]
    assert {(str(req.url), req.method) for req in sent} == {(ORIGIN + "/fixture", "POST")}
    assert len({req.content for req in sent}) == 3
    assert state.attempts[args["attempt_id"]]["related_requests"] == []
    # This checks source admissibility, not vulnerability-specific semantics.
    output = json.loads(await registry.execute("workflow", {**args, "outcome": "not-confirmed"}, None, p))
    assert len(output["result"]["evidence_manifest"]) == 3
    assert accepted_result(state, candidate, state.latest_result(candidate.id), policy)
    assert not state.eligible_for_finding(candidate.id)
    assert tool.active_attempt == args["attempt_id"]


@pytest.mark.parametrize("required", [True, False])
async def test_omitted_active_associations_keep_supplementary_evidence_obligation(runtime, tmp_path, required):
    state, candidate, _, args, _ = await setup(runtime, tmp_path, related=[declaration(required=required)])
    registry, p, policy, *_ = runtime
    before, revision = deepcopy(state.to_dict()), state.committed_revision
    resumed = json.loads(await registry.execute("workflow", {
        "action": "start_validation", "candidate_id": candidate.id}, None, p))
    assert resumed["validation_context"]["attempt_id"] == args["attempt_id"]
    assert state.to_dict() == before and state.committed_revision == revision
    result = await registry.execute("workflow", args, None, p)
    if required:
        assert result.status == "error" and "required request" in result
        assert not state.validation_results and not state.eligible_for_finding(candidate.id)
        await collect(runtime, args)
        result = await registry.execute("workflow", args, None, p)
    assert json.loads(result)["result"]["outcome"] == "confirmed"
    assert accepted_result(state, candidate, state.latest_result(candidate.id), policy)


@pytest.mark.parametrize("malformed", [False, True])
async def test_legacy_saved_assessment_rechecks_duplicate_invariant(runtime, tmp_path, malformed):
    state, candidate, _, args, _ = await setup(runtime, tmp_path, related=[declaration()])
    registry, p, policy, *_ = runtime
    await collect(runtime, args)
    await registry.execute("workflow", args, None, p)
    data = json.loads(json.dumps(state.to_dict()))
    aid = args["attempt_id"]
    if malformed:
        data["attempts"][aid]["related_requests"].append(deepcopy(data["attempts"][aid]["related_requests"][0]))
    restored = WorkflowState.from_dict(data)
    restored_candidate = restored.candidates[candidate.id]
    before = deepcopy(restored.to_dict())
    assert accepted_result(restored, restored_candidate, restored.latest_result(candidate.id), policy) is not malformed
    assert restored.eligible_for_finding(candidate.id) is not malformed
    assert restored.to_dict() == before


@pytest.mark.parametrize("explicit_proposal", [False, True])
async def test_candidate_only_does_not_bypass_generic_proposal_prerequisites(runtime, tmp_path, explicit_proposal):
    env = await generic_setup(runtime, tmp_path)
    registry, p, policy, _, state, candidate, tool, _ = env
    # A syntactically valid model proposal cannot supply trusted context.
    policy.generic_validation.contexts.clear()
    args = {"action": "start_validation", "candidate_id": candidate.id}
    if explicit_proposal:
        args["probe"] = proposal(env)
    before, revision = deepcopy(state.to_dict()), state.committed_revision
    result = await registry.execute("workflow", args, None, p)
    assert result.status == "error" and "generic context-needed" in result
    assert "DUPLICATE_REQUEST_ASSOCIATION" not in result
    assert state.to_dict() == before and state.committed_revision == revision
    assert not runtime[4] and tool.active_attempt is None
    bind_context(env)
    duplicate = {**args, "related_requests": [
        declaration(path="/readback"), declaration(path="/readback")]}
    before, revision = deepcopy(state.to_dict()), state.committed_revision
    error_envelope(await registry.execute("workflow", duplicate, None, p))
    assert state.to_dict() == before and state.committed_revision == revision
    assert policy.generic_validation.attempt is None and policy.generic_validation.durable_attempt is None
    assert not runtime[4]
    started = json.loads(await registry.execute("workflow", args, None, p))
    assert started["validator_resolution"] == "generic" and not runtime[4]
