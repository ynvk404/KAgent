"""Related requests are associations, not payload steps; all dispatch is offline."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from src.permission.permission import AlwaysAllow
from src.redaction.redact import apply_evidence
from src.skills.registry import Registry as Skills
from src.target.target import Target
from src.tools.common.outcome import ToolOutput
from src.tools.common.registry import Registry
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.assessment import DuplicateRequestAssociation, request_associations
from src.workflow.state import WorkflowObjective, WorkflowState
from src.workflow.validation.route import resolve_validation_route

ORIGIN = "https://fixture.test"
CLASSES = ("sqli", "xss", "idor", "csrf", "ssrf", "ssti")


@pytest.fixture
def dispatch(tmp_path, monkeypatch):
    skills = Skills()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    assert not skills.load_errors
    state = WorkflowState(objective=WorkflowObjective("association-objective", "direct", ORIGIN))
    tool = WorkflowTool(state, Target(ORIGIN), skills=skills, evidence_root=tmp_path,
                        session_id="association-session")
    registry = Registry()
    registry.register(tool)
    # These calls need no transport. Fail immediately if a repair adds one.
    def no_http(*args, **kwargs):
        raise AssertionError("association dispatch must not send HTTP")
    monkeypatch.setattr("httpx.AsyncClient", no_http)
    return state, tool, registry, AlwaysAllow()


async def candidate_for(dispatch, candidate_class="sqli"):
    state, tool, registry, prompter = dispatch
    created = json.loads(await registry.execute("workflow", {
        "action": "record_candidate", "candidate_class": candidate_class,
        "endpoint": "/comments", "method": "POST", "parameter": "text", "location": "body",
    }, None, prompter))
    candidate = state.candidates[created["candidate"]["id"]]
    assert resolve_validation_route(tool.skills, candidate.candidate_class).kind == "expert"
    return candidate


def declaration(role="baseline", method="POST", url="/comments", **extra):
    return {"role": role, "method": method, "url": url, **extra}


def error_envelope(output):
    assert isinstance(output, ToolOutput)
    assert output.status == "error" and output.error_kind == "workflow_state"
    assert output.startswith("error: ambiguous duplicate")
    envelope = json.loads(output.partition("\n")[2])
    assert envelope["ok"] is False
    error = envelope["error"]
    assert error["code"] == "DUPLICATE_REQUEST_ASSOCIATION"
    assert error["action"] == "start_validation" and error["field"] == "related_requests"
    assert error["message"] and error["repair_hint"]
    assert not {"state_changed", "retryable"} & envelope.keys()
    assert not {"state_changed", "retryable"} & error.keys()
    return error


@pytest.mark.parametrize("candidate_class", CLASSES)
@pytest.mark.parametrize("mode", ["candidate-only", "empty", "legacy", "supplementary"])
async def test_primary_only_and_distinct_supplementary_keep_real_routing(dispatch, candidate_class, mode):
    state, tool, registry, p = dispatch
    candidate = await candidate_for(dispatch, candidate_class)
    args = {"action": "start_validation", "candidate_id": candidate.id}
    if mode == "empty":
        args["related_requests"] = []
    elif mode == "legacy":
        args["related_requests"] = [declaration()]
    elif mode == "supplementary":
        args["related_requests"] = [
            declaration("readback", "GET", "/comments"),
            declaration("readback", "GET", "/comments/123"),
            declaration("auxiliary", "GET", "/comments/123?view=summary"),
            declaration("auxiliary", "GET", "/comments/123?view=detail"),
        ]
    original = deepcopy(args)
    result = json.loads(await registry.execute("workflow", args, None, p))
    assert result["ok"] and result["validator_resolution"] == "unique"
    context = result["validation_context"]
    assert context["candidate_id"] == candidate.id and context["method"] == "POST"
    assert context["endpoint"] == ORIGIN + "/comments"
    assert context["request_template"] is None and context["auth_context_ref"] is None
    assert candidate.status == "validating"
    assert len(state.attempts) == 1 and not state.validation_results
    assert not state.eligible_for_finding(candidate.id)
    attempt = state.attempts[context["attempt_id"]]
    assert tool.active_attempt == attempt["id"]
    rows = attempt["related_requests"]
    assert len(rows) == len(args.get("related_requests", []))
    for saved, given in zip(rows, args.get("related_requests", [])):
        assert saved == {**given, "url": ORIGIN + given["url"], "required": True}
    assert args == original


DUPLICATES = [
    [declaration(), declaration("trigger")],
    [declaration(required=True), declaration(required=False)],
    [declaration(), declaration()],
    [declaration(method="post"), declaration()],
    [declaration(), declaration(url=ORIGIN + "/comments")],
    [declaration(url="/discard/../comments"), declaration()],
    [declaration(url="/comments?token=fixture-alpha"), declaration(url="/comments?token=fixture-beta")],
]


@pytest.mark.parametrize("candidate_class", CLASSES)
@pytest.mark.parametrize("rows", DUPLICATES, ids=["roles", "required", "identical", "method", "resolution", "dot-path", "redaction"])
async def test_duplicates_are_structured_atomic_and_do_not_rewrite_arguments(dispatch, candidate_class, rows):
    state, tool, registry, p = dispatch
    candidate = await candidate_for(dispatch, candidate_class)
    args = {"action": "start_validation", "candidate_id": candidate.id,
            "related_requests": [declaration("auxiliary", "GET", "/help"), *deepcopy(rows)]}
    original = deepcopy(args)
    before, revision = deepcopy(state.to_dict()), state.committed_revision
    status = candidate.status
    error = error_envelope(await registry.execute("workflow", args, None, p))
    assert error["indices"] == [1, 2]
    assert "observations" in error["repair_hint"] and "supplementary" in error["repair_hint"]
    assert state.to_dict() == before and state.committed_revision == revision
    assert candidate.status == status and not state.attempts and tool.active_attempt is None
    assert args == original
    for sensitive in ("fixture-alpha", "fixture-beta", "/comments", ORIGIN):
        assert sensitive not in json.dumps(error)


async def test_bad_retry_preserves_active_attempt_and_omission_preserves_obligations(dispatch):
    state, tool, registry, p = dispatch
    candidate = await candidate_for(dispatch)
    start = {"action": "start_validation", "candidate_id": candidate.id}
    rows = [declaration("readback", "GET", "/comments/123")]
    first = json.loads(await registry.execute("workflow", {**start, "related_requests": rows}, None, p))
    aid = first["validation_context"]["attempt_id"]
    before, revision = deepcopy(state.to_dict()), state.committed_revision
    for _ in range(2):  # No implicit association-specific retry enforcement.
        error_envelope(await registry.execute("workflow", {**start, "related_requests": rows * 2}, None, p))
        assert state.to_dict() == before and state.committed_revision == revision
        assert tool.active_attempt == aid
    omitted = json.loads(await registry.execute("workflow", start, None, p))
    assert omitted["validation_context"]["attempt_id"] == aid
    assert state.to_dict() == before and state.committed_revision == revision
    for changed in ([], [declaration("readback", "GET", "/comments/123", required=False)]):
        rejection = await registry.execute("workflow", {**start, "related_requests": changed}, None, p)
        assert rejection.status == "error" and "explicit retest" in rejection
        assert "DUPLICATE_REQUEST_ASSOCIATION" not in rejection
        assert state.to_dict() == before and state.committed_revision == revision
    # Session loading intentionally interrupts attempts; it cannot adopt old
    # execution ownership. Retain the old declaration and start fresh work.
    resumed = WorkflowState.from_dict(json.loads(json.dumps(state.to_dict())))
    assert resumed.attempts[aid]["status"] == "interrupted"
    assert resumed.attempts[aid]["related_requests"] == before["attempts"][aid]["related_requests"]
    tool.state = resumed
    fresh = json.loads(await registry.execute("workflow", {**start, "related_requests": rows}, None, p))
    new_aid = fresh["validation_context"]["attempt_id"]
    assert new_aid != aid
    omitted = json.loads(await registry.execute("workflow", start, None, p))
    assert omitted["validation_context"]["attempt_id"] == new_aid
    assert resumed.attempts[new_aid]["related_requests"] == resumed.attempts[aid]["related_requests"]


@pytest.mark.parametrize("role", ["baseline", "control", "trigger", "readback", "cleanup", "auxiliary"])
@pytest.mark.parametrize("required", [None, False, True])
async def test_required_defaults_and_explicit_values_are_unchanged(dispatch, role, required):
    state, _, registry, p = dispatch
    candidate = await candidate_for(dispatch)
    row = declaration(role=role)
    if required is not None:
        row["required"] = required
    result = json.loads(await registry.execute("workflow", {
        "action": "start_validation", "candidate_id": candidate.id, "related_requests": [row]}, None, p))
    stored = state.attempts[result["validation_context"]["attempt_id"]]["related_requests"][0]
    assert stored["required"] is (role != "cleanup" if required is None else required)


async def test_scope_and_other_active_candidate_are_not_duplicate_argument_errors(dispatch):
    state, _, registry, p = dispatch
    candidate = await candidate_for(dispatch)
    args = {"action": "start_validation", "candidate_id": candidate.id}
    before, revision = deepcopy(state.to_dict()), state.committed_revision
    scope = await registry.execute("workflow", {**args, "related_requests": [
        declaration(url="https://outside.invalid/comments")]}, None, p)
    assert scope.status == "error" and "exact target origin" in scope
    assert "DUPLICATE_REQUEST_ASSOCIATION" not in scope
    assert state.to_dict() == before and state.committed_revision == revision
    await registry.execute("workflow", args, None, p)
    second = json.loads(await registry.execute("workflow", {
        "action": "record_candidate", "candidate_class": "xss", "endpoint": "/other",
        "method": "GET", "parameter": "q"}, None, p))["candidate"]["id"]
    before, revision = deepcopy(state.to_dict()), state.committed_revision
    conflict = await registry.execute("workflow", {"action": "start_validation", "candidate_id": second}, None, p)
    assert conflict.status == "error" and "another validation attempt is active" in conflict
    assert "DUPLICATE_REQUEST_ASSOCIATION" not in conflict
    assert state.to_dict() == before and state.committed_revision == revision


def test_resumed_association_checker_keeps_duplicate_invariant_and_safe_indices():
    url = apply_evidence(ORIGIN + "/comments?token=fixture-alpha")
    rows = [declaration(url=url, required=True)] * 2
    with pytest.raises(DuplicateRequestAssociation) as caught:
        request_associations({"related_requests": rows})
    assert caught.value.indices == (0, 1)
    assert url not in str(caught.value) and "fixture-alpha" not in str(caught.value)
