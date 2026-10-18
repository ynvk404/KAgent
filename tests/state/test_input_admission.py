"""Admission regression: exact metadata, legacy IDs and atomic bindings."""
import json
from copy import deepcopy
from typing import Any

import pytest

from src.target.target import Target
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.state import (AttackSurfaceInput, Candidate, WorkflowObjective, WorkflowState,
                                attack_surface_input_fingerprint)

ORIGIN = "http://target.test"
FIELDS: dict[str, Any] = dict(objective_id="admission", target_origin=ORIGIN, method="GET", endpoint="/search",
              parameter="q", location="query")


def state():
    return WorkflowState(objective=WorkflowObjective("admission", "whole_target", ORIGIN))


def legacy(**changes):
    values = {**FIELDS, **changes}
    fingerprint_fields: dict[str, Any] = {key: values.get(key) for key in (
        "objective_id", "target_origin", "method", "endpoint", "parameter", "location", "input_type",
        "auth_context_ref", "baseline_request_ref", "content_type")}
    values["id"] = attack_surface_input_fingerprint(**fingerprint_fields)
    return AttackSurfaceInput(**values)


@pytest.mark.parametrize("endpoint", ["/search", "search", "http://TARGET.test:80/search", "http://target.test/search"])
def test_equivalent_new_inputs(endpoint):
    assert AttackSurfaceInput(**{**FIELDS, "endpoint": endpoint}).id == AttackSurfaceInput(**FIELDS).id


@pytest.mark.parametrize("endpoint", ["/Search", "/search/", "/search?a=1&b=2", "/search?b=2&a=1",
    "/search?q=1&q=2", "/search?q=2&q=1", "/search?q=%2f", "/search?q=%2F", "/search?q=/", "/search?"])
def test_raw_request_geometry_is_distinct(endpoint):
    assert AttackSurfaceInput(**{**FIELDS, "endpoint": endpoint}).id != AttackSurfaceInput(**FIELDS).id


@pytest.mark.parametrize("field,value", [("endpoint", "https://target.test/search"), ("endpoint", "http://other.test/search"),
    ("endpoint", "http://target.test:81/search"), ("endpoint", "http://user:secret@target.test/search"),
    ("endpoint", "//target.test/search"), ("endpoint", "/a/../search"), ("endpoint", "/%2e/search"),
    ("endpoint", "/search#client-route"), ("endpoint", "/search\r\nHeader: x"),
    ("endpoint", "/" + "x" * 501), ("parameter", "x" * 501),
    ("parameter", "password=secret"), ("auth_context_ref", "token=secret"),
    ("endpoint", "/search?token=[REDACTED]"), ("endpoint", "/search?q=%"), ("endpoint", "/search?q=%0a"),
    ("location", "request"), ("method", "GET POST")])
def test_invalid_admission_atomic(field, value):
    s = state()
    tool = WorkflowTool(s, Target(ORIGIN))
    before = deepcopy(s.to_dict())
    output = tool._record_input({**FIELDS, field: value})
    assert output.startswith("error:"), output
    assert s.to_dict() == before
    assert not s.evidence and not s.attempts and not s.persisted_findings


@pytest.mark.parametrize("changes", [{"endpoint": "GET /search\n"},
    {"endpoint": "GET /search", "method": "GET\n"}])
def test_method_shorthand_cannot_strip_unsafe_identity_before_admission(changes):
    s = state()
    before = deepcopy(s.to_dict())
    output = WorkflowTool(s, Target(ORIGIN))._record_input({**FIELDS, **changes})
    assert output.startswith("error:")
    assert s.to_dict() == before


def test_valid_method_shorthand_still_admits_exact_input():
    s = state()
    result = json.loads(WorkflowTool(s, Target(ORIGIN))._record_input(
        {**FIELDS, "endpoint": "GET /search", "method": None}))
    assert result["created"] and result["input"]["method"] == "GET"
    assert result["input"]["endpoint"] == ORIGIN + "/search"


@pytest.mark.parametrize("field", ["method", "endpoint", "parameter", "location"])
def test_sparse_is_not_a_whole_request(field):
    values = {**FIELDS, field: None}
    with pytest.raises(ValueError, match=field):
        AttackSurfaceInput(**values)
    s = state()
    item = legacy(**{field: None})
    before = s.to_dict()
    with pytest.raises(ValueError, match=field):
        s.add_attack_surface_input(item)
    assert s.to_dict() == before


def test_application_base_matches_existing_dispatch_and_observed_absolute_wins():
    s = state()
    tool = WorkflowTool(s, Target(ORIGIN + "/app"))
    item = json.loads(tool._record_input(FIELDS))["input"]
    assert item["endpoint"] == ORIGIN + "/app/search"
    same = json.loads(tool._record_input({**FIELDS, "endpoint": ORIGIN + "/app/search"}))
    assert not same["created"] and same["input"]["id"] == item["id"]
    root = json.loads(tool._record_input({**FIELDS, "endpoint": ORIGIN + "/search"}))
    assert root["created"] and root["input"]["id"] != item["id"]


@pytest.mark.parametrize("field,value", [("method", "POST"), ("auth_context_ref", "user-a"),
    ("baseline_request_ref", "capture-a"), ("content_type", "application/json")])
def test_execution_context_distinctions(field, value):
    assert AttackSurfaceInput(**{**FIELDS, field: value}).id != AttackSurfaceInput(**FIELDS).id


@pytest.mark.parametrize("endpoint", ["/search", "search", "http://TARGET.test:80/search", ORIGIN + "/search"])
def test_legacy_roundtrip_unique_reuse_preserves_candidate_attempt_links(endpoint):
    s = state()
    old = legacy(endpoint=endpoint)
    s.attack_surface_inputs[old.id] = old
    c, _ = s.add_candidate(Candidate(candidate_class="xss", target=ORIGIN, objective_id="admission",
        method="GET", endpoint="/search", parameter="q", location="query"), input_id=old.id)
    s.attempts["historical-attempt"] = {"candidate_id": c.id, "input_id": old.id}
    s.active_candidate_ids.add(c.id)
    before = s.to_dict()
    restored = WorkflowState.from_dict(before)
    assert restored.to_dict() == before
    stored, created = s.add_attack_surface_input(AttackSurfaceInput(**FIELDS))
    assert not created and stored.id == old.id
    assert s.to_dict() == before


def test_ambiguous_legacy_match_never_picks_first_even_exact_new_id():
    s = state()
    rows = [legacy(), legacy(endpoint=ORIGIN + "/search")]
    s.attack_surface_inputs = {row.id: row for row in rows}
    before = deepcopy(s.to_dict())
    with pytest.raises(ValueError, match="ambiguous canonical"):
        s.add_attack_surface_input(AttackSurfaceInput(**FIELDS))
    assert s.to_dict() == before


def test_source_conflict_is_not_provenance_merge_and_does_not_mutate():
    s = state()
    s.add_attack_surface_input(AttackSurfaceInput(**FIELDS, source_ref="browser:a"))
    before = deepcopy(s.to_dict())
    with pytest.raises(ValueError, match="request context conflicts"):
        s.add_attack_surface_input(AttackSurfaceInput(**FIELDS, source_ref="browser:b"))
    assert s.to_dict() == before


@pytest.mark.parametrize("field,value", [("objective_id", "other"), ("target", "http://other.test"),
    ("baseline_request_ref", "another-capture"), ("auth_context_ref", "another-user"),
    ("endpoint", "http://other.test/search"), ("parameter", "other")])
def test_candidate_binding_rejects_wrong_context_atomically(field, value):
    s = state()
    item, _ = s.add_attack_surface_input(AttackSurfaceInput(**FIELDS, baseline_request_ref="capture-a", auth_context_ref="user-a"))
    fields: dict[str, Any] = dict(candidate_class="xss", target=ORIGIN, objective_id="admission", method="GET", endpoint="/search",
                  parameter="q", location="query", baseline_request_ref="capture-a", auth_context_ref="user-a")
    before = deepcopy(s.to_dict())
    with pytest.raises(ValueError):
        s.add_candidate(Candidate(**{**fields, field: value}), input_id=item.id)
    assert s.to_dict() == before
    with pytest.raises(ValueError, match="unknown input"):
        s.add_candidate(Candidate(**fields), input_id="input_invalid")
    assert s.to_dict() == before


def test_historical_invalid_read_retirement_does_not_grant_validation_context():
    s = state()
    bad = legacy(endpoint="http://other.test/search")
    s.attack_surface_inputs[bad.id] = bad
    restored = WorkflowState.from_dict(s.to_dict())
    assert restored.attack_surface_inputs[bad.id].to_dict() == bad.to_dict()
    tool = WorkflowTool(restored, Target(ORIGIN))
    assert tool._get_input({"input_id": bad.id}).startswith("error:")
    before = deepcopy(restored.to_dict())
    c = Candidate(candidate_class="xss", target=ORIGIN, objective_id="admission")
    with pytest.raises(ValueError): restored.add_candidate(c, input_id=bad.id)
    assert restored.to_dict() == before
    restored.set_input_disposition(bad.id, "dropped", reason="historical invalid endpoint")
    assert not restored.attempts and not restored.evidence


@pytest.mark.parametrize("context", ["auth_context_ref", "baseline_request_ref"])
def test_occupied_legacy_id_preserves_context_links_and_active_attempt(context):
    from src.workflow.assessment import start_attempt

    s = state()
    fields = {**FIELDS, "endpoint": ORIGIN + "/search"}
    context_fields: dict[str, Any] = {context: "context-a"}
    old_id = attack_surface_input_fingerprint(**fields, input_type=None)
    old = AttackSurfaceInput(**fields, id=old_id, **context_fields,
                             source_ref="source-a", disposition="analyzed")
    s.attack_surface_inputs[old.id] = old
    candidate, _ = s.add_candidate(Candidate("xss", target=ORIGIN, objective_id="admission",
        method="GET", endpoint=old.endpoint, parameter="q", location="query",
        **context_fields), input_id=old.id)
    s.link_input_candidate(old.id, candidate.id)
    attempt = start_attempt(s, candidate, "fixture", "fixture-epoch")
    s.set_candidate_status(candidate.id, "validating")
    s = WorkflowState.from_dict(s.to_dict())
    before = deepcopy(s.to_dict())
    output = WorkflowTool(s, Target(ORIGIN))._record_input(fields)
    assert output.startswith("error:") and "input id" in output
    assert s.to_dict() == before
    assert s.attempts[attempt["id"]]["candidate_id"] == candidate.id
    # Explicit compatible context still reuses the legacy ID without rekeying.
    compatible = json.loads(WorkflowTool(s, Target(ORIGIN))._record_input(
        {**fields, context: "context-a", "source_ref": "source-a"}))
    assert not compatible["created"] and compatible["input"]["id"] == old.id
    assert s.to_dict() == before


@pytest.mark.parametrize("count", [41, 80])
def test_lowercase_expansion_is_rejected_before_input_fingerprint(count):
    s = state()
    tool = WorkflowTool(s, Target(ORIGIN))
    allowed = json.loads(tool._record_input({**FIELDS, "input_type": "İ" * 40}))
    assert allowed["input"]["input_type"] == "i\u0307" * 40
    before = deepcopy(s.to_dict())
    output = tool._record_input({**FIELDS, "input_type": "İ" * count})
    assert output.startswith("error:") and "input_type" in output
    assert s.to_dict() == before
    with pytest.raises(ValueError, match="input_type"):
        AttackSurfaceInput(**FIELDS, input_type="İ" * count)
