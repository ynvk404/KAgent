from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import json
import os
from typing import Any, cast

import pytest

from src.findings.store import Finding, render
from src.report.builder import Sanitizer, SEMANTIC_WARNING, build_report, bounded_read
from src.report.model import MAX_TEXT_INTAKE, Record, ReportError, Resources, SourceSnapshot, freeze
from src.ui.commands.report_handler import capture_workflow
from src.workflow.evidence import EvidenceArtifact
from src.workflow.goals import RequestedGoal
from src.workflow.review import review_snapshot
from src.workflow.state import AttackSurfaceInput, Candidate, ValidationResult, WorkflowObjective, WorkflowState, ValidationOutcome, validation_result_fingerprint
from tests.helpers.workflow import record_completed_phase

TARGET = "https://target.test"
NOW = "2026-10-06T00:00:00+00:00"


def resources(root):
    return Resources(root, (root / "artifacts/findings", root / "findings"), root)


def source(state=None, **kwargs):
    return SourceSnapshot(target=TARGET, exported_at=NOW,
        **(capture_workflow(state, TARGET) if state else {}), **kwargs)


def finding_fixture(root, *, outcome: ValidationOutcome = "confirmed", save=True):
    state = WorkflowState(objective=WorkflowObjective("one", "direct", TARGET))
    candidate = Candidate(candidate_class="xss", target=TARGET, objective_id="one", method="GET", endpoint="/item/{id}", parameter="q")
    state.candidates[candidate.id] = candidate
    evidence = EvidenceArtifact("ev_one", candidate.id, "proof.txt", "a" * 64, 5)
    state.evidence[evidence.id] = evidence
    result = ValidationResult(candidate_id=candidate.id, objective_id="one", skill_name="cross-site-scripting", outcome=outcome,
                              evidence_refs=[evidence.id], repeatable=True, coverage_synced=True)
    state.add_validation_result(result)
    state.persisted_findings[candidate.id] = validation_result_fingerprint(result)
    finding = Finding("Đánh giá XSS", "high", TARGET + "/item/12?secret=sentinel", "Observed", "Not assessed",
                      method="GET", parameter="q", candidate_id=candidate.id, evidence_refs=[evidence.id],
                      canonical_class=candidate.candidate_class, confirmation_binding=review_snapshot(state, candidate.id), createdAt=NOW)
    path = root / "artifacts/findings/one.md"
    if save:
        path.parent.mkdir(parents=True)
        path.write_text(render(finding))
    return state, candidate, result, finding, path


def test_target_only_empty_immutable_and_deterministic(tmp_path):
    doc = build_report(source(), resources(tmp_path))
    assert doc.status.startswith("Target snapshot")
    assert "No confirmed findings recorded in this assessment." in doc.summary
    assert SEMANTIC_WARNING in doc.limitations
    assert doc == build_report(source(), resources(tmp_path))
    assert dict(doc.metadata)["Exported at (UTC)"] == NOW
    with pytest.raises(FrozenInstanceError):
        setattr(doc, "status", "completed")
    tree = freeze({"list": [{"thing": "value"}]})
    assert isinstance(tree.get("list"), tuple)
    assert isinstance(tree.get("list")[0], Record)
    assert all(isinstance(getattr(doc, attr), tuple) for attr in ("metadata", "findings", "inventory", "coverage", "limitations"))


def test_persisted_finding_missing_proof_is_historical_not_revoked(tmp_path):
    state, candidate, result, finding, path = finding_fixture(tmp_path)
    before = deepcopy(state.to_dict())
    doc = build_report(source(state), resources(tmp_path))
    assert doc.finding_count == 1 and doc.unfinalized_count == 0
    assert dict(doc.findings[0].details)["URL"] == TARGET + "/item/12"
    assert "Referenced evidence file unavailable" in doc.evidence[0][1]
    assert "a" * 64 in doc.evidence[0][1]
    assert state.to_dict() == before
    assert path.read_text() == render(finding)


@pytest.mark.parametrize("fault", ["file", "duplicate", "binding", "fingerprint", "owner", "method", "parameter", "class", "origin", "endpoint", "refs", "sync", "corrupt", "metadata", "legacy", "severity"])
def test_missing_stale_ambiguous_provenance_is_never_zero_or_finding(tmp_path, fault):
    state, c, r, f, path = finding_fixture(tmp_path)
    if fault == "file": path.unlink()
    elif fault == "duplicate":
        legacy = tmp_path / "findings/duplicate.md"
        legacy.parent.mkdir(); legacy.write_bytes(path.read_bytes())
    elif fault == "binding": f.confirmation_binding = "b" * 64
    elif fault == "fingerprint": state.persisted_findings[c.id] = "wrong"
    elif fault == "owner": state.evidence["ev_one"] = replace(state.evidence["ev_one"], candidate_id="foreign")
    elif fault == "method": f.method = "POST"
    elif fault == "parameter": f.parameter = "different"
    elif fault == "class": f.canonical_class = "sql-injection"
    elif fault == "origin": f.url = "https://other.test/item/12"
    elif fault == "endpoint": f.url = TARGET + "/wrong"
    elif fault == "refs": f.evidence_refs = ["ev_unknown"]
    elif fault == "sync": r.coverage_synced = False
    elif fault == "legacy": f.confirmation_binding = None
    elif fault == "severity": path.write_text(path.read_text().replace("**Severity:** high", "**Severity:** unknown"))
    elif fault == "metadata": path.write_text(path.read_text().replace("## Observed impact", "- **Severity:** critical\n\n## Observed impact"))
    elif fault == "corrupt": path.write_bytes(b"\xff")
    if fault in {"binding", "method", "parameter", "class", "origin", "endpoint", "refs", "legacy"}: path.write_text(render(f))
    doc = build_report(source(state), resources(tmp_path))
    assert doc.finding_count == 0 and doc.unfinalized_count == 1
    assert doc.unavailable_count == 1
    assert "No confirmed findings recorded in this assessment." not in doc.summary


def test_candidate_and_confirmed_result_alone_are_not_findings(tmp_path):
    state, c, r, f, path = finding_fixture(tmp_path)
    state.persisted_findings.clear()
    doc = build_report(source(state), resources(tmp_path))
    assert doc.unfinalized_count == 1 and not doc.findings
    state.validation_results.clear()
    doc = build_report(source(state), resources(tmp_path))
    assert not doc.findings and "no validation" in doc.status


def test_retest_owns_result_while_candidate_retains_historical_owner(tmp_path):
    state, c, r, f, path = finding_fixture(tmp_path)
    state.objective = WorkflowObjective("retest", "candidate_validation", TARGET, candidate_id=c.id)
    r.objective_id = "retest"
    f.confirmation_binding = review_snapshot(state, c.id)
    path.write_text(render(f))
    doc = build_report(source(state), resources(tmp_path))
    assert doc.finding_count == 1 and "prerequisites satisfied" in doc.status
    # A forced identical result has the same semantic fingerprint, different historical binding.
    state.validation_results.append(deepcopy(r))
    doc = build_report(source(state), resources(tmp_path))
    assert not doc.findings and any("binding" in l for l in doc.limitations)


def test_snapshot_detaches_and_filters_foreign_state(tmp_path):
    state, c, r, f, path = finding_fixture(tmp_path)
    foreign = Candidate(candidate_class="xss", target="https://foreign.test", endpoint="/secret", objective_id="foreign")
    state.candidates[foreign.id] = foreign
    snap = source(state)
    c.parameter = "changed"
    r.notes = "changed"
    assert state.objective is not None
    state.objective.id = "changed"
    doc = build_report(snap, resources(tmp_path))
    assert doc.finding_count == 1 and "changed" not in " ".join(doc.text_values())
    assert "foreign.test" not in " ".join(doc.text_values())
    assert "Other assessment records were excluded from this snapshot." in doc.limitations


def test_no_target_and_objective_conflict_rejected(tmp_path):
    for target in ("", "juice.lab", "file:///tmp/a", "http://"):
        with pytest.raises(ReportError, match="no valid active target"):
            build_report(replace(source(), target=target), resources(tmp_path))
    with pytest.raises(ReportError, match="do not match"):
        build_report(replace(source(), objective=freeze({"id": "other", "target_origin": "https://foreign.test"})), resources(tmp_path))
    assert not (tmp_path / "artifacts").exists()


@pytest.mark.parametrize("text,secret", [
    ("Authorization: Bearer SENTINEL", "SENTINEL"), ("Basic c2VudGluZWw=", "c2VudGluZWw"),
    ("Cookie: session=SENTINEL", "SENTINEL"), ("Set-Cookie: session=SENTINEL", "SENTINEL"),
    ('{"nested":{"password":"abc"}}', "abc"), ("pwd: xy", "xy"), ("p a s s w o r d: xy", "xy"),
    ("api_key: SENTINEL", "SENTINEL"), ("secret: |\n  abc\n  xyz", "abc"),
    ("curl -u me:abc https://target.test/", "abc"), ("run --password abc", "abc"),
    ("https://me:%61bc@target.test/a?token=SENTINEL#secret", "abc"),
    ("aa…[REDACTED:···]…bb", "aa"), ("jwt: eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidGVzdCJ9.abcdef", "eyJ"),
    ("token=abc&other=yes", "abc"),
])
def test_report_boundary_redacts_short_and_legacy_secrets(text, secret):
    cleaned = Sanitizer().text(text, 2000)
    assert secret not in cleaned


@pytest.mark.parametrize("label", ["session_token", "csrf_token", "private_key", "id_token", "xsrf-token",
                                  "session_key", "credentials", '"private-key"', "SESSION.TOKEN", "s e s s i o n _ t o k e n"])
@pytest.mark.parametrize("header", ["|", ">-", "[REDACTED]"])
@pytest.mark.parametrize("proof", [False, True])
def test_labelled_multiline_credentials_are_suppressed_including_redacted_headers(label, header, proof):
    text = f"Recorded details:\n  {label}: {header}\n    FIRST_SECRET_SENTINEL\n    SECOND_SECRET_SENTINEL\n"
    assert Sanitizer().text(text, 2000, proof=proof) == "[REDACTED]"


def test_ordinary_multiline_prose_is_preserved():
    text = "description: |\n  Ordinary recorded observations.\n  Follow up after deployment.\nSession token handling:\n  Review the rotation procedure."
    assert Sanitizer().text(text, 2000, proof=True) == text


@pytest.mark.parametrize("endpoint", ["https://foreign.test/private-endpoint", "//foreign.test/private-endpoint"])
def test_restored_foreign_endpoints_are_withheld_from_all_report_projections(tmp_path, endpoint):
    state = WorkflowState(objective=WorkflowObjective("one", "whole_target", TARGET))
    item = AttackSurfaceInput("one", TARGET, endpoint=endpoint, method="GET", disposition="analyzed")
    state.attack_surface_inputs[item.id] = item
    candidate = Candidate(candidate_class="xss", target=TARGET, objective_id="one", endpoint=endpoint, method="GET")
    state.candidates[candidate.id] = candidate
    state.add_validation_result(ValidationResult(candidate.id, "cross-site-scripting", "not-confirmed",
        objective_id="one", notes="FOREIGN_VALIDATION_SENTINEL", coverage_synced=True))
    restored = WorkflowState.from_dict(state.to_dict())
    for phase in ("recon", "enumeration", "input_analysis"):
        record_completed_phase(restored, phase, objective_id="one", target_origin=TARGET,
                               artifact_ref="record.txt", no_inputs_discovered=phase == "input_analysis")
    before = deepcopy(restored.to_dict())
    row = freeze(dict(endpoint="GET " + endpoint, param="q", vulnClass="xss", status="passed",
        count=1, firstSeen=0, lastSeen=0, context=dict(objective_id="one", target_origin=TARGET),
        notes="FOREIGN_COVERAGE_SENTINEL"))
    doc = build_report(source(restored, coverage=(row,)), resources(tmp_path))
    assert not doc.inventory and not doc.validations and not doc.coverage
    assert "foreign.test" not in " ".join(doc.text_values())
    assert "FOREIGN_" not in " ".join(doc.text_values())
    assert any("Report incomplete" in text and "endpoint" in text for text in doc.limitations)
    assert "prerequisites satisfied" not in doc.status
    assert restored.to_dict() == before


@pytest.mark.parametrize("endpoint", ["/relative", "relative", TARGET + "/absolute", "//target.test/same-origin"])
def test_same_origin_and_relative_endpoints_remain_reportable(tmp_path, endpoint):
    state = WorkflowState(objective=WorkflowObjective("one", "whole_target", TARGET))
    item = AttackSurfaceInput("one", TARGET, endpoint=endpoint)
    state.attack_surface_inputs[item.id] = item
    row = freeze(dict(endpoint=endpoint, param="q", vulnClass="xss", status="passed", count=1,
        firstSeen=0, lastSeen=0, context=dict(objective_id="one", target_origin=TARGET)))
    doc = build_report(source(WorkflowState.from_dict(state.to_dict()), coverage=(row,)), resources(tmp_path))
    assert len(doc.inventory) == 1 and len(doc.coverage) == 1
    assert not any("conflicting endpoint" in text for text in doc.limitations)


@pytest.mark.parametrize("endpoint", ["https://foreign.test/private-endpoint", "//foreign.test/private-endpoint"])
def test_builder_independently_withholds_conflicting_endpoints(tmp_path, endpoint):
    snap = SourceSnapshot(target=TARGET, exported_at=NOW, coverage=(),
        objective=freeze(dict(id="one", mode="direct", target_origin=TARGET)),
        candidates=(freeze(dict(id="candidate", objective_id="one", target=TARGET, endpoint=endpoint)),),
        inputs=(freeze(dict(id="input", objective_id="one", target_origin=TARGET, endpoint=endpoint)),),
        results=(freeze(dict(candidate_id="candidate", objective_id="one", outcome="not-confirmed",
                             notes="FOREIGN_VALIDATION_SENTINEL")),))
    doc = build_report(snap, resources(tmp_path))
    assert not doc.inventory and not doc.validations
    assert "foreign.test" not in " ".join(doc.text_values())
    assert "FOREIGN_VALIDATION_SENTINEL" not in " ".join(doc.text_values())
    assert any("Report incomplete" in text and "endpoint" in text for text in doc.limitations)


def test_controls_nfc_markup_are_literal_and_oversize_omitted_before_truncation():
    clean = Sanitizer()
    value = clean.text("Đa\u0301nh\x1b[31m <img src='/private'>\u202ereport\x00")
    assert value == "Đánh <img src='/private'>report"
    secret = "prefix-secret" + "x" * MAX_TEXT_INTAKE
    assert "prefix-secret" not in clean.text(secret, 20)
    assert clean.omissions == 1
    assert clean.text("x" * 600) .endswith("[truncated]")


def test_protected_evidence_path_not_opened_or_disclosed(tmp_path):
    state, c, r, f, path = finding_fixture(tmp_path)
    state.evidence["ev_one"] = replace(state.evidence["ev_one"], source_path="/etc/shadow")
    f.confirmation_binding = review_snapshot(state, c.id); path.write_text(render(f))
    doc = build_report(source(state), resources(tmp_path))
    assert doc.finding_count == 1 and "Path withheld" in doc.evidence[0][1]
    assert "proof.txt" not in doc.evidence[0][1]


def test_coverage_contexts_remain_distinct_and_legacy_not_proof(tmp_path):
    state = WorkflowState(objective=WorkflowObjective("one", "direct", TARGET))
    base = dict(endpoint="POST /search?q=SECRET", param="q", vulnClass="xss", status="passed", count=1)
    context = dict(objective_id="one", target_origin=TARGET, method="POST", location="body", media_type="application/json", auth_context_ref="auth-a", test_case="one")
    rows = [freeze({**base, "context": context}), freeze({**base, "context": {**context, "media_type": "application/x-www-form-urlencoded"}}), freeze({**base, "context": None})]
    doc = build_report(source(state, coverage=tuple(rows)), resources(tmp_path))
    assert len(doc.coverage) == 3
    assert "SECRET" not in " ".join(doc.text_values())
    assert "Legacy/unattributed" in " ".join(doc.text_values())
    assert all("Recorded check did not confirm" in row[1] for row in doc.coverage)
    assert not doc.findings


def test_coverage_known_mirror_dedup_and_foreign_exclusion(tmp_path):
    state = WorkflowState(objective=WorkflowObjective("one", "direct", TARGET))
    row = dict(endpoint="/a", param="q", vulnClass="xss", status="failed", observationIds=["obs1"])
    contexts = (dict(objective_id="one", target_origin=TARGET), None,
                dict(objective_id="other", target_origin=TARGET), dict(target_origin="https://foreign.test"))
    doc = build_report(source(state, coverage=tuple(freeze({**row, "context": c}) for c in contexts)), resources(tmp_path))
    assert len(doc.coverage) == 1 and "positive check" in doc.coverage[0][1]
    assert "method: Not recorded" in doc.coverage[0][1]


def test_unloaded_coverage_read_does_not_quarantine_corrupt_file(tmp_path):
    path = tmp_path / "coverage.json"; path.write_bytes(b"bad json")
    doc = build_report(source(), replace(resources(tmp_path), coverage_paths=(path,)))
    assert any("Coverage projection unavailable" in l for l in doc.limitations)
    assert path.read_bytes() == b"bad json"
    path.write_text(json.dumps({"version": 1, "entries": []}))
    doc = build_report(source(), replace(resources(tmp_path), coverage_paths=(path,)))
    assert not any("Coverage projection unavailable" in l for l in doc.limitations)


@pytest.mark.parametrize("bad", ["none", "sync", "cleanup", "goal", "unsupported"])
def test_recorded_closure_requires_phase_goals_and_current_terminal_links(tmp_path, bad):
    state = WorkflowState(objective=WorkflowObjective("one", "whole_target", TARGET))
    for phase in ("recon", "enumeration", "input_analysis"):
        record_completed_phase(state, phase, objective_id="one", target_origin=TARGET, artifact_ref="record.txt", no_inputs_discovered=phase == "input_analysis")
    c = Candidate(candidate_class="xss", target=TARGET, objective_id="one", endpoint="/a")
    state.candidates[c.id] = c
    r = ValidationResult(c.id, "cross-site-scripting", "not-confirmed", objective_id="one", coverage_synced=True)
    state.add_validation_result(r)
    assert state.objective is not None
    state.objective.requested_goals.append(RequestedGoal("xss", status="tested_not_confirmed", candidate_ids=[c.id]))
    assert "prerequisites satisfied" in build_report(source(state), resources(tmp_path)).status
    if bad == "none": state.validation_results.clear()
    elif bad == "sync": r.coverage_synced = False
    elif bad == "cleanup": r.cleanup_state = "pending"
    elif bad == "goal": state.objective.requested_goals[0].candidate_ids = ["missing"]
    elif bad == "unsupported": state.objective.requested_goals[0].status = "unsupported"
    assert "prerequisites satisfied" not in build_report(source(state), resources(tmp_path)).status


def test_record_limits_and_single_descriptor_byte_bound(tmp_path, monkeypatch):
    import src.report.builder as builder
    monkeypatch.setattr(builder, "MAX_RESULTS", 0)
    state, *_ = finding_fixture(tmp_path)
    with pytest.raises(ReportError, match="record limits"):
        build_report(source(state), resources(tmp_path))
    file = tmp_path / "bytes"; file.write_bytes(b"123456789")
    with pytest.raises(ValueError): bounded_read(file, 8)
    linked = tmp_path / "linked"; os.link(file, linked)
    with pytest.raises(ValueError): bounded_read(file, 20)


def test_single_saved_byte_snapshot_survives_classification_replacement(tmp_path, monkeypatch):
    import src.report.builder as builder
    state, c, r, f, path = finding_fixture(tmp_path)
    original = builder.read_report_bytes
    def replace_during_parse(raw, *, slug):
        f.cwe = ["CWE-79"]; f.classification_revision = 1
        f.classification_provenance = {"origin": "verified-local"}
        path.write_text(render(f))
        return original(raw, slug=slug)
    monkeypatch.setattr(builder, "read_report_bytes", replace_during_parse)
    doc = build_report(source(state), resources(tmp_path))
    assert doc.finding_count == 1
    assert dict(doc.findings[0].details)["CWE"] == "Not recorded"
    assert dict(doc.findings[0].details)["Classification revision"] == "0"


def test_severity_order_totals_and_explicit_detail_omissions(tmp_path, monkeypatch):
    import src.report.builder as builder
    state, c, r, f, path = finding_fixture(tmp_path)
    c2 = Candidate(candidate_class="xss", target=TARGET, objective_id="one", method="GET", endpoint="/second", parameter="q")
    state.candidates[c2.id] = c2
    e = EvidenceArtifact("ev_two", c2.id, "second.txt", "b"*64, 5)
    state.evidence[e.id] = e
    r2 = ValidationResult(c2.id, "cross-site-scripting", "confirmed", objective_id="one", evidence_refs=[e.id])
    state.add_validation_result(r2)
    state.persisted_findings[c2.id] = validation_result_fingerprint(r2)
    f2 = replace(f, candidate_id=c2.id, severity="critical", url=TARGET + "/second", evidence_refs=[e.id], confirmation_binding=review_snapshot(state, c2.id))
    (path.parent / "two.md").write_text(render(f2))
    monkeypatch.setattr(builder, "MAX_FINDINGS", 1)
    doc = build_report(source(state), resources(tmp_path))
    assert doc.finding_count == 2 and doc.omitted_count == 1
    assert doc.findings[0].severity == "critical"
    assert dict(doc.severity_counts)["high"] == 1
    assert any("Report incomplete" in text for text in doc.limitations)


def test_scan_and_intake_completeness_fail_instead_of_asserting_authority(tmp_path, monkeypatch):
    import src.report.builder as builder
    state, *_ = finding_fixture(tmp_path)
    monkeypatch.setattr(builder, "MAX_SCAN", 0)
    with pytest.raises(ReportError, match="scan limit"):
        build_report(source(state), resources(tmp_path))
    monkeypatch.setattr(builder, "MAX_SCAN", 2000)
    monkeypatch.setattr(builder, "MAX_INTAKE", 1)
    with pytest.raises(ReportError, match="intake limit"):
        build_report(source(state), resources(tmp_path))


def test_canonical_projection_links_only_matching_coverage_variant(tmp_path):
    state, c, r, f, path = finding_fixture(tmp_path)
    snap = source(state)
    projection = snap.results[-1].get("projection")
    assert isinstance(projection, Record)
    row = dict(projection.values)
    rows = (freeze({**row, "status": "failed"}), freeze({**row, "status": "failed", "context": {**dict(row["context"].values), "media_type": "application/json"}}))
    doc = build_report(replace(snap, coverage=rows), resources(tmp_path))
    assert len(doc.coverage) == 2
    assert sum("latest canonical outcome: confirmed" in details for _, details in doc.coverage) == 1


def test_protected_finding_root_never_enumerated(tmp_path, monkeypatch):
    import src.report.builder as builder
    state, *_ = finding_fixture(tmp_path)
    monkeypatch.setattr(builder, "is_sensitive_path", lambda path: True)
    def forbidden(*args): raise AssertionError("protected directory enumerated")
    monkeypatch.setattr(builder.os, "scandir", forbidden)
    doc = build_report(source(state), resources(tmp_path))
    assert not doc.findings and doc.unavailable_count == 1


def test_malformed_coverage_context_is_not_copied_or_exact_proof(tmp_path):
    state = WorkflowState(objective=WorkflowObjective("one", "direct", TARGET))
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps({"version": 1, "entries": [{"endpoint": "/a", "param": "q", "vulnClass": "xss", "status": "passed", "count": 1, "firstSeen": 0, "lastSeen": 0, "context": {
        "objective_id": "one", "target_origin": TARGET, "authorization": "SECRET_SENTINEL"}}]}))
    doc = build_report(source(state), replace(resources(tmp_path), coverage_paths=(path,)))
    assert not doc.coverage and any("Malformed coverage context" in text for text in doc.limitations)
    assert "SECRET_SENTINEL" not in " ".join(doc.text_values())


def test_value_objects_freeze_constructor_collections_and_reject_live_objects():
    from src.report.model import ReportFinding
    nested = [["URL", "https://target.test"]]
    finding = ReportFinding("cand", "title", "high", cast(Any, nested))
    nested[0][1] = "mutated"
    assert finding.details == (("URL", "https://target.test"),)
    with pytest.raises(ReportError, match="Unsupported report source"):
        ReportFinding("cand", cast(Any, object()), "high", ())


def test_corrupt_coverage_identity_list_is_omitted_without_quarantine(tmp_path):
    path = tmp_path / "coverage.json"
    raw = json.dumps({"version": 1, "entries": [{"endpoint": "/a", "param": "q", "vulnClass": "xss", "status": "passed", "count": 1, "firstSeen": 0, "lastSeen": 0, "observationIds": {"secret": "SECRET_SENTINEL"}}]})
    path.write_text(raw)
    doc = build_report(source(), replace(resources(tmp_path), coverage_paths=(path,)))
    assert not doc.coverage and any("Malformed coverage row omitted" in text for text in doc.limitations)
    assert path.read_text() == raw and "SECRET_SENTINEL" not in " ".join(doc.text_values())
