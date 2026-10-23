"""Persisted manual metadata remains readable after retiring its UI producers.

Historical operator/enrichment fields are injected only into stored test data;
no manual review or enrichment implementation is retained to build fixtures.
"""
from datetime import datetime, timezone

import pytest

from src.findings.store import Store, read_report, render
from src.report.builder import build_report
from src.report.model import Resources, SourceSnapshot
from src.report.pdf import render_pdf
from src.session.store import Store as SessionStore
from src.skills.registry import Skill
from src.tools.workflow.finding import ConfirmFindingTool
from src.ui.commands.report_handler import capture_workflow
from src.workflow.assessment import accepted_result, seal
from src.workflow.evidence.review import confirmation_binding
from tests.security.test_agent_assessment import setup
from tests.security.test_execution_policy import runtime, ORIGIN


@pytest.mark.parametrize("candidate_class,source,enriched,expected_cwe", [
    ("sqli", "agent", False, ["CWE-89"]),
    ("access-control", "agent", False, None),
    ("access-control", "operator", False, None),
    ("access-control", "operator", True, ["CWE-862"]),
])
async def test_session_finding_and_pdf_roundtrip_with_current_and_historical_metadata(
    runtime, tmp_path, candidate_class, source, enriched, expected_cwe,
):
    # Historical access-control metadata still needs a valid current result
    # for this round-trip check. Install an explicit custom test validator;
    # this class has no shipped expert playbook after catalog simplification.
    extra = (Skill("fixture-access-control", "Historical metadata fixture", ["http"], False,
        str(tmp_path / "custom/SKILL.md"), "", stage="validation",
        candidate_classes=["access-control"]),) if candidate_class == "access-control" else ()
    state, candidate, _, args, _ = await setup(runtime, tmp_path,
        candidate_class=candidate_class, extra_skills=extra)
    if candidate_class == "access-control":
        args["skill_name"] = "fixture-access-control"
    registry, prompter, policy, operator, *_ = runtime
    assessed = await registry.execute("workflow", args, None, prompter)
    assert not assessed.startswith("error:"), assessed
    store = Store(project_directory=tmp_path)
    registry.register(ConfirmFindingTool(store, workflow=state))
    await registry.execute("confirm_finding", {
        "candidate_id": candidate.id, "title": "Persisted assessment fixture",
        "url": ORIGIN + "/fixture", "severity": "low",
        "observed_impact": "Fixture response observed.",
        "potential_impact": "No additional impact assessed.",
    }, None, prompter)
    path = store.report_for_candidate(candidate.id)
    finding = read_report(path)
    result = state.latest_result(candidate.id)
    assert result is not None
    if source == "operator":
        # Simulate a previously persisted operator revision with its original
        # evidence contract intact; this fixture grants no execution authority.
        # These historical reports predate automatic CWE review annotations.
        finding.classification_review = None
        result.assessment_source = "operator"
        result.assessment_binding = seal(result)
        finding.assessment_source = "operator"
        finding.confirmation_binding = confirmation_binding(state, candidate.id)
        state.mark_finding_persisted(candidate.id)
    if enriched:
        finding.cwe = expected_cwe
        finding.classification_revision = 1
        finding.classification_provenance = {
            "origin": "promoted-external", "operator_reviewed": True,
            "selected_cwe": "CWE-862", "revision": 1,
        }
    path.write_text(render(finding), encoding="utf-8")
    original_report = path.read_bytes()
    session = SessionStore.new_with_id(tmp_path / "sessions", "persisted-metadata")
    await session.save([], workflow=state, engagement_state=policy.engagement)
    original_session = session.path.read_bytes()

    loaded = session.load().workflow
    restored = loaded.latest_result(candidate.id)
    persisted = read_report(Store(project_directory=tmp_path).report_for_candidate(candidate.id))
    assert restored is not None and restored.assessment_source == source
    assert persisted.assessment_source == source and persisted.cwe == expected_cwe
    if candidate_class == "sqli":
        assert persisted.owasp == ["A03:2021 Injection"]
    if enriched:
        assert persisted.classification_provenance == finding.classification_provenance
    assert accepted_result(loaded, loaded.candidates[candidate.id], restored, policy)
    assert loaded.finding_is_persisted(candidate.id)
    snapshot = SourceSnapshot(target=ORIGIN, exported_at=datetime.now(timezone.utc).isoformat(),
        **capture_workflow(loaded, ORIGIN, policy))
    document = build_report(snapshot, Resources(tmp_path, (store.dir,), tmp_path))
    assert document.finding_count == 1 and document.unavailable_count == 0
    details = dict(document.findings[0].details)
    assert details["CWE"] == (", ".join(expected_cwe) if expected_cwe else "Not recorded")
    if enriched:
        assert details["Classification origin"] == "promoted-external"
    assert render_pdf(document).startswith(b"%PDF-")
    assert path.read_bytes() == original_report and session.path.read_bytes() == original_session
    assert not operator.requests
