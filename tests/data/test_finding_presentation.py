from copy import deepcopy
from dataclasses import asdict
from typing import Any

import pytest

from src.findings.presentation import EvidenceLink, SummaryContext, artifact_links, render_summary
from src.findings.store import Finding
from src.workflow.evidence import EvidenceArtifact


def finding(**changes):
    values: dict[str, Any] = dict(title="Recorded finding", severity="medium", url="https://lab.test/item",
                  method="POST", parameter="q", observed_impact="Probe differed from control.",
                  potential_impact="Other effects were not assessed.", candidate_id="cand_private",
                  evidence_refs=["ev_private"], confirmation_binding="a" * 64,
                  assessment_result_id="result_private", assessment_attempt_id="attempt_private",
                  assessment_source="agent", binding_version=2,
                  classification_provenance={"origin": "verified-local"}, classification_revision=1)
    values.update(changes)
    return Finding(**values)


@pytest.mark.parametrize("kind,cwe,display", [
    ("sql-injection", ["CWE-89"], "SQL Injection"),
    ("cross-site-scripting", ["CWE-79"], "Cross-Site Scripting (XSS)"),
    ("access-control", None, "Broken Access Control"),
])
def test_summary_preserves_facts_and_omits_operational_metadata(kind, cwe, display):
    f = finding(canonical_class=kind, cwe=cwe, vulnerabilityType=display)
    ctx = SummaryContext(location="body", criteria="Control stayed unchanged.",
                         limitations="Only one input tested.")
    before = deepcopy(asdict(f))
    output = render_summary(f, context=ctx, evidence=(EvidenceLink("Proof", "../../../proof.md"),))
    assert "medium" in output and "https://lab.test/item" in output and "body" in output
    assert "Probe differed from control." in output and "Control stayed unchanged." in output
    assert "Only one input tested." in output and "Other effects were not assessed." in output
    assert "[Proof](../../../proof.md)" in output
    assert "cand_private" not in output and "ev_private" not in output and "a" * 64 not in output
    assert "result_private" not in output and "attempt_private" not in output
    assert "Classification provenance" not in output and "Binding version" not in output
    if cwe:
        assert cwe[0] in output
    else:
        assert "CWE-" not in output
    assert asdict(f) == before


def test_reproduction_retains_query_values_and_does_not_duplicate_payload():
    f = finding(payload="marker123", curl="curl 'https://lab.test/item?q=marker123'",
                responseExcerpt="marker123")
    output = render_summary(f)
    assert "curl 'https://lab.test/item?q=marker123'" in output
    assert "Recorded input:" not in output
    assert "Response excerpt:" in output
    assert "baseline/control requests and expected results" in output
    assert "Confirmation criteria:" in output and "Not recorded" in output
    assert "Verification limitations were not recorded separately." in output
    assert "Remediation" not in output


def test_xss_and_markdown_data_remain_literal_and_fences_cannot_be_closed():
    f = finding(title="XSS\n## forged", observed_impact="<script>alert(1)</script> [bad](javascript:x)",
                payload="marker\n```\n## payload heading")
    output = render_summary(f)
    assert "<script>" not in output and "&lt;script&gt;" in output
    assert "\n## forged" not in output and "[bad](javascript:x)" not in output
    assert "````\nmarker\n```\n## payload heading\n````" in output


def test_summary_redacts_context_requests_and_urls():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.signature"
    f = finding(url="https://operator:short-secret@lab.test/item?token=" + token,
                observed_impact="Authorization: Bearer hidden\n  continuation-secret",
                curl="curl -u operator:password https://lab.test/item",
                payload='{"password":"short"}')
    ctx = SummaryContext(criteria='{"api_key":"tiny"}', limitations="Cookie: short-cookie")
    output = render_summary(f, context=ctx)
    for secret in ("short-secret", token, "continuation-secret", "operator:password", "tiny", "short-cookie"):
        assert secret not in output
    assert "[REDACTED" in output
    assert "operator:" not in output


def test_long_response_stays_in_evidence_and_cleanup_is_visible():
    output = render_summary(finding(responseExcerpt="x" * 5000), context=SummaryContext(
        mutation_performed=True, cleanup_state="requires-user-action", cleanup_status="No readback performed."))
    assert "x" * 5000 not in output
    assert "requires-user-action" in output and "No readback performed." in output


@pytest.mark.parametrize("target", ["https://elsewhere.test/proof", "/etc/passwd", "//host/proof", "C:\\proof"])
def test_renderer_rejects_non_relative_evidence_links(target):
    with pytest.raises(ValueError, match="relative"):
        render_summary(finding(), evidence=(EvidenceLink("Proof", target),))


def test_artifact_links_resolve_to_original_proof_without_disclosing_source_path(tmp_path):
    proof = tmp_path / "proof with spaces.md"
    proof.write_text("Recorded proof")
    artifact = EvidenceArtifact.capture("cand", proof.name, tmp_path)
    directory = tmp_path / "artifacts/reports/findings"
    links = artifact_links([artifact], tmp_path, directory)
    output = render_summary(finding(), evidence=links)
    assert "../../../proof%20with%20spaces.md" in output
    assert str(tmp_path) not in output
    proof.unlink()
    missing = artifact_links([artifact], tmp_path, directory)
    assert missing[0].target is None and "unavailable" in missing[0].label


def test_sensitive_artifact_path_is_withheld(tmp_path):
    path = tmp_path / ".env"
    path.write_text("TOKEN=secret")
    artifact = EvidenceArtifact("ev_protected", "cand", ".env", "0" * 64, 12,
                                source_path="/operator/private/.env")
    links = artifact_links([artifact], tmp_path, tmp_path / "artifacts/reports/findings")
    assert links[0].target is None and "protected" in links[0].label
    output = render_summary(finding(), evidence=links)
    assert ".env" not in output and "TOKEN" not in output and "/operator/private" not in output
