from __future__ import annotations

import io
from dataclasses import replace
import unicodedata

import pytest

from src.report.builder import build_report
from src.report.model import ReportError, ReportFinding, Resources, SourceSnapshot
from src.report.pdf import render_pdf

VI = "Đánh giá bảo mật ứng dụng; Đ/đ; Tiếng Việt: " + "".join(chr(c) for c in range(0x1EA0, 0x1EFA))


def document(root):
    return build_report(SourceSnapshot(target="https://target.test", target_name=VI,
        exported_at="2026-10-06T00:00:00Z", coverage=()), Resources(root, (), root))


def reader(raw):
    pypdf = pytest.importorskip("pypdf", reason="Install declared dev PDF reader for extraction checks")
    return pypdf.PdfReader(io.BytesIO(raw), strict=True)


def extracted(raw):
    return "\n".join(p.extract_text() for p in reader(raw).pages)


def test_unicode_sections_footers_and_repeatable_bytes(tmp_path):
    doc = document(tmp_path)
    raw = render_pdf(doc)
    assert raw.startswith(b"%PDF-") and raw.rstrip().endswith(b"%%EOF")
    assert raw == render_pdf(doc)
    pdf = reader(raw)
    assert len(pdf.pages) > 0
    text = extracted(raw)
    for expected in ("Đánh giá bảo mật ứng dụng", "Đ/đ", "Assessment summary", "Confirmed findings", "Evidence summary",
                     "Recorded attack surface", "Methodology and limitations", "Page 1"):
        assert expected in text
    # Font-map subset must survive actual PDF extraction, including the full Vietnamese corpus.
    for c in VI:
        assert c in text
    assert pdf.metadata.title == "KAgent assessment snapshot"
    assert all(not p.get("/Annots") for p in pdf.pages)


def test_nfd_normalization_and_literal_markup_no_resources(tmp_path, monkeypatch):
    doc = document(tmp_path)
    text = unicodedata.normalize("NFD", "Đánh giá tiếng Việt") + ' <img src="/etc/shadow"/> <link href="https://secret.test">x</link> & < >'
    doc = replace(doc, metadata=(("Target name", text),))
    from reportlab.lib import utils
    def forbidden(*args, **kwargs): raise AssertionError("resource fetch attempted")
    monkeypatch.setattr(utils, "open_for_read", forbidden)
    raw = render_pdf(doc)
    result = extracted(raw)
    assert "Đánh giá tiếng Việt" in result and '<img src="/etc/shadow"/>' in result
    assert "& < >" in result
    assert all(not p.get("/Annots") for p in reader(raw).pages)


def test_long_words_rows_and_findings_split_across_pages(tmp_path):
    doc = document(tmp_path)
    details = (("Observed impact", "Đánh giá " * 250), ("Potential impact", "word" * 450), ("Remediation", "recorded fix " * 150))
    findings = tuple(ReportFinding(f"cand-{i}", "Long persisted finding", "high", details) for i in range(8))
    coverage = tuple(("https://target.test/" + "a"*500, "variant " * 80) for _ in range(24))
    doc = replace(doc, findings=findings, finding_count=8, coverage=coverage)
    raw = render_pdf(doc)
    pdf = reader(raw)
    assert 6 < len(pdf.pages) < 200
    text = extracted(raw)
    assert "8. Long persisted finding" in text and "Methodology and limitations" in text
    assert all(f"Page {i}" in page.extract_text() for i, page in enumerate(pdf.pages, 1))


@pytest.mark.parametrize("cap", ["MAX_PAGES", "MAX_PDF"])
def test_caps_fail_without_pdf_result(tmp_path, monkeypatch, cap):
    import src.report.pdf as module
    monkeypatch.setattr(module, cap, 1)
    with pytest.raises(ReportError, match="limit"):
        render_pdf(document(tmp_path))


def test_missing_font_and_unsupported_characters_fail_locally(tmp_path, monkeypatch):
    monkeypatch.setenv("KAGENT_REPORT_FONT_REGULAR", str(tmp_path / "missing.ttf"))
    with pytest.raises(ReportError, match="Vietnamese-capable"):
        render_pdf(document(tmp_path))


def test_bold_can_fallback_to_unicode_regular(tmp_path, monkeypatch):
    monkeypatch.setenv("KAGENT_REPORT_FONT_BOLD", str(tmp_path / "missing.ttf"))
    monkeypatch.setenv("KAGENT_REPORT_FONT_REGULAR", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
    assert "Đánh giá" in extracted(render_pdf(document(tmp_path)))


def test_missing_pdf_dependency_is_lazy_and_safe(tmp_path, monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "reportlab.platypus", None)
    with pytest.raises(ReportError, match="PDF dependency unavailable"):
        render_pdf(document(tmp_path))


def test_sentinel_secrets_absent_from_pdf_text_and_metadata(tmp_path):
    from tests.report.test_builder import finding_fixture, source, resources
    from src.findings.store import render
    state, c, r, finding, path = finding_fixture(tmp_path)
    finding.title = "API_KEY: TITLE_SENTINEL"
    finding.observed_impact = "Authorization: Bearer IMPACT_SENTINEL"
    finding.potential_impact = '{"nested":{"password":"SHORT_SENTINEL"}}'
    finding.remediation = "run --password CLI_SENTINEL"
    finding.payload = "PAYLOAD_SENTINEL"
    finding.curl = "CURL_SENTINEL"
    finding.responseExcerpt = "EXCERPT_SENTINEL"
    finding.url = "https://USER_SENTINEL:PW_SENTINEL@target.test/item/12?token=QUERY_SENTINEL"
    path.write_text(render(finding))
    doc = build_report(replace(source(state), provider="api_key=PROVIDER_SENTINEL"), resources(tmp_path))
    raw = render_pdf(doc)
    text = extracted(raw) + str(reader(raw).metadata)
    for secret in ("TITLE_SENTINEL", "IMPACT_SENTINEL", "SHORT_SENTINEL", "CLI_SENTINEL", "PAYLOAD_SENTINEL", "CURL_SENTINEL", "EXCERPT_SENTINEL", "USER_SENTINEL", "PW_SENTINEL", "QUERY_SENTINEL", "PROVIDER_SENTINEL"):
        assert secret not in text and secret.encode() not in raw


@pytest.mark.parametrize("already_redacted", [False, True])
def test_multiline_labelled_secret_bodies_never_reach_pdf(tmp_path, already_redacted):
    from tests.report.test_builder import finding_fixture, source, resources
    from src.findings.store import render
    from src.redaction.redact import apply
    state, _, _, finding, path = finding_fixture(tmp_path)
    finding.observed_impact = "session_token: |\n  SESSION_BODY_SENTINEL\n  SESSION_CONTINUATION_SENTINEL"
    finding.potential_impact = "csrf_token: >-\n  CSRF_BODY_SENTINEL"
    finding.remediation = "private_key: |\n  PRIVATE_KEY_BODY_SENTINEL"
    if already_redacted:
        finding.observed_impact = apply(finding.observed_impact)
        finding.potential_impact = apply(finding.potential_impact)
        finding.remediation = apply(finding.remediation)
    path.write_text(render(finding))
    doc = build_report(source(state), resources(tmp_path))
    assert doc.finding_count == 1
    raw = render_pdf(doc)
    text = extracted(raw) + str(reader(raw).metadata)
    for sentinel in ("SESSION_BODY_SENTINEL", "SESSION_CONTINUATION_SENTINEL", "CSRF_BODY_SENTINEL", "PRIVATE_KEY_BODY_SENTINEL"):
        assert sentinel not in text and sentinel.encode() not in raw
