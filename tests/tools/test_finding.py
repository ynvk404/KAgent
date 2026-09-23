from __future__ import annotations

import json

import pytest

from src.findings.store import Finding, Store, slugify
from src.findings.classification import classify
from src.permission.permission import AlwaysAllow
from src.redact.redact import apply as redact
from src.tools.finding import (
    SEVERITIES,
    ConfirmFindingTool,
    is_severity,
)
from src.workflow.state import Candidate, ValidationResult, WorkflowState


def _tool(tmp_path, notifier=None):
    store = Store(str(tmp_path / "findings"))
    return ConfirmFindingTool(store, notifier=notifier), store


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "outcome",
    [
        "not-confirmed",
        "blocked",
        "insufficient-evidence",
        "deferred",
        "browser-required",
        "authorization-required",
    ],
)
async def test_structured_non_confirmed_results_are_not_eligible(tmp_path, outcome):
    workflow = WorkflowState()
    candidate, _ = workflow.add_candidate(
        Candidate(candidate_class="xss", endpoint="/search", parameter="q")
    )
    workflow.add_validation_result(
        ValidationResult(candidate.id, "cross-site-scripting", outcome)
    )
    tool = ConfirmFindingTool(
        Store(str(tmp_path / "findings")),
        workflow=workflow,
    )

    with pytest.raises(Exception, match="latest ValidationResult"):
        await tool.run(
            {
                "candidate_id": candidate.id,
                "title": "Not eligible",
                "severity": "medium",
                "url": "https://target.test/search",
                "impact": "None proven",
            },
            None,
            AlwaysAllow(),
        )
    assert not (tmp_path / "findings").exists()


@pytest.mark.asyncio
async def test_confirmed_structured_result_is_eligible(tmp_path):
    workflow = WorkflowState()
    candidate, _ = workflow.add_candidate(
        Candidate(candidate_class="sqli", endpoint="/product", parameter="id")
    )
    workflow.add_validation_result(
        ValidationResult(
            candidate.id,
            "sql-injection",
            "confirmed",
            evidence_refs=["captures/sql-proof"],
        )
    )
    tool = ConfirmFindingTool(
        Store(str(tmp_path / "findings")),
        workflow=workflow,
    )

    result = await tool.run(
        {
            "candidate_id": candidate.id,
            "title": "Confirmed SQL injection",
            "severity": "high",
            "url": "https://target.test/product",
            "impact": "Database query manipulation",
        },
        None,
        AlwaysAllow(),
    )
    assert "written to" in result
    report = next((tmp_path / "findings").glob("*.md")).read_text(encoding="utf-8")
    assert f"- **Candidate ID:** {candidate.id}" in report


@pytest.mark.asyncio
async def test_unknown_or_resultless_candidate_cannot_create_finding(tmp_path):
    workflow = WorkflowState()
    candidate, _ = workflow.add_candidate(
        Candidate(candidate_class="xss", endpoint="/search", parameter="q")
    )
    tool = ConfirmFindingTool(Store(str(tmp_path / "findings")), workflow=workflow)

    for candidate_id in ("cand_unknown", candidate.id):
        with pytest.raises(Exception, match="latest ValidationResult"):
            await tool.run(
                {
                    "candidate_id": candidate_id,
                    "title": "Ineligible",
                    "severity": "medium",
                    "url": "https://target.test/search",
                    "impact": "No proven impact",
                },
                None,
                AlwaysAllow(),
            )
    assert not (tmp_path / "findings").exists()


@pytest.mark.asyncio
async def test_same_candidate_creates_append_only_reports(tmp_path):
    workflow = WorkflowState()
    candidate, _ = workflow.add_candidate(
        Candidate(candidate_class="sqli", endpoint="/product", parameter="id")
    )
    workflow.add_validation_result(
        ValidationResult(candidate.id, "sql-injection", "confirmed")
    )
    tool = ConfirmFindingTool(Store(str(tmp_path / "findings")), workflow=workflow)
    args = {
        "candidate_id": candidate.id,
        "title": "SQL injection in product",
        "severity": "high",
        "url": "https://target.test/product",
        "impact": "Query manipulation",
    }

    await tool.run(args, None, AlwaysAllow())
    first = tmp_path / "findings" / "sql-injection-in-product.md"
    original = first.read_bytes()
    await tool.run(args, None, AlwaysAllow())
    second = tmp_path / "findings" / "sql-injection-in-product-2.md"
    assert second.exists()
    assert first.read_bytes() == original

    await tool.run({**args, "title": "SQL injection in catalog"}, None, AlwaysAllow())
    third = tmp_path / "findings" / "sql-injection-in-catalog.md"
    assert third.exists()
    assert first.read_bytes() == original
    assert len(list((tmp_path / "findings").glob("*.md"))) == 3
    for report in (first, second, third):
        assert f"- **Candidate ID:** {candidate.id}" in report.read_text(encoding="utf-8")


def test_metadata(tmp_path):
    tool, _ = _tool(tmp_path)

    assert tool.name() == "confirm_finding"
    assert tool.context_reduction_policy() == "preserve"
    assert isinstance(tool.description(), str) and tool.description()
    assert tool.requires_permission() is False

    schema = tool.schema()
    assert schema["type"] == "object"
    assert schema["required"] == ["title", "severity", "url", "impact"]
    assert schema["properties"]["severity"]["enum"] == list(SEVERITIES)
    assert schema["properties"]["vuln_class"]["type"] == "string"
    assert "vuln_class" not in schema["required"]


@pytest.mark.parametrize(
    "value,expected",
    [
        ("  SQLI  ", "SQL Injection"),
        ("sql-injection", "SQL Injection"),
        (" xSs ", "Cross-Site Scripting (XSS)"),
        ("cross-site-scripting", "Cross-Site Scripting (XSS)"),
        ("idor", "Broken Access Control"),
        ("bola", "Broken Access Control"),
        ("access-control", "Broken Access Control"),
        ("unknown", None),
        ("", None),
    ],
)
def test_classify_normalizes_and_returns_none_for_unknown(value, expected):
    classification = classify(value)
    assert (classification.type if classification else None) == expected


@pytest.mark.parametrize(
    "vuln_class,expected_type,expected_cwe,expected_owasp",
    [
        ("sqli", "SQL Injection", ["CWE-89"], ["A03:2021 Injection"]),
        ("xss", "Cross-Site Scripting (XSS)", ["CWE-79"], ["A03:2021 Injection"]),
        ("ssrf", "Server-Side Request Forgery (SSRF)", ["CWE-918"], ["A10:2021 Server-Side Request Forgery"]),
        ("access-control", "Broken Access Control", [], ["A01:2021 Broken Access Control"]),
        ("idor", "Broken Access Control", [], ["A01:2021 Broken Access Control"]),
        ("bola", "Broken Access Control", [], ["A01:2021 Broken Access Control"]),
    ],
)
def test_classification_metadata(vuln_class, expected_type, expected_cwe, expected_owasp):
    classification = classify(vuln_class)

    assert classification is not None
    assert classification.type == expected_type
    assert classification.cwe == expected_cwe
    assert classification.owasp == expected_owasp


def test_is_severity():
    for sev in SEVERITIES:
        assert is_severity(sev) is True
    assert is_severity("nope") is False
    assert is_severity("") is False


def test_summarize():
    tool = ConfirmFindingTool.__new__(ConfirmFindingTool)
    out = tool.summarize({"title": "XSS", "severity": "high", "url": "u"})

    assert out["summary"] == "finding (high): XSS"
    assert json.loads(out["detail"])["title"] == "XSS"


@pytest.mark.asyncio
async def test_run_persists_finding_and_notifies(tmp_path):
    seen: list[tuple[Finding, str]] = []
    tool, store = _tool(tmp_path, notifier=lambda f, p: seen.append((f, p)))

    result = await tool.run(
        {
            "title": "Reflected XSS in search",
            "severity": "High",
            "url": "https://target.test/search?q=1",
            "impact": "Arbitrary JS execution",
            "method": "GET",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "response_excerpt": "<script>alert(1)</script>",
            "curl": "curl https://target.test/search",
            "remediation": "encode output",
        },
        None,
        AlwaysAllow(),
    )

    assert "Reflected XSS in search" in result
    written = list((tmp_path / "findings").glob("*.md"))
    assert len(written) == 1
    body = written[0].read_text(encoding="utf-8")
    assert "# Reflected XSS in search" in body
    assert "- **Severity:** high" in body  # severity lowercased
    assert "Candidate ID" not in body

    assert len(seen) == 1
    finding, path = seen[0]
    assert finding.severity == "high"
    assert finding.candidate_id is None
    assert finding.slug == "reflected-xss-in-search"
    assert path.endswith(".md")
    assert path in result


@pytest.mark.asyncio
async def test_run_redacts_session_material_from_persisted_evidence(tmp_path):
    tool, _ = _tool(tmp_path)
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.signature"
    password = "correct-horse-battery-staple"

    await tool.run(
        {
            "title": "Authentication response evidence",
            "severity": "medium",
            "url": f"https://target.test/login?token={jwt}",
            "impact": f"password={password}",
            "response_excerpt": f"authorization: Bearer {jwt}",
            "curl": f"curl -H 'Authorization: Bearer {jwt}' https://target.test",
        },
        None,
        AlwaysAllow(),
    )

    report = next((tmp_path / "findings").glob("*.md")).read_text(encoding="utf-8")
    assert jwt not in report
    assert password not in report
    assert "[REDACTED" in report


@pytest.mark.asyncio
async def test_run_uses_redacted_title_for_report_and_slug(tmp_path):
    tool, _ = _tool(tmp_path)
    secret = "correct-horse-battery-staple"
    title = f"Password leak password={secret} in login"

    await tool.run(
        {
            "title": title,
            "severity": "medium",
            "url": "https://target.test/login",
            "impact": f"password={secret}",
            "payload": f"password={secret}",
        },
        None,
        AlwaysAllow(),
    )

    report = next((tmp_path / "findings").glob("*.md"))
    assert report.stem == slugify(redact(title))
    assert secret not in report.name
    body = report.read_text(encoding="utf-8")
    assert body.startswith(f"# {redact(title)}\n")
    assert secret not in body
    assert "[REDACTED" in body


@pytest.mark.asyncio
async def test_run_reports_success_when_notifier_raises(tmp_path):
    def broken_notifier(*_):
        raise RuntimeError("Burp bridge unavailable")

    tool, _ = _tool(tmp_path, notifier=broken_notifier)

    result = await tool.run(
        {
            "title": "Persisted despite notifier failure",
            "severity": "high",
            "url": "https://target.test/login",
            "impact": "Impact",
        },
        None,
        AlwaysAllow(),
    )

    assert "written to" in result
    assert len(list((tmp_path / "findings").glob("*.md"))) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "vuln_class",
    ["sqli", " SQLI ", "sql-injection"],
)
async def test_run_enriches_finding_from_vuln_class(tmp_path, vuln_class):
    seen: list[Finding] = []
    tool, _ = _tool(tmp_path, notifier=lambda finding, _: seen.append(finding))

    await tool.run(
        {
            "title": "SQL injection",
            "severity": "high",
            "url": "https://target.test/login",
            "impact": "Database access",
            "vuln_class": vuln_class,
        },
        None,
        AlwaysAllow(),
    )

    assert len(seen) == 1
    assert seen[0].vulnerabilityType == "SQL Injection"
    assert seen[0].cwe == ["CWE-89"]
    assert seen[0].owasp == ["A03:2021 Injection"]


@pytest.mark.asyncio
@pytest.mark.parametrize("vuln_class", ["access-control", "idor", "bola"])
async def test_access_control_report_is_broad_and_retains_candidate_id(
    tmp_path, vuln_class
):
    workflow = WorkflowState()
    candidate, _ = workflow.add_candidate(
        Candidate(candidate_class="access-control", endpoint="/orders/1")
    )
    workflow.add_validation_result(
        ValidationResult(candidate.id, "access-control", "confirmed")
    )
    tool = ConfirmFindingTool(Store(str(tmp_path / "findings")), workflow=workflow)

    await tool.run(
        {
            "candidate_id": candidate.id,
            "vuln_class": vuln_class,
            "title": "Order access through another account",
            "severity": "high",
            "url": "https://target.test/orders/1",
            "impact": "Another account's order was readable",
        },
        None,
        AlwaysAllow(),
    )

    report = next((tmp_path / "findings").glob("*.md")).read_text(encoding="utf-8")
    assert f"- **Candidate ID:** {candidate.id}" in report
    assert "- **Vulnerability Type:** Broken Access Control" in report
    assert "- **CWE:**" not in report
    assert "- **OWASP:** A01:2021 Broken Access Control" in report


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "vuln_class,title,expected_type,expected_cwe",
    [
        ("sql-injection", "Login bypass through crafted email input", "SQL Injection", "CWE-89"),
        ("cross-site-scripting", "SQL error text reflected in search results", "Cross-Site Scripting (XSS)", "CWE-79"),
    ],
)
async def test_structured_class_beats_misleading_title(
    tmp_path, vuln_class, title, expected_type, expected_cwe
):
    tool, _ = _tool(tmp_path)

    await tool.run(
        {
            "vuln_class": vuln_class,
            "title": title,
            "severity": "medium",
            "url": "https://target.test/search",
            "impact": "Reproduced impact",
        },
        None,
        AlwaysAllow(),
    )

    report = next((tmp_path / "findings").glob("*.md")).read_text(encoding="utf-8")
    assert f"- **Vulnerability Type:** {expected_type}" in report
    assert f"- **CWE:** {expected_cwe}" in report


@pytest.mark.asyncio
@pytest.mark.parametrize("vuln_class", ["unknown", ""])
async def test_run_persists_without_classification_for_unknown_class(
    tmp_path,
    vuln_class,
):
    seen: list[Finding] = []
    tool, _ = _tool(tmp_path, notifier=lambda finding, _: seen.append(finding))

    await tool.run(
        {
            "title": "Unclassified finding",
            "severity": "low",
            "url": "https://target.test",
            "impact": "Impact",
            "vuln_class": vuln_class,
        },
        None,
        AlwaysAllow(),
    )

    assert len(seen) == 1
    assert seen[0].vulnerabilityType is None
    assert seen[0].cwe is None
    assert seen[0].owasp is None


@pytest.mark.asyncio
async def test_run_persists_without_classification_when_class_is_omitted(tmp_path):
    seen: list[Finding] = []
    tool, _ = _tool(tmp_path, notifier=lambda finding, _: seen.append(finding))

    await tool.run(
        {
            "title": "Legacy finding",
            "severity": "info",
            "url": "https://target.test",
            "impact": "Impact",
        },
        None,
        AlwaysAllow(),
    )

    assert seen[0].vulnerabilityType is None
    assert seen[0].cwe is None
    assert seen[0].owasp is None


def test_classifications_do_not_share_mutable_lists():
    first = classify("sqli")
    second = classify("sqli")
    assert first is not None and second is not None

    first.cwe.append("CWE-test")
    assert second.cwe == ["CWE-89"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "missing,message",
    [
        ("title", "title is required"),
        ("url", "url is required"),
        ("impact", "impact is required"),
    ],
)
async def test_run_requires_core_fields(tmp_path, missing, message):
    tool, _ = _tool(tmp_path)
    args = {
        "title": "t",
        "severity": "high",
        "url": "u",
        "impact": "i",
    }
    args[missing] = ""

    with pytest.raises(Exception, match=message):
        await tool.run(args, None, AlwaysAllow())


@pytest.mark.asyncio
async def test_run_rejects_invalid_severity(tmp_path):
    tool, _ = _tool(tmp_path)

    with pytest.raises(Exception, match="severity must be one of"):
        await tool.run(
            {
                "title": "t",
                "severity": "sev",
                "url": "u",
                "impact": "i",
            },
            None,
            AlwaysAllow(),
        )


@pytest.mark.asyncio
async def test_run_falls_back_to_timestamp_slug_for_unslugifiable_title(
    tmp_path,
):
    tool, _ = _tool(tmp_path)

    result = await tool.run(
        {
            "title": "!!!",
            "severity": "low",
            "url": "u",
            "impact": "i",
        },
        None,
        AlwaysAllow(),
    )

    written = list((tmp_path / "findings").glob("*.md"))
    assert len(written) == 1
    assert written[0].stem.startswith("finding-")
    assert "written to" in result
