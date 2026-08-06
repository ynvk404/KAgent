from __future__ import annotations

import json

import pytest

from src.findings.store import Finding, Store
from src.permission.permission import AlwaysAllow
from src.tools.finding import (
    SEVERITIES,
    ConfirmFindingTool,
    is_severity,
)


def _tool(tmp_path, notifier=None):
    store = Store(str(tmp_path / "findings"))
    return ConfirmFindingTool(store, notifier=notifier), store


def test_metadata(tmp_path):
    tool, _ = _tool(tmp_path)

    assert tool.name() == "confirm_finding"
    assert isinstance(tool.description(), str) and tool.description()
    assert tool.requires_permission() is False

    schema = tool.schema()
    assert schema["type"] == "object"
    assert schema["required"] == ["title", "severity", "url", "impact"]
    assert schema["properties"]["severity"]["enum"] == list(SEVERITIES)


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

    assert len(seen) == 1
    finding, path = seen[0]
    assert finding.severity == "high"
    assert finding.slug == "reflected-xss-in-search"
    assert path.endswith(".md")


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
