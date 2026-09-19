from __future__ import annotations

import json

import pytest

from src.coverage.store import CoverageStore
from src.permission.permission import AlwaysAllow
from src.tools.coverage import ACTIONS, STATUSES, CoverageTool


def _tool(tmp_path):
    store = CoverageStore(str(tmp_path / "coverage.json"))
    return CoverageTool(store), store


async def _run(tool, **args):
    return await tool.run(args, None, AlwaysAllow())


def test_metadata(tmp_path):
    tool, _ = _tool(tmp_path)

    assert tool.name() == "coverage"
    assert tool.requires_permission() is False
    schema = tool.schema()
    assert schema["properties"]["action"]["enum"] == list(ACTIONS)
    assert schema["properties"]["status"]["enum"] == list(STATUSES)
    assert schema["required"] == ["action"]


@pytest.mark.asyncio
async def test_unknown_action_errors(tmp_path):
    tool, _ = _tool(tmp_path)

    out = await _run(tool, action="bogus")

    assert out.startswith("error: action must be one of")


@pytest.mark.asyncio
async def test_mark_requires_fields(tmp_path):
    tool, _ = _tool(tmp_path)

    out = await _run(tool, action="mark", endpoint="GET /a")

    assert out.startswith("error: mark requires")


@pytest.mark.asyncio
async def test_mark_rejects_invalid_status(tmp_path):
    tool, _ = _tool(tmp_path)

    out = await _run(
        tool,
        action="mark",
        endpoint="GET /a",
        param="q",
        vuln_class="sqli",
        status="explode",
    )

    assert out.startswith("error: status must be one of")


@pytest.mark.asyncio
async def test_mark_records_entry(tmp_path):
    tool, store = _tool(tmp_path)

    out = await _run(
        tool,
        action="mark",
        endpoint="GET /api/users?id=1",
        param="id",
        vuln_class="SQLI",
        status="passed",
        notes="union based",
    )

    payload = json.loads(out)
    assert payload["ok"] is True
    entry = payload["entry"]
    # Query string stripped; alias normalized to the canonical Candidate class.
    assert entry["endpoint"] == "GET /api/users"
    assert entry["vulnClass"] == "sql-injection"
    assert entry["status"] == "passed"
    assert entry["count"] == 1
    assert entry["notes"] == "union based"
    # timestamps rendered as ISO strings
    assert "T" in entry["firstSeen"]

    await store.flush()
    assert store.path.exists()


@pytest.mark.asyncio
async def test_mark_defaults_status_to_tried(tmp_path):
    tool, _ = _tool(tmp_path)

    out = await _run(
        tool,
        action="mark",
        endpoint="/a",
        param="q",
        vuln_class="xss",
    )

    assert json.loads(out)["entry"]["status"] == "tried"


@pytest.mark.asyncio
async def test_list_empty_and_populated(tmp_path):
    tool, _ = _tool(tmp_path)

    assert await _run(tool, action="list") == "no entries match."

    await _run(
        tool, action="mark", endpoint="/a", param="q", vuln_class="xss"
    )

    rows = json.loads(await _run(tool, action="list"))
    assert len(rows) == 1
    assert rows[0]["vuln_class"] == "cross-site-scripting"
    assert rows[0]["count"] == 1


@pytest.mark.asyncio
async def test_list_filter_no_match(tmp_path):
    tool, _ = _tool(tmp_path)
    await _run(
        tool, action="mark", endpoint="/a", param="q", vuln_class="xss"
    )

    assert (
        await _run(tool, action="list", vuln_class="sqli")
        == "no entries match."
    )


@pytest.mark.asyncio
async def test_untested_requires_candidates_and_classes(tmp_path):
    tool, _ = _tool(tmp_path)

    out = await _run(tool, action="untested")
    assert out.startswith("error: untested requires")


@pytest.mark.asyncio
async def test_untested_returns_uncovered_tuples(tmp_path):
    tool, _ = _tool(tmp_path)

    await _run(
        tool, action="mark", endpoint="/a", param="q", vuln_class="sqli"
    )

    out = await _run(
        tool,
        action="untested",
        candidates=[
            {"endpoint": "/a", "param": "q"},
            {"endpoint": "/b", "param": "p"},
        ],
        vuln_classes=["sqli", "xss"],
    )

    tuples = json.loads(out)
    combos = {(t["endpoint"], t["param"], t["vulnClass"]) for t in tuples}
    # /a,q,sqli already marked -> excluded
    assert ("/a", "q", "sql-injection") not in combos
    assert ("/a", "q", "cross-site-scripting") in combos
    assert ("/b", "p", "sql-injection") in combos
    assert ("/b", "p", "cross-site-scripting") in combos


@pytest.mark.asyncio
async def test_untested_all_covered(tmp_path):
    tool, _ = _tool(tmp_path)
    await _run(
        tool, action="mark", endpoint="/a", param="q", vuln_class="sqli"
    )

    out = await _run(
        tool,
        action="untested",
        candidates=[{"endpoint": "/a", "param": "q"}],
        vuln_classes=["sqli"],
    )

    assert "all combinations marked already" in out


@pytest.mark.asyncio
async def test_untested_uses_mark_normalization_for_param_and_vuln_class(tmp_path):
    tool, _ = _tool(tmp_path)
    await _run(
        tool, action="mark", endpoint="/a", param="id", vuln_class="sqli"
    )

    out = await _run(
        tool,
        action="untested",
        candidates=[{"endpoint": "/a?source=test", "param": " id "}],
        vuln_classes=[" SQLI "],
    )

    assert "all combinations marked already" in out


@pytest.mark.asyncio
async def test_untested_rejects_whitespace_only_candidates_and_classes(tmp_path):
    tool, _ = _tool(tmp_path)

    out = await _run(
        tool,
        action="untested",
        candidates=[{"endpoint": "/a", "param": "   "}],
        vuln_classes=["   "],
    )

    assert out.startswith("error: untested requires")
    assert "all combinations marked already" not in out


@pytest.mark.asyncio
async def test_untested_ignores_malformed_candidates(tmp_path):
    tool, _ = _tool(tmp_path)

    out = await _run(
        tool,
        action="untested",
        candidates=["not-a-dict", {"endpoint": "", "param": "q"}],
        vuln_classes=["sqli"],
    )

    # only invalid candidates -> treated as no candidates
    assert out.startswith("error: untested requires")


@pytest.mark.asyncio
async def test_summary_counts(tmp_path):
    tool, _ = _tool(tmp_path)

    await _run(
        tool,
        action="mark",
        endpoint="/a",
        param="q",
        vuln_class="sqli",
        status="passed",
    )
    await _run(
        tool,
        action="mark",
        endpoint="/b",
        param="p",
        vuln_class="xss",
        status="failed",
    )

    summary = json.loads(await _run(tool, action="summary"))
    assert summary["total"] == 2
    assert summary["byStatus"]["passed"] == 1
    assert summary["byStatus"]["failed"] == 1
    assert summary["byVulnClass"] == {
        "sql-injection": 1,
        "cross-site-scripting": 1,
    }


@pytest.mark.asyncio
async def test_clear(tmp_path):
    tool, _ = _tool(tmp_path)
    await _run(
        tool, action="mark", endpoint="/a", param="q", vuln_class="sqli"
    )

    assert await _run(tool, action="clear") == "cleared."
    assert await _run(tool, action="list") == "no entries match."
