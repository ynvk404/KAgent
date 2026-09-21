from __future__ import annotations

import json

import pytest

from src.coverage.store import CoverageEntry, CoverageStore
from src.permission.permission import AlwaysAllow
from src.tools.coverage import (
    ACTIONS,
    COLLECTION_TEXT_LIMIT,
    DEFAULT_PAGE_SIZE,
    MAX_COLLECTION_RESULT_CHARS,
    MAX_PAGE_SIZE,
    STATUSES,
    SUMMARY_VULN_CLASS_LIMIT,
    CoverageTool,
)


def _tool(tmp_path):
    store = CoverageStore(str(tmp_path / "coverage.json"))
    return CoverageTool(store), store


async def _run(tool, **args):
    return await tool.run(args, None, AlwaysAllow())


async def _payload(tool, **args):
    return json.loads(await _run(tool, **args))


def test_metadata(tmp_path):
    tool, _ = _tool(tmp_path)

    assert tool.name() == "coverage"
    assert tool.requires_permission() is False
    schema = tool.schema()
    assert schema["properties"]["action"]["enum"] == list(ACTIONS)
    assert schema["properties"]["status"]["enum"] == list(STATUSES)
    assert schema["properties"]["cursor"]["type"] == "string"
    assert str(MAX_PAGE_SIZE) in schema["properties"]["limit"]["description"]
    assert schema["required"] == ["action"]
    assert tool.permission_hints({"action": "clear"}) == {"noSessionCache": True}


@pytest.mark.asyncio
async def test_unknown_action_errors(tmp_path):
    tool, _ = _tool(tmp_path)

    out = await _run(tool, action="bogus")

    assert json.loads(out)["error"].startswith("action must be one of")


@pytest.mark.asyncio
async def test_mark_requires_fields(tmp_path):
    tool, _ = _tool(tmp_path)

    out = await _run(tool, action="mark", endpoint="GET /a")

    assert json.loads(out)["error"].startswith("mark requires")


@pytest.mark.asyncio
async def test_mark_rejects_whitespace_only_fields_as_structured_error(tmp_path):
    tool, _ = _tool(tmp_path)

    payload = await _payload(
        tool,
        action="mark",
        endpoint=" /a ",
        param="   ",
        vuln_class=" xss ",
    )

    assert payload["ok"] is False
    assert payload["action"] == "mark"
    assert payload["error"].startswith("mark requires")


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

    assert json.loads(out)["error"].startswith("status must be one of")


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
    assert payload["action"] == "mark"
    assert payload["created"] is True
    assert payload["updated"] is False
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

    empty = await _payload(tool, action="list")
    assert empty["items"] == []
    assert empty["returned_count"] == 0
    assert empty["total_count"] == 0
    assert empty["complete"] is True
    assert empty["next_cursor"] is None

    await _run(
        tool, action="mark", endpoint="/a", param="q", vuln_class="xss"
    )

    page = await _payload(tool, action="list")
    assert page["returned_count"] == 1
    assert page["items"][0]["vuln_class"] == "cross-site-scripting"
    assert page["items"][0]["count"] == 1
    assert page["page_end"]["complete"] is True


@pytest.mark.asyncio
async def test_list_filter_no_match(tmp_path):
    tool, _ = _tool(tmp_path)
    await _run(
        tool, action="mark", endpoint="/a", param="q", vuln_class="xss"
    )

    page = await _payload(tool, action="list", vuln_class="sqli")
    assert page["items"] == []
    assert page["complete"] is True


@pytest.mark.asyncio
async def test_untested_requires_candidates_and_classes(tmp_path):
    tool, _ = _tool(tmp_path)

    out = await _run(tool, action="untested")
    assert json.loads(out)["error"].startswith("untested requires")


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

    page = json.loads(out)
    tuples = page["items"]
    combos = {(t["endpoint"], t["param"], t["vulnClass"]) for t in tuples}
    # /a,q,sqli already marked -> excluded
    assert ("/a", "q", "sql-injection") not in combos
    assert ("/a", "q", "cross-site-scripting") in combos
    assert ("/b", "p", "sql-injection") in combos
    assert ("/b", "p", "cross-site-scripting") in combos
    assert page["complete"] is True


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

    page = json.loads(out)
    assert page["items"] == []
    assert page["complete"] is True


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

    assert json.loads(out)["items"] == []


@pytest.mark.asyncio
async def test_untested_rejects_whitespace_only_candidates_and_classes(tmp_path):
    tool, _ = _tool(tmp_path)

    out = await _run(
        tool,
        action="untested",
        candidates=[{"endpoint": "/a", "param": "   "}],
        vuln_classes=["   "],
    )

    assert json.loads(out)["error"].startswith("untested requires")


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
    assert json.loads(out)["error"].startswith("untested requires")


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
    assert summary["vulnClassCount"] == 2
    assert summary["vulnClassesComplete"] is True
    assert summary["topVulnClasses"] == [
        {"vuln_class": "cross-site-scripting", "count": 1},
        {"vuln_class": "sql-injection", "count": 1},
    ]


@pytest.mark.asyncio
async def test_clear(tmp_path):
    tool, _ = _tool(tmp_path)
    await _run(
        tool, action="mark", endpoint="/a", param="q", vuln_class="sqli"
    )

    assert await _payload(tool, action="clear") == {
        "ok": True,
        "action": "clear",
        "cleared": True,
    }
    assert (await _payload(tool, action="list"))["items"] == []


def _seed_entries(store, count, *, text_size=0):
    store.loaded = True
    suffix = "x" * text_size
    for index in range(count):
        entry = CoverageEntry(
            endpoint=f"GET /stable/{index:04d}{suffix}",
            param=f"p{index:04d}{suffix}",
            vulnClass=f"class-{index:04d}{suffix}",
            status="tried",
            count=1,
            firstSeen=1,
            lastSeen=1,
            notes=suffix or None,
        )
        store.entries[str(index)] = entry


@pytest.mark.asyncio
async def test_mark_reports_created_then_updated_without_dumping_store(tmp_path):
    tool, _ = _tool(tmp_path)
    args = {
        "action": "mark",
        "endpoint": "/a",
        "param": "q",
        "vuln_class": "xss",
    }

    created = await _payload(tool, **args)
    updated = await _payload(tool, **args)

    assert (created["created"], created["updated"]) == (True, False)
    assert (updated["created"], updated["updated"]) == (False, True)
    assert updated["entry"]["count"] == 2
    assert "items" not in updated


@pytest.mark.asyncio
async def test_list_pages_are_complete_stable_and_non_overlapping(tmp_path):
    tool, store = _tool(tmp_path)
    _seed_entries(store, 23)

    pages = []
    cursor = None
    while True:
        args = {"action": "list", "limit": 7}
        if cursor is not None:
            args["cursor"] = cursor
        page = await _payload(tool, **args)
        pages.append(page)
        cursor = page["next_cursor"]
        if cursor is None:
            break

    items = [item for page in pages for item in page["items"]]
    assert [page["returned_count"] for page in pages] == [7, 7, 7, 2]
    assert all(page["total_count"] == 23 for page in pages)
    assert [page["complete"] for page in pages] == [False, False, False, False]
    assert [page["has_more"] for page in pages] == [True, True, True, False]
    assert len({item["endpoint"] for item in items}) == 23
    assert [item["endpoint"] for item in items] == sorted(
        item["endpoint"] for item in items
    )
    assert all(page["page_end"]["complete"] == page["complete"] for page in pages)


@pytest.mark.asyncio
async def test_list_clamps_limit_rejects_invalid_cursor_and_bounds_output(tmp_path):
    tool, store = _tool(tmp_path)
    _seed_entries(store, 60, text_size=2_000)

    page_text = await _run(tool, action="list", limit=10_000)
    page = json.loads(page_text)
    invalid = await _payload(tool, action="list", cursor="not-an-offset")
    past_end = await _payload(tool, action="list", cursor="61")

    assert page["limit"] == MAX_PAGE_SIZE
    assert page["returned_count"] <= MAX_PAGE_SIZE
    # The output-size bound removes whole structured items, never a fragment
    # that would make the continuation metadata or JSON invalid.
    assert page["returned_count"] < MAX_PAGE_SIZE
    assert [item["endpoint"] for item in page["items"]] == [
        f"GET /stable/{index:04d}" + "x" * (COLLECTION_TEXT_LIMIT - 16)
        for index in range(page["returned_count"])
    ]
    assert page["complete"] is False
    assert page["next_cursor"] == str(page["returned_count"])
    assert len(page_text) <= MAX_COLLECTION_RESULT_CHARS
    assert invalid["ok"] is False and "cursor" in invalid["error"]
    assert past_end["ok"] is False and "total_count" in past_end["error"]


@pytest.mark.asyncio
async def test_untested_pagination_reconstructs_deduplicated_stable_set(tmp_path):
    tool, _ = _tool(tmp_path)
    candidates = [
        {"endpoint": f"/e/{index:02d}", "param": "id"}
        for index in range(13)
    ]
    candidates.append(candidates[0])
    classes = ["xss", "sqli", "xss"]

    items = []
    cursor = None
    while True:
        args = {
            "action": "untested",
            "candidates": candidates,
            "vuln_classes": classes,
            "limit": 6,
        }
        if cursor is not None:
            args["cursor"] = cursor
        page = await _payload(tool, **args)
        items.extend(page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            assert page["complete"] is False
            assert page["has_more"] is False
            break

    keys = [
        (item["endpoint"], item["param"], item["vulnClass"])
        for item in items
    ]
    assert len(keys) == 26
    assert keys == sorted(keys)
    assert len(set(keys)) == len(keys)


@pytest.mark.asyncio
async def test_summary_has_a_hard_class_bound_for_large_store(tmp_path):
    tool, store = _tool(tmp_path)
    _seed_entries(store, 200, text_size=1_000)

    first_text = await _run(tool, action="summary")
    second_text = await _run(tool, action="summary")
    summary = json.loads(first_text)

    assert first_text == second_text
    assert summary["total"] == 200
    assert summary["vulnClassCount"] == 200
    assert summary["returnedVulnClassCount"] == SUMMARY_VULN_CLASS_LIMIT
    assert summary["vulnClassesComplete"] is False
    assert len(summary["topVulnClasses"]) == SUMMARY_VULN_CLASS_LIMIT
    assert len(first_text) < 10_000


@pytest.mark.asyncio
async def test_default_page_size_and_end_cursor_are_unambiguous(tmp_path):
    tool, store = _tool(tmp_path)
    _seed_entries(store, DEFAULT_PAGE_SIZE + 1)

    first = await _payload(tool, action="list")
    last = await _payload(tool, action="list", cursor=first["next_cursor"])

    assert first["returned_count"] == DEFAULT_PAGE_SIZE
    assert first["complete"] is False
    assert last["returned_count"] == 1
    assert last["complete"] is False
    assert last["has_more"] is False
    assert last["next_cursor"] is None
