from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

import pytest

from src.coverage.store import CoverageStore

def make_store() -> tuple[CoverageStore, Path]:
    tmp_dir = Path(tempfile.mkdtemp(prefix="pf-coverage-"))
    path = tmp_dir / "coverage.json"
    return CoverageStore(str(path)), path

@pytest.mark.asyncio
async def test_mark_records_new_entry_then_increments_on_remark():
    store, _ = make_store()

    a = await store.mark(
        endpoint="GET /api/users/{id}",
        param="id",
        vulnClass="idor",
        status="tried",
    )

    assert a.count == 1
    assert a.status == "tried"

    b = await store.mark(
        endpoint="GET /api/users/{id}",
        param="id",
        vulnClass="idor",
        status="failed",
    )

    assert b.count == 2
    assert b.status == "failed" 

@pytest.mark.asyncio
async def test_mark_strips_query_strings_so_shared_entry():
    store, _ = make_store()

    await store.mark(
        endpoint="GET /a?x=1",
        param="x",
        vulnClass="xss",
        status="tried",
    )

    await store.mark(
        endpoint="GET /a?x=2",
        param="x",
        vulnClass="xss",
        status="passed",
    )

    entries = await store.list()

    assert len(entries) == 1
    assert entries[0].endpoint == "GET /a"
    assert entries[0].count == 2
    assert entries[0].status == "passed"


@pytest.mark.asyncio
async def test_mark_rejects_empty_endpoint_param_vulnclass():
    store, _ = make_store()

    with pytest.raises(Exception, match="required"):
        await store.mark(
            endpoint="",
            param="p",
            vulnClass="xss",
            status="tried",
        )

@pytest.mark.asyncio
async def test_untested_returns_only_untested_pairs():
    store, _ = make_store()

    await store.mark(
        endpoint="POST /login",
        param="username",
        vulnClass="sqli",
        status="failed",
    )

    out = await store.untested(
        [
            {"endpoint": "POST /login", "param": "username"},
            {"endpoint": "POST /login", "param": "password"},
        ],
        ["sqli", "xss"],
    )

    assert len(out) == 3

    assert not any(
        t["endpoint"] == "POST /login"
        and t["param"] == "username"
        and t["vulnClass"] == "sqli"
        for t in out
    )


@pytest.mark.asyncio
async def test_summary_aggregates_by_status_and_vuln_class():
    store, _ = make_store()

    await store.mark(endpoint="GET /a", param="q", vulnClass="xss", status="tried")
    await store.mark(endpoint="GET /a", param="r", vulnClass="xss", status="passed")
    await store.mark(endpoint="GET /b", param="s", vulnClass="sqli", status="failed")

    s = await store.summary()

    assert s.total == 3
    assert s.byStatus["tried"] == 1
    assert s.byStatus["passed"] == 1
    assert s.byStatus["failed"] == 1
    assert s.byVulnClass["xss"] == 2
    assert s.byVulnClass["sqli"] == 1

@pytest.mark.asyncio
async def test_persistence_round_trips_entries_through_json_file():
    store, path = make_store()

    await store.mark(
        endpoint="GET /x",
        param="p",
        vulnClass="ssti",
        status="passed",
        notes="jinja2 sandbox escape via lipsum",
    )

    await store.flush()

    raw = path.read_text(encoding="utf8")

    assert '"version": 1' in raw
    assert '"endpoint": "GET /x"' in raw
    assert "jinja2 sandbox escape via lipsum" in raw

    fresh = CoverageStore(str(path))
    entries = await fresh.list()

    assert len(entries) == 1
    assert "lipsum" in (entries[0].notes or "")


@pytest.mark.asyncio
async def test_persistence_survives_corrupted_file_gracefully():
    _, path = make_store()

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{{ not json", encoding="utf8")

    fresh = CoverageStore(str(path))
    entries = await fresh.list()

    assert len(entries) == 0
    assert str(path.parent) 


@pytest.mark.asyncio
async def test_persistence_does_not_lose_entries_under_concurrent_first_marks():
    seed, path = make_store()

    await seed.mark(
        endpoint="GET /seed",
        param="id",
        vulnClass="idor",
        status="tried",
    )
    await seed.flush()

    fresh = CoverageStore(str(path))

    await asyncio.gather(
        fresh.mark(endpoint="GET /a", param="p", vulnClass="xss", status="tried"),
        fresh.mark(endpoint="GET /b", param="q", vulnClass="sqli", status="tried"),
    )

    await fresh.flush()

    reread = CoverageStore(str(path))
    entries = await reread.list()
    endpoints = sorted(e.endpoint for e in entries)

    assert endpoints == ["GET /a", "GET /b", "GET /seed"]


@pytest.mark.asyncio
async def test_persistence_coalesces_burst_of_marks_into_single_snapshot():
    store, path = make_store()

    await asyncio.gather(
        *(
            store.mark(
                endpoint=f"GET /x{i}",
                param="p",
                vulnClass="xss",
                status="tried",
            )
            for i in range(20)
        )
    )

    await store.flush()

    reread = CoverageStore(str(path))
    entries = await reread.list()

    assert len(entries) == 20