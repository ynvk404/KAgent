"""C4 canonical read/parse ownership and guarded controller finalization."""
import asyncio
from dataclasses import asdict
from pathlib import Path
import threading

import pytest

from src.findings import store as module
from src.permission.permission import AlwaysAllow
from tests.data.test_findings_store import make_finding
from tests.tools.test_finding import _tool, _valid_args
from tests.security.test_persistence_handoff_audit import offline  # noqa: F401


@pytest.fixture
def scratch(tmp_path):
    return tmp_path


async def test_canonical_read_and_parse_execute_in_writer_thread(scratch, monkeypatch):
    store = module.Store(project_directory=scratch)
    ui = threading.get_ident()
    threads = {}
    for name in ("_write_once_for_candidate", "read_report", "read_report_bytes"):
        owner = store if name.startswith("_") else module
        original = getattr(owner, name)
        def wrapper(fn, stage):
            def wrapped(*a, **kw):
                threads[stage] = threading.get_ident()
                return fn(*a, **kw)
            return wrapped
        monkeypatch.setattr(owner, name, wrapper(original, name))
    await store.save(make_finding())
    assert len(threads) == 3 and len(set(threads.values())) == 1
    assert threads["read_report"] != ui


async def test_queued_save_freezes_writer_scalars_before_lock(scratch):
    store = module.Store(project_directory=scratch)
    finding = make_finding(title="Original", slug="original", candidate_id="cand_original")
    async with store._save_lock:
        task = asyncio.create_task(store.save(finding))
        await asyncio.sleep(0)
        finding.slug, finding.candidate_id, finding.title = "mutated", "cand_mutated", "Mutated"
    path = await task
    assert Path(path).name == "original.md"
    assert finding.candidate_id == "cand_original" and finding.title == "Original"


async def test_cancelled_queued_save_never_starts_worker(scratch, monkeypatch):
    store = module.Store(project_directory=scratch)
    def unexpected(*_):
        pytest.fail("cancelled queued save started a worker")
    monkeypatch.setattr(store, "_write_and_read_for_candidate", unexpected)
    async with store._save_lock:
        task = asyncio.create_task(store.save(make_finding()))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert not store.dir.exists()


@pytest.mark.parametrize("fault", ["read", "parse"])
async def test_postread_failure_keeps_pending_canonical_and_retry(scratch, monkeypatch, fault):
    tool, store = _tool(scratch)
    state = tool.workflow
    assert state is not None
    cid = next(iter(state.candidates))
    name = "read_report" if fault == "read" else "read_report_bytes"
    with monkeypatch.context() as patch:
        def fail(*_, **kw):
            raise OSError("synthetic postread failure")
        patch.setattr(module, name, fail)
        with pytest.raises(OSError):
            await tool.run(_valid_args(tool), None, AlwaysAllow())
    canonical = next(store.dir.glob("*.md"))
    raw = canonical.read_bytes()
    assert not state.finding_is_persisted(cid) and not store._save_lock.locked()
    await tool.run(_valid_args(tool, title="Retry proposal"), None, AlwaysAllow())
    assert state.finding_is_persisted(cid)
    assert list(store.dir.glob("*.md")) == [canonical] and canonical.read_bytes() == raw


@pytest.mark.parametrize("change", ["result", "evidence"])
async def test_postread_wait_rechecks_live_result_and_evidence(scratch, monkeypatch, change):
    tool, store = _tool(scratch)
    state = tool.workflow
    assert state is not None
    cid = next(iter(state.candidates))
    original = module.read_report
    entered, release = threading.Event(), threading.Event()
    def held(path):
        entered.set()
        assert release.wait(3)
        return original(path)
    monkeypatch.setattr(module, "read_report", held)
    task = asyncio.create_task(tool.run(_valid_args(tool), None, AlwaysAllow()))
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        latest = state.latest_result(cid)
        assert latest is not None
        if change == "result":
            latest.notes = "changed during canonical read"
        else:
            artifact = state.evidence[latest.evidence_refs[0]]
            (scratch / artifact.path).write_text("Changed evidence")
        release.set()
        with pytest.raises(ValueError, match="changed"):
            await task
        assert not state.finding_is_persisted(cid)
        assert len(list(store.dir.glob("*.md"))) == 1 and not store._save_lock.locked()
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("fails", [False, True])
async def test_repeated_cancel_drains_read_before_retry_and_retains_error_precedence(scratch, monkeypatch, fails):
    store = module.Store(project_directory=scratch)
    other = module.Store(project_directory=scratch)
    original = module.read_report
    entered, release = threading.Event(), threading.Event()
    reads = 0
    completed = threading.Event()
    finding = make_finding(title="Original", slug="original")
    before = asdict(finding)
    def read(path):
        nonlocal reads
        reads += 1
        if reads == 1:
            entered.set()
            assert release.wait(3)
            if fails:
                completed.set()
                raise OSError("synthetic drain read error")
        snapshot = original(path)
        completed.set()
        return snapshot
    with monkeypatch.context() as patch:
        patch.setattr(module, "read_report", read)
        first = asyncio.create_task(store.save(finding))
        retry = None
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            first.cancel()
            await asyncio.sleep(0)
            first.cancel()
            retry_finding = make_finding(title="Retry", slug="retry")
            retry = asyncio.create_task(other.save(retry_finding))
            await asyncio.sleep(0.02)
            assert store._save_lock is other._save_lock and store._save_lock.locked()
            assert not first.done() and not retry.done() and reads == 1
            release.set()
            with pytest.raises(OSError if fails else asyncio.CancelledError):
                await first
            assert completed.is_set()
            path = await retry
            assert retry_finding.title == "Original" and list(store.dir.glob("*.md")) == [Path(path)]
            assert asdict(finding) == before and not store._save_lock.locked()
        finally:
            release.set()
            await asyncio.gather(first, *([retry] if retry else []), return_exceptions=True)
