import asyncio
import threading

import pytest

from src.findings import store as module
from src.permission.permission import AlwaysAllow
from src.tools.workflow.finding import ConfirmFindingTool
from tests.tools.test_finding import _tool, _valid_args


async def test_legacy_and_current_findings_with_same_name_keep_distinct_summaries(tmp_path):
    legacy_tool, _ = _tool(tmp_path)
    await legacy_tool.run(_valid_args(legacy_tool), None, AlwaysAllow())
    legacy_summary = tmp_path / "artifacts/reports/findings/finding.md"
    legacy_bytes = legacy_summary.read_bytes()
    tool, _ = _tool(tmp_path, candidate_class="sqli")
    tool = ConfirmFindingTool(module.Store(project_directory=tmp_path), workflow=tool.workflow)
    await tool.run(_valid_args(tool), None, AlwaysAllow())
    current_summary = legacy_summary.with_name("finding-2.md")
    current_bytes = current_summary.read_bytes()
    assert "CWE-89" in current_summary.read_text()
    assert legacy_summary.read_bytes() == legacy_bytes
    await tool.run(_valid_args(tool), None, AlwaysAllow())
    assert legacy_summary.read_bytes() == legacy_bytes
    assert current_summary.read_bytes() == current_bytes
    assert len(list(legacy_summary.parent.glob("*.md"))) == 2


@pytest.mark.parametrize("kind", ["directory-symlink", "file-symlink", "hardlink"])
async def test_summary_export_rejects_unsafe_resources_without_changing_canonical(tmp_path, kind):
    tool, store = _tool(tmp_path)
    assert tool.workflow is not None
    await tool.run(_valid_args(tool), None, AlwaysAllow())
    cid = next(iter(tool.workflow.candidates))
    canonical = store.report_for_candidate(cid)
    before = canonical.read_bytes()
    directory = tmp_path / "artifacts/reports/findings"
    summary = directory / canonical.name
    external = tmp_path / "external"
    external.write_text("Untouched external content")
    if kind == "directory-symlink":
        summary.unlink()
        directory.rmdir()
        directory.symlink_to(tmp_path)
    elif kind == "file-symlink":
        summary.unlink()
        summary.symlink_to(external)
    else:
        summary.unlink()
        summary.hardlink_to(external)
    output = await tool.run(_valid_args(tool), None, AlwaysAllow())
    assert "compact report export failed" in output
    assert tool.workflow.finding_is_persisted(cid)
    assert canonical.read_bytes() == before
    assert external.read_text() == "Untouched external content"


@pytest.mark.parametrize("preparation_fails", [False, True])
async def test_cancelled_summary_preparation_drains_and_holds_shared_lock(tmp_path, monkeypatch, preparation_fails):
    tool, store = _tool(tmp_path)
    assert tool.workflow is not None
    await tool.run(_valid_args(tool), None, AlwaysAllow())
    cid = next(iter(tool.workflow.candidates))
    canonical = store.report_for_candidate(cid)
    summary = tmp_path / "artifacts/reports/findings" / canonical.name
    before = summary.read_bytes()
    started, release = threading.Event(), threading.Event()
    original = module._prepare_summary
    def prepare(*args):
        started.set()
        assert release.wait(5)
        if preparation_fails:
            raise OSError("preparation failed while the caller was cancelling")
        return original(*args)
    monkeypatch.setattr(module, "_prepare_summary", prepare)
    first = asyncio.create_task(tool.write_summary(cid))
    second = None
    try:
        assert await asyncio.to_thread(started.wait, 5)
        first.cancel()
        # A separate Store for the same project must wait for draining too.
        other = module.Store(project_directory=tmp_path)
        second = asyncio.create_task(other.save(module.read_report(canonical)))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not first.done() and not second.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await first
        await second
    finally:
        release.set()
        await asyncio.gather(first, *([second] if second else []), return_exceptions=True)
    assert summary.read_bytes() == before
    assert not list(summary.parent.glob(".finding-*.tmp"))


async def test_changed_workflow_during_preparation_cannot_publish_stale_summary(tmp_path, monkeypatch):
    tool, store = _tool(tmp_path)
    assert tool.workflow is not None
    await tool.run(_valid_args(tool), None, AlwaysAllow())
    cid = next(iter(tool.workflow.candidates))
    canonical = store.report_for_candidate(cid)
    summary = tmp_path / "artifacts/reports/findings" / canonical.name
    before = summary.read_bytes()
    started, release = threading.Event(), threading.Event()
    original = module._prepare_summary
    def prepare(*args):
        started.set()
        assert release.wait(5)
        return original(*args)
    monkeypatch.setattr(module, "_prepare_summary", prepare)
    task = asyncio.create_task(tool.write_summary(cid))
    try:
        assert await asyncio.to_thread(started.wait, 5)
        tool.workflow.persisted_findings.clear()
        release.set()
        with pytest.raises(ValueError, match="current validation"):
            await task
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
    assert summary.read_bytes() == before
    assert not list(summary.parent.glob(".finding-*.tmp"))
