"""Owned scanner files only; never launch a scanner or connect a socket."""
import asyncio
import fcntl
import hashlib
import os
import threading
import time
from contextlib import contextmanager

import pytest

from src.async_io import run_sync
from src.permission.runtime.execution import ExecutionBlocked
from src.tools.execution import scanner_runner as runner
from src.tools.execution import scanner_files
from src.tools.execution.scanner_files import PrivateJob
from tests.security.test_scanner_end_to_end import runtime, require_binaries, xml
from tests.security.test_scanner_final_fixes import spawn_xml_fixture


@pytest.mark.parametrize("ending", ["success", "cancel", "revoke", "generation"])
async def test_slow_scanner_publication_yields_and_rechecks_authority(tmp_path, monkeypatch, ending):
    rt = runtime(tmp_path / "project", "http://127.0.0.1:8080")
    entered, release = threading.Event(), threading.Event()
    original = os.fsync
    stamp, generation = rt.policy.revision, rt.binding.runtime.generation
    beats = []
    async def heartbeat():
        while True:
            beats.append(time.monotonic())
            await asyncio.sleep(0.01)
    def fsync(fd):
        if not entered.is_set():
            entered.set()
            assert release.wait(2)
        return original(fd)
    def check():
        if rt.policy.revision != stamp or rt.binding.runtime.generation != generation:
            raise ExecutionBlocked("synthetic stale scanner authority")
    monkeypatch.setattr(os, "fsync", fsync)
    heartbeat_task = asyncio.create_task(heartbeat())
    envelope = {"artifacts": {}}
    task = asyncio.create_task(runner.publish_async(rt.binding, None, "scan_" + "0" * 32,
        envelope, b'{}\n', "offline", check=check))
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        if ending == "cancel":
            task.cancel()
        elif ending == "revoke":
            rt.policy.revision += 1
        elif ending == "generation":
            rt.binding.runtime.invalidate()
        for _ in range(5):
            await asyncio.sleep(0.01)
        assert not task.done() and len(beats) >= 4
        release.set()
        if ending == "success":
            assert await task
            assert envelope["artifacts"]["manifest"]
        else:
            with pytest.raises(asyncio.CancelledError if ending == "cancel" else ExecutionBlocked):
                await task
            assert not list(rt.root.rglob("manifest.json"))
            assert envelope == {"artifacts": {}}
        print({"scanner_heartbeat_gap_ms": max(b-a for a,b in zip(beats,beats[1:])) * 1000})
    finally:
        release.set()
        heartbeat_task.cancel()
        await asyncio.gather(task, heartbeat_task, return_exceptions=True)


@pytest.mark.parametrize("ending", ["cancel", "timeout"])
async def test_scanner_lock_contention_is_bounded_and_cancellable(tmp_path, ending):
    root = tmp_path / "project"
    parent = root / ".kagent/scanners" / hashlib.sha256(b"offline").hexdigest()
    parent.mkdir(parents=True, mode=0o700)
    for path in (root / ".kagent", root / ".kagent/scanners"):
        path.chmod(0o700)
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    fcntl.flock(fd, fcntl.LOCK_EX)
    entered = threading.Event()
    task = asyncio.create_task(run_sync(PrivateJob, root,
        (".kagent", "scanners", parent.name, "job"), max_siblings=32,
        check=entered.set, deadline=time.monotonic() + 0.1))
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        if ending == "cancel":
            task.cancel()
        with pytest.raises(asyncio.CancelledError if ending == "cancel" else TimeoutError):
            await asyncio.wait_for(task, 0.5)
        assert not (parent / "job").exists()
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def test_manifest_rejects_replaced_staging_inode(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    job = PrivateJob(root, (".kagent", "scanners", "offline", "job"))
    original_publication = scanner_files.publication

    @contextmanager
    def replace_staging(check=None):
        with original_publication(check):
            staging = job.path / "manifest.pending"
            staging.rename(job.path / "original.pending")
            staging.write_bytes(b'forged manifest')
            staging.chmod(0o600)
            yield

    monkeypatch.setattr(scanner_files, "publication", replace_staging)
    try:
        with pytest.raises(ExecutionBlocked, match="temporary inode changed"):
            job.write("manifest.json", b'original manifest')
        assert not (job.path / "manifest.json").exists()
        assert (job.path / "manifest.pending").read_bytes() == b'forged manifest'
        assert (job.path / "original.pending").read_bytes() == b'original manifest'
    finally:
        job.close(remove=False)
    assert not job.fds


@pytest.mark.parametrize("ending", ["revoke", "generation", "cancel"])
async def test_publication_interruption_discards_samples_and_terminal_success(tmp_path, monkeypatch, ending):
    require_binaries()
    rt = runtime(tmp_path / "project", "http://127.0.0.1:43210")
    # Existing offline fixture writes synthetic XML; no scanner/network runs.
    await spawn_xml_fixture(rt, monkeypatch, xml())
    entered, release = asyncio.Event(), asyncio.Event()
    original_publish = runner.publish_async
    produced = []
    async def publish(*args, **kwargs):
        entered.set()
        await release.wait()
        return await original_publish(*args, **kwargs)
    monkeypatch.setattr(runner, "publish_async", publish)
    token = runner.hooks.set(runner.ScannerHooks(lambda *_: None, produced.append))
    task = asyncio.create_task(rt.registry.execute("shell",
        {"scanner": "nmap", "target": "127.0.0.1", "ports": "43210"}, None, rt.prompter))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        if ending == "revoke":
            rt.policy.revoke("shell")
        elif ending == "generation":
            rt.binding.runtime.invalidate()
        else:
            task.cancel()
        release.set()
        result = (await asyncio.gather(task, return_exceptions=True))[0]
        assert len(produced) == 1
        outcome = produced[0]
        assert outcome.envelope["records"] == []
        assert outcome.envelope["summary"]["unique_records"] == 0
        assert outcome.envelope["summary"]["returned_records"] == 0
        assert outcome.envelope["parse"] == {"status": "discarded", "partial": True, "coverage_complete": False}
        # ScannerRuntime.invalidate() actively cancels its owned job task.
        cancelled = ending in {"cancel", "generation"}
        assert outcome.envelope["execution"]["status"] == ("cancelled" if cancelled else "failed")
        assert not outcome.dataset and not outcome.record_ids and not outcome.observation_fingerprints
        assert not list(rt.root.rglob("manifest.json"))
        if cancelled:
            assert isinstance(result, asyncio.CancelledError)
        else:
            assert getattr(result, "status", None) == "error"
            assert getattr(result, "error_kind", None) == "policy_block"
        assert rt.binding.runtime.task is None and rt.policy.active == 0
    finally:
        release.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        runner.hooks.reset(token)
