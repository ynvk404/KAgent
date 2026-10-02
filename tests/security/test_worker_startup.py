"""Startup capability checking is bounded and never scans the project."""
from __future__ import annotations

import asyncio
from pathlib import Path
import sys
from unittest.mock import AsyncMock

import pytest

from src.permission.execution import ExecutionBlocked
from src.permission.worker import OfflineWorker
import src.permission.worker as worker_module


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux worker startup")


def binaries(monkeypatch):
    monkeypatch.setattr(worker_module.shutil, "which", lambda name: "/usr/bin/" + name)


@pytest.mark.asyncio
async def test_startup_scans_only_temporary_probe_and_cleans_it(tmp_path, monkeypatch):
    binaries(monkeypatch)
    root = tmp_path / "project"
    root.mkdir()
    # No traversal of this tree may be required to determine OS capability.
    (root / "venv-linux").mkdir()
    visited = []
    original_walk = worker_module.os.walk

    def walk(path, **kwargs):
        visited.append(Path(path))
        assert not Path(path).is_relative_to(root)
        return original_walk(path, **kwargs)

    monkeypatch.setattr(worker_module.os, "walk", walk)
    process = AsyncMock()
    process.returncode = 0
    monkeypatch.setattr(worker_module.asyncio, "create_subprocess_exec", AsyncMock(return_value=process))
    worker = await OfflineWorker.available(root, ())
    assert worker is not None and worker.root == root
    assert len(visited) == 1 and visited[0].parent == Path("/tmp")
    assert not visited[0].exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_timeout_or_cancellation_reaps_probe(tmp_path, monkeypatch, cancel):
    binaries(monkeypatch)
    monkeypatch.setattr(worker_module, "PROBE_TIMEOUT_SECONDS", 0.03)
    entered = asyncio.Event()

    class Process:
        returncode = None
        killed = False

        async def wait(self):
            if self.returncode is None:
                entered.set()
                await asyncio.Event().wait()
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -9

    process = Process()
    monkeypatch.setattr(worker_module.asyncio, "create_subprocess_exec", AsyncMock(return_value=process))
    task = asyncio.create_task(OfflineWorker.available(tmp_path, ()))
    await entered.wait()
    if cancel:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        assert await task is None
    assert process.killed and process.returncode == -9


@pytest.mark.asyncio
async def test_timeout_includes_subprocess_creation(tmp_path, monkeypatch):
    binaries(monkeypatch)
    monkeypatch.setattr(worker_module, "PROBE_TIMEOUT_SECONDS", 0.03)

    async def slow_creation(*args, **kwargs):
        await asyncio.Event().wait()

    monkeypatch.setattr(worker_module.asyncio, "create_subprocess_exec", slow_creation)
    assert await OfflineWorker.available(tmp_path, ()) is None


def test_actual_dispatch_rejects_unreadable_tree(tmp_path, monkeypatch):
    worker = OfflineWorker(tmp_path, (), "/usr/bin/bwrap", "/usr/bin/prlimit")

    def inaccessible(path, **kwargs):
        kwargs["onerror"](PermissionError("fixture"))
        return iter(())

    monkeypatch.setattr(worker_module.os, "walk", inaccessible)
    with pytest.raises(ExecutionBlocked, match="inspection-failed"):
        worker.wrap("/bin/true", [])


@pytest.mark.asyncio
async def test_real_probe_does_not_admit_project_fifo(tmp_path):
    if worker_module.shutil.which("bwrap") is None or worker_module.shutil.which("prlimit") is None:
        pytest.skip("existing Linux bwrap/prlimit required")
    worker_module.os.mkfifo(tmp_path / "host-ipc")
    worker = await OfflineWorker.available(tmp_path, ())
    assert worker is not None
    with pytest.raises(ExecutionBlocked, match="host-ipc"):
        worker.wrap("/bin/true", [])


@pytest.mark.parametrize('name', sorted(worker_module.EXCLUDED_DIRECTORY_NAMES))
def test_dependency_and_cache_directories_are_pruned_before_descent(tmp_path, monkeypatch, name):
    excluded = tmp_path / 'nested' / name
    excluded.mkdir(parents=True)
    worker_module.os.mkfifo(excluded / 'unchecked-fifo')
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'payload.txt').write_text("' OR 1=1-- <script>fixture</script>")
    visited = []
    original_walk = worker_module.os.walk

    def observed_walk(path, **kwargs):
        for directory, folders, files in original_walk(path, **kwargs):
            visited.append(Path(directory))
            yield directory, folders, files

    monkeypatch.setattr(worker_module.os, 'walk', observed_walk)
    worker = OfflineWorker(tmp_path, (), '/usr/bin/bwrap', '/usr/bin/prlimit')
    _, args = worker.wrap('/bin/true', [])
    assert source in visited
    assert not any(path.is_relative_to(excluded) for path in visited)
    assert '/work/nested/' + name in args  # The unchecked tree is hidden too.


@pytest.mark.asyncio
async def test_pruned_dependencies_are_hidden_but_project_security_still_applies(tmp_path):
    if worker_module.shutil.which('bwrap') is None or worker_module.shutil.which('prlimit') is None:
        pytest.skip('existing Linux worker required')
    for name in ('venv-linux', '.git'):
        directory = tmp_path / name
        directory.mkdir()
        (directory / 'fake-secret').write_text('FAKE_UNCHECKED_SECRET')
        worker_module.os.mkfifo(directory / 'unchecked-fifo')
    (tmp_path / 'source.txt').write_text('SOURCE_OK <script>fixture</script>')
    worker = await OfflineWorker.available(tmp_path, ())
    assert worker is not None
    command, args = await worker.prepare('/bin/sh', ['-c', 'cat source.txt; cat venv-linux/fake-secret .git/fake-secret'])
    process = await asyncio.create_subprocess_exec(command, *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, _ = await asyncio.wait_for(process.communicate(), 3)
    assert b'SOURCE_OK <script>fixture</script>' in stdout and b'FAKE_UNCHECKED_SECRET' not in stdout
    worker_module.os.mkfifo(tmp_path / 'source-fifo')
    with pytest.raises(ExecutionBlocked, match='host-ipc'):
        await worker.prepare('/bin/true', [])
