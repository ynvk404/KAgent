"""Startup capability checking is bounded and never scans the project."""
from __future__ import annotations

import asyncio
from pathlib import Path
import sys
from unittest.mock import AsyncMock

import pytest

from src.permission.runtime.execution import ExecutionBlocked
from src.permission.worker.worker import OfflineWorker
import src.permission.worker.worker as worker_module


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


def test_external_cwe_mount_is_exact_read_only_and_opt_in(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    deployment = tmp_path / 'operator-data' / 'cwe-mcp-deployment'
    deployment.mkdir(parents=True)
    (deployment / 'launch.py').write_text("print('fixture')\n")
    worker = OfflineWorker(project, (), '/usr/bin/bwrap', '/usr/bin/prlimit',
                           cwe_mcp_deployment_path=deployment)

    _, cwe_args = worker.wrap('/usr/bin/python3', ['-I', '-B', '/opt/kagent-cwe-mcp/launch.py'],
                              cwe_mcp_deployment_path=deployment)
    _, ordinary_args = worker.wrap('/bin/true', [])

    mount_index = cwe_args.index('--ro-bind', cwe_args.index('/work/artifacts/worker') + 1)
    assert cwe_args[mount_index + 1:mount_index + 3] == [str(deployment), '/opt/kagent-cwe-mcp']
    assert str(deployment.parent) not in cwe_args
    assert str(deployment) not in ordinary_args
    assert '/opt/kagent-cwe-mcp' not in ordinary_args


@pytest.mark.parametrize('unsafe', ['missing', 'root-symlink', 'nested-symlink', 'hardlink', 'traversal',
                                   'parent-traversal', 'fifo'])
def test_external_cwe_mount_rejects_unsafe_or_nonmatching_root(tmp_path, unsafe):
    project = tmp_path / 'project'
    project.mkdir()
    parent = tmp_path / 'operator-data'
    parent.mkdir()
    deployment = parent / 'cwe-mcp-deployment'
    deployment.mkdir()
    (deployment / 'launch.py').write_text("print('fixture')\n")
    configured = deployment
    if unsafe == 'missing':
        configured = parent / 'missing'
    elif unsafe == 'root-symlink':
        configured = parent / 'deployment-link'
        configured.symlink_to(deployment, target_is_directory=True)
    elif unsafe == 'nested-symlink':
        (deployment / 'escape').symlink_to(parent, target_is_directory=True)
    elif unsafe == 'hardlink':
        outside = parent / 'sibling-secret'
        outside.write_text('not deployment data')
        (deployment / 'linked-secret').hardlink_to(outside)
    elif unsafe == 'parent-traversal':
        configured = deployment / '..' / deployment.name
    elif unsafe == 'fifo':
        worker_module.os.mkfifo(deployment / 'host-fifo')

    worker = OfflineWorker(project, (), '/usr/bin/bwrap', '/usr/bin/prlimit',
                           cwe_mcp_deployment_path=configured)
    requested = parent / 'sibling' if unsafe == 'traversal' else configured
    with pytest.raises(ExecutionBlocked):
        worker.wrap('/usr/bin/python3', ['-I', '-B', '/opt/kagent-cwe-mcp/launch.py'],
                    cwe_mcp_deployment_path=requested)


@pytest.mark.parametrize('location', ['output', 'output-child', 'output-parent', 'protected'])
def test_cwe_deployment_cannot_expose_writable_or_protected_alias(tmp_path, location):
    project = tmp_path / 'project'
    project.mkdir()
    output = project / 'artifacts/worker'
    protected = project / 'control'
    protected.mkdir()
    deployment = {'output': output, 'output-child': output / 'deployment',
                  'output-parent': output.parent, 'protected': protected}[location]
    deployment.mkdir(parents=True, exist_ok=True)
    worker = OfflineWorker(project, (protected,), '/usr/bin/bwrap', '/usr/bin/prlimit',
                           cwe_mcp_deployment_path=deployment)
    with pytest.raises(ExecutionBlocked, match='CWE-deployment-overlaps'):
        worker.wrap('/usr/bin/python3', ['-I', '-B', '/opt/kagent-cwe-mcp/launch.py'],
                    cwe_mcp_deployment_path=deployment)


@pytest.mark.parametrize('alias_child', [False, True])
def test_cwe_mount_rejects_physical_output_alias_with_different_spelling(tmp_path, monkeypatch, alias_child):
    project = tmp_path / 'project'
    project.mkdir()
    alias = tmp_path / 'different-output-spelling'
    alias.mkdir()
    deployment = alias / 'deployment' if alias_child else alias
    deployment.mkdir(exist_ok=True)
    worker = OfflineWorker(project, (), '/usr/bin/bwrap', '/usr/bin/prlimit',
                           cwe_mcp_deployment_path=deployment)
    output_info = worker.output_root.stat()
    original_stat = Path.stat
    # Simulate an NTFS case alias or a bind-mounted second pathname. These
    # cannot be created as directory hardlinks on the Linux test filesystem.
    def alias_stat(path, *args, **kwargs):
        return output_info if path == alias else original_stat(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'stat', alias_stat)
    with pytest.raises(ExecutionBlocked, match='overlaps-writable-worker-output'):
        worker.wrap('/usr/bin/python3', ['-I', '-B', '/opt/kagent-cwe-mcp/launch.py'],
                    cwe_mcp_deployment_path=deployment)


@pytest.mark.asyncio
async def test_real_worker_mounts_external_cwe_tree_read_only_without_siblings(tmp_path):
    if worker_module.shutil.which('bwrap') is None or worker_module.shutil.which('prlimit') is None:
        pytest.skip('existing Linux worker required')
    project = tmp_path / 'project'
    project.mkdir()
    parent = tmp_path / 'operator-data'
    deployment = parent / 'cwe-mcp-deployment'
    (deployment / 'corpus').mkdir(parents=True)
    (deployment / 'corpus/marker.txt').write_text('CWE_TREE_VISIBLE')
    sibling = parent / 'sibling-secret.txt'
    sibling.write_text('SIBLING_HIDDEN')
    worker = await OfflineWorker.available(project, (), cwe_mcp_deployment_path=deployment)
    assert worker is not None
    check = '\n'.join([
        'import errno',
        'from pathlib import Path',
        "root = Path('/opt/kagent-cwe-mcp')",
        "assert (root / 'corpus/marker.txt').read_text() == 'CWE_TREE_VISIBLE'",
        f'assert not Path({str(sibling)!r}).exists()',
        f'assert not Path({str(deployment)!r}).exists()',
        'try:',
        "    (root / 'write-probe').write_text('no')",
        'except OSError as error:',
        '    assert error.errno == errno.EROFS',
        "else: raise AssertionError('deployment writable')",
    ])
    command, argv = await worker.prepare('/usr/bin/python3', ['-I', '-B', '-c', check],
                                         cwe_mcp_deployment_path=deployment)
    process = await asyncio.create_subprocess_exec(command, *argv, stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.PIPE)
    _, stderr = await asyncio.wait_for(process.communicate(), 10)
    assert process.returncode == 0, stderr.decode(errors='replace')
    assert not (deployment / 'write-probe').exists()
