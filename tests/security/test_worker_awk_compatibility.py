"""Current-host executable compatibility, with unchanged worker isolation."""
import asyncio
from pathlib import Path

import pytest

from src.permission.worker.worker import OfflineWorker
from tests.security.test_offline_worker import worker_runtime


async def run(worker, command, argv):
    binary, args = worker.wrap(command, argv)
    process = await asyncio.create_subprocess_exec(binary, *args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await process.communicate()
    return process.returncode, stdout, stderr


async def test_awk_alternative_and_direct_binary_work_without_host_etc(worker_runtime):
    worker = worker_runtime[2].worker
    target = OfflineWorker._awk_alternative()
    if target is None:
        pytest.skip('current host has no executable awk alternative inside /usr/bin')
    for binary in ['/usr/bin/awk', str(target)]:
        code, stdout, stderr = await run(worker, binary, ['BEGIN { print 42 }'])
        assert code == 0 and stdout == b'42\n' and not stderr
    code, stdout, _ = await run(worker, '/bin/sh', ['-c', 'test ! -e /etc/passwd && test ! -e /etc/shadow'])
    assert code == 0 and not stdout


async def test_original_mount_layout_reproduces_external_symlink_failure(worker_runtime, monkeypatch):
    worker = worker_runtime[2].worker
    if not Path('/usr/bin/awk').is_symlink() or OfflineWorker._awk_alternative() is None:
        pytest.skip('current host does not have the reproduced alternatives chain')
    monkeypatch.setattr(OfflineWorker, '_awk_alternative', staticmethod(lambda: None))
    code, stdout, stderr = await run(worker, '/usr/bin/awk', ['BEGIN { print 42 }'])
    assert code != 0 and not stdout and stderr


@pytest.mark.parametrize('target', ['/not-mounted/awk', '/usr/bin/missing-awk-fixture'])
def test_unavailable_or_unmounted_dependency_never_adds_host_mounts(tmp_path, monkeypatch, target):
    original = Path.resolve
    def resolve(path, *args, **kwargs):
        return Path(target) if str(path) == '/etc/alternatives/awk' else original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'resolve', resolve)
    worker = OfflineWorker(tmp_path, (), '/usr/bin/bwrap', '/usr/bin/prlimit')
    assert worker._awk_alternative() is None
    _, args = worker.wrap('/bin/true', [])
    assert '/etc/alternatives/awk' not in args
    assert '/etc' not in args and '/not-mounted' not in args
    assert '--unshare-all' in args and '--cap-drop' in args and '--clearenv' in args
