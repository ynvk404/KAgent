import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

from components.cwe_mcp.pack_runtime import pack_runtime
from src.permission.runtime.execution import ExecutionBlocked
from src.permission.worker.worker import OfflineWorker
from src.tools.mcp.cwe_deployment import verify_cwe_runtime_archive


def test_offline_archive_imports_bytecode_and_resources_without_writes(tmp_path):
    runtime = tmp_path / 'runtime'
    package = runtime / 'packed_fixture'
    package.mkdir(parents=True)
    (package / '__init__.py').write_text('VALUE = 42\n')
    (package / 'data.txt').write_text('RETAINED_RESOURCE')
    metadata = runtime / 'packed_fixture-1.0.dist-info'
    metadata.mkdir()
    (metadata / 'METADATA').write_text('Name: packed_fixture\nVersion: 1.0\n')
    native = runtime / 'native_fixture'
    native.mkdir()
    (native / '__init__.py').write_text('VALUE = 7\n')
    (native / 'extension.so').write_bytes(b'fixture marker; not executed')
    archive = pack_runtime(tmp_path)
    with zipfile.ZipFile(archive) as bundle:
        assert bundle.read('packed_fixture/__init__.pyc')[:4] == importlib.util.MAGIC_NUMBER
        assert bundle.read('packed_fixture/__init__.py') == b'VALUE = 42\n'
        assert not any(name.startswith('native_fixture/') for name in bundle.namelist())
    code = '\n'.join([
        'import sys, importlib.resources, importlib.metadata',
        f'sys.path[:0] = [{str(archive)!r}, {str(runtime)!r}]',
        'import packed_fixture, native_fixture',
        'assert packed_fixture.VALUE == 42 and native_fixture.VALUE == 7',
        "assert 'runtime.zip' in packed_fixture.__file__",
        "assert packed_fixture.__file__.endswith('.pyc')",
        "assert 'runtime.zip' not in native_fixture.__file__",
        "assert importlib.resources.files(packed_fixture).joinpath('data.txt').read_text() == 'RETAINED_RESOURCE'",
        "assert importlib.metadata.version('packed_fixture') == '1.0'",
        "assert not packed_fixture.__loader__.get_source('packed_fixture') is None",
    ])
    completed = subprocess.run([sys.executable, '-I', '-B', '-c', code], capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    assert not list(runtime.rglob('__pycache__'))
    assert not list(tmp_path.glob('.runtime-*.zip'))


@pytest.mark.parametrize('unsafe', ['symlink', 'hardlink', 'fifo'])
def test_archive_preparation_rejects_unsafe_runtime(tmp_path, unsafe):
    import os
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    source = tmp_path / 'outside'
    source.write_text('external fixture')
    path = runtime / 'unsafe.py'
    if unsafe == 'symlink':
        path.symlink_to(source)
    elif unsafe == 'hardlink':
        path.hardlink_to(source)
    else:
        os.mkfifo(path)
    with pytest.raises(ValueError):
        pack_runtime(tmp_path)
    assert not (tmp_path / 'runtime.zip').exists()


def test_failed_archive_preparation_preserves_previous_archive(tmp_path):
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    (runtime / 'fixture.py').write_text('VALUE = 42\n')
    archive = pack_runtime(tmp_path)
    previous = archive.read_bytes()
    (runtime / 'fixture.py').write_text('invalid python (')
    with pytest.raises(SyntaxError):
        pack_runtime(tmp_path)
    assert archive.read_bytes() == previous
    assert not list(tmp_path.glob('.runtime-*.zip'))


@pytest.mark.skipif(sys.platform != 'linux', reason='existing Linux CWE worker')
def test_archive_imports_from_sealed_memory_with_resources_and_metadata(tmp_path):
    runtime = tmp_path / 'runtime'
    package = runtime / 'memory_fixture'
    package.mkdir(parents=True)
    (package / '__init__.py').write_text('VALUE = 42\n')
    (package / 'data.txt').write_text('MEMORY_RESOURCE')
    metadata = runtime / 'memory_fixture-1.0.dist-info'
    metadata.mkdir()
    (metadata / 'METADATA').write_text('Name: memory_fixture\nVersion: 1.0\n')
    archive = pack_runtime(tmp_path)
    launch = Path(__file__).parents[2] / 'components/cwe_mcp/launch.py'
    code = '\n'.join([
        'import runpy, sys, os, errno, importlib.resources, importlib.metadata',
        'from pathlib import Path',
        f"load = runpy.run_path({str(launch)!r})['memory_archive']",
        f'path, descriptor = load(Path({str(archive)!r}))',
        'sys.path.insert(0, path)',
        f'Path({str(archive)!r}).unlink()',
        'import memory_fixture',
        "assert memory_fixture.__file__.startswith('/proc/self/fd/')",
        "assert memory_fixture.__file__.endswith('.pyc') and memory_fixture.VALUE == 42",
        "assert importlib.resources.files(memory_fixture).joinpath('data.txt').read_text() == 'MEMORY_RESOURCE'",
        "assert importlib.metadata.version('memory_fixture') == '1.0'",
        'try:',
        "    os.write(descriptor, b'forbidden')",
        'except OSError as error:',
        '    assert error.errno == errno.EPERM',
        "else: raise AssertionError('archive not sealed')",
        'os.close(descriptor)',
    ])
    completed = subprocess.run([sys.executable, '-I', '-B', '-c', code], capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    assert not list(runtime.rglob('__pycache__'))
    assert not list(tmp_path.glob('.runtime-*'))


@pytest.mark.parametrize('change', ['source', 'same-stat-source', 'native', 'resource', 'add',
                                    'remove', 'directory', 'missing-inventory', 'corrupt-archive'])
def test_worker_blocks_stale_archive_before_launch_and_explicit_repack_recovers(tmp_path, change):
    import os
    project = tmp_path / 'project'
    project.mkdir()
    deployment = tmp_path / 'deployment'
    runtime = deployment / 'runtime'
    runtime.mkdir(parents=True)
    source = runtime / 'fixture.py'
    source.write_text('VALUE = 42\n')
    native = runtime / 'native_fixture'
    native.mkdir()
    (native / 'extension.so').write_bytes(b'nonexecuted native fixture')
    (runtime / 'data.txt').write_text('original resource')
    archive = pack_runtime(deployment)
    worker = OfflineWorker(project, (), '/usr/bin/bwrap', '/usr/bin/prlimit',
                           cwe_mcp_deployment_path=deployment)
    worker.wrap('/bin/true', [], cwe_mcp_deployment_path=deployment)
    if change in {'source', 'same-stat-source'}:
        previous = source.stat()
        source.write_text('VALUE = 99\n')
        if change == 'same-stat-source':
            os.utime(source, ns=(previous.st_atime_ns, previous.st_mtime_ns))
            assert source.stat().st_size == previous.st_size
    elif change == 'native':
        (native / 'extension.so').write_bytes(b'changed native fixture')
    elif change == 'resource':
        (runtime / 'data.txt').write_text('changed resource')
    elif change == 'add':
        (runtime / 'new_module.py').write_text('VALUE = 1\n')
    elif change == 'remove':
        source.unlink()
    elif change == 'directory':
        (runtime / 'namespace_package').mkdir()
    elif change == 'missing-inventory':
        with zipfile.ZipFile(archive, 'w') as bundle:
            bundle.writestr('fixture.py', source.read_bytes())
    else:
        archive.write_bytes(b'invalid zip archive')
    with pytest.raises(ExecutionBlocked, match='stale-or-invalid-CWE-runtime-archive'):
        worker.wrap('/bin/true', [], cwe_mcp_deployment_path=deployment)
    pack_runtime(deployment)
    worker.wrap('/bin/true', [], cwe_mcp_deployment_path=deployment)
    with zipfile.ZipFile(archive) as bundle:
        inventory = json.loads(bundle.read('kagent-runtime-manifest.json'))
        assert inventory['schema_version'] == 1
    assert not list(deployment.glob('.runtime-*'))


def test_dependency_hashing_observes_preflight_cancellation_between_chunks(tmp_path):
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    resource = runtime / 'data.bin'
    resource.write_bytes(b'x' * (2 * 1024 * 1024))
    pack_runtime(tmp_path)
    calls = 0
    def checkpoint():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ExecutionBlocked('blocked: worker-inspection-cancelled')
    with pytest.raises(ExecutionBlocked, match='worker-inspection-cancelled'):
        verify_cwe_runtime_archive(tmp_path, {'data.bin': resource}, checkpoint)
    assert calls == 2
