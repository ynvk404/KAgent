"""Independent audit regressions for publication and locking boundaries."""
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import fcntl
import os
import threading
import stat
import multiprocessing
import asyncio

import pytest

from src.session.tool_results import ResultUnavailable, ToolResultStore
from src.session.tool_results import MAX_HEADER_BYTES
from tests.state.test_tool_result_store import artifact, put


def test_directory_replacement_during_publication_cannot_return_reference(tmp_path, monkeypatch):
    store = ToolResultStore(tmp_path, 'session')
    first = put(store, 'existing live result')
    assert first is not None
    parent = artifact(store, first).parent
    original_link = os.link

    def replace_directory(*args, **kwargs):
        parent.rename(parent.with_name('detached-session'))
        parent.mkdir(mode=0o700)
        return original_link(*args, **kwargs)

    monkeypatch.setattr(os, 'link', replace_directory)
    try:
        ref = put(store, 'result published in a detached directory')
    except ResultUnavailable:
        return
    if ref is not None:
        with pytest.raises(ResultUnavailable, match='binding changed'):
            store.resolve(ref, 'generation')
    assert ref is None, 'publication must fail safely before an unreachable reference escapes'


@pytest.mark.parametrize('replace_lock', [True, False])
@pytest.mark.parametrize('quota', ['count', 'bytes'])
def test_lock_replacement_cannot_split_writer_transaction(tmp_path, monkeypatch, replace_lock, quota):
    first_store = ToolResultStore(tmp_path, 'session', max_results=2)
    second_store = ToolResultStore(tmp_path, 'session', max_results=2)
    existing = put(first_store, 'existing')
    assert existing is not None
    parent = artifact(first_store, existing).parent
    if quota == 'bytes':
        first_store.max_results = second_store.max_results = 32
        first_store.per_session = second_store.per_session = artifact(first_store, existing).stat().st_size * 2 + 50
    entered = threading.Event()
    release = threading.Event()
    original_link = os.link
    original_flock = fcntl.flock
    second_lock = threading.Event()

    def observe_lock(fd, operation):
        if threading.current_thread().name.startswith('audit-second'):
            second_lock.set()
        return original_flock(fd, operation)

    def suspend_first_writer(*args, **kwargs):
        if threading.current_thread().name.startswith('audit-first'):
            entered.set()
            assert release.wait(10), 'audit synchronization timeout'
        return original_link(*args, **kwargs)

    monkeypatch.setattr(os, 'link', suspend_first_writer)
    monkeypatch.setattr(fcntl, 'flock', observe_lock)
    with (ThreadPoolExecutor(max_workers=1, thread_name_prefix='audit-first') as pool,
          ThreadPoolExecutor(max_workers=1, thread_name_prefix='audit-second') as other):
        pending = pool.submit(put, first_store, 'first overlapping publication')
        try:
            assert entered.wait(10), 'first writer did not reach publication'
            # Same-owner replacement is the same filesystem threat model as
            # the existing symlink/hardlink/directory replacement tests.
            if replace_lock:
                (parent / '.lock').rename(parent / '.lock-detached')
            # The corrected directory lock blocks B. Run it in another worker
            # so the controller can release A; retain the original quota
            # negative case if a replaceable-lock implementation admits B.
            pending_second = other.submit(put, second_store, 'second overlapping publication')
            assert second_lock.wait(10)
            try:
                pending_second.result(timeout=0.1)
            except TimeoutError:
                pass
        finally:
            release.set()
        try:
            first = pending.result()
        except ResultUnavailable:
            first = None
        second = pending_second.result(timeout=10)
    count = len(list(parent.glob('*.result')))
    assert not (first is not None and second is not None), (
        f'two locks admitted both writers; result count={count}, quota=2'
    )
    assert count <= 2
    assert sum(path.stat().st_size for path in parent.glob('*.result')) <= first_store.per_session
    assert artifact(first_store, existing).read_bytes().endswith(b'existing')
    assert not list(parent.glob('.tmp-*'))


@pytest.mark.parametrize('header', ['short', 'oversized', 'malformed', 'missing_delimiter', 'json_list'])
def test_header_only_read_is_bounded_and_delimiter_exact(tmp_path, monkeypatch, header):
    store = ToolResultStore(tmp_path, 'session')
    ref = put(store, 'PAYLOAD-MARKER')
    assert ref is not None
    path = artifact(store, ref)
    metadata, payload = path.read_bytes().split(b'\n', 1)
    if header == 'oversized':
        metadata = b' ' * MAX_HEADER_BYTES + metadata
    elif header == 'malformed':
        metadata = b'{'  # Delimited but invalid controller header.
    elif header == 'missing_delimiter':
        path.write_bytes(metadata)
    elif header == 'json_list':
        metadata = b'[]'
    if header != 'missing_delimiter':
        path.write_bytes(metadata + b'\n' + payload)
    observed = []
    original_read = os.read
    def read(fd, size):
        value = original_read(fd, size)
        observed.append(value)
        return value
    monkeypatch.setattr(os, 'read', read)
    if header == 'short':
        assert store.provenance(ref, 'generation') == {'kind': 'file', 'path': '/fixture'}
    else:
        with pytest.raises(ResultUnavailable):
            store.provenance(ref, 'generation')
    assert b'PAYLOAD-MARKER' not in b''.join(observed)
    assert len(b''.join(observed)) <= MAX_HEADER_BYTES
    if header == 'short':
        assert b''.join(observed) == metadata + b'\n'


@pytest.mark.parametrize('binding', ['session', 'tool-results', '.kagent', 'project', 'lock'])
@pytest.mark.parametrize('boundary', ['link', 'unlink', 'fsync'])
def test_publication_checks_binding_at_commit_boundaries(tmp_path, monkeypatch, binding, boundary):
    root = tmp_path / 'project'
    root.mkdir()
    store = ToolResultStore(root, 'session')
    existing = put(store, 'existing live result')
    assert existing is not None
    parent = artifact(store, existing).parent
    victim = {'session': parent, 'tool-results': parent.parent, '.kagent': root / '.kagent',
              'project': root, 'lock': parent / '.lock'}[binding]
    detached = victim.with_name(victim.name + '-detached')
    original = getattr(os, boundary)
    mutated = False
    def replace(*args, **kwargs):
        nonlocal mutated
        is_commit = boundary != 'fsync' or stat.S_ISDIR(os.fstat(args[0]).st_mode)
        result = original(*args, **kwargs)
        if is_commit and not mutated:
            mutated = True
            victim.rename(detached)
            if binding == 'lock':
                victim.touch(mode=0o600)
            else:
                victim.mkdir(mode=0o700)
        return result
    monkeypatch.setattr(os, boundary, replace)
    with pytest.raises(ResultUnavailable):
        put(store, 'unreachable publication')
    assert mutated
    location = parent if binding == 'lock' else detached / parent.relative_to(victim)
    assert sorted(path.name for path in location.glob('*.result')) == [existing.result_ref + '.result']
    assert (location / (existing.result_ref + '.result')).read_bytes().endswith(b'existing live result')
    assert not list(location.glob('.tmp-*'))


@pytest.mark.parametrize('failure', ['unlink', 'directory_fsync', 'cancel_commit'])
def test_failure_after_link_rolls_back_only_new_publication(tmp_path, monkeypatch, failure):
    store = ToolResultStore(tmp_path, 'session')
    existing = put(store, 'preserve this result')
    assert existing is not None
    parent = artifact(store, existing).parent
    original_unlink, original_fsync = os.unlink, os.fsync
    failed = False
    def unlink(name, **kwargs):
        nonlocal failed
        if not failed and name.startswith('.tmp-'):
            failed = True
            raise OSError('injected unlink failure after publication')
        return original_unlink(name, **kwargs)
    def fsync(fd):
        nonlocal failed
        if not failed and stat.S_ISDIR(os.fstat(fd).st_mode):
            failed = True
            raise OSError('injected directory fsync failure after publication')
        return original_fsync(fd)
    checks = 0
    def cancelled():
        nonlocal checks
        checks += 1
        if checks == 3:
            raise asyncio.CancelledError
    if failure != 'cancel_commit':
        monkeypatch.setattr(os, 'unlink' if failure == 'unlink' else 'fsync', unlink if failure == 'unlink' else fsync)
    with pytest.raises(asyncio.CancelledError if failure == 'cancel_commit' else ResultUnavailable):
        put(store, 'failed publication', check_cancelled=cancelled if failure == 'cancel_commit' else lambda: None)
    assert checks == 3 if failure == 'cancel_commit' else failed
    assert sorted(path.name for path in parent.glob('*.result')) == [existing.result_ref + '.result']
    assert not list(parent.glob('.tmp-*'))
    assert store.resolve(existing, 'generation')[0] == 'preserve this result'


def _process_writer(project, pipe):
    # Spawned interpreter: no inherited held flock or in-process mutex.
    original = fcntl.flock
    def observe(fd, operation):
        pipe.send('locking')
        return original(fd, operation)
    fcntl.flock = observe
    try:
        ref = put(ToolResultStore(project, 'session', max_results=2), 'second process')
        pipe.send(ref.result_ref if ref else None)
    except ResultUnavailable:
        pipe.send(None)
    finally:
        pipe.close()


@pytest.mark.parametrize('replace_lock', [False, True])
def test_process_writers_share_directory_lock(tmp_path, monkeypatch, replace_lock):
    store = ToolResultStore(tmp_path, 'session', max_results=2)
    existing = put(store, 'existing')
    assert existing is not None
    parent = artifact(store, existing).parent
    entered, release = threading.Event(), threading.Event()
    original_link = os.link
    def pause(*args, **kwargs):
        entered.set()
        assert release.wait(15)
        return original_link(*args, **kwargs)
    monkeypatch.setattr(os, 'link', pause)
    context = multiprocessing.get_context('spawn')
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_process_writer, args=(tmp_path, sender))
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(put, store, 'first process')
        try:
            assert entered.wait(10)
            if replace_lock:
                (parent / '.lock').rename(parent / '.lock-detached')
            process.start()
            sender.close()
            assert receiver.poll(15) and receiver.recv() == 'locking'
            assert not receiver.poll(0.1), 'second process must wait on the held directory inode'
        finally:
            release.set()
            if process.pid is not None:
                process.join(15)
                if process.is_alive():
                    process.terminate()
                    process.join(5)
        try:
            first_ref = first.result(timeout=10)
        except ResultUnavailable:
            first_ref = None
    assert process.exitcode == 0
    assert receiver.poll(1)
    second_ref = receiver.recv()
    receiver.close()
    assert not (first_ref is not None and second_ref is not None)
    assert len(list(parent.glob('*.result'))) == 2
