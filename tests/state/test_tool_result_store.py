"""Phase B private storage, character ranges and publication failures."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import json
import os
import stat
import time

import pytest

from src.session.tool_results import (
    ToolResultStore, ResultUnavailable, ResultReference, read_region, valid_ref,
    MAX_READ_CHARS,
)


@pytest.fixture
def store(tmp_path):
    return ToolResultStore(tmp_path, 'session')


def put(store, text='retained 雨🙂 text', **kwargs):
    return store.put(text, generation='generation', provenance={'kind': 'file', 'path': '/fixture'},
                     tool_name='file_read', tool_call_id='call', status='success',
                     error_kind=None, http_status=None, truncated=False, **kwargs)


def artifact(store, ref):
    return store.project / '.kagent/tool-results' / store.session_id / (ref.result_ref + '.result')


def test_roundtrip_private_permissions_and_lengths(store):
    text = '雨🙂' * 100
    ref = put(store, text)
    assert ref is not None
    assert ref.char_length == len(text) and ref.byte_length == len(text.encode())
    assert store.resolve(ref, 'generation')[0] == text
    path = artifact(store, ref)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.parent.parent.stat().st_mode) == 0o700
    assert path.stat().st_nlink == 1


@pytest.mark.parametrize('invalid', ['', '../result', 'tr_'+'f'*31, 'tr_'+'f'*32+'/../x',
                                       '/etc/passwd', 'tr_'+'F'*32, 'tr_'+'f'*32+'\n', None])
def test_malformed_ref_never_accesses_filesystem(store, invalid, monkeypatch):
    assert not valid_ref(invalid)
    ref = put(store)
    assert ref is not None
    def fail():
        pytest.fail('invalid ref reached the filesystem')
    monkeypatch.setattr(store, '_directory', fail)
    with pytest.raises(ResultUnavailable, match='invalid'):
        store.resolve(replace(ref, result_ref=invalid), 'generation')


@pytest.mark.parametrize('binding', ['session', 'project', 'generation', 'owner', 'sha', 'bytes', 'chars', 'provenance'])
def test_scope_and_integrity_fail_closed(store, tmp_path, binding):
    ref = put(store)
    assert ref is not None
    if binding == 'session':
        other = ToolResultStore(tmp_path, 'other')
        # Even a copied valid blob at the other scoped location is rejected.
        other_ref = put(other)
        assert other_ref is not None
        artifact(other, other_ref).unlink()
        artifact(other, ref).write_bytes(artifact(store, ref).read_bytes())
        artifact(other, ref).chmod(0o600)
        with pytest.raises(ResultUnavailable):
            other.resolve(ref, 'generation')
        return
    if binding == 'project':
        root = tmp_path / 'other-project'
        root.mkdir()
        other = ToolResultStore(root, 'session')
        other_ref = put(other)
        assert other_ref is not None
        artifact(other, other_ref).unlink()
        artifact(other, ref).write_bytes(artifact(store, ref).read_bytes())
        artifact(other, ref).chmod(0o600)
        with pytest.raises(ResultUnavailable):
            other.resolve(ref, 'generation')
        return
    if binding == 'generation':
        with pytest.raises(ResultUnavailable):
            store.resolve(ref, 'another-generation')
        return
    path = artifact(store, ref)
    header, payload = path.read_bytes().split(b'\n', 1)
    meta = json.loads(header)
    if binding == 'owner':
        meta['session'] = 'forged'
    elif binding == 'sha':
        payload = payload.replace(b'retained', b'changed!')
    elif binding == 'bytes':
        ref = replace(ref, byte_length=ref.byte_length + 1)
        meta['reference'] = asdict(ref)
    elif binding == 'chars':
        ref = replace(ref, char_length=ref.char_length + 1)
        meta['reference'] = asdict(ref)
    else:
        meta['provenance']['path'] = '/another'
    path.write_bytes(json.dumps(meta).encode() + b'\n' + payload)
    with pytest.raises(ResultUnavailable, match='integrity|scope'):
        store.resolve(ref, 'generation')


@pytest.mark.parametrize('attack', ['symlink', 'hardlink', 'public_file', 'directory_symlink', 'directory_swap'])
def test_filesystem_attacks(store, tmp_path, attack):
    ref = put(store)
    assert ref is not None
    path = artifact(store, ref)
    if attack == 'symlink':
        copy = tmp_path / 'copy'
        path.rename(copy)
        path.symlink_to(copy)
    elif attack == 'hardlink':
        os.link(path, tmp_path / 'copy')
    elif attack == 'public_file':
        path.chmod(0o644)
    else:
        parent = path.parent
        moved = parent.with_name('moved')
        parent.rename(moved)
        if attack == 'directory_symlink':
            parent.symlink_to(moved, target_is_directory=True)
        else:
            parent.mkdir(mode=0o700)
    with pytest.raises(ResultUnavailable):
        store.resolve(ref, 'generation')


@pytest.mark.parametrize('start,size,end', [(-50, 3, 3), (3, 3, 6), (999, 100, 6), (0, -8, 0),
                                          (0, 99999, 6)])
def test_unicode_character_range_normalization(start, size, end):
    text = 'a雨🙂xyz'
    region = read_region(text, start, size)
    assert region['actual_start'] == max(0, min(6, start))
    assert region['actual_end'] == end
    assert region['content'] == text[region['actual_start']:end]
    assert region['next_offset'] == (end if end < 6 else None)
    assert region['completeness'] == ('complete' if end == 6 else 'partial')
    region['content'].encode().decode('utf-8')


def test_max_range_clamp():
    result = read_region('x'*20000, 5, 9999999)
    assert len(result['content']) == MAX_READ_CHARS
    assert result['next_offset'] == 5 + MAX_READ_CHARS


@pytest.mark.parametrize('quota', ['result', 'session', 'count'])
def test_quota_deterministic_no_live_eviction(tmp_path, quota):
    store = ToolResultStore(tmp_path, 'session', per_result=1000 if quota == 'result' else 100000,
                            per_session=1600 if quota == 'session' else 100000, max_results=1 if quota == 'count' else 32)
    first = put(store, 'x'*100)
    assert first is not None
    if quota == 'session':
        store.per_session = artifact(store, first).stat().st_size * 2 - 1
    second = put(store, 'x'*2000 if quota == 'result' else 'x'*100)
    assert second is None
    assert store.resolve(first, 'generation')[0] == 'x'*100


def test_concurrent_instances_unique_no_overwrite(tmp_path):
    stores = [ToolResultStore(tmp_path, 'session', max_results=16) for _ in range(4)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        refs = list(pool.map(lambda i: put(stores[i % 4], str(i)*100), range(24)))
    refs = [ref for ref in refs if ref is not None]
    assert len(refs) == len({ref.result_ref for ref in refs}) == 16
    assert all(store.resolve(ref, 'generation')[0] for store in stores for ref in refs)
    assert not list(artifact(stores[0], refs[0]).parent.glob('.tmp-*'))


def test_collision_never_overwrites(store, monkeypatch):
    import src.session.tool_results as module
    from types import SimpleNamespace
    first = put(store, 'first')
    assert first is not None
    monkeypatch.setattr(module.uuid, 'uuid4', lambda: SimpleNamespace(hex=first.result_ref[3:]))
    with pytest.raises(ResultUnavailable):
        put(store, 'second')
    assert store.resolve(first, 'generation')[0] == 'first'


@pytest.mark.parametrize('failure', ['cancel', 'write', 'publish', 'fsync'])
def test_incomplete_publication_never_readable(store, monkeypatch, failure):
    checks = []
    def cancel():
        checks.append(1)
        if len(checks) == 2:
            raise asyncio.CancelledError
    def broken(*args, **kwargs):
        raise OSError('synthetic disk failure')
    if failure == 'publish':
        monkeypatch.setattr(os, 'link', broken)
    elif failure == 'write':
        original = os.fdopen
        class BrokenStream:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): return self
            def __exit__(self, *args): self.stream.close()
            def fileno(self): return self.stream.fileno()
            def write(self, value):
                self.stream.write(value[:10])
                raise OSError('partial write')
        monkeypatch.setattr(os, 'fdopen', lambda fd, mode: BrokenStream(original(fd, mode)))
    elif failure == 'fsync':
        monkeypatch.setattr(os, 'fsync', broken)
    with pytest.raises(asyncio.CancelledError if failure == 'cancel' else ResultUnavailable):
        put(store, check_cancelled=cancel if failure == 'cancel' else lambda: None)
    directory = store.project / '.kagent/tool-results' / store.session_id
    assert not list(directory.glob('*.result'))
    assert not list(directory.glob('.tmp-*'))


def test_stale_orphan_and_temp_cleanup_preserves_live_and_saved(store):
    refs = [put(store, str(i)) for i in range(3)]
    assert all(refs)
    paths = [artifact(store, ref) for ref in refs]
    temp = paths[0].parent / '.tmp-stale'
    temp.write_text('partial')
    temp.chmod(0o600)
    for path in [*paths, temp]: os.utime(path, (1, 1))
    count = store.cleanup(live_refs={refs[0].result_ref}, saved_refs={refs[1].result_ref}, stale_before=time.time())
    assert count == 2
    assert paths[0].exists() and paths[1].exists()
    assert not paths[2].exists() and not temp.exists()


def test_owner_uid_mismatch_denied(store, monkeypatch):
    ref = put(store)
    assert ref is not None
    actual_uid = os.geteuid()
    monkeypatch.setattr(os, 'geteuid', lambda: actual_uid + 1)
    with pytest.raises(ResultUnavailable, match='ownership'):
        store.resolve(ref, 'generation')
