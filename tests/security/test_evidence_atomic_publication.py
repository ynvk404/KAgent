import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import os
import threading

import pytest

from src.workflow.evidence import EvidenceArtifact
from tests.security.test_evidence_reads import workflow
from src.permission.permission import AlwaysAllow


@pytest.mark.parametrize('failure', ['short', 'write', 'flush', 'fsync', 'close', 'fdopen', 'publish', 'cancel'])
async def test_failed_publication_leaves_no_final_or_metadata_and_retry_recovers(tmp_path, monkeypatch, failure):
    import src.workflow.evidence_publication as publication
    tool, cid = workflow(tmp_path)
    raw = b'complete synthetic proof'
    (tmp_path / 'proof.txt').write_bytes(raw)
    original = os.fdopen

    class Writer:
        def __init__(self, *args, **kwargs):
            self.handle = original(*args, **kwargs)
        def __getattr__(self, name):
            return getattr(self.handle, name)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.handle.close()
            if failure == 'close':
                raise OSError('injected close failure')
        def write(self, data):
            if failure in {'short', 'write', 'cancel'}:
                self.handle.write(data[:3])
                if failure == 'short':
                    return 0
                if failure == 'cancel':
                    raise asyncio.CancelledError()
                raise OSError('injected write failure')
            return self.handle.write(data)
        def flush(self):
            if failure == 'flush':
                raise OSError('injected flush failure')
            self.handle.flush()

    def fail(*args):
        raise OSError('injected publication failure')

    args = dict(action='record_evidence', candidate_id=cid, evidence_path='proof.txt')
    with monkeypatch.context() as patch:
        patch.setattr(os, 'fdopen', fail if failure == 'fdopen' else Writer)
        if failure == 'fsync':
            patch.setattr(os, 'fsync', fail)
        if failure == 'publish':
            patch.setattr(publication, '_rename_noreplace', fail)
        if failure == 'cancel':
            with pytest.raises(asyncio.CancelledError):
                await tool.run(args, None, AlwaysAllow())
        else:
            assert str(await tool.run(args, None, AlwaysAllow())).startswith('error:')
    assert not tool.state.evidence and not tool.state.mutation_lock.locked()
    assert not list(tmp_path.rglob('*.proof'))
    assert not list(tmp_path.rglob('*.proof-tmp'))
    output = json.loads(await tool.run(args, None, AlwaysAllow()))
    assert output['ok'] and len(tool.state.evidence) == 1
    proof = next(tmp_path.rglob('*.proof'))
    assert proof.read_bytes() == raw and proof.stat().st_mode & 0o777 == 0o400
    assert not list(tmp_path.rglob('*.proof-tmp'))


def test_real_short_writes_are_completed_before_publication(tmp_path, monkeypatch):
    original = os.fdopen
    class Writer:
        def __init__(self, *args, **kwargs):
            self.handle = original(*args, **kwargs)
        def __getattr__(self, name):
            return getattr(self.handle, name)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.handle.close()
        def write(self, data):
            assert not list(tmp_path.rglob('*.proof'))
            return self.handle.write(data[:3])
    (tmp_path / 'proof.txt').write_bytes(b'complete synthetic proof')
    monkeypatch.setattr(os, 'fdopen', Writer)
    artifact = EvidenceArtifact.capture_immutable_snapshot('candidate', 'proof.txt', tmp_path)
    assert artifact.is_resolvable(tmp_path)
    assert (tmp_path / artifact.path).read_bytes() == b'complete synthetic proof'


async def test_directory_fsync_failure_keeps_complete_proof_without_committing_metadata(tmp_path, monkeypatch):
    import stat
    tool, cid = workflow(tmp_path)
    (tmp_path / 'proof.txt').write_bytes(b'complete synthetic proof')
    original = os.fsync
    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError('injected directory fsync failure')
        return original(fd)
    args = dict(action='record_evidence', candidate_id=cid, evidence_path='proof.txt')
    with monkeypatch.context() as patch:
        patch.setattr(os, 'fsync', fail_directory)
        assert str(await tool.run(args, None, AlwaysAllow())).startswith('error:')
    assert not tool.state.evidence
    proofs = list(tmp_path.rglob('*.proof'))
    assert len(proofs) == 1 and proofs[0].read_bytes() == b'complete synthetic proof'
    assert not list(tmp_path.rglob('*.proof-tmp'))
    assert json.loads(await tool.run(args, None, AlwaysAllow()))['ok']
    assert len(tool.state.evidence) == 1


def test_concurrent_same_digest_publishers_reuse_only_complete_incumbent(tmp_path, monkeypatch):
    import src.workflow.evidence_publication as publication
    (tmp_path / 'proof.txt').write_bytes(b'complete synthetic proof')
    barrier = threading.Barrier(2)
    original = publication._rename_noreplace
    def publish(*args):
        barrier.wait(5)
        return original(*args)
    monkeypatch.setattr(publication, '_rename_noreplace', publish)
    with ThreadPoolExecutor(max_workers=2) as pool:
        tasks = [pool.submit(EvidenceArtifact.capture_immutable_snapshot, 'candidate', 'proof.txt', tmp_path) for _ in range(2)]
        artifacts = [task.result(5) for task in tasks]
    assert artifacts[0] == artifacts[1] and artifacts[0].is_resolvable(tmp_path)
    assert len(list(tmp_path.rglob('*.proof'))) == 1
    assert not list(tmp_path.rglob('*.proof-tmp'))


@pytest.mark.parametrize('incumbent', ['valid', 'corrupt', 'symlink', 'hardlink', 'writable'])
def test_incumbents_are_never_replaced_or_removed(tmp_path, incumbent):
    source = tmp_path / 'proof.txt'
    source.write_bytes(b'complete synthetic proof')
    artifact = EvidenceArtifact.capture_immutable_snapshot('candidate', source.name, tmp_path)
    destination = tmp_path / artifact.path
    if incumbent == 'corrupt':
        destination.chmod(0o600)
        destination.write_bytes(b'corrupt')
    elif incumbent == 'symlink':
        destination.unlink()
        destination.symlink_to(source)
    elif incumbent == 'hardlink':
        os.link(destination, tmp_path / 'other-link')
    elif incumbent == 'writable':
        destination.chmod(0o600)
    before = (destination.lstat(), destination.read_bytes())
    if incumbent == 'valid':
        assert EvidenceArtifact.capture_immutable_snapshot('candidate', source.name, tmp_path) == artifact
    else:
        with pytest.raises((ValueError, OSError)):
            EvidenceArtifact.capture_immutable_snapshot('candidate', source.name, tmp_path)
    after = destination.lstat()
    assert (after.st_dev, after.st_ino, after.st_mode) == (before[0].st_dev, before[0].st_ino, before[0].st_mode)
    assert destination.read_bytes() == before[1]
    assert not list(tmp_path.rglob('*.proof-tmp'))
