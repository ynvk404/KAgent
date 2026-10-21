"""Proof reads bind both namespace edges and the authorized single-link inode."""
import asyncio
from contextlib import contextmanager
from pathlib import Path

import pytest

from src.permission.permission import AlwaysAllow
from src.workflow.evidence.artifacts import EvidenceArtifact
from src.workflow.evidence.source import EvidenceSource
from tests.security.test_evidence_reads import workflow


@pytest.mark.parametrize('project_root', [False, True])
def test_normal_capture_through_searchable_nonreadable_directory(tmp_path, project_root):
    directory = tmp_path if project_root else tmp_path / 'search-only'
    if not project_root:
        directory.mkdir()
    source = directory / 'proof.txt'
    source.write_bytes(b'ordinary authorized proof')
    directory.chmod(0o300 if project_root else 0o100)
    try:
        artifact = EvidenceArtifact.capture_immutable_snapshot('candidate', str(source), tmp_path)
        assert artifact.is_resolvable(tmp_path)
        assert (tmp_path / artifact.path).read_bytes() == b'ordinary authorized proof'
    finally:
        directory.chmod(0o700)


@pytest.mark.parametrize('change', ['symlink', 'regular', 'ancestor', 'root', 'hardlink'])
def test_replacement_before_open_reads_nothing_and_publishes_nothing(tmp_path, monkeypatch, change):
    root = tmp_path / 'project'
    source = root / 'nested/proof.txt'
    source.parent.mkdir(parents=True)
    source.write_bytes(b'authorized proof')
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'proof.txt').write_bytes(b'foreign proof')
    original = EvidenceSource.open
    entered = []

    @contextmanager
    def swapped(binding):
        if binding.path == source:
            if change == 'ancestor':
                source.parent.rename(root / 'retired')
                source.parent.symlink_to(outside, target_is_directory=True)
            elif change == 'root':
                root.rename(tmp_path / 'retired-root')
                root.symlink_to(outside, target_is_directory=True)
            else:
                source.unlink()
                if change == 'symlink':
                    source.symlink_to(outside / 'proof.txt')
                elif change == 'hardlink':
                    source.hardlink_to(outside / 'proof.txt')
                else:
                    source.write_bytes(b'unauthorized replacement')
        with original(binding) as handle:
            entered.append(binding.path)
            yield handle

    monkeypatch.setattr(EvidenceSource, 'open', swapped)
    with pytest.raises((ValueError, OSError)):
        EvidenceArtifact.capture_immutable_snapshot('candidate', str(source), root)
    assert not entered
    assert not list(tmp_path.rglob('*.proof'))


async def test_source_binding_survives_review_only_while_resource_unchanged(tmp_path, monkeypatch):
    tool, cid = workflow(tmp_path)
    source = tmp_path / 'proof.txt'
    source.write_bytes(b'first proof')
    entered, release = asyncio.Event(), asyncio.Event()

    async def gate(*args):
        entered.set()
        await release.wait()
        return str(source)

    monkeypatch.setattr('src.tools.workflow.workflow_tool.gate_sensitive_path', gate)
    pending = asyncio.create_task(tool.run({'action': 'record_evidence', 'candidate_id': cid,
                                           'evidence_path': source.name}, None, AlwaysAllow()))
    await entered.wait()
    source.rename(tmp_path / 'old.txt')
    source.write_bytes(b'different proof')
    release.set()
    assert (await pending).startswith('error:')
    assert not tool.state.evidence and not list(tmp_path.rglob('*.proof'))


async def test_equal_state_replacement_during_review_cannot_adopt_old_evidence(tmp_path, monkeypatch):
    from src.workflow.state import WorkflowState
    tool, cid = workflow(tmp_path)
    source = tmp_path / 'proof.txt'
    source.write_bytes(b'authorized proof')
    entered, release = asyncio.Event(), asyncio.Event()
    async def gate(*args):
        entered.set()
        await release.wait()
        return str(source)
    monkeypatch.setattr('src.tools.workflow.workflow_tool.gate_sensitive_path', gate)
    task = asyncio.create_task(tool.run(dict(action='record_evidence', candidate_id=cid,
                                            evidence_path=source.name), None, AlwaysAllow()))
    await entered.wait()
    # Preserve even record object identity; serialized equality and `is`
    # checks cannot substitute for the controller-owned generation.
    replacement = WorkflowState(objective=tool.state.objective, candidates=dict(tool.state.candidates))
    tool.state.replace_from(replacement)
    release.set()
    assert str(await task).startswith('error:')
    assert not tool.state.evidence and not list(tmp_path.rglob('*.proof'))


async def test_queued_workflow_action_cannot_enter_a_replacement_generation(tmp_path):
    from src.workflow.state import WorkflowState
    tool, cid = workflow(tmp_path)
    (tmp_path / 'proof.txt').write_bytes(b'authorized queued proof')
    async with tool.state.mutation_lock:
        task = asyncio.create_task(tool.run(dict(action='record_evidence', candidate_id=cid,
                                                evidence_path='proof.txt'), None, AlwaysAllow()))
        await asyncio.sleep(0)
        tool.state.replace_from(WorkflowState(objective=tool.state.objective, candidates=dict(tool.state.candidates)))
    result = await task
    assert str(result).startswith('error:') and 'generation changed' in result
    assert not tool.state.evidence and not list(tmp_path.rglob('*.proof'))


async def test_cancelled_review_closes_directory_bindings(tmp_path, monkeypatch):
    import os
    tool, cid = workflow(tmp_path)
    (tmp_path / 'proof.txt').write_bytes(b'proof')
    entered = asyncio.Event()
    original = EvidenceSource.__init__
    descriptors = []

    def binding(self, *args):
        original(self, *args)
        descriptors.extend(self.fds)
        assert self.resource_fd is not None
        descriptors.append(self.resource_fd)

    async def gate(*args):
        entered.set()
        await asyncio.Future()

    monkeypatch.setattr(EvidenceSource, '__init__', binding)
    monkeypatch.setattr('src.tools.workflow.workflow_tool.gate_sensitive_path', gate)
    pending = asyncio.create_task(tool.run({'action': 'record_evidence', 'candidate_id': cid,
                                           'evidence_path': 'proof.txt'}, None, AlwaysAllow()))
    await entered.wait()
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert not tool.state.evidence and not tool.state.mutation_lock.locked()
