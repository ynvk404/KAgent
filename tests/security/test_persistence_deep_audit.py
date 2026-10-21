"""Additional read-only audit observations; never install a production patch.

PASS here means the stated observation holds, including unsafe outcomes.
All filesystem effects are synthetic and contained in fresh /tmp directories.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
from contextlib import contextmanager
from src.workflow.evidence.source import EvidenceSource

import pytest

from src.engagement.state import EngagementState
from src.permission.permission import AlwaysAllow, Decision, YoloPrompter
from src.permission.runtime.execution import ExecutionPolicy, ExecutionBlocked
from src.tools.common.registry import Registry
from src.tools.execution.file import FileWriteTool
from src.workflow.evidence.artifacts import EvidenceArtifact, MAX_EVIDENCE_BYTES
from tests.security.test_evidence_reads import workflow
from tests.security.test_persistence_handoff_audit import offline, scratch, observed


def test_active_dispatch_expiry_is_not_running_expiry(scratch):
    now = [0.0]
    policy = ExecutionPolicy(EngagementState(), scratch, clock=lambda: now[0])
    tool = FileWriteTool()
    args = {"path": str(scratch / "out"), "content": "fixture"}
    receipt = policy.prepare(tool, args)
    token = policy.start(receipt, tool, args, None)
    try:
        now[0] = receipt.expires + 1
        policy.revalidate_active(tool, args, None)
        assert policy.nested_allowed()
        policy.revoke(tool.name())
        with pytest.raises(ExecutionBlocked):
            policy.revalidate_active(tool, args, None)
    finally:
        policy.stop(token)
    observed("active-TTL-versus-revoke", "PASS", "PRODUCTION")


@pytest.mark.parametrize("cancel_kind", ["signal", "task"])
async def test_nested_sensitive_cancellation_has_no_write_or_active_leak(scratch, cancel_kind):
    path = scratch / ".env"
    path.write_text("synthetic original")
    entered, release, signal = asyncio.Event(), asyncio.Event(), asyncio.Event()

    class Operator:
        async def ask(self, request, signal=None):
            if request.tool == "file":
                entered.set()
                await release.wait()
            return Decision.ALLOW_ONCE

    policy = ExecutionPolicy(EngagementState(), scratch)
    prompter = YoloPrompter(Operator())
    prompter.bind_execution_policy(policy)
    registry = Registry()
    registry.register(FileWriteTool())
    task = asyncio.create_task(registry.execute(
        "file_write", {"path": str(path), "content": "changed"}, signal, prompter,
    ))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        assert policy.active == 1
        if cancel_kind == "task":
            task.cancel()
        else:
            signal.set()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert path.read_text() == "synthetic original"
        assert policy.active == 0 and not policy._active_receipts
        assert not policy._receipts and not policy._pending
        observed("nested-cancel-" + cancel_kind, "PASS", "PRODUCTION")
    finally:
        release.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_source_swap_reaches_workflow_metadata_with_real_policy(scratch, monkeypatch):
    lab = scratch / "lab"
    lab.mkdir()
    source, outside = lab / "proof.txt", scratch / "outside"
    source.write_text("synthetic inside")
    outside.write_text("synthetic outside")
    tool, cid = workflow(lab)
    policy = ExecutionPolicy(EngagementState(), lab)
    prompter = YoloPrompter(AlwaysAllow(), True)
    prompter.bind_execution_policy(policy)
    registry = Registry()
    registry.register(tool)
    original = EvidenceSource.open

    @contextmanager
    def read(binding):
        path = binding.path
        if path == source and not source.is_symlink():
            source.unlink()
            source.symlink_to(outside)
        with original(binding) as handle:
            yield handle

    monkeypatch.setattr(EvidenceSource, "open", read)
    result = await registry.execute("workflow", {
        "action": "record_evidence", "candidate_id": cid, "evidence_path": source.name,
    }, None, prompter)
    assert str(result).startswith("error:")
    assert not tool.state.evidence and not list(lab.rglob("*.proof"))
    assert not policy.active and not tool.state.mutation_lock.locked()
    observed("source-swap-workflow-adoption", "PASS", "PRODUCTION")

def test_capture_postread_growth_is_bounded_and_rejected(scratch, monkeypatch):
    source = scratch / "proof.txt"
    source.write_bytes(b"small")
    replacement = b"x" * (MAX_EVIDENCE_BYTES + 1)
    from tests.security.test_evidence_correctness import instrument_source
    reads = instrument_source(monkeypatch, source, before_read=lambda: source.write_bytes(replacement))
    with pytest.raises(ValueError, match="at most 2 MB|changed during capture"):
        EvidenceArtifact.capture("candidate", source.name, scratch)
    assert reads.received == MAX_EVIDENCE_BYTES + 1
    assert reads[0] == MAX_EVIDENCE_BYTES + 1
    observed("capture-growth-size-bound", "PASS", "PRODUCTION_ACCEPTANCE")


def test_descriptor_binding_does_not_freeze_same_inode_bytes(scratch):
    source = scratch / "proof.txt"
    source.write_bytes(b"AAAABBBB")
    fd = os.open(source, os.O_RDONLY)
    try:
        identity = os.fstat(fd)
        first = os.read(fd, 4)
        source.write_bytes(b"CCCCDDDD")
        second = os.read(fd, 4)
        after = os.fstat(fd)
        assert (identity.st_dev, identity.st_ino) == (after.st_dev, after.st_ino)
        assert first + second == b"AAAADDDD"
    finally:
        os.close(fd)
    observed("descriptor-is-not-content-snapshot", "FAIL", "DESIGN_ONLY")


async def test_same_destination_prepared_receipt_is_rejected_after_first_write(scratch):
    policy = ExecutionPolicy(EngagementState(), scratch)
    tool = FileWriteTool()
    prompter = YoloPrompter(AlwaysAllow(), True)
    prompter.bind_execution_policy(policy)
    path = scratch / "out"
    first = {"path": str(path), "content": "first"}
    second = {"path": str(path), "content": "second"}
    r1, r2 = policy.prepare(tool, first), policy.prepare(tool, second)
    token = policy.start(r1, tool, first, None)
    try:
        await tool.run(first, None, prompter)
    finally:
        policy.stop(token)
    with pytest.raises(ExecutionBlocked, match="arguments-changed"):
        policy.start(r2, tool, second, None)
    policy.finish_review(r2)
    assert path.read_text() == "first" and policy.active == 0
    observed("same-destination-stale-prepared-receipt", "PASS", "PRODUCTION")
