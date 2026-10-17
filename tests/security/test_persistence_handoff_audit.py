"""Audit probes only. Green tests reproduce observations, including defects.

PRODUCTION = current code; DESIGN_ONLY = test-local offload proposal, never
installed in src. All data lives under /tmp; network use is fail-closed.
"""
import asyncio
from contextlib import contextmanager
from dataclasses import fields
import hashlib
import json
import os
from pathlib import Path
from contextlib import contextmanager
from src.workflow.evidence_source import EvidenceSource
import socket
import tempfile
import threading

import pytest

from src.engagement.state import EngagementState
from src.findings import store as findings
from src.permission.permission import AlwaysAllow, YoloPrompter
from src.permission.runtime.execution import ExecutionBlocked, ExecutionPolicy
from src.session.store import _joined_thread
from src.tools.execution.file import FileWriteTool
from src.workflow.evidence import EvidenceArtifact
from tests.data.test_findings_store import make_finding
from tests.security.test_evidence_reads import workflow
from tests.tools.test_finding import _tool, _valid_args


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    violations = []
    def deny(*args, **kwargs):
        violations.append(True)
        raise AssertionError("audit forbids network")
    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    yield
    assert not violations, "swallowed network violation"


@pytest.fixture
def scratch():
    with tempfile.TemporaryDirectory(prefix="kagent-handoff-audit-", dir="/tmp") as directory:
        yield Path(directory)


def observed(probe, verdict, category):
    print("HANDOFF_AUDIT " + json.dumps({"probe": probe, "verdict": verdict, "category": category}))


@contextmanager
def active_file(root, args, signal=None):
    policy = ExecutionPolicy(EngagementState(), root)
    prompter = YoloPrompter(AlwaysAllow(), True)
    prompter.bind_execution_policy(policy)
    tool = FileWriteTool()
    token = policy.start(policy.prepare(tool, args, signal=signal), tool, args, signal)
    try:
        yield policy, tool, prompter
    finally:
        policy.stop(token)


async def finish(task, release):
    release.set()
    await asyncio.gather(task, return_exceptions=True)


def test_c2_revocation_before_start(scratch):
    policy = ExecutionPolicy(EngagementState(), scratch)
    tool = FileWriteTool()
    args = {"path": str(scratch / "out"), "content": "fixture"}
    receipt = policy.prepare(tool, args)
    prior = policy.stamp()
    policy.revoke("file_write")
    assert policy.stamp() != prior
    with pytest.raises(ExecutionBlocked):
        policy.start(receipt, tool, args, None)
    assert not (scratch / "out").exists()
    observed("C2-before-start-revoke", "PASS", "PRODUCTION")


@pytest.mark.parametrize("change", ["revoke", "path"])
async def test_c2_current_second_guard_rejects_changed_authority_or_resource(scratch, monkeypatch, change):
    lab = scratch / "lab"
    lab.mkdir()
    external = scratch / "outside"
    external.write_text("outside")
    destination = lab / "out"
    args = {"path": str(destination), "content": "fixture"}
    with active_file(lab, args) as (policy, tool, prompter):
        original = Path.mkdir
        def mkdir(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path == lab:
                if change == "revoke":
                    policy.revoke("file_write")
                else:
                    destination.symlink_to(external)
            return result
        monkeypatch.setattr(Path, "mkdir", mkdir)
        with pytest.raises(ExecutionBlocked):
            await tool.run(args, None, prompter)
    assert external.read_text() == "outside"
    assert not destination.exists() or destination.is_symlink()
    observed("C2-current-second-guard-" + change, "PASS", "PRODUCTION")


@pytest.mark.parametrize("change", ["revoke", "revision", "path", "cancel_signal"])
async def test_c2_naive_worker_handoff_is_unsafe(scratch, change):
    lab = scratch / "lab"
    lab.mkdir()
    external = scratch / "outside"
    external.write_text("outside")
    destination = lab / "out"
    args = {"path": str(destination), "content": "fixture"}
    signal = asyncio.Event()
    entered, release = threading.Event(), threading.Event()
    # Immutable worker payload. No policy is passed into the worker.
    path, content = str(destination), "fixture"
    def proposed_writer():
        entered.set()
        assert release.wait(5)
        Path(path).write_text(content)
    with active_file(lab, args, signal) as (policy, tool, _):
        policy.revalidate_active(tool, args, signal)
        task = asyncio.create_task(_joined_thread(proposed_writer))
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            if change == "revoke":
                policy.revoke("file_write")
            elif change == "revision":
                policy.retry()  # real API increments revision, invalidating authority
            elif change == "path":
                destination.symlink_to(external)
            else:
                signal.set()
            with pytest.raises((ExecutionBlocked, asyncio.CancelledError)):
                policy.revalidate_active(tool, args, signal)
            release.set()
            await task
            assert destination.read_text() == "fixture"
            if change == "path":
                assert external.read_text() == "fixture"
            observed("C2-naive-" + change, "FAIL", "DESIGN_ONLY")
        finally:
            await finish(task, release)


async def test_c2_revocation_after_mutation_is_not_rollback(scratch, monkeypatch):
    path = scratch / "out"
    args = {"path": str(path), "content": "fixture"}
    with active_file(scratch, args) as (policy, tool, prompter):
        original = Path.write_text
        def write(destination, *args, **kwargs):
            result = original(destination, *args, **kwargs)
            policy.revoke("file_write")
            return result
        monkeypatch.setattr(Path, "write_text", write)
        output = await tool.run(args, None, prompter)
        assert not policy.nested_allowed()
        assert "wrote" in output and path.read_text() == "fixture"
    observed("C2-revoke-after-write", "INCONCLUSIVE_SEMANTICS", "PRODUCTION")


def test_c3_source_can_change_after_successful_snapshot(scratch):
    source = scratch / "proof.txt"
    source.write_text("first proof")
    artifact = EvidenceArtifact.capture_immutable_snapshot("candidate", source.name, scratch)
    source.write_text("second proof")
    assert artifact.is_resolvable(scratch)
    assert (scratch / artifact.path).read_text() == "first proof"
    assert artifact.source_path == str(source)
    observed("C3-source-after-snapshot", "PASS", "PRODUCTION")


def test_c3_path_swap_after_scope_check_reads_outside_project(scratch, monkeypatch):
    lab = scratch / "lab"
    lab.mkdir()
    source = lab / "proof.txt"
    source.write_text("original proof")
    outside = scratch / "outside"
    outside.write_text("outside synthetic proof")
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
    with pytest.raises((OSError, ValueError)):
        EvidenceArtifact.capture_immutable_snapshot("candidate", source.name, lab)
    assert not list(lab.rglob("*.proof"))
    observed("C3-source-path-swap", "PASS", "PRODUCTION")

def test_c3_postwrite_verification_rejects_content_address_mismatch(scratch, monkeypatch):
    source = scratch / "proof.txt"
    source.write_text("original proof")
    original = EvidenceSource.open
    @contextmanager
    def read(binding):
        path = binding.path
        args = ("rb",)
        if path.suffix == ".proof" and args and args[0] == "rb":
            path.chmod(0o600)
            path.write_text("changed proof")
        with original(binding) as handle:
            yield handle
    monkeypatch.setattr(EvidenceSource, "open", read)
    with pytest.raises(ValueError, match="integrity|changed"):
        EvidenceArtifact.capture_immutable_snapshot("candidate", source.name, scratch)
    observed("C3-content-address-mismatch", "PASS", "PRODUCTION_ACCEPTANCE")


def test_c3_write_failure_leaves_no_published_proof_and_retry_recovers(scratch, monkeypatch):
    source = scratch / "proof.txt"
    source.write_text("complete proof")
    original = os.fdopen
    class Broken:
        def __init__(self, *args, **kwargs):
            self.handle = original(*args, **kwargs)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.handle.close()
        def write(self, data):
            self.handle.write(data[:3])
            self.handle.flush()
            raise OSError("injected evidence write failure")
    with monkeypatch.context() as patch:
        patch.setattr(os, "fdopen", Broken)
        with pytest.raises(OSError):
            EvidenceArtifact.capture_immutable_snapshot("candidate", source.name, scratch)
    proofs = list((scratch / ".kagent/evidence").rglob("*.proof"))
    assert not proofs and not list(scratch.rglob("*.proof-tmp"))
    artifact = EvidenceArtifact.capture_immutable_snapshot("candidate", source.name, scratch)
    assert artifact.is_resolvable(scratch)
    assert (scratch / artifact.path).read_bytes() == b"complete proof"
    observed("C3-partial-proof-retry", "PASS", "PRODUCTION")


async def test_c3_concurrent_same_hash_writers_publish_complete_proof(scratch, monkeypatch):
    source = scratch / "proof.txt"
    source.write_text("complete proof")
    entered, release = threading.Event(), threading.Event()
    original = os.fdopen
    class Held:
        def __init__(self, *args, **kwargs):
            self.handle = original(*args, **kwargs)
            self.first = not entered.is_set()
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.handle.close()
        def __getattr__(self, name):
            return getattr(self.handle, name)
        def write(self, data):
            if self.first:
                entered.set()
                assert release.wait(5)
            return self.handle.write(data)
    monkeypatch.setattr(os, "fdopen", Held)
    # Test-local offload exposes a new concurrent window; production WorkflowTool
    # serializes one state's record_evidence calls with mutation_lock.
    first = asyncio.create_task(_joined_thread(EvidenceArtifact.capture_immutable_snapshot, "candidate", source.name, scratch))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        other = await asyncio.to_thread(EvidenceArtifact.capture_immutable_snapshot, "candidate", source.name, scratch)
        release.set()
        artifact = await first
        assert artifact == other and artifact.is_resolvable(scratch)
        assert not list(scratch.rglob("*.proof-tmp"))
        observed("C3-naive-concurrent-publish", "PASS", "PRODUCTION")
    finally:
        await finish(first, release)


async def test_c3_workflow_metadata_is_not_committed_when_snapshot_fails(scratch, monkeypatch):
    tool, cid = workflow(scratch)
    (scratch / "proof.txt").write_text("fixture")
    def fail(*args, **kwargs):
        assert tool.state.mutation_lock.locked()
        raise OSError("injected snapshot failure")
    monkeypatch.setattr(EvidenceArtifact, "capture_immutable_snapshot", fail)
    output = await tool.run({"action": "record_evidence", "candidate_id": cid, "evidence_path": "proof.txt"}, None, AlwaysAllow())
    assert output.startswith("error:") and not tool.state.evidence
    assert not tool.state.mutation_lock.locked()
    observed("C3-metadata-after-worker-success", "PASS", "PRODUCTION")


@pytest.mark.parametrize("fails", [False, True])
async def test_c4_current_cancel_drain_retry_and_error_precedence(scratch, monkeypatch, fails):
    store = findings.Store(project_directory=scratch)
    entered, release = threading.Event(), threading.Event()
    original = store._write_once_for_candidate
    def writer(*args):
        entered.set()
        assert release.wait(5)
        if fails:
            raise OSError("injected writer error during cancel drain")
        return original(*args)
    monkeypatch.setattr(store, "_write_once_for_candidate", writer)
    first = asyncio.create_task(store.save(make_finding(title="original")))
    retry = None
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        first.cancel()
        await asyncio.sleep(0.01)
        first.cancel()
        other = findings.Store(project_directory=scratch)
        retry = asyncio.create_task(other.save(make_finding(title="retry")))
        await asyncio.sleep(0.03)
        assert not first.done() and not retry.done() and store._save_lock.locked()
        release.set()
        with pytest.raises(OSError if fails else asyncio.CancelledError):
            await first
        path = await retry
        assert len(list(store.dir.glob("*.md"))) == 1
        assert findings.read_report(Path(path)).title == ("retry" if fails else "original")
        observed("C4-cancel-worker-" + ("error" if fails else "success"), "ERROR_PRECEDENCE_GAP" if fails else "PASS", "PRODUCTION")
    finally:
        release.set()
        await asyncio.gather(first, *([retry] if retry else []), return_exceptions=True)


async def proposed_postread(store, finding):
    """Test-local C4 candidate: one existing worker wait covers write + read.

    Retain the current store's cancellation/error precedence. Return only a
    detached parsed record; mutate the caller's Finding on the controller.
    """
    candidate, slug, content = finding.candidate_id, finding.slug, findings.render(finding)
    def write_read():
        path = store._write_once_for_candidate(candidate, slug, content)
        return path, findings.read_report(Path(path))
    async with store._save_lock:
        pending = asyncio.create_task(asyncio.to_thread(write_read))
        try:
            path, snapshot = await asyncio.shield(pending)
        except asyncio.CancelledError:
            while not pending.done():
                try:
                    await asyncio.shield(pending)
                except asyncio.CancelledError:
                    continue
            pending.result()
            raise
        for item in fields(findings.Finding):
            setattr(finding, item.name, getattr(snapshot, item.name))
        return path


@pytest.mark.parametrize("cancel", [False, True])
async def test_c4_proposed_postread_preserves_revalidation_and_ownership(scratch, monkeypatch, cancel):
    tool, store = _tool(scratch)
    tool._export_summary = False
    state = tool.workflow
    assert state is not None
    cid = next(iter(state.candidates))
    entered, release = threading.Event(), threading.Event()
    original = findings.read_report
    def read(path):
        entered.set()
        assert release.wait(5)
        return original(path)
    monkeypatch.setattr(findings, "read_report", read)
    async def save(finding):
        return await proposed_postread(store, finding)
    monkeypatch.setattr(store, "save", save)
    task = asyncio.create_task(tool.run(_valid_args(tool), None, AlwaysAllow()))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        assert store._save_lock.locked() and not state.finding_is_persisted(cid)
        if cancel:
            task.cancel()
            await asyncio.sleep(0.01)
            task.cancel()
            await asyncio.sleep(0.02)
            assert not task.done()
        else:
            latest = state.latest_result(cid)
            assert latest is not None
            latest.notes = (latest.notes or "") + " changed during read"
        release.set()
        with pytest.raises(asyncio.CancelledError if cancel else ValueError):
            await task
        assert not state.finding_is_persisted(cid)
        assert len(list(store.dir.glob("*.md"))) == 1
        assert not store._save_lock.locked()
        observed("C4-proposed-read-" + ("cancel" if cancel else "stale-result"), "PASS", "DESIGN_ONLY")
    finally:
        await finish(task, release)


async def persisted_summary(root):
    tool, store = _tool(root)
    await tool.run(_valid_args(tool), None, AlwaysAllow())
    assert tool.workflow is not None
    cid = next(iter(tool.workflow.candidates))
    canonical = store.report_for_candidate(cid)
    summary = root / "artifacts/reports/findings" / canonical.name
    return tool, store, cid, canonical, summary


@pytest.mark.parametrize("phase", ["before_replace", "after_replace_fsync"])
async def test_c5_commit_failure_preserves_canonical_and_retry(scratch, monkeypatch, phase):
    tool, store, cid, canonical, summary = await persisted_summary(scratch)
    before = canonical.read_bytes()
    old_summary = b"old derivative\n" + summary.read_bytes()
    summary.write_bytes(old_summary)
    def fail(*args):
        raise OSError("injected summary commit failure")
    with monkeypatch.context() as patch:
        if phase == "before_replace":
            patch.setattr(os, "replace", fail)
        else:
            patch.setattr(findings, "_fsync_directory", fail)
        with pytest.raises(OSError):
            await tool.write_summary(cid)
    assert canonical.read_bytes() == before
    assert tool.workflow is not None and tool.workflow.finding_is_persisted(cid)
    assert (summary.read_bytes() == old_summary) == (phase == "before_replace")
    assert not list(summary.parent.glob(".finding-*.tmp"))
    await tool.write_summary(cid)
    assert summary.read_bytes() != old_summary and canonical.read_bytes() == before
    observed("C5-failure-" + phase, "PASS", "PRODUCTION")


@pytest.mark.parametrize("change", ["workflow", "canonical"])
async def test_c5_preparation_change_cannot_publish(scratch, monkeypatch, change):
    tool, store, cid, canonical, summary = await persisted_summary(scratch)
    before = summary.read_bytes()
    entered, release = threading.Event(), threading.Event()
    original = findings._prepare_summary
    def prepare(*args):
        entered.set()
        assert release.wait(5)
        return original(*args)
    monkeypatch.setattr(findings, "_prepare_summary", prepare)
    task = asyncio.create_task(tool.write_summary(cid))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        if change == "workflow":
            assert tool.workflow is not None
            tool.workflow.persisted_findings.clear()
        else:
            canonical.write_bytes(canonical.read_bytes() + b"\nChanged externally\n")
        release.set()
        with pytest.raises(ValueError):
            await task
        assert summary.read_bytes() == before
        assert not list(summary.parent.glob(".finding-*.tmp"))
        observed("C5-preparation-" + change, "PASS", "PRODUCTION")
    finally:
        await finish(task, release)


async def test_c5_concurrent_exports_preserve_shared_ownership(scratch, monkeypatch):
    tool, store, cid, canonical, summary = await persisted_summary(scratch)
    original = findings._prepare_summary
    entered, release = threading.Event(), threading.Event()
    calls = []
    def prepare(*args):
        calls.append(True)
        if len(calls) == 1:
            entered.set()
            assert release.wait(5)
        return original(*args)
    monkeypatch.setattr(findings, "_prepare_summary", prepare)
    first = asyncio.create_task(tool.write_summary(cid))
    second = None
    before = canonical.read_bytes()
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        second = asyncio.create_task(tool.write_summary(cid))
        await asyncio.sleep(0.03)
        assert not second.done() and len(calls) == 1
        release.set()
        assert await first == await second == str(summary)
        assert len(calls) == 2 and canonical.read_bytes() == before
        assert not list(summary.parent.glob(".finding-*.tmp"))
        observed("C5-concurrent-exports", "PASS", "PRODUCTION")
    finally:
        release.set()
        await asyncio.gather(first, *([second] if second else []), return_exceptions=True)


async def test_c5_naive_offloaded_commit_can_publish_stale_workflow(scratch, monkeypatch):
    tool, store, cid, canonical, summary = await persisted_summary(scratch)
    entered, release = threading.Event(), threading.Event()
    committed = []
    async def proposal(candidate, context, artifacts, *, guard):
        async with store._save_lock:
            finding = findings.read_report(canonical)
            temporary = await _joined_thread(findings._prepare_summary, scratch, summary, "proposed stale derivative")
            guard(finding)
            def commit():
                entered.set()
                assert release.wait(5)
                os.replace(temporary, summary)
                committed.append(True)
                findings._fsync_directory(summary.parent)
            task = asyncio.create_task(_joined_thread(commit))
            try:
                assert await asyncio.to_thread(entered.wait, 5)
                assert tool.workflow is not None
                tool.workflow.persisted_findings.clear()
                with pytest.raises(ValueError):
                    guard(finding)
                release.set()
                await task
            finally:
                await finish(task, release)
    # Local prototype obtains the actual closure used by write_summary.
    with monkeypatch.context() as patch:
        patch.setattr(store, "export_summary", proposal)
        await tool.write_summary(cid)
    assert committed and summary.read_text() == "proposed stale derivative"
    assert canonical.exists()
    observed("C5-naive-commit-stale-workflow", "FAIL", "DESIGN_ONLY")


async def test_c2_naive_old_writer_overwrites_new_completed_operation(scratch):
    destination = scratch / "out"
    old_args = {"path": str(destination), "content": "old"}
    new_args = {"path": str(destination), "content": "new"}
    entered, release = threading.Event(), threading.Event()
    def old_writer():
        entered.set()
        assert release.wait(5)
        destination.write_text("old")
    with active_file(scratch, old_args) as (policy, tool, prompter):
        policy.revalidate_active(tool, old_args, None)
        task = asyncio.create_task(_joined_thread(old_writer))
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            token = policy.start(policy.prepare(tool, new_args), tool, new_args, None)
            try:
                await tool.run(new_args, None, prompter)
            finally:
                policy.stop(token)
            assert destination.read_text() == "new"
            with pytest.raises(ExecutionBlocked):
                policy.revalidate_active(tool, old_args, None)
            release.set()
            await task
            assert destination.read_text() == "old"
            observed("C2-naive-old-after-new", "FAIL", "DESIGN_ONLY")
        finally:
            await finish(task, release)


async def test_c2_shield_drain_alone_does_not_skip_queued_cancelled_writer(scratch):
    from concurrent.futures import ThreadPoolExecutor
    entered, release = threading.Event(), threading.Event()
    destination = scratch / "out"
    args = {"path": str(destination), "content": "fixture"}
    executor = ThreadPoolExecutor(max_workers=1)
    loop = asyncio.get_running_loop()
    def occupy():
        entered.set()
        assert release.wait(5)
    blocker = loop.run_in_executor(executor, occupy)
    writer_started = threading.Event()
    def writer():
        writer_started.set()
        destination.write_text("fixture")
    async def proposal():
        pending = loop.run_in_executor(executor, writer)
        try:
            return await asyncio.shield(pending)
        except asyncio.CancelledError:
            await asyncio.shield(pending)
            raise
    with active_file(scratch, args) as (policy, tool, _):
        policy.revalidate_active(tool, args, None)
        task = asyncio.create_task(proposal())
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            await asyncio.sleep(0.02)
            task.cancel()
            await asyncio.sleep(0.02)
            assert not writer_started.is_set() and not task.done()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert writer_started.is_set() and destination.read_text() == "fixture"
            observed("C2-queued-cancel-drain-without-admission", "INCONCLUSIVE_SEMANTICS", "DESIGN_ONLY")
        finally:
            release.set()
            await asyncio.gather(task, blocker, return_exceptions=True)
            executor.shutdown(wait=True)


def test_c3_capture_rejects_size_and_hash_from_different_versions(scratch, monkeypatch):
    source = scratch / "proof.txt"
    source.write_bytes(b"old")
    from tests.security.test_evidence_correctness import instrument_source
    reads = instrument_source(monkeypatch, source, before_read=lambda: source.write_bytes(b"new longer proof"))
    with pytest.raises(ValueError, match="changed during capture"):
        EvidenceArtifact.capture("candidate", source.name, scratch)
    assert reads.opened == 1 and reads.received <= 2_000_001
    assert reads[0] == 2_000_001
    observed("C3-capture-inconsistent-size", "PASS", "PRODUCTION_ACCEPTANCE")


async def test_c3_proposed_cancelled_snapshot_drains_without_metadata_commit(scratch, monkeypatch):
    tool, cid = workflow(scratch)
    source = scratch / "proof.txt"
    source.write_text("fixture")
    entered, release = threading.Event(), threading.Event()
    original = os.fdopen
    class Held:
        def __init__(self, *args, **kwargs):
            self.handle = original(*args, **kwargs)
        def __getattr__(self, name):
            return getattr(self.handle, name)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.handle.close()
        def write(self, data):
            entered.set()
            assert release.wait(5)
            return self.handle.write(data)
    monkeypatch.setattr(os, "fdopen", Held)
    async def proposal():
        async with tool.state.mutation_lock:
            artifact = await _joined_thread(EvidenceArtifact.capture_immutable_snapshot, cid, source.name, scratch)
            tool.state.add_evidence(artifact)
    task = asyncio.create_task(proposal())
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        await asyncio.sleep(0.01)
        task.cancel()
        await asyncio.sleep(0.02)
        assert not task.done() and tool.state.mutation_lock.locked()
        assert not tool.state.evidence
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not tool.state.evidence and not tool.state.mutation_lock.locked()
        proofs = list((scratch / ".kagent/evidence").rglob("*.proof"))
        assert len(proofs) == 1 and proofs[0].read_bytes() == b"fixture"
        # A completed content-addressed file is reused; no duplicate on retry.
        artifact = EvidenceArtifact.capture_immutable_snapshot(cid, source.name, scratch)
        assert artifact.is_resolvable(scratch)
        observed("C3-proposed-cancel-drain-retry", "PASS_WITH_RETAINED_UNREGISTERED_PROOF", "DESIGN_ONLY")
    finally:
        await finish(task, release)


async def test_c4_current_writer_window_revalidates_result(scratch, monkeypatch):
    tool, store = _tool(scratch)
    tool._export_summary = False
    state = tool.workflow
    assert state is not None
    cid = next(iter(state.candidates))
    entered, release = threading.Event(), threading.Event()
    original = store._write_once_for_candidate
    def write(*args):
        entered.set()
        assert release.wait(5)
        return original(*args)
    monkeypatch.setattr(store, "_write_once_for_candidate", write)
    task = asyncio.create_task(tool.run(_valid_args(tool), None, AlwaysAllow()))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        latest = state.latest_result(cid)
        assert latest is not None
        latest.notes = "changed while canonical writer awaited"
        release.set()
        with pytest.raises(ValueError, match="changed during finalization"):
            await task
        assert not state.finding_is_persisted(cid)
        assert len(list(store.dir.glob("*.md"))) == 1
        observed("C4-current-stale-result", "PASS", "PRODUCTION")
    finally:
        await finish(task, release)


async def test_c3_naive_read_after_revocation_cannot_be_undone_by_final_guard(scratch):
    from src.tools.execution.file import gate_sensitive_path
    tool, cid = workflow(scratch)
    source = scratch / "proof.txt"
    source.write_text("fixture")
    args = {"action": "record_evidence", "candidate_id": cid, "evidence_path": source.name}
    policy = ExecutionPolicy(EngagementState(), scratch)
    prompter = YoloPrompter(AlwaysAllow(), True)
    prompter.bind_execution_policy(policy)
    token = policy.start(policy.prepare(tool, args), tool, args, None)
    entered, release = threading.Event(), threading.Event()
    def snapshot(candidate, path, root):
        entered.set()
        assert release.wait(5)
        return EvidenceArtifact.capture_immutable_snapshot(candidate, path, root, sensitive_read_approved=True)
    task = None
    try:
        real = await gate_sensitive_path(prompter, str(source), "read evidence source", None)
        policy.revalidate_active(tool, args, None)
        task = asyncio.create_task(_joined_thread(snapshot, cid, real, scratch))
        assert await asyncio.to_thread(entered.wait, 5)
        policy.revoke("workflow")
        release.set()
        artifact = await task
        with pytest.raises(ExecutionBlocked):
            policy.revalidate_active(tool, args, None)
        assert (scratch / artifact.path).read_text() == "fixture"
        assert not tool.state.evidence
        observed("C3-naive-read-after-revoke", "FAIL", "DESIGN_ONLY")
    finally:
        release.set()
        if task is not None:
            await finish(task, release)
        policy.stop(token)


async def test_c4_proposed_read_failure_keeps_canonical_retryable(scratch, monkeypatch):
    tool, store = _tool(scratch)
    tool._export_summary = False
    state = tool.workflow
    assert state is not None
    cid = next(iter(state.candidates))
    original = findings.read_report
    calls = []
    def read(path):
        calls.append(True)
        if len(calls) == 1:
            raise OSError("injected postread failure")
        return original(path)
    monkeypatch.setattr(findings, "read_report", read)
    async def save(finding):
        return await proposed_postread(store, finding)
    monkeypatch.setattr(store, "save", save)
    with pytest.raises(OSError, match="postread"):
        await tool.run(_valid_args(tool), None, AlwaysAllow())
    assert not state.finding_is_persisted(cid)
    assert len(list(store.dir.glob("*.md"))) == 1 and not store._save_lock.locked()
    await tool.run(_valid_args(tool), None, AlwaysAllow())
    assert state.finding_is_persisted(cid) and len(list(store.dir.glob("*.md"))) == 1
    observed("C4-proposed-read-error-retry", "PASS", "DESIGN_ONLY")


async def test_c5_cancel_waiting_for_lock_has_no_preparation_worker(scratch, monkeypatch):
    tool, store, cid, canonical, summary = await persisted_summary(scratch)
    before = summary.read_bytes()
    await store._save_lock.acquire()
    task = None
    with monkeypatch.context() as patch:
        def forbidden(*args):
            pytest.fail("queued cancelled export must not prepare")
        patch.setattr(findings, "_prepare_summary", forbidden)
        try:
            task = asyncio.create_task(tool.write_summary(cid))
            await asyncio.sleep(0.02)
            assert not task.done()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert summary.read_bytes() == before and canonical.exists()
            assert not list(summary.parent.glob(".finding-*.tmp"))
        finally:
            store._save_lock.release()
            if task is not None:
                await asyncio.gather(task, return_exceptions=True)
    await tool.write_summary(cid)
    observed("C5-cancel-queued-before-worker", "PASS", "PRODUCTION")


async def test_c5_proposed_postcommit_fsync_drain_keeps_store_ownership(scratch, monkeypatch):
    tool, store, cid, canonical, summary = await persisted_summary(scratch)
    before = canonical.read_bytes(), summary.read_bytes()
    entered, release = threading.Event(), threading.Event()
    original = findings._fsync_directory
    def fsync(directory):
        entered.set()
        assert release.wait(5)
        return original(directory)
    monkeypatch.setattr(findings, "_fsync_directory", fsync)
    async def proposal():
        # Existing publication is already visible. This probe isolates only the
        # postcommit durability phase, not offloaded guard/replace semantics.
        async with store._save_lock:
            await _joined_thread(findings._fsync_directory, summary.parent)
    first = asyncio.create_task(proposal())
    second = None
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        first.cancel()
        await asyncio.sleep(0.01)
        first.cancel()
        other = findings.Store(directory=store.dir, project_directory=scratch)
        second = asyncio.create_task(other.save(findings.read_report(canonical)))
        await asyncio.sleep(0.03)
        assert not first.done() and not second.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await first
        await second
        assert (canonical.read_bytes(), summary.read_bytes()) == before
        observed("C5-proposed-postcommit-fsync-drain", "PASS", "DESIGN_ONLY")
    finally:
        release.set()
        await asyncio.gather(first, *([second] if second else []), return_exceptions=True)


async def test_c2_current_path_swap_after_last_guard_redirects_write(scratch, monkeypatch):
    lab = scratch / "lab"
    lab.mkdir()
    external = scratch / "outside"
    external.write_text("outside")
    destination = lab / "out"
    args = {"path": str(destination), "content": "fixture"}
    original = Path.write_text
    def write(path, *args, **kwargs):
        if path == destination:
            destination.symlink_to(external)
        return original(path, *args, **kwargs)
    with active_file(lab, args) as (policy, tool, prompter):
        monkeypatch.setattr(Path, "write_text", write)
        await tool.run(args, None, prompter)
        assert external.read_text() == "fixture"
        with pytest.raises(ExecutionBlocked):
            policy.revalidate_active(tool, args, None)
    observed("C2-current-final-check-path-swap", "FAIL", "PRODUCTION")


async def test_c4_proposed_postread_passes_unchanged_mounted_oracle(scratch, monkeypatch):
    from src.ui.core.app import KAgent
    from tests.ui.test_persistence_responsiveness import assert_responsive, measure
    # Same startup suppression as the original oracle. Rendering, timers and
    # actual Textual Escape handling remain unchanged. Only the test-local
    # candidate replaces save; no source or existing oracle is edited.
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    monkeypatch.setattr(findings.Store, "save", proposed_postread)
    result = await measure("finding_post_read", False, scratch, monkeypatch)
    assert result.io_on_ui_thread is False
    assert_responsive(result)
    observed("C4-proposed-read-mounted-oracle", "PASS", "DESIGN_ONLY")
