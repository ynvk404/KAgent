"""Acceptance tests for captured-value correctness, separate from B1/B3 blockers."""
import hashlib
import json
import os
from pathlib import Path
from contextlib import contextmanager
from src.workflow.evidence.source import EvidenceSource

import pytest

from src.permission.permission import AlwaysDeny, UserControlledRefusal
from src.workflow.evidence.artifacts import EvidenceArtifact, MAX_EVIDENCE_BYTES
from tests.security.test_evidence_reads import workflow
from tests.security.test_persistence_handoff_audit import offline  # noqa: F401


class ReadLog(list):
    opened = 0
    received = 0


def instrument_source(monkeypatch, source, *, before_read=None, short_reads=False):
    original = EvidenceSource.open
    requests = ReadLog()
    class Reader:
        def __init__(self, handle):
            self.handle = handle
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return self.handle.__exit__(*args)
        def fileno(self):
            return self.handle.fileno()
        def read(self, size=-1):
            requests.append(size)
            if before_read:
                before_read()
            raw = self.handle.read(min(size, 2) if short_reads and size >= 0 else size)
            requests.received += len(raw)
            return raw
    @contextmanager
    def open_file(binding):
        with original(binding) as handle:
            if binding.path == source:
                requests.opened += 1
                yield Reader(handle)
            else:
                yield handle
    monkeypatch.setattr(EvidenceSource, "open", open_file)
    return requests


@pytest.mark.parametrize("snapshot", [False, True])
@pytest.mark.parametrize("size", [0, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_BYTES + 1])
def test_read_bound_and_configured_content_limit(tmp_path, monkeypatch, snapshot, size):
    source = tmp_path / "proof.txt"
    source.write_bytes(b"x" * size)
    reads = instrument_source(monkeypatch, source)
    capture = EvidenceArtifact.capture_immutable_snapshot if snapshot else EvidenceArtifact.capture
    if size == MAX_EVIDENCE_BYTES:
        artifact = capture("candidate", source.name, tmp_path)
        assert artifact.size == size
        assert artifact.sha256 == hashlib.sha256(b"x" * size).hexdigest()
    else:
        with pytest.raises(ValueError, match="nonempty|2 MB"):
            capture("candidate", source.name, tmp_path)
        assert not list(tmp_path.rglob("*.proof"))
    assert all(0 <= amount <= MAX_EVIDENCE_BYTES + 1 for amount in reads)
    assert reads.received <= MAX_EVIDENCE_BYTES + 1


@pytest.mark.parametrize("snapshot", [False, True])
@pytest.mark.parametrize("replacement", [b"new longer proof", b"", b"NEW", b"x" * (MAX_EVIDENCE_BYTES + 1)],
                         ids=["growth", "truncate", "same-inode", "over-limit"])
def test_growth_truncation_and_same_inode_mutation_reject_before_adoption(tmp_path, monkeypatch, snapshot, replacement):
    source = tmp_path / "proof.txt"
    source.write_bytes(b"old")
    inode = source.stat().st_ino
    reads = instrument_source(monkeypatch, source, before_read=lambda: source.write_bytes(replacement))
    capture = EvidenceArtifact.capture_immutable_snapshot if snapshot else EvidenceArtifact.capture
    with pytest.raises(ValueError, match="changed|nonempty|2 MB"):
        capture("candidate", source.name, tmp_path)
    assert source.stat().st_ino == inode
    assert reads and all(0 <= amount <= MAX_EVIDENCE_BYTES + 1 for amount in reads)
    assert reads.received <= MAX_EVIDENCE_BYTES + 1
    assert not list(tmp_path.rglob("*.proof"))


@pytest.mark.parametrize("snapshot", [False, True])
def test_read_once_and_metadata_from_exact_captured_value(tmp_path, monkeypatch, snapshot):
    source = tmp_path / "proof.txt"
    raw = b"Synthetic observed behavior"
    source.write_bytes(raw)
    reads = instrument_source(monkeypatch, source)
    capture = EvidenceArtifact.capture_immutable_snapshot if snapshot else EvidenceArtifact.capture
    artifact = capture("candidate", source.name, tmp_path)
    assert reads.opened == 1 and reads.received == len(raw)
    assert reads[0] == MAX_EVIDENCE_BYTES + 1
    assert artifact.size == len(raw) and artifact.sha256 == hashlib.sha256(raw).hexdigest()
    expected_id = hashlib.sha256(f"candidate\0{artifact.path}\0{artifact.sha256}".encode()).hexdigest()[:20]
    assert artifact.id == f"ev_{expected_id}"
    if snapshot:
        assert Path(artifact.path).stem == artifact.sha256
        assert (tmp_path / artifact.path).read_bytes() == raw


def test_short_reads_preserve_complete_value_within_total_budget(tmp_path, monkeypatch):
    source = tmp_path / "proof.txt"
    raw = b"synthetic proof"
    source.write_bytes(raw)
    reads = instrument_source(monkeypatch, source, short_reads=True)
    artifact = EvidenceArtifact.capture("candidate", source.name, tmp_path)
    assert reads.opened == 1 and reads.received == len(raw)
    assert all(0 < size <= MAX_EVIDENCE_BYTES + 1 for size in reads)
    assert artifact.size == len(raw) and artifact.sha256 == hashlib.sha256(raw).hexdigest()


def test_configured_read_budget_and_redaction_expansion_bound(tmp_path, monkeypatch):
    from src.workflow.evidence import artifacts as module
    source = tmp_path / "proof.txt"
    source.write_bytes(b"password=x")
    monkeypatch.setattr(module, "MAX_EVIDENCE_BYTES", 10)
    reads = instrument_source(monkeypatch, source)
    with pytest.raises(ValueError, match="redacted evidence"):
        EvidenceArtifact.capture_immutable_snapshot("candidate", source.name, tmp_path)
    assert reads[0] == 11 and reads.received == 10
    assert not list(tmp_path.rglob("*.proof"))


def test_snapshot_keeps_bounded_nonempty_source_with_unknown_stat_size(tmp_path, monkeypatch):
    # Legacy snapshot capture bounded actual bytes, not source stat size. Some
    # regular virtual files report zero size while yielding nonempty bytes.
    source = tmp_path / "proof.txt"
    raw = b"synthetic proof"
    source.write_bytes(raw)
    original = os.fstat
    def unknown_size(fd):
        value = original(fd)
        class UnknownSize:
            st_size = 0
            def __getattr__(self, name):
                return getattr(value, name)
        return UnknownSize()
    with monkeypatch.context() as patch:
        patch.setattr(os, "fstat", unknown_size)
        artifact = EvidenceArtifact.capture_immutable_snapshot("candidate", source.name, tmp_path)
    stored = (tmp_path / artifact.path).read_bytes()
    assert stored == raw and artifact.size == len(raw)
    assert artifact.sha256 == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("failure", ["read", "stat"])
def test_capture_io_failure_closes_source_and_does_not_publish(tmp_path, monkeypatch, failure):
    source = tmp_path / "proof.txt"
    source.write_bytes(b"synthetic proof")
    original_open, original_stat = os.open, os.fstat
    opened = []
    def opened_file(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        opened.append(fd)
        return fd
    monkeypatch.setattr(os, "open", opened_file)
    def fail(*_, **kw):
        raise OSError("synthetic capture failure")
    if failure == "stat":
        monkeypatch.setattr(os, "fstat", fail)
    else:
        instrument_source(monkeypatch, source, before_read=fail)
    with pytest.raises(OSError, match="synthetic capture failure"):
        EvidenceArtifact.capture_immutable_snapshot("candidate", source.name, tmp_path)
    assert opened
    for fd in opened:
        with pytest.raises(OSError):
            original_stat(fd)
    assert not list(tmp_path.rglob("*.proof"))


async def test_detected_source_mutation_has_no_workflow_adoption_and_retries(tmp_path, monkeypatch):
    from src.permission.permission import AlwaysAllow
    tool, cid = workflow(tmp_path)
    source = tmp_path / "proof.txt"
    source.write_bytes(b"old proof")
    with monkeypatch.context() as patch:
        reads = instrument_source(patch, source, before_read=lambda: source.write_bytes(b"new proof"))
        output = await tool.run({"action": "record_evidence", "candidate_id": cid,
                                 "evidence_path": source.name}, None, AlwaysAllow())
        assert output.startswith("error:") and "changed during capture" in output
        assert reads.received <= MAX_EVIDENCE_BYTES + 1
    assert not tool.state.evidence and not tool.state.mutation_lock.locked()
    assert not list(tmp_path.rglob("*.proof"))
    output = await tool.run({"action": "record_evidence", "candidate_id": cid,
                             "evidence_path": source.name}, None, AlwaysAllow())
    assert json.loads(output)["ok"] is True and len(tool.state.evidence) == 1


def test_snapshot_metadata_does_not_recapture_a_second_value(tmp_path, monkeypatch):
    source = tmp_path / "proof.txt"
    source.write_bytes(b"synthetic proof")
    def recapture(*_, **kw):
        pytest.fail("snapshot metadata must not be derived from another capture")
    monkeypatch.setattr(EvidenceArtifact, "capture", recapture)
    artifact = EvidenceArtifact.capture_immutable_snapshot("candidate", source.name, tmp_path)
    assert artifact.size == len(b"synthetic proof")


@pytest.mark.parametrize("raw", [b"UTF-8 proof: \xe2\x9c\x93\npassword=synthetic-secret", b"\xff\x00\x80binary-proof"])
def test_redaction_and_binary_fallback_unchanged(tmp_path, raw):
    from src.redaction.redact import apply_evidence
    source = tmp_path / "proof.txt"
    source.write_bytes(raw)
    artifact = EvidenceArtifact.capture_immutable_snapshot("candidate", source.name, tmp_path)
    try:
        expected = apply_evidence(raw.decode("utf-8")).encode("utf-8")
    except UnicodeDecodeError:
        expected = raw
    stored = (tmp_path / artifact.path).read_bytes()
    assert stored == expected
    assert artifact.sha256 == Path(artifact.path).stem == hashlib.sha256(expected).hexdigest()
    assert artifact.size == len(expected)
    if raw.startswith(b"UTF"):
        assert b"synthetic-secret" not in stored


async def test_permission_denial_precedes_actual_open(tmp_path, monkeypatch):
    tool, cid = workflow(tmp_path)
    source = tmp_path / ".env"
    source.write_text("synthetic secret")
    original = Path.open
    def denied(path, *args, **kwargs):
        if path == source:
            pytest.fail("source opened before permission")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", denied)
    with pytest.raises(UserControlledRefusal):
        await tool.run({"action": "record_evidence", "candidate_id": cid,
                        "evidence_path": source.name}, None, AlwaysDeny())
    assert not tool.state.evidence and not list(tmp_path.rglob("*.proof"))


def test_destination_change_is_conflict_not_a_new_snapshot_identity(tmp_path, monkeypatch):
    source = tmp_path / "proof.txt"
    source.write_bytes(b"synthetic proof")
    original = EvidenceSource.open
    @contextmanager
    def changed(binding):
        path = binding.path
        mode = "rb"
        if path.suffix == ".proof" and mode == "rb":
            path.chmod(0o600)
            path.write_bytes(b"different proof")
        with original(binding) as handle:
            yield handle
    monkeypatch.setattr(EvidenceSource, "open", changed)
    with pytest.raises(ValueError, match="integrity|collision|changed"):
        EvidenceArtifact.capture_immutable_snapshot("candidate", source.name, tmp_path)


@pytest.mark.parametrize("change", ["outside", "sensitive"])
def test_postwrite_read_preserves_existing_scope_and_sensitive_guards(tmp_path, monkeypatch, change):
    lab = tmp_path / "lab"
    lab.mkdir()
    source = lab / "proof.txt"
    source.write_bytes(b"synthetic proof")
    sensitive = lab / ".env"
    sensitive.write_bytes(b"synthetic proof")
    import src.workflow.evidence.publication as publication
    original = publication._rename_noreplace
    changed = False
    def publish(directory, temporary, destination):
        nonlocal changed
        result = original(directory, temporary, destination)
        path = next(lab.rglob(destination))
        if not changed:
            changed = True
            if change == "outside":
                parent = path.parent
                moved = tmp_path / "moved"
                parent.rename(moved)
                parent.symlink_to(moved, target_is_directory=True)
            else:
                path.unlink()
                path.symlink_to(sensitive)
        return result
    monkeypatch.setattr(publication, "_rename_noreplace", publish)
    if change == "outside":
        with pytest.raises(ValueError, match="inside the project|namespace changed"):
            EvidenceArtifact.capture_immutable_snapshot("candidate", source.name, lab)
    else:
        with pytest.raises(UserControlledRefusal):
            EvidenceArtifact.capture_immutable_snapshot("candidate", source.name, lab)
    assert changed


@pytest.mark.parametrize("conflict", [False, True])
def test_existing_proof_reuse_or_conflict_preserves_existing_bytes(tmp_path, conflict):
    source = tmp_path / "proof.txt"
    source.write_bytes(b"synthetic proof")
    first = EvidenceArtifact.capture_immutable_snapshot("candidate", source.name, tmp_path)
    destination = tmp_path / first.path
    if conflict:
        destination.chmod(0o600)
        destination.write_bytes(b"different proof")
    before = destination.read_bytes()
    if conflict:
        with pytest.raises(ValueError, match="collision|integrity"):
            EvidenceArtifact.capture_immutable_snapshot("candidate", source.name, tmp_path)
    else:
        assert EvidenceArtifact.capture_immutable_snapshot("candidate", source.name, tmp_path) == first
    assert destination.read_bytes() == before
