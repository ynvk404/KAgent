"""Observation/design counterexamples. PASS reproduces a blocker, not a fix.

No source-binding or publication proposal is installed in production here.
"""
import json
import os
from pathlib import Path

import pytest

from src.engagement.state import EngagementState
from src.permission.permission import AlwaysAllow
from src.permission.runtime.execution import ExecutionPolicy, ExecutionBlocked
from tests.security.test_evidence_reads import workflow
from tests.security.test_persistence_handoff_audit import offline  # noqa: F401

# Capture capability before pytest's containment fixture wraps os.open.
_ROOTED_OPEN_AVAILABLE = (
    os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
)


@pytest.mark.parametrize("swap", ["leaf", "ancestor"])
async def test_unresolved_source_namespace_race_remains_real_policy_blocker(tmp_path, monkeypatch, swap):
    from src.permission.permission import YoloPrompter
    from src.tools.common.registry import Registry
    lab, outside_dir = tmp_path / "lab", tmp_path / "outside"
    lab.mkdir()
    outside_dir.mkdir()
    parent = lab / "parent"
    parent.mkdir()
    source = parent / "proof.txt"
    source.write_bytes(b"synthetic inside")
    outside = outside_dir / "proof.txt"
    outside.write_bytes(b"synthetic outside")
    tool, cid = workflow(lab)
    policy = ExecutionPolicy(EngagementState(), lab)
    prompter = YoloPrompter(AlwaysAllow(), True)
    prompter.bind_execution_policy(policy)
    registry = Registry()
    registry.register(tool)
    original = Path.open
    swapped = False
    def open_file(path, *args, **kwargs):
        nonlocal swapped
        mode = args[0] if args else kwargs.get("mode", "r")
        if path == source and mode == "rb" and not swapped:
            swapped = True
            if swap == "leaf":
                source.unlink()
                source.symlink_to(outside)
            else:
                parent.rename(lab / "retired")
                parent.symlink_to(outside_dir, target_is_directory=True)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", open_file)
    result = json.loads(await registry.execute("workflow", {
        "action": "record_evidence", "candidate_id": cid, "evidence_path": "parent/proof.txt",
    }, None, prompter))
    assert result["ok"] and swapped
    artifact = tool.state.evidence[result["evidence"]["id"]]
    assert (lab / artifact.path).read_bytes() == b"synthetic outside"
    assert artifact.source_path == str(source)
    assert not policy.active and not tool.state.mutation_lock.locked()


def test_design_rooted_descriptor_does_not_lease_namespace_membership(tmp_path):
    if not _ROOTED_OPEN_AVAILABLE:
        pytest.skip("design-only POSIX capability probe; no production fallback")
    lab, outside = tmp_path / "lab", tmp_path / "outside"
    lab.mkdir()
    outside.mkdir()
    parent = lab / "parent"
    parent.mkdir()
    (parent / "proof.txt").write_bytes(b"synthetic pinned inode")
    root_fd = os.open(lab, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    parent_fd = None
    try:
        parent_fd = os.open("parent", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        # A trusted-root ownership assertion would have to forbid this actor.
        parent.rename(outside / "moved")
        fd = os.open("proof.txt", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            assert os.read(fd, 64) == b"synthetic pinned inode"
            assert os.fstat(fd).st_ino == (outside / "moved/proof.txt").stat().st_ino
        finally:
            os.close(fd)
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
        os.close(root_fd)


def test_design_no_clobber_link_has_unresolved_crash_recovery_window(tmp_path):
    temporary, final = tmp_path / ".owned.tmp", tmp_path / "complete.proof"
    temporary.write_bytes(b"synthetic complete bytes")
    temporary.chmod(0o400)
    os.link(temporary, final)
    # Model termination after link, before unlink. Both names are complete, but
    # require_path/managed evidence rejects the two-link resource on resume.
    assert final.read_bytes() == b"synthetic complete bytes"
    assert final.stat().st_nlink == 2
    policy = ExecutionPolicy(EngagementState(), tmp_path)
    with pytest.raises(ExecutionBlocked, match="ambiguous-hardlink"):
        policy.require_path(final)
    with pytest.raises(FileExistsError):
        os.link(temporary, final)
    assert final.read_bytes() == b"synthetic complete bytes"
    # Without a declared recovery owner, deleting an abandoned-looking temp
    # could interfere with an active invocation. No recovery policy is selected.


def test_design_path_cleanup_can_delete_another_invocations_resource(tmp_path):
    temporary = tmp_path / ".owned.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, b"synthetic original")
        temporary.rename(tmp_path / "retired.tmp")
        temporary.write_bytes(b"synthetic competing invocation")
        assert os.fstat(fd).st_ino != temporary.stat().st_ino
        temporary.unlink()  # Rejected unconditional-path-cleanup design.
        assert not temporary.exists() and (tmp_path / "retired.tmp").is_file()
    finally:
        os.close(fd)
