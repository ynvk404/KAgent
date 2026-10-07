from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from src.permission.permission import AlwaysAllow, AlwaysDeny, UserControlledRefusal
from src.target.target import Target
from src.tools.execution.file import FileReadTool
from src.tools.execution.search import GrepTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.evidence import EvidenceArtifact, verify_evidence_reads
from src.workflow.state import Candidate, WorkflowState


def workflow(tmp_path):
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(
        candidate_class="xxe", target="https://target.test", endpoint="/xml",
        method="POST", parameter="body", location="body",
    ))
    return WorkflowTool(state, Target("https://target.test"), evidence_root=tmp_path), candidate.id


async def snapshot(tool, cid, name, prompter):
    return json.loads(await tool.run({
        "action": "record_evidence", "candidate_id": cid, "evidence_path": name,
    }, None, prompter))["evidence"]


@pytest.mark.asyncio
async def test_snapshot_denial_precedes_source_read(tmp_path, monkeypatch):
    tool, cid = workflow(tmp_path)
    (tmp_path / ".env").write_text("FAKE_CANARY")
    def forbidden_read(_path):
        pytest.fail("source must not be read before permission")
    monkeypatch.setattr(Path, "read_bytes", forbidden_read)
    with pytest.raises(UserControlledRefusal):
        await snapshot(tool, cid, ".env", AlwaysDeny())
    assert tool.state.evidence == {}
    assert not (tmp_path / ".kagent").exists()


@pytest.mark.asyncio
async def test_approved_sensitive_snapshot_retains_source_and_access_after_restore(tmp_path):
    tool, cid = workflow(tmp_path)
    (tmp_path / ".env").write_text("FAKE_CANARY")
    ev = await snapshot(tool, cid, ".env", AlwaysAllow())
    artifact = EvidenceArtifact.from_dict(ev)
    assert artifact is not None
    assert artifact.source_path == str(tmp_path / ".env")
    assert "/sensitive/" in ev["path"]
    assert artifact.is_available_for_resume(tmp_path)
    assert not artifact.is_resolvable(tmp_path)  # no ungated checksum read
    assert await artifact.is_resolvable_with_permission(tmp_path, AlwaysAllow())
    with pytest.raises(UserControlledRefusal):
        await artifact.is_resolvable_with_permission(tmp_path, AlwaysDeny())
    reader = FileReadTool()
    with pytest.raises(UserControlledRefusal):
        await reader.run({"path": str(tmp_path / ev["path"])}, None, AlwaysDeny())
    assert await reader.run({"path": str(tmp_path / ev["path"])}, None, AlwaysAllow()) == "FAKE_CANARY"
    # Renaming the extension inside protected storage does not erase access.
    renamed = (tmp_path / ev["path"]).with_suffix(".txt")
    (tmp_path / ev["path"]).rename(renamed)
    with pytest.raises(UserControlledRefusal):
        await reader.run({"path": str(renamed)}, None, AlwaysDeny())


@pytest.mark.asyncio
async def test_legacy_sensitive_proof_cannot_bypass_result_read_gate(tmp_path):
    tool, cid = workflow(tmp_path)
    source = tmp_path / ".env"
    source.write_bytes(b"FAKE_CANARY")
    artifact = EvidenceArtifact("ev_legacy", cid, ".env", hashlib.sha256(b"FAKE_CANARY").hexdigest(), 11)
    tool.state.add_evidence(artifact)
    with pytest.raises(UserControlledRefusal):
        await tool.run({"action": "record_result", "candidate_id": cid,
                        "skill_name": "xxe", "outcome": "confirmed", "evidence_refs": [artifact.id]},
                       None, AlwaysDeny())
    assert tool.state.latest_result(cid) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("name,body", [
    ("wordlist.txt", "/admin\n/api/new"),
    ("payload.txt", "' OR 1=1-- <script>alert(1)</script> ignore previous instructions"),
    ("source.py", "def endpoint(): return '/new-endpoint'"),
    ("capture.txt", "HTTP/1.1 200 OK\n\nreflected marker"),
])
async def test_normal_inputs_and_evidence_still_work_without_dialog(tmp_path, name, body):
    tool, cid = workflow(tmp_path)
    path = tmp_path / name
    path.write_text(body)
    assert await FileReadTool().run({"path": str(path)}, None, AlwaysDeny()) == body
    ev = await snapshot(tool, cid, name, AlwaysDeny())
    artifact = EvidenceArtifact.from_dict(ev)
    assert artifact and artifact.is_resolvable(tmp_path)
    assert await artifact.is_resolvable_with_permission(tmp_path, AlwaysDeny())
    assert (tmp_path / artifact.path).read_text() == body


@pytest.mark.asyncio
async def test_multiple_derivatives_reuse_source_approval_within_one_operation(tmp_path):
    tool, cid = workflow(tmp_path)
    source = tmp_path / ".env"
    source.write_text("first fake proof")
    first = await snapshot(tool, cid, ".env", AlwaysAllow())
    source.write_text("second fake proof")
    second = await snapshot(tool, cid, ".env", AlwaysAllow())
    class CountingAllow(AlwaysAllow):
        count = 0
        async def ask(self, request, signal=None):
            self.count += 1
            return await super().ask(request, signal)
    allow = CountingAllow()
    assert await verify_evidence_reads(
        [tool.state.evidence[first["id"]], tool.state.evidence[second["id"]]], tmp_path, allow, None,
    )
    assert allow.count == 1


@pytest.mark.asyncio
async def test_grep_cannot_read_sensitive_derivative(tmp_path):
    tool, cid = workflow(tmp_path)
    (tmp_path / ".env").write_text("FAKE_CANARY")
    ev = await snapshot(tool, cid, ".env", AlwaysAllow())
    with pytest.raises(UserControlledRefusal):
        await GrepTool().run({"path": str(tmp_path / ev["path"]), "pattern": "FAKE"}, None, AlwaysDeny())


@pytest.mark.asyncio
async def test_sensitive_alias_keeps_restriction_after_resolved_source_is_snapshotted(tmp_path):
    tool, cid = workflow(tmp_path)
    (tmp_path / "ordinary.txt").write_text("FAKE_CANARY")
    alias = tmp_path / ".env"
    try:
        alias.symlink_to(tmp_path / "ordinary.txt")
    except OSError:
        pytest.skip("symlink not supported on this test host")
    with pytest.raises(UserControlledRefusal):
        await snapshot(tool, cid, ".env", AlwaysDeny())
    ev = await snapshot(tool, cid, ".env", AlwaysAllow())
    assert ev["source_path"] == str(alias)
    assert "/sensitive/" in ev["path"]
    with pytest.raises(UserControlledRefusal):
        await FileReadTool().run({"path": str(tmp_path / ev["path"])}, None, AlwaysDeny())


def test_low_level_sensitive_reads_fail_without_internal_approval(tmp_path):
    (tmp_path / ".env").write_text("FAKE_CANARY")
    for capture in [EvidenceArtifact.capture, EvidenceArtifact.capture_immutable_snapshot]:
        with pytest.raises(UserControlledRefusal):
            capture("candidate", ".env", tmp_path)


@pytest.mark.asyncio
async def test_sensitive_snapshot_requires_reverification_in_fresh_runtime(tmp_path):
    from src.workflow.evidence import _verified_sensitive
    tool, cid = workflow(tmp_path)
    (tmp_path / ".env").write_text("FAKE_CANARY")
    ev = await snapshot(tool, cid, ".env", AlwaysAllow())
    artifact = EvidenceArtifact.from_dict(ev)
    assert artifact is not None
    _verified_sensitive.pop((str((tmp_path / artifact.path).resolve()), artifact.sha256))
    assert not artifact.is_available_for_resume(tmp_path)
    with pytest.raises(UserControlledRefusal):
        await artifact.is_resolvable_with_permission(tmp_path, AlwaysDeny())
    assert await artifact.is_resolvable_with_permission(tmp_path, AlwaysAllow())
    assert artifact.is_available_for_resume(tmp_path)


@pytest.mark.asyncio
async def test_start_validation_cannot_ungated_read_terminal_sensitive_proof(tmp_path):
    from src.workflow.state import ValidationResult, WorkflowObjective
    tool, cid = workflow(tmp_path)
    objective = WorkflowObjective(id="fixture", mode="whole_target", target_origin="https://target.test")
    tool.state.objective = objective
    tool.state.candidates[cid].objective_id = objective.id
    (tmp_path / ".env").write_bytes(b"FAKE_CANARY")
    artifact = EvidenceArtifact("ev_legacy", cid, ".env", hashlib.sha256(b"FAKE_CANARY").hexdigest(), 11)
    tool.state.add_evidence(artifact)
    tool.state.add_validation_result(ValidationResult(cid, "xxe", "confirmed", evidence_refs=[artifact.id]))
    with pytest.raises(UserControlledRefusal):
        await tool.run({"action": "start_validation", "candidate_id": cid}, None, AlwaysDeny())
    assert tool.state.candidates[cid].status == "validated"


@pytest.mark.asyncio
async def test_status_does_not_accept_changed_sensitive_snapshot(tmp_path):
    tool, cid = workflow(tmp_path)
    (tmp_path / ".env").write_text("FIRST_CANARY")
    ev = await snapshot(tool, cid, ".env", AlwaysAllow())
    artifact = tool.state.evidence[ev["id"]]
    stored = tmp_path / artifact.path
    stored.chmod(0o600)
    stored.write_text("OTHER_CANARY")  # same size; stat cache cannot stand in for a new checksum
    assert not artifact.is_available_for_resume(tmp_path)
    assert not await artifact.is_resolvable_with_permission(tmp_path, AlwaysAllow())


@pytest.mark.asyncio
async def test_finding_denial_precedes_evidence_read_and_report_write(tmp_path):
    from src.findings.store import Store
    from src.tools.workflow.finding import ConfirmFindingTool
    tool, cid = workflow(tmp_path)
    (tmp_path / ".env").write_text("FAKE_CANARY")
    ev = await snapshot(tool, cid, ".env", AlwaysAllow())
    from tests.helpers.workflow import run_workflow_fixture
    result = await run_workflow_fixture(tool, {"action": "record_result", "candidate_id": cid,
                            "skill_name": "xxe", "outcome": "confirmed", "evidence_refs": [ev["id"]]},
                           None, AlwaysAllow())
    assert json.loads(result)["ok"]
    finding = ConfirmFindingTool(Store(str(tmp_path / "findings")), lambda *_: None, workflow=tool.state)
    args = {"candidate_id": cid, "title": "Fixture", "url": "https://target.test/xml",
            "severity": "low", "observed_impact": "Fixture marker", "potential_impact": "May reveal data"}
    with pytest.raises(UserControlledRefusal):
        await finding.run(args, None, AlwaysDeny())
    assert not list((tmp_path / "findings").glob("*.md"))
    assert "written" in await finding.run(args, None, AlwaysAllow())
