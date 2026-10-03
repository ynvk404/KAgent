import json
from pathlib import Path

import pytest

from src.engagement.state import EngagementState
from src.permission.runtime.execution import ExecutionBlocked, default_execution_policy
from src.permission.permission import Decision, YoloPrompter
from src.permission.permission import UserControlledRefusal
from src.tools.execution.file import FileReadTool
from src.tools.common.registry import Registry
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.state import Candidate, WorkflowState


class Operator:
    def __init__(self):
        self.calls = 0
        self.decision = Decision.ALLOW_ONCE

    async def ask(self, request, signal=None):
        self.calls += 1
        return self.decision


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["proof.txt", ".env"])
@pytest.mark.parametrize("yolo", [True, False])
async def test_cli_protected_evidence_round_trip(tmp_path, source, yolo):
    root = tmp_path
    # Exact protected resources selected by main(), not the older 'control' fixture.
    policy = default_execution_policy(EngagementState(), root)
    operator = Operator()
    p = YoloPrompter(operator, yolo)
    p.bind_execution_policy(policy)
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(candidate_class="xxe", target="http://lab.test:3000", endpoint="/xml"))
    registry = Registry()
    registry.register(WorkflowTool(state, evidence_root=root))
    registry.register(FileReadTool())
    (root / source).write_text("FAKE_EVIDENCE fixture")
    evidence = json.loads(await registry.execute("workflow", {"action": "record_evidence", "candidate_id": candidate.id,
        "evidence_path": source}, None, p))["evidence"]
    result = json.loads(await registry.execute("workflow", {"action": "record_result", "candidate_id": candidate.id,
        "skill_name": "xxe", "outcome": "insufficient-evidence", "evidence_refs": [evidence["id"]]}, None, p))
    assert result["result"]["evidence_refs"] == [evidence["id"]]
    if yolo:
        assert operator.calls == 0
    with pytest.raises(ExecutionBlocked, match="protected"):
        await registry.execute("file_read", {"path": str(root / evidence["path"])}, None, p)
    snapshot = root / evidence["path"]
    snapshot.chmod(0o600)
    snapshot.write_text("tampered fake proof")
    changed = await registry.execute("workflow", {"action": "record_result", "candidate_id": candidate.id,
        "skill_name": "xxe", "outcome": "insufficient-evidence", "evidence_refs": [evidence["id"]]}, None, p)
    assert "changed or is unavailable" in changed


@pytest.mark.asyncio
async def test_cli_sensitive_denial_before_capture_and_after_resume(tmp_path):
    root = tmp_path
    policy = default_execution_policy(EngagementState(), root)
    operator = Operator()
    operator.decision = Decision.DENY
    p = YoloPrompter(operator, False)
    p.bind_execution_policy(policy)
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(candidate_class='xxe', target='http://lab.test:3000', endpoint='/xml'))
    tool = WorkflowTool(state, evidence_root=root)
    registry = Registry()
    registry.register(tool)
    (root/'.env').write_text('FAKE_SECRET_ONLY')
    args = {'action':'record_evidence','candidate_id':candidate.id,'evidence_path':'.env'}
    with pytest.raises(UserControlledRefusal):
        await registry.execute('workflow', args, None, p)
    assert not state.evidence and not (root/'.kagent/evidence').exists()
    policy.retry()
    p.set_yolo(True)
    ev = json.loads(await registry.execute('workflow', args, None, p))['evidence']
    restored_state = WorkflowState.from_dict(state.to_dict())
    assert restored_state is not None
    new_policy = default_execution_policy(EngagementState(), root)
    new_p = YoloPrompter(operator, False)
    new_p.bind_execution_policy(new_policy)
    new_registry = Registry()
    new_registry.register(WorkflowTool(restored_state, evidence_root=root))
    with pytest.raises(UserControlledRefusal):
        await new_registry.execute('workflow', {'action':'record_result','candidate_id':candidate.id,
            'skill_name':'xxe','outcome':'insufficient-evidence','evidence_refs':[ev['id']]}, None, new_p)
    assert restored_state.latest_result(candidate.id) is None
    new_p.set_yolo(True)
    new_policy.retry()
    new_policy.revoke('workflow')
    with pytest.raises(UserControlledRefusal):
        await new_registry.execute('workflow', {'action':'record_result','candidate_id':candidate.id,
            'skill_name':'xxe','outcome':'insufficient-evidence','evidence_refs':[ev['id']]}, None, new_p)
