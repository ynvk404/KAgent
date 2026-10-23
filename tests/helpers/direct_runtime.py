"""Offline direct-process and native discovery fixtures; no worker or scanner binaries."""
from types import SimpleNamespace
from pathlib import Path
import pytest
from src.engagement.state import EngagementState
from src.permission.runtime.execution import ExecutionPolicy
from src.permission.permission import Decision, YoloPrompter
from src.tools.common.registry import Registry
from src.tools.execution.shell import ShellTool
from src.tools.execution.file import FileReadTool
from src.tools.discovery.service import ServiceDiscoveryTool
from src.workflow.state import WorkflowObjective, WorkflowMode
from tests.helpers.burp_selection import make_runtime
from tests.helpers.workflow import record_completed_phase

class Operator:
    def __init__(self): self.calls = 0
    async def ask(self, request, signal=None):
        self.calls += 1
        return Decision.DENY

@pytest.fixture
async def direct_runtime(tmp_path):
    root = tmp_path / 'lab'
    (root / 'artifacts/worker').mkdir(parents=True)
    outside = tmp_path / 'outside.txt'
    outside.write_text('fixture')
    policy = ExecutionPolicy(EngagementState(), root)
    operator = Operator()
    p = YoloPrompter(operator, True)
    p.bind_execution_policy(policy)
    registry = Registry()
    registry.register(ShellTool())
    return registry, p, policy, operator, root, outside

def agent_runtime(tmp_path, origin, model, *, mode: WorkflowMode = 'whole_target', enumeration=False):
    rt = make_runtime(tmp_path / 'project', client=model, origin=origin, session_id='native-fixture')
    rt.agent.auto_compact_threshold = 100000
    rt.agent.prompt_profile = 'compact'
    rt.agent.max_steps = 30
    rt.workflow.objective = WorkflowObjective('native-objective', mode, origin)
    rt.registry.register(FileReadTool())
    rt.registry.register(ShellTool())
    if enumeration:
        from src.skills.artifacts import completion_artifact_path
        sk = rt.skills.get('recon')
        ref = completion_artifact_path(sk.completion_artifact, origin)
        path = tmp_path / 'project' / ref
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('Offline recon fixture')
        record_completed_phase(rt.workflow, 'recon', objective_id='native-objective', target_origin=origin, artifact_ref=ref)
        rt.workflow.completed_skills.add('recon')
        rt.workflow.completed_artifacts['recon'] = ref
        rt.workflow.current_phase = 'enumeration'
    # Preserve the consumer fixtures' existing names without scanner setup.
    rt.root, rt.state = rt.policy.root, rt.engagement
    rt.workflow = rt.workflow_tool
    return rt
