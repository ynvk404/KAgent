"""Offline native Agent fixture; no optional executors or binary discovery."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from typing import cast
from src.agent.agent import Agent, AgentOptions
from src.engagement.state import EngagementState
from src.permission.permission import Decision, Prompter, YoloPrompter
from src.permission.runtime.execution import default_execution_policy
from src.target.target import Target
from src.tools.common.registry import Registry
from src.tools.execution.shell import ShellTool
from src.skills.registry import Registry as Skills
from src.skills.load_skill import LoadSkillTool
from src.tools.execution.file import FileReadTool
from src.tools.http.http_tool import HTTPTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.state import WorkflowObjective, WorkflowState, WorkflowMode
from src.session.store import Store
from tests.helpers.workflow import record_completed_phase

SKILLS = Path(__file__).resolve().parents[2] / 'skills'


def runtime(root, origin):
    root.mkdir(exist_ok=True)
    state = EngagementState()
    state.add_origin(origin)
    target = Target(origin)
    state.http_permissions.bind_target(lambda: target.revision)
    policy = default_execution_policy(state, root)
    operator = SimpleNamespace(ask=AsyncMock(return_value=Decision.ALLOW_ONCE))
    prompter = YoloPrompter(cast(Prompter, operator), False)
    prompter.bind_execution_policy(policy)
    registry = Registry()
    tool = ShellTool()
    registry.register(tool)
    return SimpleNamespace(root=root, state=state, target=target, policy=policy, operator=operator,
                           prompter=prompter, tool=tool, registry=registry)

def agent_runtime(tmp_path, origin, model, *, mode: WorkflowMode = 'whole_target', enumeration=False):
    rt = runtime(tmp_path / 'project', origin)
    skills = Skills()
    skills.load_dir(SKILLS)
    state = WorkflowState(objective=WorkflowObjective('scanner-objective', mode, origin))
    assert state.objective is not None
    rt.registry.register(LoadSkillTool(skills))
    http = HTTPTool(rt.target, rt.state)
    rt.registry.register(http)
    rt.registry.register(FileReadTool())
    workflow = WorkflowTool(state, rt.target, skills=skills, evidence_root=rt.root, http_tool=http)
    rt.registry.register(workflow)
    from src.permission.network.grants import HTTPLimits
    rt.state.http_permissions.activate(origin, HTTPLimits.session())
    if enumeration:
        from src.skills.artifacts import completion_artifact_path
        recon = skills.get('recon')
        assert recon is not None and recon.completion_artifact
        artifact = completion_artifact_path(recon.completion_artifact, origin)
        path = rt.root / artifact
        path.parent.mkdir(parents=True)
        path.write_text('Explicit synthetic recon prerequisite for scanner enumeration fixture.')
        # A fixture prerequisite, never reported as runtime recon acceptance.
        if mode == 'whole_target':
            record_completed_phase(state, 'recon', objective_id=state.objective.id,
                target_origin=origin, artifact_ref=artifact)
        state.completed_skills.add('recon')
        state.completed_artifacts['recon'] = artifact
        state.current_phase = 'enumeration'
    agent = Agent(AgentOptions(client=model, tools=rt.registry, skills=skills, prompter=rt.prompter,
        store=Store.new_with_id(tmp_path / 'sessions', 'scanner-fixture'), target=rt.target,
        engagement_state=rt.state, workflow=state, max_steps=30, auto_compact_threshold=100000,
        prompt_profile='compact', streaming_enabled=False))
    rt.agent, rt.workflow = agent, workflow
    return rt


