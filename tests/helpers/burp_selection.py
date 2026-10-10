"""Native offline runtime for explicit capture-selection regressions."""
from pathlib import Path
from typing import Any
from types import SimpleNamespace

from src.agent.agent import Agent, AgentOptions
from src.browser.store import CaptureStore
from src.coverage.store import CoverageStore
from src.engagement.state import EngagementState
from src.permission.permission import Decision, YoloPrompter
from src.permission.runtime.execution import ExecutionPolicy
from src.session.store import Store
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry as Skills
from src.target.target import Target
from src.tools.common.browser_capture import register_browser_capture_tools
from src.tools.common.registry import Registry
from src.tools.execution.file import FileWriteTool
from src.tools.http.http_tool import HTTPTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.state import WorkflowState
from tests.helpers.agent_fakes import FakeClient

ORIGIN = 'http://127.0.0.1:3000'


class Operator:
    def __init__(self):
        self.requests = []
        self.decision = Decision.ALLOW_ONCE
        self.review: Any = None

    async def ask(self, request, signal=None):
        self.requests.append(request)
        if self.review:
            await self.review(request)
        return self.decision


def make_runtime(tmp_path, client=None):
    skills = Skills()
    skills.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    target, engagement, workflow, capture = Target(ORIGIN), EngagementState(), WorkflowState(), CaptureStore()
    engagement.initialize_target(ORIGIN)
    http = HTTPTool(target, engagement, workflow, capture, validation_registry=skills)
    operator = Operator()
    prompter = YoloPrompter(operator, True)
    policy = ExecutionPolicy(engagement, tmp_path)
    prompter.bind_execution_policy(policy)
    coverage = CoverageStore(str(tmp_path / 'coverage.json'))
    workflow_tool = WorkflowTool(workflow, target, coverage, skills, tmp_path, 'burp-selection', http_tool=http)
    registry = Registry()
    register_browser_capture_tools(registry.register, capture)
    for tool in (http, workflow_tool, LoadSkillTool(skills), FileWriteTool()):
        registry.register(tool)
    client = client or FakeClient([])
    store = Store.new_with_id(str(tmp_path / 'sessions'), 'burp-selection')
    agent = Agent(AgentOptions(client, registry, skills, prompter, store, target,
                              workflow=workflow, engagement_state=engagement,
                              auto_compact_threshold=0, streaming_enabled=False))
    actions = []
    app = SimpleNamespace(agent=agent, dispatch=actions.append, read_config=lambda: {},
                          start_burp_bridge=None, close_burp_bridge=None, burp_bridge_status=None,
                          actions=actions)
    return SimpleNamespace(agent=agent, app=app, capture=capture, target=target, engagement=engagement,
                           policy=policy, registry=registry, client=client, prompter=prompter,
                           operator=operator, workflow=workflow, workflow_tool=workflow_tool, http=http)


def ingest(runtime, id_='one', *, origin=ORIGIN, path='/search?q=first', kind='burp', **extra):
    return runtime.capture.ingest({'kind': kind, 'id': id_, 'url': origin + path,
                                   'method': 'GET', **extra})


def notice(runtime):
    return runtime.app.actions[-1].entry.text
