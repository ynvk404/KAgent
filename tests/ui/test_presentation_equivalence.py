"""Offline runtime dispatch and stored state survive presentation admission."""
import copy
import json
from dataclasses import asdict
from unittest.mock import Mock

import pytest

from src.agent.agent import Agent, AgentOptions
from src.agent.events import DoneEvent
from src.browser.store import CaptureStore
from src.coverage.store import CoverageStore
from src.findings.store import Store as FindingStore
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.permission.permission import Decision
from src.session.store import Store
from src.skills.registry import Registry as Skills, Skill, SkillTriggers
from src.target.target import Target
from src.tools.common.outcome import ToolOutput
from src.tools.common.registry import Registry
from src.tools.workflow.finding import ConfirmFindingTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.ui.core.app import RunAgentOptions
from src.ui.core.state import AgentEventAction
from src.workflow.evidence import EvidenceArtifact
from src.workflow.state import Candidate, ValidationResult, WorkflowObjective, WorkflowState
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from tests.helpers.workflow import adopt_fixture_assessment
from tests.ui.test_app import make_app, timer_app


ORIGIN = "http://juice.lab:3000"


class Operator:
    def __init__(self):
        self.requests = []

    async def ask(self, request, signal=None):
        self.requests.append(copy.deepcopy(request))
        return Decision.ALLOW_ONCE


class ObservationTool:
    def __init__(self):
        self.calls = []

    def name(self):
        return "fixture_observation"

    def description(self):
        return "Offline synthetic observation"

    def schema(self):
        return {"type": "object", "properties": {"operation": {"type": "string"}}}

    def requires_permission(self):
        return True

    def summarize(self, args):
        return {"summary": "Review fixture observation", "detail": json.dumps(args)}

    async def run(self, args, signal, prompter):
        self.calls.append(copy.deepcopy(args))
        return ToolOutput("HTTP/1.1 403 Forbidden\n\nBounded observation", status="observation", http_status=403)


@pytest.mark.parametrize("candidate_class", ["sqli", "xss", "access-control", "ssrf", "authentication", "unknown-class"])
@pytest.mark.parametrize("mode", ["direct", "burp-assisted", "whole_target"])
async def test_admission_preserves_runtime_request_workflow_and_artifacts(tmp_path, candidate_class, mode):
    workflow = WorkflowState(objective=WorkflowObjective("fixture-objective",
        "whole_target" if mode == "whole_target" else "direct", ORIGIN))
    assert workflow.objective is not None
    capture = CaptureStore()
    captured = capture.ingest({"id":"fixture-capture", "kind":"burp", "url":ORIGIN + "/search?q=fixture", "method":"GET"}) if mode == "burp-assisted" else None
    candidate, _ = workflow.add_candidate(Candidate(candidate_class=candidate_class, target=ORIGIN,
        endpoint="/search", parameter="q", method="GET", objective_id=workflow.objective.id,
        baseline_request_ref=captured["id"] if captured else None, auth_context_ref="fixture-context"))
    proof = tmp_path / "evidence.txt"
    proof.write_text("Bounded offline request/response proof", encoding="utf-8")
    artifact = EvidenceArtifact.capture(candidate.id, proof.name, tmp_path)
    workflow.add_evidence(artifact)
    workflow.add_validation_result(adopt_fixture_assessment(workflow, ValidationResult(
        candidate.id, "fixture-validator", "confirmed", evidence_refs=[artifact.id])))
    coverage = CoverageStore(str(tmp_path / "coverage.json"))
    await coverage.mark(endpoint="/search", param="q", vulnClass=candidate.candidate_class, status="failed",
                        notes="Offline fixture assessment")
    registry = Registry()
    observation = ObservationTool()
    registry.register(observation)
    registry.register(WorkflowTool(workflow, Target(ORIGIN), coverage=coverage, evidence_root=tmp_path))
    findings = FindingStore(str(tmp_path / "findings"))
    registry.register(ConfirmFindingTool(findings, workflow=workflow))
    operator = Operator()
    client = FakeClient([])
    skills = Skills()
    skills.add(Skill(name="fixture-validator", description="Offline consumer fixture", tools=[],
        disable_model_invocation=False, path=str(tmp_path / "SKILL.md"), body="", stage="validation",
        candidate_classes=[candidate.candidate_class], triggers=SkillTriggers()))
    agent = Agent(AgentOptions(client, registry, skills, operator,
        Store.new_with_id(tmp_path / "sessions", "fixture-session"), Target(ORIGIN), workflow=workflow))
    args = {"operation": "bounded observation", "class":candidate_class, "context":"fixture-context"}
    finding_args = {"candidate_id":candidate.id, "title":"Offline fixture finding", "severity":"critical",
        "url":ORIGIN + "/search", "method":"GET", "parameter":"q", "observed_impact":"The linked evidence demonstrates the behavior.",
        "potential_impact":"No additional impact assessed."}
    calls = [ToolCall("observation", FunctionCall(observation.name(), json.dumps(args))),
             ToolCall("workflow", FunctionCall("workflow", '{"action":"list"}')),
             ToolCall("finding", FunctionCall("confirm_finding", json.dumps(finding_args)))]
    events = []
    from src.ui.core.outcomes import runtime_facts
    from src.ui.core.state import SetBusy
    turn_baseline = runtime_facts(agent, None, ())
    working = list(agent.history)
    batch = await agent.execute_tool_calls(calls, FakeSignal(), events.append, working)
    assert observation.calls == [args] and len(batch.calls) == 3
    assert batch.calls[0].result.status == "observation" and batch.calls[0].result.http_status == 403
    assert workflow.finding_is_persisted(candidate.id) and workflow.eligible_for_finding(candidate.id)
    await agent.save()
    before_history = copy.deepcopy(agent.history)
    before_workflow = copy.deepcopy(workflow.to_dict())
    request = agent._projection_request(agent.history, agent.memory, agent._idle_context())
    before_request = copy.deepcopy(asdict(request))
    before_prompts = copy.deepcopy(operator.requests)
    assert agent.store is not None
    files = [agent.store.path, proof, *findings.dir.glob("*.md")]
    if (tmp_path / "coverage.json").exists():
        files.append(tmp_path / "coverage.json")
    before_files = {path: path.read_bytes() for path in files}
    before_capture = copy.deepcopy((capture.list_requests(), capture.list_endpoints(), capture.list_snapshots()))
    before_events = copy.deepcopy(events)
    app = make_app()
    app.agent = agent
    app.dispatch(SetBusy(True, facts=turn_baseline))
    from src.agent.agent import _to_agent_event
    for event in events:
        app.dispatch(AgentEventAction(_to_agent_event(event)))
    app.dispatch(AgentEventAction(DoneEvent(stop_reason="workflow_blocked")))
    assert len(app.state.transcript) <= 3
    assert sum(entry.kind == "finding" for entry in app.state.transcript) == 1
    assert "(medium)" in next(entry.text for entry in app.state.transcript if entry.kind == "finding")
    assert agent.history == before_history and workflow.to_dict() == before_workflow
    assert asdict(agent._projection_request(agent.history, agent.memory, agent._idle_context())) == before_request
    assert operator.requests == before_prompts and observation.calls == [args]
    assert {path: path.read_bytes() for path in files} == before_files
    assert (capture.list_requests(), capture.list_endpoints(), capture.list_snapshots()) == before_capture
    assert events == before_events and not client.requests


async def test_live_ui_callback_publishes_diagnostics_before_admission(tmp_path):
    observation = ObservationTool()
    registry = Registry()
    registry.register(observation)
    client = FakeClient([
        ChatResponse(Message("assistant", "", tool_calls=[ToolCall("observation", FunctionCall(observation.name(), '{"operation":"fixture"}'))]), "tool_calls"),
        ChatResponse(Message("assistant", "A bounded observation does not establish a vulnerability."), "stop"),
    ])
    agent = Agent(AgentOptions(client, registry, Skills(), Operator(), None, Target(ORIGIN), streaming_enabled=False))
    app, _, _ = timer_app()
    app.agent = agent
    diagnostics = []
    app.session_debug = Mock()
    app.session_debug.agent_event.side_effect = diagnostics.append
    original_dispatch = app.dispatch
    def dispatch(action):
        if isinstance(action, AgentEventAction):
            assert diagnostics[-1] == asdict(action.event)
        original_dispatch(action)
    app.dispatch = dispatch
    await app.run_agent_turn("Inspect the bounded fixture response.", RunAgentOptions(transcript_user_text="Inspect fixture"))
    assert len(client.requests) == 2 and observation.calls == [{"operation":"fixture"}]
    assert {event["type"] for event in diagnostics} >= {"tool-call", "tool-result", "assistant-text", "done"}
    assert [entry.kind for entry in app.state.transcript] == ["user", "assistant", "info"]
