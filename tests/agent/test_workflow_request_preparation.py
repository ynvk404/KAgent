"""Frozen advertising, fresh Agent requests, unchanged production guards."""
import asyncio
from copy import deepcopy
import json
from pathlib import Path
from typing import Any, cast

import pytest

from src.agent.agent import Agent, AgentOptions, AgentRuntimeError, AgentRunOptions
from src.agent.action_guidance import render_action_guidance
from src.agent.context_estimate import text_tokens
from src.agent.decision_planner import PlannerCandidate, PlannerContext
from src.llm.core.client import StreamingClient
from src.llm.core.types import ChatRequest, ChatResponse, FunctionCall, Message, ToolCall
from src.permission.permission import AlwaysAllow
from src.skills.registry import Registry as Skills
from src.target.target import Target
from src.tools.common.registry import Registry
from src.tools.workflow.action_view import ActionView
from src.tools.workflow.workflow_tool import ACTIONS, WorkflowTool
from src.workflow.state import WorkflowObjective, WorkflowState
from tests.helpers.agent_fakes import FakeClient, FakeSignal, seed_compactable_history
from tests.security.test_agent_assessment import setup as assessment_setup
from tests.security.test_evidence_recovery_contract import agent_for
from tests.security.test_execution_policy import runtime  # noqa: F401

ORIGIN = "https://fixture.test"
SKILLS = Path(__file__).resolve().parents[2] / "skills"


class SnapshotClient(FakeClient):
    async def chat(self, request, signal=None):
        response = await super().chat(request, signal)
        self.requests[-1] = deepcopy(request)
        return response


class StreamingSnapshotClient(SnapshotClient, StreamingClient):
    async def chat_stream(self, request, on_delta, signal=None):
        response = await self.chat(request, signal)
        if response.message.content:
            on_delta(response.message.content)
        return response


def setup(tmp_path, client=None, state=None):
    state = state or WorkflowState(objective=WorkflowObjective("objective-fixture", "direct", ORIGIN))
    target = Target(ORIGIN)
    skills = Skills()
    skills.load_dir(SKILLS)
    registry = Registry()
    registry.register(WorkflowTool(state, target, skills=skills, evidence_root=tmp_path))
    agent = Agent(AgentOptions(client=client or SnapshotClient([ChatResponse(Message("assistant", "done"), "stop")]),
        workflow=state, target=target, skills=skills, tools=registry, prompter=AlwaysAllow(),
        store=None, prompt_profile="compact", streaming_enabled=False, auto_compact_threshold=0))
    return agent


def actions(request):
    specs = cast(Any, request.tools)
    return next(s["function"]["parameters"]["properties"]["action"]["enum"]
                for s in specs if s["function"]["name"] == "workflow")


def block(request, prefix):
    found = [m.content for m in request.messages if m.content.startswith(prefix)]
    assert len(found) == 1
    return found[0]


def call(action, **args):
    return ChatResponse(Message("assistant", "", tool_calls=[ToolCall(action, FunctionCall(
        "workflow", json.dumps({"action": action, **args})))]), "tool_calls")


@pytest.mark.parametrize("mode", [None, "direct", "whole_target", "candidate_validation"])
@pytest.mark.parametrize("status", ["new", "validating", "deferred", "validated"])
def test_guidance_budget_and_conditional_contract(mode, status):
    context = PlannerContext(objective_mode=mode,
        candidates=(PlannerCandidate("fixture", "sqli", status, coverage_synced=False),))
    guidance = render_action_guidance(ActionView.for_objective(mode), context)
    assert len(guidance) <= 1000 and text_tokens(guidance) <= 300
    assert "Available =" in guidance and "Recommended =" in guidance and "Excluded =" in guidance
    assert "not permission" in guidance and "sync_coverage" in guidance


def test_unknown_request_contract_is_a_discovery_gap_before_operator_dependency():
    context = PlannerContext(objective_mode='whole_target',
        completed_phases=frozenset({'recon', 'enumeration'}), blocked_input_count=1)
    guidance = render_action_guidance(ActionView.for_objective('whole_target'), context)
    assert 'an unverified method/body is a discovery gap' in guidance
    assert 'not an access prerequisite or automatic operator question' in guidance
    assert 'authentication endpoint accepts credentials' in guidance
    assert 'protected operation requires prior access' in guidance
    assert 'passive triage' in guidance and 'only when operator information/authorization is needed' in guidance
    assert 'separate unrelated dependencies' in guidance and 'exact input_ids' in guidance


@pytest.mark.parametrize("mode", ["whole_target", "direct"])
@pytest.mark.parametrize("stopped", [False, True])
async def test_owned_handoff_guidance_reaches_model_without_changing_runtime(runtime, tmp_path, mode, stopped):
    state, candidate, workflow, args, _ = await assessment_setup(runtime, tmp_path, candidate_class="sqli", mode=mode)
    agent = agent_for(runtime, workflow, state, args)
    state.attempts[args["attempt_id"]]["probing_stopped"] = stopped
    client = SnapshotClient([ChatResponse(Message("assistant", "done"), "stop")])
    agent.set_client(client)
    before = deepcopy(state.to_dict())
    policy = runtime[2]
    rights = policy.engagement.http_permissions
    grants, epoch, used = dict(rights.grants), rights.epoch, policy.used
    req = ChatRequest(client.model(), [Message("user", "continue")], tools=agent.tools.as_llm_tools())
    await agent._chat_for_turn(req, FakeSignal(), lambda event: None)
    advice = block(client.requests[0], "Workflow action guidance:")
    assert "record_attempt_state" in advice and "effects" in advice
    assert "required request" in advice and "owned observations" in advice
    assert "do not wait for proof" in advice.lower()
    assert "GET" in advice and "write acknowledgement" in advice and "does not establish mutation=false" in advice
    assert "record_evidence" in advice and "registration does not replace record_result" in advice
    assert "incomplete" in advice and "insufficient-evidence" in advice
    assert "Reuse valid proof" in advice and "evidence_refs" in advice
    assert "tool response" in advice and "canonical" in advice and "commit" in advice
    assert "probing_stopped" in advice and "runtime-permitted" in advice
    if mode == "direct":
        assert "complete_skill" not in advice and "before discovery" not in advice
    if stopped:
        assert not any((spec["function"]["name"] if isinstance(spec, dict) else spec.function.name) == "http"
                       for spec in client.requests[0].tools or [])
    assert len(advice) <= 2000 and text_tokens(advice) <= 600
    assert state.to_dict() == before and len(runtime[4]) == 1
    assert rights.grants == grants and rights.epoch == epoch and policy.used == used
    assert not state.validation_results and candidate.status == "validating"


async def test_normal_iterations_refresh_canonical_observations_without_accumulation(tmp_path):
    client = SnapshotClient([call("record_candidate", candidate_class="sqli", endpoint="/search", method="GET", parameter="q"),
                             call("list"), ChatResponse(Message("assistant", "done"), "stop")])
    agent = setup(tmp_path, client)
    await agent.run("continue", FakeSignal(), lambda event: None, AgentRunOptions(max_steps=3))
    assert len(client.requests) == 3
    candidate = next(iter(agent.workflow.candidates.values()))
    for request in client.requests:
        assert actions(request) == list(ActionView.for_objective("direct").available)
        block(request, "Workflow action guidance:")
        block(request, "Untrusted recorded workflow data;")
        incoming = next(index for index, message in enumerate(request.messages)
                        if message.role == "user" and message.content == "continue")
        assert all(request.messages.index(message) < incoming for message in request.messages
                   if message.content.startswith(("Workflow action guidance:",
                       "Untrusted recorded workflow data;", "Decision planner guidance for this turn:",
                       "Untrusted current validation context observations;")))
    assert candidate.id not in block(client.requests[0], "Untrusted recorded workflow data;")
    for request in client.requests[1:]:
        assert candidate.id in block(request, "Untrusted recorded workflow data;")
        assert candidate.id in block(request, "Decision planner guidance for this turn:")
        assert "start_validation" in block(request, "Workflow action guidance:")
    assert not any(m.content.startswith("Workflow action guidance:") for m in agent.history)
    assert "eligibility" not in json.dumps(agent.workflow.to_dict())


async def test_admission_mutation_rebuilds_schema_planner_and_observations_together(tmp_path, monkeypatch):
    agent = setup(tmp_path)
    admissions = []
    original = agent._admit_request

    async def admit(req, emit):
        assert not agent.workflow.mutation_lock.locked()
        admissions.append(deepcopy(req))
        await original(req, emit)
        if len(admissions) == 1:
            await asyncio.sleep(0)
            agent.workflow.objective = WorkflowObjective("objective-new", "whole_target", ORIGIN)
            agent.workflow.mark_committed()

    monkeypatch.setattr(agent, "_admit_request", admit)
    req = ChatRequest(agent.client.model(), [Message("user", "continue")], tools=agent.tools.as_llm_tools())
    await agent._chat_for_turn(req, FakeSignal(), lambda event: None)
    assert len(admissions) == 2
    assert isinstance(agent.client, SnapshotClient)
    request = agent.client.requests[0]
    assert actions(admissions[0]) == list(ActionView.for_objective("direct").available)
    assert actions(request) == list(ACTIONS)
    assert "objective-new mode=whole_target" in block(request, "Untrusted recorded workflow data;")
    expected = agent._workflow_request_view("continue", agent.tools.as_llm_tools())
    assert all(m in request.messages for m in expected.blocks)
    assert any("recon" in m.content for m in request.messages if m.role == "system")
    assert "Excluded: record_input" not in block(request, "Workflow action guidance:")


async def test_repeated_admission_churn_is_bounded_without_provider_dispatch(tmp_path, monkeypatch):
    agent = setup(tmp_path)
    admissions = 0

    async def admit(req, emit):
        nonlocal admissions
        admissions += 1
        assert agent.workflow.objective is not None
        agent.workflow.objective.id = "changed-" + str(admissions)
        await asyncio.sleep(0)

    monkeypatch.setattr(agent, "_admit_request", admit)
    req = ChatRequest(agent.client.model(), [Message("user", "continue")], tools=agent.tools.as_llm_tools())
    with pytest.raises(AgentRuntimeError, match="changed repeatedly"):
        await agent._chat_for_turn(req, FakeSignal(), lambda event: None)
    assert isinstance(agent.client, SnapshotClient)
    assert admissions == 3 and not agent.client.requests
    block(req, "Workflow action guidance:")


async def test_production_request_waits_for_queued_mutation_and_refreshes(tmp_path):
    agent = setup(tmp_path)
    req = ChatRequest(agent.client.model(), [Message("user", "continue")], tools=agent.tools.as_llm_tools())
    await agent.workflow.mutation_lock.acquire()

    async def mutate():
        async with agent.workflow.mutation_lock:
            assert agent.workflow.objective is not None
            agent.workflow.objective.id = "queued-mutation"
            agent.workflow.mark_committed()

    request_task = asyncio.create_task(agent._chat_for_turn(req, FakeSignal(), lambda event: None))
    mutation_task = asyncio.create_task(mutate())
    # Queue both production request collection and a canonical mutation.
    await asyncio.sleep(0)
    agent.workflow.mutation_lock.release()
    await asyncio.gather(request_task, mutation_task)
    assert isinstance(agent.client, SnapshotClient)
    assert len(agent.client.requests) == 1
    assert "queued-mutation" in block(agent.client.requests[0], "Untrusted recorded workflow data;")
    block(agent.client.requests[0], "Workflow action guidance:")
    assert agent.client.requests[0].messages[-1] == Message("user", "continue")


@pytest.mark.parametrize("streaming", [False, True])
async def test_malformed_agent_retry_prepares_fresh_context(tmp_path, monkeypatch, streaming):
    client = StreamingSnapshotClient([ChatResponse(Message("assistant", '<｜｜DSML｜｜ calls><｜｜DSML｜｜ invoke name="workflow"><｜｜DSML｜｜ parameter name="action" string="true">list</｜｜DSML｜｜ parameter></｜｜DSML｜｜ invoke></｜｜DSML｜｜ calls>'), "stop"),
                             call("list"), ChatResponse(Message("assistant", "done"), "stop")])
    agent = setup(tmp_path, client)
    agent.streaming_enabled = streaming
    original = agent.save
    changed = False

    async def save(**kwargs):
        nonlocal changed
        await original(**kwargs)
        if agent.history[-1].role == "user" and "previous assistant message contained" in agent.history[-1].content:
            changed = True
            assert agent.workflow.objective is not None
            agent.workflow.objective.id = "malformed-fresh"

    monkeypatch.setattr(agent, "save", save)
    await agent.run("continue", FakeSignal(), lambda event: None, AgentRunOptions(max_steps=2))
    assert changed and len(client.requests) >= 2
    assert "malformed-fresh" in block(client.requests[1], "Untrusted recorded workflow data;")
    assert actions(client.requests[1]) == list(ActionView.for_objective("direct").available)
    block(client.requests[1], "Workflow action guidance:")
    assert client.requests[0].messages[-1] == Message("user", "continue")
    retry = client.requests[1].messages[-1]
    assert retry.role == "user" and "structured function calling only" in retry.content
    assert client.requests[2].messages[-1].role == "tool"
    for request in client.requests:
        block(request, "Untrusted recorded workflow data;")
        block(request, "Workflow action guidance:")
    assert not any(m.content.startswith(("Workflow action guidance:", "Untrusted recorded workflow data;"))
                   for m in agent.history)


@pytest.mark.parametrize("streaming", [False, True])
async def test_production_requests_refresh_after_validation_and_across_turns(tmp_path, streaming):
    client = StreamingSnapshotClient([])
    agent = setup(tmp_path, client)
    agent.streaming_enabled = streaming
    created = json.loads(await agent.tools.execute("workflow", {"action": "record_candidate", "candidate_class": "sqli",
        "endpoint": "/search", "method": "GET", "parameter": "q"}, None, agent.prompter))
    cid = created["candidate"]["id"]
    client.scripted = [call("start_validation", candidate_id=cid),
        call("record_result", candidate_id=cid, skill_name="sql-injection", outcome="insufficient-evidence",
             notes="Offline bounded attempt has no proof"),
        call("list"), call("list"), ChatResponse(Message("assistant", "done"), "stop")]
    events = []
    await agent.run("continue", FakeSignal(), events.append, AgentRunOptions(max_steps=4))
    assert len(client.requests) == 5
    assert len(agent.workflow.attempts) == len(agent.workflow.validation_results) == 1
    assert not agent.workflow.evidence
    assert client.requests[-1].tools is None  # Existing max-step synthesis.
    for request in client.requests[:-1]:
        assert actions(request) == list(ActionView.for_objective("direct").available)
        block(request, "Workflow action guidance:")
        block(request, "Untrusted recorded workflow data;")
        observation = block(request, "Untrusted current validation context observations;")
        contexts = json.loads(observation.partition("\n")[2])
        assert len(contexts) == 1 and contexts[0]["candidate_id"] == cid
        assert contexts[0]["method"] == "GET" and contexts[0]["parameter"] == "q"
    assert "start_validation only" in block(client.requests[0], "Workflow action guidance:")
    assert "record_result for the active attempt" in block(client.requests[1], "Workflow action guidance:")
    for request in client.requests[2:4]:
        assert "insufficient-evidence" in block(request, "Untrusted recorded workflow data;")
        assert "record_result for the active attempt" not in block(request, "Workflow action guidance:")
    # A new production turn reconstructs one fresh block per responsibility.
    client.scripted.append(call("list"))
    client.scripted.append(ChatResponse(Message("assistant", "done"), "stop"))
    await agent.run("continue", FakeSignal(), events.append, AgentRunOptions(max_steps=1))
    request = client.requests[5]
    assert actions(request) == list(ActionView.for_objective("direct").available)
    block(request, "Untrusted current validation context observations;")
    block(request, "Untrusted recorded workflow data;")
    block(request, "Workflow action guidance:")
    assert "insufficient-evidence" in block(request, "Untrusted recorded workflow data;")


async def test_dependent_batch_rechecks_runtime_and_recovery_has_no_duplicate_effects(tmp_path):
    agent = setup(tmp_path)
    created = json.loads(await agent.tools.execute("workflow", {"action": "record_candidate", "candidate_class": "sqli",
        "endpoint": "/search", "method": "GET", "parameter": "q"}, None, agent.prompter))
    cid = created["candidate"]["id"]
    req = ChatRequest(agent.client.model(), [Message("user", "continue")], tools=agent.tools.as_llm_tools())
    await agent._prepare_turn_request(req, lambda event: None)
    assert {"start_validation", "record_evidence", "record_result", "sync_coverage", "complete_skill"} <= set(actions(req))
    # Advertising does not admit missing proof or cross-objective ownership.
    before = deepcopy(agent.workflow.to_dict())
    output = await agent.tools.execute("workflow", {"action": "record_result", "candidate_id": cid,
        "skill_name": "sql-injection", "outcome": "confirmed"}, None, agent.prompter)
    assert output.startswith("error:") and agent.workflow.to_dict() == before
    batch = [ToolCall("start", FunctionCall("workflow", json.dumps({"action": "start_validation", "candidate_id": cid}))),
             ToolCall("close", FunctionCall("workflow", json.dumps({"action": "record_result", "candidate_id": cid,
                 "skill_name": "sql-injection", "outcome": "insufficient-evidence", "notes": "Offline fixture has no proof"})))]
    working = []
    await agent.execute_tool_calls(batch, FakeSignal(), lambda event: None, working)
    assert [m.tool_status for m in working] == ["success", "success"]
    assert len(agent.workflow.attempts) == len(agent.workflow.validation_results) == 1
    assert not agent.workflow.evidence
    await agent._prepare_turn_request(req, lambda event: None)
    assert cid in block(req, "Untrusted recorded workflow data;")
    assert "insufficient-evidence" in block(req, "Untrusted recorded workflow data;")


async def test_streaming_parity_and_tool_free_synthesis(tmp_path):
    class StreamSnapshot(SnapshotClient, StreamingClient):
        async def chat_stream(self, request, on_delta, signal=None):
            on_delta("done")
            return await self.chat(request, signal)

    requests = []
    for streaming in (False, True):
        client = StreamSnapshot([ChatResponse(Message("assistant", "done"), "stop")])
        agent = setup(tmp_path, client)
        agent.streaming_enabled = streaming
        req = ChatRequest(client.model(), [Message("user", "continue")], tools=agent.tools.as_llm_tools())
        await agent._chat_for_turn(req, FakeSignal(), lambda event: None)
        requests.append(client.requests[0])
    assert requests[0].tools == requests[1].tools
    assert requests[0].messages == requests[1].messages
    client = StreamSnapshot([ChatResponse(Message("assistant", "done"), "stop")])
    agent = setup(tmp_path, client)
    agent.streaming_enabled = True
    req = ChatRequest(client.model(), [Message("user", "summarize")], tools=None)
    await agent._chat_for_turn(req, FakeSignal(), lambda event: None, purpose="final_synthesis")
    assert client.requests[0].tools is None
    assert not any(m.content.startswith("Workflow action guidance:") for m in client.requests[0].messages)


async def test_compaction_estimates_share_frozen_view_but_execution_refreshes(tmp_path, monkeypatch):
    agent = setup(tmp_path)
    seed_compactable_history(agent, 20000)
    agent.history.extend([Message("user", "continue"), Message("assistant", "bounded progress")])
    view = agent._workflow_request_view("continue", agent.tools.as_llm_tools())
    context = agent._snapshot_context("continue", ChatRequest(agent.client.model(), [], tools=view.tools), view.blocks)
    agent._pending_context = context
    seen = []
    original = agent._projected_estimate

    def estimate(history, memory, frozen):
        seen.append(frozen)
        return original(history, memory, frozen)

    monkeypatch.setattr(agent, "_projected_estimate", estimate)
    agent.workflow.objective = WorkflowObjective("after-compaction", "whole_target", ORIGIN)
    await agent.apply_compaction_summary("## Objectives\n- Continue bounded fixture testing\n## Completed\n- Prior discussion retained", deepcopy(agent.history), "hybrid fixture")
    assert len(seen) == 2 and all(frozen is context for frozen in seen)
    assert actions(agent._projection_request(agent.history, agent.memory, context)) == list(ActionView.for_objective("direct").available)
    req = ChatRequest(agent.client.model(), [Message("user", "continue")], tools=context.tools)
    await agent._chat_for_turn(req, FakeSignal(), lambda event: None)
    assert isinstance(agent.client, SnapshotClient)
    assert actions(agent.client.requests[0]) == list(ACTIONS)
    assert "after-compaction" in block(agent.client.requests[0], "Untrusted recorded workflow data;")


async def test_resume_rebuilds_interrupted_attempt_guidance_from_canonical_state(tmp_path):
    from src.session.store import Store
    agent = setup(tmp_path)
    created = json.loads(await agent.tools.execute("workflow", {"action": "record_candidate", "candidate_class": "sqli",
        "endpoint": "/search", "method": "GET", "parameter": "q"}, None, agent.prompter))
    cid = created["candidate"]["id"]
    started = json.loads(await agent.tools.execute("workflow", {"action": "start_validation", "candidate_id": cid}, None, agent.prompter))
    assert started["ok"]
    agent.store = Store(tmp_path / "session.json", "hybrid-session")
    await agent.save()
    restored = setup(tmp_path)
    restored.store = Store(tmp_path / "session.json", "hybrid-session")
    restored.resume_saved()
    before = deepcopy(restored.workflow.to_dict())
    req = ChatRequest(restored.client.model(), [Message("user", "continue")], tools=restored.tools.as_llm_tools())
    await restored._chat_for_turn(req, FakeSignal(), lambda event: None)
    assert isinstance(restored.client, SnapshotClient)
    assert restored.workflow.to_dict() == before
    assert cid in block(restored.client.requests[0], "Untrusted recorded workflow data;")
    advice = block(restored.client.requests[0], "Workflow action guidance:")
    assert "no owned active attempt" in advice and "record_attempt_state" not in advice
    assert "record_result for the active attempt" not in advice
    assert "status=interrupted" in block(restored.client.requests[0], "Runtime validation continuation")
    assert "record_result" in actions(restored.client.requests[0])
    assert len(restored.workflow.attempts) == 1
