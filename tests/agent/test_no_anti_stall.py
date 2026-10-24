"""Offline Agent regressions: repetition is bounded only by real runtime gates."""
from copy import deepcopy
import json

import pytest

from src.agent.events import DoneEvent, MaxStepsError
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.workflow.assessment import seal
from src.workflow.evidence.recovery import current_budget
from src.workflow.planning.goals import RequestedGoal
from src.workflow.state import WorkflowState
from tests.helpers.agent_fakes import FakeClient, FakeSignal, collect
from tests.security.test_agent_assessment import setup
from tests.security.test_evidence_recovery_contract import agent_for
from tests.security.test_execution_policy import runtime  # noqa: F401


class RepeatingClient(FakeClient):
    def __init__(self, state, aid, oid, kind, limit, repair=None):
        super().__init__([])
        self.state, self.aid, self.oid = state, aid, oid
        self.kind, self.limit, self.repair = kind, limit, repair
        self.iterations = 0

    async def chat(self, request, signal=None):
        self.requests.append(deepcopy(request))
        assert not self.state.attempts[self.aid].get("probing_stopped")
        if not request.tools:
            return ChatResponse(Message("assistant", "Incomplete bounded fixture."), "stop")
        self.iterations += 1
        assert self.iterations <= self.limit, "unexpected probing turn after max_steps"
        if self.repair is not None and self.iterations == self.limit:
            name, args = "workflow", self.repair
        elif self.kind == "text":
            return ChatResponse(Message("assistant", "Still working on this fixture."), "stop")
        elif self.kind == "invalid":
            name, args = "workflow", {"action": "not-a-real-action"}
        elif self.kind == "error":
            name, args = "read_http_observation", {"observation_id": "obs_" + "f" * 32}
        elif self.kind == "read":
            name, args = "read_http_observation", {"observation_id": self.oid, "start_char": 0, "max_chars": 2000}
        else:
            name, args = "workflow", {"action": "list"}
        return ChatResponse(Message("assistant", "", tool_calls=[ToolCall(
            str(self.iterations), FunctionCall(name, json.dumps(args)))]), "tool_calls")


@pytest.mark.parametrize("mode", ["direct", "candidate_validation", "whole_target"])
@pytest.mark.parametrize("kind", ["invalid", "error", "list", "read", "text"])
async def test_repetition_reaches_exact_outer_budget_without_stopping_probing(runtime, tmp_path, mode, kind):
    state, candidate, tool, args, oid = await setup(runtime, tmp_path, mode=mode)
    assert state.objective is not None
    state.objective.requested_goals = [RequestedGoal(candidate.candidate_class, candidate_ids=[candidate.id])]
    limit = 16  # Cross both the old four-iteration threshold and exploration allowance.
    agent = agent_for(runtime, tool, state, args, max_steps=limit)
    client = RepeatingClient(state, args["attempt_id"], oid, kind, limit)
    agent.set_client(client)
    evidence = deepcopy(state.evidence)
    before = len(runtime[4])
    output = collect()
    await agent.run("Continue current validation.", FakeSignal(), output["sink"])
    done = output["events"][-1]
    assert isinstance(done, DoneEvent) and done.stop_reason == "max_steps"
    assert client.iterations == done.workflow_metrics["outer_iterations"] == limit
    assert done.agent_loop_llm_calls == limit and done.final_synthesis_llm_calls == 1
    assert len(client.requests) == limit + 1 and client.requests[-1].tools is None
    assert not any(e.stop_reason == "workflow_stalled" for e in output["events"] if isinstance(e, DoneEvent))
    result = state.latest_result(candidate.id)
    assert result is not None and len(state.validation_results) == 1
    assert result.outcome == "insufficient-evidence" and result.attempt_id == args["attempt_id"]
    assert result.mutation_performed is None and result.cleanup_state == "unknown"
    assert result.assessment_binding == seal(result)
    assert not result.evidence_refs and not result.evidence_manifest and state.evidence == evidence
    assert result.attempt_id is not None
    assert state.attempts[result.attempt_id]["status"] == "unresolved" and candidate.status == "deferred"
    assert state.objective.requested_goals[0].status not in {"tested_confirmed", "tested_not_confirmed"}
    assert not state.persisted_findings and not state.eligible_for_finding(candidate.id)
    assert len(runtime[4]) == before
    assert WorkflowState.from_dict(state.to_dict()).to_dict() == state.to_dict()
    errors = [e for e in output["events"] if e.type == "error"]
    assert len(errors) == 1 and isinstance(errors[0].err, MaxStepsError)


@pytest.mark.parametrize("kind", ["invalid", "error", "list", "read", "text"])
async def test_valid_correction_after_repetition_can_complete(runtime, tmp_path, kind):
    state, candidate, tool, args, oid = await setup(runtime, tmp_path, mode="direct")
    assert state.objective is not None
    state.objective.requested_goals = [RequestedGoal(candidate.candidate_class, candidate_ids=[candidate.id])]
    agent = agent_for(runtime, tool, state, args, max_steps=20)
    client = RepeatingClient(state, args["attempt_id"], oid, kind, 16, repair={**args, "outcome": "not-confirmed"})
    # After the valid result, a normal final response is sufficient.
    original = client.chat
    async def chat(request, signal=None):
        if client.iterations == 16:
            client.requests.append(deepcopy(request))
            return ChatResponse(Message("assistant", "Bounded negative recorded."), "stop")
        return await original(request, signal)
    client.chat = chat
    agent.set_client(client)
    output = collect()
    before = len(runtime[4])
    await agent.run("Continue current validation.", FakeSignal(), output["sink"])
    done = output["events"][-1]
    assert done.stop_reason == "final_response" and done.agent_loop_llm_calls == 17
    assert done.final_synthesis_llm_calls == 0
    assert state.objective.requested_goals[0].status == "tested_not_confirmed"
    result = state.latest_result(candidate.id)
    assert result is not None and result.outcome == "not-confirmed" and result.evidence_refs
    assert result.coverage_synced and len(state.validation_results) == 1
    assert not state.attempts[args["attempt_id"]].get("probing_stopped")
    assert not state.persisted_findings and len(runtime[4]) == before


@pytest.mark.parametrize("mode", ["direct", "candidate_validation", "whole_target"])
@pytest.mark.parametrize("kind", ["invalid", "text"])
async def test_paused_evidence_recovery_survives_repetition_and_budget(runtime, tmp_path, mode, kind):
    state, candidate, tool, args, oid = await setup(runtime, tmp_path, mode=mode)
    assert state.objective is not None
    state.objective.requested_goals = [RequestedGoal(candidate.candidate_class, candidate_ids=[candidate.id])]
    sent = runtime[4]
    registration = {
        "action": "record_evidence", "candidate_id": candidate.id,
        "evidence_path": "proof.md", "observation_ids": ["obs_" + "f" * 32],
    }
    agent = agent_for(runtime, tool, state, registration, max_steps=1)
    await agent.run("Continue current validation.", FakeSignal(), collect()["sink"])
    budget = current_budget(state, candidate.id)
    assert budget is not None and budget["rejections"] == 1 and budget["paused"]
    before = deepcopy(budget), deepcopy(state.evidence), len(sent)
    agent._explicit_max_steps = 16
    client = RepeatingClient(state, args["attempt_id"], oid, kind, 16)
    agent.set_client(client)
    output = collect()
    await agent.run("Continue current validation.", FakeSignal(), output["sink"])
    assert output["events"][-1].stop_reason == "max_steps" and client.iterations == 16
    assert state.attempts[args["attempt_id"]]["status"] == "active"
    assert not state.validation_results and not state.persisted_findings
    assert (budget, state.evidence, len(sent)) == before
    restored = WorkflowState.from_dict(state.to_dict())
    assert restored.evidence_recovery == state.evidence_recovery
    assert restored.attempts[args["attempt_id"]]["status"] == "interrupted"
