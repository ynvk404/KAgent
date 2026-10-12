"""Producer events belong to admitted requests, not initial projections."""
from copy import deepcopy
import json
from pathlib import Path
import socket
import tempfile

import pytest

from src.agent.agent import AgentRunOptions
from src.llm.core.types import ChatRequest, ChatResponse, Message
from src.llm.transport.retry import RetryOptions, with_retry
from src.llm.transport.errors import BackendError
from src.workflow.state import WorkflowObjective
from tests.agent.test_workflow_request_preparation import (
    SnapshotClient, StreamingSnapshotClient, setup, call, block,
)
from tests.helpers.agent_fakes import FakeSignal


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    violations = []
    def deny(*args, **kwargs):
        violations.append("network")
        raise AssertionError("network forbidden in Planner emission tests")
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket.socket, "connect_ex", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    yield
    assert not violations, "offline violation was swallowed by runtime"


@pytest.fixture
def scratch():
    with tempfile.TemporaryDirectory(prefix="planner-emission-", dir="/tmp") as directory:
        yield Path(directory)


def recommendations(events):
    return [event for event in events if event.get("type") == "decision"
            and event.get("recommended_skill")]


@pytest.mark.parametrize("streaming", [False, True])
async def test_one_recommendation_per_admitted_request(scratch, streaming):
    client = StreamingSnapshotClient([call("list"), ChatResponse(Message("assistant", "done"), "stop")])
    agent = setup(scratch, client)
    agent.streaming_enabled = streaming
    events = []
    await agent.run("Test SQL injection", FakeSignal(), events.append, AgentRunOptions(max_steps=1))
    plans = recommendations(events)
    assert len(client.requests) == 2 and client.requests[1].tools is None
    assert len(plans) == 1, [(p.get("recommended_skill"), p.get("decision_id")) for p in plans]
    assert plans[0].get("recommended_skill") == "sql-injection"
    # Initial projection still supplies one guidance block to the provider.
    block(client.requests[0], "Decision planner guidance for this turn:")
    assert not any(m.content.startswith("Decision planner guidance for this turn:") for m in agent.history)


async def test_admission_mutation_emits_only_final_plan(scratch, monkeypatch):
    client = SnapshotClient([call("list"), ChatResponse(Message("assistant", "done"), "stop")])
    agent = setup(scratch, client)
    original = agent._admit_request
    admissions = 0
    expected = []

    async def admit(req, emit):
        nonlocal admissions
        await original(req, emit)
        admissions += 1
        if admissions == 1:
            agent.workflow.objective = WorkflowObjective("changed", "whole_target", "https://fixture.test")
            agent.workflow.mark_committed()
            expected.append(agent._workflow_request_view("Test SQL injection", agent.tools.as_llm_tools()).decision)

    monkeypatch.setattr(agent, "_admit_request", admit)
    events = []
    await agent.run("Test SQL injection", FakeSignal(), events.append, AgentRunOptions(max_steps=1))
    plans = recommendations(events)
    assert len(plans) == 1
    assert expected[0] is not None
    assert plans[0].get("recommended_skill") == expected[0].recommended_skill
    assert plans[0].get("objective_id") == "changed"
    block(client.requests[0], "Decision planner guidance for this turn:")


@pytest.mark.parametrize("churn", [False, True])
async def test_unadmitted_request_never_publishes_recommendation(scratch, monkeypatch, churn):
    client = SnapshotClient([])
    agent = setup(scratch, client)
    admissions = 0

    async def admit(req, emit):
        nonlocal admissions
        admissions += 1
        if not churn:
            raise RuntimeError("offline admission failure")
        assert agent.workflow.objective is not None
        agent.workflow.objective.id = f"churn-{admissions}"

    monkeypatch.setattr(agent, "_admit_request", admit)
    events = []
    await agent.run("Test SQL injection", FakeSignal(), events.append, AgentRunOptions(max_steps=1))
    assert admissions == (3 if churn else 1)
    assert not client.requests
    assert not recommendations(events)
    assert any(event.get("type") == "error" for event in events)


@pytest.mark.parametrize("streaming", [False, True])
async def test_malformed_agent_retry_emits_once_per_fresh_request(scratch, streaming):
    malformed = '<｜｜DSML｜｜ calls><｜｜DSML｜｜ invoke name="workflow"><｜｜DSML｜｜ parameter name="action" string="true">list</｜｜DSML｜｜ parameter></｜｜DSML｜｜ invoke></｜｜DSML｜｜ calls>'
    client = StreamingSnapshotClient([ChatResponse(Message("assistant", malformed), "stop"),
                                     call("list"), ChatResponse(Message("assistant", "done"), "stop")])
    agent = setup(scratch, client)
    agent.streaming_enabled = streaming
    events = []
    await agent.run("Test SQL injection", FakeSignal(), events.append, AgentRunOptions(max_steps=1))
    enabled = [req for req in client.requests if req.tools is not None]
    assert len(enabled) == 2
    assert "structured function calling only" in enabled[1].messages[-1].content
    plans = recommendations(events)
    assert len(plans) == 2
    assert len({p.get("decision_id") for p in plans}) == 2


async def test_new_candidate_and_route_still_publish_new_events(scratch):
    client = SnapshotClient([ChatResponse(Message("assistant", "done"), "stop") for _ in range(2)])
    agent = setup(scratch, client)
    events = []
    ids = []
    for candidate_class in ("sqli", "xss"):
        if ids:
            agent.workflow.candidates[ids[0]].status = "deferred"
        created = json.loads(await agent.tools.execute("workflow", {
            "action": "record_candidate", "candidate_class": candidate_class,
            "endpoint": "/" + candidate_class, "method": "GET", "parameter": "q",
        }, None, agent.prompter))
        ids.append(created["candidate"]["id"])
        req = ChatRequest(agent.client.model(), [Message("user", "continue")], tools=agent.tools.as_llm_tools())
        await agent._chat_for_turn(req, FakeSignal(), events.append)
    plans = recommendations(events)
    assert [p.get("candidate_id") for p in plans] == ids
    assert [p.get("recommended_skill") for p in plans] == ["sql-injection", "cross-site-scripting"]


async def test_tool_free_request_does_not_publish_a_plan(scratch):
    agent = setup(scratch)
    events = []
    req = ChatRequest(agent.client.model(), [Message("user", "Test SQL injection")], tools=None)
    await agent._chat_for_turn(req, FakeSignal(), events.append, purpose="final_synthesis")
    assert not recommendations(events)


async def test_transport_retry_reuses_request_without_extra_event(scratch):
    class RetryClient(SnapshotClient):
        attempts = 0
        payloads = []

        async def chat(self, request, signal=None):
            async def attempt():
                self.attempts += 1
                self.payloads.append(deepcopy(request))
                if self.attempts == 1:
                    raise BackendError("fake", "backend-down", 503, "offline transient failure")
                return await super(RetryClient, self).chat(request, signal)
            return await with_retry(attempt, RetryOptions(retries=1, base_delay_ms=0, max_delay_ms=0))

    client = RetryClient([call("list"), ChatResponse(Message("assistant", "done"), "stop")])
    agent = setup(scratch, client)
    events = []
    await agent.run("Test SQL injection", FakeSignal(), events.append, AgentRunOptions(max_steps=1))
    assert client.attempts == 3  # two transport attempts, then tool-free synthesis
    assert client.payloads[0] == client.payloads[1]
    assert len(recommendations(events)) == 1
