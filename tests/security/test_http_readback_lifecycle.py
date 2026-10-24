"""Offline Direct/readback and real session boundaries from independent review."""
import hashlib
import json
from dataclasses import replace

import pytest

from src.agent.agent import Agent, AgentOptions
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.permission.permission import UserControlledRefusal
from src.session.store import Store
from src.skills.registry import Skill
from src.tools.skills.payloads import ReadPayloadsTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.assessment import digest, source_row
from src.workflow.planning.goals import RequestedGoal
from src.workflow.state import WorkflowObjective
from tests.helpers.agent_fakes import FakeClient, FakeSignal, ScriptedModel, collect
from tests.security.test_execution_policy import runtime  # noqa: F401
from tests.security.test_http_observation_reader import reader_runtime


class RepeatedReadbackClient(FakeClient):
    def __init__(self):
        super().__init__([])
        self.tool_iterations = 0
        self.last_observation = None

    async def chat(self, request, signal=None):
        self.requests.append(request)
        if not request.tools:
            return ChatResponse(Message("assistant", "Validation remains unresolved."), "stop")
        step = self.tool_iterations
        self.tool_iterations += 1
        if step % 2 == 0:
            name, args = "http", {"url": f"/fixture?q=repeat-{step}", "phase": "validation"}
        else:
            feedback = next(m.content for m in reversed(request.messages) if m.name == "http")
            line = next((line for line in feedback.splitlines() if line.startswith("Runtime HTTP evidence (")), None)
            if line is not None:
                row, _ = json.JSONDecoder().raw_decode(line.split(": ", 1)[1])
                self.last_observation = row["observation_id"]
            else:
                assert "probing stopped" in feedback
            name, args = "read_http_observation", {
                "observation_id": self.last_observation, "start_char": 0, "max_chars": 2000,
            }
        return ChatResponse(Message("assistant", "", tool_calls=[
            ToolCall(str(step), FunctionCall(name, json.dumps(args))),
        ]), "tool_calls")


class RecordingScriptedModel(ScriptedModel):
    def __init__(self, script, prefix):
        super().__init__(script, prefix=prefix)
        self.requests = []

    async def chat(self, request, signal=None):
        self.requests.append(request)
        return await super().chat(request, signal)


async def test_direct_identical_http_readback_reaches_24_steps(runtime, tmp_path):
    agent, state, candidate, _, _ = await reader_runtime(runtime, tmp_path)
    assert state.objective is not None
    state.objective.mode = "direct"
    state.objective.requested_goals = [RequestedGoal(candidate.candidate_class, candidate_ids=[candidate.id])]
    agent._explicit_max_steps = 24
    client = RepeatedReadbackClient()
    agent.set_client(client)
    evidence = {key: value.to_dict() for key, value in state.evidence.items()}
    attempts = {key: value.copy() for key, value in state.attempts.items()}
    events = collect()
    await agent.run("continue", FakeSignal(), events["sink"])
    assert events["events"][-1].stop_reason == "max_steps"
    assert client.tool_iterations == 24 and len(client.requests) == 25
    # The embedded controller has a WorkflowTool session owner. Missing effect
    # interpretation is now honest unknown, not a forced false or orphan.
    errors = [event for event in events["events"] if event["type"] == "error"]
    from src.agent.events import MaxStepsError
    assert len(errors) == 1 and isinstance(errors[0].err, MaxStepsError)
    assert not state.persisted_findings
    result = state.latest_result(candidate.id)
    assert result is not None and result.attempt_id is not None
    assert result.outcome == "insufficient-evidence" and result.mutation_performed is None
    assert result.cleanup_state == "unknown"
    assert state.objective.requested_goals[0].status not in {"tested_confirmed", "tested_not_confirmed"}
    assert {key: value.to_dict() for key, value in state.evidence.items()} == evidence
    assert set(state.attempts) == set(attempts)
    assert state.attempts[result.attempt_id]["status"] == "unresolved"
    assert len({item.response_hash for item in runtime[2].observations._items.values()}) == 1


async def test_http_readback_ranges_repeats_and_eof_do_not_dispatch(runtime, tmp_path):
    agent, _, _, _, oid = await reader_runtime(runtime, tmp_path)
    _, prompter, policy, _, sent, *_ = runtime
    before = len(sent)

    async def read(start=0, maximum=2):
        args = {"observation_id": oid, "start_char": start, "max_chars": maximum}
        output = await agent.tools.execute("read_http_observation", args, None, prompter)
        header, body = output.split("\n", 1)
        page = json.loads(header)
        assert page["start_char"] == start and page["end_char"] == start + len(body)
        assert body == policy.observations._items[oid].body.decode()[start:page["end_char"]]
        return output, page

    first, _ = await read()
    assert (await read())[0] == first
    await read(2)
    await read(4)
    _, eof = await read(7)
    assert eof["next_start_char"] is None and eof["start_char"] == eof["end_char"]
    item = policy.observations._items[oid]
    body = b"a genuinely different retained response"
    updated = replace(item, body=body, response_hash=hashlib.sha256(body).hexdigest())
    policy.observations._items[oid] = replace(updated, retained_hash=digest(source_row(updated)))
    assert (await read())[0] != first
    assert len(sent) == before


async def test_retired_skill_page_reread_can_finish_direct_validation(runtime, tmp_path):
    agent, state, candidate, result_args, _ = await reader_runtime(runtime, tmp_path)
    assert state.objective is not None
    state.objective.mode = "direct"
    state.objective.requested_goals = [RequestedGoal(candidate.candidate_class, candidate_ids=[candidate.id])]
    payloads = tmp_path / "payloads"
    payloads.mkdir()
    for index in range(5):
        (payloads / f"page-{index}.txt").write_text(f"Distinct validation guidance {index}.\n")
    agent.skills.add(Skill("readback-fixture", "fixture", [], False, str(tmp_path / "SKILL.md"), ""))
    agent.tools.register(ReadPayloadsTool(agent.skills))
    agent._explicit_max_steps = 24
    sent_before = len(runtime[4])

    def script():
        pages = []
        for index in range(5):
            pages.append((yield "read_payloads", {"skill": "readback-fixture", "file": f"page-{index}.txt"}))
        # Five pages have crossed actual Agent request admission; the first is retired.
        request_pages = [m for m in client.requests[-1].messages if m.name == "read_payloads"]
        assert request_pages[0].content.startswith("[Older skill page omitted;")
        assert [m.content for m in request_pages[-4:]] == pages[-4:]
        reread = yield "read_payloads", {"skill": "readback-fixture", "file": "page-0.txt"}
        assert reread == pages[0]
        recorded = yield "workflow", {**result_args, "outcome": "not-confirmed"}
        assert json.loads(recorded)["ok"]

    client = RecordingScriptedModel(script(), prefix="retired-page")
    agent.set_client(client)
    events = collect()
    await agent.run("continue", FakeSignal(), events["sink"])
    assert client.consumed and not client.errors
    assert not [event for event in events["events"] if event["type"] == "error"]
    assert events["events"][-1].stop_reason == "final_response"
    assert state.objective.requested_goals[0].status == "tested_not_confirmed"
    assert len(runtime[4]) == sent_before
    assert all(not m.content.startswith("[Older skill page omitted;")
               for m in agent.history if m.name == "read_payloads")


LAB_BODY = ('Safe reflection é <script>fixture</script>\nCookie: sid=target-session\n'
            'JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.fixture-signature')


async def saved_reader(runtime, tmp_path):
    agent, state, _, result_args, oid = await reader_runtime(runtime, tmp_path)
    registry, prompter, policy, _, sent, *_ = runtime
    item = replace(policy.observations._items[oid], body=LAB_BODY.encode(),
                   response_hash=hashlib.sha256(LAB_BODY.encode()).hexdigest())
    policy.observations._items[oid] = replace(item, retained_hash=digest(source_row(item)))
    # Active execution rights are intentionally interrupted by WorkflowState hydration.
    # Completed current attempts remain readable, without minting resume authority.
    assert json.loads(await registry.execute("workflow", {**result_args, "outcome": "not-confirmed"},
        None, prompter))["ok"]
    before = len(sent)
    args = {"observation_id": oid, "start_char": 0, "max_chars": 2000}
    working = []
    events = collect()
    batch = await agent.execute_tool_calls([
        ToolCall("readback", FunctionCall("read_http_observation", json.dumps(args))),
    ], FakeSignal(), events["sink"], working, defer_admission=True)
    assert not batch.calls[0].result.err_str
    message = working[-1]
    assert message.content.split("\n", 1)[1] == LAB_BODY
    assert message.http_response_sources == [oid]
    store = Store(tmp_path / "reader-session.json", "assessment-session")
    await store.save(working, target=agent.target, workflow=state, engagement_state=policy.engagement)
    loaded = store.load()
    # A fresh controller inherits existing test rights, never creates a new grant/owner.
    resumed = Agent(AgentOptions(client=FakeClient([]), tools=registry, skills=agent.skills,
        prompter=prompter, store=None, target=agent.target, workflow=loaded.workflow,
        engagement_state=policy.engagement, streaming_enabled=False))
    resumed.active_skills.add("cross-site-scripting")
    workflow = registry.get("workflow")
    assert isinstance(workflow, WorkflowTool)
    workflow.state = loaded.workflow
    assert len(sent) == before
    return resumed, loaded.messages, message, oid, store


async def test_real_session_reader_round_trip_keeps_body_and_sources(runtime, tmp_path):
    agent, messages, original, oid, _ = await saved_reader(runtime, tmp_path)
    assert messages[-1].content == original.content
    assert messages[-1].http_response_sources == [oid]
    assert messages[-1].http_runtime_stamp is None  # transient rights are not serialized
    agent._protect_http_context(messages)
    assert messages[-1].content == original.content
    assert "target-session" in messages[-1].content and "eyJhbGciOiJIUzI1NiJ9" in messages[-1].content


@pytest.mark.parametrize("fault", ["http-revoked", "reader-revoked", "scope", "session", "epoch",
    "retest", "candidate", "attempt", "integrity", "unavailable", "missing-metadata",
    "malformed-metadata", "header-source", "body-tampered", "internal-secret"])
async def test_resumed_reader_fails_closed_without_new_http(runtime, tmp_path, fault):
    agent, messages, original, oid, store = await saved_reader(runtime, tmp_path)
    registry, prompter, policy, _, sent, *_ = runtime
    before = len(sent)
    item = policy.observations._items[oid]
    assert item.candidate_id is not None and item.attempt_id is not None
    if fault.endswith("revoked"):
        policy.revoke("http" if fault == "http-revoked" else "read_http_observation")
    elif fault == "scope":
        policy.engagement.remove_origin(item.url)
    elif fault == "session":
        policy.session_id = "other-session"
    elif fault == "epoch":
        policy.engagement.http_permissions.epoch = "other-epoch"
    elif fault == "retest":
        origin = agent.target.origin()
        assert origin is not None
        agent.workflow.objective = WorkflowObjective("retest", "candidate_validation",
            origin.as_url(), candidate_id=item.candidate_id)
        candidate = agent.workflow.candidates[item.candidate_id]
        candidate.status = "queued"
        assert json.loads(await registry.execute("workflow", {"action": "start_validation",
            "candidate_id": candidate.id}, None, prompter))["ok"]
    elif fault == "candidate":
        agent.workflow.candidates[item.candidate_id].endpoint = "/different"
    elif fault == "attempt":
        agent.workflow.attempts[item.attempt_id]["status"] = "unresolved"
    elif fault == "integrity":
        policy.observations._items[oid] = replace(item, body=b"tampered")
    elif fault == "unavailable":
        policy.observations._items.pop(oid)
    elif fault in {"missing-metadata", "malformed-metadata"}:
        serialized = json.loads(store.path.read_text())
        if fault == "missing-metadata":
            serialized["messages"][-1].pop("http_response_sources")
        else:
            serialized["messages"][-1]["http_response_sources"] = ["obs_bad"]
        store.path.write_text(json.dumps(serialized))
        messages = store.load().messages
    elif fault == "header-source":
        header, body = original.content.split("\n", 1)
        row = json.loads(header)
        row["observation_id"] = "obs_" + "f" * 32
        messages[-1] = replace(messages[-1], content=json.dumps(row) + "\n" + body)
    elif fault == "body-tampered":
        messages[-1] = replace(messages[-1], content=original.content + "invented evidence")
    elif fault == "internal-secret":
        policy.internal_secret_values = lambda: ("target-session",)
        with pytest.raises(UserControlledRefusal, match="internal secret"):
            await agent.tools.execute("read_http_observation", {
                "observation_id": oid, "start_char": 0, "max_chars": 8,
            }, None, prompter)
    agent._protect_http_context(messages)
    assert "HTTP analysis omitted" in messages[-1].content
    assert "Safe reflection" not in messages[-1].content and "target-session" not in messages[-1].content
    assert messages[-1].http_response_sources is None
    assert len(sent) == before


async def test_reader_error_without_body_keeps_its_diagnostic(runtime, tmp_path):
    agent, _, _, _, _ = await reader_runtime(runtime, tmp_path)
    message = Message("tool", "error: primary reference unavailable", name="read_http_observation",
        tool_status="error", tool_error_kind="reference_unavailable")
    working = [message]
    agent._protect_http_context(working)
    assert working == [message]
