"""Offline regressions for start commit boundaries and transient retention."""
from __future__ import annotations

import asyncio
from copy import deepcopy
import json
from pathlib import Path

import httpx
import pytest

from src.agent.agent import (
    Agent, AgentOptions, ParsedToolCall, ToolCallResult,
    bounded_history_for_compaction, elide_persisted_workflow_results,
)
from src.agent.compaction import format_history_for_compaction
from src.agent.compaction import bounded_history_for_compaction as bounded_compaction
from src.agent.tool_results import source_provenance
from src.llm.core.types import ChatRequest, ChatResponse, FunctionCall, Message, ToolCall
from src.permission.permission import AlwaysAllow, Decision, YoloPrompter
from src.permission.runtime.execution import ExecutionPolicy
from src.redaction.redact import redact_payload
from src.session.store import Store
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.evidence import EvidenceArtifact
from src.workflow.state import ValidationResult, WorkflowObjective
from src.workflow.validation_context import resolve_validation_context, without_transient_validation_context
from tests.helpers.agent_fakes import FakeClient, FakeSignal, seed_compactable_history
from tests.integration.test_phase2a_handoff import (
    ORIGIN, call, capture_payload, linked, runtime,
)


async def terminal_fixture(tmp_path):
    state, registry, http, captures = runtime(tmp_path)
    raw = captures.ingest(capture_payload(
        authContextRef="user", requestHeaders={"Content-Type": "application/json",
                                               "Authorization": "Bearer live-fixture"},
    ))
    item, record = await linked(registry, content_type="application/json", sample_payload='{"q":"safe"}',
                                baseline_request_ref=raw["baseline_request_ref"], auth_context_ref="user")
    request = httpx.Request("POST", ORIGIN + "/api", headers={"Authorization": "Bearer live-fixture"})
    http.context_store.extract(request, httpx.Response(200, request=request), "user")
    (tmp_path / "proof.md").write_text("terminal proof")
    artifact = EvidenceArtifact.capture(record["id"], "proof.md", tmp_path)
    state.add_evidence(artifact)
    state.add_validation_result(ValidationResult(record["id"], "cross-site-scripting", "confirmed",
                                                evidence_refs=[artifact.id]))
    return state, registry, http, captures, item, state.candidates[record["id"]]


def pause_evidence(monkeypatch):
    entered, release = asyncio.Event(), asyncio.Event()

    async def read(*args, **kwargs):
        entered.set()
        await release.wait()
        return False  # Broken evidence permits repair under the existing gate.

    monkeypatch.setattr("src.tools.workflow.workflow_tool.verify_evidence_reads", read)
    return entered, release


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["capture", "auth", "both"])
async def test_availability_observed_after_evidence_await(tmp_path, monkeypatch, change):
    state, registry, http, captures, _, candidate = await terminal_fixture(tmp_path)
    before = resolve_validation_context(state, candidate.id, target=ORIGIN, http_tool=http).to_dict()
    assert before["baseline"]["available"] and before["auth"]["available"]
    entered, release = pause_evidence(monkeypatch)
    task = asyncio.create_task(call(registry, "start_validation", candidate_id=candidate.id))
    await asyncio.wait_for(entered.wait(), 5)
    assert candidate.status == "validated"
    if change in {"capture", "both"}:
        captures.clear()
    if change in {"auth", "both"}:
        http.permissions.reset()
    release.set()
    result = json.loads(await task)
    assert result["ok"] and result["candidate"]["status"] == "validating"
    context = result["validation_context"]
    assert context["baseline"]["available"] is (change == "auth")
    if change in {"capture", "auth"}:
        assert context["auth"]["available"]
        if change == "auth":
            assert context["auth"]["reason"] == "captured_credentials_require_permission"
            assert not http.permissions._capture_grants
    else:
        assert not context["auth"]["available"]


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["candidate", "replace_candidate", "objective", "input", "result", "target"])
async def test_state_changes_during_evidence_read_abort_before_bookkeeping(tmp_path, monkeypatch, change):
    state, registry, http, _, item, candidate = await terminal_fixture(tmp_path)
    entered, release = pause_evidence(monkeypatch)
    task = asyncio.create_task(call(registry, "start_validation", candidate_id=candidate.id))
    await asyncio.wait_for(entered.wait(), 5)
    if change == "candidate":
        candidate.parameter = "changed"
    elif change == "replace_candidate":
        state.candidates[candidate.id] = deepcopy(candidate)
    elif change == "objective":
        state.objective = WorkflowObjective("new", "whole_target", ORIGIN)
    elif change == "input":
        state.attack_surface_inputs[item["id"]].sample_payload = "changed"
    elif change == "result":
        state.add_validation_result(ValidationResult(candidate.id, "cross-site-scripting", "not-confirmed"))
    elif change == "target":
        http.target.set_base_url("https://other.test")
    expected = deepcopy(state.to_dict())
    release.set()
    output = await task
    assert output.startswith("error: validation state changed during evidence read")
    assert state.to_dict() == expected
    assert "validation_context" not in output


@pytest.mark.asyncio
async def test_cancelled_evidence_read_does_not_start_validation(tmp_path, monkeypatch):
    state, registry, _, _, _, candidate = await terminal_fixture(tmp_path)
    before = deepcopy(state.to_dict())
    entered, _ = pause_evidence(monkeypatch)
    task = asyncio.create_task(call(registry, "start_validation", candidate_id=candidate.id))
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert state.to_dict() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["capture", "candidate"])
async def test_real_sensitive_evidence_permission_await(tmp_path, change):
    state, registry, _, captures, _, candidate = await terminal_fixture(tmp_path)
    proof = tmp_path / ".env"
    proof.write_text("original fixture proof")
    artifact = EvidenceArtifact.capture(candidate.id, ".env", tmp_path, sensitive_read_approved=True)
    state.evidence = {artifact.id: artifact}
    state.validation_results[-1].evidence_refs = [artifact.id]
    proof.write_text("changed fixture proof")
    entered, release = asyncio.Event(), asyncio.Event()

    class PausingOperator:
        async def ask(self, request, signal=None):
            assert request.tool == "file" and request.no_session_cache
            entered.set()
            await release.wait()
            return Decision.ALLOW_ONCE

    task = asyncio.create_task(registry.execute("workflow", {
        "action": "start_validation", "candidate_id": candidate.id,
    }, None, PausingOperator()))
    await asyncio.wait_for(entered.wait(), 5)
    if change == "capture":
        captures.clear()
    else:
        candidate.parameter = "changed"
    before = deepcopy(state.to_dict())
    release.set()
    output = await task
    if change == "capture":
        assert not json.loads(output)["validation_context"]["baseline"]["available"]
    else:
        assert output.startswith("error: validation state changed")
        assert state.to_dict() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["inflight", "boundary"])
async def test_runtime_boundary_changes_do_not_partially_select_expert(tmp_path, monkeypatch, change):
    state, registry, http, _, _, candidate = await terminal_fixture(tmp_path)
    policy = ExecutionPolicy(http.engagement, tmp_path)
    prompter = YoloPrompter(AlwaysAllow(), False)
    prompter.bind_execution_policy(policy)
    entered, release = pause_evidence(monkeypatch)
    task = asyncio.create_task(registry.execute("workflow", {
        "action": "start_validation", "candidate_id": candidate.id,
    }, None, prompter))
    await asyncio.wait_for(entered.wait(), 5)
    boundary = policy.generic_validation
    before = deepcopy(state.to_dict())
    if change == "inflight":
        boundary.in_flight["another-attempt"] = 1
    else:
        workflow_tool = registry.get("workflow")
        assert isinstance(workflow_tool, WorkflowTool)
        policy.bind_validation_context(deepcopy(state), workflow_tool.skills, http.target)
    release.set()
    output = await task
    assert output.startswith("error:")
    assert state.to_dict() == before and candidate.status == "validated"
    assert boundary.expert_attempt is None and boundary.started_candidate is None
    assert policy.active == 0


TRANSIENT = {"baseline": {"state": "available", "available": True},
             "auth": {"state": "available", "available": True},
             "sample_payload": "TRANSIENT-FULL-SAMPLE"}
RESPONSE = {"ok": True, "candidate": {"id": "cand-fixture", "status": "validating"},
            "validator_resolution": "unique", "proof_source_path": None,
            "extra": {"trace": "preserve-me"}, "validation_context": TRANSIENT}


def wrapped(kind):
    raw = json.dumps(RESPONSE)
    if kind == "plain":
        return raw
    if kind == "fence":
        return "Response:\n```json\n" + raw + "\n```"
    if kind == "nested":
        return json.dumps({"metadata": "preserve-me", "response": RESPONSE})
    if kind == "mcp":
        return json.dumps({"content": [{"type": "text", "text": raw}], "metadata": "preserve-me"})
    if kind == "encoded":
        return json.dumps(raw)
    if kind == "double_encoded":
        return json.dumps(json.dumps(raw))
    if kind == "escaped":
        return raw.replace("validation_context", r"\u0076alidation_context")
    if kind == "truncated":
        return raw[:-5]
    if kind == "malformed":
        return raw.replace('"ok": true', '"ok": INVALID')
    raise AssertionError(kind)


@pytest.mark.parametrize("kind", ["plain", "fence", "nested", "mcp", "encoded", "double_encoded", "escaped", "truncated", "malformed"])
def test_omission_removes_whole_view_without_availability_ghost(kind):
    original = wrapped(kind)
    safe = without_transient_validation_context(original)
    assert "validation_context" not in safe and "TRANSIENT-FULL-SAMPLE" not in safe
    assert '"available"' not in safe
    assert without_transient_validation_context(safe) == safe
    if kind not in {"truncated", "malformed"}:
        for retained in ("preserve-me", "cand-fixture", "validating", "validator_resolution", "proof_source_path"):
            assert retained in safe
    else:
        assert "could not be separated safely" in safe


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["plain", "fence", "nested", "mcp", "encoded", "double_encoded", "escaped", "truncated", "malformed"])
async def test_save_load_and_compaction_omit_wrapped_transience(tmp_path, kind):
    original = wrapped(kind)
    message = Message("tool", original, name="workflow", tool_call_id="call",
                      tool_status="success", tool_truncated=kind == "truncated")
    session = Store.new_with_id(tmp_path / "sessions", "audit")
    await session.save([message])
    loaded = session.load().messages[0]
    assert loaded.content == without_transient_validation_context(original)
    assert loaded.tool_status == "success" and loaded.tool_call_id == "call"
    assert loaded.tool_truncated == message.tool_truncated
    assert message.content == original
    assert "TRANSIENT-FULL-SAMPLE" not in format_history_for_compaction([message], redact_payload=redact_payload)
    prior = deepcopy(message)
    elide_persisted_workflow_results([prior])
    assert "TRANSIENT-FULL-SAMPLE" not in prior.content and '"available"' not in prior.content
    # Also sanitize previously saved sessions, before a provider can replay them.
    session.path.write_text(json.dumps({"messages": [{"role": "tool", "name": "workflow", "content": original}]}))
    assert session.load().messages[0].content == loaded.content


def test_plain_candidate_metadata_survives_transient_key_mentions():
    content = json.dumps({"candidate": {"signals": ["validation_context is transient", "validation_context"]}})
    assert without_transient_validation_context(content) == content


def test_canonical_sample_and_template_with_same_named_parameter_remain_exact():
    sample = '{"validation_context":"safe input"}'
    template = '{"validation_context":"{INJECTION_POINT}"}'
    payload = deepcopy(RESPONSE)
    payload["candidate"].update(candidate_class="xss", request_template=template, signals=[sample])
    payload["input"] = {"id": "input_fixture", "objective_id": "fixture", "sample_payload": sample}
    safe = json.loads(without_transient_validation_context(json.dumps(payload)))
    assert safe["candidate"] == payload["candidate"] and safe["input"] == payload["input"]
    assert "validation_context" not in safe


@pytest.mark.asyncio
async def test_truncated_orphan_availability_cannot_survive_without_owning_key(tmp_path):
    fragment = '... "baseline": {"state": "available", "available": true}, "sample_payload": "TRANSIENT-FULL-SAMPLE" ...'
    message = Message("tool", fragment, name="workflow", tool_truncated=True, tool_status="success")
    session = Store.new_with_id(tmp_path, "orphan")
    await session.save([message])
    loaded = session.load().messages[0]
    assert "TRANSIENT-FULL-SAMPLE" not in loaded.content and '"available"' not in loaded.content
    assert loaded.tool_truncated and loaded.tool_status == "success"
    assert "TRANSIENT-FULL-SAMPLE" not in bounded_history_for_compaction([message])
    elide_persisted_workflow_results([message])
    assert '"available"' not in message.content


def test_compaction_omits_before_sampling_can_cut_away_key():
    response = deepcopy(RESPONSE)
    response["extra"]["padding"] = "P" * 20000
    response["validation_context"]["padding"] = "T" * 20000
    message = Message("tool", json.dumps(response), name="workflow")
    output = bounded_compaction([message], input_char_limit=2300,
                                format_history=lambda messages: format_history_for_compaction(messages, redact_payload=redact_payload),
                                sanitize_content=redact_payload)
    assert "TRANSIENT-FULL-SAMPLE" not in output and '"available"' not in output
    assert '"baseline"' not in output and '"auth"' not in output


@pytest.mark.asyncio
@pytest.mark.parametrize("interrupted", [False, True])
async def test_real_agent_current_turn_checkpoint_snapshot_and_retention(tmp_path, monkeypatch, interrupted):
    state, registry, http, _ = runtime(tmp_path)
    full_sample = '{"q":"' + "FULL-CANONICAL-SAMPLE-" * 150 + '"}'
    item, candidate = await linked(registry, sample_payload=full_sample, content_type="application/json")
    output = await call(registry, "start_validation", candidate_id=candidate["id"])
    workflow_tool = registry.get("workflow")
    assert isinstance(workflow_tool, WorkflowTool)
    assert workflow_tool.skills is not None
    agent = Agent(AgentOptions(client=FakeClient([]), tools=registry, skills=workflow_tool.skills,
                              target=http.target, workflow=state, prompter=AlwaysAllow(),
                              store=Store.new_with_id(tmp_path / "sessions", "audit"),
                              engagement_state=http.engagement, auto_compact_threshold=100000))
    assert agent.store is not None
    events = []
    working = list(agent.history)
    agent.record_tool_result(ToolCall("call", FunctionCall("workflow", "{}")),
                             ParsedToolCall({"action": "start_validation"}, "{}"),
                             ToolCallResult(output, "", 0), events.append, working,
                             defer_admission=True)
    assert json.loads(working[-1].content)["validation_context"]["sample_payload"] == full_sample
    assert source_provenance(agent, "workflow", {"action": "start_validation"}) is None
    assert not agent.result_retention.pending and not agent.result_retention.references
    assert registry.context_reduction_policy("workflow") == "preserve"
    if interrupted:
        # Exercise the shielded interruption checkpoint with an actual session write.
        entered, release = asyncio.Event(), asyncio.Event()
        save = agent.store.save

        async def delayed_save(*args, **kwargs):
            entered.set()
            await release.wait()
            await save(*args, **kwargs)

        monkeypatch.setattr(agent.store, "save", delayed_save)
        agent._tool_checkpoint_request = ChatRequest("fake-model", working)
        task = asyncio.create_task(agent._finish_tool_results())
        await asyncio.wait_for(entered.wait(), 5)
        task.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        await agent.save()
    saved = agent.store.load()
    assert "validation_context" not in agent.store.path.read_text()
    assert saved.workflow.candidates[candidate["id"]].status == "validating"
    assert saved.workflow.attack_surface_inputs[item["id"]].sample_payload == full_sample
    path = await agent.save_context_snapshot("audit")
    snapshot = Path(path).read_text()
    sample_body = "FULL-CANONICAL-SAMPLE-" * 150
    assert "validation_context" not in snapshot and sample_body not in snapshot
    assert sample_body not in agent.sys_prompt and sample_body not in agent.format_memory()
    # A canonical read's full sample also cannot become compaction memory input.
    lookup = await call(registry, "get_input", input_id=item["id"])
    history = [Message("tool", lookup, name="workflow")]
    elide_persisted_workflow_results(history)
    assert sample_body not in bounded_history_for_compaction(history)
    # Execute the real compaction path with an offline scripted provider.
    if not interrupted:
        seed_compactable_history(agent)
        agent.history.extend(history)
        client = FakeClient([ChatResponse(Message("assistant", "## Plan\n- Continue from canonical workflow records."), "stop")])
        agent.client = client
        await agent.compact(FakeSignal(), events.append)
        assert len(client.requests) == 1
        compact_input = "\n".join(message.content for message in client.requests[0].messages)
        assert "validation_context" not in compact_input and sample_body not in compact_input
        assert agent.memory is not None
        assert "validation_context" not in str(agent.memory) and sample_body not in str(agent.memory)
        assert sample_body not in agent.sys_prompt


@pytest.mark.asyncio
async def test_provider_encoders_use_omitted_resumed_tool_content(tmp_path):
    from src.llm.providers.anthropic import encode_message as anthropic_message
    from src.llm.providers.gemini import encode_message as gemini_message
    from src.llm.providers.openai import OpenAIClient

    session = Store.new_with_id(tmp_path, "encoders")
    await session.save([Message("tool", wrapped("mcp"), name="workflow", tool_call_id="call")])
    message = session.load().messages[0]
    bodies = [anthropic_message(message), gemini_message(message, model="fixture")]
    for label in ("openai", "openai-compat", "deepseek", "kimi", "groq", "xai"):
        client = OpenAIClient("https://unused.test", model="fixture", provider_name=label)
        bodies.append(client.encode_request(ChatRequest("fixture", [message]), False))
    for body in bodies:
        encoded = json.dumps(body)
        assert "TRANSIENT-FULL-SAMPLE" not in encoded and "validation_context" not in encoded
        assert "preserve-me" in encoded and "cand-fixture" in encoded


@pytest.mark.parametrize("kind", ["plain", "mcp", "truncated", "orphan"])
def test_actual_session_debug_sink_omits_context_without_mutating_ui_event(tmp_path, kind):
    from src.logger.session_debug import FileSessionDebugLog

    content = ('... "baseline": {"available": true}, "sample_payload": "TRANSIENT-FULL-SAMPLE"'
               if kind == "orphan" else wrapped(kind))
    event = {"type": "tool-result", "name": "workflow", "result": content, "id": "call",
             "status": "success", "duration_ms": 5, "truncated": kind in {"orphan", "truncated"}}
    before = deepcopy(event)
    path = tmp_path / "debug.jsonl"
    log = FileSessionDebugLog("audit", path)
    log.agent_event(event)
    # Direct write is the same sink; it cannot bypass event omission.
    log.write("agent_event", event)
    assert event == before
    for line in path.read_text().splitlines():
        saved = json.loads(line)
        assert "validation_context" not in saved["result"]
        assert "TRANSIENT-FULL-SAMPLE" not in saved["result"] and '"available"' not in saved["result"]
        assert saved["id"] == "call" and saved["status"] == "success" and saved["duration_ms"] == 5
        if kind in {"plain", "mcp"}:
            assert "cand-fixture" in saved["result"] and "preserve-me" in saved["result"]
