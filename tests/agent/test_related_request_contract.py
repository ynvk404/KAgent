"""The actual Agent/provider path sees a failed association and its repair hint."""
from copy import deepcopy
import json

import httpx
import pytest

from src.agent.agent import AgentRunOptions, elide_persisted_workflow_results
from src.llm.core.types import ChatRequest, FunctionCall, Message, ToolCall
from src.llm.providers import anthropic, gemini
from src.llm.providers.openai import OpenAIClient
from src.session.store import Store
from src.tools.workflow.action_view import ActionView
from tests.agent.test_workflow_request_preparation import (
    setup, call, block, SnapshotClient, StreamingSnapshotClient,
)
from tests.helpers.agent_fakes import FakeSignal, seed_compactable_history


async def create_candidate(agent):
    return json.loads(await agent.tools.execute("workflow", {
        "action": "record_candidate", "candidate_class": "sqli", "endpoint": "/login",
        "method": "POST", "parameter": "email", "location": "body",
    }, None, agent.prompter))["candidate"]["id"]


def duplicate_args(cid):
    return {"action": "start_validation", "candidate_id": cid, "related_requests": [
        {"role": "baseline", "method": "POST", "url": "/login"},
        {"role": "trigger", "method": "POST", "url": "/login"},
    ]}


def check_message(message):
    assert message.role == "tool" and message.name == "workflow"
    assert message.tool_status == "error" and message.tool_error_kind == "workflow_state"
    payload = json.loads(message.content.partition("\n")[2])
    assert payload["ok"] is False
    assert payload["error"]["code"] == "DUPLICATE_REQUEST_ASSOCIATION"
    assert payload["error"]["indices"] == [0, 1] and payload["error"]["repair_hint"]
    assert message.tool_result_refs is None
    return payload


@pytest.mark.parametrize("streaming", [False, True])
async def test_next_production_request_receives_structured_error_then_explicit_correction(tmp_path, monkeypatch, streaming):
    def no_http(*args, **kwargs):
        raise AssertionError("workflow argument repair must not send HTTP")
    monkeypatch.setattr("httpx.AsyncClient", no_http)
    monkeypatch.setattr("src.agent.tool_results.project_root", lambda: tmp_path)
    client = StreamingSnapshotClient([]) if streaming else SnapshotClient([])
    agent = setup(tmp_path, client)
    agent.streaming_enabled = streaming
    cid = await create_candidate(agent)
    client.scripted = [call("start_validation", **{k: v for k, v in duplicate_args(cid).items() if k != "action"}),
        call("start_validation", candidate_id=cid),
        call("record_result", candidate_id=cid, skill_name="sql-injection", outcome="insufficient-evidence",
             notes="Offline fixture: no probes or proof"),
        # Tool-free max-step synthesis uses the existing Agent controller.
    ]
    from src.llm.core.types import ChatResponse
    client.scripted.append(ChatResponse(Message("assistant", "No evidence collected."), "stop"))
    events = []
    await agent.run("Continue the recorded candidate", FakeSignal(), events.append, AgentRunOptions(max_steps=3))
    rejected = next(m for m in client.requests[1].messages if m.role == "tool")
    check_message(rejected)
    guidance = block(client.requests[0], "Workflow action guidance:")
    assert "start_validation(candidate_id)" in guidance and "Candidate covers" in guidance
    assert "Available = exposed for consideration, not permission or guaranteed execution." in guidance
    assert "Recommended = conditional on current runtime state." in guidance
    assert "Excluded = incompatible with the verified objective contract." in guidance
    failures = [event for event in events if event.type == "tool-result" and event.status == "error"]
    assert len(failures) == 1 and "DUPLICATE_REQUEST_ASSOCIATION" in failures[0].result
    assert len(agent.workflow.attempts) == len(agent.workflow.validation_results) == 1
    assert not agent.workflow.evidence and not agent.workflow.eligible_for_finding(cid)
    assert agent.workflow.attempts[next(iter(agent.workflow.attempts))]["related_requests"] == []
    # Prior-turn elision only consumes real successful receipts.
    elide_persisted_workflow_results(agent.history)
    check_message(next(m for m in agent.history if m.role == "tool" and m.tool_status == "error"))


async def test_retention_session_and_compaction_never_publish_rejection_as_success(tmp_path, monkeypatch):
    monkeypatch.setattr("src.agent.tool_results.project_root", lambda: tmp_path)
    agent = setup(tmp_path)
    agent.store = Store.new_with_id(tmp_path / "sessions", "association-session")
    from src.agent.tool_results import ResultRetention
    agent.result_retention = ResultRetention(agent)
    cid = await create_candidate(agent)
    seed_compactable_history(agent, 24000)
    agent.history.append(Message("user", "Start the recorded validation"))
    before, revision = deepcopy(agent.workflow.to_dict()), agent.workflow.committed_revision
    working = list(agent.history)
    tc = ToolCall("duplicate-start", FunctionCall("workflow", json.dumps(duplicate_args(cid))))
    await agent.execute_tool_calls([tc], FakeSignal(), lambda event: None, working)
    rejected = working[-1]
    payload = check_message(rejected)
    agent.result_retention.admit(working, agent.tools_token_estimate(), threshold=1, strict=True)
    assert not agent.result_retention.pending and not agent.result_retention.references
    assert check_message(working[-1]) == payload
    await agent.save()
    saved = agent.store.load()
    check_message(next(m for m in saved.messages if m.tool_status == "error"))
    # Full compaction summarizes old tool traffic; canonical state stays the
    # authority and no success receipt is synthesized for the rejected start.
    await agent.apply_compaction_summary(
        "## Objectives\n- Continue the recorded candidate\n## Completed\n- Duplicate arguments were rejected; no validation started",
        deepcopy(agent.history), "offline association contract")
    assert agent.workflow.to_dict() == before and agent.workflow.committed_revision == revision
    assert not agent.workflow.attempts and not agent.workflow.eligible_for_finding(cid)
    assert not any(m.role == "tool" and m.tool_status == "success" for m in agent.history)
    request = ChatRequest(agent.client.model(), list(agent.history), tools=agent.tools.as_llm_tools())
    await agent._chat_for_turn(request, FakeSignal(), lambda event: None)
    assert isinstance(agent.client, SnapshotClient)
    current = agent.client.requests[-1]
    assert "start_validation(candidate_id)" in block(current, "Workflow action guidance:")
    workflow = block(current, "Untrusted recorded workflow data;")
    assert cid in workflow and "status=queued" in workflow


@pytest.mark.parametrize("provider", ["openai-compat", "deepseek", "anthropic", "gemini"])
async def test_schema_examples_and_error_text_survive_supported_provider_encoding(tmp_path, provider):
    agent = setup(tmp_path)
    cid = await create_candidate(agent)
    output = await agent.tools.execute("workflow", duplicate_args(cid), None, agent.prompter)
    tool = agent.tools.get("workflow")
    assert tool is not None
    local = tool.schema()
    primary = json.loads(local["properties"]["candidate_id"]["description"].partition("Example: ")[2])
    supplementary = json.loads(local["properties"]["related_requests"]["description"].partition("readback: ")[2])
    assert primary == {"action": "start_validation", "candidate_id": "<returned candidate.id>"}
    assert supplementary["related_requests"] == [{"role": "readback", "method": "GET", "url": "/comments/123"}]
    related = local["properties"]["related_requests"]
    assert "resolved/redacted" in related["description"] and "observations" in related["description"]
    assert "required defaults to true, except cleanup defaults to false" in related["description"]
    for field in (local, local["properties"]["candidate_id"], related, related["items"]):
        assert not {"oneOf", "anyOf", "allOf", "if", "then", "else", "uniqueItems"} & field.keys()
    specs = ActionView.for_objective("direct").project_tools(agent.tools.as_llm_tools())
    original = deepcopy(specs)
    tc = ToolCall("duplicate", FunctionCall("workflow", json.dumps(duplicate_args(cid))))
    messages = [Message("user", "Continue"), Message("assistant", "", tool_calls=[tc]),
        Message("tool", str(output), tool_call_id=tc.id, name="workflow", tool_status="error", tool_error_kind="workflow_state")]
    request = ChatRequest("offline-fixture", messages, tools=specs)
    if provider in {"openai-compat", "deepseek"}:
        encoded = OpenAIClient("https://fixture.invalid", "synthetic", "offline-fixture").encode_request(request, False)
        schema = encoded["tools"][0]["function"]["parameters"]
    elif provider == "anthropic":
        encoded = anthropic.encode_request(request, request.model)
        schema = encoded["tools"][0]["input_schema"]
    else:
        encoded = gemini.encode_request(request)
        schema = encoded["tools"][0]["functionDeclarations"][0]["parameters"]
    assert specs == original
    assert schema["properties"]["candidate_id"]["description"] == local["properties"]["candidate_id"]["description"]
    assert schema["properties"]["related_requests"]["description"] == related["description"]
    body = json.dumps(encoded)
    error = json.loads(output.partition("\n")[2])["error"]
    assert error["code"] in body and json.dumps(error["repair_hint"])[1:-1] in body


@pytest.mark.parametrize("provider", ["openai-compat", "deepseek", "anthropic", "gemini"])
async def test_unchanged_request_keeps_contract_and_error_on_transport_retry(tmp_path, monkeypatch, provider):
    agent = setup(tmp_path)
    cid = await create_candidate(agent)
    output = await agent.tools.execute("workflow", duplicate_args(cid), None, agent.prompter)
    tc = ToolCall("duplicate", FunctionCall("workflow", json.dumps(duplicate_args(cid))))
    request = ChatRequest("offline-fixture", [Message("user", "Continue"),
        Message("assistant", "", tool_calls=[tc]),
        Message("tool", str(output), tool_call_id=tc.id, name="workflow", tool_status="error", tool_error_kind="workflow_state")],
        tools=ActionView.for_objective("direct").project_tools(agent.tools.as_llm_tools()))
    original = deepcopy(request)
    bodies = []
    if provider == "anthropic":
        client = anthropic.AnthropicClient("https://fixture.invalid", "synthetic", request.model)
        payload = {"content": [{"type": "text", "text": "Correct arguments using the supplied hint."}], "stop_reason": "end_turn"}
    elif provider == "gemini":
        client = gemini.GeminiClient("https://fixture.invalid", "synthetic", request.model)
        payload = {"candidates": [{"content": {"parts": [{"text": "Correct arguments using the supplied hint."}]}, "finishReason": "STOP"}]}
    else:
        from src.config.config import Config
        from src.llm.core.factory import new_from_config
        client = new_from_config(Config(backend=provider, base_url="https://fixture.invalid",
            model=request.model, api_keys={provider: "synthetic"}))
        payload = {"choices": [{"message": {"role": "assistant", "content": "Correct arguments using the supplied hint."}, "finish_reason": "stop"}]}

    def respond(req):
        bodies.append(json.loads(req.content))
        if len(bodies) == 1:
            return httpx.Response(503, json={"error": {"message": "offline transient"}}, headers={"Retry-After": "0"})
        return httpx.Response(200, json=payload)

    module = "src.llm.providers." + ("openai" if provider in {"openai-compat", "deepseek"} else provider)
    monkeypatch.setattr(module + ".new_provider_async_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(respond)))
    response = await client.chat(request)
    assert response.message.content and len(bodies) == 2 and bodies[0] == bodies[1]
    assert request == original
    for body in bodies:
        text = json.dumps(body)
        assert "DUPLICATE_REQUEST_ASSOCIATION" in text and "repair_hint" in text
        assert "resolved/redacted" in text
