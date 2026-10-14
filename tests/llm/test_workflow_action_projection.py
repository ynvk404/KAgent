"""Real provider encoders/transports, mocked HTTP only."""
from copy import deepcopy
import json
from typing import Any, cast

import httpx
import pytest

from src.config.config import Config
from src.llm.core.factory import new_from_config
from src.llm.core.types import ChatRequest, Message, ToolFunction, ToolSpec
from src.llm.providers import anthropic, gemini
from src.tools.workflow.action_view import ActionView
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.state import WorkflowState


@pytest.mark.parametrize("provider", ["openai-compat", "deepseek", "anthropic", "gemini"])
@pytest.mark.parametrize("mode", [None, "whole_target", "direct", "candidate_validation"])
@pytest.mark.parametrize("stream", [False, True])
def test_offline_encoding_projects_enum_and_rows_without_mutation(provider, mode, stream):
    tool = WorkflowTool(WorkflowState())
    original = [ToolSpec(ToolFunction(tool.name(), tool.description(), tool.schema()))]
    baseline = deepcopy(original)
    view = ActionView.for_objective(mode)
    tools = view.project_tools(original)
    request = ChatRequest("offline-fixture", [Message("user", "continue")], tools=tools, stream=stream)
    if provider in {"openai-compat", "deepseek"}:
        client = new_from_config(Config(backend=provider, base_url="https://fixture.invalid",
            model="offline-fixture", api_keys={provider: "synthetic"}))
        body = cast(Any, client).encode_request(request, stream)
        schema = body["tools"][0]["function"]["parameters"]
    elif provider == "anthropic":
        body = anthropic.encode_request(request, request.model)
        schema = body["tools"][0]["input_schema"]
    else:
        body = gemini.encode_request(request)
        schema = body["tools"][0]["functionDeclarations"][0]["parameters"]
    assert len(body["tools"]) == 1
    assert schema["properties"]["action"]["enum"] == list(view.available)
    rows = schema["properties"]["action"]["description"].splitlines()[1:]
    assert [row.partition("(")[0] for row in rows] == list(view.available)
    assert original == baseline
    assert not {"oneOf", "anyOf", "allOf"} & schema.keys()
    request.tools = None
    if provider in {"openai-compat", "deepseek"}:
        assert "tools" not in cast(Any, client).encode_request(request, stream)
    elif provider == "anthropic":
        assert "tools" not in anthropic.encode_request(request, request.model)
    else:
        assert "tools" not in gemini.encode_request(request)


@pytest.mark.parametrize("provider", ["openai-compat", "deepseek", "anthropic", "gemini"])
async def test_transport_retry_keeps_encoded_projection_snapshot(provider, monkeypatch):
    tool = WorkflowTool(WorkflowState())
    source = [{"type": "function", "function": {"name": tool.name(), "description": tool.description(), "parameters": tool.schema()}}]
    request = ChatRequest("offline-fixture", [Message("user", "continue")],
        tools=cast(Any, ActionView.for_objective("direct").project_tools(source)))
    bodies = []
    wire_payloads = []
    payload = ({"content": [{"type": "text", "text": "done"}], "stop_reason": "end_turn"}
        if provider == "anthropic" else {"candidates": [{"content": {"parts": [{"text": "done"}]}, "finishReason": "STOP"}]}
        if provider == "gemini" else {"choices": [{"message": {"role": "assistant", "content": "done"}, "finish_reason": "stop"}]})

    def respond(req):
        bodies.append(json.loads(req.content))
        wire_payloads.append(req.content)
        if len(bodies) == 1:
            # A transport retry must not derive another Agent action view.
            request.tools = cast(Any, ActionView.for_objective("whole_target").project_tools(source))
            return httpx.Response(503, json={"error": {"message": "offline transient"}})
        return httpx.Response(200, json=payload)

    module = "src.llm.providers." + ("openai" if provider in {"openai-compat", "deepseek"} else provider)
    monkeypatch.setattr(module + ".new_provider_async_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(respond)))
    if provider in {"openai-compat", "deepseek"}:
        client = new_from_config(Config(backend=provider, base_url="https://fixture.invalid", model="offline-fixture", api_keys={provider: "synthetic"}))
    else:
        client_type = anthropic.AnthropicClient if provider == "anthropic" else gemini.GeminiClient
        client = client_type("https://fixture.invalid", "synthetic", "offline-fixture")
    response = await client.chat(request)
    assert response.message.content == "done"
    assert len(bodies) == 2 and bodies[0] == bodies[1]
    assert wire_payloads[0] == wire_payloads[1]


@pytest.mark.parametrize("provider,stream", [
    ("anthropic", False), ("gemini", False), ("gemini", True),
])
async def test_retry_payload_detaches_nested_tools_and_gemini_replay(provider, stream, monkeypatch):
    tool = WorkflowTool(WorkflowState())
    tools = ActionView.for_objective("direct").project_tools([
        ToolSpec(ToolFunction(tool.name(), tool.description(), tool.schema()))])
    assert tools is not None
    spec = tools[0]
    assert isinstance(spec, ToolSpec)
    replay_args = {"action": "list"}
    request = ChatRequest("offline-fixture", [Message("user", "continue"),
        Message("assistant", "", provider_state_provider="gemini", provider_state_model="offline-fixture",
            gemini_parts=[{"functionCall": {"name": "workflow", "args": replay_args},
                           "thoughtSignature": "synthetic-signature"}])], tools=tools)
    bodies, wire_payloads = [], []
    clients = []
    payload = ({"content": [{"type": "text", "text": "done"}], "stop_reason": "end_turn"}
        if provider == "anthropic" else
        {"candidates": [{"content": {"parts": [{"text": "done"}]}, "finishReason": "STOP"}]})

    def respond(req):
        bodies.append(json.loads(req.content))
        wire_payloads.append(req.content)
        if len(bodies) == 1:
            # Exercise aliases inside the original typed tool and signed replay
            # part, without replacing either request field.
            spec.function.parameters["properties"]["action"]["enum"].append("record_input")
            replay_args["action"] = "record_result"
            return httpx.Response(503, json={"error": {"message": "offline transient"}})
        if stream:
            return httpx.Response(200, headers={"Content-Type": "text/event-stream"},
                content="data: " + json.dumps(payload) + "\n\n")
        return httpx.Response(200, json=payload)

    def new_client():
        client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
        clients.append(client)
        return client

    module = anthropic if provider == "anthropic" else gemini
    monkeypatch.setattr(module, "new_provider_async_client", new_client)
    client_type = anthropic.AnthropicClient if provider == "anthropic" else gemini.GeminiClient
    client = client_type("https://fixture.invalid", "synthetic", "offline-fixture")
    deltas = []
    if stream:
        assert isinstance(client, gemini.GeminiClient)
        response = await client.chat_stream(request, deltas.append)
        assert deltas == ["done"]
    else:
        response = await client.chat(request)
    assert response.message.content == "done"
    assert len(bodies) == 2 and bodies[0] == bodies[1]
    assert wire_payloads[0] == wire_payloads[1]
    assert all(transport.is_closed for transport in clients)
    if provider == "gemini":
        assert response.retry_count == 1 and response.retry_wait_ms is not None and response.retry_wait_ms > 0
