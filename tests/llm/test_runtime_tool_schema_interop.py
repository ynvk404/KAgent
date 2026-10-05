"""Runtime registry -> real provider encoders/clients, with offline transports."""
from copy import deepcopy
from dataclasses import asdict
from typing import Any, cast

import pytest
import httpx

from src.agent.agent import AgentRunOptions
from src.llm.core.types import ChatRequest, Message, ToolFunction, ToolSpec
from src.llm.providers import anthropic, gemini
from src.tools.common.registry import Registry
from src.tools.execution.file import FileReadTool
from tests.agent.test_token_accounting_independent_verify import make_agent
from tests.helpers.agent_fakes import FakeSignal

PARAMETERS = {"type": "object", "properties": {
    "rows": {"type": "array", "items": {"type": "object", "properties": {
        "value": {"type": "string", "enum": ["a", "b"]}}, "required": ["value"]}}},
    "required": ["rows"], "additionalProperties": False}


def declaration(provider, body):
    return body["tools"][0] if provider == "anthropic" else body["tools"][0]["functionDeclarations"][0]


def encode(provider, req):
    return anthropic.encode_request(req, req.model) if provider == "anthropic" else gemini.encode_request(req)


@pytest.mark.parametrize("provider", ["anthropic", "gemini"])
@pytest.mark.parametrize("representation", ["registry", "dict", "typed", "empty"])
def test_tool_schema_encoding_preserves_nested_semantics(provider, representation):
    parameters = deepcopy(PARAMETERS)
    spec = ToolSpec(ToolFunction("nested", "description", parameters))
    if representation == "registry":
        registry = Registry()
        tool = FileReadTool()
        tool.schema = lambda: parameters
        registry.register(tool)
        tools = registry.as_llm_tools()
        name = "file_read"
    else:
        tools = [] if representation == "empty" else [cast(Any, asdict(spec)) if representation == "dict" else spec]
        name = "nested"
    before = deepcopy(tools)
    body = encode(provider, ChatRequest("fixture", [Message("user", "next")], tools=tools))
    assert tools == before and parameters == PARAMETERS
    if representation == "empty":
        assert "tools" not in body
        return
    decl = declaration(provider, body)
    assert decl["name"] == name
    schema = decl["input_schema" if provider == "anthropic" else "parameters"]
    if provider == "anthropic":
        assert schema == PARAMETERS
    else:
        assert schema["type"] == "OBJECT" and "additionalProperties" not in schema
        assert schema["required"] == ["rows"]
        items = schema["properties"]["rows"]["items"]
        assert items["type"] == "OBJECT" and items["required"] == ["value"]
        assert items["properties"]["value"] == {"type": "STRING", "enum": ["a", "b"]}


@pytest.mark.parametrize("provider", ["anthropic", "gemini"])
@pytest.mark.parametrize("bad", [None, {}, {"type": "other", "function": {}},
    {"type": "function", "function": None},
    {"type": "function", "function": {"name": "", "parameters": {}}},
    {"type": "function", "function": {"name": "f", "parameters": []}},
    {"type": "function", "function": {"name": "f", "description": 1, "parameters": {}}},
    ToolSpec(cast(Any, None))])
def test_malformed_tools_fail_clearly(provider, bad):
    with pytest.raises(ValueError, match="invalid tool specification"):
        encode(provider, ChatRequest("fixture", [Message("user", "next")], tools=[cast(Any, bad)]))


@pytest.mark.parametrize("provider", ["anthropic", "gemini"])
@pytest.mark.parametrize("retry", [False, True])
async def test_actual_registry_agent_client_sends_provider_payload(provider, monkeypatch, retry):
    module = anthropic if provider == "anthropic" else gemini
    payload = ({"content": [{"type": "text", "text": "done"}], "stop_reason": "end_turn"}
        if provider == "anthropic" else
        {"candidates": [{"content": {"parts": [{"text": "done"}]}, "finishReason": "STOP"}]})
    bodies = []
    class Transport:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def post(self, url, **kwargs):
            bodies.append(deepcopy(kwargs["json"]))
            if retry and len(bodies) == 1:
                return httpx.Response(503, json={"error": {"message": "offline transient failure"}})
            return httpx.Response(200, json=deepcopy(payload))
    monkeypatch.setattr(module, "new_provider_async_client", Transport)
    client_type = anthropic.AnthropicClient if provider == "anthropic" else gemini.GeminiClient
    registry = Registry()
    tool = FileReadTool()
    tool.schema = lambda: deepcopy(PARAMETERS)
    registry.register(tool)
    agent = make_agent(tools=registry, client=client_type("https://fixture.invalid", "synthetic", "fixture"))
    client_invocations = []
    original_chat = agent.client.chat
    async def chat(request, signal=None):
        client_invocations.append(deepcopy(request))
        return await original_chat(request, signal)
    monkeypatch.setattr(agent.client, "chat", chat)
    events = []
    await agent.run("Describe the available tools", FakeSignal(), events.append, AgentRunOptions(max_steps=1))
    assert events[-1].stop_reason == "final_response"
    assert len(bodies) == (2 if retry else 1)
    assert len(client_invocations) == events[-1].total_llm_calls == 1
    assert len(agent.request_metrics.records) == 1
    decl = declaration(provider, bodies[0])
    assert decl["name"] == "file_read"
    schema = decl["input_schema" if provider == "anthropic" else "parameters"]
    assert schema["properties"]["rows"]["items"]["required"] == ["value"]
