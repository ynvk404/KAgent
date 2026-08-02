from __future__ import annotations
import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, cast
import pytest
from . import anthropic as anthropic_module
from .anthropic import AnthropicClient, map_finish_reason
from .types import ChatRequest, FunctionCall, Message, ToolCall, ToolFunction, ToolSpec


# ---------------------------------------------------------------------------
# Mock server
# ---------------------------------------------------------------------------
@dataclass
class _Captured:
    last_body: dict[str, Any] | None = None
    last_api_key_header: str | None = None
    last_version_header: str | None = None


captured = _Captured()

# The mock server's canned /v1/messages response: one text block plus one
# tool_use block, matching what a real Claude response looks like.
_MOCK_RESPONSE = {
    "content": [
        {"type": "text", "text": "working"},
        {
            "type": "tool_use",
            "id": "toolu_abc123",
            "name": "http",
            "input": {"url": "https://example.com"},
        },
    ],
    "stop_reason": "tool_use",
}


class _MockHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass

    def do_GET(self) -> None:  # noqa: N802
        captured.last_api_key_header = self.headers.get("x-api-key")
        captured.last_version_header = self.headers.get("anthropic-version")
        if self.path == "/v1/models":
            self._send_json(200, {"models": []})
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        captured.last_api_key_header = self.headers.get("x-api-key")
        captured.last_version_header = self.headers.get("anthropic-version")

        if self.path != "/v1/messages":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        body_bytes = self.rfile.read(length) if length else b"{}"
        captured.last_body = json.loads(body_bytes.decode("utf-8"))

        self._send_json(200, _MOCK_RESPONSE)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def base_url():
    server = HTTPServer(("127.0.0.1", 0), _MockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    # anthropic.py builds paths as f"{base_url}/messages" / f"{base_url}/models",
    # so base_url must already carry the /v1 prefix.
    yield f"http://127.0.0.1:{port}/v1"
    server.shutdown()
    server.server_close()
    thread.join()


@pytest.fixture(autouse=True)
def _reset_captured():
    captured.last_body = None
    captured.last_api_key_header = None
    captured.last_version_header = None
    yield


# ---------------------------------------------------------------------------
# chat(): request encoding + response parsing
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_encodes_system_prompt_tool_turns_and_parses_tool_use(base_url, monkeypatch):
    # Keep this test deterministic regardless of which real models
    # anthropic_accepts_temperature() allows sampling params for.
    monkeypatch.setattr(anthropic_module, "anthropic_accepts_temperature", lambda model: True)

    c = AnthropicClient(base_url, "test-key", "claude-test", {"temperature": 0.5})
    req = ChatRequest(
        model="claude-test",
        messages=[
            Message(role="system", content="system prompt"),
            Message(role="user", content="test"),
            Message(
                role="assistant",
                content="",
                tool_calls=[
                    ToolCall(
                        id="toolu_grep1",
                        function=FunctionCall(name="grep", arguments='{"pattern":"x"}'),
                    )
                ],
            ),
            Message(role="tool", tool_call_id="toolu_grep1", content="matched"),
        ],
        tools=[
            ToolSpec(
                function=ToolFunction(
                    name="http",
                    description="make request",
                    parameters={
                        "type": "object",
                        "properties": {"url": {"type": "string"}},
                        "required": ["url"],
                    },
                )
            )
        ],
    )

    out = await c.chat(req)

    assert captured.last_api_key_header == "test-key"
    assert captured.last_version_header  # some non-empty anthropic-version value

    assert out.message.content == "working"
    assert out.finish_reason == "tool_calls"  # stop_reason "tool_use" maps to this

    assert out.message.tool_calls is not None
    tool_call = cast(dict, out.message.tool_calls[0])
    assert tool_call["id"] == "toolu_abc123"
    assert tool_call["function"]["name"] == "http"
    assert json.loads(tool_call["function"]["arguments"]) == {"url": "https://example.com"}

    assert captured.last_body is not None
    body = captured.last_body

    # System prompt is a top-level field, not a message.
    assert body["system"] == "system prompt"

    # Only non-system turns appear in messages: user, assistant(tool_use), tool(tool_result).
    messages = body["messages"]
    assert len(messages) == 3

    assert messages[0] == {"role": "user", "content": [{"type": "text", "text": "test"}]}

    assert messages[1]["role"] == "assistant"
    assert messages[1]["content"] == [
        {"type": "tool_use", "id": "toolu_grep1", "name": "grep", "input": {"pattern": "x"}}
    ]

    assert messages[2] == {
        "role": "user",
        "content": [{"type": "tool_result", "tool_use_id": "toolu_grep1", "content": "matched"}],
    }

    # Tools are encoded with input_schema, not "parameters".
    assert body["tools"] == [
        {
            "name": "http",
            "description": "make request",
            "input_schema": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        }
    ]

    assert body["temperature"] == 0.5


@pytest.mark.asyncio
async def test_drops_empty_assistant_turns_from_the_request(base_url, monkeypatch):
    monkeypatch.setattr(anthropic_module, "anthropic_accepts_temperature", lambda model: True)

    c = AnthropicClient(base_url, "test-key", "claude-test")
    req = ChatRequest(
        model="claude-test",
        messages=[
            Message(role="user", content="hi"),
            # An assistant turn with no text and no tool calls encodes to
            # nothing and must be dropped, not sent as a content-less block.
            Message(role="assistant", content=""),
        ],
    )

    await c.chat(req)

    assert captured.last_body is not None
    assert captured.last_body["messages"] == [
        {"role": "user", "content": [{"type": "text", "text": "hi"}]}
    ]


# ---------------------------------------------------------------------------
# max_tokens handling
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_falls_back_to_default_max_tokens_when_not_configured(base_url):
    c = AnthropicClient(base_url, "test-key", "claude-test")
    await c.chat(
        ChatRequest(model="claude-test", messages=[Message(role="user", content="hi")])
    )
    assert captured.last_body is not None

    from .providers import ANTHROPIC_DEFAULT_MAX_TOKENS

    assert captured.last_body["max_tokens"] == ANTHROPIC_DEFAULT_MAX_TOKENS


@pytest.mark.asyncio
async def test_uses_configured_max_tokens_when_positive(base_url):
    c = AnthropicClient(base_url, "test-key", "claude-test", {"maxTokens": 256})
    await c.chat(
        ChatRequest(model="claude-test", messages=[Message(role="user", content="hi")])
    )
    assert captured.last_body is not None
    assert captured.last_body["max_tokens"] == 256


# ---------------------------------------------------------------------------
# temperature gating
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_sends_temperature_when_the_model_accepts_it(base_url, monkeypatch):
    monkeypatch.setattr(anthropic_module, "anthropic_accepts_temperature", lambda model: True)

    c = AnthropicClient(base_url, "test-key", "claude-test", {"temperature": 0.7})
    await c.chat(
        ChatRequest(model="claude-test", messages=[Message(role="user", content="hi")])
    )
    assert captured.last_body is not None
    assert captured.last_body["temperature"] == 0.7


@pytest.mark.asyncio
async def test_omits_temperature_when_the_model_rejects_sampling_params(base_url, monkeypatch):
    # e.g. opus-4-7/4-8 and the Fable/Mythos 5 family 400 on any sampling param.
    monkeypatch.setattr(anthropic_module, "anthropic_accepts_temperature", lambda model: False)

    c = AnthropicClient(base_url, "test-key", "claude-test", {"temperature": 0.7})
    await c.chat(
        ChatRequest(model="claude-test", messages=[Message(role="user", content="hi")])
    )
    assert captured.last_body is not None
    assert "temperature" not in captured.last_body


# ---------------------------------------------------------------------------
# finish-reason mapping (pure function, no server needed)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "stop_reason,expected",
    [
        ("end_turn", "stop"),
        ("stop_sequence", "stop"),
        ("tool_use", "tool_calls"),
        ("max_tokens", "length"),
        ("refusal", "refusal"),  # unknown values pass through verbatim
        (None, ""),
    ],
)
def test_maps_stop_reason_to_finish_reason(stop_reason, expected):
    assert map_finish_reason(stop_reason) == expected


# ---------------------------------------------------------------------------
# ping()
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_pings_the_models_endpoint(base_url):
    c = AnthropicClient(base_url, "test-key", "claude-test")
    assert await c.ping() is None
    assert captured.last_api_key_header == "test-key"
    assert captured.last_version_header