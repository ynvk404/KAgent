"""
Port of gemini.test.ts (Vitest) to Python (pytest + pytest-asyncio), matched
against the real `gemini.py` / `types.py` implementations.

Two runtime quirks in gemini.py that this test relies on:

1. `encode_message()` only forwards a tool call's `thoughtSignature` when
   `tc.provider` is a plain `dict` (it does `isinstance(tc_provider, dict)`).
   A `ToolProvider` dataclass instance would silently be dropped. So when
   *sending* a tool call we must set `provider={"gemini": {"thoughtSignature": ...}}`
   as a raw dict, not a `ToolProvider`/`GeminiProvider` dataclass.

2. `part_to_tool_call()` (used to build tool calls out of a model response)
   returns a plain `dict`, not a `ToolCall` dataclass. So when *reading* the
   parsed response, tool calls must be indexed like
   `tool_calls[0]["function"]["name"]`, not `.function.name`.

3. `_gen_opts()` reads camelCase keys off the `gen_opts` dict passed into
   `GeminiClient(...)`: `temperature`, `maxTokens`, `thinkingBudget`.

Note on Pylance: points (1) and (2) above are deliberate mismatches against
the static type hints (`ToolCall.provider: ToolProvider | None`,
`Message.tool_calls: list[ToolCall] | None`), because they reflect the actual
runtime shapes produced/consumed by gemini.py. `# type: ignore[arg-type]` and
`cast(...)` are used at exactly those spots to document the mismatch instead
of silencing typing project-wide. `assert ... is not None` calls are plain
Optional-narrowing, not behavior changes.

Run with:  pytest test_gemini.py
Requires:  pytest, pytest-asyncio, httpx
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, cast

import pytest

from .gemini import GeminiClient
from .types import ChatRequest, FunctionCall, Message, ToolCall, ToolFunction, ToolSpec


# ---------------------------------------------------------------------------
# Shared mutable state captured by the mock HTTP server (equivalent to the
# `lastBody` / `lastApiKeyHeader` module-level vars in the TS test).
# ---------------------------------------------------------------------------
@dataclass
class _Captured:
    last_body: dict[str, Any] | None = None
    last_api_key_header: str | None = None


captured = _Captured()


def _sse_event(obj: Any) -> bytes:
    return f"data: {json.dumps(obj)}\n\n".encode("utf-8")


class _MockHandler(BaseHTTPRequestHandler):
    # Silence default request logging.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass

    def do_GET(self) -> None:  # noqa: N802
        captured.last_api_key_header = self.headers.get("x-goog-api-key")
        if self.path == "/v1beta/models":
            self._send_json(200, {"models": []})
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        captured.last_api_key_header = self.headers.get("x-goog-api-key")

        is_stream = self.path == "/v1beta/models/gemini-test:streamGenerateContent?alt=sse"
        is_generate = self.path == "/v1beta/models/gemini-test:generateContent"

        if not is_stream and not is_generate:
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        body_bytes = self.rfile.read(length) if length else b"{}"
        captured.last_body = json.loads(body_bytes.decode("utf-8"))

        if is_stream:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()

            # A thought summary, then answer text split across two chunks,
            # then a function call with a finishReason.
            self.wfile.write(
                _sse_event(
                    {"candidates": [{"content": {"parts": [{"text": "pondering", "thought": True}]}}]}
                )
            )
            self.wfile.write(_sse_event({"candidates": [{"content": {"parts": [{"text": "wor"}]}}]}))
            self.wfile.write(_sse_event({"candidates": [{"content": {"parts": [{"text": "king"}]}}]}))
            self.wfile.write(
                _sse_event(
                    {
                        "candidates": [
                            {
                                "content": {
                                    "parts": [
                                        {
                                            "functionCall": {
                                                "name": "http",
                                                "args": {"url": "https://example.com"},
                                            },
                                            "thoughtSignature": "sig-http",
                                        }
                                    ]
                                },
                                "finishReason": "STOP",
                            }
                        ]
                    }
                )
            )
            self.wfile.flush()
            return

        # Plain (non-streaming) generateContent response.
        self._send_json(
            200,
            {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {"text": "working"},
                                {
                                    "functionCall": {
                                        "name": "http",
                                        "args": {"url": "https://example.com"},
                                    },
                                    "thoughtSignature": "sig-http",
                                },
                            ]
                        },
                        "finishReason": "STOP",
                    }
                ]
            },
        )

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
    # gemini.py builds paths as f"{base_url}/{model}:generateContent" etc, so
    # base_url must already include the /v1beta prefix, just like the TS mock.
    yield f"http://127.0.0.1:{port}/v1beta"
    server.shutdown()
    server.server_close()
    thread.join()


@pytest.fixture(autouse=True)
def _reset_captured():
    captured.last_body = None
    captured.last_api_key_header = None
    yield


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_encodes_messages_and_tools_and_parses_function_calls(base_url):
    c = GeminiClient(base_url, "test-key", "models/gemini-test")
    req = ChatRequest(
        model="models/gemini-test",
        messages=[
            Message(role="system", content="system prompt"),
            Message(role="user", content="test"),
            Message(
                role="assistant",
                content="",
                tool_calls=[
                    ToolCall(
                        id="call_1",
                        function=FunctionCall(name="grep", arguments='{"pattern":"x"}'),
                        # Must be a raw dict: encode_message only forwards the
                        # thoughtSignature when isinstance(provider, dict). This
                        # intentionally doesn't match the ToolProvider type hint.
                        provider={"gemini": {"thoughtSignature": "sig-grep"}},  # type: ignore[arg-type]
                    )
                ],
            ),
            Message(role="tool", name="grep", tool_call_id="call_1", content="matched"),
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
    assert out.message.content == "working"

    # part_to_tool_call() returns plain dicts, not ToolCall dataclasses, so the
    # ToolCall|None static type doesn't reflect the runtime shape here.
    assert out.message.tool_calls is not None
    tool_call = cast(dict, out.message.tool_calls[0])
    assert tool_call["function"]["name"] == "http"
    assert tool_call["function"]["arguments"] == '{"url": "https://example.com"}'
    assert tool_call["provider"]["gemini"]["thoughtSignature"] == "sig-http"

    assert captured.last_body is not None
    assert captured.last_body["systemInstruction"] == {"parts": [{"text": "system prompt"}]}

    contents = captured.last_body["contents"]
    assert contents[1]["parts"][0]["thoughtSignature"] == "sig-grep"

    tools = captured.last_body["tools"]
    assert tools[0]["functionDeclarations"][0]["parameters"] == {
        "type": "OBJECT",
        "properties": {"url": {"type": "STRING"}},
        "required": ["url"],
    }


@pytest.mark.asyncio
async def test_emits_generation_config_from_temperature_and_max_tokens(base_url):
    c = GeminiClient(
        base_url, "test-key", "models/gemini-test", gen_opts={"temperature": 0.4, "maxTokens": 512}
    )
    await c.chat(
        ChatRequest(model="models/gemini-test", messages=[Message(role="user", content="hi")])
    )
    assert captured.last_body is not None
    assert captured.last_body["generationConfig"] == {"temperature": 0.4, "maxOutputTokens": 512}


@pytest.mark.asyncio
async def test_omits_generation_config_when_no_gen_opts_configured(base_url):
    c = GeminiClient(base_url, "test-key", "models/gemini-test")
    await c.chat(
        ChatRequest(model="models/gemini-test", messages=[Message(role="user", content="hi")])
    )
    assert captured.last_body is not None
    assert "generationConfig" not in captured.last_body


@pytest.mark.asyncio
async def test_emits_thinking_config_to_disable_thinking_when_budget_is_zero(base_url):
    c = GeminiClient(base_url, "test-key", "models/gemini-test", gen_opts={"thinkingBudget": 0})
    await c.chat(
        ChatRequest(model="models/gemini-test", messages=[Message(role="user", content="hi")])
    )
    assert captured.last_body is not None
    assert captured.last_body["generationConfig"] == {"thinkingConfig": {"thinkingBudget": 0}}


@pytest.mark.asyncio
async def test_caps_thinking_and_requests_thought_summaries_for_positive_budget(base_url):
    c = GeminiClient(base_url, "test-key", "models/gemini-test", gen_opts={"thinkingBudget": 256})
    await c.chat(
        ChatRequest(model="models/gemini-test", messages=[Message(role="user", content="hi")])
    )
    assert captured.last_body is not None
    assert captured.last_body["generationConfig"] == {
        "thinkingConfig": {"thinkingBudget": 256, "includeThoughts": True}
    }


@pytest.mark.asyncio
async def test_streams_answer_deltas_surfaces_thoughts_and_parses_tool_calls(base_url):
    c = GeminiClient(base_url, "test-key", "models/gemini-test")
    deltas: list[str] = []

    out = await c.chat_stream(
        ChatRequest(
            model="models/gemini-test",
            messages=[Message(role="user", content="hi")],
            stream=True,
        ),
        lambda d: deltas.append(d),
    )

    # Thought summary is streamed as progress but kept out of the message.
    assert deltas == ["pondering", "wor", "king"]
    assert out.message.content == "working"
    assert out.finish_reason == "STOP"

    assert out.message.tool_calls is not None
    tool_call = cast(dict, out.message.tool_calls[0])
    assert tool_call["function"]["name"] == "http"
    assert tool_call["function"]["arguments"] == '{"url": "https://example.com"}'
    assert tool_call["provider"]["gemini"]["thoughtSignature"] == "sig-http"


@pytest.mark.asyncio
async def test_pings_the_model_list_endpoint(base_url):
    c = GeminiClient(base_url, "test-key", "models/gemini-test")
    assert await c.ping() is None