from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from src.llm import openai as openai_module
from src.llm import transport
from src.browser.store import CaptureStore
from src.llm.openai import OpenAIClient
from src.llm.types import ChatRequest, Message, ToolFunction, ToolSpec
from src.tools.browser_capture import BrowserCaptureClearTool
from src.tools.ask import AskUserTool
from src.ask.ask import FirstOptionPrompter
from src.tools.registry import Registry as ToolRegistry

server: HTTPServer | None = None
base_url = ""

last_body: dict[str, object] = {}
last_headers: dict[str, str] = {}

proxy_rate_limit_calls = 0

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/v1/models":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"data": []}).encode())
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        global last_body
        global last_headers
        global proxy_rate_limit_calls

        length = int(self.headers["Content-Length"])
        body = self.rfile.read(length)
        last_body = json.loads(body.decode())
        last_headers = dict(self.headers)

        if self.path != "/v1/chat/completions":
            self.send_response(404)
            self.end_headers()
            return

        model = last_body["model"]

        if last_body.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()

            def send(obj):
                self.wfile.write(("data: " + json.dumps(obj) + "\n\n").encode())

            if model in {"reasoning-stream", "deepseek-reasoning-stream", "kimi-k2.6"}:
                send({
                    "choices": [{
                        "delta": {"reasoning_content": "Let me think..."}
                    }]
                })
                send({
                    "choices": [{
                        "delta": {"content": "The answer "}
                    }]
                })
                send({
                    "choices": [{
                        "delta": {"content": "is 42."}
                    }]
                })
            else:
                send({
                    "choices": [{
                        "delta": {"content": "Working"}
                    }]
                })
                send({
                    "choices": [{
                        "delta": {"content": " on it"}
                    }]
                })
                send({
                    "choices": [{
                        "delta": {
                            "tool_calls": [{
                                "index": 0,
                                "id": "call_abc",
                                "function": {
                                    "name": "http",
                                    "arguments": '{"url":'
                                }
                            }]
                        }
                    }]
                })
                send({
                    "choices": [{
                        "delta": {
                            "tool_calls": [{
                                "index": 0,
                                "function": {
                                    "arguments": '"https://x.example.com"}'
                                }
                            }]
                        }
                    }]
                })

            send({
                "choices": [{
                    "delta": {},
                    "finish_reason": "tool_calls",
                }]
            })
            send({
                "choices": [],
                "usage": {
                    "prompt_tokens": 100, "completion_tokens": 30, "total_tokens": 130,
                    "prompt_tokens_details": {"cached_tokens": 20},
                    "completion_tokens_details": {"reasoning_tokens": 10},
                },
            })
            self.wfile.write(b"data: [DONE]\n\n")
            return

        if model == "proxy-200-ratelimit":
            proxy_rate_limit_calls += 1
            if proxy_rate_limit_calls == 1:
                response = {
                    "error": {
                        "message": "Rate limit exceeded"
                    }
                }
            else:
                response = {
                    "choices": [{
                        "message": {
                            "role": "assistant",
                            "content": "recovered",
                        },
                        "finish_reason": "stop",
                    }]
                }
        elif model in {"deepseek-reasoning", "kimi-k2.6"}:
            response = {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "final answer",
                        "reasoning_content": "private reasoning",
                    },
                    "finish_reason": "tool_calls",
                }]
            }
        elif model == "glm-leak":
            response = {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "Hi!<|user|>hello",
                    }
                }]
            }
        else:
            response = {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "hi",
                    },
                    "finish_reason": "stop",
                }]
            }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

@pytest.fixture(scope="module", autouse=True)
def start_server():
    global server
    global base_url

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}/v1"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield

    server.shutdown()

def _req(model: str, content: str = "hi") -> ChatRequest:
    return ChatRequest(
        model=model,
        messages=[Message(role="user", content=content)],
    )

pytestmark = pytest.mark.asyncio

async def test_non_stream_chat():
    c = OpenAIClient(base_url, "", "qwen")
    out = await c.chat(_req("qwen"))
    assert out.message.content == "hi"


async def test_official_openai_luna_uses_chat_tool_compatible_parameters():
    client = OpenAIClient(base_url, "official-key", "gpt-6-luna", "openai", gen_opts={"max_tokens": 200})
    body = client.encode_request(ChatRequest(
        model="gpt-6-luna", messages=[Message(role="user", content="hello")],
        tools=[ToolSpec(function=ToolFunction(name="noop", description="", parameters={"type": "object"}))],
    ), stream=False)
    assert body["reasoning_effort"] == "none"
    assert body["max_completion_tokens"] == 200
    assert "max_tokens" not in body
    assert body["tools"][0]["function"]["name"] == "noop"
    assert client.name() == "openai"

    manual = OpenAIClient(base_url, "manual-key", "gpt-6-luna", "openai-compat")
    assert "reasoning_effort" not in manual.encode_request(_req("gpt-6-luna"), False)


async def test_ping_streaming_and_non_streaming_share_provider_transport(monkeypatch):
    calls = []
    real_factory = transport.new_provider_async_client

    def recording_factory(timeout=transport.CHAT_TIMEOUT_SEC):
        calls.append(timeout)
        return real_factory(timeout)

    monkeypatch.setattr(openai_module, "new_provider_async_client", recording_factory)
    monkeypatch.setattr(transport, "new_provider_async_client", recording_factory)

    c = OpenAIClient(base_url, "", "qwen")
    await c.ping()
    await c.chat(_req("qwen"))
    await c.chat_stream(_req("qwen"), lambda _: None)

    assert calls == [
        transport.PING_TIMEOUT_SEC,
        transport.CHAT_TIMEOUT_SEC,
        transport.CHAT_TIMEOUT_SEC,
    ]


async def test_serializes_browser_capture_clear_schema_without_action_argument():
    tools = ToolRegistry()
    tools.register(BrowserCaptureClearTool(CaptureStore()))
    request = ChatRequest(
        model="qwen",
        messages=[Message(role="user", content="clear")],
        tools=tools.as_llm_tools(),
    )

    body = OpenAIClient(base_url, "", "qwen").encode_request(request, False)
    function = body["tools"][0]["function"]

    assert function["name"] == "browser_capture_clear"
    assert function["parameters"] == {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    }
    assert "action" not in function["parameters"]["properties"]


async def test_serializes_ask_user_with_optional_options():
    tools = ToolRegistry()
    tools.register(AskUserTool(FirstOptionPrompter()))
    body = OpenAIClient(base_url, "", "qwen").encode_request(
        ChatRequest(
            model="qwen",
            messages=[Message(role="user", content="reset")],
            tools=tools.as_llm_tools(),
        ),
        False,
    )
    function = body["tools"][0]["function"]
    question = function["parameters"]["properties"]["questions"]["items"]

    assert "blocks same-turn work" in function["description"]
    assert "does not approve actions or replace a runtime permission prompt" in function["description"]
    assert question["required"] == ["question"]
    assert question["properties"]["options"]["minItems"] == 2
    assert "arbitrary user-supplied values" in question["properties"]["options"]["description"]

async def test_stream_reasoning_content():
    c = OpenAIClient(base_url, "", "reasoning-stream")
    deltas = []
    out = await c.chat_stream(_req("reasoning-stream", "go"), lambda x: deltas.append(x))

    assert "Let me think..." not in "".join(deltas)
    assert out.message.content == "The answer is 42."
    assert out.message.reasoning_content is None
    assert out.usage is not None and out.usage.reasoning_tokens == 10

async def test_deepseek_keeps_reasoning_separate_and_does_not_stream_it():
    c = OpenAIClient(base_url, "", "deepseek-reasoning-stream", "deepseek")
    deltas = []
    out = await c.chat_stream(
        _req("deepseek-reasoning-stream", "go"), lambda x: deltas.append(x)
    )

    assert "Let me think..." not in "".join(deltas)
    assert out.message.content == "The answer is 42."
    assert out.message.reasoning_content == "Let me think..."
    assert out.usage is not None and out.usage.cached_input_tokens == 20

async def test_deepseek_non_stream_keeps_reasoning_separate():
    c = OpenAIClient(base_url, "", "deepseek-reasoning", "deepseek")
    out = await c.chat(_req("deepseek-reasoning"))

    assert out.message.content == "final answer"
    assert out.message.reasoning_content == "private reasoning"


async def test_kimi_stream_and_non_stream_keep_reasoning_private():
    client = OpenAIClient(base_url, "", "kimi-k2.6", "kimi")
    request = ChatRequest(model="kimi-k2.6", messages=[Message(role="user", content="go")],
                          thinking_enabled=True)
    deltas = []
    streamed = await client.chat_stream(request, deltas.append)
    assert streamed.message.content == "The answer is 42."
    assert streamed.message.reasoning_content == "Let me think..."
    assert "Let me think..." not in "".join(deltas)
    assert streamed.message.provider_state_provider == "kimi"

    plain = await client.chat(request)
    assert plain.message.content == "final answer"
    assert plain.message.reasoning_content == "private reasoning"
    assert plain.message.provider_state_model == "kimi-k2.6"

async def test_deepseek_replays_reasoning_and_honors_thinking_toggle():
    c = OpenAIClient(base_url, "", "deepseek-flash", "deepseek", gen_opts={"temperature": 0.3})
    req = ChatRequest(
        model="ignored-by-configured-client",
        messages=[
            Message(role="user", content="Find this"),
            Message(
                role="assistant",
                content="I'll look it up.",
                reasoning_content="Need to call search.",
                provider_state_provider="deepseek",
                provider_state_model="deepseek-flash",
            ),
            Message(role="tool", content="result", tool_call_id="call_1"),
        ],
        tools=[],
        thinking_enabled=True,
    )

    body = c.encode_request(req, stream=False)

    assert body["model"] == "deepseek-flash"
    assert body["thinking"] == {"type": "enabled"}
    assert "temperature" not in body
    assert body["messages"][1]["reasoning_content"] == "Need to call search."

    disabled = c.encode_request(
        ChatRequest(model="x", messages=[], thinking_enabled=False), stream=False
    )
    assert disabled["thinking"] == {"type": "disabled"}
    assert disabled["temperature"] == 0.3

async def test_non_deepseek_does_not_send_reasoning_content():
    c = OpenAIClient(base_url, "", "qwen")
    body = c.encode_request(
        ChatRequest(
            model="qwen",
            messages=[
                Message(role="assistant", content="answer", reasoning_content="state")
            ],
        ),
        stream=False,
    )

    assert "reasoning_content" not in body["messages"][0]

async def test_stream_tool_call_fragment():
    c = OpenAIClient(base_url, "", "qwen")
    out = await c.chat_stream(_req("qwen", "scan"), lambda x: None)

    assert out.message.tool_calls is not None
    tool = out.message.tool_calls[0]
    assert tool.id == "call_abc"
    assert tool.function.name == "http"
    assert tool.function.arguments == '{"url":"https://x.example.com"}'

async def test_stream_preserves_response_when_delta_callback_raises():
    c = OpenAIClient(base_url, "", "qwen")

    def broken_callback(_: str) -> None:
        raise RuntimeError("UI disconnected")

    out = await c.chat_stream(_req("qwen", "scan"), broken_callback)

    assert out.message.content == "Working on it"
    assert out.message.tool_calls is not None
    assert out.message.tool_calls[0].function.name == "http"

async def test_proxy_error_body():
    c = OpenAIClient(base_url, "sk", "proxy-200-ratelimit", "openrouter")
    with pytest.raises(RuntimeError):
        await c.chat(_req("proxy-200-ratelimit"))

async def test_temperature():
    c = OpenAIClient(base_url, "", "qwen", gen_opts={"temperature": 0.3})
    await c.chat(_req("qwen"))
    assert last_body["temperature"] == 0.3

async def test_extra_headers():
    c = OpenAIClient(
        base_url,
        "sk-or",
        "openrouter",
        "openrouter",
        {"HTTP-Referer": "https://github.com/kagent/agent"},
    )
    await c.chat(_req("openrouter"))
    assert last_headers["HTTP-Referer"] == "https://github.com/kagent/agent"
