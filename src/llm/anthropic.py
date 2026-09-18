from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import httpx

from .client import Client, Pinger
from .errors import classify_backend
from .providers import (
    ANTHROPIC_DEFAULT_MAX_TOKENS,
    ANTHROPIC_VERSION,
    anthropic_accepts_temperature,
)
from .retry import RetryOptions, with_retry
from .transport import (
    CHAT_TIMEOUT_SEC,
    aborted,
    attach_retry_after,
    ping_models_endpoint,
    resolve_max_tokens,
    run_cancellable,
)
from .types import ChatRequest, ChatResponse, FunctionCall, Message, ToolCall, ToolSpec


class AnthropicClient(Client, Pinger):
    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        gen_opts: Optional[Dict[str, Any]] = None,
    ):
        if gen_opts is None:
            gen_opts = {}
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.model_id = model
        self.temperature = gen_opts.get("temperature")
        self.max_tokens = resolve_max_tokens(gen_opts)

    def _gen_opts(self) -> Dict[str, Any]:
        return {
            "temperature": self.temperature,
            "maxTokens": self.max_tokens,
        }

    def name(self) -> str:
        return "anthropic"

    def model(self) -> str:
        return self.model_id

    async def ping(self, signal: Optional[Any] = None) -> None:
        await ping_models_endpoint(
            self.base_url,
            {
                "x-api-key": self.api_key,
                "anthropic-version": ANTHROPIC_VERSION,
            },
            "anthropic",
        )

    async def chat(self, request: ChatRequest, signal: Optional[Any] = None) -> ChatResponse:
        return await with_retry(
            lambda: self._chat_once(request, signal),
            RetryOptions(signal=signal),
        )

    async def _chat_once(self, req: ChatRequest, signal: Optional[Any] = None) -> ChatResponse:
        model = req.model or self.model_id
        body = encode_request(req, model, self._gen_opts())

        async with httpx.AsyncClient(timeout=CHAT_TIMEOUT_SEC) as client:
            try:
                resp = await run_cancellable(
                    client.post(
                        f"{self.base_url}/messages",
                        headers={
                            "Content-Type": "application/json",
                            "x-api-key": self.api_key,
                            "anthropic-version": ANTHROPIC_VERSION,
                        },
                        json=body
                    ),
                    signal,
                )
            except Exception as err:
                if aborted(signal):
                    raise
                raise classify_backend('anthropic', err, 0, None)

            raw = resp.text
            if resp.status_code != 200:
                raise attach_retry_after(classify_backend('anthropic', None, resp.status_code, raw), resp)

            try:
                out = resp.json()
            except json.JSONDecodeError:
                raise classify_backend('anthropic', None, resp.status_code, f"invalid JSON from anthropic: {raw}")

            if out.get("error", {}).get("message"):
                raise classify_backend('anthropic', None, resp.status_code, out["error"]["message"])

            blocks = out.get("content") or []
            text_parts = [
                b.get("text", "")
                for b in blocks
                if b.get("type") == "text"
            ]
            text = "".join(text_parts)

            calls = [b for b in blocks if b.get("type") == "tool_use"]

            msg = Message(role="assistant", content=text)
            if calls:
                msg.tool_calls = [block_to_tool_call(b) for b in calls]

            return ChatResponse(message=msg, finish_reason=map_finish_reason(out.get("stop_reason")))


def block_to_tool_call(block: Dict[str, Any]) -> ToolCall:
    return ToolCall(
        id=block.get("id") or "",
        function=FunctionCall(
            name=block.get("name") or "",
            arguments=json.dumps(block.get("input") or {}),
        ),
    )


def map_finish_reason(reason: Optional[str]) -> str:
    if reason in ("end_turn", "stop_sequence"):
        return "stop"
    if reason == "tool_use":
        return "tool_calls"
    if reason == "max_tokens":
        return "length"
    return reason or ""


def encode_request(
    req: ChatRequest,
    model: str,
    gen_opts: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if gen_opts is None:
        gen_opts = {}

    system_text = "\n\n".join(
        m.content for m in req.messages if m.role == 'system'
    )

    messages: List[Dict[str, Any]] = []
    for m in req.messages:
        if m.role == 'system':
            continue
        encoded = encode_message(m)
        if encoded is not None:
            messages.append(encoded)

    max_tokens = resolve_max_tokens(gen_opts)
    body: Dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens if max_tokens and max_tokens > 0 else ANTHROPIC_DEFAULT_MAX_TOKENS,
        "messages": messages,
    }

    if system_text:
        body["system"] = system_text

    if req.tools:
        body["tools"] = [encode_tool(t) for t in req.tools]

    temperature = gen_opts.get("temperature")
    if temperature is not None and anthropic_accepts_temperature(model):
        body["temperature"] = temperature

    return body


def encode_message(m: Message) -> Optional[Dict[str, Any]]:
    if m.role == 'tool':
        return {
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": getattr(m, "tool_call_id", None) or "",
                "content": m.content,
            }]
        }

    if m.role == 'assistant':
        content: List[Dict[str, Any]] = []
        if m.content:
            content.append({"type": "text", "text": m.content})

        tool_calls = getattr(m, "tool_calls", None) or []
        for tc in tool_calls:
            try:
                input_ = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                input_ = {}

            content.append({
                "type": "tool_use",
                "id": tc.id,
                "name": tc.function.name,
                "input": input_,
            })

        return {"role": "assistant", "content": content} if content else None

    return {"role": "user", "content": [{"type": "text", "text": m.content}]}


def encode_tool(tool: ToolSpec) -> Dict[str, Any]:
    return {
        "name": tool.function.name,
        "description": tool.function.description,
        "input_schema": tool.function.parameters,
    }
