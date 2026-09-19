from __future__ import annotations

import json
from typing import Any, Callable

import httpx

from src.logger.logger import get_logger

from .client import StreamingClient
from .errors import classify_backend
from .providers import kimi_locks_temperature, kimi_supports_thinking_toggle
from .retry import RetryInfo, RetryOptions, with_retry
from .transport import (
    attach_retry_after,
    new_call_id,
    new_provider_async_client,
    ping_models_endpoint,
    resolve_max_tokens,
    run_cancellable,
)
from .types import ChatRequest, ChatResponse, FunctionCall, Message, ToolCall

logger = get_logger("llm.openai")


def _emit_delta(on_delta: Callable[[str], None], text: str) -> None:
    """Keep a display callback failure from aborting a provider response."""
    try:
        on_delta(text)
    except Exception:
        logger.debug("LLM stream delta callback failed", exc_info=True)


class OpenAIClient(StreamingClient):
    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        model: str = "",
        provider_name: str = "openai-compat",
        extra_headers: dict[str, str] | None = None,
        gen_opts: dict[str, Any] | None = None,
        log_error: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model_id = model
        self.label = provider_name
        self.extra_headers = extra_headers or {}
        self.log_error = log_error

        gen_opts = gen_opts or {}
        self.temperature = gen_opts.get("temperature")
        self.max_tokens = resolve_max_tokens(gen_opts)

    def name(self) -> str:
        return self.label

    def model(self) -> str:
        return self.model_id

    def headers(self) -> dict[str, str]:
        headers = {**self.extra_headers, "Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def ping(self) -> None:
        await ping_models_endpoint(self.base_url, self.headers(), self.label)

    def _on_retry(self, info: RetryInfo) -> None:
        if not self.log_error:
            return
        err = info["err"]
        self.log_error(
            "llm: transient error, retrying",
            {
                "backend": self.label,
                "attempt": info["attempt"],
                "delay_ms": info["delay_ms"],
                "category": getattr(err, "category", None),
                "status": getattr(err, "status_code", None),
                "detail": getattr(err, "detail", None),
            },
        )

    async def chat(
        self,
        request: ChatRequest,
        signal: Any = None,
    ) -> ChatResponse:
        body = self.encode_request(request, False)

        async def do_request() -> dict[str, Any]:
            async with new_provider_async_client() as client:
                try:
                    resp = await client.post(
                        f"{self.base_url}/chat/completions",
                        headers=self.headers(),
                        json=body,
                    )
                except (httpx.ConnectError, httpx.TimeoutException) as err:
                    raise classify_backend(self.label, err, 0, None) from err

                if resp.status_code >= 400:
                    raise attach_retry_after(
                        classify_backend(
                            self.label, None, resp.status_code, resp.text
                        ),
                        resp,
                    )

                try:
                    data = resp.json()
                except ValueError as err:
                    raise classify_backend(
                        self.label, None, resp.status_code, f"invalid JSON: {resp.text}"
                    ) from err

                return data

        async def attempt() -> dict[str, Any]:
            return await run_cancellable(do_request(), signal)

        data = await with_retry(
            attempt,
            RetryOptions(signal=signal, on_retry=self._on_retry),
        )

        if data.get("error"):
            raise RuntimeError(data["error"].get("message", "backend error"))

        choices = data.get("choices", [])
        if not choices:
            raise RuntimeError(f"{self.label}: empty choices")

        choice = choices[0]
        message = choice.get("message", {})

        # reasoning_content is provider state, not a fallback answer.  DeepSeek
        # requires it to be included again when tools are present in a later
        # request, so retain it separately from the visible final content.
        msg = Message(
            role="assistant",
            content=message.get("content") or "",
            reasoning_content=message.get("reasoning_content"),
        )

        if message.get("tool_calls"):
            msg.tool_calls = [
                ToolCall(
                    id=tc.get("id") or new_call_id(),
                    function=FunctionCall(
                        name=tc.get("function", {}).get("name", ""),
                        arguments=tc.get("function", {}).get("arguments", ""),
                    ),
                )
                for tc in message["tool_calls"]
            ]

        return ChatResponse(message=msg, finish_reason=choice.get("finish_reason", ""))

    async def chat_stream(
        self,
        request: ChatRequest,
        on_delta: Callable[[str], None],
        signal: Any = None,
    ) -> ChatResponse:
        body = self.encode_request(request, True)

        async def open_stream() -> tuple[httpx.AsyncClient, httpx.Response]:
            client = new_provider_async_client()
            try:
                req_obj = client.build_request(
                    "POST",
                    f"{self.base_url}/chat/completions",
                    headers={**self.headers(), "Accept": "text/event-stream"},
                    json=body,
                )
                resp = await client.send(req_obj, stream=True)
            except (httpx.ConnectError, httpx.TimeoutException) as err:
                await client.aclose()
                raise classify_backend(self.label, err, 0, None) from err

            if resp.status_code >= 400:
                raw = await resp.aread()
                await resp.aclose()
                await client.aclose()
                raise attach_retry_after(
                    classify_backend(
                        self.label, None, resp.status_code, raw.decode("utf-8", "replace")
                    ),
                    resp,
                )

            return client, resp

        async def attempt() -> tuple[httpx.AsyncClient, httpx.Response]:
            return await run_cancellable(open_stream(), signal)

        client, resp = await with_retry(
            attempt,
            RetryOptions(signal=signal, on_retry=self._on_retry),
        )

        chunks: list[str] = []
        reasoning_chunks: list[str] = []
        finish = ""
        tool_parts: dict[int, dict[str, str]] = {}
        fallback_index = -1

        async def consume() -> None:
            nonlocal finish, fallback_index

            async for line in resp.aiter_lines():
                if not line or not line.startswith("data:"):
                    continue

                data_str = line[5:].strip()
                if data_str == "[DONE]":
                    break

                try:
                    chunk = json.loads(data_str)
                except Exception:
                    continue

                choices = chunk.get("choices", [])
                if not choices:
                    continue

                choice = choices[0]

                if choice.get("finish_reason"):
                    finish = choice["finish_reason"]

                delta = choice.get("delta", {})

                if delta.get("reasoning_content"):
                    reasoning = delta["reasoning_content"]
                    reasoning_chunks.append(reasoning)
                    # DeepSeek's structured CoT is not transcript text.  Do
                    # not leak it to the UI, while preserving it for replay.
                    if self.label != "deepseek":
                        _emit_delta(on_delta, reasoning)

                if delta.get("content"):
                    text = delta["content"]
                    _emit_delta(on_delta, text)
                    chunks.append(text)

                for tc in delta.get("tool_calls", []):
                    idx = tc.get("index")

                    if idx is None:
                        if (
                            tc.get("id")
                            or tc.get("function", {}).get("name")
                            or fallback_index < 0
                        ):
                            fallback_index += 1
                        idx = fallback_index

                    current = tool_parts.setdefault(
                        idx, {"id": "", "name": "", "arguments": ""}
                    )

                    if tc.get("id"):
                        current["id"] = tc["id"]

                    fn = tc.get("function", {})
                    if fn.get("name"):
                        current["name"] += fn["name"]
                    if fn.get("arguments"):
                        current["arguments"] += fn["arguments"]

        try:
            await run_cancellable(consume(), signal)
        finally:
            await resp.aclose()
            await client.aclose()

        msg = Message(
            role="assistant",
            content="".join(chunks),
            reasoning_content="".join(reasoning_chunks) or None,
        )

        if tool_parts:
            msg.tool_calls = [
                ToolCall(
                    id=value["id"] or new_call_id(),
                    function=FunctionCall(
                        name=value["name"],
                        arguments=value["arguments"],
                    ),
                )
                for value in tool_parts.values()
            ]

        return ChatResponse(message=msg, finish_reason=finish)

    def encode_request(self, req: ChatRequest, stream: bool) -> dict[str, Any]:
        messages: list[dict[str, Any]] = []

        for m in req.messages:
            msg: dict[str, Any] = {"role": m.role, "content": m.content}

            if m.tool_call_id:
                msg["tool_call_id"] = m.tool_call_id

            if m.name:
                msg["name"] = m.name

            # DeepSeek requires the CoT of every prior assistant turn in a
            # tool-enabled request.  Other OpenAI-compatible endpoints often
            # reject unknown fields, so serialize it only for DeepSeek.
            if (
                self.label == "deepseek"
                and m.role == "assistant"
                and m.reasoning_content is not None
            ):
                msg["reasoning_content"] = m.reasoning_content

            if m.tool_calls:
                msg["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in m.tool_calls
                ]

            messages.append(msg)

        body: dict[str, Any] = {
            "model": self.model_id,
            "stream": stream,
            "messages": messages,
        }

        if req.tools:
            encoded_tools = []
            for tool in req.tools:
                if hasattr(tool, "function"):
                    encoded_tools.append(
                        {
                            "type": getattr(tool, "type", "function"),
                            "function": {
                                "name": tool.function.name,
                                "description": tool.function.description,
                                "parameters": tool.function.parameters,
                            },
                        }
                    )
                elif isinstance(tool, dict):
                    encoded_tools.append(tool)

            body["tools"] = encoded_tools

        if self.label == "kimi" and kimi_supports_thinking_toggle(self.model_id):
            body["thinking"] = {"type": "disabled"}
        elif self.label == "deepseek":
            # The API defaults to enabled.  Always send KAgent's explicit
            # setting so /thinking controls provider behavior as well as the
            # prompt.  Requests constructed outside the agent retain the API
            # default when no preference is supplied.
            if req.thinking_enabled is not None:
                body["thinking"] = {
                    "type": "enabled" if req.thinking_enabled else "disabled"
                }

        if self.temperature is not None and not (
            self.label == "kimi" and kimi_locks_temperature(self.model_id)
        ) and not (self.label == "deepseek" and req.thinking_enabled):
            body["temperature"] = self.temperature

        if self.max_tokens is not None and self.max_tokens > 0:
            if self.label == "kimi":
                body["max_completion_tokens"] = self.max_tokens
            else:
                body["max_tokens"] = self.max_tokens

        return body
