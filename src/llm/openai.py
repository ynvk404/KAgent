from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from typing import Any, Awaitable, Callable, TypeVar

import httpx

from .client import Client
from .errors import BackendError, classify_backend, parse_retry_after
from .providers import kimi_locks_temperature, kimi_supports_thinking_toggle
from .retry import RetryInfo, RetryOptions, with_retry
from .types import ChatRequest, ChatResponse, FunctionCall, Message, ToolCall

T = TypeVar("T")


def new_call_id() -> str:
    return f"call_{uuid.uuid4().hex}"


CHAT_TIMEOUT = 600.0  #s
_ABORT_POLL_INTERVAL = 0.1  #s


class OpenAIClient(Client):
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
        self.max_tokens = (
            gen_opts.get("maxTokens")
            if gen_opts.get("maxTokens") is not None
            else gen_opts.get("max_tokens")
        )

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
        import requests

        loop = asyncio.get_running_loop()

        def _do_request():
            return requests.get(
                f"{self.base_url}/models",
                headers=self.headers(),
                timeout=10,
            )

        resp = await loop.run_in_executor(None, _do_request)

        if resp.status_code >= 500:
            raise RuntimeError(f"{self.label} status {resp.status_code}")

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

    def _attach_retry_after(self, err: BackendError, resp: httpx.Response) -> None:
        if err.retry_after_ms is not None:
            return
        ms = parse_retry_after(resp.headers.get("retry-after"))
        if ms is not None:
            err.retry_after_ms = ms

    async def _run_cancellable(self, coro: Awaitable[T], signal: Any) -> T:
        """Chạy `coro` dưới dạng task, liên tục poll `signal.aborted` để có thể ngắt request HTTP đang chạy."""
        task: asyncio.Task[T] = asyncio.ensure_future(coro)
        if signal is None:
            return await task
        while not task.done():
            if getattr(signal, "aborted", False):
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
                raise RuntimeError("aborted")
            await asyncio.wait({task}, timeout=_ABORT_POLL_INTERVAL)
        return task.result()

    async def chat(
        self,
        req: ChatRequest,
        signal: Any = None,
    ) -> ChatResponse:
        body = self.encode_request(req, False)

        async def do_request() -> dict[str, Any]:
            async with httpx.AsyncClient(timeout=CHAT_TIMEOUT) as client:
                try:
                    resp = await client.post(
                        f"{self.base_url}/chat/completions",
                        headers=self.headers(),
                        json=body,
                    )
                except (httpx.ConnectError, httpx.TimeoutException) as err:
                    raise classify_backend(self.label, err, 0, None) from err

                if resp.status_code >= 400:
                    backend_err = classify_backend(
                        self.label, None, resp.status_code, resp.text
                    )
                    self._attach_retry_after(backend_err, resp)
                    raise backend_err

                try:
                    data = resp.json()
                except ValueError as err:
                    raise classify_backend(
                        self.label, None, resp.status_code, f"invalid JSON: {resp.text}"
                    ) from err

                return data

        async def attempt() -> dict[str, Any]:
            return await self._run_cancellable(do_request(), signal)

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

        raw_content = message.get("content") or message.get("reasoning_content") or ""

        msg = Message(role="assistant", content=raw_content)

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
        req: ChatRequest,
        on_delta: Callable[[str], None],
        signal: Any = None,
    ) -> ChatResponse:
        body = self.encode_request(req, True)

        async def open_stream() -> tuple[httpx.AsyncClient, httpx.Response]:
            client = httpx.AsyncClient(timeout=CHAT_TIMEOUT)
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
                backend_err = classify_backend(
                    self.label, None, resp.status_code, raw.decode("utf-8", "replace")
                )
                self._attach_retry_after(backend_err, resp)
                raise backend_err

            return client, resp

        async def attempt() -> tuple[httpx.AsyncClient, httpx.Response]:
            return await self._run_cancellable(open_stream(), signal)

        client, resp = await with_retry(
            attempt,
            RetryOptions(signal=signal, on_retry=self._on_retry),
        )

        chunks: list[str] = []
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
                    on_delta(delta["reasoning_content"])

                if delta.get("content"):
                    text = delta["content"]
                    on_delta(text)
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
            await self._run_cancellable(consume(), signal)
        finally:
            await resp.aclose()
            await client.aclose()

        msg = Message(role="assistant", content="".join(chunks))

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
            body["thinking"] = {"type": "disabled"}
            
        if self.temperature is not None and not (
            self.label == "kimi" and kimi_locks_temperature(self.model_id)
        ):
            body["temperature"] = self.temperature

        if self.max_tokens is not None and self.max_tokens > 0:
            if self.label == "kimi":
                body["max_completion_tokens"] = self.max_tokens
            else:
                body["max_tokens"] = self.max_tokens

        return body