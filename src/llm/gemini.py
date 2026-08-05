import asyncio
import contextlib
import json
import uuid
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional, TypeVar

import httpx

from .client import Client, Pinger, StreamingClient
from .errors import BackendError, classify_backend, parse_retry_after
from .retry import RetryOptions, with_retry
from .types import (
    ChatRequest,
    ChatResponse,
    FunctionCall,
    GeminiProvider,
    Message,
    ToolCall,
    ToolProvider,
    ToolSpec,
)


def with_retry_after(err: BackendError, resp: httpx.Response) -> BackendError:
    retry_after = resp.headers.get('retry-after')
    if retry_after:
        ms = parse_retry_after(retry_after)
        if ms is not None:
            err.retry_after_ms = ms
    return err


CHAT_TIMEOUT_MS = 10 * 60 * 1000
CHAT_TIMEOUT_SEC = CHAT_TIMEOUT_MS / 1000.0
_ABORT_POLL_INTERVAL_SEC = 0.1

T = TypeVar("T")


class _CompatToolCall(ToolCall):
    def __getitem__(self, key: str) -> Any:
        if key == "id":
            return self.id
        if key == "type":
            return self.type
        if key == "function":
            return {
                "name": self.function.name,
                "arguments": self.function.arguments,
            }
        if key == "provider":
            if self.provider and self.provider.gemini:
                return {
                    "gemini": {
                        "thoughtSignature": self.provider.gemini.thought_signature
                    }
                }
            return None
        raise KeyError(key)


async def _run_cancellable(coro: Awaitable[T], signal: Optional[Any]) -> T:
    task: asyncio.Task[T] = asyncio.ensure_future(coro)
    if signal is None:
        return await task
    while not task.done():
        if getattr(signal, "aborted", False):
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            raise RuntimeError("aborted")
        await asyncio.wait({task}, timeout=_ABORT_POLL_INTERVAL_SEC)
    return task.result()


class GeminiClient(StreamingClient, Pinger):
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
        self.max_tokens = (
            gen_opts.get("maxTokens")
            if gen_opts.get("maxTokens") is not None
            else gen_opts.get("max_tokens")
        )
        self.thinking_budget = gen_opts.get("thinkingBudget")

    def _gen_opts(self) -> Dict[str, Any]:
        return {
            "temperature": self.temperature,
            "maxTokens": self.max_tokens,
            "thinkingBudget": self.thinking_budget,
        }

    def name(self) -> str:
        return "gemini"

    def model(self) -> str:
        return self.model_id

    async def ping(self, signal: Optional[Any] = None) -> None:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{self.base_url}/models",
                headers={"x-goog-api-key": self.api_key}
            )
            if resp.status_code >= 500:
                raise Exception(f"gemini status {resp.status_code}")

    async def chat(self, req: ChatRequest, signal: Optional[Any] = None) -> ChatResponse:
        return await with_retry(
            lambda: self._chat_once(req, signal),
            RetryOptions(signal=signal),
        )

    async def _chat_once(self, req: ChatRequest, signal: Optional[Any] = None) -> ChatResponse:
        body = encode_request(req, self._gen_opts())
        async with httpx.AsyncClient(timeout=CHAT_TIMEOUT_SEC) as client:
            try:
                resp = await _run_cancellable(
                    client.post(
                        f"{self.base_url}/{with_models_prefix(req.model or self.model_id)}:generateContent",
                        headers={
                            "Content-Type": "application/json",
                            "x-goog-api-key": self.api_key
                        },
                        json=body
                    ),
                    signal,
                )
            except Exception as err:
                if getattr(signal, "aborted", False):
                    raise
                raise classify_backend('gemini', err, 0, None)

            raw = resp.text
            if resp.status_code != 200:
                raise with_retry_after(classify_backend('gemini', None, resp.status_code, raw), resp)

            try:
                out = resp.json()
            except json.JSONDecodeError:
                raise classify_backend('gemini', None, resp.status_code, f"invalid JSON from gemini: {raw}")

            if out.get("error", {}).get("message"):
                raise classify_backend('gemini', None, resp.status_code, out["error"]["message"])

            candidates = out.get("candidates", [])
            choice = candidates[0] if candidates else None
            if not choice:
                raise Exception("gemini: empty candidates")

            parts = choice.get("content", {}).get("parts", [])
            text_parts = [
                p.get("text", "")
                for p in parts
                if not p.get("thought") and p.get("text")
            ]
            text = "".join(text_parts)

            calls = [p for p in parts if p.get("functionCall", {}).get("name")]
            msg = Message(role="assistant", content=text)
            if calls:
                msg.tool_calls = [part_to_tool_call(p) for p in calls]

            return ChatResponse(message=msg, finish_reason=choice.get("finishReason", ""))

    async def chat_stream(
        self,
        req: ChatRequest,
        on_delta: Callable[[str], None],
        signal: Optional[Any] = None,
    ) -> ChatResponse:
        client, resp = await with_retry(
            lambda: self._open_stream(req, signal),
            RetryOptions(signal=signal),
        )
        
        chunks: List[str] = []
        calls: List[Dict[str, Any]] = []
        finish = ""

        async def consume() -> None:
            nonlocal finish
            async for line in iter_sse(resp):
                if not line.startswith('data:'):
                    continue
                data = line[5:].strip()
                if not data or data == '[DONE]':
                    continue
                try:
                    chunk = json.loads(data)
                except json.JSONDecodeError:
                    continue

                if chunk.get("error", {}).get("message"):
                    raise classify_backend('gemini', None, 200, chunk["error"]["message"])

                candidates = chunk.get("candidates", [])
                choice = candidates[0] if candidates else None
                if not choice:
                    continue

                if choice.get("finishReason"):
                    finish = choice["finishReason"]

                for part in choice.get("content", {}).get("parts", []):
                    if part.get("functionCall", {}).get("name"):
                        calls.append(part)
                        continue
                    if not part.get("text"):
                        continue

                    on_delta(part["text"])
                    if not part.get("thought"):
                        chunks.append(part["text"])

        try:
            await _run_cancellable(consume(), signal)
        finally:
            await resp.aclose()
            await client.aclose()

        msg = Message(role="assistant", content="".join(chunks))
        if calls:
            msg.tool_calls = [part_to_tool_call(p) for p in calls]

        return ChatResponse(message=msg, finish_reason=finish)

    async def _open_stream(self, req: ChatRequest, signal: Optional[Any] = None):
 
        body = encode_request(req, self._gen_opts())
        client = httpx.AsyncClient(timeout=CHAT_TIMEOUT_SEC)
        
        try:

            req_obj = client.build_request(
                "POST",
                f"{self.base_url}/{with_models_prefix(req.model or self.model_id)}:streamGenerateContent?alt=sse",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream",
                    "x-goog-api-key": self.api_key
                },
                json=body
            )
            resp = await _run_cancellable(client.send(req_obj, stream=True), signal)
        except Exception as err:
            await client.aclose()
            if getattr(signal, "aborted", False):
                raise
            raise classify_backend('gemini', err, 0, None)

        if resp.status_code != 200:
            await resp.aread()
            raw = resp.text
            await resp.aclose()
            await client.aclose()
            raise with_retry_after(classify_backend('gemini', None, resp.status_code, raw), resp)

        return client, resp


def part_to_tool_call(part: Dict[str, Any]) -> ToolCall:

    fc = part.get("functionCall", {})
    thought_sig = part.get("thoughtSignature") or part.get("thought_signature")

    tc = _CompatToolCall(
        id=f"call_{uuid.uuid4().hex[:16]}",
        function=FunctionCall(
            name=fc.get("name", ""),
            arguments=json.dumps(fc.get("args", {})),
        ),
    )
    if thought_sig:
        tc.provider = ToolProvider(gemini=GeminiProvider(thought_signature=thought_sig))

    return tc


async def iter_sse(resp: httpx.Response) -> AsyncIterator[str]:
    async for line in resp.aiter_lines():
        if line:
            yield line.rstrip('\r')


def encode_request(
    req: ChatRequest,
    gen_opts: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if gen_opts is None:
        gen_opts = {}

    system_text = "\n\n".join(
        m.content for m in req.messages if m.role == 'system' and m.content
    )
    
    contents = []
    for m in req.messages:
        if m.role != 'system':
            contents.extend(encode_message(m))

    body: Dict[str, Any] = {"contents": contents}

    if system_text:
        body["systemInstruction"] = {"parts": [{"text": system_text}]}

    if req.tools:
        body["tools"] = [{"functionDeclarations": [encode_tool(t) for t in req.tools]}]

    generation_config: Dict[str, Any] = {}
    if gen_opts.get("temperature") is not None:
        generation_config["temperature"] = gen_opts["temperature"]
    max_tokens = (
        gen_opts.get("maxTokens")
        if gen_opts.get("maxTokens") is not None
        else gen_opts.get("max_tokens")
    )
    if max_tokens is not None and max_tokens > 0:
        generation_config["maxOutputTokens"] = max_tokens

    thinking_budget = gen_opts.get("thinkingBudget")
    if thinking_budget is not None and thinking_budget >= 0:
        if thinking_budget == 0:
            generation_config["thinkingConfig"] = {"thinkingBudget": 0}
        else:
            generation_config["thinkingConfig"] = {
                "thinkingBudget": thinking_budget,
                "includeThoughts": True
            }

    if generation_config:
        body["generationConfig"] = generation_config

    return body


def with_models_prefix(model_id: str) -> str:
    if model_id.startswith('models/') or model_id.startswith('tunedModels/'):
        return model_id
    return f"models/{model_id}"


def encode_message(m: Message) -> List[Dict[str, Any]]:
    if m.role == 'tool':
        return [{
            "role": "user",
            "parts": [{
                "functionResponse": {
                    "name": getattr(m, "name", None) or "tool_result",
                    "response": {"result": m.content}
                }
            }]
        }]
        
    if m.role == 'assistant':
        parts: List[Dict[str, Any]] = []
        if m.content:
            parts.append({"text": m.content})
            
        tool_calls = getattr(m, "tool_calls", None) or []
        for tc in tool_calls:
            tc_name = tc.function.name
            tc_args_str = tc.function.arguments
            
            try:
                args = json.loads(tc_args_str or "{}")
            except json.JSONDecodeError:
                args = {}
                
            part: Dict[str, Any] = {
                "functionCall": {"name": tc_name, "args": args}
            }
            
            tc_provider: Any = getattr(tc, "provider", None)
            thought_sig = None
            if isinstance(tc_provider, ToolProvider) and tc_provider.gemini:
                thought_sig = tc_provider.gemini.thought_signature
            elif isinstance(tc_provider, dict):
                gemini_provider = tc_provider.get("gemini") or {}
                thought_sig = gemini_provider.get("thoughtSignature")

            if thought_sig:
                part["thoughtSignature"] = thought_sig
                
            parts.append(part)
            
        return [{"role": "model", "parts": parts}] if parts else []

    return [{"role": "user", "parts": [{"text": m.content}]}]


def encode_tool(tool: ToolSpec) -> Dict[str, Any]:
    return {
        "name": tool.function.name,
        "description": tool.function.description or "",
        "parameters": normalize_schema(tool.function.parameters),
    }


def normalize_schema(schema: Any) -> Any:
    if isinstance(schema, list):
        return [normalize_schema(v) for v in schema]
    if not schema or not isinstance(schema, dict):
        return schema

    out: Dict[str, Any] = {}
    for key, value in schema.items():
        if value is None:
            continue
        if key == 'type' and isinstance(value, str):
            out['type'] = value.upper()
            continue
        if key == 'properties' and isinstance(value, dict) and not isinstance(value, list):
            out['properties'] = {
                k: normalize_schema(v)
                for k, v in value.items()
            }
            continue
        if key == 'items':
            out['items'] = normalize_schema(value)
            continue
        if key in ('additionalProperties', '$schema', 'definitions', '$defs'):
            continue
        
        out[key] = normalize_schema(value)
        
    return out
