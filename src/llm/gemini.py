import json
import uuid
from typing import Any, AsyncIterator, Callable, Dict, List, Optional

import httpx

from .client import Client, Pinger, StreamingClient
from .errors import BackendError, classify_backend, parse_retry_after
from .retry import with_retry
from .types import ChatRequest, ChatResponse, Message, ToolSpec


def with_retry_after(err: BackendError, resp: httpx.Response) -> BackendError:
    """Annotate a backend error with the server's Retry-After so with_retry can
    honor it instead of its computed backoff."""
    retry_after = resp.headers.get('retry-after')
    if retry_after:
        ms = parse_retry_after(retry_after)
        if ms is not None:
            err.retry_after_ms = ms
    return err


CHAT_TIMEOUT_MS = 10 * 60 * 1000
CHAT_TIMEOUT_SEC = CHAT_TIMEOUT_MS / 1000.0


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
        self.max_tokens = gen_opts.get("maxTokens")
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
                # Pass the key as a header, not a query param, so it can't leak into
                # access/proxy logs or error messages that echo the request URL.
                headers={"x-goog-api-key": self.api_key}
            )
            if resp.status_code >= 500:
                raise Exception(f"gemini status {resp.status_code}")

    async def chat(self, req: ChatRequest, signal: Optional[Any] = None) -> ChatResponse:
        # Retry rate limits / transient 5xx with backoff (E7). The call has no
        # observable side effects before it returns, so re-running it is safe.
        return await with_retry(lambda: self._chat_once(req, signal))

    async def _chat_once(self, req: ChatRequest, signal: Optional[Any] = None) -> ChatResponse:
        body = encode_request(req, self._gen_opts())
        try:
            async with httpx.AsyncClient(timeout=CHAT_TIMEOUT_SEC) as client:
                try:
                    resp = await client.post(
                        f"{self.base_url}/{with_models_prefix(req.model or self.model_id)}:generateContent",
                        headers={
                            "Content-Type": "application/json",
                            "x-goog-api-key": self.api_key
                        },
                        json=body
                    )
                except Exception as err:
                    raise classify_backend('gemini', err, 0, None)

                raw = resp.text
                if resp.status_code != 200:
                    raise with_retry_after(classify_backend('gemini', None, resp.status_code, raw), resp)

                try:
                    out = resp.json()
                except json.JSONDecodeError:
                    raise classify_backend('gemini', None, resp.status_code, f"invalid JSON from gemini: {raw}")

                if out.get("error", {}).get("message"):
                    # Route through the classifier so rate-limit phrasing in a 200 body
                    # becomes a retryable BackendError rather than a plain Error.
                    raise classify_backend('gemini', None, resp.status_code, out["error"]["message"])

                candidates = out.get("candidates", [])
                choice = candidates[0] if candidates else None
                if not choice:
                    raise Exception("gemini: empty candidates")

                parts = choice.get("content", {}).get("parts", [])
                
                # Skip thought parts: they're reasoning summaries, not the answer, and
                # must not enter the model's history.
                text_parts = [
                    p.get("text", "") 
                    for p in parts 
                    if not p.get("thought") and p.get("text")
                ]
                text = "".join(text_parts)

                calls = [p for p in parts if p.get("functionCall", {}).get("name")]
                
                msg_kwargs: Dict[str, Any] = {"role": "assistant", "content": text}
                if calls:
                    msg_kwargs["tool_calls"] = [part_to_tool_call(p) for p in calls]
                    
                msg = Message(**msg_kwargs)
                return ChatResponse(message=msg, finish_reason=choice.get("finishReason", ""))
        except Exception as e:
            raise e

    async def chat_stream(
        self,
        req: ChatRequest,
        on_delta: Callable[[str], None],
        signal: Optional[Any] = None,
    ) -> ChatResponse:
        # Retry only the connection setup (E7): a transient 429/5xx surfaces before
        # any delta is emitted, so re-running openStream can't double-emit tokens.
        client, resp = await with_retry(lambda: self._open_stream(req, signal))
        
        chunks: List[str] = []
        calls: List[Dict[str, Any]] = []
        finish = ""

        try:
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

                    # Stream both thought summaries and answer text as visible progress
                    # (so the UI shows movement instead of a frozen spinner), but only
                    # accumulate answer text into the returned message.
                    on_delta(part["text"])
                    if not part.get("thought"):
                        chunks.append(part["text"])
        finally:
            await resp.aclose()
            await client.aclose()

        msg_kwargs: Dict[str, Any] = {"role": "assistant", "content": "".join(chunks)}
        if calls:
            msg_kwargs["tool_calls"] = [part_to_tool_call(p) for p in calls]
            
        msg = Message(**msg_kwargs)
        return ChatResponse(message=msg, finish_reason=finish)

    async def _open_stream(self, req: ChatRequest, signal: Optional[Any] = None):
        """Open the SSE stream and return the live 200 response paired with a
        client that is intentionally left open for iter_sse streaming. Extracted
        so with_retry can re-attempt without re-entering the consume loop."""
        body = encode_request(req, self._gen_opts())
        client = httpx.AsyncClient(timeout=CHAT_TIMEOUT_SEC)
        
        try:
            # alt=sse switches streamGenerateContent from a JSON array to an SSE
            # stream of data: events, which iter_sse consumes incrementally.
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
            resp = await client.send(req_obj, stream=True)
        except Exception as err:
            await client.aclose()
            raise classify_backend('gemini', err, 0, None)

        if resp.status_code != 200:
            await resp.aread()
            raw = resp.text
            await resp.aclose()
            await client.aclose()
            raise with_retry_after(classify_backend('gemini', None, resp.status_code, raw), resp)

        return client, resp


def part_to_tool_call(part: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a Gemini functionCall part into a provider-neutral ToolCall,
    preserving the thoughtSignature so a follow-up turn can echo it back."""
    fc = part.get("functionCall", {})
    thought_sig = part.get("thoughtSignature") or part.get("thought_signature")

    tc = {
        "id": f"call_{uuid.uuid4().hex[:16]}",
        "type": "function",
        "function": {
            "name": fc.get("name", ""),
            "arguments": json.dumps(fc.get("args", {}))
        }
    }
    if thought_sig:
        tc["provider"] = {"gemini": {"thoughtSignature": thought_sig}}
    
    return tc


async def iter_sse(resp: httpx.Response) -> AsyncIterator[str]:
    """Decode a byte stream into SSE-style logical lines, splitting on \\n."""
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

    # Generation knobs
    generation_config: Dict[str, Any] = {}
    if gen_opts.get("temperature") is not None:
        generation_config["temperature"] = gen_opts["temperature"]
    if gen_opts.get("maxTokens") is not None and gen_opts["maxTokens"] > 0:
        generation_config["maxOutputTokens"] = gen_opts["maxTokens"]

    # Gemini 2.5/3 Flash models run an internal "thinking" pass on every turn.
    # 0 disables thinking entirely (fastest); a positive budget caps it.
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
    """Ensure the model id carries the models/ (or tunedModels/) prefix."""
    if model_id.startswith('models/') or model_id.startswith('tunedModels/'):
        return model_id
    return f"models/{model_id}"


def encode_message(m: Message) -> List[Dict[str, Any]]:
    if m.role == 'tool':
        return [{
            # v1beta Content.role accepts only 'user' / 'model'.
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
            
            tc_provider = getattr(tc, "provider", None)
            if tc_provider and isinstance(tc_provider, dict):
                thought_sig = tc_provider.get("gemini", {}).get("thoughtSignature")
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