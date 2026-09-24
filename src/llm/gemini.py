import json
from typing import Any, Callable, Dict, List, Optional

from src.logger.logger import get_logger

from .client import Client, Pinger, StreamingClient
from .errors import classify_backend
from .retry import RetryOptions, with_retry
from .providers import GEMINI_RECOMMENDED_MODELS
from .reasoning import ReasoningCapabilities, ReasoningLevel, resolve_level
from .metrics import gemini_usage
from .transport import (
    aborted,
    attach_retry_after,
    iter_sse_lines,
    new_call_id,
    new_provider_async_client,
    ping_models_endpoint,
    resolve_max_tokens,
    run_cancellable,
)
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

logger = get_logger("llm.gemini")


def gemini_reasoning_capabilities(model: str) -> ReasoningCapabilities | None:
    if with_models_prefix(model) not in GEMINI_RECOMMENDED_MODELS:
        return None
    # Gemini 3.x supports thinkingLevel low/medium/high. None of these
    # recommended models guarantees a fully disabled thinking mode.
    return ReasoningCapabilities(
        frozenset({ReasoningLevel.LOW, ReasoningLevel.MEDIUM, ReasoningLevel.HIGH}),
        fallbacks={ReasoningLevel.OFF: ReasoningLevel.LOW},
    )


def _emit_delta(on_delta: Callable[[str], None], text: str) -> None:
    """Keep a display callback failure from aborting a provider response."""
    try:
        on_delta(text)
    except Exception:
        logger.debug("LLM stream delta callback failed", exc_info=True)


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
        self.max_tokens = resolve_max_tokens(gen_opts)
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

    def reasoning_capabilities(
        self, *, has_tools: bool = False
    ) -> ReasoningCapabilities | None:
        return gemini_reasoning_capabilities(self.model_id)

    async def ping(self, signal: Optional[Any] = None) -> None:
        await ping_models_endpoint(
            self.base_url,
            {"x-goog-api-key": self.api_key},
            "gemini",
        )

    async def chat(self, request: ChatRequest, signal: Optional[Any] = None) -> ChatResponse:
        retry_count = 0
        retry_wait_ms = 0.0

        def on_retry(info: Any) -> None:
            nonlocal retry_count, retry_wait_ms
            retry_count += 1
            retry_wait_ms += info["delay_ms"]

        response = await with_retry(
            lambda: self._chat_once(request, signal),
            RetryOptions(signal=signal, on_retry=on_retry),
        )
        response.retry_count = retry_count
        response.retry_wait_ms = round(retry_wait_ms, 2)
        return response

    async def _chat_once(self, req: ChatRequest, signal: Optional[Any] = None) -> ChatResponse:
        body = encode_request(req, self._gen_opts())
        async with new_provider_async_client() as client:
            try:
                resp = await run_cancellable(
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
                if aborted(signal):
                    raise
                raise classify_backend('gemini', err, 0, None)

            raw = resp.text
            if resp.status_code != 200:
                raise attach_retry_after(classify_backend('gemini', None, resp.status_code, raw), resp)

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
            msg = Message(
                role="assistant", content=text,
                provider_state_provider="gemini",
                provider_state_model=self.model_id,
                gemini_parts=[p for part in parts if (p := safe_replay_part(part))],
            )
            if calls:
                msg.tool_calls = [part_to_tool_call(p) for p in calls]

            return ChatResponse(
                message=msg, finish_reason=choice.get("finishReason", ""),
                usage=gemini_usage(out.get("usageMetadata")),
            )

    async def chat_stream(
        self,
        request: ChatRequest,
        on_delta: Callable[[str], None],
        signal: Optional[Any] = None,
    ) -> ChatResponse:
        retry_count = 0
        retry_wait_ms = 0.0

        def on_retry(info: Any) -> None:
            nonlocal retry_count, retry_wait_ms
            retry_count += 1
            retry_wait_ms += info["delay_ms"]

        client, resp = await with_retry(
            lambda: self._open_stream(request, signal),
            RetryOptions(signal=signal, on_retry=on_retry),
        )
        
        chunks: List[str] = []
        calls: List[Dict[str, Any]] = []
        replay_parts: list[dict[str, Any]] = []
        finish = ""
        usage = None

        async def consume() -> None:
            nonlocal finish, usage
            async for line in iter_sse_lines(resp):
                if not line.startswith('data:'):
                    continue
                data = line[5:].strip()
                if not data or data == '[DONE]':
                    continue
                try:
                    chunk = json.loads(data)
                except json.JSONDecodeError:
                    continue

                parsed_usage = gemini_usage(chunk.get("usageMetadata"))
                if parsed_usage is not None:
                    usage = parsed_usage

                if chunk.get("error", {}).get("message"):
                    raise classify_backend('gemini', None, 200, chunk["error"]["message"])

                candidates = chunk.get("candidates", [])
                choice = candidates[0] if candidates else None
                if not choice:
                    continue

                if choice.get("finishReason"):
                    finish = choice["finishReason"]

                for part in choice.get("content", {}).get("parts", []):
                    replay_part = safe_replay_part(part)
                    if replay_part:
                        replay_parts.append(replay_part)
                    if part.get("functionCall", {}).get("name"):
                        calls.append(part)
                        continue
                    if part.get("thought") or not part.get("text"):
                        continue

                    _emit_delta(on_delta, part["text"])
                    chunks.append(part["text"])

        try:
            await run_cancellable(consume(), signal)
        finally:
            await resp.aclose()
            await client.aclose()

        msg = Message(
            role="assistant", content="".join(chunks),
            provider_state_provider="gemini",
            provider_state_model=self.model_id,
            gemini_parts=replay_parts,
        )
        if calls:
            msg.tool_calls = [part_to_tool_call(p) for p in calls]

        return ChatResponse(
            message=msg, finish_reason=finish, usage=usage,
            retry_count=retry_count,
            retry_wait_ms=round(retry_wait_ms, 2),
        )

    async def _open_stream(self, req: ChatRequest, signal: Optional[Any] = None):
 
        body = encode_request(req, self._gen_opts())
        client = new_provider_async_client()
        
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
            resp = await run_cancellable(client.send(req_obj, stream=True), signal)
        except Exception as err:
            await client.aclose()
            if aborted(signal):
                raise
            raise classify_backend('gemini', err, 0, None)

        if resp.status_code != 200:
            await resp.aread()
            raw = resp.text
            await resp.aclose()
            await client.aclose()
            raise attach_retry_after(classify_backend('gemini', None, resp.status_code, raw), resp)

        return client, resp


def part_to_tool_call(part: Dict[str, Any]) -> ToolCall:

    fc = part.get("functionCall", {})
    thought_sig = part.get("thoughtSignature") or part.get("thought_signature")

    tc = _CompatToolCall(
        id=new_call_id(16),
        function=FunctionCall(
            name=fc.get("name", ""),
            arguments=json.dumps(fc.get("args", {})),
        ),
    )
    if thought_sig:
        tc.provider = ToolProvider(gemini=GeminiProvider(thought_signature=thought_sig))

    return tc


def safe_replay_part(part: Any) -> dict[str, Any] | None:
    """Retain signed provider parts exactly; discard unsigned thought text."""
    if not isinstance(part, dict):
        return None
    result: dict[str, Any] = {}
    call = part.get("functionCall")
    if isinstance(call, dict) and isinstance(call.get("name"), str):
        result["functionCall"] = {
            "name": call["name"],
            "args": call.get("args") if isinstance(call.get("args"), dict) else {},
        }
    signature = part.get("thoughtSignature") or part.get("thought_signature")
    signed = isinstance(signature, str)
    if "functionCall" not in result and isinstance(part.get("text"), str):
        if not part.get("thought") or signed:
            result["text"] = part["text"]
            if part.get("thought"):
                result["thought"] = True
    if signed and result:
        result["thoughtSignature"] = signature
    return result or None


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
    previous_was_tool = False
    for m in req.messages:
        if m.role != 'system':
            encoded = encode_message(m, req.model)
            if m.role == "tool" and previous_was_tool and contents and encoded:
                contents[-1]["parts"].extend(encoded[0]["parts"])
            else:
                contents.extend(encoded)
            previous_was_tool = m.role == "tool"

    body: Dict[str, Any] = {"contents": contents}

    if system_text:
        body["systemInstruction"] = {"parts": [{"text": system_text}]}

    if req.tools:
        body["tools"] = [{"functionDeclarations": [encode_tool(t) for t in req.tools]}]

    generation_config: Dict[str, Any] = {}
    if gen_opts.get("temperature") is not None:
        generation_config["temperature"] = gen_opts["temperature"]
    max_tokens = resolve_max_tokens(gen_opts)
    if max_tokens is not None and max_tokens > 0:
        generation_config["maxOutputTokens"] = max_tokens

    thinking_budget = gen_opts.get("thinkingBudget")
    resolution = (
        resolve_level(req.reasoning_level, gemini_reasoning_capabilities(req.model))
        if req.reasoning_level is not None
        else None
    )
    effective = resolution.effective if resolution is not None else None
    if effective is not None:
        # Explicit turn policy takes precedence over the legacy numeric budget.
        # Direct callers without a generic level retain their old budget.
        thinking_config: Dict[str, Any] = {"thinkingLevel": effective.value}
        if thinking_budget is not None and thinking_budget > 0:
            thinking_config["includeThoughts"] = True
        generation_config["thinkingConfig"] = thinking_config
    elif thinking_budget is not None and thinking_budget >= 0:
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


def encode_message(m: Message, model: str | None = None) -> List[Dict[str, Any]]:
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
        if (
            m.gemini_parts is not None
            and m.provider_state_provider == "gemini"
            and model is not None and m.provider_state_model is not None
            and with_models_prefix(model) == with_models_prefix(m.provider_state_model)
        ):
            replay_parts: list[dict[str, Any]] = []
            for raw in m.gemini_parts:
                replay_part = safe_replay_part(raw)
                if replay_part is not None:
                    replay_parts.append(replay_part)
            return [{"role": "model", "parts": replay_parts}] if replay_parts else []
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

            if (thought_sig and m.provider_state_provider == "gemini"
                    and model is not None and m.provider_state_model is not None
                    and with_models_prefix(model) == with_models_prefix(m.provider_state_model)):
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
