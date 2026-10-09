"""Deterministic request estimates, never provider usage or exact token counts.

UTF-8 bytes / 4 rounded up reserves more for Unicode than the old character
heuristic. Four tokens per represented message/call reserve role/envelope
framing; these are small policy allowances, not vendor tokenizer constants.
Opaque signatures reserve one token per encoded character without decoding.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
import json
from typing import Any

from src.llm.core.types import ChatRequest, Message
from src.llm.providers.gemini import encode_message as gemini_message
from src.llm.providers.openai import reasoning_replay_eligible


def text_tokens(text: str) -> int:
    return (len(text.encode("utf-8")) + 3) // 4 if text else 0


def schema_tokens(tools: list[Any] | None) -> int:
    if not tools:
        return 0
    return text_tokens(json.dumps(
        [asdict(tool) if is_dataclass(tool) and not isinstance(tool, type) else tool for tool in tools],
        ensure_ascii=False,
    ))


@dataclass(frozen=True)
class ContextEstimate:
    system_tokens: int = 0
    history_tokens: int = 0
    incoming_tokens: int = 0
    injected_tokens: int = 0
    tool_schema_tokens: int = 0
    provider_private_tokens: int = 0
    framing_tokens: int = 0
    compactable_history_tokens: int = 0

    @property
    def estimated_total(self) -> int:
        return (self.system_tokens + self.history_tokens + self.incoming_tokens
                + self.injected_tokens + self.tool_schema_tokens
                + self.provider_private_tokens + self.framing_tokens)

    @property
    def fixed_floor_tokens(self) -> int:
        return self.estimated_total - self.compactable_history_tokens


def message_cost(message: Message, req: ChatRequest, provider: str) -> tuple[int, int, int]:
    """Visible, eligible private, framing costs of the selected representation."""
    if provider == "gemini" and message.role != "system":
        encoded = gemini_message(message, req.model)
        visible = private = framing = 0
        for item in encoded:
            framing += 4
            for part in item["parts"]:
                cost = text_tokens(part.get("text", ""))
                if part.get("thought"):
                    private += cost
                else:
                    visible += cost
                for field in ("functionCall", "functionResponse"):
                    if field in part:
                        visible += text_tokens(json.dumps(part[field], ensure_ascii=False))
                        framing += 4
                # Opaque bytes may tokenize very differently from prose.
                private += len(part.get("thoughtSignature", ""))
        return visible, private, framing

    visible = text_tokens(message.content)
    private = (text_tokens(message.reasoning_content or "")
               if reasoning_replay_eligible(message, req, provider, req.model) else 0)
    framing = 4
    for call in message.tool_calls or []:
        visible += text_tokens(call.function.name) + text_tokens(call.function.arguments)
        framing += 4 + text_tokens(call.id)
    if message.name:
        framing += text_tokens(message.name)
    if message.tool_call_id:
        framing += text_tokens(message.tool_call_id)
    return visible, private, framing


def estimate_request(req: ChatRequest, provider: str = "", *,
                     history_count: int | None = None,
                     incoming_index: int | None = None) -> ContextEstimate:
    """Projection callers identify history and pending input; guards count all.

    History boundaries refer to the source history prefix, including system.
    Private/framing costs are separate, while compactable history includes its
    own private/framing contribution. Only the initial system prompt is fixed
    inside history; later system messages (including slash-injected skills)
    belong to the history[1:] input summarized by compaction. System messages
    injected outside that history prefix remain fixed request context.
    No disk artifacts are read here.
    """
    system = history = incoming = injected = private = framing = compactable = 0
    for index, message in enumerate(req.messages):
        visible_cost, private_cost, framing_cost = message_cost(message, req, provider)
        private += private_cost
        framing += framing_cost
        in_history = history_count is None or index < history_count
        if message.role == "system" and (index == 0 or not in_history):
            system += visible_cost
        elif index == incoming_index:
            incoming += visible_cost
        elif in_history:
            history += visible_cost
            compactable += visible_cost + private_cost + framing_cost
        else:
            injected += visible_cost
    return ContextEstimate(system, history, incoming, injected, schema_tokens(req.tools),
                           private, framing, compactable)


def approximate_message_tokens(messages: list[Message]) -> int:
    """Idle generic history estimate; no active provider-private replay assumed."""
    return estimate_request(ChatRequest(model="", messages=messages)).estimated_total
