"""Shared deterministic doubles for agent integration tests."""

from collections.abc import Generator
import json
from typing import Any

from src.llm.core.client import Client
from src.llm.core.types import ChatRequest, ChatResponse, FunctionCall, Message, ToolCall


class FakeSignal:
    def __init__(self) -> None:
        self.aborted = False


class FakeClient(Client):
    def __init__(self, scripted: list[ChatResponse]) -> None:
        self.scripted = scripted
        self.idx = 0
        self.requests: list[ChatRequest] = []

    def name(self) -> str:
        return "fake"

    def model(self) -> str:
        return "fake-model"

    async def chat(self, request: ChatRequest, signal=None) -> ChatResponse:
        self.requests.append(request)
        if self.idx >= len(self.scripted):
            raise Exception("FakeClient: script exhausted")
        response = self.scripted[self.idx]
        self.idx += 1
        return response


class ScriptedModel(Client):
    """One call per step, driven by the previous production tool's feedback.

    Retain script failures separately: Agent can catch/retry provider errors.
    Exhaustion allows tool-free synthesis, but never another scripted effect.
    """

    def __init__(self, script: Generator[tuple[str, Any], str, None], *, prefix="scenario"):
        self.script = script
        self.prefix = prefix
        self.calls: list[tuple[str, Any]] = []
        self.errors: list[Exception] = []
        self.started = False
        self.consumed = False
        self.summaries = 0
        self.runtime_stop: tuple[int, str] | None = None

    def name(self) -> str:
        return "fake"

    def model(self) -> str:
        return "offline-scenario"

    async def chat(self, request: ChatRequest, signal=None) -> ChatResponse:
        try:
            if self.errors:
                raise AssertionError("script failed earlier; provider retry cannot repair it")
            if self.consumed:
                self.summaries += 1
                assert self.summaries <= 3, "unexpected repeated synthesis"
                return self._summary()
            if self.started:
                feedback = next(m for m in reversed(request.messages) if m.role == "tool")
                if (self.runtime_stop is not None and request.tools is None
                        and len(self.calls) == self.runtime_stop[0]
                        and (feedback.tool_call_id or "").startswith(self.runtime_stop[1])):
                    self.script.close()
                    self.consumed = True
                    self.summaries += 1
                    return self._summary()
                assert feedback.tool_call_id == f"{self.prefix}-{len(self.calls)}", "wrong tool feedback"
                name, args = self.script.send(feedback.content)
            else:
                self.started = True
                name, args = next(self.script)
            assert request.tools, "runtime requested synthesis before the script finished"
            # Invalid names and raw JSON reach production dispatch unchanged.
            self.calls.append((name, args.copy() if isinstance(args, dict) else args))
            return ChatResponse(Message("assistant", "", tool_calls=[ToolCall(
                f"{self.prefix}-{len(self.calls)}", FunctionCall(name, args if isinstance(args, str) else json.dumps(args)),
            )]), "tool_calls")
        except StopIteration:
            self.consumed = True
            self.summaries += 1
            return self._summary()
        except Exception as error:
            self.errors.append(error)
            raise

    @staticmethod
    def _summary() -> ChatResponse:
        return ChatResponse(Message("assistant", "Bounded fixture observations recorded; remaining limitations are in the workflow."), "stop")


class EchoTool:
    def __init__(self) -> None:
        self.calls = 0

    def name(self) -> str:
        return "echo"

    def description(self) -> str:
        return "echo"

    def schema(self) -> dict:
        return {"type": "object", "properties": {"msg": {"type": "string"}}}

    def requires_permission(self) -> bool:
        return False

    async def run(self, args: dict[str, Any], signal, prompter) -> str:
        self.calls += 1
        return f"echoed: {str(args.get('msg', ''))}"


def seed_compactable_history(agent, size: int = 12_000) -> None:
    agent.history.extend(
        [
            Message(role="user", content="older request " + "x" * size),
            Message(role="assistant", content="older answer " + "y" * size),
        ]
    )


def collect() -> dict:
    events = []

    def sink(event) -> None:
        events.append(event)

    return {"events": events, "sink": sink}
