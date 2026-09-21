"""Shared deterministic doubles for agent integration tests."""

from typing import Any

from src.llm.client import Client
from src.llm.types import ChatRequest, ChatResponse, Message


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
