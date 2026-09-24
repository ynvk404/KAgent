
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import TypeGuard

from .types import ChatRequest, ChatResponse
from .reasoning import ReasoningCapabilities

class Client(ABC):

    def reasoning_capabilities(
        self, *, has_tools: bool = False
    ) -> ReasoningCapabilities | None:
        """Unknown clients retain their existing provider request behavior."""
        return None

    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def model(self) -> str:
        ...

    @abstractmethod
    async def chat(
        self,
        request: ChatRequest,
        signal: object | None = None,
    ) -> ChatResponse:
        ...


class StreamingClient(Client, ABC):

    @abstractmethod
    async def chat_stream(
        self,
        request: ChatRequest,
        on_delta: Callable[[str], None],
        signal: object | None = None,
    ) -> ChatResponse:
        ...


# ============================================================================
# Pinger
# ============================================================================


class Pinger(ABC):

    @abstractmethod
    async def ping(
        self,
        signal: object | None = None,
    ) -> None:
        ...


def is_streaming(client: Client) -> TypeGuard[StreamingClient]:
    return isinstance(client, StreamingClient)


def is_pinger(client: Client) -> TypeGuard[Pinger]:
    return isinstance(client, Pinger)
