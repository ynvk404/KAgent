"""
LLM client interfaces.

Streaming uses an `on_delta` callback rather than an async iterator so
the call site can keep an imperative flow. Higher layers may wrap the
callback into an async iterator if needed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import TypeGuard

from .types import ChatRequest, ChatResponse


# ============================================================================
# Client
# ============================================================================


class Client(ABC):
    """Base interface implemented by every LLM backend."""

    @abstractmethod
    def name(self) -> str:
        """
        Backend label.

        Examples:
            openai
            openrouter
            groq
            gemini
        """
        ...

    @abstractmethod
    def model(self) -> str:
        """Currently selected model identifier."""
        ...

    @abstractmethod
    async def chat(
        self,
        request: ChatRequest,
        signal: object | None = None,
    ) -> ChatResponse:
        """
        Execute a non-streaming chat request.
        """
        ...


# ============================================================================
# Streaming Client
# ============================================================================


class StreamingClient(Client, ABC):
    """
    Client supporting streaming chat responses.
    """

    @abstractmethod
    async def chat_stream(
        self,
        request: ChatRequest,
        on_delta: Callable[[str], None],
        signal: object | None = None,
    ) -> ChatResponse:
        """
        Execute a streaming chat request.

        `on_delta` is invoked for every text chunk produced by the model.
        The returned ChatResponse contains the accumulated final message.
        """
        ...


# ============================================================================
# Pinger
# ============================================================================


class Pinger(ABC):
    """
    Optional interface for health checking.

    Implementations should perform a lightweight request against the
    backend and:

    - return normally when reachable (including HTTP 401/403),
    - raise an exception on transport failures or server errors.
    """

    @abstractmethod
    async def ping(
        self,
        signal: object | None = None,
    ) -> None:
        ...


# ============================================================================
# Type Guards
# ============================================================================


def is_streaming(client: Client) -> TypeGuard[StreamingClient]:
    """
    Return True if the client supports streaming responses.
    """
    return isinstance(client, StreamingClient)


def is_pinger(client: Client) -> TypeGuard[Pinger]:
    """
    Return True if the client supports health checks.
    """
    return isinstance(client, Pinger)