from __future__ import annotations

import asyncio

import pytest

from src.ask.ask import Option, Question
from src.ui.bridges.ask_bridge import AskRequest, BridgedAskPrompter


@pytest.mark.asyncio
async def test_bridge_accepts_the_ask_prompter_signal_argument():
    published: list[AskRequest | None] = []
    prompter = BridgedAskPrompter(published.append)
    question = Question(
        question="What should be reset?",
        options=[Option("Browser capture data"), Option("Coverage state")],
    )

    pending = asyncio.create_task(prompter.ask(question, signal=object()))
    await asyncio.sleep(0)

    request = published[-1]
    assert isinstance(request, AskRequest)
    request.resolve("Coverage state")

    assert await pending == "Coverage state"
    assert published[-1] is None


@pytest.mark.asyncio
async def test_abort_signal_closes_active_ask_and_allows_a_later_request():
    published: list[AskRequest | None] = []
    prompter = BridgedAskPrompter(published.append)
    signal = asyncio.Event()
    question = Question(
        question="What should be reset?",
        options=[Option("Browser capture data"), Option("Coverage state")],
    )

    cancelled = asyncio.create_task(prompter.ask(question, signal))
    await asyncio.sleep(0)
    assert isinstance(published[-1], AskRequest)

    signal.set()
    with pytest.raises(Exception, match="aborted"):
        await cancelled
    assert published[-1] is None

    next_request = asyncio.create_task(prompter.ask(question))
    await asyncio.sleep(0)
    request = published[-1]
    assert isinstance(request, AskRequest)
    request.resolve("Browser capture data")
    assert await next_request == "Browser capture data"
    assert published[-1] is None


@pytest.mark.asyncio
async def test_preaborted_signal_does_not_publish_an_ask_request():
    published: list[AskRequest | None] = []
    prompter = BridgedAskPrompter(published.append)
    signal = asyncio.Event()
    signal.set()
    question = Question(
        question="Continue?",
        options=[Option("Yes"), Option("No")],
    )

    with pytest.raises(Exception, match="aborted"):
        await prompter.ask(question, signal)
    assert published == []


@pytest.mark.asyncio
async def test_task_cancellation_closes_an_active_ask_request():
    published: list[AskRequest | None] = []
    prompter = BridgedAskPrompter(published.append)
    question = Question(
        question="Continue?",
        options=[Option("Yes"), Option("No")],
    )

    pending = asyncio.create_task(prompter.ask(question))
    await asyncio.sleep(0)
    assert isinstance(published[-1], AskRequest)

    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    assert published[-1] is None
