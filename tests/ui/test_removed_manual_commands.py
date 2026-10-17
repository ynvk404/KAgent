"""Legacy slash strings use the normal agent prompt path."""
import asyncio
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, Mock

import pytest

from src.ui.commands.slash_handler import build_help_text
from src.ui.commands.slash_items import filter_slash
from tests.helpers.agent_fakes import FakeClient
from tests.ui.test_app import make_app
from tests.ui.test_slash_handler import HelpAgent


LEGACY_COMMANDS = ("/review-result", "/enrich-cwe", "/next", "/snapshot")


@pytest.mark.parametrize("command", LEGACY_COMMANDS)
@pytest.mark.parametrize("arguments", ["", " candidate-id", " candidate-id confirmed high observed impact"])
@pytest.mark.parametrize("padding", ["", " \t"])
async def test_legacy_command_submit_uses_normal_agent_prompt_path(command, arguments, padding):
    app = cast(Any, make_app())
    client = FakeClient([])
    execute = AsyncMock(side_effect=AssertionError("slash dispatch must not execute tools"))
    skills = SimpleNamespace(has=Mock(return_value=False))
    app.agent = SimpleNamespace(client=client, tools=SimpleNamespace(execute=execute), skills=skills)
    app.run_agent_turn = AsyncMock()

    prompt = padding + command + arguments + " \n"
    app.submit(prompt)
    await asyncio.sleep(0)

    app.run_agent_turn.assert_awaited_once()
    awaited = app.run_agent_turn.await_args
    assert awaited is not None
    assert awaited.args[0] == prompt
    execute.assert_not_called()
    assert not client.requests

def test_legacy_commands_absent_from_menu_prefixes_and_help():
    help_text = build_help_text(cast(Any, HelpAgent()), lambda: {"backend": "ollama", "model": "test"})
    menu = {item.name for item in filter_slash("/")}
    for command in LEGACY_COMMANDS:
        assert command not in menu
        assert command not in help_text
        assert not filter_slash(command)


async def test_valid_slash_command_still_intercepts_before_agent_turn():
    app = cast(Any, make_app())
    app.agent = HelpAgent()
    app.run_agent_turn = AsyncMock()

    app.submit("/help")
    await asyncio.sleep(0)

    app.run_agent_turn.assert_not_awaited()
    assert app.state.transcript[-1].help_document is not None


@pytest.mark.parametrize("prompt", [
    "", "plain prompt", "/review-result-extra", "/enrich-cwe-extra", "/next-extra",
    "/help-typo", "/target-typo",
])
async def test_other_input_keeps_existing_agent_fallback(prompt):
    app = cast(Any, make_app())
    app.agent.skills.has = lambda _: False
    app.run_agent_turn = AsyncMock()
    app.submit(prompt)
    await asyncio.sleep(0)
    app.run_agent_turn.assert_awaited_once()
    assert app.run_agent_turn.call_args.args[0] == prompt
