"""Retired command names stop at the UI and cannot become agent instructions."""
import asyncio
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, Mock

import pytest

from src.ui.commands.slash_handler import build_help_text, handle_slash
from src.ui.commands.slash_items import filter_slash
from tests.helpers.agent_fakes import FakeClient
from tests.ui.test_app import make_app
from tests.ui.test_slash_handler import HelpAgent


REMOVED = ("/review-result", "/enrich-cwe", "/next")


@pytest.mark.parametrize("command", REMOVED)
@pytest.mark.parametrize("arguments", ["", " candidate-id", " candidate-id confirmed high observed impact"])
@pytest.mark.parametrize("padding", ["", " \t"])
async def test_removed_command_submit_never_starts_agent_or_tools(command, arguments, padding):
    app = cast(Any, make_app())
    client = FakeClient([])
    execute = AsyncMock(side_effect=AssertionError("retired commands cannot execute tools"))
    skills = SimpleNamespace(has=Mock(side_effect=AssertionError("retired names are reserved")))
    app.agent = SimpleNamespace(client=client, tools=SimpleNamespace(execute=execute), skills=skills)
    app.run_agent_turn = AsyncMock()

    app.submit(padding + command + arguments + " \n")
    await asyncio.sleep(0)

    app.run_agent_turn.assert_not_called()
    execute.assert_not_called()
    assert not client.requests
    assert app.state.transcript[-1].text == f"{command}: command has been removed."


@pytest.mark.parametrize("command", REMOVED)
def test_removed_command_is_handled_without_runtime_or_tasks(command):
    notices = []
    # Deliberately no agent: handling a retired command is local presentation.
    assert handle_slash(cast(Any, SimpleNamespace(dispatch=notices.append)), command)
    assert notices[-1].entry.text == f"{command}: command has been removed."


def test_removed_commands_absent_from_menu_prefixes_and_help():
    help_text = build_help_text(cast(Any, HelpAgent()), lambda: {"backend": "ollama", "model": "test"})
    menu = {item.name for item in filter_slash("/")}
    for command in REMOVED:
        assert command not in menu
        assert command not in help_text
        assert not filter_slash(command)


@pytest.mark.parametrize("prompt", ["", "plain prompt", "/review-result-extra", "/enrich-cwe-extra", "/next-extra"])
async def test_other_input_keeps_existing_agent_fallback(prompt):
    app = cast(Any, make_app())
    app.agent.skills.has = lambda _: False
    app.run_agent_turn = AsyncMock()
    app.submit(prompt)
    await asyncio.sleep(0)
    app.run_agent_turn.assert_awaited_once()
    assert app.run_agent_turn.call_args.args[0] == prompt
