"""The input sends @ text literally without a file completion menu."""
from unittest.mock import AsyncMock
from typing import cast

import pytest

from src.ui.core.app import KAgent
from tests.ui.test_input_rendering import app


@pytest.mark.parametrize("value", ["@", "@note.txt", "review @note.txt", "user@example.test"])
async def test_at_text_accepts_tab_and_submits_without_completion(app: KAgent, tmp_path, monkeypatch, value):
    (tmp_path / "note.txt").write_text("fixture content")
    monkeypatch.chdir(tmp_path)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press(*value)
        assert app.input.value == value
        assert not app.overlay_static.display
        assert not app.slash_matches

        await pilot.press("tab")
        assert app.input.value == value + "\t"
        assert not app.overlay_static.display
        cast(AsyncMock, app.run_agent_turn).assert_not_called()

        await pilot.press("enter")
        cast(AsyncMock, app.run_agent_turn).assert_awaited_once()
        assert cast(AsyncMock, app.run_agent_turn).call_args.args[0] == value
        assert app.input.value == ""
