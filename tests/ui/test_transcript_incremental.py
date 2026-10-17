import time
from dataclasses import replace
from textual.geometry import Offset
from textual.selection import Selection

import pytest

from src.ui.core.app import KAgent
from src.ui.core.state import TranscriptEntry
from tests.ui.test_overview import _make_app


@pytest.mark.parametrize("reading", [False, True])
async def test_one_changed_entry_preserves_other_strips_and_viewport(monkeypatch, reading):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = _make_app()
    async with app.run_test(size=(100, 30)) as pilot:
        rows = tuple(TranscriptEntry("system", f"Fixture entry {index}") for index in range(300))
        app.state = replace(app.state, transcript=rows)
        app._recompute_view()
        await pilot.pause()
        if reading:
            app.transcript_log.scroll_to(y=400, animate=False, immediate=True, force=True)
        before_top = app.transcript_log.scroll_y
        app.screen.selections = {app.transcript_log: Selection(Offset(0, 400), Offset(18, 400))}
        selected_before = app.screen.get_selected_text()
        before = list(app.transcript_log.lines)
        changes = []
        original = app.transcript_writer._replace_lines
        assert original is not None
        def replace_lines(start, end, lines):
            changes.append((start, end))
            return original(start, end, lines)
        monkeypatch.setattr(app.transcript_writer, "_replace_lines", replace_lines)
        updated = list(rows)
        updated[100] = TranscriptEntry("assistant", "**Updated entry**\nextra line")
        app.state = replace(app.state, transcript=tuple(updated), transcript_revision=1)
        started = time.perf_counter()
        app._recompute_view()
        print({"transcript_incremental_ms": (time.perf_counter()-started)*1000, "entries_replaced": len(changes)})
        assert len(changes) == 1
        start, end = changes[0]
        assert all(a is b for a, b in zip(before[:start], app.transcript_log.lines[:start]))
        assert app.transcript_log.lines[-1] is before[-1]
        await pilot.pause()
        assert app.screen.get_selected_text() == selected_before
        if reading:
            added = len(app.transcript_log.lines) - len(before)
            assert app.transcript_log.scroll_y == before_top + added
        else:
            assert app.transcript_log.is_vertical_scroll_end


async def test_viewport_context_does_not_suppress_render_errors(monkeypatch):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = _make_app()
    async with app.run_test():
        app.transcript_log.auto_scroll = False
        with pytest.raises(RuntimeError, match="synthetic render failure"):
            with app.transcript_log.preserve_viewport():
                app.transcript_log.write("changed")
                raise RuntimeError("synthetic render failure")
