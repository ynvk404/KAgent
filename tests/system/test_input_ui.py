"""Real runtime's idle UI survives long text, picker navigation and resizing."""
import pytest

from src.ui.widgets.skills_modal import SkillsModal
from tests.helpers.system_runtime import assert_idle, drain, make_system_app
from tests.system.test_local_boundaries import runtime_for


async def test_input_picker_resize_and_viewport_with_real_runtime(tmp_path, local_lab):
    rt = runtime_for(tmp_path, local_lab)
    app = make_system_app(rt)
    try:
        async with app.run_test(size=(100, 32)) as pilot:
            app.input.set_value("long synthetic input " * 250)
            app._render_input()
            await pilot.resize_terminal(42, 20)
            # The full text widget is virtual content; the visible scrolling
            # panel and caret, rather than its offscreen rows, must stay visible.
            for widget in (app.input_panel, app.status_bar):
                assert widget.region.x >= 0 and widget.region.right <= 42
                assert widget.region.y >= 0 and widget.region.bottom <= 20
            assert 0 < app.input_panel.scroll_y <= app.input_panel.max_scroll_y
            assert app.input_panel.region.contains(app.cursor_position.x, app.cursor_position.y)
            assert app.input.value.endswith("input ")
            app.input.set_value("/")
            app._render_input()
            await pilot.press("down", "down", "up", "escape")
            assert app.input.value == "" and app._get_active_modal() is None
            app.submit("/skills")
            await pilot.pause()
            modal = app._get_active_modal()
            assert isinstance(modal, SkillsModal)
            await pilot.press(*(["down"] * 12), "up")
            assert 0 <= modal.idx < len(rt.skills.list())
            await pilot.resize_terminal(55, 22)
            assert app.overlay_static.region.right <= 55 and app.overlay_static.region.bottom <= 22
            await pilot.press("escape")
            assert app._get_active_modal() is None
            app.input.clear()
            await pilot.press("x")
            assert app.input.value == "x"
            assert app.transcript_log.scroll_x == 0
            assert not rt.client.requests and not local_lab.wire
            assert_idle(app)
    finally:
        await drain(rt)
