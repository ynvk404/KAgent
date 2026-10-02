from __future__ import annotations

from unittest.mock import Mock

import pytest

from src.ui.bridges.perm_bridge import BridgedPermissionRequest
from src.ui.core.app import KAgent
from src.ui.core.state import SetPerm
from tests.ui.test_app import make_app


@pytest.mark.asyncio
async def test_full_approval_detail_can_be_reviewed_with_keyboard_scroll(monkeypatch):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    # The shared fixture stubs repaint methods for non-mounted unit tests.
    # This integration check needs the real repaint/keyboard path.
    app._sync_overlay = KAgent._sync_overlay.__get__(app, KAgent)
    resolve = Mock()
    request = BridgedPermissionRequest(
        tool="shell", summary="Review command",
        detail="\n".join(f"line {i}: " + "x" * 100 for i in range(100)) + "\nLAST_OPERATION",
        resolve=resolve, reject=Mock(),
    )
    async with app.run_test(size=(80, 40)) as pilot:
        app.dispatch(SetPerm(request))
        app._sync_overlay()
        await pilot.pause()
        assert app._perm_modal and not app._perm_modal.show_full_detail
        await pilot.press("v")
        await pilot.pause()
        assert app._perm_modal and app._perm_modal.show_full_detail
        await pilot.press("end")
        await pilot.pause()
        assert app.overlay_content_static.scroll_y > 0
        assert app.overlay_content_static.scroll_y == app.overlay_content_static.max_scroll_y
        await pilot.press("home")
        await pilot.pause()
        assert app.overlay_content_static.scroll_y == 0
        resolve.assert_not_called()
