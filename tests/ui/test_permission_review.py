from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from src.permission.permission import UserControlledRefusal
from src.tools.common.registry import Registry
from src.tools.execution.shell import ShellTool
from src.ui.bridges.perm_bridge import BridgedPermissionRequest, BridgedPrompter
from src.ui.core.app import AbortEvent, KAgent
from src.ui.core.state import SetBusy, SetPerm
from tests.ui.test_app import make_app


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(80, 40), (40, 18)])
async def test_full_approval_detail_can_be_reviewed_with_keyboard_scroll(monkeypatch, size):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    # The shared fixture stubs repaint methods for non-mounted unit tests.
    # This integration check needs the real repaint/keyboard path.
    app._sync_overlay = KAgent._sync_overlay.__get__(app, KAgent)
    resolve = Mock()
    request = BridgedPermissionRequest(
        tool="shell", summary="Review command",
        detail="\n".join(f"line {i}: " + "x" * 100 for i in range(100))
        + "\nLAST_OPERATION --token=fake-secret",
        risk_tier="high-impact", no_session_cache=True,
        resolve=resolve, reject=Mock(),
    )
    async with app.run_test(size=size) as pilot:
        app.dispatch(SetPerm(request))
        app._sync_overlay()
        await pilot.pause()
        assert app._perm_modal and not app._perm_modal.show_full_detail
        assert app.overlay_static.border_title == "Permission"
        assert app.overlay_static.region.right <= size[0]
        assert app.overlay_static.region.bottom <= size[1]
        assert app.overlay_content_static.max_scroll_x == 0
        preview = _content_text(app)
        assert "LAST_OPERATION" not in preview
        assert "truncated" in preview
        await pilot.press("v")
        await pilot.pause()
        assert app._perm_modal and app._perm_modal.show_full_detail
        full = _content_text(app)
        assert "LAST_OPERATION" in full
        assert "fake-secret" not in full
        assert "truncated" not in full
        assert full.count("y allow once") == 1
        assert full.count("n deny") == 1
        await pilot.press("pagedown")
        await pilot.pause()
        assert app.overlay_content_static.scroll_y > 0
        await pilot.press("end")
        await pilot.pause()
        assert app.overlay_content_static.scroll_y > 0
        assert app.overlay_content_static.scroll_y == app.overlay_content_static.max_scroll_y
        visible = _content_text(app, visible_only=True)
        assert "v preview" in visible
        await pilot.press("home")
        await pilot.pause()
        assert app.overlay_content_static.scroll_y == 0
        assert "Tool: shell" in _content_text(app, visible_only=True)
        resolve.assert_not_called()


def _content_text(app: KAgent, *, visible_only: bool = False) -> str:
    widget = app.overlay_text_static
    first = int(app.overlay_content_static.scroll_y) if visible_only else 0
    last = widget.virtual_size.height
    if visible_only:
        last = min(first + app.overlay_content_static.size.height, last)
    return "\n".join(widget.render_line(y).text for y in range(first, last))


@pytest.mark.asyncio
async def test_short_high_impact_shell_preview_needs_no_scroll_at_normal_size(monkeypatch):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    req = BridgedPermissionRequest(
        tool="shell", summary="shell: pwd; python3 --version", detail="pwd; python3 --version",
        risk_tier="high-impact", no_session_cache=True, resolve=Mock(), reject=Mock(),
    )
    async with app.run_test(size=(64, 40)) as pilot:
        app.dispatch(SetPerm(req))
        KAgent._sync_overlay(app)
        await pilot.pause()
        assert app.overlay_static.border_title == "Permission"
        assert app.overlay_content_static.max_scroll_y == 0
        text = _content_text(app, visible_only=True)
        assert "all Shell commands" in text
        assert "approval is not cached" in text
        assert "pwd; python3 --version" in text
        assert "y allow once · n deny · Esc cancel" in text


@pytest.mark.asyncio
@pytest.mark.parametrize("key", ["y", "n", "escape"])
async def test_shell_operator_decision_reaches_registry_without_changing_execution(monkeypatch, key):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    app._sync_overlay = KAgent._sync_overlay.__get__(app, KAgent)
    app.run_abort_event = AbortEvent()
    app.dispatch(SetBusy(True))
    bridge = BridgedPrompter(lambda req: app.dispatch(SetPerm(req)))
    run_capture = AsyncMock(return_value="fixture output")
    monkeypatch.setattr("src.tools.execution.shell.run_with_capture", run_capture)
    registry = Registry()
    registry.register(ShellTool())
    command = "pwd; python3 --version"

    async with app.run_test(size=(64, 30)) as pilot:
        pending = asyncio.create_task(
            registry.execute("shell", {"command": command}, app.run_abort_event, bridge)
        )
        try:
            await pilot.pause()
            assert app.state.pending_perm is not None
            assert app.state.pending_perm.risk_tier == "high-impact"
            assert app.state.pending_perm.no_session_cache is True
            run_capture.assert_not_called()
            await pilot.press("a")
            await pilot.pause()
            assert not pending.done()
            run_capture.assert_not_called()
            await pilot.press(key)
            if key == "y":
                assert await asyncio.wait_for(pending, 2) == "fixture output"
                run_capture.assert_awaited_once()
                assert run_capture.call_args.args[1][-1] == command
            elif key == "n":
                with pytest.raises(UserControlledRefusal):
                    await asyncio.wait_for(pending, 2)
                run_capture.assert_not_called()
            else:
                with pytest.raises(Exception, match="aborted"):
                    await asyncio.wait_for(pending, 2)
                assert app.run_abort_event.is_set()
                run_capture.assert_not_called()
            assert app.state.pending_perm is None
            assert not bridge._session_allowed
        finally:
            if not pending.done():
                pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
