"""Presentation contracts; offline inputs never grant authority."""
import pytest

from src.ui.core.state import TranscriptEntry
from src.ui.theme import BOLD_ACCENT, BOLD_ERROR, PRIMARY, WARNING
from src.ui.widgets.transcript import entry_view


@pytest.mark.parametrize("kind", ["assistant", "user"])
def test_indented_sanitized_text_keeps_role_style_and_every_line(kind):
    text = "Analysis\n  Substantive explanation\n    Final conclusion\nPermission denied is quoted text"
    entry = TranscriptEntry(kind, text)
    lines = entry_view(entry, streaming=True)
    assert all(line.color == lines[0].color for line in lines if line.text)
    assert [line.text[2:] for line in lines[:-1]] == text.splitlines()
    assert entry.text == text


def test_authoritative_milestones_and_issues_have_distinct_styles():
    assert entry_view(TranscriptEntry("info", "Candidate recorded · fixture"))[0].color == BOLD_ACCENT
    assert entry_view(TranscriptEntry("error", "Operation failed"))[0].color == BOLD_ERROR
    assert entry_view(TranscriptEntry("warning", "Permission denied"))[0].color == WARNING
    assert entry_view(TranscriptEntry("assistant", "Finding saved, validation confirmed"))[0].color == PRIMARY


def test_assistant_markdown_indentation_is_never_dimmed_by_role_renderer():
    lines = entry_view(TranscriptEntry("assistant", "Explanation\n  Still relevant\n    Final answer"))
    assert all(line.color == PRIMARY for line in lines)


def test_workflow_overview_stays_separate_from_inventory_and_blocked_outcome():
    from src.agent.events import DoneEvent
    from src.ui.core.outcomes import OutcomeFacts, ProgressRecord
    from src.ui.core.state import AgentEventAction, SetBusy, initial_state, reducer
    from src.ui.widgets.banner import BannerData
    baseline = OutcomeFacts(scope="fixture")
    state = reducer(initial_state("", BannerData("offline", "fixture", ".")), SetBusy(True, facts=baseline))
    facts = OutcomeFacts(scope="fixture", overview="Workflow · enumeration pending · 0/1 inputs reviewed",
                         records=(ProgressRecord("input", "one", "GET /search · q", "pending"),))
    state = reducer(state, AgentEventAction(DoneEvent(stop_reason="workflow_blocked"), facts=facts))
    inventory = [entry for entry in state.transcript if entry.text.startswith("Attack surface recorded:")]
    assert len(inventory) == 1
    assert "1 input (1 pending)" in inventory[0].text and "GET /search · q" in inventory[0].text
    assert inventory[0].kind == "info" and entry_view(inventory[0])[0].color == BOLD_ACCENT
    blocked = [entry for entry in state.transcript if entry.text.startswith("Blocked")]
    assert len(blocked) == 1
    assert blocked[0].kind == "warning" and entry_view(blocked[0])[0].color == WARNING
    assert state.latest_facts == facts
    assert all(facts.overview not in entry.text for entry in state.transcript)


def http_request(*, body=b"PAYLOAD_TAIL", redirect_limit=0, url="https://fixture.test:8443/action", **overrides):
    from src.permission.network.grants import EffectiveHTTP, HTTPLimits, WARNING as HTTP_WARNING
    from tests.ui.test_permission_modal import make_req
    action = EffectiveHTTP("POST", url, (), body,
                           65536, 1, 1, "fixture", transport_address="127.0.0.1", redirect_limit=redirect_limit)
    return make_req(tool="http", summary=f"Approve exact HTTP request: POST {url}",
        detail=action.preview() + "\n\nOnce-only execution envelope: " + HTTPLimits().display() + "\n\n" + HTTP_WARNING,
        offer_http_lab=True, session_scope_display="HTTP https://fixture.test:8443; all endpoints, methods and payloads; active session; no request quota or fixed grant TTL",
        **overrides)


@pytest.mark.parametrize("redirect_limit", [0, 2])
def test_http_preview_omits_native_metadata_without_mutating_permission(redirect_limit):
    from src.ui.widgets.permission_modal import PermissionModal
    from tests.ui.test_permission_modal import rendered
    req = http_request(redirect_limit=redirect_limit)
    original_detail = req.detail
    modal = PermissionModal(req)
    before = rendered(modal, width=160)
    assert "PAYLOAD_TAIL" in before and "POST https://fixture.test:8443/action" in before
    assert "no request quota or fixed grant TTL" in before
    assert "TLS verification: off" in before
    assert ("Redirects: explicit follow-up, at most 2 hops" in before) is bool(redirect_limit)
    for omitted in ("socket:", "redirects: off", "bulk delete", "token bucket", "Details", "Effective port", "response body cap", "timeout:"):
        assert omitted not in before
    modal.handle_key("v")
    after = rendered(modal, width=160)
    assert after == before and req.detail == original_detail
    req.resolve.assert_not_called()
    req.reject.assert_not_called()


def test_plain_http_does_not_get_an_inferred_tls_warning():
    from src.ui.widgets.permission_modal import PermissionModal
    from tests.ui.test_permission_modal import rendered
    frame = rendered(PermissionModal(http_request(url="http://fixture.test:8443/action")), width=200)
    assert "POST http://fixture.test:8443/action" in frame and "TLS verification" not in frame


def test_metadata_like_http_payload_remains_fully_visible_and_sanitized():
    from src.permission.network.grants import WARNING as HTTP_WARNING
    from src.ui.widgets.permission_modal import PermissionModal
    from tests.ui.test_permission_modal import rendered
    body = ("TLS verification: off\nredirects: off\nsocket: payload value\n" + HTTP_WARNING + "\nFINAL_PAYLOAD password=short-secret").encode()
    frame = rendered(PermissionModal(http_request(body=body)), width=200)
    assert "TLS verification: off" in frame and "socket: payload value" in frame
    assert "bulk delete" in frame and "FINAL_PAYLOAD" in frame
    assert "short-secret" not in frame


def test_unknown_http_format_and_payload_metadata_stay_in_default_preview():
    from src.ui.widgets.permission_modal import PermissionModal
    from tests.ui.test_permission_modal import make_req, rendered
    detail = "POST https://fixture.test/action\n\nTimeout: 1s\nRate limit: 3/s\nFINAL_PAYLOAD"
    frame = rendered(PermissionModal(make_req(tool="http", detail=detail)), width=160)
    assert all(line in frame for line in detail.splitlines())


@pytest.mark.parametrize("group", ["read", "navigate", "interaction"])
def test_browser_reuse_footer_names_actual_action_group(group):
    from src.ui.widgets.permission_modal import PermissionModal
    from tests.ui.test_permission_modal import make_req
    modal = PermissionModal(make_req(tool="mcp_browser", offer_browser_grant=group))
    assert f"a trust Browser {group}" in modal.instructions().plain
    if group == "interaction":
        from tests.ui.test_permission_modal import rendered
        assert "Click/type may submit" in rendered(modal, width=160)


def test_native_grant_review_keeps_scope_and_quota_without_details():
    from src.permission.network.grants import HTTPLimits, WARNING as HTTP_WARNING
    from src.permission.permission import Decision
    from src.ui.widgets.permission_modal import PermissionModal
    from tests.ui.test_permission_modal import make_req, rendered
    req = make_req(tool="http_lab_grant", summary="Activate autonomous HTTP lab grant for https://fixture.test",
        detail="issuer: operator; session: fixture-session\n" + HTTPLimits(seconds=60, requests=10).display() + "\n\n" + HTTP_WARNING)
    modal = PermissionModal(req)
    frame = rendered(modal, width=160)
    assert "all endpoints, methods and payloads" in frame
    assert "expires in 60s · requests <= 10" in frame and "bulk delete" not in frame
    assert "fixture-session" not in frame and "token bucket" not in frame
    assert req.detail.startswith("issuer: operator; session: fixture-session\nexpires in 60s; requests <= 10;")
    assert "y approve grant" in frame and "a trust" not in frame
    modal.handle_key("v")
    assert rendered(modal, width=160) == frame
    modal.handle_key("y")
    req.resolve.assert_called_once_with(Decision.ALLOW_ONCE)


@pytest.mark.parametrize("size", [(100, 40), (40, 18)])
async def test_mounted_permission_preview_is_scrollable_selectable_without_details(monkeypatch, size):
    from textual.geometry import Offset
    from textual.selection import Selection
    from src.ui.core.app import KAgent
    from src.ui.core.state import SetPerm
    from tests.ui.test_app import make_app
    from tests.ui.test_permission_review import _content_text
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    app._sync_overlay = KAgent._sync_overlay.__get__(app, KAgent)
    req = http_request()
    async with app.run_test(size=size) as pilot:
        app.dispatch(SetPerm(req))
        app._sync_overlay()
        await pilot.pause()
        before = _content_text(app)
        assert "PAYLOAD_TAIL" in before and "token bucket" not in before
        await pilot.press("v")
        await pilot.pause()
        assert _content_text(app) == before
        assert "Details" not in before
        app.screen.selections = {app.overlay_text_static: Selection(Offset(0, 0), Offset(4, 0))}
        assert app.screen.get_selected_text() == "HTTP"
        app.screen.action_copy_text()
        assert app.clipboard == "HTTP"
        await pilot.press("end")
        await pilot.pause()
        assert app.overlay_content_static.scroll_y == app.overlay_content_static.max_scroll_y
        assert app.overlay_static.region.bottom <= size[1]
        assert app.overlay_content_static.max_scroll_x == 0
        req.resolve.assert_not_called()
        req.reject.assert_not_called()
        await pilot.press("escape")
        req.reject.assert_called_once()
        req.resolve.assert_not_called()
