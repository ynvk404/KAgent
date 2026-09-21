from __future__ import annotations

from unittest.mock import Mock

from src.permission.permission import Decision
from src.ui.bridges.perm_bridge import BridgedPermissionRequest
from src.ui.widgets.permission_modal import (
    PermissionModal,
    is_command_tool,
)


def make_req(**overrides) -> BridgedPermissionRequest:
    data = {
        "tool": "shell",
        "summary": "shell: curl …",
        "detail": "",
        "resolve": Mock(),
        "reject": Mock(),
    }

    data.update(overrides)

    return BridgedPermissionRequest(**data)

def test_is_command_tool():

    for tool in [
        "shell",
        "bash",
        "BashTool",
        "http",
        "file_write",
        "file_edit",
    ]:
        assert is_command_tool(tool) is True


    for tool in [
        "web_fetch",
        "ask_user",
        "coverage",
        "confirm_finding",
    ]:
        assert is_command_tool(tool) is False


def test_shows_long_command_without_prose_cap():

    long_cmd = (
        "curl -s -X POST "
        "'https://target.test/api/login' "
        + "-H x:y " * 380
        + "END"
    )

    assert len(long_cmd) > 1200


    modal = PermissionModal(
        make_req(
            tool="shell",
            detail=long_cmd,
        )
    )


    frame = "\n".join(
        modal.render()
    )


    assert "curl -s -X POST" in frame
    assert "END" in frame
    assert "truncated" not in frame



def test_caps_huge_command():

    huge = (
        "echo "
        + "A" * 9000
    )


    modal = PermissionModal(
        make_req(
            tool="shell",
            detail=huge,
        )
    )


    frame = "\n".join(
        modal.render()
    )


    assert "echo AAAA" in frame
    assert "truncated" in frame


def test_allow_once_key():

    resolve = Mock()

    modal = PermissionModal(
        make_req(resolve=resolve)
    )

    modal.handle_key("y")

    resolve.assert_called_once_with(
        Decision.ALLOW_ONCE
    )



def test_allow_session_key():

    resolve = Mock()

    modal = PermissionModal(
        make_req(resolve=resolve)
    )

    modal.handle_key("a")

    resolve.assert_called_once_with(
        Decision.ALLOW_SESSION
    )


def test_displays_actual_session_trust_scope():
    frame = "\n".join(
        PermissionModal(
            make_req(
                tool="http",
                session_scope_display="HTTP requests to http://juice.lab:3000",
            )
        ).render()
    )

    assert "Session trust: HTTP requests to http://juice.lab:3000" in frame
    assert "a trust for session" in frame


def test_displays_exact_shell_trust_scope():
    frame = "\n".join(
        PermissionModal(
            make_req(session_scope_display="this exact shell command only")
        ).render()
    )

    assert "Session trust: this exact shell command only" in frame


def test_displays_unavailable_session_trust_for_non_cacheable_request():
    frame = "\n".join(
        PermissionModal(make_req(no_session_cache=True)).render()
    )

    assert "Session trust unavailable for this sensitive action" in frame


def test_displays_tool_wide_scope_when_no_cache_scope_is_provided():
    frame = "\n".join(
        PermissionModal(make_req(tool="plugin_tool")).render()
    )

    assert "Session trust: this tool for the current runtime" in frame



def test_deny_key():

    resolve = Mock()

    modal = PermissionModal(
        make_req(resolve=resolve)
    )

    modal.handle_key("n")

    resolve.assert_called_once_with(
        Decision.DENY
    )



def test_escape_key():

    resolve = Mock()

    modal = PermissionModal(
        make_req(resolve=resolve)
    )

    modal.handle_key("escape")

    resolve.assert_called_once_with(
        Decision.DENY
    )


def test_footer_distinguishes_explicit_deny_from_escape_cancel():
    modal = PermissionModal(make_req())

    frame = "\n".join(modal.render())

    assert "n deny · Esc cancel" in frame
