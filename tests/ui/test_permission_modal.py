from __future__ import annotations

from unittest.mock import Mock

from rich.console import Console

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


def rendered(modal: PermissionModal, width: int = 64) -> str:
    console = Console(width=width, record=True, force_terminal=False, color_system=None)
    console.print(modal.render())
    return console.export_text()

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


    frame = rendered(modal)


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


    frame = rendered(modal)


    assert "echo" in frame
    assert "AAAA" in frame
    assert "truncated" in frame


def test_shell_command_is_shown_once_in_a_native_titled_panel():
    frame = rendered(PermissionModal(make_req(
        summary="shell: echo world",
        detail="echo world",
        session_scope_display="this exact shell command only",
    )))

    assert frame.count("echo world") == 1
    assert "Shell command" in frame
    assert "Session trust: this exact shell command only" in frame
    assert "y allow once · a trust for session · n deny · Esc cancel" in frame


def test_shell_command_panel_has_closed_native_border():
    frame = rendered(PermissionModal(make_req(detail="echo world")), width=48)
    panel_lines = [line for line in frame.splitlines() if "Shell command" in line or "echo world" in line]

    assert panel_lines[0].startswith("╭") and panel_lines[0].endswith("╮")
    assert panel_lines[1].startswith("│") and panel_lines[1].endswith("│")
    assert any(line.startswith("╰") and line.endswith("╯") for line in frame.splitlines())


def test_short_shell_command_panel_is_content_sized_with_left_aligned_title():
    frame = rendered(PermissionModal(make_req(detail="echo world")), width=80)
    panel_lines = [line for line in frame.splitlines() if line.startswith(("╭", "│", "╰"))]

    assert panel_lines[0].startswith("╭─ Shell command ")
    assert panel_lines[0].endswith("╮")
    assert len(panel_lines[0]) < 80


def test_http_request_action_is_shown_once_in_framed_block():
    frame = rendered(PermissionModal(make_req(
        tool="http",
        summary="http: GET http://juice.lab:3000/robots.txt",
        detail="GET http://juice.lab:3000/robots.txt",
        session_scope_display="HTTP requests to http://juice.lab:3000",
    )))

    assert frame.count("GET http://juice.lab:3000/robots.txt") == 1
    assert "HTTP request" in frame
    assert "Session trust: HTTP requests to http://juice.lab:3000" in frame


def test_file_actions_frame_path_once_and_keep_edit_content_visible():
    write_frame = rendered(PermissionModal(make_req(
        tool="file_write",
        summary="write file: report.txt",
        detail="path: report.txt\n--- content ---\nsummary",
        session_scope_display="writes to /resolved/report.txt",
    )))
    edit_frame = rendered(PermissionModal(make_req(
        tool="file_edit",
        summary="edit file: report.txt",
        detail="path: report.txt\n- before\n+ after",
    )))

    assert "File write" in write_frame
    assert "/resolved/report.txt" in write_frame
    assert "write file: report.txt" not in write_frame
    assert "path: report.txt" not in write_frame
    assert "--- content ---\nsummary" in write_frame
    assert edit_frame.count("report.txt") == 1
    assert "File edit" in edit_frame
    assert "- before\n+ after" in edit_frame


def test_private_host_http_keeps_reason_without_duplicating_action():
    http_frame = rendered(PermissionModal(make_req(
        tool="http",
        summary="http: private/internal URL http://127.0.0.1/status",
        detail="host: 127.0.0.1\nreason: DNS resolves to loopback IPv4 (127.0.0.1)",
        no_session_cache=True,
    )))

    assert http_frame.count("http://127.0.0.1/status") == 1
    assert "HTTP request" in http_frame
    assert "host: 127.0.0.1" in http_frame
    assert "DNS resolves to loopback IPv4 (127.0.0.1)" in http_frame
    assert "Session trust unavailable for this sensitive action" in http_frame


def test_generic_mcp_permission_remains_plain_text():
    frame = rendered(PermissionModal(make_req(
        tool="mcp_plugin_action",
        summary="mcp: plugin action",
        detail='{"path": "report.txt"}',
    )))

    assert "mcp: plugin action" in frame
    assert '{"path": "report.txt"}' in frame
    assert "╭" not in frame


def test_coverage_and_sensitive_file_permissions_keep_plain_explanations():
    coverage_frame = rendered(PermissionModal(make_req(
        tool="coverage",
        summary="coverage",
        detail='{"action": "clear"}',
        no_session_cache=True,
    )))
    sensitive_file_frame = rendered(PermissionModal(make_req(
        tool="file",
        summary="write to sensitive file: /home/user/.ssh/config",
        detail="path: /home/user/.ssh/config\n\nThis path is on the sensitive-path list.",
        no_session_cache=True,
    )))

    assert '{"action": "clear"}' in coverage_frame
    assert "╭" not in coverage_frame
    assert "Session trust unavailable for this sensitive action" in coverage_frame
    assert "This path is on the sensitive-path list." in sensitive_file_frame
    assert "Session trust unavailable for this sensitive action" in sensitive_file_frame


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
    frame = rendered(PermissionModal(make_req(
        tool="http",
        session_scope_display="HTTP requests to http://juice.lab:3000",
    )))

    assert "Session trust: HTTP requests to http://juice.lab:3000" in frame
    assert "a trust for session" in frame


def test_displays_exact_shell_trust_scope():
    frame = rendered(PermissionModal(
        make_req(session_scope_display="this exact shell command only")
    ))

    assert "Session trust: this exact shell command only" in frame


def test_displays_unavailable_session_trust_for_non_cacheable_request():
    frame = rendered(PermissionModal(make_req(no_session_cache=True)))

    assert "Session trust unavailable for this sensitive action" in frame


def test_displays_tool_wide_scope_when_no_cache_scope_is_provided():
    frame = rendered(PermissionModal(make_req(tool="plugin_tool")))

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

    frame = rendered(modal)

    assert "n deny · Esc cancel" in frame
