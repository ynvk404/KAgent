from __future__ import annotations

import asyncio
from unittest.mock import Mock

import pytest
from rich.console import Console

from src.permission.permission import Decision
from src.tools.execution.shell import ShellTool
from src.ui.bridges.perm_bridge import BridgedPermissionRequest
from src.ui.widgets.permission_modal import (
    PermissionModal,
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



def test_huge_command_is_complete():

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
    assert "truncated" not in frame


def test_shell_command_is_shown_once_in_a_native_titled_panel():
    frame = rendered(PermissionModal(make_req(
        summary="shell: echo world",
        detail="echo world",
        session_scope_display="this exact shell command only",
    )))

    assert frame.count("echo world") == 1
    assert "Shell command" in frame
    assert "Allow once: current invocation only" in frame
    assert "a unavailable" not in frame
    assert "y allow once · n deny · Esc cancel" in frame


def test_action_has_one_title_without_nested_frame():
    frame = rendered(PermissionModal(make_req(detail="echo world")), width=48)
    assert frame.count("Shell command") == 1
    assert frame.count("echo world") == 1
    assert "╭" not in frame
    assert "Tool: shell" not in frame


def test_http_request_action_is_shown_once_in_framed_block():
    frame = rendered(PermissionModal(make_req(
        tool="http",
        summary="http: GET http://juice.lab:3000/robots.txt",
        detail="GET http://juice.lab:3000/robots.txt",
        session_scope_display="HTTP requests to http://juice.lab:3000", offer_http_lab=True,
    )))

    assert frame.count("GET http://juice.lab:3000/robots.txt") == 1
    assert "HTTP request" in frame
    assert "Session trust: HTTP requests to http://juice.lab:3000" in frame


def test_file_actions_frame_path_once_and_keep_edit_content_visible():
    write_frame = rendered(PermissionModal(make_req(
        tool="file_write",
        summary="write file: report.txt",
        detail="path: report.txt\n--- content ---\nsummary",
        session_scope_display="writes to /resolved/report.txt", no_session_cache=False, cache_key="/resolved/report.txt",
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
    assert "Allow once: current invocation only" in http_frame


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
    assert "Allow once: current invocation only" in coverage_frame
    assert "This path is on the sensitive-path list." in sensitive_file_frame
    assert "Allow once: current invocation only" in sensitive_file_frame


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
        make_req(tool="file_write", resolve=resolve, no_session_cache=False, cache_key="artifacts",
                 session_scope_display="writes under canonical artifacts root")
    )

    modal.handle_key("a")

    resolve.assert_called_once_with(
        Decision.ALLOW_SESSION
    )


def test_displays_actual_session_trust_scope():
    frame = rendered(PermissionModal(make_req(
        tool="http",
        session_scope_display="HTTP requests to http://juice.lab:3000", offer_http_lab=True,
    )))

    assert "Session trust: HTTP requests to http://juice.lab:3000" in frame
    assert "a trust origin" in frame


def test_displays_exact_shell_trust_scope():
    frame = rendered(PermissionModal(
        make_req(session_scope_display="this exact shell command only")
    ))

    assert "Allow once: current invocation only" in frame
    assert "a unavailable" not in frame


def test_displays_unavailable_session_trust_for_non_cacheable_request():
    frame = rendered(PermissionModal(make_req(no_session_cache=True)))

    assert "Allow once: current invocation only" in frame
    assert "y allow once · n deny · Esc cancel" in frame
    assert " · a trust " not in frame


def test_displays_risk_tier_separately_from_session_trust():
    frame = rendered(PermissionModal(make_req(risk_tier="high-impact")))

    assert "Risk tier:" not in frame
    assert "Allow once: current invocation only" in frame
    assert "a unavailable" not in frame


def test_missing_scope_never_offers_tool_wide_authority():
    frame = rendered(PermissionModal(make_req(tool="plugin_tool")))

    assert "Allow once: current invocation only" in frame
    assert "a unavailable" not in frame



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

    resolve.assert_not_called()
    assert isinstance(modal.req.reject.call_args.args[0], asyncio.CancelledError)


def test_footer_distinguishes_explicit_deny_from_escape_cancel():
    modal = PermissionModal(make_req())

    frame = rendered(modal)

    assert "n deny · Esc cancel" in frame


@pytest.mark.parametrize("command", ["pwd", "pwd; python3 --version", "pwd\npython3 --version"])
def test_shell_preview_explains_actual_tool_policy_without_changing_it(command):
    tool = ShellTool()
    args = {"command": command}
    hints = tool.permission_hints(args)
    req = make_req(
        **tool.summarize(args),
        risk_tier=hints.get("riskTier"),
        no_session_cache=hints.get("noSessionCache"),
        session_scope_display=hints.get("sessionScopeDisplay"),
    )
    modal = PermissionModal(req)
    frame = rendered(modal, width=80)

    assert "Risk tier:" not in frame
    assert "Timeout: 300s" in frame
    assert "Allow once: current invocation only" in frame
    for line in command.splitlines():
        assert frame.count(line) == 1
    assert "scroll to review" not in frame and "secrets redacted" not in frame
    assert " · a trust " not in frame
    modal.handle_key("a")
    req.resolve.assert_not_called()
    assert req.risk_tier == "high-impact"
    assert req.no_session_cache is True
    assert req.yolo_auto_approve is False


@pytest.mark.parametrize("tier", ["routine", "bounded-impact", "high-impact"])
@pytest.mark.parametrize("no_session_cache", [False, True])
def test_all_risk_tiers_preserve_independent_session_trust_choices(tier, no_session_cache):
    req = make_req(tool="plugin_tool", risk_tier=tier, no_session_cache=no_session_cache)
    modal = PermissionModal(req)
    frame = rendered(modal, width=100)

    assert req.risk_tier == tier
    assert "Risk tier:" not in frame
    assert "all Shell commands" not in frame
    assert "explicit action approval required" not in frame
    assert " · a trust " not in frame
    modal.handle_key("a")
    req.resolve.assert_not_called()


@pytest.mark.parametrize("offer_lab", [False, True])
def test_http_grant_action_is_offered_only_when_requested(offer_lab):
    req = make_req(
        tool="http", summary="Approve exact HTTP request: GET http://juice.lab:3000/status",
        detail="GET http://juice.lab:3000/status\nRequest budget: 10",
        risk_tier="high-impact", no_session_cache=True, offer_http_lab=offer_lab,
    )
    modal = PermissionModal(req)
    frame = rendered(modal, width=100)

    assert "HTTP grants are managed separately" not in frame
    assert "Request budget: 10" in frame
    assert ("a trust origin" in frame) is offer_lab
    assert "g review" not in frame
    modal.handle_key("a")
    if offer_lab:
        req.resolve.assert_called_once_with(Decision.ALLOW_SESSION)
    else:
        req.resolve.assert_not_called()


def test_lab_grant_keeps_warning_and_does_not_describe_grant_as_exact_request():
    frame = rendered(PermissionModal(make_req(
        tool="http_lab_grant", summary="Activate autonomous HTTP lab grant for http://juice.lab:3000",
        detail="Rate limit: 2/s\nWARNING: broad grant for this session",
        risk_tier="high-impact", no_session_cache=True,
    )), width=100)

    assert "Activate autonomous HTTP lab grant" in frame
    assert "Rate limit: 2/s" in frame
    assert "WARNING: broad grant for this session" in frame
    assert "HTTP grants are managed separately" not in frame
    assert "Exact request review" not in frame


def test_full_detail_preserves_multiline_tail_and_redacts_every_preview_mode():
    req = make_req(
        detail="pwd\n" + "x" * 9000 + "\nFINAL_OPERATION https://user:fake-password@target.test --token=fake-secret",
        session_scope_display="requests to https://user:fake-password@target.test",
    )
    modal = PermissionModal(req)
    preview = rendered(modal)
    assert "truncated" not in preview
    assert "FINAL_OPERATION" in preview
    assert "v full detail" not in preview

    modal.handle_key("v")
    full = rendered(modal)
    assert "FINAL_OPERATION" in full
    assert "v preview" not in full
    assert "truncated" not in full
    for frame in [preview, full]:
        assert "fake-secret" not in frame
        assert "fake-password" not in frame
        assert "target.test" in frame
    req.resolve.assert_not_called()


def test_long_mcp_arguments_remain_accessible_and_redacted_in_full_detail():
    modal = PermissionModal(make_req(
        tool="mcp_plugin_action", summary="mcp: fixture-server operation",
        detail='{"args": {"password": "fake-secret", "content": "' + "x" * 1500 + 'FINAL_ARGUMENT"}}',
        no_session_cache=True, risk_tier="high-impact",
    ))
    preview = rendered(modal)
    assert "FINAL_ARGUMENT" in preview
    assert "truncated" not in preview
    modal.handle_key("v")
    full = rendered(modal)
    assert "FINAL_ARGUMENT" in full
    assert "fake-secret" not in preview + full
    assert "fixture-server operation" in full
    assert '"args"' in full


def test_producer_details_include_effective_shell_timeout_and_file_replace_all():
    from src.tools.execution.file import FileEditTool
    shell = ShellTool()
    assert 'Timeout: 1800s' in shell.summarize({'command':'printf fixture','timeout_seconds':9999})['detail']
    edit = FileEditTool()
    summary = edit.summarize({'path':'artifacts/report.md','old_string':'before','new_string':'after','replace_all':True})
    assert 'replace_all: True' in summary['detail']
    frame = rendered(PermissionModal(make_req(tool='file_edit', **summary)))
    assert 'replace_all: True' in frame and '- before' in frame and '+ after' in frame
