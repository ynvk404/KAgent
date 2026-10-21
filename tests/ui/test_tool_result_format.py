"""Keep Shell outcome parsing and uncertainty when deleting raw previews."""
import pytest
from src.ui.render.shell_outcome import _parse_shell_result
from src.ui.core.admission import call_metadata, result_issues, issue_category
from src.agent.events import ToolCallEvent, ToolResultEvent


@pytest.mark.parametrize("code", ["0", "1", "3", "-1", "timeout after 300s"])
def test_shell_exit_stderr_and_crlf_parsing_is_preserved(code):
    parts = _parse_shell_result(f"exit: {code}\r\nstdout:\r\nfirst\r\nsecond\r\nstderr:\r\nwarning\r\n")
    assert parts and parts.exit == code and parts.stdout == "first\nsecond" and parts.stderr == "warning"


@pytest.mark.parametrize("command", ["rg missing .", "grep missing file"])
def test_simple_search_no_matches_is_hidden(command):
    call = call_metadata(ToolCallEvent(id="search", name="shell", args={"command":command}))
    assert not result_issues(ToolResultEvent(id="search", name="shell", result="exit: 1\nstdout:\n"), call)


@pytest.mark.parametrize("command", ["rg missing . | false", "rg missing .; false", "rg missing . && false", "false"])
def test_complex_search_exit_one_remains_actionable(command):
    call = call_metadata(ToolCallEvent(name="shell", args={"command":command}))
    assert "Shell exit 1" in result_issues(ToolResultEvent(name="shell", result="exit: 1\nstdout:\n"), call)


def test_shell_success_stderr_is_retained_without_stdout_traffic():
    issues = result_issues(ToolResultEvent(name="shell", result="exit: 0\nstdout:\nHIDDEN_PAYLOAD\nstderr:\nWARNING: cleanup required\npassword=secret"), None)
    assert "cleanup required" in " ".join(issues)
    assert "secret" not in " ".join(issues) and "HIDDEN_PAYLOAD" not in " ".join(issues)


def test_unknown_failure_metadata_never_dumps_arbitrary_json():
    event = ToolResultEvent(name="unknown", status="error", error_kind="network", result='{"body":"HIDDEN_PAYLOAD"}')
    assert result_issues(event, None) == ["network"]
    assert result_issues(ToolResultEvent(name="unknown", result='error: adapter unavailable\n{"body":"HIDDEN_PAYLOAD"}'), None) == ["adapter unavailable"]
    assert result_issues(ToolResultEvent(name="unknown", err='could not parse arguments: invalid JSON (raw: HIDDEN_PAYLOAD)',
                                       status="error", error_kind="invalid_args"), None) == ["could not parse arguments: invalid JSON"]
    assert result_issues(ToolResultEvent(name="unknown", status="partial", result="HIDDEN_PAYLOAD"), None) == ["Unrecognized tool outcome. Review the operation."]


def test_mcp_text_envelope_keeps_explicit_warnings_without_dumping_content():
    event = ToolResultEvent(name="mcp_fixture_action", result='[{"type":"text","text":"Hidden routine output\\nWARNING: cleanup required"}]\n[runtime observation: hidden-id]')
    assert result_issues(event, None) == ["WARNING: cleanup required"]
    assert result_issues(ToolResultEvent(name="mcp_fixture_action", result='[{"type":"text","text":"Hidden data\n[... truncated 500 chars ...]'), None) == ["MCP output truncated. Omitted output may limit validation."]


@pytest.mark.parametrize("name,result,truncated", [
    ("confirm_finding", "Finding persisted; compact report export failed.", False),
    ("fixture", "RAW_EXTERNAL_OUTPUT; do not rewrite", True),
])
def test_presentation_keeps_export_marker_diagnostic_category_and_raw_result(name, result, truncated):
    event = ToolResultEvent(name=name, result=result, truncated=truncated)
    issues = result_issues(event, None)
    assert len(issues) == 1
    assert issue_category(issues[0], event) == ("export" if name == "confirm_finding" else "diagnostic")
    assert event.result == result and event.truncated is truncated


@pytest.mark.parametrize("status", [200, 403, 503, None])
@pytest.mark.parametrize("redirects", [0, 2])
def test_http_status_and_native_body_warning_keep_request_and_metadata_source(status, redirects):
    from src.ui.core.state import AgentEventAction, initial_state, reducer
    from src.ui.widgets.banner import BannerData
    state = initial_state("", BannerData("offline", "fixture", "."))
    state = reducer(state, AgentEventAction(ToolCallEvent(id="http", name="http", args={
        "method":"POST", "url":"https://user:short-secret@fixture.test/start?token=short-secret",
        "parameter":"email", "max_redirects":redirects})))
    event = ToolResultEvent(id="http", name="http", status="observation", http_status=status,
                            truncated=True, result="HTTP/1.1 999 fabricated\nHIDDEN_BODY")
    state = reducer(state, AgentEventAction(event))
    assert len(state.transcript) == 1 and state.transcript[0].kind == "system"
    text = state.transcript[0].text
    assert "POST /start · input email" in text
    assert "validation may be limited" in text
    assert ("Last response body truncated" if redirects else "Response body truncated") in text
    assert ("initial request" in text) == bool(redirects)
    if status is not None:
        assert (f"Last response {status}" if redirects else f"· {status}") in text
    else:
        assert "Last response 999" not in text
    assert not any(hidden in text for hidden in ("short-secret", "HIDDEN_BODY", "999", "final URL", "chain completed"))
    assert issue_category(result_issues(event, call_metadata(ToolCallEvent(name="http", args={
        "max_redirects":redirects})))[0], event) == "diagnostic"
    assert event.result.endswith("HIDDEN_BODY")


def test_sparse_http_activity_adds_status_without_new_success_rows_and_keeps_correlation():
    from src.ui.core.state import AgentEventAction, initial_state, reducer
    from src.ui.widgets.banner import BannerData
    from src.agent.events import AssistantTextEvent
    state = initial_state("", BannerData("offline", "fixture", "."))
    for identifier, path, redirects in [("a", "/first", 0), ("b", "/second", 2)]:
        state = reducer(state, AgentEventAction(ToolCallEvent(id=identifier, name="http", args={
            "method":"GET", "url":path, "max_redirects":redirects})))
    for identifier, code in [("b", 503), ("a", 403)]:
        event = ToolResultEvent(id=identifier, name="http", http_status=code, status="observation")
        state = reducer(state, AgentEventAction(event))
        before = state
        state = reducer(state, AgentEventAction(event))
        assert state is before
    assert not state.transcript and not state.issues
    state = reducer(state, AgentEventAction(AssistantTextEvent(text="Observed responses.")))
    assert len(state.transcript) == 2
    activity = state.transcript[0].text
    assert "initial request · GET /second · Last response 503" in activity
    assert "GET /first · 403" in activity
    assert not state.issues


def test_missing_status_and_context_elision_never_infer_http_metadata_or_completeness():
    from src.ui.core.admission import http_activity
    call = call_metadata(ToolCallEvent(name="http", args={"url":"/path"}))
    event = ToolResultEvent(name="http", result="HTTP/1.1 200 OK\n[response body truncated at 65536 decoded bytes]")
    assert not result_issues(event, call)
    assert http_activity(event, call, call.activity) == "http · GET /path"
    event.http_status = 200
    assert http_activity(event, None, "") == "http · Last response 200"
    event.name = "shell"
    event.truncated = True
    assert result_issues(event, None) == ["Tool output truncated. Omitted output may limit validation."]


def test_http_recovery_status_updates_only_the_already_visible_activity():
    from src.ui.core.state import AgentEventAction, initial_state, reducer
    from src.ui.widgets.banner import BannerData
    state = initial_state("", BannerData("offline", "fixture", "."))
    for identifier, result in [("fail", ToolResultEvent(id="fail", name="http", status="error", err="connection failed")),
                               ("ok", ToolResultEvent(id="ok", name="http", status="observation", http_status=500))]:
        state = reducer(state, AgentEventAction(ToolCallEvent(id=identifier, name="http", args={"url":"/path"})))
        state = reducer(state, AgentEventAction(result))
    assert len(state.transcript) == 1 and state.transcript[0].kind == "info"
    assert state.transcript[0].text == "http · GET /path · 500"
    assert state.transcript[0].details == ("Recovered after 1 failed attempt",)
