"""Keep Shell outcome parsing and uncertainty when deleting raw previews."""
import pytest
from src.ui.render.shell_outcome import _parse_shell_result
from src.ui.core.admission import call_metadata, result_issues
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
    assert result_issues(ToolResultEvent(name="unknown", status="partial", result="HIDDEN_PAYLOAD"), None) == ["Unrecognized tool outcome; operation needs review"]


def test_mcp_text_envelope_keeps_explicit_warnings_without_dumping_content():
    event = ToolResultEvent(name="mcp_fixture_action", result='[{"type":"text","text":"Hidden routine output\\nWARNING: cleanup required"}]\n[runtime observation: hidden-id]')
    assert result_issues(event, None) == ["WARNING: cleanup required"]
    assert result_issues(ToolResultEvent(name="mcp_fixture_action", result='[{"type":"text","text":"Hidden data\n[... truncated 500 chars ...]'), None) == ["MCP output truncated; omitted output may limit validation"]
