"""Keep Shell outcome parsing and uncertainty when deleting raw previews."""
from copy import deepcopy
import json

import pytest
from src.ui.render.shell_outcome import _parse_shell_result
from src.ui.core.admission import call_metadata, result_issues, issue_category
from src.agent.events import ToolCallEvent, ToolResultEvent
from src.tools.common.outcome import ToolOutput
from src.tools.common.runtime_metadata import RuntimeMetadata, StreamCapture


def shell_metadata(code=0, *, stdout=0, stderr=0):
    return RuntimeMetadata(process="exit", exit_code=code,
        stdout=StreamCapture(stdout, stdout, True), stderr=StreamCapture(stderr, stderr, True))


@pytest.mark.parametrize("code", ["0", "1", "3", "-1", "timeout after 300s"])
def test_shell_exit_stderr_and_crlf_parsing_is_preserved(code):
    parts = _parse_shell_result(f"exit: {code}\r\nstdout:\r\nfirst\r\nsecond\r\nstderr:\r\nwarning\r\n")
    assert parts and parts.exit == code and parts.stdout == "first\nsecond" and parts.stderr == "warning"


@pytest.mark.parametrize("command", ["rg missing .", "grep missing file"])
def test_simple_search_no_matches_is_hidden(command):
    call = call_metadata(ToolCallEvent(id="search", name="shell", args={"command":command}))
    assert not result_issues(ToolResultEvent(id="search", name="shell", result="exit: 1\nstdout:\n",
        status="error", error_kind="tool_exception", err="Shell exit 1", runtime_metadata=shell_metadata(1)), call)


@pytest.mark.parametrize("command", ["rg missing . | false", "rg missing .; false", "rg missing . && false", "false"])
def test_complex_search_exit_one_remains_actionable(command):
    call = call_metadata(ToolCallEvent(name="shell", args={"command":command}))
    assert "Shell exit 1" in result_issues(ToolResultEvent(name="shell", result="exit: 1\nstdout:\n",
        status="error", error_kind="tool_exception", runtime_metadata=shell_metadata(1)), call)


def test_shell_success_stderr_is_diagnosed_without_copying_output():
    event = ToolResultEvent(name="shell", result="exit: 0\nstdout:\nHIDDEN_PAYLOAD\nstderr:\nWARNING: cleanup required\npassword=secret",
        runtime_metadata=shell_metadata(stderr=40))
    issues = result_issues(event, None)
    assert "Shell stderr: 40 bytes observed" in " ".join(issues)
    assert "secret" not in " ".join(issues) and "HIDDEN_PAYLOAD" not in " ".join(issues)
    assert "cleanup required" not in " ".join(issues) and "cleanup required" in event.result


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
    assert not state.transcript
    from src.ui.core.admission import http_activity
    call = call_metadata(ToolCallEvent(name="http", args={"method": "POST", "url": "/start",
        "parameter": "email", "max_redirects": redirects}))
    text = http_activity(event, call, call.activity)
    assert "POST /start · input email" in text
    assert "validation may be limited" in result_issues(event, call)[0]
    assert ("Last response body truncated" if redirects else "Response body truncated") in result_issues(event, call)[0]
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
    assert not state.transcript
    state = reducer(state, AgentEventAction(AssistantTextEvent(text="Observed responses.")))
    assert len(state.transcript) == 2
    activity = state.transcript[0].text
    assert "initial request · GET /second · Last response 503" in activity
    assert "GET /first · 403" in activity
    assert not any(row.kind == "error" for row in state.transcript)


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


def test_http_status_without_native_completion_cannot_recover_an_unknown_failure():
    from src.ui.core.state import AgentEventAction, initial_state, reducer
    from src.ui.widgets.banner import BannerData
    state = initial_state("", BannerData("offline", "fixture", "."))
    for identifier, result in [("fail", ToolResultEvent(id="fail", name="http", status="error", err="connection failed")),
                               ("ok", ToolResultEvent(id="ok", name="http", status="observation", http_status=500))]:
        state = reducer(state, AgentEventAction(ToolCallEvent(id=identifier, name="http", args={"url":"/path"})))
        state = reducer(state, AgentEventAction(result))
    assert not state.transcript
    assert not state.pending_calls
    assert not any(row.kind == "error" for row in state.transcript)


@pytest.mark.parametrize('name', ['read_payloads', 'read_skill_file'])
async def test_skill_reader_pages_show_actual_character_ranges_without_duplicate_results(tmp_path, name):
    from src.agent.events import Invocation
    from src.permission.permission import AlwaysAllow
    from src.skills.registry import Registry, Skill
    from src.tools.skills.payloads import ReadPayloadsTool
    from src.tools.skills.skill_file import ReadSkillFileTool
    from src.ui.core.state import AgentEventAction, initial_state, reducer
    from src.ui.widgets.banner import BannerData

    # The second page's UTF-8 byte count differs from its character range.
    (tmp_path / 'payloads.txt').write_text('a' * 8233 + '\n' + 'é' * 4374 + '\n' + 'done\n', encoding='utf-8')
    skills = Registry()
    skills.add(Skill('fixture', 'Offline reader fixture', [], False, str(tmp_path / 'SKILL.md'), ''))
    reader = ReadPayloadsTool(skills) if name == 'read_payloads' else ReadSkillFileTool(skills)
    args = {'skill': 'fixture', 'file' if name == 'read_payloads' else 'path': 'payloads.txt', 'limit': 1}
    state = initial_state('', BannerData('offline', 'fixture', '.'))
    for index in range(3):
        call = ToolCallEvent(id=f'page-{index}', name=name, args=deepcopy(args),
                             invocation=Invocation(f'invocation-{index}', 'offline'))
        state = reducer(state, AgentEventAction(call))
        output = await reader.run(args, None, AlwaysAllow())
        assert isinstance(output, ToolOutput)
        result = ToolResultEvent(id=call.id, name=name, result=output,
                                 truncated=output.truncated, invocation=call.invocation)
        original = deepcopy(result)
        state = reducer(state, AgentEventAction(result))
        repeated = reducer(state, AgentEventAction(result))
        assert repeated is state and result == original
        if index < 2:
            notices = result_issues(result, call_metadata(call))
            assert len(notices) == 1 and issue_category(notices[0], result) == 'diagnostic'
        else:
            assert not result_issues(result, call_metadata(call))
        page = json.loads(output.rsplit('\nContinuation: ', 1)[1])
        args.update(source_ref=page['source_ref'], start_char=page['next_start_char'])
    assert not state.transcript  # Pagination diagnostics remain raw tool feedback.


@pytest.mark.parametrize('changes', [
    {'start_char': True}, {'end_char': -1}, {'source_chars': 5},
    {'next_start_char': None}, {'next_start_char': 8}, {'offset_unit': 'bytes'},
])
def test_invalid_skill_pagination_metadata_keeps_generic_truncation_notice(changes):
    page = {'start_char': 0, 'end_char': 10, 'source_chars': 20,
            'next_start_char': 10, 'offset_unit': 'unicode_characters', **changes}
    event = ToolResultEvent(name='read_payloads', truncated=True,
        result='# fixture/payloads.txt — 3 line(s), 20 bytes\nHIDDEN_BODY\nContinuation: ' + json.dumps(page))
    assert result_issues(event, None) == ['Tool output truncated. Omitted output may limit validation.']


@pytest.mark.parametrize('name', ['read_payloads', 'read_skill_file', 'fixture'])
def test_missing_skill_page_metadata_keeps_truncation_and_failure_details(name):
    event = ToolResultEvent(name=name, truncated=True, result='HIDDEN_BODY\nContinuation: malformed')
    assert result_issues(event, None) == ['Tool output truncated. Omitted output may limit validation.']
    event.status = 'error'
    event.error_kind = 'reference_unavailable'
    assert result_issues(event, None) == ['reference_unavailable', 'Tool output truncated. Omitted output may limit validation.']
