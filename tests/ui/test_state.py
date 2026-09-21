from __future__ import annotations
from src.ui.widgets.banner import BannerData
import json
from typing import Any

import pytest
from src.ui.theme import ACCENT, DANGER, ERROR, MUTED, WARNING

from src.ui.core.state import (
    initial_state,
    reducer,
    AgentEventAction,
    SetBusy,
    SetAsk,
    SetPerm,
    Clear,
    CycleTranscriptFilter,
    ExpandToolOutput,
)

from src.agent.events import (
    ToolCallEvent,
    ToolResultEvent,
    ErrorEvent,
    AssistantDeltaEvent,
    DoneEvent,
    DecisionEvent,
)
from src.ui.widgets.transcript import entry_view


def seed():
    return initial_state(
        "",
        BannerData(
            provider="",
            model="",
            cwd="",
        ),
    )


def test_decision_summary_keeps_one_prefix_and_indents_matched_signals():
    out = reducer(
        seed(),
        AgentEventAction(
            DecisionEvent(
                summary=(
                    "Planner · web-enumeration · risk: normal\n"
                    "matched: skill:web-enumeration · stage:enumeration · web enumeration"
                )
            )
        ),
    )

    entry = out.transcript[-1]
    lines = entry_view(entry)

    assert entry.kind == "decision"
    assert lines[0].text == "· Planner · web-enumeration · risk: normal"
    assert lines[1].text == (
        "  matched: skill:web-enumeration · stage:enumeration · web enumeration"
    )
    assert not lines[0].text.startswith("· ·")


def test_collapses_escaped_newline_in_args_preview():

    out = reducer(
        seed(),
        AgentEventAction(
            ToolCallEvent(
                name="shell",
                args_json=json.dumps(
                    {
                        "command": "python3 -c \"\\nports=[\\n80,443\\n]\""
                    }
                ),
            )
        ),
    )

    last = out.transcript[-1]

    assert last.kind == "tool-call"
    assert "\\n" not in last.text
    assert "Shell" in last.text
    assert "python3" in last.text



def test_caps_preview_120_chars():

    long_args = json.dumps(
        {
            "command": "echo " * 500
        }
    )

    out = reducer(
        seed(),
        AgentEventAction(
            ToolCallEvent(
                name="shell",
                args_json=long_args,
            )
        ),
    )

    last = out.transcript[-1]

    assert len(last.text) <= 150
    assert last.text.endswith("…")



def test_shows_command_not_json():

    out = reducer(
        seed(),
        AgentEventAction(
            ToolCallEvent(
                name="shell",
                args_json=json.dumps(
                    {
                        "command":
                        "curl -ksS https://example.com"
                    }
                ),
            )
        ),
    )

    last = out.transcript[-1]

    assert last.prefix == "⏺  "
    assert '{"command"' not in last.text
    assert "curl -ksS https://example.com" in last.text


def test_short_shell_command_uses_ui_separator_not_function_call_style():
    out = reducer(
        seed(),
        AgentEventAction(
            ToolCallEvent(
                name="shell",
                args_json=json.dumps({"command": "echo hello"}),
            )
        ),
    )

    assert out.transcript[-1].text == "Shell · echo hello"
    assert "Shell(echo hello)" not in out.transcript[-1].text


def test_long_shell_command_keeps_descriptive_header_and_command_block():
    command = "curl -s " + "https://example.test/path?query=value&" * 8
    out = reducer(
        seed(),
        AgentEventAction(
            ToolCallEvent(name="shell", args_json=json.dumps({"command": command}))
        ),
    )

    text = out.transcript[-1].text
    assert text.startswith("Shell · HTTP request\n$ ")
    assert command not in text
    assert text.endswith("…")



def test_BashTool_compact_style():

    out = reducer(
        seed(),
        AgentEventAction(
            ToolCallEvent(
                name="BashTool",
                args_json=json.dumps(
                    {
                        "command":
                        "mkdir -p recon/gobus.net"
                    }
                ),
            )
        ),
    )

    last = out.transcript[-1]

    assert last.prefix == "⏺  "
    assert "mkdir -p recon/gobus.net" in last.text



def test_comment_shell_command():

    command = "\n".join(
        [
            "# Check for Laravel debug mode - try to trigger an error",
            'curl -s "https://egyptianclothingbank.org/donor/login" -X POST',
        ]
    )

    out = reducer(
        seed(),
        AgentEventAction(
            ToolCallEvent(
                name="shell",
                args_json=json.dumps(
                    {
                        "command": command
                    }
                ),
            )
        ),
    )

    last = out.transcript[-1]

    assert "Laravel debug mode" in last.text
    assert "curl -s" in last.text
    assert last.prefix == "⏺  "


def test_delta_changes_planning_to_answering():

    s = reducer(
        seed(),
        SetBusy(True)
    )

    assert s.phase == "planning"


    s = reducer(
        s,
        AgentEventAction(
            AssistantDeltaEvent(
                text="hello"
            )
        ),
    )


    assert s.phase == "answering"
    assert s.transcript[-1].text == "hello"


def test_busy_turn_transitions_through_waiting_input_and_back_to_answering():
    request: Any = object()
    s = reducer(seed(), SetBusy(True))

    s = reducer(s, SetAsk(request))
    assert s.busy is True
    assert s.phase == "waiting-user"

    s = reducer(s, SetAsk(None))
    assert s.busy is True
    assert s.phase == "answering"


def test_busy_turn_transitions_through_waiting_approval_and_back_to_tool():
    request: Any = object()
    s = reducer(seed(), SetBusy(True))

    s = reducer(s, SetPerm(request))
    assert s.busy is True
    assert s.phase == "waiting-approval"

    s = reducer(s, SetPerm(None))
    assert s.busy is True
    assert s.phase == "running-tool"


def test_finishing_turn_returns_to_idle():
    s = reducer(seed(), SetBusy(True))

    s = reducer(s, SetBusy(False))

    assert s.busy is False
    assert s.phase == "idle"



def test_streaming_finalized_by_done():

    s = reducer(
        seed(),
        AgentEventAction(
            AssistantDeltaEvent(
                text="hello"
            )
        ),
    )

    assert s.transcript[-1].streaming is True


    s = reducer(
        s,
        AgentEventAction(
            DoneEvent()
        ),
    )


    assert s.transcript[-1].streaming is False
    assert s.busy is False


def test_cycle_filters():

    s = seed()

    assert s.transcript_filter == "all"


    for expected in [
        "compact",
        "findings",
        "errors",
        "current",
        "all",
    ]:

        s = reducer(
            s,
            CycleTranscriptFilter()
        )

        assert s.transcript_filter == expected



def test_clear():

    s = reducer(
        seed(),
        Clear()
    )

    assert len(s.transcript) == 0
    assert s.clear_gen == 1


def test_ask_user_result_is_human_readable_without_mutating_event():
    raw = json.dumps(
        {
            "answers": [
                {
                    "question": "Which endpoint and parameter would you like to test?",
                    "answer": "sql injection",
                }
            ]
        },
        indent=2,
    )
    event = ToolResultEvent(
        name="ask_user",
        result=raw,
        duration_ms=12,
    )

    out = reducer(seed(), AgentEventAction(event))

    entry = out.transcript[-1]
    assert entry.text == "\n".join(
        [
            "[ok] Ask User (12ms)",
            "answers:",
            "- sql injection",
            "  Which endpoint and parameter would you like to test?",
        ]
    )
    assert '"answers"' not in entry.text
    assert event.result == raw
    assert entry.collapsible is False
    assert entry.full_text is None


def test_invalid_ask_user_result_falls_back_to_raw_output():
    raw = '{"unexpected":"technical payload"}'

    out = reducer(
        seed(),
        AgentEventAction(
            ToolResultEvent(
                name="ask_user",
                result=raw,
                duration_ms=3,
            )
        ),
    )

    assert out.transcript[-1].text == f"[ok] Ask User (3ms)\n{raw}"


def test_exact_ask_user_error_duplicate_is_rendered_once_without_mutating_event():
    raw = "ERROR: aborted"
    event = ToolResultEvent(
        name="ask_user",
        result=raw,
        err="aborted",
        duration_ms=1,
    )

    out = reducer(
        seed(),
        AgentEventAction(event),
    )

    assert out.transcript[-1].text == "[error] Ask User: aborted"
    assert event.err == "aborted"
    assert event.result == raw


@pytest.mark.parametrize(
    ("name", "err"),
    [
        ("http", "permission denied by user for http"),
        ("file_read", "unexpected tool exception"),
        ("shell", "could not parse arguments: invalid JSON"),
        ("browser", "tool blocked by active skills"),
    ],
)
def test_exact_tool_error_duplicate_is_rendered_once(name, err):
    event = ToolResultEvent(
        name=name,
        result=f"ERROR: {err}",
        err=err,
        duration_ms=4,
    )

    out = reducer(seed(), AgentEventAction(event))

    entry = out.transcript[-1]
    assert entry.text == f"[error] {name}: {err}"
    assert entry.text.count(err) == 1
    assert event.result == f"ERROR: {err}"
    assert event.err == err


def test_distinct_tool_error_body_is_preserved():
    result = "ERROR: command failed\nstderr: detailed diagnostics"

    out = reducer(
        seed(),
        AgentEventAction(
            ToolResultEvent(
                name="shell",
                result=result,
                err="command failed",
                duration_ms=5,
            )
        ),
    )

    assert out.transcript[-1].text == f"[error] shell: command failed\n{result}"


def test_runtime_error_event_rendering_is_unchanged():
    out = reducer(
        seed(),
        AgentEventAction(ErrorEvent(err=RuntimeError("provider unavailable"))),
    )

    assert out.transcript[-1].kind == "error"
    assert out.transcript[-1].text == "provider unavailable"


def test_evidence_result_remains_raw_and_expandable():
    raw = "HTTP/1.1 200 OK\ncontent-type: text/plain\n\n" + "\n".join(
        f"evidence line {i}" for i in range(40)
    )

    collapsed = reducer(
        seed(),
        AgentEventAction(
            ToolResultEvent(
                name="http",
                result=raw,
                duration_ms=20,
            )
        ),
    )

    entry = collapsed.transcript[-1]
    assert entry.collapsible is True
    assert entry.full_text is not None
    assert "evidence line 39" in entry.full_text
    assert "Ctrl-O to expand" in entry.text

    expanded = reducer(collapsed, ExpandToolOutput())
    assert "evidence line 39" in expanded.transcript[-1].text


def test_confirm_finding_card():

    out = reducer(
        seed(),
        AgentEventAction(
            ToolCallEvent(
                name="confirm_finding",
                args_json=json.dumps(
                    {
                        "severity": "low",
                        "title":
                            "Information Disclosure - PHP Version in Response Headers",
                        "method": "GET",
                        "url": "https://x.test/",
                        "parameter": "debug",
                        "impact":
                            "Leaks the PHP version."
                    }
                ),
            )
        ),
    )

    last = out.transcript[-1]

    assert last.kind == "finding"
    assert last.prefix == "★ "
    assert last.color == ACCENT

    assert (
        "LOW · Information Disclosure - PHP Version in Response Headers"
        in last.text
    )

    assert "GET https://x.test/" in last.text
    assert "impact: Leaks the PHP version." in last.text



@pytest.mark.parametrize(
    "severity,color",
    [
        ("critical", DANGER),
        ("high", ERROR),
        ("medium", WARNING),
        ("low", ACCENT),
        ("info", MUTED),
    ]
)
def test_finding_colors(severity, color):

    out = reducer(
        seed(),
        AgentEventAction(
            ToolCallEvent(
                name="confirm_finding",
                args_json=json.dumps(
                    {
                        "severity": severity,
                        "title": "T"
                    }
                ),
            )
        ),
    )

    assert out.transcript[-1].color == color



def test_invalid_finding_fallback():

    out = reducer(
        seed(),
        AgentEventAction(
            ToolCallEvent(
                name="confirm_finding",
                args_json="{bad json"
            )
        ),
    )

    assert out.transcript[-1].kind == "tool-call"
