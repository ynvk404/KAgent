from __future__ import annotations
from src.ui.widgets.banner import BannerData
import json

import pytest

from src.ui.core.state import (
    initial_state,
    reducer,
    AgentEventAction,
    SetBusy,
    Clear,
    CycleTranscriptFilter,
)

from src.agent.events import (
    ToolCallEvent,
    AssistantDeltaEvent,
    DoneEvent,
)


def seed():
    return initial_state(
        "",
        BannerData(
            provider="",
            model="",
            cwd="",
        ),
    )

# ============================================================
# tool-call preview
# ============================================================


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

    assert last.prefix == "⏺ "
    assert '{"command"' not in last.text
    assert "curl -ksS https://example.com" in last.text



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

    assert last.prefix == "⏺ "
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
    assert last.prefix == "⏺ "



# ============================================================
# Streaming
# ============================================================


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



# ============================================================
# Filter / Clear
# ============================================================


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

# ============================================================
# Finding
# ============================================================


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
    assert last.color == "cyan"

    assert (
        "LOW · Information Disclosure - PHP Version in Response Headers"
        in last.text
    )

    assert "GET https://x.test/" in last.text
    assert "impact: Leaks the PHP version." in last.text



@pytest.mark.parametrize(
    "severity,color",
    [
        ("critical", "magenta"),
        ("high", "red"),
        ("medium", "yellow"),
        ("low", "cyan"),
        ("info", "gray"),
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