import json
from pathlib import Path

from src.logger.session_debug import (
    create_session_debug_log,
    SessionDebugOptions,
)


def test_writes_jsonl_events_with_session_metadata(tmp_path: Path):
    path = tmp_path / "session.jsonl"

    log = create_session_debug_log(
        SessionDebugOptions(
            enabled=True,
            path=str(path),
            session_id="abc123",
        )
    )

    log.write(
        "session_start",
        {"cwd": "/tmp/project"},
    )

    log.agent_event(
        {
            "type": "assistant-text",
            "text": "hello",
        }
    )

    lines = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").strip().splitlines()
    ]

    assert len(lines) == 2

    assert lines[0]["seq"] == 1
    assert lines[0]["event"] == "session_start"
    assert lines[0]["session_id"] == "abc123"
    assert lines[0]["cwd"] == "/tmp/project"

    assert lines[1]["seq"] == 2
    assert lines[1]["event"] == "agent_event"
    assert lines[1]["session_id"] == "abc123"
    assert lines[1]["type"] == "assistant-text"
    assert lines[1]["text"] == "hello"


def test_serializes_agent_errors_into_json_safe_objects(tmp_path: Path):
    path = tmp_path / "session.jsonl"

    log = create_session_debug_log(
        SessionDebugOptions(
            enabled=True,
            path=str(path),
            session_id="abc123",
        )
    )

    try:
        raise RuntimeError("boom")
    except RuntimeError as err:
        log.agent_event(
            {
                "type": "error",
                "err": err,
            }
        )

    line = json.loads(path.read_text(encoding="utf-8"))

    assert line["err"]["message"] == "boom"
    assert line["err"]["name"] == "RuntimeError"


def test_is_noop_when_disabled():
    log = create_session_debug_log(
        SessionDebugOptions(
            enabled=False,
            session_id="abc123",
        )
    )

    assert log.enabled is False
    log.write("ignored")