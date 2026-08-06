from __future__ import annotations

from typing import cast

import pytest

from src.ui.core.state import TranscriptEntry
from src.ui.render.transcript_filter import (
    TranscriptFilter,
    filter_transcript,
    transcript_entry_matches_filter,
)


def _e(kind, text=""):
    return TranscriptEntry(kind=kind, text=text)


def test_all_returns_everything():
    entries = [_e("user"), _e("assistant"), _e("decision")]

    assert filter_transcript(entries, "all") == entries


def test_current_returns_from_last_user_message():
    entries = [
        _e("user", "first"),
        _e("assistant", "a"),
        _e("user", "second"),
        _e("assistant", "b"),
    ]

    result = filter_transcript(entries, "current")

    assert [e.text for e in result] == ["second", "b"]


def test_current_returns_all_when_no_user_message():
    entries = [_e("assistant"), _e("tool-result")]

    assert filter_transcript(entries, "current") == entries


def test_compact_hides_ok_tool_results_and_decisions():
    entries = [
        _e("assistant", "hi"),
        _e("tool-result", "[ok] done"),
        _e("tool-result", "real output"),
        _e("decision", "planning"),
    ]

    result = filter_transcript(entries, "compact")

    kinds = [(e.kind, e.text) for e in result]
    assert ("tool-result", "[ok] done") not in kinds
    assert ("tool-result", "real output") in kinds
    assert ("decision", "planning") not in kinds
    assert ("assistant", "hi") in kinds


def test_findings_filter():
    entries = [
        _e("finding", "★ x"),
        _e("assistant", "Confirmed Finding: SQLi"),
        _e("assistant", "unrelated"),
    ]

    result = filter_transcript(entries, "findings")

    assert len(result) == 2
    assert entries[2] not in result


def test_errors_filter():
    entries = [
        _e("error", "boom"),
        _e("tool-result", "[error] failed"),
        _e("assistant", "fine"),
    ]

    result = filter_transcript(entries, "errors")

    assert len(result) == 2
    assert entries[2] not in result


def test_matches_all_and_current_always_true():
    entry = _e("decision", "x")
    assert transcript_entry_matches_filter(entry, "all") is True
    assert transcript_entry_matches_filter(entry, "current") is True


def test_unhandled_filter_raises():
    # Intentionally passing a value outside the TranscriptFilter Literal to
    # exercise the defensive `assert` branch at runtime; cast() tells the
    # type checker this is deliberate rather than a real type error.
    bogus_filter = cast(TranscriptFilter, "nonsense")

    with pytest.raises(AssertionError, match="Unhandled TranscriptFilter"):
        transcript_entry_matches_filter(_e("assistant"), bogus_filter)