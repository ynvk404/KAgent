from __future__ import annotations

from src.ui.core.state import TranscriptEntry, TranscriptFilter


def filter_transcript(
    entries: list[TranscriptEntry],
    filter: TranscriptFilter,
) -> list[TranscriptEntry]:
    if filter == "all":
        return entries
    if filter == "current":
        last_user_idx = -1
        for i in range(len(entries) - 1, -1, -1):
            if entries[i].kind == "user":
                last_user_idx = i
                break
        return entries if last_user_idx == -1 else entries[last_user_idx:]
    return [entry for entry in entries if transcript_entry_matches_filter(entry, filter)]


def transcript_entry_matches_filter(
    entry: TranscriptEntry,
    filter: TranscriptFilter,
) -> bool:
    if filter == "all" or filter == "current":
        return True
    if filter == "compact":
        if entry.kind == "tool-result" and entry.text.startswith("[ok]"):
            return False
        return entry.kind != "decision"
    if filter == "findings":
        return entry.kind == "finding" or "Confirmed Finding" in entry.text
    if filter == "errors":
        return entry.kind == "error" or "[error]" in entry.text
    raise AssertionError(f"Unhandled TranscriptFilter: {filter!r}")