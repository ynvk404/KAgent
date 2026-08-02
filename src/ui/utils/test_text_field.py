# Pure-function tests for the text-field helpers. The stateful TextField
# class itself would be exercised end-to-end through the app; here we cover
# the arithmetic that's hardest to get right: line/column math and the
# paste-detection predicate.

from __future__ import annotations

from .text_field import (
    expand_pasted_text_markers,
    looks_like_paste,
    normalize_pasted_text,
    offset_at,
    pasted_text_marker,
    position_of,
    should_collapse_paste,
    strip_paste_markers,
)

ESC = chr(0x1B)


class TestPositionOf:
    def test_handles_single_line_offsets(self):
        assert position_of("hello", 0) == (0, 0)
        assert position_of("hello", 3) == (0, 3)
        assert position_of("hello", 5) == (0, 5)

    def test_walks_across_newlines(self):
        assert position_of("ab\ncd\nef", 0) == (0, 0)
        assert position_of("ab\ncd\nef", 2) == (0, 2)
        assert position_of("ab\ncd\nef", 3) == (1, 0)
        assert position_of("ab\ncd\nef", 5) == (1, 2)
        assert position_of("ab\ncd\nef", 6) == (2, 0)
        assert position_of("ab\ncd\nef", 8) == (2, 2)

    def test_clamps_offset_to_value_length(self):
        assert position_of("hi", 999) == (0, 2)


class TestOffsetAt:
    def test_computes_flat_offset_from_line_col(self):
        assert offset_at("ab\ncd\nef", 0, 0) == 0
        assert offset_at("ab\ncd\nef", 1, 0) == 3
        assert offset_at("ab\ncd\nef", 1, 2) == 5
        assert offset_at("ab\ncd\nef", 2, 1) == 7

    def test_clamps_column_to_target_line_length(self):
        # line 1 ("cd") is only 2 chars — column 99 should clamp.
        assert offset_at("ab\ncd\nef", 1, 99) == 5

    def test_clamps_line_to_last_line_index(self):
        # 3 lines total (indices 0-2); line 99 should clamp to line 2.
        assert offset_at("ab\ncd\nef", 99, 1) == 7


class TestLooksLikePaste:
    def test_flags_multi_character_input_as_paste(self):
        assert looks_like_paste("abc") is True

    def test_flags_single_char_with_embedded_newline_as_paste_when_not_return(self):
        assert looks_like_paste("a\nb", key_return=False) is True

    def test_treats_true_enter_keypress_as_not_paste(self):
        # The terminal may report empty input + a return keypress for Enter.
        assert looks_like_paste("", key_return=True) is False
        assert looks_like_paste("\n", key_return=True) is False

    def test_treats_single_printable_character_as_not_paste(self):
        assert looks_like_paste("a") is False

    def test_ignores_empty_input(self):
        assert looks_like_paste("") is False


class TestStripPasteMarkers:
    def test_removes_bracketed_paste_start_end_escape_sequences(self):
        wrapped = f"{ESC}[200~hello\nworld{ESC}[201~"
        assert strip_paste_markers(wrapped) == "hello\nworld"

    def test_passes_plain_text_through_unchanged(self):
        assert strip_paste_markers("hello world") == "hello world"


class TestPastedTextMarkers:
    def test_normalizes_pasted_crlf_text(self):
        assert normalize_pasted_text("a\r\nb\rc") == "a\nb\nc"

    def test_collapses_only_multiline_pasted_text(self):
        assert should_collapse_paste("single line") is False
        assert should_collapse_paste("line 1\nline 2") is True

    def test_builds_compact_marker_with_id_line_count_char_count(self):
        assert pasted_text_marker(1, "one\ntwo\nthree") == "[Pasted text #1 +3 lines, 13 chars]"

    def test_expands_pasted_text_markers_before_submission(self):
        pasted = {1: "alpha\nbeta"}
        assert (
            expand_pasted_text_markers("review [Pasted text #1 +2 lines, 10 chars]", pasted)
            == "review alpha\nbeta"
        )

    def test_leaves_unknown_pasted_text_markers_readable(self):
        assert (
            expand_pasted_text_markers("[Pasted text #2 +9 lines]", {})
            == "[Pasted text #2 +9 lines]"
        )