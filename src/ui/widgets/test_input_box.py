from __future__ import annotations

import pytest

from src.ui.widgets.input_box import InputBox, InputLine, InputSegment


def texts(line: InputLine) -> list[str]:
    return [s.text for s in line.segments]


def styles(line: InputLine) -> list[str | None]:
    return [s.style for s in line.segments]


@pytest.fixture(autouse=True)
def fixed_columns(monkeypatch):
    """Pin terminal width so rule-line assertions are deterministic
    regardless of the real terminal the tests run in."""
    monkeypatch.setattr(
        "src.ui.widgets.input_box.get_terminal_size",
        lambda: (10, 5),
    )


def test_every_branch_is_wrapped_by_rule_top_and_bottom():
    disabled_empty = InputBox(value="", cursor=0, disabled=True).render()
    placeholder = InputBox(value="", cursor=0, placeholder="hi").render()
    normal = InputBox(value="hello", cursor=2).render()

    for lines in (disabled_empty, placeholder, normal):
        assert texts(lines[0]) == ["─" * 10]
        assert styles(lines[0]) == ["gray"]
        assert texts(lines[-1]) == ["─" * 10]
        assert styles(lines[-1]) == ["gray"]


def test_rule_width_tracks_terminal_columns(monkeypatch):
    monkeypatch.setattr(
        "src.ui.widgets.input_box.get_terminal_size",
        lambda: (20, 5),
    )

    lines = InputBox(value="x", cursor=0).render()

    assert texts(lines[0]) == ["─" * 20]


def test_rule_has_minimum_width_of_one(monkeypatch):
    monkeypatch.setattr(
        "src.ui.widgets.input_box.get_terminal_size",
        lambda: (0, 5),
    )

    lines = InputBox(value="x", cursor=0).render()

    assert texts(lines[0]) == ["─"]


def test_disabled_and_empty_shows_agent_running():
    lines = InputBox(value="", cursor=0, disabled=True).render()

    assert len(lines) == 3
    content = lines[1]
    assert texts(content) == ["❯ ", "agent running…"]
    assert styles(content) == ["gray", "gray"]


def test_disabled_and_empty_ignores_placeholder():
    lines = InputBox(
        value="",
        cursor=0,
        disabled=True,
        placeholder="type something",
    ).render()

    content = lines[1]
    assert texts(content) == ["❯ ", "agent running…"]


def test_placeholder_shown_with_cursor_block():
    lines = InputBox(
        value="",
        cursor=0,
        placeholder="ask me anything",
    ).render()

    assert len(lines) == 3
    content = lines[1]
    assert texts(content) == ["❯ ", "ask me anything", "▌"]
    assert styles(content) == ["prompt", "gray", "cursor"]


def test_placeholder_omits_cursor_block_when_disabled():
    lines = InputBox(
        value="",
        cursor=0,
        placeholder="ask me anything",
        disabled=True,
    ).render()

    content = lines[1]
    assert texts(content) == ["❯ ", "agent running…"]


def test_no_placeholder_falls_through_to_normal_empty_input():
    lines = InputBox(value="", cursor=0).render()

    assert len(lines) == 3
    content = lines[1]
    assert texts(content) == ["❯ ", "", "▌", ""]
    assert styles(content) == ["prompt", "text", "cursor", "text"]


def test_cursor_mid_line_highlights_char_under_cursor():
    lines = InputBox(value="hello", cursor=2).render()

    content = lines[1]
    assert texts(content) == ["❯ ", "he", "l", "lo"]
    assert styles(content) == ["prompt", "text", "cursor_char", "text"]


def test_cursor_at_start_of_line():
    lines = InputBox(value="hello", cursor=0).render()

    content = lines[1]
    assert texts(content) == ["❯ ", "", "h", "ello"]
    assert styles(content) == ["prompt", "text", "cursor_char", "text"]


def test_cursor_at_end_of_line_shows_block_cursor():
    lines = InputBox(value="hi", cursor=2).render()

    content = lines[1]
    assert texts(content) == ["❯ ", "hi", "▌", ""]
    assert styles(content) == ["prompt", "text", "cursor", "text"]


def test_disabled_normal_input_renders_gray_with_no_cursor():
    lines = InputBox(value="hello", cursor=2, disabled=True).render()

    content = lines[1]
    assert texts(content) == ["❯ ", "hello"]
    assert styles(content) == ["gray", "gray"]


def test_custom_prompt_is_used_as_prefix():
    lines = InputBox(value="hi", cursor=0, prompt=">>> ").render()

    content = lines[1]
    assert texts(content)[0] == ">>> "


def test_multiline_uses_continuation_indent_on_later_lines():
    lines = InputBox(value="foo\nbar", cursor=0).render()

    assert len(lines) == 4
    first, second = lines[1], lines[2]
    assert texts(first)[0] == "❯ "
    assert texts(second)[0] == "  "


def test_multiline_cursor_lands_on_correct_line():
    lines = InputBox(value="foo\nbar", cursor=5).render()

    first, second = lines[1], lines[2]
    assert texts(first) == ["❯ ", "foo"]
    assert styles(first) == ["prompt", "text"]
    assert texts(second) == ["  ", "b", "a", "r"]
    assert styles(second) == ["prompt", "text", "cursor_char", "text"]


def test_multiline_disabled_renders_all_lines_gray_no_cursor():
    lines = InputBox(value="foo\nbar", cursor=5, disabled=True).render()

    first, second = lines[1], lines[2]
    assert texts(first) == ["❯ ", "foo"]
    assert styles(first) == ["gray", "gray"]
    assert texts(second) == ["  ", "bar"]
    assert styles(second) == ["gray", "gray"]