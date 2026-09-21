import pytest

from src.agent.sanitize import (
    ThinkingStreamFilter,
    strip_thinking_tags,
)


def test_removes_complete_think_blocks():
    assert (
        strip_thinking_tags(
            "<think>reasoning</think>\nAnswer"
        )
        == "Answer"
    )


def test_removes_dangling_closing_think_tags():
    assert (
        strip_thinking_tags(
            "</think>\nAnswer"
        )
        == "Answer"
    )


def test_keeps_trailing_text_after_unterminated_think_tag():
    assert (
        strip_thinking_tags(
            "<think>reasoning that never closed"
        )
        == "reasoning that never closed"
    )

    assert (
        strip_thinking_tags(
            "<think>reasoning ... and the answer here"
        )
        == "reasoning ... and the answer here"
    )


def test_balances_nested_think_blocks():
    assert (
        strip_thinking_tags(
            "<think>a<think>b</think>visible</think>real"
        )
        == "real"
    )


def test_strips_thinking_and_reasoning_variants():
    assert (
        strip_thinking_tags(
            "<thinking>plan</thinking>\nAnswer"
        )
        == "Answer"
    )

    assert (
        strip_thinking_tags(
            "<reasoning>why</reasoning>\nAnswer"
        )
        == "Answer"
    )


def test_strips_kimi_unicode_delimiters():
    assert (
        strip_thinking_tags(
            "◁think▷deliberating◁/think▷\nAnswer"
        )
        == "Answer"
    )

    assert (
        strip_thinking_tags(
            "◁/think▷Answer"
        )
        == "Answer"
    )


def run(chunks):
    f = ThinkingStreamFilter()

    out = ""

    for chunk in chunks:
        out += f.push(chunk)

    out += f.flush()

    return out


def test_passes_plain_text_through():
    assert run(
        ["hello ", "world"]
    ) == "hello world"


def test_suppresses_complete_think_block():
    assert run(
        ["<think>secret</think>answer"]
    ) == "answer"


def test_stream_balances_nested_thinking_blocks():
    text = (
        "<think>outer<think>inner</think>"
        "SHOULD_STILL_BE_HIDDEN</think>final"
    )

    assert run(
        [
            "<think>outer<think>inner</think>",
            "SHOULD_STILL_BE_HIDDEN</think>final",
        ]
    ) == strip_thinking_tags(text) == "final"


def test_stream_balances_nested_mixed_thinking_blocks():
    text = (
        "<think>outer<reasoning>inner</reasoning>"
        "SHOULD_STILL_BE_HIDDEN</think>final"
    )

    assert run(
        [
            "<think>outer<reasoning>inner</reasoning>",
            "SHOULD_STILL_BE_HIDDEN</think>final",
        ]
    ) == strip_thinking_tags(text) == "final"


def test_suppresses_split_tags():
    assert run(
        [
            "<thi",
            "nk>sec",
            "ret</thi",
            "nk>ans",
            "wer",
        ]
    ) == "answer"


@pytest.mark.parametrize(
    ("opening", "closing"),
    [
        ("<think>", "</think>"),
        ("<thinking>", "</thinking>"),
        ("<reasoning>", "</reasoning>"),
        ("◁think▷", "◁/think▷"),
    ],
)
def test_suppresses_all_tag_variants_split_across_chunks(opening, closing):
    open_split = len(opening) // 2
    close_split = len(closing) // 2

    assert run(
        [
            opening[:open_split],
            opening[open_split:] + "secret" + closing[:close_split],
            closing[close_split:] + "visible",
        ]
    ) == "visible"


def test_keeps_text_before_and_after():
    assert run(
        [
            "before ",
            "<think>hidden",
            "</think> after",
        ]
    ) == "before after"


def test_drops_lone_close_tag():
    assert run(
        [
            "reasoning text",
            "</think>",
            "the answer",
        ]
    ) == "reasoning textthe answer"


def test_stream_variants():
    assert run(
        [
            "<thinking>x</thinking>a"
        ]
    ) == "a"

    assert run(
        [
            "<reasoning>x</reasoning>a"
        ]
    ) == "a"

    assert run(
        [
            "◁think▷x◁/think▷a"
        ]
    ) == "a"


def test_unterminated_block_at_flush():
    assert run(
        [
            "answer ",
            "<think>never closes",
        ]
    ) == "answer "


def test_partial_open_tag():
    assert run(
        [
            "answer <thi"
        ]
    ) == "answer <thi"
