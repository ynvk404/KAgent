"""
test_sanitizer.py

Port từ sanitize.test.ts
"""

from agent.sanitize import (
    ThinkingStreamFilter,
    strip_thinking_tags,
)


# ==========================================================
# strip_thinking_tags
# ==========================================================

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
    # H7: an unclosed <think> means we can't tell where reasoning ends,
    # so strip only the tag and preserve the remaining text.
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
    # M14: peel nested pairs from inside out.
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

    # Lone Kimi close tag (no opener)
    assert (
        strip_thinking_tags(
            "◁/think▷Answer"
        )
        == "Answer"
    )


# ==========================================================
# ThinkingStreamFilter
# ==========================================================

def run(chunks):
    """
    Feed each chunk and concatenate
    everything emitted by the filter.
    """
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


def test_suppresses_split_tags():
    # Open/close tags split across chunks.
    assert run(
        [
            "<thi",
            "nk>sec",
            "ret</thi",
            "nk>ans",
            "wer",
        ]
    ) == "answer"


def test_keeps_text_before_and_after():
    assert run(
        [
            "before ",
            "<think>hidden",
            "</think> after",
        ]
    ) == "before after"


def test_drops_lone_close_tag():
    # DeepSeek-R1 style stream:
    # reasoning -> </think> -> answer
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
    # An open block never closes.
    assert run(
        [
            "answer ",
            "<think>never closes",
        ]
    ) == "answer "


def test_partial_open_tag():
    # Stream ends in the middle of an opening tag.
    assert run(
        [
            "answer <thi"
        ]
    ) == "answer <thi"