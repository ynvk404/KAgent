"""
"""

import re
from typing import List, Tuple


# ==========================================================
# Regex
# ==========================================================

THINK_PAIR_RE = re.compile(
    r"(?:<(?:think|thinking|reasoning)>|◁think▷)"
    r"(?:(?!<(?:think|thinking|reasoning)>|◁think▷)[\s\S])*?"
    r"(?:</(?:think|thinking|reasoning)>|◁/think▷)\s*",
    re.IGNORECASE,
)

LONE_THINK_TAG_RE = re.compile(
    r"</?(?:think|thinking|reasoning)>|◁/?think▷",
    re.IGNORECASE,
)

ANY_THINK_TAG_RE = re.compile(
    r"</?(?:think|thinking|reasoning)>|◁/?think▷",
    re.IGNORECASE,
)


# ==========================================================
# stripThinkingTags
# ==========================================================

def strip_thinking_tags(text: str) -> str:
    """
    Xóa toàn bộ block <think>...</think>
    và các tag lẻ còn sót.
    """

    if not ANY_THINK_TAG_RE.search(text):
        return text

    out = text

    while True:
        prev = out
        out = THINK_PAIR_RE.sub("", out)

        if out == prev:
            break

    out = LONE_THINK_TAG_RE.sub("", out)

    return out.lstrip()


# ==========================================================
# Tags
# ==========================================================

THINK_OPEN_TAGS = [
    "<think>",
    "<thinking>",
    "<reasoning>",
    "◁think▷",
]

THINK_CLOSE_TAGS = [
    "</think>",
    "</thinking>",
    "</reasoning>",
    "◁/think▷",
]

ALL_THINK_TAGS = THINK_OPEN_TAGS + THINK_CLOSE_TAGS


# ==========================================================
# Helpers
# ==========================================================

def find_first_tag(
    text: str,
    tags: List[str],
) -> Tuple[int, int]:
    """
    Trả về (index, length)
    """

    lower = text.lower()

    index = -1
    length = 0

    for tag in tags:

        i = lower.find(tag)

        if i >= 0 and (index < 0 or i < index):
            index = i
            length = len(tag)

    return index, length


def safe_prefix_length(
    text: str,
    tags: List[str],
) -> int:
    """
    Tính số ký tự an toàn có thể xử lý.
    """

    lower = text.lower()

    hold = 0

    for tag in tags:

        max_len = min(len(tag) - 1, len(lower))

        for p in range(max_len, hold, -1):

            if lower.endswith(tag[:p]):
                hold = p
                break

    return len(text) - hold


# ==========================================================
# Streaming Filter
# ==========================================================

class ThinkingStreamFilter:
    """
    Lọc reasoning khi model stream.
    """

    def __init__(self):

        self.in_thinking = False
        self.pending = ""

    def push(self, chunk: str) -> str:

        if not chunk:
            return ""

        self.pending += chunk

        out = ""

        while self.pending:

            if self.in_thinking:

                close_index, close_len = find_first_tag(
                    self.pending,
                    THINK_CLOSE_TAGS,
                )

                if close_index < 0:

                    safe = safe_prefix_length(
                        self.pending,
                        THINK_CLOSE_TAGS,
                    )

                    self.pending = self.pending[safe:]

                    break

                self.pending = (
                    self.pending[close_index + close_len :]
                    .lstrip()
                )

                self.in_thinking = False

                continue

            open_index, open_len = find_first_tag(
                self.pending,
                THINK_OPEN_TAGS,
            )

            close_index, close_len = find_first_tag(
                self.pending,
                THINK_CLOSE_TAGS,
            )

            open_first = (
                open_index >= 0
                and (
                    close_index < 0
                    or open_index <= close_index
                )
            )

            if open_first:
                next_index = open_index
                next_len = open_len
            else:
                next_index = close_index
                next_len = close_len

            if next_index < 0:

                safe = safe_prefix_length(
                    self.pending,
                    ALL_THINK_TAGS,
                )

                out += self.pending[:safe]

                self.pending = self.pending[safe:]

                break

            out += self.pending[:next_index]

            self.pending = self.pending[next_index + next_len :]

            if open_first:
                self.in_thinking = True
            else:
                self.pending = self.pending.lstrip()

        return out

    def flush(self) -> str:
        """
        Gọi khi stream kết thúc.
        """

        if self.in_thinking:
            out = ""
        else:
            out = self.pending

        self.pending = ""
        self.in_thinking = False

        return out