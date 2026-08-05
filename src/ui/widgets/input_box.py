from __future__ import annotations

from dataclasses import dataclass

from src.ui.core.terminal_size import get_terminal_size
from src.ui.utils.text_field import position_of

@dataclass(frozen=True, slots=True)
class InputSegment:
    text: str
    style: str | None = None


@dataclass(frozen=True, slots=True)
class InputLine:
    segments: list[InputSegment]


CONTINUATION_INDENT = "  "


class InputBox:

    def __init__(
        self,
        value: str,
        cursor: int,
        prompt: str = "❯ ",
        placeholder: str | None = None,
        disabled: bool = False,
    ):
        self.value = value
        self.cursor = cursor
        self.prompt = prompt
        self.placeholder = placeholder
        self.disabled = disabled

    def _rule(self) -> InputLine:
        columns, _rows = get_terminal_size()
        return InputLine(
            [InputSegment("─" * max(1, columns), "gray")]
        )

    def render(self) -> list[InputLine]:
        rule = self._rule()

        lines: list[InputLine] = [rule]

        is_empty = len(self.value) == 0

        if self.disabled and is_empty:
            lines.append(
                InputLine(
                    [
                        InputSegment(self.prompt, "gray"),
                        InputSegment("agent running…", "gray"),
                    ]
                )
            )
            lines.append(rule)
            return lines

        if is_empty and self.placeholder:
            segments = [
                InputSegment(self.prompt, "prompt"),
                InputSegment(self.placeholder, "gray"),
            ]

            if not self.disabled:
                segments.append(InputSegment("▌", "cursor"))

            lines.append(InputLine(segments))
            lines.append(rule)
            return lines

        text_lines = self.value.split("\n")

        cursor_line, cursor_col = position_of(self.value, self.cursor)

        for index, text in enumerate(text_lines):
            prefix = self.prompt if index == 0 else CONTINUATION_INDENT

            active = index == cursor_line and not self.disabled

            segments: list[InputSegment] = []

            segments.append(
                InputSegment(prefix, "gray" if self.disabled else "prompt")
            )

            if self.disabled:
                segments.append(InputSegment(text, "gray"))

            elif active:
                head = text[:cursor_col]
                under = text[cursor_col] if cursor_col < len(text) else ""
                tail = text[cursor_col + 1:]

                segments.append(InputSegment(head, "text"))

                if under:
                    segments.append(InputSegment(under, "cursor_char"))
                else:
                    segments.append(InputSegment("▌", "cursor"))

                segments.append(InputSegment(tail, "text"))

            else:
                segments.append(InputSegment(text, "text"))

            lines.append(InputLine(segments))

        lines.append(rule)
        return lines