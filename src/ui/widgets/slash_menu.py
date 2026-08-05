
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from src.ui.commands.menu_window import compute_menu_window
from src.ui.commands.slash_items import SlashItem


@dataclass(frozen=True, slots=True)
class SlashMenuLine:
    text: str
    selected: bool = False
    dim: bool = False


class SlashMenu:

    def __init__(
        self,
        items: Sequence[SlashItem],
        selected: int,
    ):
        self.items = list(items)
        self.selected = selected


    def render(self) -> list[SlashMenuLine]:

        if not self.items:
            return []


        window = compute_menu_window(
            len(self.items),
            self.selected,
        )


        lines: list[SlashMenuLine] = []


        if window.hidden_above > 0:
            lines.append(
                SlashMenuLine(
                    text=f"  ↑ {window.hidden_above} more",
                    dim=True,
                )
            )


        visible = self.items[
            window.start:window.end
        ]


        for idx, item in enumerate(visible):

            absolute_idx = window.start + idx

            is_selected = (
                absolute_idx == self.selected
            )


            args = (
                f" {item.args}"
                if item.args
                else ""
            )


            text = (
                f"  {item.name}"
                f"{args}"
                f"  {item.description}"
            )


            lines.append(
                SlashMenuLine(
                    text=text,
                    selected=is_selected,
                    dim=not is_selected,
                )
            )


        if window.hidden_below > 0:
            lines.append(
                SlashMenuLine(
                    text=f"  ↓ {window.hidden_below} more",
                    dim=True,
                )
            )


        return lines