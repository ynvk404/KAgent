
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from src.ui.commands.menu_window import compute_menu_window
from src.ui.theme import ACCENT


@dataclass(slots=True)
class MentionCandidate:
    insert: str
    display: str
    is_dir: bool


@dataclass(frozen=True, slots=True)
class MentionMenuLine:
    text: str
    selected: bool = False
    dim: bool = False
    icon_color: str | None = None


class MentionMenu:

    def __init__(
        self,
        cwd: str,
        candidates: Sequence[MentionCandidate],
        selected: int,
    ):
        self.cwd = cwd
        self.candidates = list(candidates)
        self.selected = selected


    def render(self) -> list[MentionMenuLine]:

        if not self.candidates:
            return []


        w = compute_menu_window(
            len(self.candidates),
            self.selected,
        )


        lines: list[MentionMenuLine] = []


        lines.append(
            MentionMenuLine(
                text=f"  @{self.cwd or ''}",
                dim=True,
            )
        )


        if w.hidden_above > 0:
            lines.append(
                MentionMenuLine(
                    text=f"  ↑ {w.hidden_above} more",
                    dim=True,
                )
            )


        visible = self.candidates[
            w.start:w.end
        ]


        for idx, candidate in enumerate(visible):

            absolute_idx = w.start + idx

            is_selected = (
                absolute_idx == self.selected
            )


            icon = (
                "▸"
                if candidate.is_dir
                else "+"
            )


            lines.append(
                MentionMenuLine(
                    text=f"  {icon} {candidate.display}",
                    selected=is_selected,
                    dim=not is_selected,
                    icon_color=ACCENT if candidate.is_dir else None,
                )
            )


        if w.hidden_below > 0:
            lines.append(
                MentionMenuLine(
                    text=f"  ↓ {w.hidden_below} more",
                    dim=True,
                )
            )


        return lines