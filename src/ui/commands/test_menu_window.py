from __future__ import annotations

from dataclasses import dataclass


MENU_VISIBLE_CAP = 5


@dataclass(frozen=True, slots=True)
class MenuWindow:
    start: int
    end: int
    hidden_above: int
    hidden_below: int


def compute_menu_window(
    total: int,
    selected: int,
    cap: int = MENU_VISIBLE_CAP,
) -> MenuWindow:

    if total <= cap:
        return MenuWindow(
            start=0,
            end=total,
            hidden_above=0,
            hidden_below=0,
        )

    start = max(
        0,
        min(
            selected - (cap // 2),
            total - cap,
        ),
    )

    end = min(
        start + cap,
        total,
    )

    return MenuWindow(
        start=start,
        end=end,
        hidden_above=start,
        hidden_below=total - end,
    )