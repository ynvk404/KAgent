"""Small semantic palette for KAgent's live Textual UI."""

from dataclasses import dataclass
from typing import Literal

from textual.theme import Theme

PRIMARY = "#D6DEE8"
MUTED = "#7E8A9A"
ACCENT = "#38BDF8"
SUCCESS = "#3FB950"
WARNING = "#F59E0B"
ERROR = "#EF4444"
DANGER = "#F43F5E"
LINK = "#60A5FA"

BOLD_ACCENT = f"bold {ACCENT}"
BOLD_SUCCESS = f"bold {SUCCESS}"
BOLD_ERROR = f"bold {ERROR}"
BOLD_DANGER = f"bold {DANGER}"

ThemeChoice = Literal["dark", "light"]


@dataclass(frozen=True, slots=True)
class UIPalette:
    """Presentation colors only; semantic/status colors remain the constants above."""

    text: str = PRIMARY
    muted: str = MUTED
    accent: str = ACCENT
    border: str = MUTED
    light: bool = False


DARK_UI = UIPalette()
LIGHT_UI = UIPalette("#1F2937", "#52606D", "#075985", "#52606D", light=True)


def light_theme() -> Theme:
    """Create the startup-only light theme without modifying Textual's dark theme."""
    return Theme(
        name="kagent-light",
        primary=LIGHT_UI.accent,
        accent=LIGHT_UI.accent,
        foreground=LIGHT_UI.text,
        background="#FAF8F2",
        surface="#F2F0E8",
        panel="#EEECE4",
        success=SUCCESS,
        warning=WARNING,
        error=ERROR,
        dark=False,
        variables={
            "ui-muted": LIGHT_UI.muted,
            "ui-accent": LIGHT_UI.accent,
            "ui-border": LIGHT_UI.border,
            "ui-selection-background": f"{LIGHT_UI.accent} 10%",
        },
    )
