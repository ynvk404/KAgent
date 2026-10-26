"""Read-only access to the latest outcome recorded by this UI instance."""
from typing import Callable

from rich.text import Text

from src.ui.core.state import TurnDetails
from src.ui.render.sanitize import sanitize_text
from src.ui.theme import BOLD_ACCENT
from src.ui.theme import DARK_UI, UIPalette


class TurnDetailsModal:
    def __init__(self, details: TurnDetails | None, close: Callable[[], None]):
        self.details = details
        self.close = close

    def handle_key(self, key: str) -> None:
        if key in {"escape", "esc", "enter"}:
            self.close()

    def instructions(self, *, ui: UIPalette = DARK_UI) -> Text:
        return Text("↑↓ scroll · Home/End · Esc close", style=ui.muted)

    def render(self, *, ui: UIPalette = DARK_UI) -> Text:
        text = Text()
        text.append("Latest turn in this UI session\n", style=f"bold {ui.accent}")
        details = self.details
        if details is None:
            text.append("No completed turn diagnostics recorded here.\n", style="")
        else:
            text.append(f"UI turn {details.turn_number}\n" if details.turn_number else "Observed turn (start not recorded)\n", style=ui.muted)
            text.append(sanitize_text(details.outcome) + "\n", style="")
            text.append("Completed operations (successful operation records):\n", style=BOLD_ACCENT)
            text.append("\n".join(f"  {sanitize_text(name)} ({count})" for name, count in details.completed_operations)
                        or "  None recorded", style="")
            if details.remaining:
                text.append("\n\nAssessment details:\n", style=BOLD_ACCENT)
                text.append("\n".join(f"  {sanitize_text(item)}" for item in details.remaining), style="")
        text.append("\n\nLatest snapshot from this UI session. Cleared by /clear or /reset.\n"
                    "Historical diagnostics are unavailable after resume.", style=ui.muted)
        return text
