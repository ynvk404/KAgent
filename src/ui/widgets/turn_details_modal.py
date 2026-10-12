"""Read-only access to the latest outcome recorded by this UI instance."""
from typing import Callable

from rich.text import Text

from src.ui.core.state import TurnDetails
from src.ui.render.sanitize import sanitize_text
from src.ui.theme import BOLD_ACCENT, MUTED


class TurnDetailsModal:
    def __init__(self, details: TurnDetails | None, close: Callable[[], None]):
        self.details = details
        self.close = close

    def handle_key(self, key: str) -> None:
        if key in {"escape", "esc", "enter"}:
            self.close()

    def instructions(self) -> Text:
        return Text("↑↓ scroll · Home/End · Esc close", style=MUTED)

    def render(self) -> Text:
        text = Text()
        text.append("Latest turn in this UI session\n", style=BOLD_ACCENT)
        details = self.details
        if details is None:
            text.append("No completed turn diagnostics recorded here.\n", style="")
        else:
            text.append(f"UI turn {details.turn_number}\n" if details.turn_number else "Observed turn (start not recorded)\n", style=MUTED)
            text.append(sanitize_text(details.outcome) + "\n", style="")
            text.append("Completed operations (successful operation records):\n", style=BOLD_ACCENT)
            text.append("\n".join(f"  {sanitize_text(name)} ({count})" for name, count in details.completed_operations)
                        or "  None recorded", style="")
        text.append("\n\nLocal latest snapshot only; cleared with /clear or /reset.\n"
                    "Historical diagnostics are unavailable after resume.", style=MUTED)
        return text
