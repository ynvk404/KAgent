"""Terminal caret anchoring for KAgent's custom, Static-based text fields."""
from rich.style import Style
from textual.geometry import Offset, Region
from textual.strip import Strip
from textual.widgets import Static


# Nonvisual metadata survives Rich/Textual wrapping and cell-width conversion.
CARET_STYLE = Style(meta={"kagent_caret": True})


class CursorStatic(Static):
    def render_lines(self, crop: Region) -> list[Strip]:
        strips = super().render_lines(crop)
        if self.screen is not self.app.screen:
            return strips
        for y, strip in enumerate(strips):
            x = 0
            for segment in strip:
                if segment.style is not None and segment.style.meta.get("kagent_caret"):
                    # Publish the visible caret through Textual. Its driver uses
                    # this even with the hardware cursor hidden, to anchor OS
                    # IME composition. Use the final CSS/cropped render so wrap,
                    # Unicode widths, padding, scrolling and resize agree.
                    self.app.cursor_position = self.region.offset + crop.offset + Offset(x, y)
                    return strips
                x += segment.cell_length
        return strips
