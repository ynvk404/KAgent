"""Structured quick reference, laid out at the current transcript width."""
from __future__ import annotations

from dataclasses import dataclass
from io import StringIO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from src.ui.render.sanitize import sanitize_text


@dataclass(frozen=True, slots=True)
class HelpSection:
    title: str
    rows: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class HelpDocument:
    summary: str
    sections: tuple[HelpSection, ...]
    footer: str

    def plain_text(self) -> str:
        """Keep an unwrapped text representation for non-widget consumers."""
        parts = [self.summary, ""]
        for section in self.sections:
            parts.append(section.title)
            parts.extend(f"  {label}  {description}" for label, description in section.rows)
            parts.append("")
        parts.append(self.footer)
        return "\n".join(parts)


def render_help(document: HelpDocument, width: int | None = None) -> str:
    # entry_view adds the two-cell transcript prefix after layout. RichLog must
    # not wrap the resulting rows a second time and lose their cell boundaries.
    available = max(1, (width if width is not None else 80) - 2)
    output = StringIO()
    console = Console(file=output, width=available, color_system=None, highlight=False)
    console.print(Text(sanitize_text(document.summary), overflow="fold"))
    console.print()
    # All sections share these widths, independent of their longest command.
    gap = 2
    command_width = min(42, max(1, (available - gap) * 2 // 5))
    for section in document.sections:
        console.print(Text(sanitize_text(section.title)))
        if available < 6:
            # Two cells would leave no readable content at extreme widths.
            for label, description in section.rows:
                console.print(Text(sanitize_text(label), overflow="fold"))
                console.print(Text(sanitize_text(description), overflow="fold"))
        else:
            table = Table.grid(padding=(0, gap), expand=True)
            table.add_column(width=command_width, overflow="fold")
            table.add_column(ratio=1, overflow="fold")
            for label, description in section.rows:
                # Text cells keep syntax brackets/pipes literal, not markup.
                table.add_row(Text(sanitize_text(label)), Text(sanitize_text(description)))
            console.print(table)
        console.print()
    console.print(Text(sanitize_text(document.footer), overflow="fold"))
    return "\n".join(line.rstrip() for line in output.getvalue().splitlines())
