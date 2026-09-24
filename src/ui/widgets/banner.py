
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from rich import box
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.ui.theme import ACCENT, ERROR, MUTED, SUCCESS, WARNING, PRIMARY


LOGO = [
    "██╗  ██╗ █████╗",
    "██║ ██╔╝██╔══██╗",
    "█████╔╝ ███████║",
    "██╔═██╗ ██╔══██║",
    "██║  ██╗██║  ██║",
    "╚═╝  ╚═╝╚═╝  ╚═╝",
]


ToolSupportPill = Literal[
    "yes",
    "no",
    "unknown",
    "probing",
]


@dataclass(frozen=True, slots=True)
class BannerData:
    provider: str
    model: str
    cwd: str

    endpoint: str | None = None
    state: str | None = None
    status: str | None = None

    tool_support: ToolSupportPill | None = None

    context_window: int | None = None


@dataclass(frozen=True, slots=True)
class Pill:
    text: str
    color: str

def model_pill(
    tool_support: ToolSupportPill | None,
) -> Pill | None:

    match tool_support:

        case "yes":
            return Pill(
                text="tools ✓",
                color=SUCCESS,
            )

        case "no":
            return Pill(
                text="NO TOOLS",
                color=ERROR,
            )

        case "probing":
            return Pill(
                text="probing…",
                color=WARNING,
            )

        case "unknown":
            return Pill(
                text="tools ?",
                color=MUTED,
            )

        case _:
            return None


@dataclass(frozen=True, slots=True)
class BannerLine:
    text: str
    color: str = PRIMARY

class Banner:

    def __init__(
        self,
        data: BannerData,
        width: int = 80,
    ):
        self.data = data
        self.width = max(
            20,
            width,
        )

    def _detail_lines(self) -> list[Text]:
        """Build the welcome metadata used by the framed TUI header."""
        data = self.data
        context = f" · ctx {data.context_window}" if data.context_window else ""
        provider = (
            f"{data.provider} ({data.state})" if data.state else data.provider
        )
        fields = [
            ("Provider", provider),
            ("Model", f"{data.model}{context}"),
        ]
        if data.endpoint:
            fields.append(("Endpoint", data.endpoint))
        fields.append(("Path", data.cwd))
        if data.status:
            fields.append(("Status", data.status))

        lines = [Text("Welcome to KAgent", style=f"bold {ACCENT}")]
        for label, value in fields:
            line = Text(f"{label}: ", style=MUTED)
            line.append(value, style=PRIMARY)
            lines.append(line)
        return lines

    def render_panel(self) -> RenderableType:
        """Render the welcome block as one compact, responsive Rich panel."""
        details = Group(*self._detail_lines())
        logo = Text("\n".join(LOGO), style=ACCENT, no_wrap=True)

        if self.width >= 52:
            content = Table.grid(padding=(0, 2), expand=True)
            content.add_column(width=max(len(row) for row in LOGO), no_wrap=True)
            content.add_column(ratio=1)
            content.add_row(logo, details)
        else:
            content = Group(logo, Text(""), details)

        return Panel(
            content,
            title=Text(" Overview ", style=ACCENT),
            title_align="left",
            border_style=MUTED,
            box=box.ROUNDED,
            padding=(0, 1),
            expand=True,
        )


    def render(self) -> list[BannerLine]:

        data = self.data


        ctx = (
            f" · ctx {data.context_window}"
            if data.context_window
            else ""
        )


        model_value = (
            f"{data.model}{ctx}"
        )


        labels: list[tuple[str, str, bool]] = []


        labels.append(
            (
                "Welcome to KAgent",
                "",
                True,
            )
        )


        provider = (
            f"{data.provider} ({data.state})"
            if data.state
            else data.provider
        )


        labels.append(
            (
                "Provider",
                provider,
                False,
            )
        )


        labels.append(
            (
                "Model",
                model_value,
                False,
            )
        )


        if data.endpoint:
            labels.append(
                (
                    "Endpoint",
                    data.endpoint,
                    False,
                )
            )


        labels.append(
            (
                "Path",
                data.cwd,
                False,
            )
        )


        if data.status:
            labels.append(
                (
                    "Status",
                    data.status,
                    False,
                )
            )


        pad_top = max(
            0,
            (len(labels) - len(LOGO)) // 2,
        )


        pad_bottom = max(
            0,
            len(labels)
            - len(LOGO)
            - pad_top,
        )


        logo_rows = (
            [""] * pad_top
            + LOGO
            + [""] * pad_bottom
        )


        output: list[BannerLine] = []


        logo_width = max(
            len(row)
            for row in LOGO
        )


        for i, row in enumerate(labels):

            label, value, accent = row

            logo = (
                logo_rows[i]
                if i < len(logo_rows)
                else ""
            )


            if accent:
                text = label
                color = ACCENT

            else:

                text = (
                    f"{label}: {value}"
                )


                color = PRIMARY


            prefix = (
                f"{logo:<{logo_width}}  "
                if logo
                else f"{'':<{logo_width}}  "
            )


            output.append(
                BannerLine(
                    text=f"{prefix}{text}",
                    color=color,
                )
            )


        return output
