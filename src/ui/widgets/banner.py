# ui/widgets/banner.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


# ==========================================================
# Logo
# ==========================================================

LOGO = [
    "██████╗  █████╗",
    "██╔══██╗██╔══██╗",
    "██████╔╝███████║",
    "██╔═══╝ ██╔══██║",
    "██║     ██║  ██║",
    "╚═╝     ╚═╝  ╚═╝",
]


ToolSupportPill = Literal[
    "yes",
    "no",
    "unknown",
    "probing",
]


# ==========================================================
# Data
# ==========================================================

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



# ==========================================================
# Pill
# ==========================================================

def model_pill(
    tool_support: ToolSupportPill | None,
) -> Pill | None:

    match tool_support:

        case "yes":
            return Pill(
                text="tools ✓",
                color="green",
            )

        case "no":
            return Pill(
                text="NO TOOLS",
                color="red",
            )

        case "probing":
            return Pill(
                text="probing…",
                color="yellow",
            )

        case "unknown":
            return Pill(
                text="tools ?",
                color="gray",
            )

        case _:
            return None



# ==========================================================
# Render line
# ==========================================================

@dataclass(frozen=True, slots=True)
class BannerLine:
    text: str
    color: str = "white"



# ==========================================================
# Banner
# ==========================================================

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


    def render(self) -> list[BannerLine]:

        data = self.data


        pill = model_pill(
            data.tool_support
        )


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
                "Welcome to pentestagent",
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
                color = "magenta"

            else:

                text = (
                    f"{label}: {value}"
                )


                if pill and label == "Model":
                    text += (
                        f" [{pill.text}]"
                    )

                color = "white"


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
