from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from src.config.config import ToolingProfile


# ==========================================================
# Profile Option
# ==========================================================

@dataclass(slots=True)
class ProfileOption:
    value: ToolingProfile
    label: str
    description: str
    helper: str


# ==========================================================
# Options
# ==========================================================
OPTIONS: list[ProfileOption] = [
    ProfileOption(
        value=ToolingProfile.MINIMAL,
        label="curl + Unix tools only  (recommended)",
        description=(
            "curl + jq, grep, awk, sed, head, sort, uniq"
        ),
        helper=(
            "The agent stays inside reproducible one-liners. "
            "Every probe drops straight into a bug-bounty report. "
            "It won't reach for ffuf / nuclei / sqlmap on its own."
        ),
    ),

    ProfileOption(
        value=ToolingProfile.FULL,
        label="curl + Unix + specialized scanners",
        description=(
            "adds ffuf, nuclei, sqlmap, gobuster, "
            "subfinder, httpx, wfuzz, masscan"
        ),
        helper=(
            "The agent may pick a specialized scanner when "
            "it judges the workload (large fuzz, CVE template sweep). "
            "You still approve each run via the permission modal — "
            "scanners are only invoked when locally installed."
        ),
    ),
]


# ==========================================================
# Request
# ==========================================================

@dataclass(slots=True)
class FirstRunPickerRequest:
    on_pick: Callable[[ToolingProfile], None]
    on_cancel: Callable[[], None]
    exit_app: Callable[[], None]


# ==========================================================
# First Run Picker
# ==========================================================

class FirstRunPicker:
    """
    One-time first-launch picker.

    Select tooling profile for agent.

    Keys:
        ↑ / up       previous option
        ↓ / down     next option
        Enter        choose
        Esc          cancel
        Ctrl+C       cancel
    """

    def __init__(
        self,
        req: FirstRunPickerRequest,
    ):
        self.req = req
        self.idx = 0


    # ======================================================
    # Input
    # ======================================================

    def handle_key(
        self,
        key: str,
    ) -> None:

        # Cancel
        if key in (
            "escape",
            "esc",
            "ctrl+c",
        ):
            self.req.on_cancel()
            self.req.exit_app()
            return


        # Previous
        if key in (
            "up",
            "arrowup",
        ):
            self.idx = (
                self.idx - 1
            ) % len(OPTIONS)

            return


        # Next
        if key in (
            "down",
            "arrowdown",
        ):
            self.idx = (
                self.idx + 1
            ) % len(OPTIONS)

            return


        # Select
        if key in (
            "enter",
            "return",
        ):
            selected = OPTIONS[self.idx]

            self.req.on_pick(
                selected.value
            )

            return


    # ======================================================
    # Render
    # ======================================================

    def render(self) -> list[str]:

        lines: list[str] = []


        lines.append(
            "pentestagent first-run setup"
        )

        lines.append("")


        lines.append(
            "Which tooling should the agent reach for?"
        )

        lines.append("")


        for index, option in enumerate(OPTIONS):

            selected = (
                index == self.idx
            )


            prefix = (
                "› "
                if selected
                else "  "
            )


            lines.append(
                prefix
                + option.label
            )


            lines.append(
                "    "
                + option.description
            )


            lines.append(
                "    "
                + option.helper
            )


            lines.append("")


        lines.append(
            "↑↓ select · Enter pick · "
            "Esc cancel · changeable later via config"
        )


        return lines