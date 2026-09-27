from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from src.config.config import ToolingProfile


@dataclass(slots=True)
class ProfileOption:
    value: ToolingProfile
    label: str
    description: str
    helper: str

OPTIONS: list[ProfileOption] = [
    ProfileOption(
        value=ToolingProfile.MINIMAL,
        label="curl + native discovery  (recommended)",
        description=(
            "built-in HTTP, native path discovery and TCP checks"
        ),
        helper=(
            "The agent uses built-in and native semantic discovery. Optional "
            "scanners are not selected automatically in this profile; generic "
            "shell scanner use requires an explicit user request."
        ),
    ),

    ProfileOption(
        value=ToolingProfile.FULL,
        label="curl + optional ffuf / nmap",
        description=(
            "allows bounded ffuf path discovery and nmap TCP checks when installed"
        ),
        helper=(
            "The agent may select these semantic backends only for a concrete "
            "coverage gap. Each action stays target-scoped, bounded, and subject "
            "to the permission prompt. Other scanners are not enabled automatically."
        ),
    ),
]


@dataclass(slots=True)
class FirstRunPickerRequest:
    on_pick: Callable[[ToolingProfile], None]
    on_cancel: Callable[[], None]
    exit_app: Callable[[], None]

class FirstRunPicker:

    def __init__(
        self,
        req: FirstRunPickerRequest,
    ):
        self.req = req
        self.idx = 0

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
            "shift+tab",
        ):
            self.idx = (
                self.idx - 1
            ) % len(OPTIONS)

            return


        # Next
        if key in (
            "down",
            "arrowdown",
            "tab",
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

    def render(self) -> list[str]:

        lines: list[str] = []


        lines.append(
            "kagent first-run setup"
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
            "↑↓/Tab select · Enter pick · "
            "Esc cancel · changeable later via config"
        )


        return lines
