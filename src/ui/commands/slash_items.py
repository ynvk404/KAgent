from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True, slots=True)
class SlashItem:
    """
    Một slash command.

    Ví dụ:
        /help
        /model <id|list>
    """

    name: str
    description: str
    args: str | None = None


# ==========================================================
# Slash command catalog
# ==========================================================

SLASH_ITEMS: tuple[SlashItem, ...] = (

    SlashItem(
        name="/help",
        description="show keybindings + slash commands",
    ),

    SlashItem(
        name="/provider",
        description="interactive picker: select LLM backend, then a model from its catalog",
    ),

    SlashItem(
        name="/model",
        args="<id|list>",
        description="switch model or list backend models",
    ),

    SlashItem(
        name="/plan",
        args="[objective]",
        description="plan-only mode without tools",
    ),

    SlashItem(
        name="/next",
        args="[objective]",
        description="coverage-driven next test suggestions",
    ),

    SlashItem(
        name="/compact",
        description="summarize conversation into persistent session memory",
    ),

    SlashItem(
        name="/memory",
        args="[add <text>|list|forget <text>|clear]",
        description="saved + session memory; add/list curated facts",
    ),

    SlashItem(
        name="/snapshot",
        description="write the current redacted context snapshot now",
    ),

    SlashItem(
        name="/burp",
        args="[port]",
        description="start the local Burp/pentestagent listener",
    ),

    SlashItem(
        name="/clear",
        description="clear the on-screen transcript only",
    ),

    SlashItem(
        name="/reset",
        description="clear conversation + saved session",
    ),

    SlashItem(
        name="/target",
        args="<url>",
        description="pin an engagement base URL",
    ),

    SlashItem(
        name="/skills",
        args="[enable|disable|new <name>]",
        description="list/toggle skills",
    ),

    SlashItem(
        name="/maxsteps",
        args="<n>",
        description="per-turn tool-call cap",
    ),

    SlashItem(
        name="/thinking",
        args="on|off",
        description="toggle show-thinking directive",
    ),

    SlashItem(
        name="/update",
        args="[version]",
        description="fetch GitHub release updates and install",
    ),

    SlashItem(
        name="/yolo",
        args="[on|off]",
        description="toggle auto-approve for every tool call",
    ),

    SlashItem(
        name="/exit",
        description="quit pentestagent",
    ),
)


# ==========================================================
# Filter
# ==========================================================

def filter_slash(
    input_text: str,
    extras: Sequence[SlashItem] = (),
) -> list[SlashItem]:
    """
    Lọc command theo input.

    Ví dụ:

        "/he"
            -> [/help]

        "/mo"
            -> [/model]

        "/"
            -> toàn bộ command
    """

    trimmed = input_text.strip()

    if not trimmed.startswith("/"):
        return []


    # user bắt đầu nhập argument:
    #
    # /model qwen
    #
    # không hiện menu nữa

    if " " in trimmed[1:]:
        return []


    all_items = (
        list(SLASH_ITEMS) + list(extras)
        if extras
        else list(SLASH_ITEMS)
    )


    needle = trimmed.lower()


    if needle == "/":
        return all_items


    return [
        item
        for item in all_items
        if item.name.lower().startswith(needle)
    ]