from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SlashItem:
    name: str
    description: str
    args: str | None = None

SLASH_ITEMS: tuple[SlashItem, ...] = (
    SlashItem(
        name="/help",
        description="show keybindings + slash commands",
    ),

    SlashItem(
        name="/provider",
        description="configure LLM backend, API settings, models, and connection",
    ),

    SlashItem(
        name="/model",
        args="<id|list>",
        description="switch model or list backend models",
    ),

    SlashItem(
        name="/thinking",
        args="[on|off|default]",
        description="show or set reasoning mode",
    ),

    SlashItem(
        name="/maxsteps",
        args="[<n>|default]",
        description="show or set per-turn tool-call limit",
    ),

    SlashItem(
        name="/target",
        args="[<url>|clear]",
        description="show, set, or clear engagement target",
    ),

    SlashItem(
        name="/scope",
        args="[show|add <origin>|remove <origin>|tcp-add <ip> <ports>|tcp-remove <ip> [ports]|reset]",
        description="show or edit exact HTTP origins and explicit TCP IP/ports",
    ),

    SlashItem(
        name="/permissions",
        args="[action]",
        description="view execution profile, HTTP limits and tool revocations",
    ),

    SlashItem(
        name="/yolo",
        args="[on|off|default]",
        description="toggle auto-approval within resource limits",
    ),

    SlashItem(
        name="/plan",
        args="[objective]",
        description="plan-only mode without tools",
    ),

    SlashItem(name="/report", args="[filename.pdf]",
              description="export the current assessment snapshot as PDF"),
    SlashItem(name="/turn-details", description="view latest turn diagnostics in this UI session"),

    SlashItem(
        name="/skills",
        args="[enable|disable|new <name>]",
        description="open skill picker, use, toggle, or create skills",
    ),

    SlashItem(
        name="/burp",
        args="[port|stop|status|credentials|list|use [id|cancel]|all]",
        description="manage Burp bridge and captured requests",
    ),

    SlashItem(
        name="/memory",
        args="[add <text>|list|forget <text>|clear]",
        description="manage saved and session memory",
    ),

    SlashItem(
        name="/compact",
        description="summarize conversation into persistent session memory",
    ),

    SlashItem(
        name="/clear",
        description="clear the on-screen transcript only",
    ),

    SlashItem(
        name="/reset",
        description="reset conversation and saved session, keep target and HTTP/TCP scope",
    ),

    SlashItem(
        name="/exit",
        description="quit kagent",
    ),
)

def filter_slash(
    input_text: str,
) -> list[SlashItem]:

    trimmed = input_text.strip()

    if not trimmed.startswith("/"):
        return []


    if " " in trimmed[1:]:
        return []


    needle = trimmed.lower()


    if needle == "/":
        return list(SLASH_ITEMS)


    return [
        item
        for item in SLASH_ITEMS
        if item.name.lower().startswith(needle)
    ]
