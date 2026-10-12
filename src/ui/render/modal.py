"""Rich formatting for UI modal renderables."""

from rich.console import RenderableType
from rich.text import Text
from rich.style import Style

from src.ui.theme import ACCENT, BOLD_ERROR, MUTED, PRIMARY, SUCCESS
from src.ui.widgets.ask_modal import AskModal
from src.ui.widgets.input_box import DEFAULT_PROMPT
from src.ui.widgets.cursor_static import CARET_STYLE
from src.ui.widgets.permission_modal import PermissionModal
from src.ui.widgets.provider_picker_modal import ProviderPickerModal
from src.ui.widgets.skills_modal import SkillsModal
from src.ui.widgets.text_input_modal import TextInputModal


_INPUT_STYLE_MAP: dict[str, str] = {
    "gray": MUTED,
    "prompt": f"bold {ACCENT}",
    "text": PRIMARY,
    "cursor": f"bold {PRIMARY}",
    "cursor_char": "reverse",
}


def _input_style(
    name: str | None,
    *,
    style_map: dict[str, str] | None = None,
) -> str:
    active_style_map = _INPUT_STYLE_MAP if style_map is None else style_map
    return active_style_map.get(name or "text", name or "")


def _modal_text(
    modal,
    *,
    input_style=None,
    accent_style: str = ACCENT,
    success_style: str = SUCCESS,
    muted_style: str = MUTED,
    error_style: str = BOLD_ERROR,
    escape_action: str = "cancel",
    compact: bool = False,
) -> RenderableType:
    input_style_fn = input_style or _input_style
    if isinstance(modal, PermissionModal):
        return modal.render()

    text = Text()
    lines = modal.render()
    for i, line in enumerate(lines):
        if compact and i == 0 and isinstance(modal, TextInputModal):
            continue
        if compact and i == 0 and isinstance(modal, AskModal) and modal.req.presentation == "loading" and modal.req.question.header:
            continue
        if i == len(lines) - 1 and isinstance(modal, (AskModal, TextInputModal)):
            line = line.replace("Esc cancel", f"Esc {escape_action}")
        if len(text):
            text.append("\n")
        line_start = len(text)
        if isinstance(modal, TextInputModal) and i == len(lines) - 3:
            text.append(DEFAULT_PROMPT, style=input_style_fn("prompt"))
            value = line[len(DEFAULT_PROMPT):]
            if "▌" in value:
                cursor = modal.cursor if modal.value else len(modal.req.placeholder or "")
                before, after = value[:cursor], value[cursor + 1:]
                if before:
                    text.append(before, style=input_style_fn("text"))
                start = len(text)
                text.append("▌", style=input_style_fn("cursor"))
                text.stylize(CARET_STYLE, start, len(text))
                text.stylize(Style(meta={"modal_cursor": True}), start, len(text))
                if after:
                    text.append(after, style=input_style_fn("text"))
            else:
                text.append(value, style=input_style_fn("text"))
        elif isinstance(modal, ProviderPickerModal) and i == 0 and modal.confirming_delete is None:
            text.append_text(modal.render_header_text())
        elif isinstance(modal, ProviderPickerModal) and modal.confirming_delete is not None and ("> [ Delete ]" in line or "> [ Cancel ]" in line):
            if "> [ Delete ]" in line:
                text.append("> [ Delete ]", style=f"bold {accent_style}")
                text.append("   [ Cancel ]")
            else:
                text.append("  [ Delete ]   ")
                text.append("> [ Cancel ]", style=f"bold {accent_style}")
        elif isinstance(modal, ProviderPickerModal) and line.startswith("> "):
            if "● active" in line:
                prefix_part, _, tail = line.partition("● active")
                text.append(prefix_part, style=f"bold {accent_style}")
                text.append("● active", style=f"bold {success_style}")
                text.append(tail)
            else:
                text.append(line, style=f"bold {accent_style}")
        elif isinstance(modal, ProviderPickerModal) and "● active" in line:
            prefix_part, _, tail = line.partition("● active")
            text.append(prefix_part)
            text.append("● active", style=f"bold {success_style}")
            text.append(tail)
        elif isinstance(modal, AskModal) and line.startswith("› "):
            if " — " in line:
                head, desc = line.split(" — ", 1)
                text.append(head, style=f"bold {accent_style}")
                text.append(" — ")
                if "● active" in desc:
                    d_head, _, tail = desc.partition("● active")
                    if d_head:
                        text.append(d_head)
                    text.append("● active", style=f"bold {success_style}")
                    text.append(tail)
                else:
                    text.append(desc)
            else:
                text.append(line, style=f"bold {accent_style}")
        elif isinstance(modal, AskModal) and "● active" in line:
            head, _, tail = line.partition("● active")
            text.append(head)
            text.append("● active", style=f"bold {success_style}")
            text.append(tail)
        elif isinstance(modal, SkillsModal) and line.startswith("› "):
            if " — " in line:
                head, desc = line.split(" — ", 1)
                text.append(head, style=f"bold {accent_style}")
                text.append(" — " + desc)
            else:
                text.append(line, style=f"bold {accent_style}")
        elif i == len(lines) - 1 or line.strip().startswith("↑ ") or line.strip().startswith("↓ "):
            text.append(line, style=muted_style)
        elif line.startswith("error: "):
            text.append(line, style=error_style)
        else:
            text.append(line)
        item = getattr(modal, "item_lines", {}).get(i)
        if item is not None:
            text.stylize(Style(meta={"modal_item": item}), line_start, len(text))
        if isinstance(modal, ProviderPickerModal) and i == 0 and modal.confirming_delete is None:
            for section, name in enumerate(("Official", "Custom", "Manual")):
                start = text.plain.find(name, line_start)
                text.stylize(Style(meta={"modal_section": section}), start, start + len(name))
        if i == len(lines) - 1:
            text.stylize(Style(meta={"modal_hint": True}), line_start, len(text))
    return text
