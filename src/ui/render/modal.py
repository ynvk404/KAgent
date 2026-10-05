"""Rich formatting for UI modal renderables."""

from rich.console import RenderableType
from rich.text import Text

from src.ui.theme import ACCENT, BOLD_ERROR, MUTED, PRIMARY, SUCCESS
from src.ui.widgets.ask_modal import AskModal
from src.ui.widgets.input_box import DEFAULT_PROMPT
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
) -> RenderableType:
    input_style_fn = input_style or _input_style
    if isinstance(modal, PermissionModal):
        return modal.render()

    text = Text()
    for i, line in enumerate(modal.render()):
        if i > 0:
            text.append("\n")
        if isinstance(modal, TextInputModal) and line.startswith(DEFAULT_PROMPT):
            text.append(DEFAULT_PROMPT, style=input_style_fn("prompt"))
            value = line[len(DEFAULT_PROMPT):]
            if "▌" in value:
                before, after = value.split("▌", 1)
                if before:
                    text.append(before, style=input_style_fn("text"))
                text.append("▌", style=input_style_fn("cursor"))
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
                prefix_part, _, _ = line.partition("● active")
                text.append(prefix_part, style=f"bold {accent_style}")
                text.append("● active", style=f"bold {success_style}")
            else:
                text.append(line, style=f"bold {accent_style}")
        elif isinstance(modal, ProviderPickerModal) and "● active" in line:
            prefix_part, _, _ = line.partition("● active")
            text.append(prefix_part)
            text.append("● active", style=f"bold {success_style}")
        elif isinstance(modal, AskModal) and line.startswith("› "):
            if " — " in line:
                head, desc = line.split(" — ", 1)
                text.append(head, style=f"bold {accent_style}")
                text.append(" — ")
                if "● active" in desc:
                    d_head, _, _ = desc.partition("● active")
                    if d_head:
                        text.append(d_head)
                    text.append("● active", style=f"bold {success_style}")
                else:
                    text.append(desc)
            else:
                text.append(line, style=f"bold {accent_style}")
        elif isinstance(modal, AskModal) and "● active" in line:
            head, _, _ = line.partition("● active")
            text.append(head)
            text.append("● active", style=f"bold {success_style}")
        elif isinstance(modal, SkillsModal) and line.startswith("› "):
            if " — " in line:
                head, desc = line.split(" — ", 1)
                text.append(head, style=f"bold {accent_style}")
                text.append(" — " + desc)
            else:
                text.append(line, style=f"bold {accent_style}")
        elif line.strip().startswith("↑ ") or line.strip().startswith("↓ "):
            text.append(line, style=muted_style)
        elif line.startswith("error: "):
            text.append(line, style=error_style)
        else:
            text.append(line)
    return text
