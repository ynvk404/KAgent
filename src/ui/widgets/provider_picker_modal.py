from __future__ import annotations

import asyncio
from typing import Any, Callable, Sequence
from rich.text import Text
from src.ask.ask import Option, Question
from src.ui.bridges.ask_bridge import AskRequest
from src.ui.core.custom_provider_adapter import (
    CustomProviderAdapter,
    CustomProviderProfile,
    get_custom_provider_adapter,
)
from src.ui.theme import ACCENT

SECTION_OFFICIAL = 0
SECTION_CUSTOM = 1
SECTION_MANUAL = 2

SECTION_NAMES = ("Official", "Custom", "Manual")

OFFICIAL_BACKENDS = (
    ("kimi", "Kimi"),
    ("groq", "Groq"),
    ("gemini", "Gemini"),
    ("anthropic", "Claude"),
    ("openrouter", "OpenRouter"),
    ("deepseek", "DeepSeek"),
)

MANAGEMENT_ACTIONS = (
    "Change API key",
    "Test connection",
    "Show current config",
)

ADD_CUSTOM_LABEL = "+ Add custom provider"
MANUAL_OAI_LABEL = "OpenAI-compatible — one-off configuration"


class ProviderPickerModal:
    """Three-section provider picker modal: [ Official ] [ Custom ] [ Manual ].

    Sections:
        Official: Official remote providers + provider management actions
        Custom: Saved custom provider profiles + Add custom provider
        Manual: OpenAI-compatible one-off configuration
    """

    def __init__(
        self,
        req: AskRequest,
        adapter: CustomProviderAdapter | None = None,
        current_backend: str = "",
        on_add_provider: Callable[[], Any] | None = None,
        on_edit_provider: Callable[[CustomProviderProfile], Any] | None = None,
        on_delete_provider: Callable[[CustomProviderProfile], Any] | None = None,
        on_activate_provider: Callable[[CustomProviderProfile], Any] | None = None,
        on_active_delete_blocked: Callable[[CustomProviderProfile], Any] | None = None,
        initial_section: int = SECTION_OFFICIAL,
    ) -> None:
        self.req = req
        self.adapter = adapter or getattr(req, "adapter", None) or get_custom_provider_adapter()
        self.current_backend = current_backend or getattr(req, "current_backend", "")

        self.on_add_provider = on_add_provider or getattr(req, "on_add_provider", None)
        self.on_edit_provider = on_edit_provider or getattr(req, "on_edit_provider", None)
        self.on_delete_provider = on_delete_provider or getattr(req, "on_delete_provider", None)
        self.on_activate_provider = on_activate_provider or getattr(req, "on_activate_provider", None)
        self.on_active_delete_blocked = on_active_delete_blocked or getattr(req, "on_active_delete_blocked", None)

        req_section = getattr(req, "initial_section", None)
        self.section = req_section if req_section is not None and initial_section == SECTION_OFFICIAL else initial_section
        self.selected_by_section: dict[int, int] = {
            SECTION_OFFICIAL: 0,
            SECTION_CUSTOM: 0,
            SECTION_MANUAL: 0,
        }

        # Sub-state for in-modal delete confirmation:
        # If set, modal renders delete confirmation dialog
        self.confirming_delete: CustomProviderProfile | None = None
        self.confirm_idx: int = 0  # 0: Delete, 1: Cancel
        self.error_message: str | None = None

    @property
    def idx(self) -> int:
        return self.selected_by_section.get(self.section, 0)

    @idx.setter
    def idx(self, val: int) -> None:
        count = len(self._get_section_items(self.section))
        if count > 0:
            self.selected_by_section[self.section] = max(0, min(val, count - 1))
        else:
            self.selected_by_section[self.section] = 0

    def _get_official_items(self) -> list[str]:
        items: list[str] = []
        for backend_id, label in OFFICIAL_BACKENDS:
            is_current = (
                self.current_backend == backend_id
                or self.current_backend == label.lower()
            )
            tag = "   ● active" if is_current else ""
            items.append(f"{label}{tag}")

        for act in MANAGEMENT_ACTIONS:
            items.append(act)
        return items

    def _get_custom_items(self) -> list[CustomProviderProfile | str]:
        """Returns list of CustomProviderProfile objects followed by ADD_CUSTOM_LABEL."""
        profiles = self.adapter.list_custom_providers()
        items: list[CustomProviderProfile | str] = list(profiles)
        items.append(ADD_CUSTOM_LABEL)
        return items

    def _get_manual_items(self) -> list[str]:
        is_current = self.current_backend in ("openai-compat", "openai-compatible")
        tag = " (current)" if is_current else ""
        tag = "   ● active" if is_current else ""
        return [f"{MANUAL_OAI_LABEL}{tag}"]

    def _get_section_items(self, section: int) -> list[Any]:
        if section == SECTION_OFFICIAL:
            return self._get_official_items()
        if section == SECTION_CUSTOM:
            return self._get_custom_items()
        if section == SECTION_MANUAL:
            return self._get_manual_items()
        return []

    def handle_key(self, key: str) -> Any:
        key = key.lower()

        # If confirming delete, handle delete dialog keys
        if self.confirming_delete is not None:
            return self._handle_delete_dialog_key(key)

        if key in ("escape", "esc"):
            self.req.reject(Exception("cancelled"))
            return

        if key in ("left", "arrowleft"):
            self._switch_section(-1)
            return

        if key in ("right", "arrowright"):
            self._switch_section(1)
            return

        if key != "d":
            self.error_message = None

        items = self._get_section_items(self.section)
        total = len(items)

        if key in ("up", "arrowup", "shift+tab"):
            if total > 0:
                self.idx = (self.idx - 1 + total) % total
            return

        if key in ("down", "arrowdown", "tab"):
            if total > 0:
                self.idx = (self.idx + 1) % total
            return

        if key in ("enter", "return"):
            return self._activate_current_selection()

        if key == "e":
            if self.section == SECTION_CUSTOM:
                selected_item = self._get_current_item()
                if isinstance(selected_item, CustomProviderProfile):
                    if self.on_edit_provider:
                        return self.on_edit_provider(selected_item)
            return

        if key == "d":
            if self.section == SECTION_CUSTOM:
                selected_item = self._get_current_item()
                if isinstance(selected_item, CustomProviderProfile):
                    if self.adapter.is_active(selected_item.id):
                        self.error_message = "Cannot delete active custom provider. Select another provider first."
                        if self.on_active_delete_blocked:
                            return self.on_active_delete_blocked(selected_item)
                        return
                    # Open confirmation
                    self.confirming_delete = selected_item
                    self.confirm_idx = 0
            return

    def _switch_section(self, delta: int) -> None:
        self.error_message = None
        self.section = (self.section + delta) % 3
        # Ensure index in new section is bounded
        items = self._get_section_items(self.section)
        cur = self.selected_by_section.get(self.section, 0)
        if items:
            self.selected_by_section[self.section] = max(0, min(cur, len(items) - 1))
        else:
            self.selected_by_section[self.section] = 0

    def _get_current_item(self) -> Any:
        items = self._get_section_items(self.section)
        if not items:
            return None
        safe_idx = max(0, min(self.idx, len(items) - 1))
        return items[safe_idx]

    def _activate_current_selection(self) -> Any:
        item = self._get_current_item()
        if item is None:
            return

        if self.section == SECTION_OFFICIAL:
            label = str(item)
            # Resolve to label or clean provider name
            clean_label = label.replace(" (current)", "").strip()
            self.req.resolve(clean_label)
            return

        if self.section == SECTION_CUSTOM:
            if item == ADD_CUSTOM_LABEL:
                if self.on_add_provider:
                    return self.on_add_provider()
                return
            if isinstance(item, CustomProviderProfile):
                if self.on_activate_provider:
                    return self.on_activate_provider(item)
                else:
                    self.adapter.activate_custom_provider(item.id)
                    self.req.resolve(f"custom:{item.id}")
                return

        if self.section == SECTION_MANUAL:
            label = str(item)
            if label.startswith(MANUAL_OAI_LABEL):
                self.req.resolve("OpenAI-compatible")
            else:
                clean_label = label.replace(" (current)", "").strip()
                self.req.resolve(clean_label)
            return

    def _handle_delete_dialog_key(self, key: str) -> Any:
        if key in ("escape", "esc"):
            self.confirming_delete = None
            return

        if key in ("left", "arrowleft", "right", "arrowright", "tab", "shift+tab"):
            self.confirm_idx = 1 - self.confirm_idx
            return

        if key in ("enter", "return"):
            if self.confirm_idx == 0:  # Delete confirmed
                target = self.confirming_delete
                self.confirming_delete = None
                if target is not None:
                    if self.on_delete_provider:
                        return self.on_delete_provider(target)
                    else:
                        self.adapter.delete_custom_provider(target.id)
                        # Clamp idx after deletion
                        items = self._get_section_items(self.section)
                        self.idx = max(0, min(self.idx, len(items) - 1))
            else:  # Cancel
                self.confirming_delete = None
            return

    def handle_scroll(self, delta: int) -> None:
        """Handle mouse wheel scroll: delta > 0 is down, delta < 0 is up."""
        if self.confirming_delete is not None:
            return
        items = self._get_section_items(self.section)
        total = len(items)
        if total == 0:
            return
        if delta > 0:
            self.idx = (self.idx + 1) % total
        elif delta < 0:
            self.idx = (self.idx - 1 + total) % total

    def handle_click(self, x: int, y: int) -> None:
        """Handle mouse click. Selects item only (does not activate)."""
        if self.confirming_delete is not None:
            return

        # Line 0 is section header: [ Official ]   [ Custom ]   [ Manual ]
        if y == 0:
            if x < 12:
                self.section = SECTION_OFFICIAL
            elif x < 23:
                self.section = SECTION_CUSTOM
            else:
                self.section = SECTION_MANUAL
            return

        # Body items start at y == 2 (after header and blank line)
        item_y_start = 2
        items = self._get_section_items(self.section)
        if not items:
            return

        if self.section == SECTION_CUSTOM:
            profiles = self.adapter.list_custom_providers()
            if not profiles:
                # Empty state: line 2 is "  No custom providers saved.", line 4 is "+ Add custom provider"
                if y == 4:
                    self.idx = 0
                return
            else:
                # Items are: profiles, then blank line, then + Add custom provider
                num_profiles = len(profiles)
                clicked_offset = y - item_y_start
                if 0 <= clicked_offset < num_profiles:
                    self.idx = clicked_offset
                elif clicked_offset == num_profiles + 1:  # On + Add custom provider row
                    self.idx = num_profiles
                return

        # Official or Manual sections
        clicked_idx = y - item_y_start
        if 0 <= clicked_idx < len(items):
            self.idx = clicked_idx

    def render_header_text(self) -> Text:
        header = Text()
        if self.section == SECTION_OFFICIAL:
            header.append("[ Official ]", style=f"bold {ACCENT}")
            header.append("   Custom   Manual")
        elif self.section == SECTION_CUSTOM:
            header.append("Official   ")
            header.append("[ Custom ]", style=f"bold {ACCENT}")
            header.append("   Manual")
        elif self.section == SECTION_MANUAL:
            header.append("Official   Custom   ")
            header.append("[ Manual ]", style=f"bold {ACCENT}")
        else:
            header.append("Official   Custom   Manual")
        return header

    def render(self) -> list[str]:
        if self.confirming_delete is not None:
            return self._render_delete_dialog()

        lines: list[str] = []

        # 1. Section Header Tabs
        h_official = "[ Official ]" if self.section == SECTION_OFFICIAL else "Official"
        h_custom = "[ Custom ]" if self.section == SECTION_CUSTOM else "Custom"
        h_manual = "[ Manual ]" if self.section == SECTION_MANUAL else "Manual"
        lines.append(f"{h_official}   {h_custom}   {h_manual}")
        lines.append("")

        # 2. Section Body
        if self.section == SECTION_OFFICIAL:
            items = self._get_official_items()
            for i, item in enumerate(items):
                is_selected = i == self.idx
                prefix = "> " if is_selected else "  "
                lines.append(f"{prefix}{item}")

        elif self.section == SECTION_CUSTOM:
            profiles = self.adapter.list_custom_providers()
            if not profiles:
                lines.append("  No custom providers saved.")
                lines.append("")
                is_selected = self.idx == 0
                prefix = "> " if is_selected else "  "
                lines.append(f"{prefix}{ADD_CUSTOM_LABEL}")
            else:
                for i, profile in enumerate(profiles):
                    is_selected = i == self.idx
                    prefix = "> " if is_selected else "  "
                    is_current = (
                        self.adapter.is_active(profile.id)
                        or self.adapter.get_current_provider_id() == profile.id
                        or self.current_backend == profile.name
                    )
                    tag = "   ● active" if is_current else ""
                    lines.append(f"{prefix}{profile.name}{tag}")

                lines.append("")
                add_selected = self.idx == len(profiles)
                prefix = "> " if add_selected else "  "
                lines.append(f"{prefix}{ADD_CUSTOM_LABEL}")

        elif self.section == SECTION_MANUAL:
            items = self._get_manual_items()
            for i, item in enumerate(items):
                is_selected = i == self.idx
                prefix = "> " if is_selected else "  "
                lines.append(f"{prefix}{item}")

        # 3. Footer
        if self.error_message:
            lines.append("")
            lines.append(f"error: {self.error_message}")

        lines.append("")
        if self.section == SECTION_CUSTOM:
            cur_item = self._get_current_item()
            if cur_item == ADD_CUSTOM_LABEL:
                lines.append("←→ section · ↑↓ select · Enter add · Esc cancel")
            else:
                lines.append("←→ section · ↑↓ select · Enter use · e edit · d delete · Esc cancel")
        else:
            lines.append("←→ section · ↑↓ select · Enter pick · Esc cancel")

        return lines

    def _render_delete_dialog(self) -> list[str]:
        target = self.confirming_delete
        name = target.name if target else "provider"
        if self.confirm_idx == 0:
            button_row = "> [ Delete ]   [ Cancel ]"
        else:
            button_row = "  [ Delete ]   > [ Cancel ]"

        return [
            f'Delete custom provider "{name}"?',
            "",
            "This will remove its saved configuration and API key.",
            "",
            button_row,
            "",
            "←→ select · Enter confirm · Esc cancel",
        ]
