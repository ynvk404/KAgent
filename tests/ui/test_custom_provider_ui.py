from __future__ import annotations

import asyncio
from typing import Any, cast
from unittest.mock import AsyncMock, Mock
import pytest

from src.ask.ask import Option, Question
from src.config.config import Backend
from src.ui.bridges.ask_bridge import AskRequest
from src.ui.commands.provider_picker import (
    ProviderPickerRequest,
    open_provider_picker,
)
from src.ui.core.app import AppProps, ConfigSnapshot, KAgent, _modal_text
from src.ui.theme import ACCENT
from src.ui.widgets.banner import BannerData
from src.ui.core.custom_provider_adapter import (
    CustomProviderProfile,
    InMemoryCustomProviderAdapter,
)
from src.ui.core.state import Append, Clear, SetAsk, TranscriptEntry
from src.ui.widgets.provider_picker_modal import (
    ADD_CUSTOM_LABEL,
    MANUAL_OAI_LABEL,
    ProviderPickerModal,
    SECTION_CUSTOM,
    SECTION_MANUAL,
    SECTION_OFFICIAL,
)
from src.ui.widgets.text_input_modal import TextInputRequest


# ==========================================================
# 1. UI Adapter Boundary Tests
# ==========================================================

def test_adapter_add_list_edit_delete_and_activate():
    adapter = InMemoryCustomProviderAdapter()
    assert adapter.list_custom_providers() == []
    assert adapter.get_current_provider_id() is None

    # Add custom provider (secret key is not stored in plaintext on profile)
    profile = adapter.add_custom_provider(
        name="Token Harbor",
        base_url="https://api.tokenharbor.test/v1",
        api_key="secret-token-123",
        default_model="llama-3.3-70b",
    )
    assert profile.name == "Token Harbor"
    assert profile.base_url == "https://api.tokenharbor.test/v1"
    assert profile.default_model == "llama-3.3-70b"
    assert profile.has_api_key is True
    # Verify no plaintext api_key attribute exposed
    assert not hasattr(profile, "api_key")

    listed = adapter.list_custom_providers()
    assert len(listed) == 1
    assert listed[0].id == profile.id

    # Activate
    adapter.activate_custom_provider(profile.id)
    assert adapter.get_current_provider_id() == profile.id
    assert adapter.is_active(profile.id) is True

    # Edit without changing key
    updated = adapter.edit_custom_provider(
        profile_id=profile.id,
        name="Token Harbor Renamed",
        base_url="https://api.tokenharbor.test/v2",
        api_key=None,  # keep existing key
        default_model="llama-3.1-8b",
    )
    assert updated is not None
    assert updated.name == "Token Harbor Renamed"
    assert updated.base_url == "https://api.tokenharbor.test/v2"
    assert updated.default_model == "llama-3.1-8b"
    assert updated.has_api_key is True

    # Delete
    deleted = adapter.delete_custom_provider(profile.id)
    assert deleted is True
    assert adapter.list_custom_providers() == []
    assert adapter.is_active(profile.id) is False


# ==========================================================
# 2. Provider Sections & Contents Tests
# ==========================================================

def test_official_section_contents():
    req = AskRequest(
        question=Question(header="provider", question="Select provider"),
        resolve=Mock(),
        reject=Mock(),
    )
    modal = ProviderPickerModal(req=req, current_backend="groq")
    assert modal.section == SECTION_OFFICIAL

    frame = "\n".join(modal.render())
    assert "[ Official ]" in frame
    assert "Custom" in frame
    assert "Manual" in frame
    assert "Groq (current)" in frame
    assert "Kimi" in frame
    assert "Gemini" in frame
    assert "Claude" in frame
    assert "OpenRouter" in frame
    assert "DeepSeek" in frame
    # General management actions preserved
    assert "Change API key" in frame
    assert "Test connection" in frame
    assert "Show current config" in frame
    assert "←→ section · ↑↓ select · Enter pick · Esc cancel" in frame


def test_custom_section_empty_state():
    adapter = InMemoryCustomProviderAdapter()
    req = AskRequest(
        question=Question(header="provider", question="Select provider"),
        resolve=Mock(),
        reject=Mock(),
    )
    modal = ProviderPickerModal(req=req, adapter=adapter, initial_section=SECTION_CUSTOM)
    assert modal.section == SECTION_CUSTOM

    frame = "\n".join(modal.render())
    assert "Official" in frame
    assert "[ Custom ]" in frame
    assert "Manual" in frame
    assert "No custom providers saved." in frame
    assert "> + Add custom provider" in frame
    # When Add is selected, do not show edit/delete actions
    assert "e edit" not in frame
    assert "d delete" not in frame
    assert "←→ section · ↑↓ select · Enter add · Esc cancel" in frame


def test_custom_section_with_profiles_and_active_label():
    adapter = InMemoryCustomProviderAdapter()
    p1 = adapter.add_custom_provider("Token Harbor", "https://token.test", api_key="k1")
    p2 = adapter.add_custom_provider("Local LM Studio", "http://localhost:1234")
    adapter.activate_custom_provider(p1.id)

    req = AskRequest(
        question=Question(header="provider", question="Select provider"),
        resolve=Mock(),
        reject=Mock(),
    )
    modal = ProviderPickerModal(req=req, adapter=adapter, initial_section=SECTION_CUSTOM)

    frame = "\n".join(modal.render())
    assert "Token Harbor (current)" in frame
    assert "Local LM Studio" in frame
    assert "+ Add custom provider" in frame
    # Since first profile is selected by default:
    assert "←→ section · ↑↓ select · Enter use · e edit · d delete · Esc cancel" in frame


def test_manual_section_contents():
    req = AskRequest(
        question=Question(header="provider", question="Select provider"),
        resolve=Mock(),
        reject=Mock(),
    )
    modal = ProviderPickerModal(req=req, current_backend="openai-compat", initial_section=SECTION_MANUAL)
    assert modal.section == SECTION_MANUAL

    frame = "\n".join(modal.render())
    assert "Official" in frame
    assert "Custom" in frame
    assert "[ Manual ]" in frame
    assert f"> {MANUAL_OAI_LABEL} (current)" in frame
    assert "←→ section · ↑↓ select · Enter pick · Esc cancel" in frame


# ==========================================================
# 3. Keyboard Navigation Tests
# ==========================================================

def test_keyboard_navigation_sections_and_state_preservation():
    adapter = InMemoryCustomProviderAdapter()
    adapter.add_custom_provider("P1", "http://p1.test")
    adapter.add_custom_provider("P2", "http://p2.test")

    req = AskRequest(
        question=Question(header="provider", question="Select provider"),
        resolve=Mock(),
        reject=Mock(),
    )
    modal = ProviderPickerModal(req=req, adapter=adapter)

    # In Official section, navigate down to index 2
    assert modal.section == SECTION_OFFICIAL
    modal.handle_key("down")
    modal.handle_key("down")
    assert modal.idx == 2

    # Switch right to Custom section
    modal.handle_key("right")
    assert modal.section == SECTION_CUSTOM
    assert modal.idx == 0  # Starts at 0 for custom

    # Move down to index 1 in Custom
    modal.handle_key("down")
    assert modal.idx == 1

    # Switch right to Manual section
    modal.handle_key("right")
    assert modal.section == SECTION_MANUAL
    assert modal.idx == 0

    # Switch left back to Custom section -> preserves selection index 1!
    modal.handle_key("left")
    assert modal.section == SECTION_CUSTOM
    assert modal.idx == 1

    # Switch left back to Official section -> preserves selection index 2!
    modal.handle_key("left")
    assert modal.section == SECTION_OFFICIAL
    assert modal.idx == 2


def test_keyboard_tab_and_up_down_wrapping():
    req = AskRequest(
        question=Question(header="provider", question="Select provider"),
        resolve=Mock(),
        reject=Mock(),
    )
    modal = ProviderPickerModal(req=req)
    total_official = len(modal._get_official_items())

    # Up wraps to last item
    modal.handle_key("up")
    assert modal.idx == total_official - 1

    # Down wraps back to 0
    modal.handle_key("down")
    assert modal.idx == 0

    # Tab advances
    modal.handle_key("tab")
    assert modal.idx == 1

    # Shift+Tab goes back
    modal.handle_key("shift+tab")
    assert modal.idx == 0


def test_keyboard_enter_activations():
    adapter = InMemoryCustomProviderAdapter()
    p = adapter.add_custom_provider("My Local", "http://localhost:5000")

    resolve_mock = Mock()
    add_mock = Mock()
    activate_mock = Mock()

    req = AskRequest(
        question=Question(header="provider", question="Select provider"),
        resolve=resolve_mock,
        reject=Mock(),
    )

    modal = ProviderPickerModal(
        req=req,
        adapter=adapter,
        on_add_provider=add_mock,
        on_activate_provider=activate_mock,
    )

    # 1. Enter on Official
    modal.handle_key("enter")
    resolve_mock.assert_called_with("Kimi")

    # 2. Enter on Custom profile
    modal.handle_key("right")
    assert modal.section == SECTION_CUSTOM
    assert modal.idx == 0
    modal.handle_key("enter")
    activate_mock.assert_called_with(p)

    # 3. Enter on + Add custom provider
    modal.handle_key("down")  # p is 0, ADD is 1
    assert modal.idx == 1
    modal.handle_key("enter")
    add_mock.assert_called_once()

    # 4. Enter on Manual
    modal.handle_key("right")
    assert modal.section == SECTION_MANUAL
    modal.handle_key("enter")
    resolve_mock.assert_called_with("OpenAI-compatible")


def test_keyboard_esc_cancels():
    reject_mock = Mock()
    req = AskRequest(
        question=Question(header="provider", question="Select provider"),
        resolve=Mock(),
        reject=reject_mock,
    )
    modal = ProviderPickerModal(req=req)
    modal.handle_key("escape")
    reject_mock.assert_called_once()


def test_keyboard_e_and_d_only_on_custom_profiles():
    adapter = InMemoryCustomProviderAdapter()
    p = adapter.add_custom_provider("Editable", "http://editable.test")

    edit_mock = Mock()
    delete_mock = Mock()

    req = AskRequest(
        question=Question(header="provider", question="Select provider"),
        resolve=Mock(),
        reject=Mock(),
    )
    modal = ProviderPickerModal(
        req=req,
        adapter=adapter,
        on_edit_provider=edit_mock,
        on_delete_provider=delete_mock,
    )

    # In Official: e and d are no-op
    modal.handle_key("e")
    modal.handle_key("d")
    edit_mock.assert_not_called()
    delete_mock.assert_not_called()
    assert modal.confirming_delete is None

    # In Custom:
    modal.handle_key("right")
    # On profile:
    modal.handle_key("e")
    edit_mock.assert_called_once_with(p)

    # On + Add custom provider: e and d are no-op
    modal.handle_key("down")  # move to + Add
    modal.handle_key("e")
    modal.handle_key("d")
    assert edit_mock.call_count == 1
    assert modal.confirming_delete is None

    # Back to profile and press d: opens delete confirmation dialog
    modal.handle_key("up")
    modal.handle_key("d")
    assert modal.confirming_delete == p
    frame = "\n".join(modal.render())
    assert 'Delete custom provider "Editable"?' in frame
    assert "> [ Delete ]   [ Cancel ]" in frame

    # Toggle to Cancel and press Enter
    modal.handle_key("right")
    modal.handle_key("enter")
    assert modal.confirming_delete is None
    delete_mock.assert_not_called()

    # Press d again, stay on Delete, and press Enter
    modal.handle_key("d")
    modal.handle_key("enter")
    delete_mock.assert_called_once_with(p)


def test_delete_blocked_when_active():
    adapter = InMemoryCustomProviderAdapter()
    p = adapter.add_custom_provider("Active Profile", "http://active.test")
    adapter.activate_custom_provider(p.id)

    blocked_mock = Mock()
    req = AskRequest(
        question=Question(header="provider", question="Select provider"),
        resolve=Mock(),
        reject=Mock(),
    )
    modal = ProviderPickerModal(
        req=req,
        adapter=adapter,
        on_active_delete_blocked=blocked_mock,
        initial_section=SECTION_CUSTOM,
    )

    modal.handle_key("d")
    blocked_mock.assert_called_once_with(p)
    assert modal.confirming_delete is None


# ==========================================================
# 4. Mouse Support Tests
# ==========================================================

def test_mouse_wheel_navigation():
    req = AskRequest(
        question=Question(header="provider", question="Select provider"),
        resolve=Mock(),
        reject=Mock(),
    )
    modal = ProviderPickerModal(req=req)
    assert modal.idx == 0

    # Wheel down moves next
    modal.handle_scroll(1)
    assert modal.idx == 1

    # Wheel up moves back
    modal.handle_scroll(-1)
    assert modal.idx == 0


def test_mouse_click_header_and_item_selection():
    adapter = InMemoryCustomProviderAdapter()
    adapter.add_custom_provider("P1", "http://p1.test")
    adapter.add_custom_provider("P2", "http://p2.test")

    resolve_mock = Mock()
    req = AskRequest(
        question=Question(header="provider", question="Select provider"),
        resolve=resolve_mock,
        reject=Mock(),
    )
    modal = ProviderPickerModal(req=req, adapter=adapter)

    # Click Custom header (x=16, y=0)
    modal.handle_click(16, 0)
    assert modal.section == SECTION_CUSTOM

    # Click item row 1 (x=5, y=3: line 0 header, line 1 blank, line 2 P1, line 3 P2)
    modal.handle_click(5, 3)
    assert modal.idx == 1
    # Left click must SELECT only, not activate
    resolve_mock.assert_not_called()

    # Click Manual header (x=26, y=0)
    modal.handle_click(26, 0)
    assert modal.section == SECTION_MANUAL

    # Click Official header (x=5, y=0)
    modal.handle_click(5, 0)
    assert modal.section == SECTION_OFFICIAL


# ==========================================================
# 5. Integration with open_provider_picker (Add, Edit, Delete Flows)
# ==========================================================

@pytest.mark.asyncio
async def test_open_provider_picker_dispatches_provider_picker_request():
    dispatched = []
    adapter = InMemoryCustomProviderAdapter()

    def dispatch(action):
        dispatched.append(action)

    def read_config() -> ConfigSnapshot:
        return {
            "backend": Backend.GROQ,
            "model": "llama-test",
            "base_url": "",
            "api_key": "k",
            "api_keys": {},
        }

    open_provider_picker(
        dispatch=dispatch,
        read_config=read_config,
        apply_provider=AsyncMock(),
        prompt_text=AsyncMock(),
        adapter=adapter,
    )

    assert len(dispatched) == 1
    assert isinstance(dispatched[0], SetAsk)
    req = dispatched[0].req
    assert isinstance(req, ProviderPickerRequest)
    assert isinstance(req, AskRequest)
    # Options length preserved for backwards-compatibility
    assert len(req.question.options) == 10


@pytest.mark.asyncio
async def test_add_custom_provider_flow():
    dispatched = []
    adapter = InMemoryCustomProviderAdapter()

    def dispatch(action):
        dispatched.append(action)

    def read_config() -> ConfigSnapshot:
        return {
            "backend": Backend.GROQ,
            "model": "llama-test",
            "base_url": "",
            "api_key": "k",
            "api_keys": {},
        }

    # Mock sequential inputs: name, base_url, api_key, model
    responses = iter(["Test Harbor", "https://api.test.harbor/v1", "secret-key", "my-model"])

    async def prompt_text(_req: TextInputRequest):
        return next(responses)

    open_provider_picker(
        dispatch=dispatch,
        read_config=read_config,
        apply_provider=AsyncMock(),
        prompt_text=prompt_text,
        adapter=adapter,
    )

    req = dispatched[0].req
    assert isinstance(req, ProviderPickerRequest)

    # Trigger Add flow callback
    req.on_add_provider()
    await asyncio.sleep(0.05)

    # Profile added to adapter
    profiles = adapter.list_custom_providers()
    assert len(profiles) == 1
    assert profiles[0].name == "Test Harbor"
    assert profiles[0].base_url == "https://api.test.harbor/v1"
    assert profiles[0].default_model == "my-model"
    assert profiles[0].has_api_key is True

    # Check transcript feedback
    appended = [a for a in dispatched if isinstance(a, Append)]
    assert any("Custom provider 'Test Harbor' added." in a.entry.text for a in appended)


@pytest.mark.asyncio
async def test_edit_custom_provider_flow():
    dispatched = []
    adapter = InMemoryCustomProviderAdapter()
    profile = adapter.add_custom_provider("Old Name", "http://old.url", api_key="old-key", default_model="old-model")

    def dispatch(action):
        dispatched.append(action)

    def read_config() -> ConfigSnapshot:
        return {
            "backend": Backend.GROQ,
            "model": "llama-test",
            "base_url": "",
            "api_key": "k",
            "api_keys": {},
        }

    # Edit: new name, keep base_url (return empty), keep key (return empty), new model
    responses = iter(["New Name", "", "", "new-model"])

    async def prompt_text(_req: TextInputRequest):
        return next(responses)

    open_provider_picker(
        dispatch=dispatch,
        read_config=read_config,
        apply_provider=AsyncMock(),
        prompt_text=prompt_text,
        adapter=adapter,
    )

    req = dispatched[0].req
    req.on_edit_provider(profile)
    await asyncio.sleep(0.05)

    updated = adapter.list_custom_providers()[0]
    assert updated.name == "New Name"
    assert updated.base_url == "http://old.url"
    assert updated.default_model == "new-model"
    assert updated.has_api_key is True  # Blank key kept existing key


def test_active_section_tab_styling():
    req = AskRequest(
        question=Question(header="provider", question="Select provider"),
        resolve=Mock(),
        reject=Mock(),
    )
    modal = ProviderPickerModal(req=req, current_backend="groq")

    # 1. Official section active by default
    assert modal.section == SECTION_OFFICIAL
    h_text = modal.render_header_text()
    assert h_text.plain == "[ Official ]   Custom   Manual"
    assert len(h_text.spans) == 1
    assert h_text.spans[0].start == 0
    assert h_text.spans[0].end == len("[ Official ]")
    assert str(h_text.spans[0].style) == f"bold {ACCENT}"

    rendered_modal = _modal_text(modal)
    official_spans = [s for s in rendered_modal.spans if str(s.style) == f"bold {ACCENT}"]
    assert len(official_spans) == 1
    assert rendered_modal.plain[official_spans[0].start:official_spans[0].end] == "[ Official ]"

    # 2. Switch to Custom section
    modal.handle_key("right")
    assert modal.section == SECTION_CUSTOM
    h_text = modal.render_header_text()
    assert h_text.plain == "Official   [ Custom ]   Manual"
    assert len(h_text.spans) == 1
    assert h_text.plain[h_text.spans[0].start:h_text.spans[0].end] == "[ Custom ]"
    assert str(h_text.spans[0].style) == f"bold {ACCENT}"

    rendered_modal = _modal_text(modal)
    custom_spans = [s for s in rendered_modal.spans if str(s.style) == f"bold {ACCENT}"]
    assert len(custom_spans) == 1
    assert rendered_modal.plain[custom_spans[0].start:custom_spans[0].end] == "[ Custom ]"

    # 3. Switch to Manual section
    modal.handle_key("right")
    assert modal.section == SECTION_MANUAL
    h_text = modal.render_header_text()
    assert h_text.plain == "Official   Custom   [ Manual ]"
    assert len(h_text.spans) == 1
    assert h_text.plain[h_text.spans[0].start:h_text.spans[0].end] == "[ Manual ]"
    assert str(h_text.spans[0].style) == f"bold {ACCENT}"

    rendered_modal = _modal_text(modal)
    manual_spans = [s for s in rendered_modal.spans if str(s.style) == f"bold {ACCENT}"]
    assert len(manual_spans) == 1
    assert rendered_modal.plain[manual_spans[0].start:manual_spans[0].end] == "[ Manual ]"


class _DummyWidget:
    def __init__(self) -> None:
        self.text = ""
        self.display = False
        self.border_title = ""
        self.classes: set[str] = set()

    def update(self, val: Any) -> None:
        self.text = val

    def set_class(self, val: bool, cls: str) -> None:
        if val:
            self.classes.add(cls)
        else:
            self.classes.discard(cls)


def _make_test_kagent() -> KAgent:
    from types import SimpleNamespace
    from src.agent.agent import Agent

    app = KAgent(
        AppProps(
            agent=cast(
                Agent,
                SimpleNamespace(skills=SimpleNamespace(list_enabled=lambda: [])),
            ),
            banner_data=BannerData(provider="test", model="test", cwd="."),
            parent_signal=asyncio.Event(),
            read_config=lambda: {
                "backend": Backend.GROQ,
                "model": "llama-test",
                "base_url": "",
                "api_key": "k",
                "api_keys": {},
            },
            apply_provider=AsyncMock(),
        )
    )
    app.overlay_static = cast(Any, _DummyWidget())
    app.overlay_content_static = cast(Any, _DummyWidget())
    app.overlay_text_static = cast(Any, _DummyWidget())
    app.input_static = cast(Any, _DummyWidget())
    app._recompute_view = lambda: app._sync_overlay()
    return app


@pytest.mark.asyncio
async def test_prompt_text_lifecycle_syncs_overlay_immediately():
    app = _make_test_kagent()
    assert app.overlay_static.display is False

    task = asyncio.create_task(
        app.prompt_text(
            TextInputRequest(
                header="custom provider",
                question="Enter provider name",
                placeholder="e.g. My Gateway",
                resolve=lambda _v: None,
                reject=lambda _e: None,
            )
        )
    )
    # The overlay must be displayed immediately without waiting for any timer or event
    await asyncio.sleep(0)
    assert app.text_input is not None
    assert app.text_input.question == "Enter provider name"
    assert app.overlay_static.display is True
    assert app.overlay_static.border_title == "Input"

    # Resolving immediately updates overlay and completes future
    app.resolve_text_input("My Provider")
    result = await task
    assert result == "My Provider"
    assert app.text_input is None
    assert app.overlay_static.display is False


@pytest.mark.asyncio
async def test_add_custom_provider_consecutive_field_transitions():
    app = _make_test_kagent()
    adapter = InMemoryCustomProviderAdapter()
    dispatched = []

    def dispatch(action: Any) -> None:
        dispatched.append(action)
        app.dispatch(action)

    open_provider_picker(
        dispatch=dispatch,
        read_config=lambda: {
            "backend": Backend.GROQ,
            "model": "llama-test",
            "base_url": "",
            "api_key": "k",
            "api_keys": {},
        },
        apply_provider=AsyncMock(),
        prompt_text=app.prompt_text,
        adapter=adapter,
    )

    req = dispatched[0].req
    assert isinstance(req, ProviderPickerRequest)

    # 1. Trigger Add flow -> Provider name appears immediately
    req.on_add_provider()
    await asyncio.sleep(0)

    assert app.text_input is not None
    assert app.text_input.question == "Enter provider name"
    assert app.overlay_static.display is True

    # 2. Enter provider name -> Base URL prompt appears immediately without delay
    app.resolve_text_input("Token Harbor")
    await asyncio.sleep(0)

    assert app.text_input is not None
    assert app.text_input.question == "Enter base URL"
    assert app.overlay_static.display is True

    # 3. Enter base URL -> API key prompt appears immediately
    app.resolve_text_input("https://api.tokenharbor.test/v1")
    await asyncio.sleep(0)

    assert app.text_input is not None
    assert app.text_input.question == "Enter API key (optional)"
    assert app.text_input.masked is True
    assert app.overlay_static.display is True

    # 4. Enter API key -> Default model prompt appears immediately
    app.resolve_text_input("sk-secret-123")
    await asyncio.sleep(0)

    assert app.text_input is not None
    assert app.text_input.question == "Enter default model (optional)"
    assert app.overlay_static.display is True

    # 5. Enter model -> Completed and provider picker restored
    app.resolve_text_input("llama-3.3-70b")
    await asyncio.sleep(0)

    profiles = adapter.list_custom_providers()
    assert len(profiles) == 1
    assert profiles[0].name == "Token Harbor"
    assert profiles[0].base_url == "https://api.tokenharbor.test/v1"
    assert profiles[0].default_model == "llama-3.3-70b"
    assert profiles[0].has_api_key is True

    # Picker re-opened on custom section
    last_set_ask = [a for a in dispatched if isinstance(a, SetAsk)][-1]
    assert isinstance(last_set_ask.req, ProviderPickerRequest)
    assert last_set_ask.req.initial_section == SECTION_CUSTOM


@pytest.mark.asyncio
async def test_add_custom_provider_cancellation_restores_picker_immediately():
    app = _make_test_kagent()
    adapter = InMemoryCustomProviderAdapter()
    dispatched = []

    def dispatch(action: Any) -> None:
        dispatched.append(action)
        app.dispatch(action)

    open_provider_picker(
        dispatch=dispatch,
        read_config=lambda: {
            "backend": Backend.GROQ,
            "model": "llama-test",
            "base_url": "",
            "api_key": "k",
            "api_keys": {},
        },
        apply_provider=AsyncMock(),
        prompt_text=app.prompt_text,
        adapter=adapter,
    )

    req = dispatched[0].req
    req.on_add_provider()
    await asyncio.sleep(0)

    assert app.text_input is not None
    assert app.text_input.question == "Enter provider name"

    # User cancels at provider name step
    app.reject_text_input(Exception("cancelled"))
    await asyncio.sleep(0)

    # Re-opened provider picker on custom section
    last_set_ask = [a for a in dispatched if isinstance(a, SetAsk)][-1]
    assert isinstance(last_set_ask.req, ProviderPickerRequest)
    assert last_set_ask.req.initial_section == SECTION_CUSTOM
    assert adapter.list_custom_providers() == []


@pytest.mark.asyncio
async def test_edit_custom_provider_consecutive_field_transitions():
    app = _make_test_kagent()
    adapter = InMemoryCustomProviderAdapter()
    profile = adapter.add_custom_provider("Old Name", "http://old.url", api_key="old-key", default_model="old-model")
    dispatched = []

    def dispatch(action: Any) -> None:
        dispatched.append(action)
        app.dispatch(action)

    open_provider_picker(
        dispatch=dispatch,
        read_config=lambda: {
            "backend": Backend.GROQ,
            "model": "llama-test",
            "base_url": "",
            "api_key": "k",
            "api_keys": {},
        },
        apply_provider=AsyncMock(),
        prompt_text=app.prompt_text,
        adapter=adapter,
    )

    req = dispatched[0].req
    req.on_edit_provider(profile)
    await asyncio.sleep(0)

    # 1. Name prompt with initial value
    assert app.text_input is not None
    assert app.text_input.question == "Edit provider name"
    assert app.text_input.initial_value == "Old Name"
    assert app.overlay_static.display is True

    # 2. Enter new name -> Base URL prompt appears immediately
    app.resolve_text_input("New Name")
    await asyncio.sleep(0)

    assert app.text_input is not None
    assert app.text_input.question == "Edit base URL"
    assert app.text_input.initial_value == "http://old.url"
    assert app.overlay_static.display is True

    # 3. Enter empty -> API key prompt appears immediately
    app.resolve_text_input("")
    await asyncio.sleep(0)

    assert app.text_input is not None
    assert app.text_input.question == "Edit API key"
    assert app.text_input.masked is True
    assert app.overlay_static.display is True

    # 4. Enter empty key -> Default model prompt appears immediately
    app.resolve_text_input("")
    await asyncio.sleep(0)

    assert app.text_input is not None
    assert app.text_input.question == "Edit default model"
    assert app.text_input.initial_value == "old-model"
    assert app.overlay_static.display is True

    # 5. Enter new model -> Profile updated and picker restored
    app.resolve_text_input("new-model")
    await asyncio.sleep(0)

    updated = adapter.list_custom_providers()[0]
    assert updated.name == "New Name"
    assert updated.base_url == "http://old.url"
    assert updated.default_model == "new-model"
    assert updated.has_api_key is True

    last_set_ask = [a for a in dispatched if isinstance(a, SetAsk)][-1]
    assert isinstance(last_set_ask.req, ProviderPickerRequest)
    assert last_set_ask.req.initial_section == SECTION_CUSTOM
