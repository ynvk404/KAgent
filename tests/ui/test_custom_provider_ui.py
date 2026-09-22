from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, Mock
import pytest

from src.ask.ask import Option, Question
from src.config.config import Backend
from src.ui.bridges.ask_bridge import AskRequest
from src.ui.commands.provider_picker import (
    ProviderPickerRequest,
    open_provider_picker,
)
from src.ui.core.app import ConfigSnapshot
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

