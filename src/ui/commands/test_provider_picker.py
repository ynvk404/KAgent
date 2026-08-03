import asyncio

import pytest

from src.ask.ask import Question
from src.ui.bridges.ask_bridge import AskRequest
from src.ui.commands.provider_picker import mask_api_key, open_provider_picker
from src.ui.core.app import ConfigSnapshot
from src.ui.core.state import Append, SetAsk
from src.config.config import Backend


def test_open_provider_picker_dispatches_state_actions():
    dispatched = []

    def dispatch(action):
        dispatched.append(action)

    def read_config() -> ConfigSnapshot:
        return {
            "backend": Backend.OPENAI_COMPAT,
            "model": "test-model",
            "base_url": "",
            "api_key": "",
            "api_keys": {},
        }

    async def apply_provider(payload):
        return None

    async def prompt_text(_req):
        return None

    open_provider_picker(
        dispatch,
        read_config,
        apply_provider,
        prompt_text,
    )

    assert len(dispatched) == 1
    assert isinstance(dispatched[0], SetAsk)
    assert dispatched[0].req is not None

    req = dispatched[0].req

    assert isinstance(req, AskRequest)
    assert isinstance(req.question, Question)

    assert req.question.header == "provider"
    assert req.question.question == "Select LLM provider or manage provider settings"

    # 3 advanced actions + 7 provider choices.
    assert len(req.question.options) == 10

    labels = [
        option.label
        for option in req.question.options
    ]

    assert labels[0] == "Change API key"
    assert labels[1] == "Test connection"
    assert labels[2] == "Show current config"
    assert labels[3].startswith("Kimi")
    assert labels[4].startswith("Groq")
    assert labels[5].startswith("Gemini")
    assert labels[6].startswith("Claude")
    assert labels[7].startswith("OpenRouter")
    assert labels[8].startswith("DeepSeek")
    assert labels[9].startswith("OpenAI-compatible")

    assert "Ollama" not in labels
    assert "LM Studio" not in labels

    assert callable(req.resolve)
    assert callable(req.reject)


@pytest.mark.asyncio
async def test_provider_picker_reuses_saved_provider_key(monkeypatch):
    dispatched = []
    seen = {}

    def dispatch(action):
        dispatched.append(action)

    def read_config() -> ConfigSnapshot:
        return {
            "backend": Backend.KIMI,
            "model": "kimi-model",
            "base_url": "",
            "api_key": "kimi-key",
            "api_keys": {
                "kimi": "kimi-key",
                "groq": "groq-key",
            },
        }

    async def apply_provider(payload):
        seen["payload"] = payload

    async def prompt_text(_req):
        seen["prompted"] = True
        return "new-key"

    async def fake_fetch_and_pick_model(
        backend,
        base_url,
        api_key,
        dispatch,
        apply_provider,
        *_args,
        **_kwargs,
    ):
        seen["backend"] = backend
        seen["base_url"] = base_url
        seen["api_key"] = api_key

    import src.ui.commands.model_picker as model_picker

    monkeypatch.setattr(
        model_picker,
        "fetch_and_pick_model",
        fake_fetch_and_pick_model,
    )

    open_provider_picker(
        dispatch,
        read_config,
        apply_provider,
        prompt_text,
    )

    req = dispatched[0].req
    req.resolve("Groq")
    await asyncio.sleep(0)

    assert seen.get("prompted") is None
    assert seen["backend"] == "groq"
    assert seen["api_key"] == "groq-key"


@pytest.mark.asyncio
async def test_provider_picker_change_api_key_preserves_other_keys():
    dispatched = []
    api_keys = {
        "groq": "old",
        "gemini": "abc",
    }

    def dispatch(action):
        dispatched.append(action)

    def read_config() -> ConfigSnapshot:
        return {
            "backend": Backend.GEMINI,
            "model": "gemini-model",
            "base_url": "",
            "api_key": api_keys["gemini"],
            "api_keys": dict(api_keys),
        }

    async def apply_provider(_payload):
        raise AssertionError("provider should not change")

    async def prompt_text(_req):
        return "new"

    async def update_provider_api_key(provider, api_key):
        api_keys[provider] = api_key

    open_provider_picker(
        dispatch,
        read_config,
        apply_provider,
        prompt_text,
        update_provider_api_key,
    )

    dispatched[0].req.resolve("Change API key")
    await asyncio.sleep(0)

    key_req = dispatched[-1].req
    key_req.resolve("Groq")
    await asyncio.sleep(0)

    assert api_keys == {
        "groq": "new",
        "gemini": "abc",
    }


@pytest.mark.asyncio
async def test_provider_picker_show_current_config_masks_keys():
    dispatched = []

    def dispatch(action):
        dispatched.append(action)

    def read_config() -> ConfigSnapshot:
        return {
            "backend": Backend.GROQ,
            "model": "llama-test",
            "base_url": "https://api.groq.test",
            "api_key": "gsk_123456WGdyL",
            "api_keys": {
                "groq": "gsk_123456WGdyL",
                "gemini": "AQ.A123456H8xyQ",
            },
        }

    async def apply_provider(_payload):
        return None

    async def prompt_text(_req):
        return None

    open_provider_picker(
        dispatch,
        read_config,
        apply_provider,
        prompt_text,
    )

    dispatched[0].req.resolve("Show current config")
    await asyncio.sleep(0)

    appended = [
        action
        for action in dispatched
        if isinstance(action, Append)
    ]

    assert appended
    text = appended[-1].entry.text

    assert "Backend:" in text
    assert "Model:" in text
    assert "Base URL:" in text
    assert "gsk_****WGdyL" in text
    assert "AQ.A****H8xyQ" in text
    assert "gsk_123456WGdyL" not in text
    assert "AQ.A123456H8xyQ" not in text


@pytest.mark.asyncio
async def test_provider_picker_test_connection_success():
    dispatched = []
    seen = {}

    def dispatch(action):
        dispatched.append(action)

    def read_config() -> ConfigSnapshot:
        return {
            "backend": Backend.GROQ,
            "model": "llama-test",
            "base_url": "",
            "api_key": "groq-key",
            "api_keys": {"groq": "groq-key"},
        }

    async def apply_provider(_payload):
        return None

    async def prompt_text(_req):
        return None

    async def test_connection():
        seen["called"] = True

    open_provider_picker(
        dispatch,
        read_config,
        apply_provider,
        prompt_text,
        test_connection=test_connection,
    )

    dispatched[0].req.resolve("Test connection")
    await asyncio.sleep(0)

    appended = [
        action
        for action in dispatched
        if isinstance(action, Append)
    ]

    assert seen["called"] is True
    assert "✓ Connection OK" in appended[-1].entry.text
    assert "Provider: groq" in appended[-1].entry.text
    assert "Model: llama-test" in appended[-1].entry.text


@pytest.mark.asyncio
async def test_provider_picker_test_connection_failure():
    dispatched = []

    def dispatch(action):
        dispatched.append(action)

    def read_config() -> ConfigSnapshot:
        return {
            "backend": Backend.GROQ,
            "model": "llama-test",
            "base_url": "",
            "api_key": "groq-key",
            "api_keys": {"groq": "groq-key"},
        }

    async def apply_provider(_payload):
        return None

    async def prompt_text(_req):
        return None

    async def test_connection():
        raise RuntimeError("boom")

    open_provider_picker(
        dispatch,
        read_config,
        apply_provider,
        prompt_text,
        test_connection=test_connection,
    )

    dispatched[0].req.resolve("Test connection")
    await asyncio.sleep(0)

    appended = [
        action
        for action in dispatched
        if isinstance(action, Append)
    ]

    assert "✗ Connection failed" in appended[-1].entry.text
    assert "boom" in appended[-1].entry.text


def test_mask_api_key():
    assert mask_api_key("gsk_123456WGdyL") == "gsk_****WGdyL"
    assert mask_api_key("short") == "*****"
