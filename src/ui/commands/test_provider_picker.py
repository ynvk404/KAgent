from typing import Any, cast

from src.ui.commands.provider_picker import open_provider_picker
from src.ui.core.state import SetAsk
from src.ui.core.app import ConfigSnapshot
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
        }

    async def apply_provider(payload):
        return None

    async def prompt_secret(_req):
        return None

    open_provider_picker(
        dispatch,
        read_config,
        apply_provider,
        prompt_secret,
    )

    assert len(dispatched) == 1
    assert isinstance(dispatched[0], SetAsk)
    assert dispatched[0].req is not None

    req = cast(dict[str, Any], dispatched[0].req)

    assert req["question"]["header"] == "provider"