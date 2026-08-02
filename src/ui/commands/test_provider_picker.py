from src.ask.ask import Question
from src.ui.bridges.ask_bridge import AskRequest
from src.ui.commands.provider_picker import open_provider_picker
from src.ui.core.app import ConfigSnapshot
from src.ui.core.state import SetAsk
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

    req = dispatched[0].req

    assert isinstance(req, AskRequest)
    assert isinstance(req.question, Question)

    assert req.question.header == "provider"
    assert req.question.question == "Which LLM backend should pentestagent use?"

    # Ollama + LM Studio đã được loại khỏi provider picker
    assert len(req.question.options) == 7

    labels = [
        option.label
        for option in req.question.options
    ]

    assert labels[0].startswith("Kimi")
    assert labels[1].startswith("Groq")
    assert labels[2].startswith("Gemini")
    assert labels[3].startswith("Claude")
    assert labels[4].startswith("OpenRouter")
    assert labels[5].startswith("DeepSeek")
    assert labels[6].startswith("OpenAI-compatible")

    assert "Ollama" not in labels
    assert "LM Studio" not in labels

    assert callable(req.resolve)
    assert callable(req.reject)