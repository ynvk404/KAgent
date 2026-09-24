"""Request-level reasoning policy without live provider calls."""

import pytest

from src.llm.gemini import GeminiClient, encode_request as encode_gemini
from src.llm.anthropic import AnthropicClient, encode_request as encode_anthropic
from src.llm.openai import OpenAIClient
from src.llm.reasoning import (
    ReasoningCapabilities,
    ReasoningLevel as Level,
    ReasoningPurpose as Purpose,
    requested_level,
    resolve_level,
)
from src.llm.types import ChatRequest, Message, ToolFunction, ToolSpec


def _request(level: Level, *, tools: bool = False) -> ChatRequest:
    return ChatRequest(
        model="ignored",
        messages=[Message(role="user", content="hello")],
        tools=[ToolSpec(ToolFunction("echo", "echo", {"type": "object"}))] if tools else None,
        thinking_enabled=level is not Level.OFF,
        reasoning_level=level,
    )


def test_purpose_policy_and_request_compatibility():
    assert requested_level(Purpose.COMPACTION, True) is Level.OFF
    assert requested_level(Purpose.AGENT_TURN, True) is Level.LOW
    assert requested_level(Purpose.FINAL_SYNTHESIS, True) is Level.LOW
    assert requested_level(Purpose.AGENT_TURN, False) is Level.OFF
    assert ChatRequest("model", [], thinking_enabled=True).reasoning_level is None
    assert ChatRequest("model", [], thinking_enabled=False).reasoning_level is None
    with pytest.raises(ValueError, match="conflicts"):
        ChatRequest("model", [], thinking_enabled=False, reasoning_level=Level.LOW)
    with pytest.raises(ValueError, match="conflicts"):
        ChatRequest("model", [], thinking_enabled=True, reasoning_level=Level.OFF)


def test_capability_resolution_is_explicit():
    caps = ReasoningCapabilities(
        frozenset({Level.OFF, Level.LOW, Level.HIGH}),
        aliases={Level.MEDIUM: Level.HIGH},
    )
    assert resolve_level(Level.LOW, caps).relation == "exact"
    medium = resolve_level(Level.MEDIUM, caps)
    assert (medium.effective, medium.relation) == (Level.HIGH, "alias")
    no_off = ReasoningCapabilities(
        frozenset({Level.LOW, Level.MEDIUM, Level.HIGH}),
        fallbacks={Level.OFF: Level.LOW},
    )
    assert resolve_level(Level.OFF, no_off).relation == "fallback"
    assert resolve_level(Level.OFF, no_off).effective is Level.LOW
    assert resolve_level(Level.HIGH, None).relation == "legacy"
    assert resolve_level(Level.HIGH, None).effective is None


@pytest.mark.parametrize("model", ["deepseek-flash", "deepseek-v4-pro"])
def test_deepseek_levels_and_tool_state(model):
    client = OpenAIClient("https://api.deepseek.com", "", model, "deepseek")
    assert resolve_level(Level.MEDIUM, client.reasoning_capabilities()).effective is Level.HIGH
    for level, thinking, effort in [
        (Level.OFF, "disabled", None),
        (Level.LOW, "enabled", "low"),
        (Level.MEDIUM, "enabled", "high"),
        (Level.HIGH, "enabled", "high"),
    ]:
        req = _request(level, tools=True)
        req.messages.insert(
            0, Message(role="assistant", content="calling echo", reasoning_content="private state",
                       provider_state_provider="deepseek", provider_state_model=model)
        )
        body = client.encode_request(req, stream=False)
        assert body["thinking"] == {"type": thinking}
        assert body.get("reasoning_effort") == effort
        assert body["messages"][0]["reasoning_content"] == "private state"


@pytest.mark.parametrize("model", ["models/gemini-3.8-flash", "models/gemini-3.5-flash-lite"])
def test_gemini_levels_and_off_fallback(model):
    client = GeminiClient("https://generativelanguage.googleapis.com/v1beta", "", model)
    caps = client.reasoning_capabilities()
    assert resolve_level(Level.OFF, caps).effective is Level.LOW
    for level, expected in [
        (Level.OFF, "low"),
        (Level.LOW, "low"),
        (Level.MEDIUM, "medium"),
        (Level.HIGH, "high"),
    ]:
        req = _request(level)
        req.model = model
        body = encode_gemini(req, {"thinkingBudget": 256})
        assert body["generationConfig"]["thinkingConfig"] == {
            "thinkingLevel": expected,
            "includeThoughts": True,
        }


def test_unknown_and_custom_provider_keep_legacy_shape():
    generic = OpenAIClient("https://gateway.example/v1", "", "deepseek-flash", "openai-compat")
    body = generic.encode_request(_request(Level.LOW), stream=False)
    assert "thinking" not in body and "reasoning_effort" not in body
    unknown = OpenAIClient("https://api.deepseek.com", "", "future-model", "deepseek")
    body = unknown.encode_request(_request(Level.LOW), stream=False)
    assert body["thinking"] == {"type": "enabled"}
    assert "reasoning_effort" not in body


@pytest.mark.parametrize("model", ["openai/gpt-oss-20b", "openai/gpt-oss-120b"])
def test_groq_gpt_oss_has_low_but_no_verified_off(model):
    client = OpenAIClient("https://api.groq.com/openai/v1", "", model, "groq")
    caps = client.reasoning_capabilities()
    assert resolve_level(Level.OFF, caps).effective is None
    assert resolve_level(Level.LOW, caps).effective is Level.LOW
    off = client.encode_request(_request(Level.OFF, tools=True), False)
    low = client.encode_request(_request(Level.LOW, tools=True), True)
    assert off["reasoning_format"] == low["reasoning_format"] == "hidden"
    assert "reasoning_effort" not in off
    assert low["reasoning_effort"] == "low"


def test_groq_unverified_listed_model_has_no_fabricated_reasoning_control():
    client = OpenAIClient("https://api.groq.com/openai/v1", "", "qwen/qwen3.6-27b", "groq")
    assert client.reasoning_capabilities() is None
    body = client.encode_request(_request(Level.LOW), False)
    assert "reasoning_effort" not in body
    assert "reasoning_format" not in body


def test_kimi_k26_off_is_exact_and_on_is_binary_unknown():
    client = OpenAIClient("https://api.moonshot.ai/v1", "", "kimi-k2.6", "kimi")
    caps = client.reasoning_capabilities()
    assert resolve_level(Level.OFF, caps).effective is Level.OFF
    assert resolve_level(Level.LOW, caps).effective is None
    assert client.encode_request(_request(Level.OFF), False)["thinking"] == {"type": "disabled"}
    on = client.encode_request(_request(Level.LOW, tools=True), False)
    assert on["thinking"] == {"type": "enabled"}
    assert "reasoning_effort" not in on
    direct = ChatRequest("kimi-k2.6", [Message(role="user", content="hi")],
                         reasoning_level=Level.LOW)
    assert client.encode_request(direct, False)["thinking"] == {"type": "enabled"}


@pytest.mark.parametrize("model", ["kimi-k2.7-code", "kimi-k2.5", "moonshot-v1-32k"])
def test_other_kimi_models_have_unknown_generic_reasoning(model):
    client = OpenAIClient("https://api.moonshot.ai/v1", "", model, "kimi")
    assert client.reasoning_capabilities() is None
    body = client.encode_request(_request(Level.LOW), False)
    assert "reasoning_effort" not in body
    if model == "kimi-k2.7-code":
        assert "thinking" not in body


@pytest.mark.parametrize("provider", ["openrouter", "openai-compat"])
def test_gateway_and_manual_do_not_infer_capability_from_model_name(provider):
    client = OpenAIClient("https://example.test/v1", "", "openai/gpt-oss-120b", provider)
    assert client.reasoning_capabilities() is None
    body = client.encode_request(_request(Level.LOW), False)
    assert "reasoning_effort" not in body
    assert "reasoning_format" not in body


@pytest.mark.parametrize("model", ["claude-sonnet-4-6", "claude-opus-4-8", "claude-haiku-4-5"])
def test_anthropic_defers_generic_reasoning_until_continuation_is_supported(model):
    client = AnthropicClient("https://api.anthropic.com/v1", "", model)
    assert client.reasoning_capabilities() is None
    for level in (Level.OFF, Level.LOW):
        req = _request(level, tools=True)
        body = encode_anthropic(req, model)
        assert "thinking" not in body
        assert "output_config" not in body
        assert resolve_level(level, client.reasoning_capabilities()).effective is None


def test_openai_chat_completions_tool_fallback_preserves_existing_behavior():
    for model in ("gpt-6-luna", "gpt-6-sol", "gpt-5.6-terra"):
        client = OpenAIClient(
            "https://api.openai.com/v1", "", model, "openai",
            gen_opts={"temperature": 0.2},
        )
        resolution = resolve_level(Level.LOW, client.reasoning_capabilities(has_tools=True))
        assert (resolution.effective, resolution.relation) == (Level.OFF, "fallback")
        assert client.encode_request(_request(Level.LOW, tools=True), False)["reasoning_effort"] == "none"
        low_body = client.encode_request(_request(Level.LOW), False)
        assert low_body["reasoning_effort"] == "low"
        assert "temperature" not in low_body
        legacy = ChatRequest(model, [Message(role="user", content="hello")])
        assert client.encode_request(legacy, False)["reasoning_effort"] == "none"
