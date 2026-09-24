import json

import pytest

from src.agent.agent import format_history_for_compaction, reconcile_tool_calls
from src.llm.gemini import encode_request as gemini_encode, safe_replay_part
from src.llm.openai import OpenAIClient
from src.llm.types import ChatRequest, FunctionCall, Message, ToolCall, ToolProvider, GeminiProvider
from src.session.store import Store


def test_deepseek_replay_requires_matching_provider_and_model():
    client = OpenAIClient("https://api.deepseek.com", "", "deepseek-flash", "deepseek")
    assistant = Message(
        role="assistant", content="visible", reasoning_content="SECRET_INTERNAL_REASONING_MARKER",
        provider_state_provider="deepseek", provider_state_model="deepseek-flash",
    )
    request = ChatRequest(model="deepseek-flash", messages=[assistant])
    assert client.encode_request(request, False)["messages"][0]["reasoning_content"] == assistant.reasoning_content
    assistant.provider_state_provider = "openai-compat"
    assert "reasoning_content" not in client.encode_request(request, False)["messages"][0]
    assistant.provider_state_provider = "deepseek"
    assistant.provider_state_model = "deepseek-v4-pro"
    assert "reasoning_content" not in client.encode_request(request, False)["messages"][0]
    assistant.provider_state_model = None
    assert "reasoning_content" not in client.encode_request(request, False)["messages"][0]
    assistant.provider_state_model = "deepseek-flash"
    assistant.provider_state_provider = None
    assert "reasoning_content" not in client.encode_request(request, False)["messages"][0]
    assert "SECRET_INTERNAL_REASONING_MARKER" not in format_history_for_compaction([assistant])


@pytest.mark.asyncio
async def test_deepseek_sequential_tool_reasoning_survives_session_round_trip(tmp_path):
    history = [Message(role="user", content="inspect")]
    for index in (1, 2):
        history.extend([
            Message(
                role="assistant", content=f"step {index}",
                reasoning_content=f"private-step-{index}",
                tool_calls=[ToolCall(f"call-{index}", FunctionCall("lookup", "{}"))],
                provider_state_provider="deepseek", provider_state_model="deepseek-flash",
            ),
            Message(role="tool", content=f"result {index}",
                    tool_call_id=f"call-{index}", name="lookup"),
        ])
    store = Store.new_with_id(tmp_path, "deepseek")
    await store.save(history)
    loaded = store.load().messages
    client = OpenAIClient("https://api.deepseek.com", "", "deepseek-flash", "deepseek")
    body = client.encode_request(ChatRequest(model="deepseek-flash", messages=loaded), False)
    assert [message.get("reasoning_content") for message in body["messages"]] == [
        None, "private-step-1", None, "private-step-2", None
    ]
    assert [message["role"] for message in body["messages"]] == [
        "user", "assistant", "tool", "assistant", "tool"
    ]


@pytest.mark.asyncio
async def test_kimi_k26_tool_reasoning_replays_only_on_matching_enabled_model(tmp_path):
    assistant = Message(
        role="assistant", content="", reasoning_content="PRIVATE_KIMI_STATE",
        tool_calls=[ToolCall("call-1", FunctionCall("lookup", "{}"))],
        provider_state_provider="kimi", provider_state_model="kimi-k2.6",
    )
    store = Store.new_with_id(tmp_path, "kimi")
    await store.save([assistant, Message(role="tool", content="found",
                                         tool_call_id="call-1", name="lookup")])
    loaded = store.load().messages
    client = OpenAIClient("https://api.moonshot.ai/v1", "", "kimi-k2.6", "kimi")
    request = ChatRequest(model="kimi-k2.6", messages=loaded, thinking_enabled=True)
    body = client.encode_request(request, False)
    assert body["messages"][0]["reasoning_content"] == "PRIVATE_KIMI_STATE"
    assert "PRIVATE_KIMI_STATE" not in format_history_for_compaction(loaded)
    request.thinking_enabled = False
    assert "reasoning_content" not in client.encode_request(request, False)["messages"][0]
    request.thinking_enabled = True
    loaded[0].provider_state_model = "kimi-k2.7-code"
    assert "reasoning_content" not in client.encode_request(request, False)["messages"][0]
    loaded[0].provider_state_model = "kimi-k2.6"
    loaded[0].provider_state_provider = "deepseek"
    assert "reasoning_content" not in client.encode_request(request, False)["messages"][0]


def test_kimi_k27_preserved_thinking_replays_even_without_generic_off_control():
    assistant = Message(
        role="assistant", content="visible", reasoning_content="PRIVATE_KIMI_STATE",
        provider_state_provider="kimi", provider_state_model="kimi-k2.7-code",
    )
    client = OpenAIClient("https://api.moonshot.ai/v1", "", "kimi-k2.7-code", "kimi")
    request = ChatRequest(model="kimi-k2.7-code", messages=[assistant], thinking_enabled=False)
    body = client.encode_request(request, False)
    assert "thinking" not in body
    assert body["messages"][0]["reasoning_content"] == "PRIVATE_KIMI_STATE"


@pytest.mark.asyncio
async def test_incomplete_saved_tool_step_is_marked_cancelled_on_resume(tmp_path):
    history = [Message(
        role="assistant", content="", reasoning_content="private-step",
        tool_calls=[ToolCall("call-1", FunctionCall("lookup", "{}"))],
        provider_state_provider="deepseek", provider_state_model="deepseek-flash",
    )]
    store = Store.new_with_id(tmp_path, "interrupted")
    await store.save(history)
    resumed = reconcile_tool_calls(store.load().messages)
    assert [message.role for message in resumed] == ["assistant", "tool"]
    assert resumed[1].tool_status == "cancelled"
    assert resumed[1].tool_call_id == "call-1"


@pytest.mark.asyncio
async def test_gemini_parts_keep_order_and_signature_through_session(tmp_path):
    parts = [
        {"text": "visible", "thoughtSignature": "sig-text"},
        {"text": "SECRET_INTERNAL_REASONING_MARKER", "thought": True},
        {"functionCall": {"name": "first", "args": {"x": 1}}, "thoughtSignature": "sig-first"},
        {"functionCall": {"name": "second", "args": {"x": 2}}},
    ]
    assistant = Message(
        role="assistant", content="visible",
        tool_calls=[
            ToolCall("one", FunctionCall("first", '{"x": 1}')),
            ToolCall("two", FunctionCall("second", '{"x": 2}')),
        ],
        provider_state_provider="gemini", provider_state_model="gemini-3-flash-preview",
        gemini_parts=[part for raw in parts if (part := safe_replay_part(raw))],
    )
    store = Store.new_with_id(tmp_path, "reasoning")
    await store.save([assistant])
    assert "SECRET_INTERNAL_REASONING_MARKER" not in store.path.read_text()
    restored = store.load().messages[0]
    encoded = gemini_encode(ChatRequest(model="gemini-3-flash-preview", messages=[restored]))
    assert encoded["contents"][0]["parts"] == [
        {"text": "visible", "thoughtSignature": "sig-text"},
        {"functionCall": {"name": "first", "args": {"x": 1}}, "thoughtSignature": "sig-first"},
        {"functionCall": {"name": "second", "args": {"x": 2}}},
    ]
    assert "thoughtSignature" not in json.dumps(
        gemini_encode(ChatRequest(model="gemini-3-pro-preview", messages=[restored]))
    )
    restored.provider_state_model = None
    assert "thoughtSignature" not in json.dumps(
        gemini_encode(ChatRequest(model="gemini-3-flash-preview", messages=[restored]))
    )
    restored.provider_state_model = "gemini-3-flash-preview"
    restored.provider_state_provider = None
    assert "thoughtSignature" not in json.dumps(
        gemini_encode(ChatRequest(model="gemini-3-flash-preview", messages=[restored]))
    )
    assert "SECRET_INTERNAL_REASONING_MARKER" not in format_history_for_compaction([restored])


def test_gemini_parallel_tool_results_share_one_function_response_step():
    request = ChatRequest(model="gemini-3-flash-preview", messages=[
        Message(role="user", content="look up both"),
        Message(role="assistant", content="", tool_calls=[
            ToolCall("one", FunctionCall("first", "{}")),
            ToolCall("two", FunctionCall("second", "{}")),
        ], provider_state_provider="gemini", provider_state_model="gemini-3-flash-preview",
            gemini_parts=[
                {"functionCall": {"name": "first", "args": {}}, "thoughtSignature": "sig"},
                {"functionCall": {"name": "second", "args": {}}},
            ]),
        Message(role="tool", content="a", name="first", tool_call_id="one"),
        Message(role="tool", content="b", name="second", tool_call_id="two"),
    ])
    contents = gemini_encode(request)["contents"]
    assert len(contents) == 3
    assert [part["functionResponse"]["name"] for part in contents[-1]["parts"]] == [
        "first", "second"
    ]


def test_gemini_legacy_tool_signature_requires_exact_provenance():
    assistant = Message(
        role="assistant", content="", tool_calls=[ToolCall(
            "one", FunctionCall("first", "{}"),
            provider=ToolProvider(gemini=GeminiProvider(thought_signature="sig")),
        )],
    )
    request = ChatRequest(model="gemini-3-flash-preview", messages=[assistant])
    def encoded():
        return gemini_encode(request)["contents"][0]["parts"][0]
    assert "thoughtSignature" not in encoded()
    assistant.provider_state_provider = "gemini"
    assert "thoughtSignature" not in encoded()
    assistant.provider_state_model = "gemini-3-pro-preview"
    assert "thoughtSignature" not in encoded()
    assistant.provider_state_model = "gemini-3-flash-preview"
    assert encoded()["thoughtSignature"] == "sig"


def test_gemini_sequential_signatures_remain_on_their_original_steps():
    messages = [Message(role="user", content="two steps")]
    for index in (1, 2):
        messages.extend([
            Message(
                role="assistant", content="",
                tool_calls=[ToolCall(f"call-{index}", FunctionCall("lookup", "{}"))],
                provider_state_provider="gemini", provider_state_model="gemini-3-flash-preview",
                gemini_parts=[{
                    "functionCall": {"name": "lookup", "args": {}},
                    "thoughtSignature": f"signature-{index}",
                }],
            ),
            Message(role="tool", content=f"result-{index}",
                    name="lookup", tool_call_id=f"call-{index}"),
        ])
    contents = gemini_encode(ChatRequest(model="gemini-3-flash-preview", messages=messages))["contents"]
    assert [contents[index]["parts"][0]["thoughtSignature"] for index in (1, 3)] == [
        "signature-1", "signature-2"
    ]
    assert [contents[index]["parts"][0]["functionResponse"]["response"]["result"]
            for index in (2, 4)] == ["result-1", "result-2"]


@pytest.mark.asyncio
async def test_signed_gemini_thought_part_is_private_session_state(tmp_path):
    marker = "SECRET_INTERNAL_REASONING_MARKER"
    signed_part = {"text": marker, "thought": True, "thoughtSignature": "opaque-sig"}
    assistant = Message(
        role="assistant", content="visible",
        provider_state_provider="gemini", provider_state_model="gemini-3-flash-preview",
        gemini_parts=[signed_part, {"text": "visible"}],
    )
    store = Store.new_with_id(tmp_path, "signed")
    await store.save([assistant])
    restored = store.load().messages[0]
    assert restored.gemini_parts == [signed_part, {"text": "visible"}]
    encoded = gemini_encode(ChatRequest(model="gemini-3-flash-preview", messages=[restored]))
    assert encoded["contents"][0]["parts"][0] == signed_part
    assert marker not in format_history_for_compaction([restored])
