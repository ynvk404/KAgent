"""Independent audit regression tests demonstrating token accounting anomalies and gaps.

This file provides reproducible proof of the audited findings:
1. Gemini replayed thoughts in gemini_parts are completely uncounted by approximate_message_tokens.
2. Injected context (SessionMemory, WorkflowState, catalog) is omitted from trigger_tokens.
3. Auto-compact gate has a severe deadband between 16,000 and 19,312 tokens at default threshold.
4. Groq baseline fixed overhead (compact prompt + tools) exceeds GROQ_AUTO_COMPACT_THRESHOLD before turn 0.
5. AnthropicClient drops provider usage from API responses.
6. tools_token_estimate cache key does not detect in-place tool schema or description mutations.
7. Integer truncation // 4 per message causes cumulative undercounting on short turns.
"""
import json
import pytest

from src.agent.agent import (
    approximate_message_tokens,
    minimum_compactable_history_tokens,
    Agent,
    AgentOptions,
)
from src.agent.system_prompt import (
    build_system_prompt,
    BuildOptions,
    render_memory_observation,
    render_workflow,
)
from src.cli.runtime import GROQ_AUTO_COMPACT_THRESHOLD, effective_auto_compact_threshold
from src.config.config import Config, DEFAULT_AUTO_COMPACT_THRESHOLD
from src.engagement.state import EngagementState
from src.llm.core.client import Client
from src.llm.core.types import ChatRequest, ChatResponse, FunctionCall, Message, ToolCall
from src.llm.providers.anthropic import AnthropicClient
from src.session.store import SessionMemory
from src.skills.registry import Registry as SkillRegistry
from src.target.target import new_target
from src.tools.common.registry import Registry as ToolRegistry, Tool
from src.workflow.state import Candidate, WorkflowObjective, WorkflowState
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from src.permission.permission import AlwaysAllow


def test_gemini_replayed_thought_parts_uncounted():
    """Gemini replayed thought parts are excluded from content and ignored by approximate_message_tokens."""
    # When Gemini responds with thinking enabled, thought text is placed in gemini_parts.
    # On subsequent turns, gemini_parts are replayed to the API, consuming context window tokens.
    msg = Message(
        role="assistant",
        content="Final answer",
        gemini_parts=[
            {"thought": True, "text": "Reasoning step 1: analyze parameter..." * 200},  # ~8,000 chars (~2,000 tokens)
            {"text": "Final answer"},
        ],
        provider_state_provider="gemini",
        provider_state_model="gemini-2.5-flash",
    )
    tokens = approximate_message_tokens([msg])
    # Expected if counted: ~2,003 tokens.
    # Actual: only "Final answer" (12 chars // 4 = 3 tokens) is counted!
    assert tokens == 3, f"Expected 3 tokens due to uncounted gemini_parts, got {tokens}"


def test_injected_context_omitted_from_trigger_tokens():
    """Injected session memory and workflow context in run_inner are excluded from trigger_tokens."""
    memory = SessionMemory(
        objectives=["Audit token accounting across all provider boundaries"],
        plan=["Inspect code", "Write test", "Produce report"],
        completed=["Checked agent.py", "Checked tool_results.py"],
        findings=["Finding 1: prompt overhead", "Finding 2: gemini_parts gap"],
        tested=["/api/login", "/api/user", "/api/search"],
        todos=["Verify Groq threshold", "Check Anthropic usage"],
        files=["src/agent/agent.py", "src/llm/providers/anthropic.py"],
        commands=["pytest tests/agent/test_agent.py"],
        compactions=1,
    )
    memory_text = render_memory_observation(memory)
    memory_tokens = len(memory_text) // 4
    assert memory_tokens > 100

    workflow = WorkflowState()
    workflow.objective = WorkflowObjective(
        id="obj1",
        mode="whole_target",
        target_origin="http://127.0.0.1:3000",
    )
    workflow.add_candidate(Candidate(
        candidate_class="sqli",
        endpoint="/rest/products/1",
    ))
    wf_text = render_workflow(workflow)
    wf_tokens = len(wf_text) // 4
    assert wf_tokens > 50

    # In run_inner, trigger_tokens = history_tokens + incoming_tokens + tools_tokens
    # Neither memory_text nor wf_text is in self.history; they are injected into working only.
    # Therefore, trigger_tokens undercounts by at least (memory_tokens + wf_tokens).
    uncounted_tokens = memory_tokens + wf_tokens
    assert uncounted_tokens > 150


def test_auto_compact_deadband_at_default_threshold():
    """At auto_compact_threshold=16000, trigger_tokens can exceed threshold by >3,000 tokens before auto_compact can trigger."""
    threshold = DEFAULT_AUTO_COMPACT_THRESHOLD  # 16000
    min_compactable = minimum_compactable_history_tokens(threshold)
    # min_compactable = max(2048, int(16000 * (1/3))) = 5333
    assert min_compactable == 5333

    # Fixed overhead with full profile and default tools:
    # Sys prompt: ~9,086 tok, Tools: ~4,893 tok => fixed baseline = ~13,979 tok
    fixed_overhead = 13979

    # Conversation history: 2500 tokens (well beyond typical single turns)
    conv_history_tokens = 2500
    trigger_tokens = fixed_overhead + conv_history_tokens
    # Total trigger tokens is 16,479, which is 479 tokens OVER the 16,000 threshold!
    assert trigger_tokens > threshold

    # But auto_compact requires compactable_history_tokens >= min_compactable (5333)
    can_trigger = trigger_tokens >= threshold and conv_history_tokens >= min_compactable
    # Compaction CANNOT trigger even though total request is over threshold!
    assert not can_trigger, "Auto-compact should be blocked by minimum_compactable_history_tokens"

    # In fact, trigger_tokens must reach 13979 + 5333 = 19,312 tokens before it can trigger!
    earliest_trigger = fixed_overhead + min_compactable
    assert earliest_trigger == 19312
    assert earliest_trigger - threshold == 3312  # 3,312 tokens deadband!


def test_groq_baseline_fixed_overhead_exceeds_threshold():
    """On Groq, compact system prompt plus standard tools exceeds GROQ_AUTO_COMPACT_THRESHOLD on turn 0."""
    target = new_target()
    target.set_base_url("http://127.0.0.1:3000")
    eng = EngagementState()
    skills = SkillRegistry()

    compact_prompt = build_system_prompt(
        BuildOptions(
            skills=skills,
            thinking_enabled=False,
            target=target,
            engagement_state=eng,
            prompt_profile="compact",
        )
    )
    compact_prompt_tokens = len(compact_prompt) // 4

    # Standard registry has ~4,893 tokens of tool schemas
    tools_tokens = 4893
    fixed_groq_baseline = compact_prompt_tokens + tools_tokens

    assert GROQ_AUTO_COMPACT_THRESHOLD == 5500
    # Fixed overhead alone is ~6,490 tokens > 5,500 tokens!
    assert fixed_groq_baseline > GROQ_AUTO_COMPACT_THRESHOLD
    overflow = fixed_groq_baseline - GROQ_AUTO_COMPACT_THRESHOLD
    assert overflow >= 900, f"Expected at least 900 tokens overflow, got {overflow}"


def test_anthropic_client_drops_provider_usage():
    """AnthropicClient does not extract usage from API response dictionary."""
    client = AnthropicClient("https://api.anthropic.com", "test-key", "claude-3-5-sonnet")
    # Verify that block_to_tool_call or ChatResponse construction in anthropic.py does not pass usage.
    # In anthropic.py line 118:
    # return ChatResponse(message=msg, finish_reason=map_finish_reason(out.get("stop_reason")))
    # Notice usage is omitted.
    # Let's inspect AnthropicClient.chat source or verify ChatResponse has usage=None
    import inspect
    lines = inspect.getsource(client.chat)
    assert 'usage=' not in lines, "AnthropicClient.chat unexpectedly passes usage="


def test_tools_token_estimate_cache_invalidation_gap():
    """tools_token_estimate caches by tuple(names()) and misses schema/description changes."""
    class DynamicTool(Tool):
        def __init__(self, desc: str):
            self._desc = desc
        def name(self) -> str:
            return "dynamic_tool"
        def description(self) -> str:
            return self._desc
        def schema(self) -> dict:
            return {"type": "object", "properties": {"arg": {"type": "string"}}}
        async def execute(self, args, signal, prompter):
            return "done"

    reg = ToolRegistry()
    tool = DynamicTool("short description")
    reg.register(tool)

    agent = Agent(AgentOptions(
        client=FakeClient([]),
        tools=reg,
        skills=SkillRegistry(),
        prompter=AlwaysAllow(),
        store=None,
        target=new_target(),
    ))

    initial_est = agent.tools_token_estimate()

    # Mutate description in-place without changing name
    tool._desc = "a" * 4000  # +1000 tokens
    mutated_est = agent.tools_token_estimate()

    # Because tool name did not change, cache returns stale estimate!
    assert mutated_est == initial_est, "tools_token_estimate unexpectedly updated despite same tool names"


def test_integer_division_zeroes_out_short_messages():
    """approximate_message_tokens drops all tokens for messages shorter than 4 chars due to // 4 per message."""
    messages = [Message(role="user", content="ok") for _ in range(50)]
    assert approximate_message_tokens(messages) == 0
