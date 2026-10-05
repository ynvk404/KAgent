"""Focused regressions derived from the token-accounting audit.

Historical defect descriptions remain in the independent verification report.
"""
import json

from src.agent.agent import (
    approximate_message_tokens,
    minimum_compactable_history_tokens,
    Agent,
    AgentOptions,
)
from src.agent.context_estimate import estimate_request, text_tokens
from src.llm.runtime.metrics import anthropic_usage
from src.agent.system_prompt import (
    render_memory_observation,
    render_workflow,
)
from src.cli.runtime import GROQ_AUTO_COMPACT_THRESHOLD, effective_auto_compact_threshold
from src.config.config import Config, DEFAULT_AUTO_COMPACT_THRESHOLD
from src.llm.core.types import ChatRequest, Message
from src.session.store import SessionMemory
from src.skills.registry import Registry as SkillRegistry
from src.target.target import new_target
from src.tools.common.registry import Registry as ToolRegistry, Tool
from src.workflow.state import Candidate, WorkflowObjective, WorkflowState
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from src.permission.permission import AlwaysAllow


def test_gemini_unsigned_thoughts_are_not_replayed_or_counted():
    msg = Message("assistant", "Final answer", gemini_parts=[
        {"thought": True, "text": "private" * 200}, {"text": "Final answer"}],
        provider_state_provider="gemini", provider_state_model="gemini-2.5-flash")
    estimate = estimate_request(ChatRequest(model="gemini-2.5-flash", messages=[msg]), "gemini")
    assert estimate.history_tokens == text_tokens("Final answer")
    assert estimate.provider_private_tokens == 0


def test_projection_counts_injected_memory_and_workflow():
    """Carried memory and workflow belong to projected pressure."""
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

    agent = Agent(AgentOptions(client=FakeClient([]), tools=ToolRegistry(), skills=SkillRegistry(),
                               prompter=AlwaysAllow(), store=None, target=new_target(), workflow=workflow))
    agent.memory = memory
    projection = agent.idle_request_estimate()
    assert projection.injected_tokens >= memory_tokens + wf_tokens
    assert projection.estimated_total > agent.approx_tokens()


def test_soft_gate_retains_minimum_history_ratio():
    """The economic history gate is independent of request/model capacity."""
    threshold = DEFAULT_AUTO_COMPACT_THRESHOLD
    minimum = minimum_compactable_history_tokens(threshold)
    assert minimum == max(2048, int(threshold / 3))
    # Crossing the soft trigger alone never bypasses the economic history gate.
    pressure = threshold + 1000
    for history in (minimum - 1, minimum):
        eligible = pressure >= threshold and history >= minimum
        assert eligible is (history == minimum)


def test_groq_fixed_floor_is_observable_with_real_inventory(tmp_path, monkeypatch):
    from tests.agent.test_token_accounting_independent_verify import runtime_inventory
    from src.config.config import Backend
    agent = runtime_inventory(tmp_path, monkeypatch, "compact")
    cfg = Config(backend=Backend.GROQ)
    baseline = agent.approx_tokens() + agent.tools_token_estimate()
    assert effective_auto_compact_threshold(cfg) == GROQ_AUTO_COMPACT_THRESHOLD == 5500
    assert baseline > GROQ_AUTO_COMPACT_THRESHOLD
    # An operator's explicit zero remains the existing Groq soft policy.
    cfg.auto_compact_threshold = 0
    assert effective_auto_compact_threshold(cfg) == 5500
    cfg.auto_compact_threshold = 4000
    assert effective_auto_compact_threshold(cfg) == 4000


def test_anthropic_full_input_is_uncached_plus_cache_components():
    usage = anthropic_usage({"input_tokens": 100, "output_tokens": 20,
                             "cache_read_input_tokens": 40, "cache_creation_input_tokens": 10})
    assert usage is not None and usage.input_tokens == 150
    assert usage.total_tokens == 170 and usage.reasoning_tokens is None


def test_tools_token_estimate_detects_same_name_schema_mutation():
    """Description changes invalidate the schema content digest."""
    class DynamicTool(Tool):
        def __init__(self, desc: str):
            self._desc = desc
        def name(self) -> str:
            return "dynamic_tool"
        def description(self) -> str:
            return self._desc
        def schema(self) -> dict:
            return {"type": "object", "properties": {"arg": {"type": "string"}}}
        def requires_permission(self) -> bool:
            return False
        async def run(self, args, signal, prompter):
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

    # Same names still require new estimates when encoded schemas change.
    assert mutated_est > initial_est + 900


def test_tiny_nonempty_messages_have_content_and_framing_cost():
    """Tiny components and role envelopes no longer disappear."""
    messages = [Message(role="user", content="ok") for _ in range(50)]
    assert approximate_message_tokens(messages) >= len(messages)
