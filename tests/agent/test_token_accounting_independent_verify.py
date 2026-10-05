"""Behavioral regressions for the independently verified accounting defects.

Historical baseline evidence is preserved in the independent verification doc.
All provider responses here are local fixtures; no inference or target traffic.
"""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
from typing import Any, cast

import pytest

from src.agent.agent import (
    Agent, AgentOptions, AgentRunOptions, approximate_message_tokens,
    minimum_compactable_history_tokens, IneffectiveCompactionError,
)
from src.agent.system_prompt import PromptProfile
from src.agent.context_estimate import estimate_request, text_tokens
from src.cli import runtime
from src.config.config import PluginConfig
from src.llm.core.reasoning import ReasoningLevel
from src.llm.core.types import ChatRequest, ChatResponse, Message
from src.llm.providers import anthropic, gemini
from src.permission.permission import AlwaysAllow
from src.session.store import SessionMemory, Store
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.common.permission_status import PermissionStatusTool
from src.tools.common.registry import Registry
from src.tools.execution.plugin import CommandPluginTool
from src.workflow.state import WorkflowState
from tests.helpers.agent_fakes import FakeClient, FakeSignal


class SnapshotClient(FakeClient):
    async def chat(self, request, signal=None):
        response = await super().chat(request, signal)
        self.requests[-1] = deepcopy(request)
        return response


def make_agent(*, tools=None, skills=None, target=None, workflow=None,
               client=None, store=None, profile: PromptProfile = "compact"):
    return Agent(AgentOptions(
        client=client or SnapshotClient([ChatResponse(Message("assistant", "done"), "stop")]),
        tools=tools or Registry(), skills=skills or SkillRegistry(),
        target=target or Target(), workflow=workflow, store=store,
        prompter=AlwaysAllow(), streaming_enabled=False, prompt_profile=profile,
    ))


def runtime_inventory(tmp_path, monkeypatch, profile):
    """Mirror runtime.py:723-804 built-ins, without runtime startup/network.

    Uses actual schemas, loaded repository skills, active target, browser tools,
    permission status, and the session-bound Phase B reader. Operator-added
    skills, plugins, and MCP are deliberately not assumed.
    """
    monkeypatch.setattr("src.agent.tool_results.project_root", lambda: tmp_path)
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    target = Target()
    target.set_base_url("http://127.0.0.1:3000")
    workflow = WorkflowState()
    engagement = runtime.EngagementState()
    captures = runtime.CaptureStore(max_entries=10)
    capabilities = runtime.CapabilityInventory(which=lambda _: None)
    coverage = runtime.CoverageStore(str(tmp_path / "coverage.json"))
    registry = Registry()
    constructors = [
        runtime.ShellTool(), runtime.BashTool(), runtime.FileReadTool(),
        runtime.FileReadToolAlias(), runtime.FileWriteTool(), runtime.FileWriteToolAlias(),
        runtime.FileEditTool(), runtime.FileEditToolAlias(), runtime.GlobTool(), runtime.GrepTool(),
        runtime.HTTPTool(target, engagement, workflow, captures, validation_registry=skills),
        runtime.ContentDiscoveryTool(target, engagement, capabilities, lambda: "minimal", workflow),
        runtime.ServiceDiscoveryTool(target, engagement, capabilities, lambda: "minimal", workflow),
        runtime.WebFetchTool(engagement, target), runtime.WebSearchTool(), runtime.AskUserTool(cast(Any, None)),
        PermissionStatusTool(),
        runtime.ConfirmFindingTool(runtime.FindingsStore(str(tmp_path / "findings")), workflow=workflow),
        runtime.LoadSkillTool(skills), runtime.ReadPayloadsTool(skills), runtime.ReadSkillFileTool(skills),
        runtime.CoverageTool(coverage),
        runtime.WorkflowTool(workflow, target, coverage, skills, evidence_root=tmp_path, session_id="verify"),
    ]
    for tool in constructors:
        registry.register(tool)
    runtime.register_browser_capture_tools(registry.register, captures)
    return make_agent(tools=registry, skills=skills, target=target, workflow=workflow,
                      store=Store.new_with_id(tmp_path / "sessions", "verify"), profile=profile)


@pytest.mark.parametrize("profile", ["compact", "full"])
async def test_audit_runtime_inventory_and_minimum_history_gate(tmp_path, monkeypatch, profile):
    agent = runtime_inventory(tmp_path, monkeypatch, profile)
    baseline = agent.approx_tokens() + agent.tools_token_estimate()
    print(json.dumps({"profile": profile, "skills": len(agent.skills.list_enabled()),
                      "tools": len(agent.tools.names()), "prompt": agent.approx_tokens(),
                      "schemas": agent.tools_token_estimate(), "baseline": baseline,
                      "default_gate_baseline_plus_min_history": baseline + minimum_compactable_history_tokens(16000)}))
    assert len(agent.tools.names()) == 32
    agent.history.append(Message("user", "h" * 10000))
    agent.set_auto_compact_threshold(5500 if profile == "compact" else 16000)
    attempts = []

    async def compact_probe(signal):
        attempts.append(True)
        return False

    monkeypatch.setattr(agent, "compact_in_place", compact_probe)
    await agent.run("next", FakeSignal(), lambda _: None)
    if profile == "compact":
        assert baseline > 5500
        assert attempts  # 2500 history tokens clear the 2048 minimum.
    else:
        assert baseline + 2500 > 16000
        assert not attempts  # production soft gate, not a hard ceiling.
    request = cast(SnapshotClient, agent.client).requests[-1]
    pressure = approximate_message_tokens(request.messages) + agent.tools_token_estimate()
    assert pressure > agent.get_auto_compact_threshold()
    print(json.dumps({"profile": profile, "attempts": len(attempts), "sent_estimate": pressure}))


async def test_audit_injection_changes_eligible_pre_turn_decision(monkeypatch):
    agent = make_agent()
    agent.memory = SessionMemory()
    for field in ("objectives", "plan", "completed", "findings", "tested", "todos", "files", "commands"):
        setattr(agent.memory, field, [f"{field}-{i} " + "m" * 220 for i in range(24)])
    agent.rebuild_system_prompt()
    agent.history[0] = Message("system", agent.sys_prompt)
    agent.history.append(Message("user", "h" * 24000))
    pre = agent.approx_tokens() + len("next") // 4
    threshold = pre + 1000
    assert 6000 >= minimum_compactable_history_tokens(threshold)
    agent.set_auto_compact_threshold(threshold)
    attempts = []

    async def compact_probe(signal):
        attempts.append(True)
        return False

    monkeypatch.setattr(agent, "compact_in_place", compact_probe)
    events = []
    await agent.run("next", FakeSignal(), events.append, AgentRunOptions(tools=False))
    request = cast(SnapshotClient, agent.client).requests[0]
    pressure = approximate_message_tokens(request.messages)
    assert pre < threshold < pressure
    assert attempts == [True]
    print(json.dumps({"pre": pre, "threshold": threshold, "sent": pressure,
                      "injected_delta": pressure - pre, "compact_attempts": len(attempts)}))


async def test_audit_large_incoming_request_is_not_a_hard_ceiling():
    agent = make_agent()
    agent.set_auto_compact_threshold(16000)
    await agent.run("z" * 100000, FakeSignal(), lambda _: None, AgentRunOptions(tools=False))
    requests = cast(SnapshotClient, agent.client).requests
    assert approximate_message_tokens(requests[0].messages) > 16000
    assert len(requests) == 1


async def test_audit_real_gemini_replay_filters_unsigned_and_preserves_signed(tmp_path):
    unsigned = {"thought": True, "text": "u" * 8000}
    signed = {"thought": True, "text": "s" * 8000, "thoughtSignature": "q" * 4000}
    assert gemini.safe_replay_part(unsigned) is None
    parts = [part for raw in [unsigned, signed, {"text": "answer"}]
             if (part := gemini.safe_replay_part(raw)) is not None]
    message = Message("assistant", "answer", gemini_parts=parts,
                      provider_state_provider="gemini", provider_state_model="gemini-2.5-flash")
    store = Store.new_with_id(tmp_path, "gemini-replay")
    await store.save([message])
    restored = store.load().messages[0]
    encoded = gemini.encode_request(ChatRequest(model="gemini-2.5-flash", messages=[restored]))
    assert encoded["contents"][0]["parts"] == [signed, {"text": "answer"}]
    estimate = estimate_request(ChatRequest(model="gemini-2.5-flash", messages=[restored]), "gemini")
    assert estimate.history_tokens == text_tokens("answer")
    assert estimate.provider_private_tokens == text_tokens(signed["text"]) + len(signed["thoughtSignature"])
    assert estimate.estimated_total > 6000
    other = gemini.encode_request(ChatRequest(model="gemini-other", messages=[restored]))
    assert other["contents"][0]["parts"] == [{"text": "answer"}]
    print(json.dumps({"message_estimate": approximate_message_tokens([restored]),
                      "replayed_private_text_chars": len(signed["text"]),
                      "signature_chars": len(signed["thoughtSignature"])}))


async def test_anthropic_usage_through_response_and_metrics(monkeypatch):
    payload = {"content": [{"type": "text", "text": "done"}], "stop_reason": "end_turn",
               "usage": {"input_tokens": 100, "output_tokens": 20,
                         "cache_read_input_tokens": 40, "cache_creation_input_tokens": 10}}

    class Response:
        status_code = 200
        text = json.dumps(payload)
        def json(self):
            return deepcopy(payload)

    class Transport:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def post(self, *args, **kwargs):
            return Response()

    monkeypatch.setattr(anthropic, "new_provider_async_client", Transport)
    client = anthropic.AnthropicClient("https://api.anthropic.com/v1", "synthetic", "claude-test")
    agent = make_agent(client=client)
    await agent.run("next", FakeSignal(), lambda _: None, AgentRunOptions(tools=False))
    assert agent.request_metrics.records[-1].status == "success"
    usage = agent.request_metrics.records[-1].usage
    assert usage is not None
    assert (usage.input_tokens, usage.output_tokens, usage.cached_input_tokens,
            usage.cache_creation_input_tokens, usage.total_tokens) == (150, 20, 40, 10, 170)
    assert usage.reasoning_tokens is None


def test_audit_plugin_schema_mutation_is_possible_but_requires_external_mutation():
    cfg = PluginConfig(name="fixture", command="never-executed", description="short")
    registry = Registry()
    registry.register(CommandPluginTool(cfg))
    agent = make_agent(tools=registry)
    estimate = agent.tools_token_estimate()
    cfg.description = "d" * 4000
    assert agent.tools_token_estimate() > estimate + 900
    # Characterizes a public mutable object, not an observed production edit path.


async def test_compaction_rejects_history_savings_that_increase_request_pressure():
    agent = make_agent()
    agent.history.extend([Message("user", "h" * 6000), Message("assistant", "a"),
                          Message("user", "recent"), Message("assistant", "done")])
    before = agent.approx_tokens()
    sections = ("Current objective", "Plan", "Completed tasks", "Findings and evidence",
                "Tested surface", "Open TODOs", "Files and commands")
    summary = "\n".join(f"## {title}\n" + "\n".join(
        f"- {title}-{i} /local/file.py " + "m" * 210 for i in range(8)) for title in sections)
    history_before = deepcopy(agent.history)
    memory_before = agent.memory
    with pytest.raises(IneffectiveCompactionError, match="projected request"):
        await agent.apply_compaction_summary(summary, agent.get_history(), "regression")
    assert agent.history == history_before
    assert agent.memory is memory_before
    assert agent.approx_tokens() == before


async def test_final_synthesis_does_not_count_tools_it_does_not_send(tmp_path, monkeypatch):
    agent = runtime_inventory(tmp_path, monkeypatch, "compact")
    working = [Message("system", agent.sys_prompt), Message("tool", "x" * 12000, name="http")]
    actual_before = approximate_message_tokens(working)
    agent.set_auto_compact_threshold(actual_before + 1000)
    await agent._whole_target_synthesis(
        working, FakeSignal(), lambda _: None, thinking_enabled=False,
        reasoning_level=ReasoningLevel.OFF, requested_reasoning_level=ReasoningLevel.OFF,
        stop_reason="max_steps", instruction="Produce a concise summary.", max_steps=1,
    )
    request = cast(SnapshotClient, agent.client).requests[-1]
    assert request.tools is None
    assert request.messages[1].content == "x" * 12000
    print(json.dumps({"synthesis_actual_before": actual_before,
                      "threshold": agent.get_auto_compact_threshold(),
                      "synthesis_sent": approximate_message_tokens(request.messages),
                      "schemas_counted_but_not_sent": agent.tools_token_estimate()}))


def test_audit_heuristic_samples_without_tokenizer_or_network():
    samples = {
        "english": "Inspect the request and compare the response. " * 20,
        "vietnamese": "Kiểm tra yêu cầu và so sánh phản hồi. " * 20,
        "json": json.dumps({"items": [{"id": i, "url": f"/api/{i}"} for i in range(20)]}),
        "code": "def handler(x):\n    return {'value': x + 1}\n" * 20,
        "urls": "https://local.example/api/items?q=123&sort=desc " * 20,
        "ascii": "x" * 800,
        "minified": "function f(a){return a.map(x=>x.id).filter(Boolean)};" * 20,
        "emoji": "🔎🧪✅" * 100,
    }
    for label, sample in samples.items():
        assert approximate_message_tokens([Message("user", sample)]) >= text_tokens(sample)
        print(json.dumps({"sample": label, "chars": len(sample),
                          "utf8_bytes": len(sample.encode()), "estimate": len(sample) // 4}))
    assert approximate_message_tokens([Message("user", "ok") for _ in range(50)]) >= 50
    print(json.dumps({"tiktoken_installed": importlib.util.find_spec("tiktoken") is not None}))
