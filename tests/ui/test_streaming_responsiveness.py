"""Real offline workflow/agent: chunks are presentation, not evidence gates."""
import time
from unittest.mock import patch

import pytest

from src.agent.events import AssistantDeltaEvent, AssistantTextEvent
from src.llm.core.types import Message
from src.config.config import PluginConfig
from src.session.store import SessionMemory
from src.tools.execution.plugin import CommandPluginTool
from src.target.target import Target
from src.tools.common.registry import Registry
from src.tools.workflow.workflow_tool import WorkflowTool
from src.ui.core import app as app_module
from src.ui.core.app import KAgent
from src.ui.core.state import AgentEventAction, SetBusy
from src.workflow.evidence import artifacts as evidence_module
from src.workflow.evidence.artifacts import EvidenceArtifact
from src.workflow.state import Candidate, ValidationResult, WorkflowState
from tests.helpers.workflow import adopt_fixture_assessment
from tests.agent.test_token_accounting_independent_verify import make_agent
from tests.ui.test_overview import _make_app


async def test_text_deltas_do_not_rebuild_semantic_context_or_reread_proofs(tmp_path, monkeypatch):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    target = Target()
    target.set_base_url("https://offline.invalid")
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(candidate_class="xss", target=target.base_url(), endpoint="/search"))
    (tmp_path / "proof.txt").write_text("Synthetic offline proof")
    artifact = EvidenceArtifact.capture(candidate.id, "proof.txt", tmp_path)
    state.add_evidence(artifact)
    state.add_validation_result(adopt_fixture_assessment(state, ValidationResult(
        candidate.id, "cross-site-scripting", "confirmed", evidence_refs=[artifact.id])))
    registry = Registry()
    registry.register(WorkflowTool(state, target, evidence_root=tmp_path))
    agent = make_agent(tools=registry, target=target, workflow=state)
    agent.history.extend(Message("user", "x" * 256) for _ in range(1000))
    app = _make_app()
    app.agent = agent
    async with app.run_test():
        app.dispatch(SetBusy(True))
        with (patch.object(app_module, "runtime_facts", wraps=app_module.runtime_facts) as facts,
              patch.object(evidence_module, "_read_captured_value", wraps=evidence_module._read_captured_value) as reads,
              patch.object(agent, "approx_tokens", wraps=agent.approx_tokens) as history,
              patch.object(agent, "idle_request_estimate", wraps=agent.idle_request_estimate) as estimate,
              patch.object(agent.tools, "as_llm_tools", wraps=agent.tools.as_llm_tools) as schemas):
            started = time.perf_counter()
            for _ in range(100):
                app.dispatch(AgentEventAction(AssistantDeltaEvent(text="chunk ")))
            elapsed = (time.perf_counter() - started) * 1000
            counts = dict(facts=facts.call_count, reads=reads.call_count,
                          history=history.call_count, estimate=estimate.call_count, schemas=schemas.call_count)
            print({"deltas": 100, "elapsed_ms": elapsed, **counts})
            assert all(count == 0 for count in counts.values())
            app.dispatch(AgentEventAction(AssistantTextEvent(text="complete sanitized answer")))
            assert facts.call_count and history.call_count and estimate.call_count
        assert app.state.transcript[-1].text == "complete sanitized answer"


async def test_explicit_status_refresh_observes_in_place_history_memory_and_schema(monkeypatch):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    agent = make_agent()
    config = PluginConfig("offline_fixture", "never-executed", schema={"type": "object", "description": "small"})
    agent.tools.register(CommandPluginTool(config))
    app = _make_app()
    app.agent = agent
    async with app.run_test():
        app._sync_status_bar()
        first = dict(app._status_info)
        assert config.schema is not None
        config.schema["description"] = "large synthetic schema " * 1000
        agent.history.append(Message("user", "synthetic history " * 1000))
        agent.memory = SessionMemory(objectives=["synthetic memory " * 1000])
        app._sync_status_bar()
        assert app._status_info["ctx_tokens"] > first["ctx_tokens"]
        assert app._status_info["request_tokens"] > first["request_tokens"]
        assert app._status_info["memory_items"] == 1
        assert app._status_info["ctx_tokens"] == agent.approx_tokens()
        assert app._status_info["request_tokens"] == agent.idle_request_estimate().estimated_total
