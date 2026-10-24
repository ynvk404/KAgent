"""Independent offline regressions for benchmark-audited runtime mechanisms."""
import json

import pytest

from src.llm.core.types import Message
from src.llm.runtime.context_budget import ContextCapacityError
from src.tools.common.outcome import ToolOutput
from src.skills.registry import Registry as Skills
from src.skills.registry import Skill
from src.permission.permission import AlwaysAllow
from src.tools.common.registry import Registry
from src.tools.skills.payloads import ReadPayloadsTool
from src.tools.skills.skill_file import ReadSkillFileTool
from src.workflow.evidence.artifacts import check_proof_references
from src.workflow.evidence.errors import EvidenceSubmissionError
from src.workflow.state import ValidationResult, _text
from tests.agent.test_token_accounting_independent_verify import make_agent
from tests.helpers.agent_fakes import EchoTool, FakeSignal, collect
from tests.integration.test_requested_goal_lifecycle import _direct_goal_agent, NoProgressToolClient


@pytest.mark.parametrize("prefix", ["x" * 999 + " ", "é" * 999 + "\u2003"])
def test_capped_result_text_has_stable_round_trip(prefix):
    result = ValidationResult("candidate", "sql-injection", "insufficient-evidence",
                              notes=prefix + "remaining text", objective_id="objective")
    serialized = result.to_dict()
    restored = ValidationResult.from_dict(serialized)
    assert restored is not None and restored.to_dict() == serialized


@pytest.mark.parametrize("text", ["password=long-sensitive-value", "Cookie: sid=private-session",
                                  "Authorization: Bearer private-value", "[REDACTED]"])
@pytest.mark.parametrize("limit", [8, 20, 500])
def test_capped_redacted_text_is_idempotent(text, limit):
    value = _text(text, limit=limit)
    assert _text(value, limit=limit) == value
    assert "long-sensitive-value" not in (value or "")
    assert "private-session" not in (value or "")


@pytest.mark.parametrize("reader_type", [ReadPayloadsTool, ReadSkillFileTool])
def test_recent_skill_page_preserved_and_archived_pages_bounded(reader_type):
    registry = Registry()
    reader = reader_type(Skills())
    registry.register(reader)
    agent = make_agent(tools=registry)
    agent.set_auto_compact_threshold(1000)
    page = "# fixture page\n" + "essential payload detail\n" * 400 + "\nContinuation: exact next page"
    history = [Message("tool", page, name=reader.name(), tool_call_id=str(i)) for i in range(12)]
    agent.history.extend(history)
    working = list(agent.history)
    agent.guard_working_context(working, lambda _: None)
    pages = [message for message in working if message.name == reader.name()]
    assert pages[-1].content == page
    assert sum(message.content == page for message in pages) <= 4
    assert all(message.content == page for message in agent.history if message.name == reader.name())


@pytest.mark.parametrize("claim", ["### Request `{id}`", "| baseline | `{id}` | 200 |"])
def test_heading_and_table_source_handles_require_selected_parents(claim):
    unknown = "obs_" + "f" * 32
    content = ("# Proof\n- candidate_id: candidate\n" + claim.format(id=unknown)).encode()
    with pytest.raises(EvidenceSubmissionError, match="primary parent"):
        check_proof_references(content, "candidate", [])
    check_proof_references(content, "candidate", [unknown])


async def test_direct_tool_batches_reach_hard_limit_without_negative(tmp_path):
    client = NoProgressToolClient()
    agent, _ = _direct_goal_agent(tmp_path, client=client, max_steps=24, extra_tools=(EchoTool(),))
    output = collect()
    await agent.run("Test SQL injection for GET /fixture?q=sample", FakeSignal(), output["sink"])
    assert len(client.requests) == 25 and client.requests[-1].tools is None
    assert output["events"][-1].stop_reason == "max_steps"
    assert output["events"][-1].agent_loop_llm_calls == 24
    assert not agent.workflow.validation_results
    assert agent.workflow.objective is not None
    assert [goal.status for goal in agent.workflow.objective.requested_goals] == ["pending"]
    assert not agent.workflow.candidates and not agent.workflow.attempts


async def test_preserved_page_cannot_bypass_hard_context_admission():
    registry = Registry()
    registry.register(ReadPayloadsTool(Skills()))
    agent = make_agent(tools=registry)
    setattr(agent.client, "input_token_limit", 500)
    working = [Message("tool", "# fixture\n" + "essential\n" * 1000, name="read_payloads")]
    request = agent._request_for_messages(working, agent.tools.as_llm_tools())
    with pytest.raises(ContextCapacityError):
        await agent._admit_request(request, lambda _: None)
    assert working[-1].content.endswith("essential\n")


async def test_complete_first_page_and_smaller_reread_share_identity_and_eof(tmp_path):
    skills = Skills()
    skills.add(Skill("fixture", "fixture", [], False, str(tmp_path / "SKILL.md"), ""))
    (tmp_path / "payloads.txt").write_text("first\nsecond\nthird\n")
    reader = ReadPayloadsTool(skills)
    args = {"skill": "fixture", "file": "payloads.txt"}
    first = await reader.run(args, None, AlwaysAllow())
    assert isinstance(first, ToolOutput)
    full = json.loads(first.rsplit("\nContinuation: ", 1)[1])
    assert full["next_start_char"] is None and not first.truncated
    second = await reader.run({**args, "limit": 1}, None, AlwaysAllow())
    part = json.loads(second.rsplit("\nContinuation: ", 1)[1])
    assert part["source_ref"] == full["source_ref"] and part["sha256"] == full["sha256"]
    assert part["start_char"] == full["start_char"] == 0
    assert part["end_char"] <= full["end_char"]
