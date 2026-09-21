from __future__ import annotations

import json

import pytest

from src.permission.permission import AlwaysAllow
from src.target.target import Target
from src.tools.workflow import DEFAULT_LIST_LIMIT, WorkflowTool
from src.workflow.state import Candidate, WorkflowState


def test_workflow_preserves_same_turn_result_context():
    tool = WorkflowTool(WorkflowState())

    assert tool.context_reduction_policy() == "preserve"


def test_schema_describes_action_specific_required_fields():
    tool = WorkflowTool(WorkflowState())
    schema = tool.schema()

    assert schema["required"] == ["action"]
    assert "record_result needs candidate_id, skill_name, and outcome" in (
        tool.description()
    )
    assert "Required for start_validation and record_result" in (
        schema["properties"]["candidate_id"]["description"]
    )
    assert "Required for record_result" in (
        schema["properties"]["outcome"]["description"]
    )
    assert "not used by record_result" in (
        schema["properties"]["status"]["description"]
    )


@pytest.mark.asyncio
async def test_structured_candidate_to_validation_handoff_and_dedup():
    state = WorkflowState()
    tool = WorkflowTool(state, Target("https://target.test"))
    args = {
        "action": "record_candidate",
        "candidate_class": "sqli",
        "method": "POST",
        "endpoint": "/product",
        "parameter": "id",
        "source_skill": "web-input-analysis",
        "signals": ["syntax differential"],
    }
    first = json.loads(await tool.run(args, None, AlwaysAllow()))
    second = json.loads(await tool.run(args, None, AlwaysAllow()))
    candidate_id = first["candidate"]["id"]

    assert first["created"] is True
    assert second["created"] is False
    assert state.relevant_candidate_classes() == frozenset({"sql-injection"})

    await tool.run(
        {"action": "start_validation", "candidate_id": candidate_id},
        None,
        AlwaysAllow(),
    )
    result = json.loads(
        await tool.run(
            {
                "action": "record_result",
                "candidate_id": candidate_id,
                "skill_name": "sql-injection",
                "outcome": "confirmed",
                "evidence_refs": ["captures/sql-1"],
                "repeatable": True,
            },
            None,
            AlwaysAllow(),
        )
    )

    assert result["eligible_for_confirm_finding"] is True
    assert state.candidates[candidate_id].status == "validated"


@pytest.mark.asyncio
async def test_candidate_uses_active_target_when_argument_is_omitted():
    state = WorkflowState()
    target = Target("https://a.example")
    tool = WorkflowTool(state, target)
    args = {
        "action": "record_candidate",
        "candidate_class": "sqli",
        "method": "POST",
        "endpoint": "/product",
        "parameter": "id",
    }

    first = json.loads(await tool.run(args, None, AlwaysAllow()))
    target.set_base_url("https://b.example")
    second = json.loads(await tool.run(args, None, AlwaysAllow()))
    explicit = json.loads(
        await tool.run(
            {**args, "target": "https://explicit.example"},
            None,
            AlwaysAllow(),
        )
    )

    assert first["candidate"]["target"] == "https://a.example"
    assert second["candidate"]["target"] == "https://b.example"
    assert explicit["candidate"]["target"] == "https://explicit.example"
    assert first["candidate"]["id"] != second["candidate"]["id"]


@pytest.mark.asyncio
async def test_record_candidate_requires_resolvable_target():
    output = await WorkflowTool(WorkflowState(), Target()).run(
        {
            "action": "record_candidate",
            "candidate_class": "xss",
            "endpoint": "/search",
        },
        None,
        AlwaysAllow(),
    )
    assert output.startswith("error: record_candidate requires target")


@pytest.mark.asyncio
async def test_list_is_bounded_prioritized_and_supports_specific_lookup():
    state = WorkflowState()
    candidates = []
    for index in range(DEFAULT_LIST_LIMIT + 5):
        candidate, _ = state.add_candidate(
            Candidate(
                candidate_class="xss",
                target="https://target.test",
                endpoint=f"/search/{index}/" + "e" * 500,
                parameter="p" * 500,
                location="query" * 50,
                signals=["s" * 500, "t" * 500, "omitted"],
                baseline_request_ref="b" * 500,
                auth_context_ref="a" * 500,
            )
        )
        candidates.append(candidate)
    state.set_candidate_status(candidates[-1].id, "validating")
    tool = WorkflowTool(state, Target("https://target.test"))

    listed = json.loads(
        await tool.run({"action": "list"}, None, AlwaysAllow())
    )
    specific = json.loads(
        await tool.run(
            {"action": "list", "candidate_id": candidates[-2].id},
            None,
            AlwaysAllow(),
        )
    )

    assert listed["total"] == DEFAULT_LIST_LIMIT + 5
    assert listed["returned"] == DEFAULT_LIST_LIMIT
    assert listed["truncated"] is True
    assert listed["candidates"][0]["id"] == candidates[-1].id
    assert len(json.dumps(listed)) < 20_000
    assert len(listed["candidates"][0]["endpoint"]) == 200
    assert len(listed["candidates"][0]["signals"]) == 2
    assert specific["returned"] == 1
    assert specific["candidates"][0]["id"] == candidates[-2].id


@pytest.mark.asyncio
async def test_skill_completion_is_explicit():
    state = WorkflowState()
    tool = WorkflowTool(state)

    output = json.loads(
        await tool.run(
            {"action": "complete_skill", "skill_name": "sql_injection"},
            None,
            AlwaysAllow(),
        )
    )

    assert output["ok"] is True
    assert state.completed_skills == {"sql-injection"}


@pytest.mark.asyncio
async def test_workflow_tool_rejects_result_without_candidate():
    output = await WorkflowTool(WorkflowState()).run(
        {
            "action": "record_result",
            "candidate_id": "cand_missing",
            "skill_name": "cross-site-scripting",
            "outcome": "blocked",
        },
        None,
        AlwaysAllow(),
    )
    assert output.startswith("error: unknown candidate")
