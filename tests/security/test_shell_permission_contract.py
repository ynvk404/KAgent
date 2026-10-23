"""Production registry/receipts and evidence gates, without network or models."""
import asyncio
import json
from unittest.mock import AsyncMock

import pytest

from src.permission.permission import Decision, UserControlledRefusal
from src.permission.runtime.execution import ExecutionBlocked
from src.tools.execution.shell import BashTool, ShellTool
from src.workflow.state import Candidate, WorkflowObjective
from tests.helpers.burp_selection import make_runtime
from tests.security.test_agent_assessment import ASSESSMENT


@pytest.mark.parametrize("tool_type", [ShellTool, BashTool])
async def test_bound_direct_call_cannot_skip_registry_receipt(tmp_path, monkeypatch, tool_type):
    rt = make_runtime(tmp_path)
    spawn = AsyncMock(side_effect=AssertionError("no process may launch"))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    with pytest.raises(ExecutionBlocked, match="process-without-execution-receipt"):
        await tool_type().run({"command": "printf fixture"}, None, rt.prompter)
    spawn.assert_not_called()
    assert rt.policy.used == rt.policy.active == 0


@pytest.mark.parametrize("tool_type", [ShellTool, BashTool])
async def test_off_reviews_every_command_and_rejects_session_approval(tmp_path, tool_type):
    rt = make_runtime(tmp_path, yolo=False)
    tool = tool_type()
    rt.registry.register(tool)
    args = {"command": "printf fixture"}
    for _ in range(2):
        output = await rt.registry.execute(tool.name(), args, None, rt.prompter)
        assert output.status == "success"
    assert len(rt.operator.requests) == 2
    assert all(request.no_session_cache and not request.supports_session
               for request in rt.operator.requests)
    rt.operator.decision = Decision.ALLOW_SESSION
    with pytest.raises(UserControlledRefusal, match="permission denied"):
        await rt.registry.execute(tool.name(), args, None, rt.prompter)
    assert rt.policy.used == 2 and rt.policy.active == 0


@pytest.mark.parametrize("tool_type", [ShellTool, BashTool])
async def test_yolo_cannot_override_revoked_shell_adapter(tmp_path, monkeypatch, tool_type):
    rt = make_runtime(tmp_path)
    tool = tool_type()
    rt.registry.register(tool)
    rt.policy.revoke(tool.name())
    spawn = AsyncMock(side_effect=AssertionError("no process may launch"))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    with pytest.raises(ExecutionBlocked, match="tool/session-revoked"):
        await rt.registry.execute(tool.name(), {"command": "printf fixture"}, None, rt.prompter)
    spawn.assert_not_called()
    assert not rt.operator.requests and rt.policy.used == rt.policy.active == 0


async def test_http_session_deny_is_not_a_shell_network_sandbox(tmp_path, monkeypatch):
    rt = make_runtime(tmp_path)
    rt.registry.register(ShellTool())
    rights = rt.engagement.http_permissions
    rights.deny_session()
    authorize = AsyncMock(side_effect=AssertionError("shell must not claim native HTTP authority"))
    monkeypatch.setattr(rights, "authorize", authorize)
    # Print only: an actual curl would use account network rights, but this
    # audit must not contact a target or make an external request.
    output = await rt.registry.execute("shell", {
        "command": "printf 'https://outside.invalid/not-a-request'",
    }, None, rt.prompter)
    assert output.status == "success" and output.runtime_metadata.http is None
    authorize.assert_not_called()
    with pytest.raises(ExecutionBlocked, match="network/session-revoked"):
        await rt.registry.execute("http", {"url": "/", "phase": "recon"}, None, rt.prompter)
    assert rt.policy.used == 1 and rt.policy.active == 0


@pytest.mark.parametrize("tool_type", [ShellTool, BashTool])
@pytest.mark.parametrize("candidate_class", ["xss", "sqli"])
@pytest.mark.parametrize("outcome", ["confirmed", "not-confirmed"])
async def test_http_looking_stdout_and_registered_proof_cannot_replace_primary_evidence(
    tmp_path, tool_type, candidate_class, outcome,
):
    rt = make_runtime(tmp_path)
    tool = tool_type()
    rt.registry.register(tool)
    rt.workflow.objective = WorkflowObjective("shell-evidence-audit", "direct", rt.target.base_url())
    candidate, _ = rt.workflow.add_candidate(Candidate(
        candidate_class, target=rt.target.base_url(), endpoint="/fixture", method="GET",
        parameter="q", location="query", objective_id=rt.workflow.objective.id,
    ))
    started = json.loads(await rt.registry.execute("workflow", {
        "action": "start_validation", "candidate_id": candidate.id,
    }, None, rt.prompter))
    assert started["ok"], started
    output = await rt.registry.execute(tool.name(), {
        "command": "printf 'HTTP/1.1 200 OK\\nContent-Type: text/html\\n\\nfixture'",
    }, None, rt.prompter)
    meta = output.runtime_metadata
    assert meta is not None and meta.http is None
    source = rt.policy.observations._items[meta.observation_id]
    assert source.source_kind == "tool-output" and source.method == "OUTPUT"
    assert source.status == 0 and source.url == ""
    assert source.candidate_id == candidate.id and source.complete
    assert not rt.workflow.discovery_sources
    (tmp_path / "proof.md").write_text("Supplementary process output: " + source.id, encoding="utf-8")
    registered = json.loads(await rt.registry.execute("workflow", {
        "action": "record_evidence", "candidate_id": candidate.id,
        "evidence_path": "proof.md", "observation_ids": [source.id],
    }, None, rt.prompter))
    assert registered["ok"], registered
    result = await rt.registry.execute("workflow", {
        "action": "record_result", "candidate_id": candidate.id,
        "attempt_id": started["validation_context"]["attempt_id"],
        "skill_name": "sql-injection" if candidate_class == "sqli" else "cross-site-scripting",
        "outcome": outcome, "observation_ids": [source.id],
        "evidence_refs": [registered["evidence"]["id"]], "assessment": ASSESSMENT.copy(),
    }, None, rt.prompter)
    assert "tool output claims alone cannot establish target request/response evidence" in result
    assert not rt.workflow.validation_results and not rt.workflow.eligible_for_finding(candidate.id)
    assert not await rt.coverage.list()
    assert rt.policy.active == 0 and not rt.policy._active_receipts
