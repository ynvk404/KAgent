"""Offline behavior at model request, compaction and diagnostic boundaries."""
from copy import deepcopy
import json
from typing import Any, cast

import pytest

from src.agent.agent import AgentRunOptions, COMPACTION_SYSTEM_PROMPT
from src.llm.core.types import FunctionCall, ToolCall, Message, ChatResponse
from src.tools.common.outcome import ToolOutput
from src.tools.workflow.coverage import CoverageTool
from src.workflow.state import WorkflowObjective
from src.workflow.planning.goals import RequestedGoal
from tests.agent.test_token_accounting_independent_verify import runtime_inventory, SnapshotClient
from tests.agent.test_tool_outcomes import make_agent as outcome_agent
from tests.helpers.agent_fakes import FakeClient, FakeSignal, seed_compactable_history


@pytest.mark.parametrize('http_allowed', [True, False])
async def test_actual_xss_model_request_filters_certainly_unavailable_capabilities(tmp_path, monkeypatch, http_allowed):
    agent = runtime_inventory(tmp_path, monkeypatch, 'compact')
    agent.auto_compact_threshold = 0
    from src.tools.common.tool_result import ReadHTTPObservation
    if agent.tools.get('read_http_observation') is None:
        agent.tools.register(ReadHTTPObservation(agent))
    if not http_allowed:
        agent.skills.skills['cross-site-scripting'].tools.remove('http')
    coverage = agent.tools.get('coverage')
    assert isinstance(coverage, CoverageTool)
    original = coverage.requires_permission_for
    seen = []
    def permission(args):
        assert args, 'projection must never decide argument permissions with empty args'
        seen.append(args)
        return original(args)
    monkeypatch.setattr(coverage, 'requires_permission_for', permission)
    await agent.inject_skill('cross-site-scripting')
    agent.client = SnapshotClient([ChatResponse(Message('assistant', 'Bounded fixture response.'), 'stop') for _ in range(5)])
    await agent.run('Continue bounded validation.', FakeSignal(), lambda _: None, AgentRunOptions(max_steps=3))
    specs = cast(Any, agent.client.requests[0].tools)
    names = {s['function']['name'] for s in specs}
    assert not {'file_edit', 'FileEditTool'} & names
    assert {'shell', 'BashTool', 'file_write', 'FileWriteTool', 'read_tool_result', 'coverage'} <= names
    assert ('http' in names) is http_allowed
    assert ('read_http_observation' in names) is http_allowed
    assert not seen
    assert agent.is_tool_allowed('coverage', {'action': 'summary'}).ok
    assert not agent.is_tool_allowed('coverage', {'action': 'clear'}).ok
    assert not agent.is_tool_allowed('file_edit', {'path': 'proof.md'}).ok


@pytest.mark.parametrize('case', ['typed', 'exception', '403', '500'])
async def test_typed_and_raised_errors_log_one_code_only_diagnostic(monkeypatch, case):
    agent = outcome_agent()
    secret = 'opaque-fixture-value-in-unlabelled-prose'
    async def run(*_args, **_kwargs):
        if case == 'exception': raise RuntimeError(secret + ' https://user:password@example.test/?token=secret')
        return ToolOutput(secret, status='error' if case == 'typed' else 'observation',
                          error_kind='network' if case == 'typed' else None,
                          http_status=None if case == 'typed' else int(case))
    monkeypatch.setattr(agent.tools.get('case'), 'run', run)
    logs = []
    monkeypatch.setattr('src.agent.agent.log_error', lambda message, data: logs.append((message, data)))
    call = ToolCall('fixture', FunctionCall('case', '{"case":"fixture"}'))
    result = await agent.run_parsed_tool_call(call, agent.parse_tool_call(call), FakeSignal())
    if case in {'typed', 'exception'}:
        assert result.status == 'error' and len(logs) == 1
        assert logs[0][0] == 'agent: tool failed'
        assert logs[0][1]['error_kind'] == ('network' if case == 'typed' else 'tool_exception')
        assert secret not in json.dumps(logs) and 'example.test' not in json.dumps(logs)
    else:
        assert result.status == 'observation' and result.http_status == int(case) and not logs


async def test_compaction_omission_and_wrong_summary_do_not_replace_canonical_goals(tmp_path, monkeypatch):
    agent = runtime_inventory(tmp_path, monkeypatch, 'compact')
    agent.workflow.objective = WorkflowObjective('fixture-objective', 'whole_target', agent.target.base_url(),
        requested_goals=[RequestedGoal('sqli', status='deferred'), RequestedGoal('xss')])
    before = deepcopy(agent.workflow.to_dict())
    summary = ('## Current objective\n- Finish SQLi and the report.\n## Plan\n'
               '- Reader redacted SQL and credentials block the work.\n## Completed tasks\n- XSS completed.')
    seed_compactable_history(agent, 40000)
    agent.history += [Message('user', 'Continue.'), Message('assistant', 'Work remains.')]
    agent.client = FakeClient([ChatResponse(Message('assistant', summary), 'stop')])
    assert await agent.compact_in_place(FakeSignal())
    assert agent.workflow.to_dict() == before
    prompt = agent.client.requests[0].messages[0].content
    assert '"mode": "whole_target"' in prompt and '"class": "cross-site-scripting", "status": "pending"' in prompt
    assert 'hypotheses and verified blockers' in COMPACTION_SYSTEM_PROMPT
    assert agent.memory is not None and agent.store is not None
    assert agent.memory.last_summary == summary  # Kept as untrusted model output, not fact-checked prose.
    saved = agent.store.load()
    assert saved.workflow.to_dict() == before
    agent.workflow = saved.workflow
    context = agent._planner_context()
    assert context.objective_mode == 'whole_target'
    assert [(g.candidate_class, g.status) for g in context.requested_goals] == [
        ('sql-injection', 'deferred'), ('cross-site-scripting', 'pending')]
    view = agent._workflow_request_view('Continue.', agent.tools.as_llm_tools())
    text = '\n'.join(m.content for m in view.blocks)
    assert 'cross-site-scripting' in text and 'status=pending' in text
