"""Offline lan-07 regressions; scripted compliance does not predict model choices."""
from copy import deepcopy
import json
from pathlib import Path
from typing import Any, cast

import pytest

from src.agent.agent import AgentRunOptions
from src.agent.system_prompt import BuildOptions, PromptProfile, build_system_prompt
from src.llm.core.reasoning import ReasoningLevel
from src.llm.core.types import ChatRequest, ChatResponse, Message
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry as Skills
from src.tools.common.ask import AskUserTool, FirstOptionPrompter
from src.tools.execution.file import FileEditTool, FileEditToolAlias
from src.tools.skills.payloads import ReadPayloadsTool
from src.workflow.state import WorkflowMode, WorkflowObjective
from tests.agent.test_validation_continuation import (
    InspectModel, candidate_for, offline, workflow,
)
from tests.helpers.agent_fakes import FakeClient, FakeSignal, collect
from tests.helpers.burp_selection import make_runtime, ORIGIN
from tests.helpers.discovery_calls import execute
from tests.integration.test_lan06_handoff import complete_phase


@pytest.mark.parametrize('profile', ['full', 'compact'])
async def test_artifact_guidance_respects_advertised_analysis_contract(tmp_path, profile: PromptProfile):
    rt = make_runtime(tmp_path)
    for tool in (FileEditTool(), FileEditToolAlias()):
        rt.registry.register(tool)
    rt.workflow.objective = WorkflowObjective('handoff', 'whole_target', ORIGIN)
    await execute(rt, 'load_skill', {'name': 'web-input-analysis'})
    request = ChatRequest(rt.client.model(), [], tools=rt.registry.as_llm_tools())
    await rt.agent._prepare_turn_request(request, lambda _: None)
    names = {x['function']['name'] for x in cast(Any, request.tools)}
    assert 'file_write' in names and not {'file_edit', 'FileEditTool'} & names
    result = await execute(rt, 'file_edit', {'path': str(tmp_path / 'absent.md'),
        'old_string': 'old', 'new_string': 'new'}, success=False)
    assert result.err_str and not (tmp_path / 'absent.md').exists()
    prompt = build_system_prompt(BuildOptions(rt.skills, False, None, prompt_profile=profile))
    assert 'If file_edit is unavailable, rewrite' in prompt
    assert 'active skill' in prompt.split('If file_edit is unavailable', 1)[1].split('\n', 1)[0]


async def test_blocked_inputs_require_real_resolution_or_operator_exclusion(tmp_path):
    rt = make_runtime(tmp_path)
    rt.registry.register(AskUserTool(FirstOptionPrompter()))
    rt.workflow.objective = WorkflowObjective('handoff', 'whole_target', ORIGIN)
    complete_phase(rt, 'recon', 'recon')
    complete_phase(rt, 'enumeration', 'web-enumeration')
    await execute(rt, 'load_skill', {'name': 'web-input-analysis'})
    candidate = json.loads((await execute(rt, 'workflow', {'action': 'record_candidate',
        'candidate_class': 'sql-injection', 'endpoint': '/search', 'method': 'GET',
        'parameter': 'q', 'location': 'query'})).result)['candidate']['id']
    public = json.loads((await execute(rt, 'workflow', {'action': 'record_input',
        'endpoint': '/search', 'method': 'GET', 'parameter': 'q', 'location': 'query'})).result)['input']['id']
    await execute(rt, 'workflow', {'action': 'link_input_candidate', 'input_id': public, 'candidate_id': candidate})
    await execute(rt, 'workflow', {'action': 'set_input_disposition', 'input_id': public, 'disposition': 'analyzed', 'analysis_complete': True})
    blocked = []
    for field in ('customer', 'lines'):
        item = json.loads((await execute(rt, 'workflow', {'action': 'record_input',
            'endpoint': '/orders', 'method': 'POST', 'parameter': field, 'location': 'json',
            'content_type': 'application/json'})).result)['input']['id']
        await execute(rt, 'workflow', {'action': 'set_input_disposition', 'input_id': item,
            'disposition': 'blocked', 'disposition_reason': 'Authorized session unavailable; field consumption unknown.'})
        blocked.append(item)
    ref = 'artifacts/web-input-analysis/127-0-0-1-3000/candidates.md'
    await execute(rt, 'file_write', {'path': str(tmp_path / ref), 'content': 'One hypothesis; two blocked inputs.'})
    rejected = await execute(rt, 'workflow', {'action': 'complete_skill', 'skill_name': 'web-input-analysis'}, success=False)
    assert 'PHASE_NOT_READY' in rejected.result
    early = await execute(rt, 'workflow', {'action': 'start_validation', 'candidate_id': candidate}, success=False)
    assert 'input_analysis must complete' in early.result and not rt.workflow.attempts
    request = ChatRequest(rt.client.model(), [], tools=rt.registry.as_llm_tools())
    await rt.agent._prepare_turn_request(request, lambda _: None)
    advice = next(m.content for m in request.messages if m.content.startswith('Workflow action guidance:'))
    assert 'ask_user' in advice and 'operator exclusion' in advice and 'blocked' in advice
    assert 'guess credentials' in advice
    # This is the existing operator branch, not automatic exclusion or permission.
    answered = await execute(rt, 'ask_user', {'questions': [{'question': 'Exclude the two inaccessible inputs from this assessment or leave blocked?',
        'options': [{'label': 'Exclude these inputs'}, {'label': 'Leave blocked'}]}]})
    assert json.loads(answered.result)['answers'][0]['answer'] == 'Exclude these inputs'
    for item in blocked:
        await execute(rt, 'workflow', {'action': 'set_input_disposition', 'input_id': item,
            'disposition': 'dropped', 'disposition_reason': 'Operator exclusion for this assessment; auth-limited and untested.'})
    await execute(rt, 'file_write', {'path': str(tmp_path / ref), 'content': 'One hypothesis; two operator exclusions, untested.'})
    await execute(rt, 'workflow', {'action': 'complete_skill', 'skill_name': 'web-input-analysis'})
    await execute(rt, 'load_skill', {'name': 'sql-injection'})
    started = await execute(rt, 'workflow', {'action': 'start_validation', 'candidate_id': candidate})
    assert json.loads(started.result)['ok'] and not rt.policy.observations._items


@pytest.mark.parametrize('mode', ['direct', 'whole_target'])
async def test_new_payload_pages_are_progress_but_repeated_pages_still_stop(offline, mode: WorkflowMode):
    rt, sent = offline
    rt.workflow.objective = WorkflowObjective('offline-objective', mode, ORIGIN)
    rt.workflow.objective.add_requested_goal('sql-injection')
    if mode == 'whole_target':
        cid = await candidate_for(rt)
    else:
        cid = await candidate_for(rt, ready=False)
    rt.registry.register(ReadPayloadsTool(rt.skills))
    aid = None

    def script():
        nonlocal aid
        yield 'load_skill', {'name': 'sql-injection'}
        started = json.loads((yield workflow('start_validation', candidate_id=cid)))
        aid = started['validation_context']['attempt_id']
        yield 'http', {'url': '/fixture?q=normal', 'phase': 'validation'}
        args = {'skill': 'sql-injection', 'file': 'payloads.txt', 'limit': 2}
        for _ in range(5):
            text = yield 'read_payloads', args
            assert not rt.workflow.attempts[aid].get('probing_stopped')
            page = json.loads(text.rsplit('\nContinuation: ', 1)[1])
            args = {**args, 'source_ref': page['source_ref'], 'start_char': page['next_start_char']}
        # Re-reading an already consumed range cannot replenish progress.
        for _ in range(4):
            yield 'read_payloads', {'skill': 'sql-injection', 'file': 'payloads.txt', 'limit': 2}
        assert rt.workflow.attempts[aid]['probing_stopped']
        yield workflow('record_result', candidate_id=cid, skill_name='sql-injection',
            outcome='insufficient-evidence', deferred_reason='Oracle not established; bounded local review complete.')

    model = InspectModel(script())
    rt.agent.set_client(model)
    trace = collect()
    await rt.agent.run('Continue the SQL injection assessment.', FakeSignal(), trace['sink'], AgentRunOptions(max_steps=14))
    assert not model.errors and model.consumed
    kinds = [e.metrics.get('progress_kind') for e in trace['events'] if e.type == 'workflow-progress' and e.stage == 'iteration_evaluated']
    assert kinds.count('reader_progress') == 5
    assert len(sent) == 1 and not rt.workflow.evidence and not rt.workflow.eligible_for_finding(cid)


@pytest.mark.parametrize('mode', ['direct', 'whole_target'])
async def test_synthesis_refreshes_persisted_result_and_distinguishes_unregistered_file(offline, tmp_path, mode: WorkflowMode):
    rt, sent = offline
    rt.workflow.objective = WorkflowObjective('offline-objective', mode, ORIGIN)
    rt.workflow.objective.add_requested_goal('sql-injection')
    cid = await candidate_for(rt, ready=mode == 'whole_target')
    await execute(rt, 'load_skill', {'name': 'sql-injection'})
    await execute(rt, 'workflow', {'action': 'start_validation', 'candidate_id': cid})
    await execute(rt, 'http', {'url': '/fixture?q=normal', 'phase': 'validation'})
    path = tmp_path / 'artifacts/sql-injection/proof.md'
    await execute(rt, 'file_write', {'path': str(path), 'content': 'Synthetic unresolved observations; not registered.'})
    stale = rt.agent._workflow_request_view('Continue.', rt.registry.as_llm_tools())
    working = deepcopy(rt.agent.history) + list(stale.blocks)
    model = FakeClient([ChatResponse(Message('assistant', 'Incomplete fixture assessment.'), 'stop')])
    rt.agent.set_client(model)
    await rt.agent._whole_target_synthesis(working, FakeSignal(), lambda _: None,
        thinking_enabled=False, reasoning_level=ReasoningLevel.OFF,
        requested_reasoning_level=ReasoningLevel.OFF, stop_reason='max_steps',
        instruction='Hard iteration limit reached; report the saved state.', max_steps=1)
    result = rt.workflow.latest_result(cid)
    assert result is not None and result.outcome == 'insufficient-evidence' and not result.evidence_refs
    assert path.is_file() and not rt.workflow.evidence
    request = model.requests[-1]
    assert request.tools is None
    # A new canonical projection after runtime closure, not stale validating state.
    rows = [m.content for m in request.messages if m.content.startswith('Untrusted recorded workflow data;')]
    assert len(rows) == 1 and f'result_id={result.result_id}' in rows[0]
    assert 'evidence_refs=none' in rows[0] and 'status=validating' not in rows[0]
    instructions = '\n'.join(m.content for m in request.messages if m.role == 'system')
    assert 'unregistered' in instructions and 'proof file' in instructions
    assert 'result_id' in instructions and 'evidence_refs' in instructions
    assert not rt.workflow.eligible_for_finding(cid) and len(sent) == 1


async def test_loaded_sqli_guidance_plans_before_probes_and_stops_after_exhaustion():
    skills = Skills()
    skills.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    loaded = ' '.join((await LoadSkillTool(skills).run({'name': 'sql-injection'})).split())
    for obligation in ('Read the applicable payload guidance before the first confirmation probe',
                       'Do not use an arbitrary nonmatching seed for an AND',
                       'Exhausted syntax adjustments are a finalization checkpoint',
                       'Do not spend finalization turns rereading',
                       'An unregistered proof file'):
        assert obligation.lower() in loaded.lower()
