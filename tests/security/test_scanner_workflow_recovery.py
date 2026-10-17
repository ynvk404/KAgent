"""Scanner retirement must close owned history without restoring source rights."""
from copy import deepcopy
from dataclasses import replace
import asyncio
import json

import pytest

from src.agent.agent import ExecutedToolCall, ToolCallResult, WholeTargetStallTracker
from src.llm.core.types import FunctionCall, ToolCall
from src.permission.network.grants import HTTPLimits
from src.permission.runtime.execution import ExecutionBlocked
from src.tools.workflow.workflow_tool import WorkflowTool
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from tests.integration.test_scanner_agent_handoff import agent_runtime
from tests.security.test_scanner_end_to_end import require_binaries, runtime, wire
from tests.state.test_scanner_state import job, state


def triage_runtime(tmp_path):
    rt = runtime(tmp_path / 'project', 'http://127.0.0.1:43210')
    rt.workflow, rt.job = state(), job(rt.root)
    rt.job.triage(rt.root, rt.job.sample_ids[:1], 'selected', 'Needs request context')
    rt.workflow.add_scanner_job(rt.job)
    rt.registry.register(WorkflowTool(rt.workflow, rt.target, evidence_root=rt.root))
    return rt


def restrict_source(rt, restriction):
    if restriction == 'shell':
        rt.policy.revoke('shell')
    elif restriction == 'network':
        rt.state.http_permissions.deny_session()
    else:
        grant = rt.state.http_permissions.activate(rt.target.base_url(), HTTPLimits())
        rt.state.http_permissions.revoke(grant.id)


def triage_args(rt, disposition='deferred', **extra):
    return {'action': 'triage_scanner_results', 'job_id': rt.job.job_id,
            'record_ids': rt.job.sample_ids[:1], 'scanner_disposition': disposition,
            'scanner_reason': 'Source unavailable; selected observation has not been analyzed', **extra}


@pytest.mark.parametrize('restriction', ['shell', 'network', 'origin'])
@pytest.mark.parametrize('disposition', ['deferred', 'dropped'])
@pytest.mark.parametrize('missing', [False, True])
async def test_selected_retirement_after_source_revocation_keeps_permissions_and_evidence_honest(
    tmp_path, restriction, disposition, missing,
):
    rt = triage_runtime(tmp_path)
    if missing:
        (rt.root / rt.job.artifacts['normalized']).unlink()
    restrict_source(rt, restriction)
    authority = (rt.policy.stamp(), frozenset(rt.policy.revoked), rt.state.http_permissions.denied)
    execution = deepcopy((rt.job.execution, rt.job.parse, rt.job.counts))
    result = await rt.registry.execute('workflow', triage_args(rt, disposition), None, rt.prompter)
    assert json.loads(result)['ok'] is True
    assert rt.job.unresolved_selected == 0
    assert rt.job.dispositions[rt.job.sample_ids[0]]['disposition'] == disposition
    assert (rt.job.execution, rt.job.parse, rt.job.counts) == execution
    assert (rt.policy.stamp(), frozenset(rt.policy.revoked), rt.state.http_permissions.denied) == authority
    assert not rt.operator.ask.called and rt.policy.active == 0
    assert not rt.workflow.candidates and not rt.workflow.validation_results
    if missing:
        assert rt.job.artifacts['retrieval_error'] == 'missing_artifact'
    with pytest.raises(ExecutionBlocked):
        await rt.registry.execute('shell', {'scanner': 'ffuf',
            'url': rt.target.base_url() + '/FUZZ', 'wordlist_id': 'fixture'}, None, rt.prompter)


@pytest.mark.parametrize('disposition,selection,remaining', [
    ('handled', 'selected', False), ('selected', 'selected', False),
    ('deferred', 'new', False), ('dropped', 'mixed', False), ('deferred', 'none', True),
])
async def test_source_revocation_cannot_create_membership_or_claim_analysis(
    tmp_path, disposition, selection, remaining,
):
    rt = triage_runtime(tmp_path)
    restrict_source(rt, 'shell')
    before = deepcopy(rt.job.to_dict())
    ids = {'selected': rt.job.sample_ids[:1], 'new': rt.job.sample_ids[1:2],
           'mixed': rt.job.sample_ids[:2], 'none': []}[selection]
    result = await rt.registry.execute('workflow', triage_args(rt, disposition,
        record_ids=ids, remaining=remaining), None, rt.prompter)
    assert result.status == 'error' and rt.job.to_dict() == before


@pytest.mark.parametrize('revoked', ['*', 'workflow'])
async def test_retirement_does_not_bypass_registry_session_or_workflow_revocation(tmp_path, revoked):
    rt = triage_runtime(tmp_path)
    rt.policy.revoke(revoked)
    before = deepcopy(rt.job.to_dict())
    with pytest.raises(ExecutionBlocked):
        await rt.registry.execute('workflow', triage_args(rt), None, rt.prompter)
    assert rt.job.to_dict() == before


@pytest.mark.parametrize('owner', ['target', 'objective'])
async def test_revoked_source_retirement_still_requires_current_job_ownership(tmp_path, owner):
    rt = triage_runtime(tmp_path)
    restrict_source(rt, 'shell')
    if owner == 'target':
        rt.target.set_base_url('http://127.0.0.1:43211')
    else:
        rt.workflow.objective.id = 'different-objective'
    before = deepcopy(rt.job.to_dict())
    result = await rt.registry.execute('workflow', triage_args(rt), None, rt.prompter)
    assert result.status == 'error' and 'current target/objective' in str(result)
    assert rt.job.to_dict() == before


@pytest.mark.parametrize('damage', ['dataset', 'missing_dataset_corrupt_manifest'])
async def test_retirement_after_revocation_still_rejects_integrity_failures(tmp_path, damage):
    rt = triage_runtime(tmp_path)
    if damage == 'dataset':
        (rt.root / rt.job.artifacts['normalized']).write_text('tamper')
    else:
        (rt.root / rt.job.artifacts['normalized']).unlink()
        (rt.root / rt.job.artifacts['manifest']).write_text('tamper')
    restrict_source(rt, 'shell')
    before = deepcopy(rt.job.to_dict())
    result = await rt.registry.execute('workflow', triage_args(rt), None, rt.prompter)
    assert result.status == 'error' and 'integrity failure' in str(result)
    assert rt.job.to_dict() == before and rt.job.unresolved_selected == 1


@pytest.mark.parametrize('mutation', ['tcp_add', 'tcp_remove', 'scope_reset', 'http_reset'])
async def test_live_scope_change_closes_running_checkpoint_without_late_observations(tmp_path, wire, mutation):
    require_binaries()
    origin, _ = wire
    rt = agent_runtime(tmp_path, origin, FakeClient([]), enumeration=True)
    port = str(rt.target.origin().port)
    if mutation in {'tcp_remove', 'scope_reset'}:
        rt.agent.update_tcp_scope('127.0.0.1', port)
    dict(rt.binding.wordlists)['fixture'].write_text(''.join(f'slow{i}\n' for i in range(100)))
    tc = ToolCall('scope-change', FunctionCall('shell', json.dumps({'scanner': 'ffuf',
        'url': origin + '/FUZZ', 'wordlist_id': 'fixture', 'threads': 1, 'rate': 1})))
    parsed = rt.agent.parse_tool_call(tc)
    rt.agent._tool_call_event(tc, parsed)
    started = asyncio.Event()
    def emit(event):
        if event['type'] == 'tool-started':
            started.set()
    task = asyncio.create_task(rt.agent.run_parsed_tool_call(tc, parsed, FakeSignal(), emit=emit))
    try:
        await asyncio.wait_for(started.wait(), 4)
        running = next(iter(rt.agent.workflow.scanner_jobs.values()))
        assert running.execution['status'] == 'running' and not task.done()
        if mutation == 'tcp_add':
            rt.agent.update_tcp_scope('127.0.0.1', port)
        elif mutation == 'tcp_remove':
            rt.agent.update_tcp_scope('127.0.0.1', remove=True)
        elif mutation == 'scope_reset':
            rt.agent.reset_scope_to_target()
        else:
            rt.state.http_permissions.reset()
        if mutation == 'scope_reset':
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 5)
            result = None
        else:
            result = await asyncio.wait_for(task, 5)
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    terminal = rt.agent.workflow.scanner_jobs[running.job_id]
    if result is not None:
        assert terminal.execution == json.loads(result.result)['execution']
    assert terminal.execution['status'] in {'failed', 'cancelled'}
    assert terminal.parse['coverage_complete'] is False and terminal.counts['unique_records'] == 0
    assert not rt.agent.workflow.scanner_observations and not rt.agent.result_retention.references
    assert not rt.binding.runtime.task and rt.policy.active == 0
    await rt.agent.save()
    assert rt.agent.store.load().workflow.scanner_jobs[running.job_id].execution == terminal.execution
    # Closed history can be evicted; repeated scope changes must not fill all
    # 32 slots with checkpoints for processes that no longer exist.
    for index in range(31):
        assert rt.agent.workflow.add_scanner_job(replace(terminal,
            job_id='scan_' + f'{index:032x}', execution={'status': 'running'}))
    assert rt.agent.workflow.add_scanner_job(replace(terminal, job_id='scan_' + 'f' * 32))
    assert running.job_id not in rt.agent.workflow.scanner_jobs


def test_repeated_scanner_triage_cannot_replenish_the_stall_budget(tmp_path):
    workflow, row = state(), job(tmp_path)
    workflow.add_scanner_job(row)
    tracker = WholeTargetStallTracker()
    outcomes = []
    for index in range(12):
        before = workflow.progress_facts()
        row.triage(tmp_path, row.sample_ids[:1], 'selected' if index % 2 == 0 else 'deferred',
                   'Same record; no new observations')
        outcomes.append(tracker.record_iteration(new_facts=workflow.progress_facts() - before,
                                                 activity_fingerprints=[]))
    assert outcomes[:2] == ['structured_progress'] * 2
    assert outcomes[2:] == ['no_progress'] * 10
    assert tracker.consecutive_no_progress == 10
    tracker.set_phase('input_analysis')
    before = workflow.progress_facts()
    row.triage(tmp_path, row.sample_ids[:1], 'selected', 'Revisiting the same record')
    assert tracker.record_iteration(new_facts=workflow.progress_facts() - before,
                                    activity_fingerprints=[]) == 'no_progress'
    before = workflow.progress_facts()
    row.triage(tmp_path, row.sample_ids[1:2], 'selected', 'A different record needs context')
    assert tracker.record_iteration(new_facts=workflow.progress_facts() - before,
                                    activity_fingerprints=[]) == 'structured_progress'
    assert tracker.consecutive_no_progress == 0


def test_new_reader_content_still_counts_when_a_state_fact_is_reintroduced():
    tracker = WholeTargetStallTracker()
    fact = frozenset({'previously-credited-triage'})
    assert tracker.record_iteration(new_facts=fact, activity_fingerprints=[]) == 'structured_progress'
    text = '# fixture\nnew content\nContinuation: ' + json.dumps({
        'sha256': 'a' * 64, 'start_char': 0, 'end_char': 10, 'source_chars': 10})
    call = ExecutedToolCall('read_payloads', {}, True, ToolCallResult(text, '', 0))
    assert tracker.record_validation_batch([call], new_facts=fact,
        target_base_url=None) == 'reader_progress'
    assert tracker.record_validation_batch([call], new_facts=fact,
        target_base_url=None) == 'no_progress'
