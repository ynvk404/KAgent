"""Regression tests for conclusion review transactions, without variant metadata."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.coverage.store import CoverageStore
from src.findings.store import Store, read_report
from src.permission.permission import Decision
from src.permission.runtime.observations import ObservationStore
from src.skills.registry import Registry as Skills
from src.tools.workflow.finding import ConfirmFindingTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.ui.commands.result_review import review_result
from src.workflow.review import review_snapshot
from src.workflow.state import Candidate, ValidationResult, WorkflowState, validation_result_fingerprint
from tests.security.test_execution_policy import runtime, ORIGIN


async def setup_review(runtime, tmp_path, *, coverage=None):
    registry, prompter, _, operator, _, _, _ = runtime
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(
        candidate_class='access-control', target=ORIGIN,
        endpoint='/fixture', method='GET', parameter='id',
    ))
    skills = Skills()
    skills.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    tool = WorkflowTool(state, skills=skills, evidence_root=tmp_path, coverage=coverage)
    registry.register(tool)
    source = tmp_path / 'proof.txt'
    source.write_text('Designated private fixture resource returned to a principal without access; authorized and no-session controls recorded. No credentials retained.')
    result = await registry.execute('workflow', {
        'action': 'record_evidence', 'candidate_id': candidate.id, 'evidence_path': source.name,
    }, None, prompter)
    ref = json.loads(result)['evidence']['id']
    state.add_validation_result(ValidationResult(
        candidate.id, 'access-control', 'insufficient-evidence',
        evidence_refs=[ref], repeatable=True, notes='Original review context.',
    ))
    output = []
    app = SimpleNamespace(agent=SimpleNamespace(
        prompter=prompter, workflow=state, tools=registry, skills=skills, save=AsyncMock(),
    ), dispatch=output.append)
    operator.decision = Decision.ALLOW_ONCE
    return app, state, candidate, tool, ref, output


def command(candidate, outcome='confirmed', severity='low'):
    return [candidate.id, outcome, severity, 'Observed fixture boundary failure.']


def certificate(policy, candidate, ref):
    return policy.observations.result(candidate.id, (ref,), policy.engagement.http_permissions.epoch, candidate)


@pytest.mark.asyncio
@pytest.mark.parametrize('outcome', ['confirmed', 'not-confirmed'])
async def test_certificate_published_only_after_workflow_and_session_commit(runtime, tmp_path, outcome):
    _, _, policy, operator, sent, _, _ = runtime
    app, state, candidate, _, ref, output = await setup_review(runtime, tmp_path)
    path = tmp_path / 'observations.json'
    policy.observations.attach_storage(path)

    async def save():
        latest = state.latest_result(candidate.id)
        assert latest is not None and latest.outcome == outcome
        assert latest.notes == 'Original review context.'
        assert candidate.id not in policy.observations._results
        assert not path.exists()
    app.agent.save.side_effect = save
    await review_result(app, command(candidate, outcome))
    assert output[-1].entry.kind == 'system', output[-1]
    trusted = certificate(policy, candidate, ref)
    assert trusted is not None and trusted.outcome == outcome
    assert [r.tool for r in operator.requests] == ['review_result']
    assert operator.requests[0].no_session_cache
    assert 'Exact result:' in operator.requests[0].detail
    assert not policy.observations._reviews and policy.active == 0 and not sent
    raw = json.loads(path.read_text())
    assert set(raw) == {'observations', 'results'}
    restored = ObservationStore()
    restored.attach_storage(path)
    assert restored.result(candidate.id, (ref,), 'resumed-epoch', candidate) == trusted


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['record-error', 'coverage-error', 'save-error', 'persist-error', 'denied', 'cancel'])
async def test_review_failure_never_publishes_new_certificate(runtime, tmp_path, monkeypatch, failure):
    _, _, policy, operator, _, _, _ = runtime
    coverage = CoverageStore(str(tmp_path / 'coverage.json')) if failure == 'coverage-error' else None
    app, _, candidate, tool, ref, output = await setup_review(runtime, tmp_path, coverage=coverage)
    if failure == 'record-error':
        monkeypatch.setattr(tool, 'run', AsyncMock(return_value='error: record failed'))
    elif failure == 'coverage-error':
        monkeypatch.setattr(tool, '_sync_coverage', AsyncMock(side_effect=OSError('coverage failed')))
    elif failure == 'save-error':
        app.agent.save.side_effect = OSError('session failed')
    elif failure == 'persist-error':
        monkeypatch.setattr(policy.observations, 'persist', lambda: (_ for _ in ()).throw(OSError('owner failed')))
    elif failure == 'denied':
        operator.decision = Decision.DENY
    else:
        operator.ask = AsyncMock(side_effect=asyncio.CancelledError)
    if failure == 'cancel':
        with pytest.raises(asyncio.CancelledError):
            await review_result(app, command(candidate))
    else:
        await review_result(app, command(candidate))
        assert output[-1].entry.kind == 'error'
    assert certificate(policy, candidate, ref) is None
    assert candidate.id not in policy.observations._results
    assert not policy.observations._reviews and policy.active == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('change', ['new-result', 'notes', 'identical-retest', 'proof', 'policy', 'candidate'])
async def test_changes_during_dialog_reject_stale_conclusion(runtime, tmp_path, change):
    _, _, policy, operator, _, _, _ = runtime
    app, state, candidate, _, ref, output = await setup_review(runtime, tmp_path)
    opened, release = asyncio.Event(), asyncio.Event()
    async def delayed(request, signal=None):
        operator.requests.append(request)
        opened.set()
        await release.wait()
        return Decision.ALLOW_ONCE
    operator.ask = delayed
    task = asyncio.create_task(review_result(app, command(candidate)))
    await asyncio.wait_for(opened.wait(), 2)
    latest = state.latest_result(candidate.id)
    assert latest is not None
    fingerprint = validation_result_fingerprint(latest)
    if change == 'new-result':
        state.add_validation_result(ValidationResult(candidate.id, 'access-control', 'deferred', evidence_refs=[ref]), force=True)
    elif change == 'notes':
        latest.notes = 'Changed while dialog open.'
        assert validation_result_fingerprint(latest) == fingerprint
    elif change == 'identical-retest':
        repeated = ValidationResult.from_dict(latest.to_dict())
        assert repeated is not None
        state.add_validation_result(repeated, force=True)
        current = state.latest_result(candidate.id)
        assert current is not None and validation_result_fingerprint(current) == fingerprint
    elif change == 'policy':
        policy.revoke('workflow')
    elif change == 'candidate':
        candidate.auth_context_ref = 'different-principal-context'
    else:
        artifact = tmp_path / state.evidence[ref].path
        artifact.chmod(0o600)
        artifact.write_text('Changed immutable proof.')
    release.set()
    await task
    assert output[-1].entry.kind == 'error'
    assert certificate(policy, candidate, ref) is None
    assert not policy.observations._reviews and policy.active == 0


@pytest.mark.asyncio
async def test_overlapping_reviews_newest_wins_without_stale_overwrite(runtime, tmp_path):
    _, _, policy, operator, _, _, _ = runtime
    app, state, candidate, _, ref, output = await setup_review(runtime, tmp_path)
    opened, release = asyncio.Event(), asyncio.Event()
    calls = 0
    async def ask(request, signal=None):
        nonlocal calls
        calls += 1
        if calls == 1:
            opened.set()
            await release.wait()
        return Decision.ALLOW_ONCE
    operator.ask = ask
    first = asyncio.create_task(review_result(app, command(candidate, 'confirmed')))
    await asyncio.wait_for(opened.wait(), 2)
    await review_result(app, command(candidate, 'not-confirmed'))
    committed = review_snapshot(state, candidate.id)
    trusted = certificate(policy, candidate, ref)
    assert trusted is not None and trusted.outcome == 'not-confirmed'
    release.set()
    await first
    assert output[-1].entry.kind == 'error'
    assert review_snapshot(state, candidate.id) == committed
    assert certificate(policy, candidate, ref) == trusted
    assert not policy.observations._reviews and policy.active == 0


@pytest.mark.asyncio
async def test_cancellation_during_save_does_not_leak_staged_certificate(runtime, tmp_path):
    _, _, policy, _, _, _, _ = runtime
    app, _, candidate, _, ref, _ = await setup_review(runtime, tmp_path)
    saving = asyncio.Event()
    async def save():
        saving.set()
        await asyncio.Event().wait()
    app.agent.save = save
    task = asyncio.create_task(review_result(app, command(candidate)))
    await asyncio.wait_for(saving.wait(), 2)
    assert certificate(policy, candidate, ref) is None
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert certificate(policy, candidate, ref) is None
    assert not policy.observations._reviews and policy.active == 0


@pytest.mark.asyncio
async def test_new_result_during_record_result_proof_read_is_not_overwritten(runtime, tmp_path, monkeypatch):
    _, _, policy, _, _, _, _ = runtime
    app, state, candidate, _, ref, output = await setup_review(runtime, tmp_path)
    import src.tools.workflow.workflow_tool as workflow_module
    original = workflow_module.verify_evidence_reads
    reading, release = asyncio.Event(), asyncio.Event()
    async def delayed(*args, **kwargs):
        reading.set()
        await release.wait()
        return await original(*args, **kwargs)
    monkeypatch.setattr(workflow_module, 'verify_evidence_reads', delayed)
    task = asyncio.create_task(review_result(app, command(candidate)))
    await asyncio.wait_for(reading.wait(), 2)
    changed = ValidationResult(candidate.id, 'access-control', 'deferred', evidence_refs=[ref], notes='New conclusion.')
    state.add_validation_result(changed, force=True)
    release.set()
    await task
    assert state.latest_result(candidate.id) is changed
    assert output[-1].entry.kind == 'error' and certificate(policy, candidate, ref) is None


@pytest.mark.asyncio
async def test_new_result_during_session_save_prevents_certificate_publish(runtime, tmp_path):
    _, _, policy, _, _, _, _ = runtime
    app, state, candidate, _, ref, output = await setup_review(runtime, tmp_path)
    async def save():
        state.add_validation_result(ValidationResult(candidate.id, 'access-control', 'deferred', evidence_refs=[ref]), force=True)
    app.agent.save.side_effect = save
    await review_result(app, command(candidate))
    assert output[-1].entry.kind == 'error' and certificate(policy, candidate, ref) is None


@pytest.mark.asyncio
async def test_failed_owner_commit_preserves_previous_certificate(runtime, tmp_path, monkeypatch):
    _, _, policy, _, _, _, _ = runtime
    app, _, candidate, _, ref, output = await setup_review(runtime, tmp_path)
    await review_result(app, command(candidate, 'not-confirmed'))
    old = certificate(policy, candidate, ref)
    assert old is not None and old.outcome == 'not-confirmed'
    monkeypatch.setattr(policy.observations, 'persist', lambda: (_ for _ in ()).throw(OSError('owner failed')))
    await review_result(app, command(candidate, 'confirmed'))
    assert output[-1].entry.kind == 'error'
    assert certificate(policy, candidate, ref) == old
    assert not policy.observations._reviews


def test_operator_result_has_no_immediate_publication_api(runtime):
    _, _, policy, _, _, _, _ = runtime

    assert getattr(policy.observations, 'operator_result', None) is None


@pytest.mark.asyncio
async def test_finding_retry_uses_persisted_snapshot_for_notifier_and_tool_result(runtime, tmp_path, monkeypatch):
    registry, prompter, _, _, _, _, _ = runtime
    app, state, candidate, _, _, _ = await setup_review(runtime, tmp_path)
    await review_result(app, command(candidate))
    notified = []
    store = Store(project_directory=tmp_path)
    finding_tool = ConfirmFindingTool(store, lambda f, path: notified.append((f, path)), state)
    registry.register(finding_tool)
    args = {'candidate_id': candidate.id, 'title': 'Original finding', 'url': ORIGIN + '/fixture',
            'severity': 'low', 'observed_impact': 'Observed fixture access.', 'potential_impact': 'No additional impact assessed.'}
    first = await registry.execute('confirm_finding', args, None, prompter)
    persisted = read_report(Path(notified[-1][1]))
    content = Path(notified[-1][1]).read_text()
    assert notified[-1][0] == persisted and persisted.cwe is None
    await review_result(app, command(candidate, severity='high'))
    import src.tools.workflow.finding as finding_module
    monkeypatch.setattr(finding_module, 'classify', lambda _: SimpleNamespace(type='Changed taxonomy', cwe=['CWE-999'], owasp=[]))
    retry = await registry.execute('confirm_finding', {**args, 'title': 'New proposed title'}, None, prompter)
    assert retry == first and 'Original finding' in retry and 'CWE: none' in retry
    assert notified[-1][0] == persisted and Path(notified[-1][1]).read_text() == content
    assert len(list(Path(notified[-1][1]).parent.glob('*.md'))) == 1


@pytest.mark.asyncio
async def test_finding_rejects_result_changed_during_evidence_read(runtime, tmp_path, monkeypatch):
    registry, prompter, _, _, _, _, _ = runtime
    app, state, candidate, _, _, _ = await setup_review(runtime, tmp_path)
    await review_result(app, command(candidate))
    notified = []
    store = Store(project_directory=tmp_path)
    finding_tool = ConfirmFindingTool(store, lambda *args: notified.append(args), state)
    registry.register(finding_tool)
    import src.tools.workflow.finding as finding_module
    original = finding_module.verify_evidence_reads
    async def changed(*args, **kwargs):
        result = await original(*args, **kwargs)
        latest = state.latest_result(candidate.id)
        assert latest is not None
        latest.notes = 'Result changed during finalization.'
        return result
    monkeypatch.setattr(finding_module, 'verify_evidence_reads', changed)
    with pytest.raises(ValueError, match='result changed during finalization'):
        await registry.execute('confirm_finding', {
            'candidate_id': candidate.id, 'title': 'Finding', 'url': ORIGIN + '/fixture',
            'severity': 'low', 'observed_impact': 'Observed access.', 'potential_impact': 'No additional impact assessed.',
        }, None, prompter)
    assert not notified and not list(store.dir.glob('*.md'))


@pytest.mark.asyncio
async def test_finding_result_change_during_store_save_is_not_finalized(runtime, tmp_path, monkeypatch):
    registry, prompter, _, _, _, _, _ = runtime
    app, state, candidate, _, ref, _ = await setup_review(runtime, tmp_path)
    await review_result(app, command(candidate))
    notified = []
    store = Store(project_directory=tmp_path)
    finding_tool = ConfirmFindingTool(store, lambda *args: notified.append(args), state)
    registry.register(finding_tool)

    saving, release = asyncio.Event(), asyncio.Event()
    original_save = store.save

    async def delayed_save(finding):
        saving.set()
        await release.wait()
        return await original_save(finding)

    monkeypatch.setattr(store, 'save', delayed_save)
    task = asyncio.create_task(registry.execute('confirm_finding', {
        'candidate_id': candidate.id, 'title': 'Finding', 'url': ORIGIN + '/fixture',
        'severity': 'low', 'observed_impact': 'Observed fixture access.',
        'potential_impact': 'No additional impact assessed.',
    }, None, prompter))
    await asyncio.wait_for(saving.wait(), 2)

    state.add_validation_result(ValidationResult(
        candidate.id, 'access-control', 'confirmed', evidence_refs=[ref],
        notes='Result replaced while report save was pending.',
    ), force=True)
    release.set()

    with pytest.raises(ValueError, match='result changed during finalization'):
        await task
    assert not notified
    assert len(list(store.dir.glob('*.md'))) == 1
    assert not state.finding_is_persisted(candidate.id)


@pytest.mark.asyncio
async def test_finding_evidence_change_during_store_save_is_not_notified(runtime, tmp_path, monkeypatch):
    registry, prompter, _, _, _, _, _ = runtime
    app, state, candidate, _, ref, _ = await setup_review(runtime, tmp_path)
    await review_result(app, command(candidate))
    notified = []
    store = Store(project_directory=tmp_path)
    finding_tool = ConfirmFindingTool(store, lambda *args: notified.append(args), state)
    registry.register(finding_tool)

    saving, release = asyncio.Event(), asyncio.Event()
    original_save = store.save

    async def delayed_save(finding):
        saving.set()
        await release.wait()
        return await original_save(finding)

    monkeypatch.setattr(store, 'save', delayed_save)
    task = asyncio.create_task(registry.execute('confirm_finding', {
        'candidate_id': candidate.id, 'title': 'Finding', 'url': ORIGIN + '/fixture',
        'severity': 'low', 'observed_impact': 'Observed fixture access.',
        'potential_impact': 'No additional impact assessed.',
    }, None, prompter))
    await asyncio.wait_for(saving.wait(), 2)

    proof_path = tmp_path / state.evidence[ref].path
    proof_path.chmod(0o600)
    proof_path.write_text('Evidence replaced while report save was pending.')
    release.set()

    with pytest.raises(ValueError, match='evidence artifact changed or is unavailable'):
        await task
    assert not notified
    assert len(list(store.dir.glob('*.md'))) == 1
    assert not state.finding_is_persisted(candidate.id)
