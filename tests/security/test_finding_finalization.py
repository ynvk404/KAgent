"""Finding finalization through native assessments, independent of manual commands."""
import asyncio
from dataclasses import replace
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.findings.store import Store, read_report
from src.skills.registry import Skill
from src.tools.workflow.finding import ConfirmFindingTool
from src.workflow.state import ValidationResult
from src.workflow.assessment import accepted_result, seal
from tests.security.test_agent_assessment import setup
from tests.security.test_execution_policy import runtime, ORIGIN


async def confirmed_fixture(runtime, tmp_path):
    # Keep broad-class/no-CWE persistence coverage with a test-only validator.
    validator = Skill(
        name="access-control", description="Synthetic finding finalization validator",
        tools=["http", "workflow", "confirm_finding"],
        disable_model_invocation=False, path="/fixture/access-control/SKILL.md",
        body="", stage="validation", candidate_classes=["access-control"],
    )
    state, candidate, tool, args, _ = await setup(
        runtime, tmp_path, candidate_class="access-control", extra_skills=(validator,),
    )
    args["skill_name"] = "access-control"
    result = await runtime[0].execute("workflow", args, None, runtime[1])
    assert not result.startswith("error:"), result
    return state, candidate, tool, args


@pytest.mark.asyncio
async def test_finding_retry_uses_persisted_snapshot_for_notifier_and_tool_result(runtime, tmp_path, monkeypatch):
    registry, prompter, _, _, _, _, _ = runtime
    state, candidate, _, _ = await confirmed_fixture(runtime, tmp_path)
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
    previous = state.latest_result(candidate.id)
    assert previous is not None
    # Consumer-only state fixture: an independently persisted newer assessment.
    revision = replace(previous, result_id="result_" + uuid.uuid4().hex,
        supersedes=previous.result_id, assessment={**previous.assessment, "severity": "high"})
    revision.assessment_binding = seal(revision)
    state.add_validation_result(revision, force=True)
    assert accepted_result(state, candidate, revision, runtime[2])
    import src.tools.workflow.finding as finding_module
    monkeypatch.setattr(finding_module, 'classify', lambda _: SimpleNamespace(type='Changed taxonomy', cwe=['CWE-999'], owasp=[]))
    with pytest.raises(ValueError, match='Historical report'):
        await registry.execute('confirm_finding', {**args, 'title': 'New proposed title'}, None, prompter)
    assert not state.finding_is_persisted(candidate.id)
    assert notified[-1][0] == persisted and Path(notified[-1][1]).read_text() == content
    assert len(list(Path(notified[-1][1]).parent.glob('*.md'))) == 1



@pytest.mark.asyncio
async def test_finding_rejects_result_changed_during_evidence_read(runtime, tmp_path, monkeypatch):
    registry, prompter, _, _, _, _, _ = runtime
    state, candidate, _, _ = await confirmed_fixture(runtime, tmp_path)
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
    state, candidate, _, _args = await confirmed_fixture(runtime, tmp_path)
    ref = _args["evidence_refs"][0]
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
    state, candidate, _, _args = await confirmed_fixture(runtime, tmp_path)
    ref = _args["evidence_refs"][0]
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

