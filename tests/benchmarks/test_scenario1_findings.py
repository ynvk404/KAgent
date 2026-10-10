"""Offline finding exports use actual production assessments and immutable runs."""
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from benchmarks.common.contracts import digest, file_hash, read_json, write_new
from benchmarks.scenario1.core.canonical import projection
from benchmarks.scenario1.core.evaluate import evaluate
from benchmarks.scenario1.core.runner import run
from benchmarks.scenario1.core.storage import resolve_run
from benchmarks.scenario1.reporting.projection import json_bytes
from benchmarks.scenario1.reporting.writer import write_report
from src.findings.store import Finding, render
from src.workflow.review import confirmation_binding
from src.workflow.state import validation_result_fingerprint
from tests.benchmarks.test_scenario1 import (
    ScriptedClient, execute_case, isolated_project_environment, mock_http, op, settings, single_manifest,
)


@pytest.fixture
async def finding_run(tmp_path, monkeypatch, op, settings, mock_http, request):
    workspace = tmp_path / 'fixture-workspace'
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    execution = await execute_case(op, settings, workspace, 'run', 'ex',
                                   ScriptedClient(getattr(request, 'param', 'confirmed')))
    raw = asdict(execution)
    state = projection(raw['result']['workflow'])
    cid = raw['result']['candidate_id']
    latest = state.latest_result(cid)
    assert latest is not None
    finding = Finding(title='Confirmed fixture', severity='low',
        url=settings.target + '/benchmark/fixture', method='GET', parameter='q',
        observed_impact=latest.assessment['observed_impact'], potential_impact='No additional impact assessed.',
        candidate_id=cid, evidence_refs=latest.evidence_refs, canonical_class=state.candidates[cid].candidate_class,
        confirmation_binding=confirmation_binding(state, cid), assessment_source=latest.assessment_source,
        assessment_result_id=latest.result_id, assessment_attempt_id=latest.attempt_id,
        binding_version=latest.assessment_contract_version, createdAt=latest.recorded_at or '')
    def build(kind='persisted', report=None):
        # Each invocation is an independent run; no existing snapshot is rewritten.
        import copy
        data = copy.deepcopy(raw)
        wf = data['result']['workflow']
        if kind != 'unpersisted':
            wf['persisted_findings'][cid] = validation_result_fingerprint(latest)
        if kind == 'old-fingerprint':
            wf['persisted_findings'][cid] = '0' * 64
        source = render(report or finding).encode()
        def launcher(payload, _):
            data['execution_id'] = payload['execution_id']
            data['result']['execution_id'] = payload['execution_id']
            directory = Path(payload['workspace']) / 'artifacts/findings'
            if kind == 'other-workspace':
                directory = Path(payload['workspace']).parent / 'other-execution' / 'artifacts/findings'
            directory.mkdir(parents=True)
            if kind != 'missing':
                path = directory / 'fixture.md'
                path.write_bytes(source)
                if kind == 'ambiguous':
                    (directory / 'duplicate.md').write_bytes(source)
                elif kind == 'symlink-file':
                    path.unlink()
                    path.symlink_to(workspace / 'external.md')
                    (workspace / 'external.md').write_bytes(source)
                elif kind == 'symlink-directory':
                    external = workspace / 'external-findings'
                    external.mkdir()
                    path.rename(external / 'fixture.md')
                    directory.rmdir()
                    directory.symlink_to(external, target_is_directory=True)
                elif kind == 'hardlink-file':
                    (directory / 'duplicate.md').hardlink_to(path)
            write_new(Path(payload['output']), data)
            return 0, False
        public = tmp_path / ('public-' + kind)
        root = run(single_manifest(op, settings), settings, public, launcher=launcher)
        evaluate(root)
        return root, public
    return build, finding


@pytest.mark.asyncio
async def test_finding_export_redacts_links_and_preserves_sources(finding_run, op, tmp_path):
    build, finding = finding_run
    secret = 'sk-' + 'S' * 40
    report = replace(finding, title=f'Finding {secret}', payload='password=short',
                     curl="curl -H 'Cookie: sid=cookie-secret' http://127.0.0.1/fixture",
                     remediation=f'Inspect {tmp_path}/private/code.py; api_key={secret}')
    root, public = build(report=report)
    before = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    baseline = evaluate(root, publish=False)
    write_report(root)
    case = read_json(public / 'results' / f'{op.case_id}.json')
    assert case['finding'] == {'status': 'persisted', 'report_ref': f'../findings/{op.case_id}.md', 'reason': None}
    assert case['persisted_finding'] is True
    assert {p.name for p in public.iterdir()} == {'report', 'results', 'findings'}
    exported = public / 'results' / case['finding']['report_ref']
    content = exported.read_text()
    assert '## Observed impact' in content and finding.observed_impact in content
    assert secret not in content and 'cookie-secret' not in content and 'password=short' not in content
    assert str(tmp_path) not in content and finding.candidate_id not in content
    index = read_json(public / 'results/index.json')
    assert index['files'][f'findings/{op.case_id}.md'] == file_hash(exported)
    assert resolve_run(public) == root
    assert evaluate(root, publish=False) == baseline
    assert all((root / ref).read_bytes() == value for ref, value in before.items())


@pytest.mark.asyncio
@pytest.mark.parametrize('kind,reason', [
    ('unpersisted', 'not-persisted-for-current-result'), ('missing', 'report-missing'),
    ('ambiguous', 'report-ambiguous'), ('stale', 'report-stale'),
    ('old-fingerprint', 'not-persisted-for-current-result'), ('other-workspace', 'report-missing'),
])
async def test_missing_or_stale_finding_is_pending(finding_run, op, kind, reason):
    build, finding = finding_run
    report = replace(finding, assessment_result_id='historical-result') if kind == 'stale' else finding
    root, public = build(kind, report)
    write_report(root)
    case = read_json(public / 'results' / f'{op.case_id}.json')
    assert case['agent_outcome'] == 'confirmed'
    assert case['finding'] == {'status': 'pending', 'report_ref': None, 'reason': reason}
    assert case['persisted_finding'] is False
    assert not (public / 'findings').exists()
    assert resolve_run(public) == root


@pytest.mark.asyncio
@pytest.mark.parametrize('finding_run', ['not-confirmed'], indirect=True)
async def test_negative_assessment_never_exports_a_finding(finding_run, op):
    build, _ = finding_run
    root, public = build()
    write_report(root)
    case = read_json(public / 'results' / f'{op.case_id}.json')
    assert case['finding'] == {'status': 'not-applicable', 'report_ref': None, 'reason': None}
    assert case['persisted_finding'] is False
    assert not (public / 'findings').exists()
    assert resolve_run(public) == root


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['symlink-file', 'symlink-directory', 'hardlink-file'])
async def test_unsafe_finding_does_not_publish(finding_run, kind):
    build, _ = finding_run
    root, public = build(kind)
    with pytest.raises(ValueError, match='unsafe finding'):
        write_report(root)
    assert not public.exists()


@pytest.mark.asyncio
async def test_finding_tamper_cannot_be_blessed_by_rehashing_index(finding_run, op):
    build, _ = finding_run
    root, public = build()
    write_report(root)
    ref = f'findings/{op.case_id}.md'
    (public / ref).write_text('# Invented finding\n')
    index = read_json(public / 'results/index.json')
    index['files'][ref] = file_hash(public / ref)
    index['binding'] = digest({k: v for k, v in index.items() if k != 'binding'})
    (public / 'results/index.json').write_bytes(json_bytes(index))
    with pytest.raises(ValueError, match='public/canonical projection binding mismatch'):
        resolve_run(public)
