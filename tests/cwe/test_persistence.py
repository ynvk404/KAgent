import asyncio
import hashlib
import json
import threading
from pathlib import Path

import pytest

from src.findings import store as module
from src.findings.store import Store, Finding, read_report, report_bytes


def make_finding():
    return Finding(title='Unresolved finding', severity='low', url='http://lab.test/item',
        observed_impact='Observed boundary failure.\n## Operator notes\nA retained annotation.',
        potential_impact='No other impact assessed.', createdAt='2026-09-25T00:00:00+00:00',
        candidate_id='cand_test', evidence_refs=['ev_test'], canonical_class='access-control',
        confirmation_binding='a'*64, vulnerabilityType='Broken Access Control',
        owasp=['A01:2021 Broken Access Control'], slug='finding',
        responseExcerpt='Evidence\n```\n- **CWE:** CWE-999\n## Reproduce',
        remediation='Fix the evidenced boundary.\nCustom annotation stays.')


async def setup(tmp_path):
    store = Store(project_directory=tmp_path)
    path = Path(await store.save(make_finding()))
    raw = report_bytes(path)
    return store, path, raw


def promotion(store, path, raw, *, guard=lambda: None, publish=lambda *_: None, cwe='CWE-862'):
    return store.promote_classification(path, expected_digest=hashlib.sha256(raw).hexdigest(),
        expected_revision=0, cwe=cwe,
        provenance={'origin': 'promoted-external', 'selected_cwe': cwe, 'revision': 1},
        guard=guard, publish=publish)


@pytest.mark.asyncio
@pytest.mark.parametrize('newline', ['LF', 'CRLF'])
async def test_targeted_edit_preserves_all_other_bytes(tmp_path, newline):
    store, path, raw = await setup(tmp_path)
    if newline == 'CRLF':
        raw = raw.replace(b'\n', b'\r\n')
        path.write_bytes(raw)
    before = read_report(path)
    after, durable = await promotion(store, path, raw)
    assert durable and after.cwe == ['CWE-862']
    # Remove only new classification metadata to recover the identical artifact.
    preserved = b''.join(line for line in report_bytes(path).splitlines(keepends=True) if not any(
        line.startswith(prefix) for prefix in (b'- **CWE:** CWE-862', b'- **Classification provenance:**', b'- **Classification revision:**')))
    assert preserved == raw
    assert before.createdAt == after.createdAt and before.owasp == after.owasp
    assert list(store.dir.glob('*.md')) == [path] and not list(path.parent.glob('.cwe-*.tmp'))


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['prepare', 'replace', 'final-guard', 'stale-report'])
async def test_pre_commit_failure_preserves_report(tmp_path, monkeypatch, failure):
    store, path, raw = await setup(tmp_path)
    published = []
    calls = 0
    def guard():
        nonlocal calls
        calls += 1
        if failure == 'final-guard' and calls == 2:
            raise ValueError('stale result')
    def broken(*_):
        raise OSError('injected write failure')
    if failure == 'prepare':
        monkeypatch.setattr(module, '_prepare_classification', broken)
    elif failure == 'replace':
        monkeypatch.setattr(module.os, 'replace', broken)
    elif failure == 'stale-report':
        path.write_bytes(raw+b'\nchanged by operator\n')
    expected = report_bytes(path)
    with pytest.raises((OSError, ValueError)):
        await promotion(store, path, raw, guard=guard, publish=lambda *_: published.append(True))
    assert report_bytes(path) == expected and not published
    assert not list(path.parent.glob('.cwe-*.tmp'))


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['directory-fsync', 'publish'])
async def test_post_commit_failure_never_rolls_back(tmp_path, monkeypatch, failure):
    store, path, raw = await setup(tmp_path)
    def broken(*_):
        raise OSError('injected post-commit failure')
    if failure == 'directory-fsync':
        monkeypatch.setattr(module, '_fsync_directory', broken)
    committed, durable = await promotion(store, path, raw, publish=broken if failure == 'publish' else lambda *_: None)
    assert committed == read_report(path) and committed.cwe == ['CWE-862']
    assert durable == (failure != 'directory-fsync') and report_bytes(path) != raw
    assert not list(path.parent.glob('.cwe-*.tmp'))


@pytest.mark.asyncio
async def test_cancelled_offloaded_preparation_drains_under_shared_lock(tmp_path, monkeypatch):
    store, path, raw = await setup(tmp_path)
    other = Store(project_directory=tmp_path)
    assert other._save_lock is store._save_lock
    entered, release = asyncio.Event(), threading.Event()
    loop = asyncio.get_running_loop()
    real_prepare = module._prepare_classification
    def slow_prepare(path, content):
        loop.call_soon_threadsafe(entered.set)
        if not release.wait(timeout=5):
            raise TimeoutError('test did not release preparation')
        return real_prepare(path, content)
    monkeypatch.setattr(module, '_prepare_classification', slow_prepare)
    task = asyncio.create_task(promotion(store, path, raw))
    await asyncio.wait_for(entered.wait(), 2)
    task.cancel()
    retry_finding = make_finding()
    retry = asyncio.create_task(other.save(retry_finding))
    await asyncio.sleep(0)
    assert not task.done() and not retry.done() and report_bytes(path) == raw
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert await retry == str(path) and retry_finding.cwe is None
    assert report_bytes(path) == raw and not list(path.parent.glob('.cwe-*.tmp'))


@pytest.mark.asyncio
async def test_cancellation_after_replace_preserves_committed_classification(tmp_path):
    store, path, raw = await setup(tmp_path)
    def cancel_after_commit(*_):
        task = asyncio.current_task()
        assert task is not None
        task.cancel()
    task = asyncio.create_task(promotion(store, path, raw, publish=cancel_after_commit))
    with pytest.raises(asyncio.CancelledError):
        await task
    assert read_report(path).cwe == ['CWE-862']
    retry = make_finding()
    assert await Store(project_directory=tmp_path).save(retry) == str(path)
    assert retry.classification_provenance is not None
    assert retry.classification_provenance['origin'] == 'promoted-external'


@pytest.mark.asyncio
async def test_overlapping_promotion_and_retry_consistency(tmp_path):
    store, path, raw = await setup(tmp_path)
    retry = make_finding()
    other = Store(project_directory=tmp_path)
    results = await asyncio.gather(promotion(store, path, raw), promotion(other, path, raw, cwe='CWE-863'),
                                   other.save(retry), return_exceptions=True)
    assert isinstance(results[1], ValueError)
    assert read_report(path).cwe == retry.cwe == ['CWE-862']
    assert list(store.dir.glob('*.md')) == [path]


@pytest.mark.asyncio
@pytest.mark.parametrize('change', ['duplicate', 'unknown-heading', 'missing-binding', 'already-classified'])
async def test_ambiguous_or_classified_reports_fail_safely(tmp_path, change):
    store, path, raw = await setup(tmp_path)
    if change == 'duplicate':
        raw = raw.replace(b'- **Severity:** low', b'- **Severity:** low\n- **Severity:** high')
    elif change == 'unknown-heading':
        raw = raw.replace(b'## Observed impact', b'## Unknown leading section')
    elif change == 'missing-binding':
        raw = b'\n'.join(line for line in raw.split(b'\n') if not line.startswith(b'- **Confirmation binding:**'))
    else:
        raw = raw.replace(b'- **URL:**', b'- **CWE:** CWE-89\n- **URL:**', 1)
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        await promotion(store, path, raw)
    assert report_bytes(path) == raw


def test_historical_provenance_never_inferred():
    fixture = Path(__file__).parents[1] / 'data/fixtures/findings/legacy-single-impact.md'
    legacy = read_report(fixture)
    assert legacy.cwe == ['CWE-89'] and legacy.classification_provenance is None
    assert legacy.classification_origin == 'legacy/unknown'
    assert legacy.classification_revision == 0 and legacy.confirmation_binding is None


@pytest.mark.asyncio
async def test_failed_snapshot_refresh_reports_visible_commit(tmp_path, monkeypatch):
    store, path, raw = await setup(tmp_path)
    real_read = module.read_report
    def fail_after_commit(path):
        if b'- **Classification revision:** 1' in report_bytes(path):
            raise OSError('injected post-commit refresh failure')
        return real_read(path)
    monkeypatch.setattr(module, 'read_report', fail_after_commit)
    with pytest.raises(module.ClassificationCommittedError, match='replacement committed'):
        await promotion(store, path, raw)
    assert real_read(path).cwe == ['CWE-862'] and report_bytes(path) != raw


@pytest.mark.asyncio
async def test_empty_cwe_header_still_unresolved(tmp_path):
    store, path, raw = await setup(tmp_path)
    raw = raw.replace(b'- **URL:**', b'- **CWE:** \n- **URL:**', 1)
    path.write_bytes(raw)
    assert read_report(path).cwe is None
    await promotion(store, path, raw)
    assert read_report(path).cwe == ['CWE-862']


@pytest.mark.asyncio
async def test_revision_overflow_fails_before_replacement(tmp_path):
    store, path, raw = await setup(tmp_path)
    raw = raw.replace(b'- **URL:**', b'- **Classification revision:** 999999999\n- **URL:**', 1)
    path.write_bytes(raw)
    with pytest.raises(ValueError, match='invalid persisted classification revision'):
        await store.promote_classification(path, expected_digest=hashlib.sha256(raw).hexdigest(),
            expected_revision=999999999, cwe='CWE-862', provenance=dict(origin='promoted-external',
            selected_cwe='CWE-862', revision=1000000000), guard=lambda: None, publish=lambda *_: None)
    assert report_bytes(path) == raw and not list(path.parent.glob('.cwe-*.tmp'))


@pytest.mark.asyncio
async def test_temp_fsync_failure_removes_prepared_file_and_preserves_report(tmp_path, monkeypatch):
    store, path, raw = await setup(tmp_path)
    published = []
    def fail_fsync(_fd):
        raise OSError('temporary file fsync failed')
    monkeypatch.setattr(module.os, 'fsync', fail_fsync)
    with pytest.raises(OSError, match='temporary file fsync failed'):
        await promotion(store, path, raw, publish=lambda *_: published.append(True))
    assert report_bytes(path) == raw and not published
    assert not list(path.parent.glob('.cwe-*.tmp'))


@pytest.mark.asyncio
@pytest.mark.parametrize('provenance', [
    {'origin': 'legacy/unknown', 'future_field': {'version': 2}},
    {'origin': 'unknown-future-origin'},
])
async def test_future_and_malformed_provenance_never_migrate_report(tmp_path, provenance):
    store, path, raw = await setup(tmp_path)
    raw = raw.replace(b'- **URL:**', ('- **Classification provenance:** '+json.dumps(provenance)+'\n- **URL:**').encode(), 1)
    path.write_bytes(raw)
    if provenance['origin'] == 'legacy/unknown':
        assert read_report(path).classification_provenance == provenance
        retry = make_finding()
        assert await store.save(retry) == str(path)
        assert retry.classification_provenance == provenance
    else:
        with pytest.raises(ValueError, match='invalid persisted classification provenance'):
            read_report(path)
    assert report_bytes(path) == raw
