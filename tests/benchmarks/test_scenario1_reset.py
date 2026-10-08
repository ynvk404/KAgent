"""Offline parent admission regressions; no Docker, HTTP target or model calls."""
from dataclasses import replace
from contextlib import nullcontext
import json
from pathlib import Path
import time

import pytest

from benchmarks.common.contracts import write_new
from benchmarks.scenario1.dataset import select
from benchmarks.scenario1.runner import run
from benchmarks.scenario1.reset.client import ResetBlocked, ResetController
from benchmarks.scenario1.reset.install import COMMIT
from tests.benchmarks.test_scenario1 import make_dataset, op, settings, single_manifest


class Controller:
    def ownership(self):
        return nullcontext()
    def __init__(self, fail=None):
        self.calls = []
        self.resets = 0
        self.fail = fail

    def check_identity(self, *_):
        self.calls.append('identity')

    def reset(self):
        self.calls.append('reset')
        self.resets += 1
        if self.resets == self.fail:
            raise ResetBlocked('unknown outcome')
        return {'verified': True, 'internal_seconds': .01}

    def authorize(self, *_):
        self.calls.append('authorize')
        return {'verified': True}

    def block(self):
        self.calls.append('block')


def audit_for(tmp_path, manifest):
    path = tmp_path / 'audit.json'
    write_new(path, {'source_commit': COMMIT, 'source_bounded': {
        op['case_id']: manifest.dataset['artifacts'][f'src/main/java/org/owasp/benchmark/testcode/{op["case_id"]}.java']
        for op in manifest.operational if op['vulnerability_class'] == 'sql-injection'}})
    return path


def test_reset_before_after_and_separate_evidence(tmp_path, op, settings):
    manifest = single_manifest(replace(op, vulnerability_class='cross-site-scripting'), settings)
    control = Controller()
    called = []

    def worker(payload, _):
        called.append(payload)
        assert control.calls[-1] == 'authorize'
        assert not any(key in payload for key in ('truth', 'reset', 'token', 'audit'))
        return -9, False

    root = run(manifest, settings, tmp_path / 'run', launcher=worker, reset_controller=control)
    assert len(called) == 1
    assert control.calls == ['identity', 'reset', 'authorize', 'reset']
    receipts = [json.loads(p.read_text()) for p in (root / 'reset-evidence').glob('*.json')]
    assert {r['phase'] for r in receipts} == {'before', 'authorize', 'after'}
    assert all(r['status'] == 'verified' and r['end_to_end_seconds'] >= 0 for r in receipts)
    events = [json.loads(row) for row in (root / 'events.jsonl').read_text().splitlines()]
    assert events[-1]['kind'] == 'runtime-finished'
    assert 'llm' not in events[-1]['data']


@pytest.mark.parametrize('failure,launched', [(1, 0), (2, 1), (3, 1)])
def test_unknown_reset_blocks_every_next_worker(tmp_path, settings, failure, launched):
    manifest = select(make_dataset(tmp_path / 'dataset'), 'run', mode='smoke')
    control = Controller(failure)
    workers = []
    root = run(manifest, settings, tmp_path / 'run', launcher=lambda *args: (workers.append(args) or (-9, False)),
               reset_controller=control, reset_audit=audit_for(tmp_path, manifest))
    assert len(workers) == launched
    assert (root / 'blocked.json').exists()
    events = [json.loads(row) for row in (root / 'events.jsonl').read_text().splitlines()]
    untouched = [row for row in events if row['kind'] == 'evaluated']
    assert len(untouched) == 12 - launched
    assert all(r['status'] == 'not-run' and r['data']['partition'] == 'not-run' for r in untouched)
    assert any(json.loads(p.read_text())['status'] == 'blocked' for p in (root / 'reset-evidence').glob('*.json'))
    from benchmarks.scenario1.evaluate import evaluate
    from benchmarks.scenario1.reporting.loader import load_report
    evaluation = evaluate(root)
    assert evaluation['metrics']['overall']['not-run'] == 12 - launched
    assert all(record['confusion'] is None for record in evaluation['records'])
    # Existing fail-fast sentinel preserves evaluator/reporting contracts; the
    # separate block_reason and blocked.json identify mandatory reset blocking.
    assert len(load_report(root).cases) == len(manifest.execution_order)


def test_verified_reset_admits_all_synthetic_cases_sequentially(tmp_path, settings):
    manifest = select(make_dataset(tmp_path / 'dataset'), 'run', mode='smoke')
    control = Controller()
    workers = []
    def worker(payload, _):
        assert control.calls[-1] == 'authorize'
        workers.append(payload['operational']['case_id'])
        return -9, False
    root = run(manifest, settings, tmp_path / 'run', launcher=worker,
               reset_controller=control, reset_audit=audit_for(tmp_path, manifest))
    assert workers == manifest.execution_order
    assert control.resets == 2 * len(workers)
    assert not (root / 'blocked.json').exists()
    from benchmarks.scenario1.evaluate import evaluate
    assert evaluate(root)['metrics']['overall']['execution-failed'] == len(workers)


def test_interruption_resume_requires_new_verified_reset(tmp_path, op, settings):
    manifest = single_manifest(replace(op, vulnerability_class='cross-site-scripting'), settings)
    first = Controller()

    def interrupted(*_):
        raise KeyboardInterrupt

    original = tmp_path / 'first'
    with pytest.raises(KeyboardInterrupt):
        run(manifest, settings, original, launcher=interrupted, reset_controller=first)
    history = (original / 'events.jsonl').read_bytes()
    second = Controller()
    run(manifest, settings, tmp_path / 'resumed', launcher=lambda *_: (-9, False),
        reset_controller=second, resume_from=original)
    assert second.calls == ['identity', 'reset', 'authorize', 'reset']
    assert first.calls[-2:] == ['reset', 'block']
    assert (original / 'events.jsonl').read_bytes() == history


def test_production_requires_reset(tmp_path, op, settings):
    with pytest.raises(ResetBlocked, match='requires --reset-state'):
        run(single_manifest(op, settings), settings, tmp_path / 'rejected')
    assert not (tmp_path / 'rejected').exists()


@pytest.mark.parametrize('with_audit', [True, False])
def test_sql_control_classification_does_not_block_logical_reset(tmp_path, settings, with_audit):
    manifest = select(make_dataset(tmp_path / 'dataset'), 'run', mode='smoke')
    audit = tmp_path / 'audit.json' if with_audit else None
    if audit:
        write_new(audit, {'source_commit': COMMIT, 'source_bounded': {},
                         'blocked_external_effects': [op['case_id'] for op in manifest.operational
                                                      if op['vulnerability_class'] == 'sql-injection']})
    control = Controller()
    workers = []
    def worker(payload, _):
        workers.append(payload['operational']['case_id'])
        assert not {'truth', 'audit', 'reset_policy', 'external_effects_restoration_verified'} & payload.keys()
        return -9, False
    root = run(manifest, settings, tmp_path / 'run', launcher=worker,
               reset_controller=control, reset_audit=audit)
    assert workers == manifest.execution_order
    assert control.resets == 2 * len(workers)
    assert not (root / 'blocked.json').exists()
    policy = json.loads((root / 'reset-policy.json').read_text())
    assert policy['mode'] == 'logical-reset-all-cases'
    assert policy['scope_verdict'] == 'PARTIAL'
    assert policy['external_effects_restoration_verified'] is False
    assert policy['audit_role'] == 'historical-context-only'
    receipts = [json.loads(p.read_text()) for p in (root / 'reset-evidence').glob('*.json')]
    assert all(r['external_effects_restoration_verified'] is False for r in receipts)


class Response:
    status = 200
    def __init__(self, data):
        self.data = data
    def __enter__(self):
        return self
    def __exit__(self, *_):
        pass
    def read(self, _):
        return json.dumps(self.data).encode()


@pytest.mark.parametrize('changed', [
    {'catalogs': {}}, {'verified': False}, {'state': 'OPEN'}, {'nonce': 'stale'},
    {'source_commit': 'wrong'}, {'hsqldb': '2.7.2'}, {'tomcat': '9.0.121'}, {'jdk': '21'},
    {'war_sha256': 'wrong'}, {'active_requests': 1}, {'tracked_sessions': 1}, {'generation': None},
])
def test_http_200_is_not_cleanliness_proof(tmp_path, changed):
    config = {'target': 'http://127.0.0.1:8080', 'context_path': '/benchmark', 'token': 'secret-test-value',
              'base_war_sha256': 'a' * 64, 'reset_source_sha256': 'b' * 64}
    state = tmp_path / 'state.json'
    write_new(state, config)
    controller = ResetController(state)

    class Opener:
        def open(self, request, **_):
            result = {'protocol': 'kagent-logical-reset-v1', 'nonce': json.loads(request.data)['nonce'],
                'source_commit': COMMIT, 'hsqldb': '2.7.4', 'tomcat': '9.0.122', 'jdk': '17',
                'war_sha256': 'a' * 64, 'reset_source_sha256': 'b' * 64, 'verified': True, 'state': 'CLOSED',
                'active_requests': 0, 'tracked_sessions': 0, 'internal_seconds': .1,
                'catalogs': {'server': 'c' * 64, 'embedded': 'd' * 64}, 'generation': 1, 'boot_id': 'boot', **changed}
            return Response(result)
    controller.opener = Opener()
    with pytest.raises(ResetBlocked):
        controller.reset()


def test_target_ownership_excludes_concurrent_runners(tmp_path):
    state = tmp_path / 'target.json'
    write_new(state, {})
    first, second = ResetController(state), ResetController(state)
    with first.ownership():
        with pytest.raises(ResetBlocked, match='another runner'):
            with second.ownership():
                pytest.fail('second runner acquired ownership')
    with second.ownership():
        pass


@pytest.mark.parametrize('field,value', [('git_commit', 'wrong'), ('dirty', True)])
def test_wrong_dataset_is_rejected_before_control_traffic(tmp_path, op, settings, monkeypatch, field, value):
    manifest = single_manifest(op, settings)
    manifest = replace(manifest, dataset={**manifest.dataset, 'git_commit': COMMIT, 'dirty': False, field: value})
    state = tmp_path / 'target.json'
    write_new(state, {'target': settings.target, 'context_path': settings.context_path, 'source_commit': COMMIT})
    control = ResetController(state)
    monkeypatch.setattr('benchmarks.scenario1.reset.client.docker', lambda *_: pytest.fail('Docker or HTTP reached'))
    with pytest.raises(ResetBlocked, match='identity mismatch'):
        control.check_identity(manifest, replace(settings, target_state='external-reset'))


def test_reset_seconds_are_excluded_from_worker_wall_time(tmp_path, op, settings):
    control = Controller()
    fast_reset = control.reset
    def slow_reset():
        time.sleep(.05)
        return fast_reset()
    control.reset = slow_reset
    root = run(single_manifest(op, settings), settings, tmp_path / 'run',
               launcher=lambda *_: (-9, False), reset_controller=control)
    event = next(json.loads(row) for row in (root / 'events.jsonl').read_text().splitlines()
                 if json.loads(row)['kind'] == 'runtime-finished')
    receipts = [json.loads(p.read_text()) for p in (root / 'reset-evidence').glob('*.json')]
    reset_time = sum(r['end_to_end_seconds'] for r in receipts if r['phase'] in {'before', 'after'})
    assert reset_time >= .1
    assert event['data']['wall_seconds'] < reset_time
