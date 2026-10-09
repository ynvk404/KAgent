"""Existing-container admission and optional real reset; never manage Docker lifecycle."""
from copy import deepcopy
from dataclasses import replace
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from benchmarks.common.contracts import RuntimeSettings, file_hash
from benchmarks.scenario1.core.runner import run
from benchmarks.scenario1.reset.client import ResetBlocked, ResetController
from benchmarks.scenario1.reset.install import COMMIT, source_hash
from benchmarks.scenario1.reset import operator_target as module
from tests.benchmarks.test_scenario1 import op, settings, single_manifest
from tests.benchmarks.test_scenario1_reset import Response


@pytest.fixture
def deployment(tmp_path, monkeypatch, op, settings):
    settings = replace(settings, target='http://127.0.0.1:18080', target_state='external-reset')
    war = tmp_path / 'offline.war'
    war.write_bytes(b'trusted offline WAR fixture')
    target = {'Id': 'a' * 64, 'Image': 'sha256:' + 'b' * 64, 'Name': '/operator-benchmark',
        'State': {'Running': True, 'StartedAt': 'initial'},
        'Config': {'Env': ['KAGENT_RESET_TOKEN=' + 'c' * 64], 'Labels': {},
                   'Entrypoint': ['/bin/bash'], 'Cmd': ['/reset-source/run-target.sh']},
        'HostConfig': {'ReadonlyRootfs': True, 'Privileged': False, 'CapDrop': ['ALL'],
                       'SecurityOpt': ['no-new-privileges'], 'NetworkMode': 'isolated'},
        'Mounts': [{'Type': 'bind', 'Destination': '/reset-source', 'RW': False}],
        'NetworkSettings': {'Networks': {'isolated': {'NetworkID': 'network-id'}},
                            'Ports': {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '18080'}]}}}
    manifest = single_manifest(op, settings)
    manifest = replace(manifest, dataset={**manifest.dataset, 'git_commit': COMMIT, 'dirty': False})
    report = {'source_commit': COMMIT, 'base_war_sha256': file_hash(war), 'reset_source_sha256': source_hash(),
              'reference': False, 'installation_mode': 'predeployment-descriptor; original initializer and filters retained'}
    status = {'protocol': 'kagent-logical-reset-v1', 'boot_id': '12345678-1234-1234-1234-123456789abc',
        'generation': 0, 'state': 'CLOSED', 'verified': True, 'source_commit': COMMIT,
        'war_sha256': file_hash(war), 'reset_source_sha256': source_hash(),
        'hsqldb': '2.7.4', 'tomcat': '9.0.122', 'jdk': '17', 'active_requests': 0, 'tracked_sessions': 0,
        'catalogs': {'server': 'd' * 64, 'embedded': 'e' * 64}}
    d = SimpleNamespace(target=target, proxy=None, network={'Id': 'network-id', 'Internal': True,
                                                         'Containers': {target['Id']: {}}},
        manifest=manifest, settings=settings, war=war, report=report, status=status, calls=[], corrupt_hash=False)
    def docker(*args):
        d.calls.append(args)
        if args[0] == 'inspect':
            return json.dumps([d.proxy if d.proxy and args[-1] in {'ingress', d.proxy['Id']} else d.target])
        if args[:2] == ('network', 'inspect'):
            if args[-1] == 'ingress-net':
                return json.dumps([{'Id': 'ingress-id', 'Internal': False, 'Containers': {d.proxy['Id']: {}}}])
            return json.dumps([d.network])
        assert args[:2] == ('exec', d.target['Id']) or d.proxy and args[:2] == ('exec', d.proxy['Id'])
        if args[2] == 'cat':
            if args[3] == module.INSTALLATION:
                return json.dumps(d.report)
            return d.proxy_config
        if args[2] == 'python3':
            assert args[3] == '-c' and args[4] in {module.STATUS_SCRIPT, module.BLOCK_SCRIPT}
            if args[4] == module.BLOCK_SCRIPT and d.status['state'] != 'FAILED':
                d.status['state'] = 'CLOSED'
            return json.dumps({**d.status, 'nonce': '1' * 32, 'internal_seconds': .01})
        assert args[2] == 'sha256sum'
        hashes = {module.SOURCE_ROOT + ref: hashed for ref, hashed in d.manifest.dataset['artifacts'].items()}
        hashes[module.SOURCE_ROOT + 'target/benchmark.war'] = file_hash(d.war)
        for path in [module.BOOTSTRAP / 'install.py', module.BOOTSTRAP / 'run-target.sh', *sorted(module.JAVA.glob('*.java'))]:
            hashes['/reset-source/' + str(path.relative_to(module.BOOTSTRAP))] = file_hash(path)
        return '\n'.join(('0' * 64 if d.corrupt_hash else hashes[p]) + '  ' + p for p in args[3:])
    monkeypatch.setattr(module, 'docker', docker)
    return d


def controller(d):
    return module.OperatorResetController('operator-benchmark', d.war, d.settings,
                                          ingress_container='ingress' if d.proxy else None)


def test_existing_unlabelled_container_admission_and_http_boot_binding(deployment, monkeypatch):
    d = deployment
    control = controller(d)
    identity = control.check_identity(d.manifest, d.settings)
    assert identity['mode'] == 'operator-managed' and identity['docker_lifecycle_mutations'] is False
    assert identity['Id'] == d.target['Id']
    assert control.generation == 0 and control.baseline == d.status['catalogs']
    class Opener:
        def open(self, request, **_):
            assert request.get_header('X-kagent-reset-token') == control.config['token']
            return Response({**d.status, 'nonce': json.loads(request.data)['nonce'], 'generation': 1,
                             'internal_seconds': .1})
    monkeypatch.setattr(control, 'opener', Opener())
    assert control.reset()['generation'] == 1
    # The same build/token/catalogs on another JVM still fail exact URL/container matching.
    d.status['boot_id'] = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    with pytest.raises(ResetBlocked, match='instance changed'):
        control.reset()
    assert all(args[0] in {'inspect', 'network', 'exec'} for args in d.calls)


@pytest.mark.parametrize('change,message', [
    ('port', 'port binding'), ('public-port', 'port binding'), ('extra-port', 'port binding'),
    ('source', 'hash mismatch'), ('instrumentation', 'installation'), ('war', 'installation'),
    ('baseline', 'baseline'), ('failed', 'baseline'), ('active', 'baseline'), ('sessions', 'baseline'),
    ('probes', 'test/reference'), ('reference', 'test/reference'), ('network', 'internal target network'),
    ('egress', 'no egress'), ('rootfs', 'read-only'), ('mount', 'read-only'), ('bootstrap', 'bootstrap'),
    ('entrypoint', 'bootstrap'), ('stopped', 'running'), ('generation', 'baseline'),
    ('shared-network', 'only selected target'),
])
def test_missing_prerequisites_fail_before_http_control(deployment, change, message, monkeypatch):
    d = deployment
    if change == 'port': d.target['NetworkSettings']['Ports']['8080/tcp'][0]['HostPort'] = '18081'
    elif change == 'public-port': d.target['NetworkSettings']['Ports']['8080/tcp'][0]['HostIp'] = '0.0.0.0'
    elif change == 'extra-port': d.target['NetworkSettings']['Ports']['9001/tcp'] = [{'HostIp': '127.0.0.1', 'HostPort': '9001'}]
    elif change == 'source': d.corrupt_hash = True
    elif change == 'instrumentation': d.report['reset_source_sha256'] = '0' * 64
    elif change == 'war': d.report['base_war_sha256'] = '0' * 64
    elif change == 'baseline': d.status['catalogs'] = {}
    elif change == 'failed': d.status['state'] = 'FAILED'
    elif change == 'active': d.status['active_requests'] = 1
    elif change == 'sessions': d.status['tracked_sessions'] = 1
    elif change == 'probes': d.target['Config']['Env'].append('KAGENT_RESET_TEST_PROBES=1')
    elif change == 'reference': d.target['Config']['Env'].append('KAGENT_RESET_REFERENCE=1')
    elif change == 'network': d.network['Internal'] = False
    elif change == 'egress': d.target['NetworkSettings']['Networks']['bridge'] = {'NetworkID': 'other'}
    elif change == 'rootfs': d.target['HostConfig']['ReadonlyRootfs'] = False
    elif change == 'mount': d.target['Mounts'][0]['RW'] = True
    elif change == 'bootstrap': d.target['Mounts'] = []
    elif change == 'entrypoint': d.target['Config']['Cmd'] = ['other.sh']
    elif change == 'stopped': d.target['State']['Running'] = False
    elif change == 'generation': d.status['generation'] = None
    elif change == 'shared-network': d.network['Containers']['f' * 64] = {}
    control = controller(d)
    monkeypatch.setattr(control.opener, 'open', lambda *_a, **_k: pytest.fail('HTTP control reached'))
    with pytest.raises(ResetBlocked, match=message):
        control.check_identity(d.manifest, d.settings)
    control.block()
    with pytest.raises(ResetBlocked, match='identity must be verified'):
        control.reset()


def test_missing_credential_and_unsafe_selector(deployment):
    d = deployment
    d.target['Config']['Env'] = []
    with pytest.raises(ResetBlocked, match='missing KAGENT_RESET_TOKEN'):
        controller(d)
    d.calls.clear()
    with pytest.raises(ResetBlocked, match='selector'):
        module.OperatorResetController('--other', d.war, d.settings)
    assert not d.calls


def test_replacement_and_generation_changes_block_next_admission(deployment):
    d = deployment
    control = controller(d)
    control.check_identity(d.manifest, d.settings)
    d.status['generation'] = 2
    with pytest.raises(ResetBlocked, match='generation changed'):
        control.check_identity(d.manifest, d.settings)
    d.target['State']['StartedAt'] = 'restarted'
    with pytest.raises(ResetBlocked, match='running instance changed'):
        control.check_identity(d.manifest, d.settings)


def test_existing_fixed_ingress_and_wrong_upstream(deployment):
    d = deployment
    d.proxy = deepcopy(d.target)
    d.proxy.update(Id='f' * 64, Name='/operator-ingress')
    d.network['Containers'][d.proxy['Id']] = {}
    d.proxy['Config'].update(Entrypoint=['nginx'], Cmd=['-c', '/reset-config/proxy.conf', '-g', 'daemon off;'])
    d.proxy['NetworkSettings']['Networks']['ingress-net'] = {'NetworkID': 'ingress-id'}
    d.target['NetworkSettings']['Ports']['8080/tcp'] = None
    d.proxy_config = ('pid /tmp/nginx.pid;\nerror_log stderr;\nevents {}\nhttp { access_log off; '
        'client_body_temp_path /tmp/client; proxy_temp_path /tmp/proxy; server { listen 8080; '
        'location / { proxy_pass http://operator-benchmark:8080; proxy_read_timeout 45s; } } }')
    control = controller(d)
    assert control.check_identity(d.manifest, d.settings)['ingress']['Id'] == d.proxy['Id']
    d.proxy_config = d.proxy_config.replace('operator-benchmark', 'another-target')
    with pytest.raises(ResetBlocked, match='upstream'):
        control.check_identity(d.manifest, d.settings)


def test_operator_and_legacy_lock_same_container_independent_state(deployment, tmp_path, monkeypatch):
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: tmp_path))
    first = controller(deployment)
    second = ResetController(tmp_path / 'different-state.json', config=first.config)
    with first.ownership():
        with pytest.raises(ResetBlocked, match='another runner'):
            with second.ownership(): pytest.fail('overlapping target ownership')


def test_runner_persists_identity_blocker_without_launch_or_secret(deployment, tmp_path, monkeypatch):
    d = deployment
    control = controller(d)
    d.corrupt_hash = True
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: tmp_path))
    root = run(d.manifest, d.settings, tmp_path / 'run', reset_controller=control,
               launcher=lambda *_: pytest.fail('worker launched'))
    assert 'hash mismatch' in json.loads((root / 'blocked.json').read_text())['detail']
    receipts = list((root / 'reset-evidence').glob('*.json'))
    assert {json.loads(p.read_text())['phase'] for p in receipts} == {'block', 'identity'}
    assert all(control.config['token'] not in p.read_text() for p in root.rglob('*') if p.is_file())


def test_operator_runner_preserves_reset_sequence_and_worker_boundary(deployment, tmp_path, monkeypatch):
    from benchmarks.scenario1.core.evaluate import evaluate
    d = deployment
    control = controller(d)
    actions, workers = [], []
    class Opener:
        def open(self, request, **_):
            action = json.loads(request.data)['action']
            actions.append(action)
            d.status['state'] = {'authorize': 'OPEN', 'idle': 'IDLE'}.get(action, 'CLOSED')
            d.status['generation'] += action == 'reset'
            return Response({**d.status, 'nonce': json.loads(request.data)['nonce'], 'internal_seconds': .01})
    monkeypatch.setattr(control, 'opener', Opener())
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: tmp_path))
    def worker(payload, _):
        assert actions[-1] == 'authorize'
        assert not {'token', 'reset', 'truth', 'audit'} & payload.keys()
        assert control.config['token'] not in json.dumps(payload)
        workers.append(payload)
        return -9, False
    root = run(d.manifest, d.settings, tmp_path / 'run', reset_controller=control, launcher=worker)
    assert actions == ['reset', 'authorize', 'reset', 'idle'] and len(workers) == 1
    receipts = [json.loads(p.read_text()) for p in (root / 'reset-evidence').glob('*.json')]
    assert {r['phase'] for r in receipts} == {'block', 'identity', 'before', 'authorize', 'after', 'idle'}
    assert all(r['status'] == 'verified' and r['external_effects_restoration_verified'] is False for r in receipts)
    assert evaluate(root)['metrics']['overall']['execution-failed'] == 1
    assert not (root / 'blocked.json').exists()


def test_cli_operator_dry_run_never_reads_docker(tmp_path, monkeypatch, capsys):
    from benchmarks.scenario1.__main__ import main
    from tests.benchmarks.test_scenario1 import make_dataset
    make_dataset(tmp_path / 'dataset')
    monkeypatch.setattr(module, 'docker', lambda *_: pytest.fail('dry-run Docker read'))
    args = ['run', '--dataset', str(tmp_path / 'dataset'), '--case', 'BenchmarkTest00001',
            '--target', 'http://127.0.0.1:18080', '--context-path', '/benchmark', '--authorized-lab',
            '--target-state', 'external-reset', '--container', 'operator-benchmark', '--dry-run']
    assert main(args) == 2
    assert '--reset-war' in capsys.readouterr().err
    (tmp_path / 'not-read.war').write_bytes(b'offline dry-run identity fixture')
    assert main(args + ['--reset-war', str(tmp_path / 'not-read.war')]) == 0
    assert json.loads(capsys.readouterr().out)['dry_run'] is True


@pytest.mark.parametrize('args', [('start', 'target'), ('restart', 'target'), ('rm', 'target'),
                                  ('create', 'target'), ('run', 'target'), ('network', 'create', 'net')])
def test_admission_docker_wrapper_refuses_lifecycle(args, monkeypatch):
    from benchmarks.scenario1.reset import docker_access
    monkeypatch.setattr(docker_access.subprocess, 'run', lambda *_a, **_k: pytest.fail('lifecycle launched'))
    with pytest.raises(ValueError, match='refused'):
        docker_access.docker(*args)


@pytest.mark.skipif(not os.environ.get('KAGENT_S1_EXISTING_CONTAINER'),
                    reason='requires explicitly selected prepared existing lab; never creates or prepares containers')
def test_real_existing_container_logical_reset_between_requests(tmp_path):
    """Fixed insert/identity allocator/readback fixtures, no model and no lifecycle mutations."""
    import hashlib
    import urllib.error
    import urllib.request
    from benchmarks.common.contracts import OperationalCaseInput, decode
    from benchmarks.scenario1.core.dataset import Dataset, select
    from benchmarks.scenario1.core.runtime import request_fixture
    from benchmarks.scenario1.reset.client import _NoRedirect
    settings = RuntimeSettings(os.environ['KAGENT_S1_EXISTING_TARGET'], '/benchmark', True, 'external-reset')
    dataset = Dataset(Path(os.environ['KAGENT_S1_EXISTING_DATASET']))
    manifest = select(dataset, 'existing-reset-test', case_id='BenchmarkTest00018')
    control = module.OperatorResetController(os.environ['KAGENT_S1_EXISTING_CONTAINER'],
        Path(os.environ['KAGENT_S1_EXISTING_WAR']), settings,
        ingress_container=os.environ.get('KAGENT_S1_EXISTING_INGRESS'))
    from benchmarks.scenario1.reset.client import persist
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    def ui_status():
        try:
            with opener.open(settings.target + '/benchmark/', timeout=15) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code
    def insert_response(op):
        fixture = request_fixture(decode(OperationalCaseInput, op), settings)
        request = urllib.request.Request(fixture['url'], method=fixture['method'], headers=fixture['headers'],
                                         data=fixture['body'].encode() if fixture['body'] else None)
        with opener.open(request, timeout=15) as response:
            body = response.read(65537)
            assert response.status == 200 and len(body) <= 65536
            assert b'Update complete for query:' in body  # SQL executed, not a 200 error page.
        return hashlib.sha256(body).hexdigest()
    with control.ownership():
        assert ui_status() == 200
        persist(tmp_path, 'BenchmarkTest00018', 'block', control.begin)
        assert ui_status() == 503
        identity = control.check_identity(manifest, settings)
        persist(tmp_path, 'BenchmarkTest00018', 'identity', lambda: identity)
        try:
            baseline = persist(tmp_path, 'BenchmarkTest00018', 'before', control.reset)['verification']
            op = manifest.operational[0]
            control.authorize(op, settings)
            assert ui_status() == 503
            first = insert_response(op)
            # Original rollback filter leaves allocation changes; the real SQL/DDL
            # reset must restore them along with both catalog fingerprints.
            restored = persist(tmp_path, 'BenchmarkTest00018', 'between', control.reset)['verification']
            assert restored['catalogs'] == baseline['catalogs']
            control.authorize(op, settings)
            assert insert_response(op) == first
            assert module.OperatorResetController.snapshot(module.inspect(control.config['container_id'])) == control.target_snapshot
        except BaseException:
            control.block()
            raise
        finally:
            persist(tmp_path, 'BenchmarkTest00018', 'after', control.reset)
        persist(tmp_path, 'BenchmarkTest00018', 'idle', control.idle)
        assert ui_status() == 200


def test_idle_activity_is_revoked_before_identity_and_restored_only_after_reset(deployment, monkeypatch):
    d = deployment
    d.status.update(state='IDLE', active_requests=1, tracked_sessions=2)
    control = controller(d)
    monkeypatch.setattr(control.opener, 'open', lambda *_a, **_k: pytest.fail('unverified published URL reached'))
    assert control.begin()['state'] == 'CLOSED'
    assert d.calls[-1][-1] == module.BLOCK_SCRIPT
    control.check_identity(d.manifest, d.settings)
    class Opener:
        def open(self, request, **_):
            action = json.loads(request.data)['action']
            d.status.update(active_requests=0, tracked_sessions=0,
                            state='IDLE' if action == 'idle' else 'CLOSED')
            d.status['generation'] += action == 'reset'
            return Response({**d.status, 'nonce': json.loads(request.data)['nonce'], 'internal_seconds': .01})
    monkeypatch.setattr(control, 'opener', Opener())
    assert control.reset()['generation'] == 1
    control.check_identity(d.manifest, d.settings)
    assert control.idle()['state'] == 'IDLE'
    control.block()
    assert d.status['state'] == 'CLOSED'


def test_identity_failure_closes_selected_jvm_without_using_unverified_url(deployment, monkeypatch):
    d = deployment
    d.status['state'] = 'IDLE'
    control = controller(d)
    d.corrupt_hash = True
    monkeypatch.setattr(control.opener, 'open', lambda *_a, **_k: pytest.fail('unverified published URL reached'))
    control.begin()
    with pytest.raises(ResetBlocked, match='hash mismatch'):
        control.check_identity(d.manifest, d.settings)
    control.block()
    assert d.status['state'] == 'CLOSED'
    assert d.calls[-1][-1] == module.BLOCK_SCRIPT
