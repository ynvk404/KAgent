"""Owned Docker resources only. No operation targets shared owasp-benchmark."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import uuid

from .install import COMMIT, source_hash

LABEL = 'org.kagent.reset.owner'
SOURCE = Path(__file__).parent.resolve()


def docker(*args):
    # Docker Desktop may remount a Windows drive while establishing a bind.
    # Preserve the path and reacquire that directory if its old inode vanished.
    original_cwd = os.getcwd()
    try:
        try:
            return subprocess.run(['docker', *args], check=True, capture_output=True, text=True).stdout.strip()
        except subprocess.CalledProcessError:
            # Docker run argv includes the private control credential. Never
            # propagate CalledProcessError's command rendering to logs/evidence.
            raise ValueError('owned Docker operation failed: ' + args[0]) from None
    finally:
        try:
            os.getcwd()
        except FileNotFoundError:
            os.chdir(original_cwd)


def create(state: Path, war: Path, image: str, port: int, *, test_probes=False, reference=False):
    state = state.absolute()
    if state.exists():
        raise ValueError('target state file already exists')
    identity = json.loads(docker('image', 'inspect', image))[0]
    if identity['Config'].get('Labels', {}).get('org.kagent.experiment.source') != COMMIT:
        raise ValueError('image source label mismatch')
    owner = uuid.uuid4().hex
    network = f'kagent-s1-reset-{owner}'
    ingress = network + '-ingress'
    token = secrets.token_hex(32)
    container = None
    proxy = None
    state.parent.mkdir(parents=True, exist_ok=True)
    assets = state.parent / f'{owner}-assets'
    proxy_config = assets / f'{owner}-proxy.conf'
    try:
        assets.mkdir()
        for name in ('install.py', 'run-target.sh'):
            shutil.copy2(SOURCE / name, assets / name)
        shutil.copytree(SOURCE / 'java', assets / 'java')
        if test_probes:
            shutil.copytree(SOURCE / 'tests', assets / 'tests')
        docker('network', 'create', '--internal', '--label', f'{LABEL}={owner}', network)
        docker('network', 'create', '--label', f'{LABEL}={owner}', ingress)
        container = docker('run', '-d', '--name', network, '--label', f'{LABEL}={owner}',
            '--network', network, '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--pids-limit', '256', '--memory', '2g', '--cpus', '2',
            '--tmpfs', '/runtime:rw,nosuid,nodev,size=1g', '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m',
            '--mount', f'type=bind,src={assets},dst=/reset-source,readonly',
            '-e', f'KAGENT_RESET_OWNER={owner}', '-e', f'KAGENT_RESET_TOKEN={token}',
            '-e', f'KAGENT_RESET_TEST_PROBES={int(test_probes)}',
            '-e', f'KAGENT_RESET_REFERENCE={int(reference)}',
            '--entrypoint', '/bin/bash', identity['Id'], '/reset-source/run-target.sh')
        # Docker does not publish ports for --internal networks. A fixed-upstream
        # ingress proxy reaches this target only; the target has no egress network.
        proxy_config.write_text('pid /tmp/nginx.pid;\nerror_log stderr;\nevents {}\nhttp { access_log off; '
            'client_body_temp_path /tmp/client; proxy_temp_path /tmp/proxy; server { listen 8080; '
            'location / { proxy_pass http://' + network + ':8080; proxy_read_timeout 45s; } } }\n')
        proxy_hash = hashlib.sha256(proxy_config.read_bytes()).hexdigest()
        proxy_image = json.loads(docker('image', 'inspect', 'nginx:alpine'))[0]['Id']
        proxy = docker('create', '--name', network + '-proxy', '--label', f'{LABEL}={owner}',
            '--network', ingress, '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--user', '101:101',
            '--pids-limit', '64', '--memory', '128m', '--tmpfs', '/tmp:rw,nosuid,nodev,size=16m',
            '--tmpfs', '/var/cache/nginx:rw,nosuid,nodev,mode=1777,size=16m', '-p', f'127.0.0.1:{port}:8080',
            '--mount', f'type=bind,src={assets},dst=/reset-config,readonly',
            '--entrypoint', 'nginx', proxy_image, '-c', f'/reset-config/{proxy_config.name}', '-g', 'daemon off;')
        docker('network', 'connect', network, proxy)
        docker('start', proxy)
        value = {'schema_version': 1, 'owner': owner, 'container_id': container, 'network': network,
                 'image_id': identity['Id'], 'target': f'http://127.0.0.1:{port}', 'context_path': '/benchmark',
                 'source_commit': COMMIT, 'base_war_sha256': hashlib.sha256(war.read_bytes()).hexdigest(),
                 'reset_source_sha256': source_hash(), 'token': token, 'test_probes': test_probes,
                 'reference': reference,
                 'proxy_id': proxy, 'ingress_network': ingress, 'proxy_config': str(proxy_config),
                 'proxy_config_sha256': proxy_hash, 'proxy_image_id': proxy_image}
        value['assets'] = str(assets)
        state.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(state, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if proxy:
            docker('rm', '-f', proxy)
        if container:
            docker('rm', '-f', container)
        docker('network', 'rm', network)
        docker('network', 'rm', ingress)
        proxy_config.unlink(missing_ok=True)
        shutil.rmtree(assets)
        raise


def cleanup(state: Path):
    value = json.loads(state.read_text())
    container = json.loads(docker('inspect', value['container_id']))[0]
    network = json.loads(docker('network', 'inspect', value['network']))[0]
    if container['Config']['Labels'].get(LABEL) != value['owner'] or network['Labels'].get(LABEL) != value['owner']:
        raise ValueError('resource ownership mismatch; cleanup refused')
    if not container['Name'].startswith('/kagent-s1-reset-') or not value['network'].startswith('kagent-s1-reset-'):
        raise ValueError('resource naming mismatch; cleanup refused')
    if value.get('proxy_id'):
        proxy = json.loads(docker('inspect', value['proxy_id']))[0]
        ingress = json.loads(docker('network', 'inspect', value['ingress_network']))[0]
        if proxy['Config']['Labels'].get(LABEL) != value['owner'] or ingress['Labels'].get(LABEL) != value['owner']:
            raise ValueError('proxy ownership mismatch; cleanup refused')
        docker('rm', '-f', value['proxy_id'])
    docker('rm', '-f', value['container_id'])
    docker('network', 'rm', value['network'])
    if value.get('proxy_id'):
        docker('network', 'rm', value['ingress_network'])
        config = Path(os.path.abspath(value['proxy_config']))
        expected_parent = Path(value['assets']).absolute() if value.get('assets') else state.absolute().parent
        if config.parent != expected_parent or config.name != value['owner'] + '-proxy.conf':
            raise ValueError('proxy configuration path mismatch; cleanup refused')
        config.unlink()
    if value.get('assets'):
        assets = Path(os.path.abspath(value['assets']))
        if assets.parent != state.absolute().parent or assets.name != value['owner'] + '-assets':
            raise ValueError('deployment asset path mismatch; cleanup refused')
        shutil.rmtree(assets)
    state.unlink()


def wait_ready(state: Path):
    value = json.loads(state.read_text())
    target = json.loads(docker('inspect', value['container_id']))[0]
    if target['Config']['Labels'].get(LABEL) != value['owner'] or value.get('reference'):
        raise ValueError('owned logical target identity mismatch')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    until = time.monotonic() + 90
    while time.monotonic() < until:
        nonce = uuid.uuid4().hex
        request = urllib.request.Request(value['target'] + '/benchmark/__kagent_reset',
            data=json.dumps({'action': 'status', 'nonce': nonce}).encode(), method='POST',
            headers={'Content-Type': 'application/json', 'X-KAgent-Reset-Token': value['token']})
        try:
            with opener.open(request, timeout=3) as response:
                result = json.load(response)
            if (result.get('nonce') == nonce and result.get('source_commit') == COMMIT
                    and result.get('war_sha256') == value['base_war_sha256']
                    and result.get('reset_source_sha256') == value['reset_source_sha256']
                    and result.get('verified') is True and result.get('state') == 'IDLE'):
                print('Owned target ready; runner must still reset and independently verify before admission.')
                return
            raise ValueError('target reported invalid readiness')
        except (urllib.error.URLError, TimeoutError):
            time.sleep(1)
    raise ValueError('target did not become ready within 90 seconds')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['create', 'wait-ready', 'cleanup'])
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--war', type=Path)
    parser.add_argument('--image', default='kagent-experiment:kagent-s1-build-62da4de4df96')
    parser.add_argument('--port', type=int, default=18080)
    parser.add_argument('--test-probes', action='store_true', help='disposable focused tests only; runner rejects this target')
    parser.add_argument('--reference', action='store_true', help='unwrapped fresh HTTP parity reference only; runner rejects this target')
    args = parser.parse_args()
    if args.action == 'create':
        if not args.war:
            parser.error('--war required for create')
        create(args.state, args.war, args.image, args.port, test_probes=args.test_probes, reference=args.reference)
    elif args.action == 'wait-ready':
        wait_ready(args.state)
    else:
        cleanup(args.state)


if __name__ == '__main__':
    main()
