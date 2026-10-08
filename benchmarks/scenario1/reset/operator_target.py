"""Attest an existing operator-managed deployment without changing Docker resources.

The supported deployment reuses run-target.sh and its immutable bootstrap mount.
Ownership labels/state files are unnecessary; isolation and reset remain mandatory.
"""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import re
import time
from urllib.parse import urlsplit

from benchmarks.common.contracts import file_hash
from .client import ResetBlocked, ResetController
from .docker_access import docker
from .install import COMMIT, JAVA, source_hash

SOURCE_ROOT = '/owasp/BenchmarkJava/'
INSTALLATION = '/runtime/tomcat/installation.json'
BOOTSTRAP = JAVA.parent

# Runs a read-only status query inside the selected container. The credential is
# read from its environment, never placed in argv/output. This binds HTTP receipts
# to the actual JVM boot, even if another deployment uses the same source/token.
STATUS_SCRIPT = '''import json, os, urllib.request, uuid
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args): raise ValueError('status redirect refused')
nonce = uuid.uuid4().hex
request = urllib.request.Request('http://127.0.0.1:8080/benchmark/__kagent_reset',
    data=json.dumps({'action':'status','nonce':nonce}).encode(), method='POST',
    headers={'Content-Type':'application/json','X-KAgent-Reset-Token':os.environ['KAGENT_RESET_TOKEN']})
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
with opener.open(request, timeout=5) as response:
    body = response.read(32769)
    if response.status != 200 or len(body) > 32768: raise ValueError('status rejected')
result = json.loads(body)
if result.get('nonce') != nonce: raise ValueError('status nonce mismatch')
print(json.dumps({key: result.get(key) for key in
    ('protocol','nonce','internal_seconds','boot_id','generation','state','verified','catalogs','source_commit',
     'war_sha256','reset_source_sha256','hsqldb','tomcat','jdk','active_requests','tracked_sessions')}))
'''
# Closing the selected JVM directly remains possible if URL/source admission
# fails. No control request is redirected through an unverified published port.
BLOCK_SCRIPT = STATUS_SCRIPT.replace("'action':'status'", "'action':'block'")


def inspect(identifier: str) -> dict:
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', identifier):
        raise ResetBlocked('invalid Docker container selector')
    values = json.loads(docker('inspect', '--type', 'container', identifier))
    if len(values) != 1 or not re.fullmatch('[a-f0-9]{64}', values[0]['Id']):
        raise ResetBlocked('exact Docker container identity unavailable')
    return values[0]


def isolation(container: dict):
    host = container['HostConfig']
    if (not container['State']['Running'] or not host['ReadonlyRootfs'] or host.get('Privileged')
            or set(host.get('CapDrop') or []) != {'ALL'}
            or not any(opt in {'no-new-privileges', 'no-new-privileges:true', 'no-new-privileges=true'}
                       for opt in (host.get('SecurityOpt') or []))
            or any(m.get('RW') for m in container['Mounts'])
            or host.get('NetworkMode') in {'host', 'none'}):
        raise ResetBlocked('container requires running, read-only, capability-dropped, no-new-privileges isolation and read-only mounts')


class OperatorResetController(ResetController):
    def __init__(self, container: str, war: Path, settings, *, ingress_container: str | None = None):
        parsed = urlsplit(settings.target)
        if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or settings.context_path != '/benchmark':
            raise ResetBlocked('operator target requires exact http://127.0.0.1:<published-port> and /benchmark context')
        try:
            target = inspect(container)
            env = dict(entry.split('=', 1) for entry in target['Config'].get('Env', []) if '=' in entry)
            token = env.get('KAGENT_RESET_TOKEN', '')
            if len(token) < 32:
                raise ResetBlocked('missing KAGENT_RESET_TOKEN; prepare reset instrumentation separately before running')
            self.target_snapshot = self.snapshot(target)
            self.ingress_snapshot = self.snapshot(inspect(ingress_container)) if ingress_container else None
            self.war = war
            cfg = {'container_id': target['Id'], 'image_id': target['Image'],
                   'target': settings.target.rstrip('/'), 'context_path': settings.context_path,
                   'source_commit': COMMIT, 'base_war_sha256': file_hash(war),
                   'reset_source_sha256': source_hash(), 'token': token}
            super().__init__(Path.home() / '.kagent' / 'benchmark-target-locks' / (target['Id'] + '.json'), config=cfg)
            self.identity_verified = False
        except ResetBlocked:
            raise
        except Exception:
            raise ResetBlocked('operator target inspection or trusted --reset-war unavailable') from None

    @staticmethod
    def snapshot(container):
        return {key: container[key] for key in ('Id', 'Image')} | {'started_at': container['State']['StartedAt']}

    def check_identity(self, manifest, settings):
        self.identity_verified = False
        try:
            return self._check_identity(manifest, settings)
        except ResetBlocked:
            raise
        except Exception:
            raise ResetBlocked('operator target prerequisites unavailable: inspect deployment, installation.json and bootstrap/source files') from None

    def _check_identity(self, manifest, settings):
        cfg = self.config
        if (manifest.dataset.get('git_commit') != COMMIT or manifest.dataset.get('dirty') is not False
                or settings.target.rstrip('/') != cfg['target'] or settings.context_path != cfg['context_path']
                or settings.target_state != 'external-reset' or not settings.authorized_lab):
            raise ResetBlocked('exact dataset/target/reset identity mismatch')
        target = inspect(cfg['container_id'])
        if self.snapshot(target) != self.target_snapshot:
            raise ResetBlocked('selected container image or running instance changed')
        isolation(target)
        env = dict(e.split('=', 1) for e in target['Config'].get('Env', []) if '=' in e)
        if (env.get('KAGENT_RESET_TOKEN') != cfg['token']
                or env.get('KAGENT_RESET_TEST_PROBES', '0') != '0'
                or env.get('KAGENT_RESET_REFERENCE', '0') != '0'):
            raise ResetBlocked('reset credential changed or test/reference deployment selected')
        if (target['Config'].get('Entrypoint') != ['/bin/bash']
                or target['Config'].get('Cmd') != ['/reset-source/run-target.sh']):
            raise ResetBlocked('compatible immutable run-target.sh bootstrap required')
        if not any(m.get('Destination') == '/reset-source' and m.get('Type') == 'bind'
                   and m.get('RW') is False for m in target['Mounts']):
            raise ResetBlocked('immutable read-only /reset-source bootstrap bind required')
        networks = target['NetworkSettings']['Networks']
        if len(networks) != 1:
            raise ResetBlocked('target must have exactly one internal network and no egress interface')
        network = next(iter(networks))
        net = json.loads(docker('network', 'inspect', network))[0]
        if net['Internal'] is not True or networks[network]['NetworkID'] != net['Id']:
            raise ResetBlocked('verified internal target network required')
        members = {target['Id']}
        if self.ingress_snapshot:
            members.add(self.ingress_snapshot['Id'])
        if set(net.get('Containers') or {}) != members:
            raise ResetBlocked('target internal network must contain only selected target and ingress')
        published = target
        if self.ingress_snapshot:
            published = inspect(self.ingress_snapshot['Id'])
            if self.snapshot(published) != self.ingress_snapshot:
                raise ResetBlocked('selected ingress instance changed')
            isolation(published)
            proxy_networks = published['NetworkSettings']['Networks']
            if (len(proxy_networks) != 2 or network not in proxy_networks
                    or proxy_networks[network]['NetworkID'] != net['Id']):
                raise ResetBlocked('ingress must join only target internal network and one ingress network')
            ingress_name = next(name for name in proxy_networks if name != network)
            ingress = json.loads(docker('network', 'inspect', ingress_name))[0]
            if (ingress['Internal'] is not False or ingress['Id'] != proxy_networks[ingress_name]['NetworkID']
                    or set(ingress.get('Containers') or {}) != {published['Id']}):
                raise ResetBlocked('verified dedicated ingress network required')
            if published['Config'].get('Entrypoint') != ['nginx']:
                raise ResetBlocked('fixed nginx ingress required')
            cmd = published['Config'].get('Cmd') or []
            if (len(cmd) != 4 or cmd[0] != '-c' or cmd[2:] != ['-g', 'daemon off;']
                    or not cmd[1].startswith('/reset-config/') or '..' in cmd[1]):
                raise ResetBlocked('explicit immutable nginx configuration required')
            upstream = target['Name'].removeprefix('/')
            expected = ('pid /tmp/nginx.pid;\nerror_log stderr;\nevents {}\nhttp { access_log off; '
                'client_body_temp_path /tmp/client; proxy_temp_path /tmp/proxy; server { listen 8080; '
                'location / { proxy_pass http://' + upstream + ':8080; proxy_read_timeout 45s; } } }')
            if docker('exec', published['Id'], 'cat', cmd[1]) != expected:
                raise ResetBlocked('ingress configuration is not the fixed selected-container upstream')
            if target['NetworkSettings']['Ports'].get('8080/tcp'):
                raise ResetBlocked('target has an additional published ingress')
        bindings = published['NetworkSettings']['Ports']
        selected = bindings.get('8080/tcp') or []
        if (len(selected) != 1 or selected[0]['HostIp'] != '127.0.0.1'
                or int(selected[0]['HostPort']) != (urlsplit(cfg['target']).port or 80)
                or any(value for key, value in bindings.items() if key != '8080/tcp')):
            raise ResetBlocked('target URL does not match the sole loopback Docker port binding')
        try:
            report = json.loads(docker('exec', target['Id'], 'cat', INSTALLATION))
        except Exception:
            raise ResetBlocked('missing or unreadable /runtime/tomcat/installation.json; prepare compatible reset instrumentation separately') from None
        if (report.get('source_commit') != COMMIT or report.get('base_war_sha256') != cfg['base_war_sha256']
                or report.get('reset_source_sha256') != cfg['reset_source_sha256'] or report.get('reference') is not False
                or report.get('installation_mode') != 'predeployment-descriptor; original initializer and filters retained'):
            raise ResetBlocked('compatible reset installation and trusted WAR identity required')
        if file_hash(self.war) != cfg['base_war_sha256']:
            raise ResetBlocked('trusted WAR changed during run')
        refs = manifest.dataset['artifacts']
        if not refs or any(PurePosixPath(ref).is_absolute() or '..' in PurePosixPath(ref).parts for ref in refs):
            raise ResetBlocked('invalid source artifact references')
        expected_hashes = {SOURCE_ROOT + ref: hashed for ref, hashed in refs.items()}
        expected_hashes[SOURCE_ROOT + 'target/benchmark.war'] = cfg['base_war_sha256']
        for path in [BOOTSTRAP / 'install.py', BOOTSTRAP / 'run-target.sh', *sorted(JAVA.glob('*.java'))]:
            expected_hashes['/reset-source/' + str(path.relative_to(BOOTSTRAP))] = file_hash(path)
        try:
            actual = docker('exec', target['Id'], 'sha256sum', *expected_hashes)
        except Exception:
            raise ResetBlocked('missing or unreadable selected source artifacts, offline WAR or /reset-source bootstrap') from None
        found = {line.split(None, 1)[1]: line.split(None, 1)[0] for line in actual.splitlines()}
        if found != expected_hashes:
            raise ResetBlocked('deployed source, WAR or reset bootstrap hash mismatch')
        try:
            status = json.loads(docker('exec', target['Id'], 'python3', '-c', STATUS_SCRIPT))
        except Exception:
            raise ResetBlocked('selected JVM reset endpoint unavailable; require authenticated compatible reset gate and successful baseline capture') from None
        catalogs = status.get('catalogs')
        if (status.get('protocol') != 'kagent-logical-reset-v1' or status.get('state') != 'CLOSED'
                or status.get('verified') is not True or status.get('source_commit') != COMMIT
                or status.get('war_sha256') != cfg['base_war_sha256']
                or status.get('reset_source_sha256') != cfg['reset_source_sha256']
                or any(status.get(k) != v for k, v in [('hsqldb', '2.7.4'), ('tomcat', '9.0.122'), ('jdk', '17')])
                or any(type(status.get(k)) is not int or status[k] < 0
                       for k in ('active_requests', 'tracked_sessions'))
                or (not self.starting and (status['active_requests'] != 0 or status['tracked_sessions'] != 0))
                or type(status.get('generation')) is not int or status['generation'] < 0
                or not isinstance(status.get('boot_id'), str)
                or not re.fullmatch('[a-f0-9-]{36}', status['boot_id'])
                or not isinstance(catalogs, dict) or set(catalogs) != {'server', 'embedded'}
                or any(not isinstance(v, str) or not re.fullmatch('[a-f0-9]{64}', v) for v in catalogs.values())):
            raise ResetBlocked('selected JVM has no verified closed reset gate and two-catalog baseline')
        if self.boot is not None and (self.boot != status['boot_id'] or self.baseline != catalogs
                                      or self.generation != status['generation']):
            raise ResetBlocked('selected JVM baseline, boot or generation changed')
        self.boot, self.baseline, self.generation = status['boot_id'], catalogs, status['generation']
        self.identity_verified = True
        return {'mode': 'operator-managed', **self.target_snapshot, 'source_commit': COMMIT,
                'base_war_sha256': cfg['base_war_sha256'], 'reset_source_sha256': cfg['reset_source_sha256'],
                'ingress': self.ingress_snapshot, 'boot_id': self.boot,
                'docker_lifecycle_mutations': False}

    def request(self, action, **kwargs):
        if action == 'block':
            started = time.monotonic()
            target = inspect(self.config['container_id'])
            env = dict(e.split('=', 1) for e in target['Config'].get('Env', []) if '=' in e)
            if (target['Id'] != self.config['container_id'] or target['Image'] != self.config['image_id']
                    or env.get('KAGENT_RESET_TOKEN') != self.config['token']):
                raise ResetBlocked('selected JVM identity changed; direct gate closure unavailable')
            result = json.loads(docker('exec', target['Id'], 'python3', '-c', BLOCK_SCRIPT))
            self._verify(result, action, result.get('nonce'))
            result['end_to_end_seconds'] = time.monotonic() - started
            return result
        if not self.identity_verified:
            raise ResetBlocked('operator container identity must be verified before reset control traffic')
        return super().request(action, **kwargs)
