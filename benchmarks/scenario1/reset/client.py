"""Parent-only reset control. Credentials and audit classifications never enter workers."""
from __future__ import annotations

import json
import math
import os
from contextlib import contextmanager
from pathlib import Path
import re
import time
import urllib.request
import uuid

from benchmarks.common.contracts import file_hash, read_json, write_new
from .install import COMMIT
from .owned_target import LABEL, docker


class ResetBlocked(ValueError):
    """Target outcome is unknown or unsafe; another worker must not be launched."""


class ResetController:
    def __init__(self, state: Path, *, timeout: float = 40):
        self.state_path = state.absolute()
        self.config = read_json(state)
        self.timeout = timeout
        self.baseline = None
        self.boot = None
        self.generation = None
        self.source_identity = None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    @contextmanager
    def ownership(self):
        import fcntl
        fd = os.open(self.state_path.with_suffix('.runner.lock'), os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as err:
                raise ResetBlocked('owned target already in use by another runner') from err
            yield
        finally:
            os.close(fd)

    def check_identity(self, manifest, settings):
        cfg = self.config
        if (manifest.dataset.get('git_commit') != COMMIT or manifest.dataset.get('dirty') is not False
                or settings.target.rstrip('/') != cfg.get('target') or settings.context_path != cfg.get('context_path')
                or cfg.get('source_commit') != COMMIT or settings.target_state != 'external-reset'
                or cfg.get('test_probes') or cfg.get('reference')):
            raise ResetBlocked('exact dataset/target/reset identity mismatch')
        target = json.loads(docker('inspect', cfg['container_id']))[0]
        net = json.loads(docker('network', 'inspect', cfg['network']))[0]
        host = target['HostConfig']
        if (target['Config']['Labels'].get(LABEL) != cfg['owner'] or net['Labels'].get(LABEL) != cfg['owner']
                or target['Image'] != cfg['image_id'] or not target['State']['Running'] or not net['Internal']
                or set(target['NetworkSettings']['Networks']) != {cfg['network']}
                or not host['ReadonlyRootfs'] or host.get('Privileged')
                or set(host.get('CapDrop') or []) != {'ALL'}
                or 'no-new-privileges' not in (host.get('SecurityOpt') or [])
                or any(m.get('RW') for m in target['Mounts'])):
            raise ResetBlocked('owned target isolation identity mismatch')
        proxy = json.loads(docker('inspect', cfg['proxy_id']))[0]
        if (proxy['Config']['Labels'].get(LABEL) != cfg['owner'] or proxy['Image'] != cfg['proxy_image_id']
                or not proxy['HostConfig']['ReadonlyRootfs'] or not proxy['State']['Running']
                or file_hash(Path(cfg['proxy_config'])) != cfg['proxy_config_sha256']
                or set(proxy['NetworkSettings']['Networks']) != {cfg['network'], cfg['ingress_network']}):
            raise ResetBlocked('fixed ingress proxy identity mismatch')
        bindings = proxy['NetworkSettings']['Ports'].get('8080/tcp') or []
        if len(bindings) != 1 or bindings[0]['HostIp'] != '127.0.0.1' or cfg['target'] != 'http://127.0.0.1:' + bindings[0]['HostPort']:
            raise ResetBlocked('target published port mismatch')
        if self.source_identity is None:
            refs = manifest.dataset['artifacts']
            # Literal argv, never a shell; read only the selected pinned source artifacts.
            actual = docker('exec', cfg['container_id'], 'sha256sum',
                            *('/owasp/BenchmarkJava/' + ref for ref in refs))
            found = {line.split(None, 1)[1].removeprefix('/owasp/BenchmarkJava/'): line.split(None, 1)[0]
                     for line in actual.splitlines()}
            if found != refs:
                raise ResetBlocked('deployed source artifact identity mismatch')
            self.source_identity = dict(refs)
        elif self.source_identity != manifest.dataset['artifacts']:
            raise ResetBlocked('selection source identity changed')

    def request(self, action: str, *, route: str | None = None, lease_seconds: int | None = None) -> dict:
        nonce = uuid.uuid4().hex
        data: dict[str, str | int | None] = {'action': action, 'nonce': nonce}
        if route is not None:
            data.update(route=route, lease_seconds=lease_seconds)
        started = time.monotonic()
        request = urllib.request.Request(self.config['target'] + self.config['context_path'] + '/__kagent_reset',
            data=json.dumps(data).encode(), method='POST',
            headers={'Content-Type': 'application/json', 'X-KAgent-Reset-Token': self.config['token']})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = response.read(32769)
                if response.status != 200 or len(body) > 32768:
                    raise ResetBlocked('reset transport rejected')
            result = json.loads(body)
            expected_state = 'OPEN' if action == 'authorize' else 'CLOSED'
            catalogs = result.get('catalogs')
            duration = result.get('internal_seconds')
            if (result.get('protocol') != 'kagent-logical-reset-v1' or result.get('nonce') != nonce
                    or result.get('source_commit') != COMMIT or result.get('hsqldb') != '2.7.4'
                    or result.get('tomcat') != '9.0.122' or result.get('jdk') != '17'
                    or result.get('war_sha256') != self.config['base_war_sha256']
                    or result.get('reset_source_sha256') != self.config['reset_source_sha256']
                    or result.get('verified') is not True or result.get('state') != expected_state
                    or result.get('active_requests') != 0 or result.get('tracked_sessions') != 0
                    or type(duration) not in {int, float} or not math.isfinite(duration) or duration < 0
                    or not isinstance(catalogs, dict) or set(catalogs) != {'server', 'embedded'}
                    or any(not isinstance(v, str) or not re.fullmatch('[a-f0-9]{64}', v) for v in catalogs.values())
                    or type(result.get('generation')) is not int or result['generation'] < 1
                    or not isinstance(result.get('boot_id'), str)):
                raise ResetBlocked('incomplete reset verification')
            if self.baseline is not None and (catalogs != self.baseline or result['boot_id'] != self.boot):
                raise ResetBlocked('baseline/target instance changed during run')
            if self.generation is not None and result['generation'] != self.generation + (action == 'reset'):
                raise ResetBlocked('reset generation mismatch')
            self.baseline, self.boot, self.generation = catalogs, result['boot_id'], result['generation']
            result['end_to_end_seconds'] = time.monotonic() - started
            return result
        except ResetBlocked:
            raise
        except Exception as err:
            raise ResetBlocked('reset failed or outcome unknown: ' + type(err).__name__) from err

    def reset(self):
        return self.request('reset')

    def authorize(self, op, settings):
        return self.request('authorize', route=op['servlet_path'], lease_seconds=min(3600, math.ceil(settings.timeout_seconds + 60)))

    def block(self):
        # Best effort only: failures never become a clean-state certificate.
        try:
            self.request('block')
        except Exception:
            pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ResetBlocked('reset redirect refused')


def persist(directory: Path, case_id: str, phase: str, operation) -> dict:
    """Fsync a unique receipt on both success and failure, including interruption."""
    receipt = {'case_id': case_id, 'phase': phase, 'status': 'unknown',
               'verification_scope': 'database-catalogs-and-application-lifecycle',
               'external_effects_restoration_verified': False}
    started = time.monotonic()
    path = directory / 'reset-evidence' / f'{case_id}-{phase}-{uuid.uuid4().hex}.json'
    try:
        result = operation()
        receipt.update(status='verified', verification=result)
    except BaseException as err:
        receipt.update(status='blocked', error=type(err).__name__)
        raise
    finally:
        receipt['end_to_end_seconds'] = time.monotonic() - started
        write_new(path, receipt)
    return {'receipt_ref': str(path.relative_to(directory)), 'receipt_sha256': file_hash(path), **receipt}
