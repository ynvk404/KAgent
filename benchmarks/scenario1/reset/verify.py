"""Focused, model-free exact-target reproduction. Always cleans owned resources."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import http.cookiejar
import json
from pathlib import Path
import statistics
import time
import traceback
import urllib.error
import urllib.request
import uuid

from benchmarks.common.contracts import RuntimeSettings, write_new
from benchmarks.common.contracts import OperationalCaseInput, decode
from benchmarks.scenario1.core.dataset import Dataset
from benchmarks.scenario1.core.dataset import select
from benchmarks.scenario1.core.runtime import request_fixture
from .client import ResetController, ResetBlocked, _NoRedirect
from .install import source_hash
from .owned_target import create, cleanup, docker


def raw_control(config, action, **kwargs):
    request = urllib.request.Request(config['target'] + '/benchmark/__kagent_reset',
        data=json.dumps({'action': action, 'nonce': uuid.uuid4().hex, **kwargs}).encode(), method='POST',
        headers={'Content-Type': 'application/json', 'X-KAgent-Reset-Token': config['token']})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    with opener.open(request, timeout=40) as response:
        return json.load(response)


def ready(config, *, reference=False):
    until = time.monotonic() + 90
    while time.monotonic() < until:
        try:
            if reference:
                with urllib.request.urlopen(config['target'] + '/benchmark/__kagent_probe?action=inspect', timeout=3) as r:
                    return json.load(r)
            result = raw_control(config, 'status')
            if result.get('verified') is True and result.get('state') == 'IDLE':
                return result
            raise ResetBlocked('startup reported failure')
        except (urllib.error.URLError, TimeoutError):
            time.sleep(1)
    raise ResetBlocked('exact target did not become ready within 90 seconds')


def probe(config, action, *, opener=None, **kwargs):
    from urllib.parse import urlencode
    client = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with client.open(config['target'] + '/benchmark/__kagent_probe?' + urlencode({'action': action, **kwargs}), timeout=20) as response:
        return json.load(response)


def response(config, op):
    settings = RuntimeSettings(config['target'], '/benchmark', True, 'external-reset')
    fixture = request_fixture(op, settings)
    req = urllib.request.Request(fixture['url'], method=fixture['method'], headers=fixture['headers'],
                                 data=fixture['body'].encode() if fixture['body'] else None)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        result = opener.open(req, timeout=15)
    except urllib.error.HTTPError as error:
        result = error
    with result:
        body = result.read(2 * 1024 * 1024)
        names = ['content-type', 'x-content-type-options', 'x-frame-options', 'strict-transport-security',
                 'content-security-policy', 'x-xss-protection']
        headers = {name: result.headers.get_all(name) for name in names}
        cookies = []
        for value in result.headers.get_all('Set-Cookie') or []:
            name_value, *attributes = value.split(';')
            name, _, cookie_value = name_value.partition('=')
            cookies.append({'name': name, 'value_sha256': None if name.lower() == 'jsessionid' else hashlib.sha256(cookie_value.encode()).hexdigest(),
                            'attributes': [a.strip() for a in attributes]})
        return {'status': result.status, 'body_sha256': hashlib.sha256(body).hexdigest(),
                'body_bytes': len(body), 'security_headers': headers, 'cookies': cookies}


def verify(dataset: Path, war: Path, destination: Path, image: str, port: int) -> bool:
    destination = destination.absolute()
    dataset = dataset.absolute()
    war = war.absolute()
    if destination.exists():
        raise ValueError('verification evidence directory already exists')
    destination.mkdir(parents=True)
    report = {'verdict': 'IMPLEMENTED BUT UNVERIFIED', 'checks': [], 'reset_receipts': [], 'http_parity': [],
              'source_sha256': source_hash(), 'orm_cache_parity': False,
              'historical_results': 'Not used as proof of this implementation'}
    owned = []
    def check(name, condition):
        print(name + ': ' + ('PASS' if condition else 'FAIL'), flush=True)
        report['checks'].append({'name': name, 'status': 'PASS' if condition else 'FAIL'})
        if not condition:
            raise AssertionError(name)
    def target(label, offset, *, reference=False, test_probes=True):
        state = destination / (label + '-private-state.json')
        create(state, war, image, port + offset, test_probes=test_probes, reference=reference)
        owned.append(state)
        config = json.loads(state.read_text())
        ready(config, reference=reference)
        return state, config
    def reset(controller):
        receipt = controller.reset()
        report['reset_receipts'].append(receipt)
        return receipt
    def authorize(config, route='/__kagent_probe', seconds=60):
        raw_control(config, 'authorize', route=route, lease_seconds=seconds)
    def wait_active(config):
        until = time.monotonic() + 3
        while time.monotonic() < until:
            if raw_control(config, 'status').get('active_requests', 0) > 0:
                return
            time.sleep(.01)
        raise AssertionError('probe did not enter original request chain')
    try:
        original = Dataset(dataset)
        check('exact_source_commit', original.identity()['git_commit'] == '8b67a88d73b2594570fc21150705283de884620b')
        check('all_959_cases_preserved', len(original.truth) == 959)
        state, config = target('logical', 0)
        control = ResetController(state)
        original_start = json.loads(docker('inspect', config['container_id']))[0]['State']['StartedAt']
        check('initial_idle_access', _http_status(config['target'] + '/benchmark/') == 200)
        raw_control(config, 'block')
        authorize(config)
        fresh = probe(config, 'inspect')
        raw_control(config, 'block')
        reset(control)
        baseline = control.baseline
        check('both_catalogs_exact_baseline', baseline is not None and len(baseline) == 2)
        authorize(config)
        before = probe(config, 'inspect')
        raw_control(config, 'block')
        for mutation in ('committed', 'rolled-back', 'ddl', 'spring', 'hibernate-active'):
            report['last_phase'] = mutation
            authorize(config)
            probe(config, mutation)
            reset(control)
            check('reset_' + mutation, True)
        authorize(config)
        after = probe(config, 'inspect')
        check('JDBC_Spring_Hibernate_replaced', all(before[key] != after[key] for key in ('jdbc', 'spring', 'normal_factory', 'classic_factory')))
        check('known_Hibernate_cache_difference_retained', fresh['normal_hobbies'] == [2, 1, 3]
              and after['normal_hobbies'] == after['classic_hobbies'] == [1, 1, 1])
        reset(control)
        authorize(config)
        allocation = probe(config, 'allocators')
        reset(control)
        authorize(config)
        again = probe(config, 'allocators')
        check('USER_HOBBY_allocators_idempotent', (allocation['user_id'], allocation['hobby_id']) == (again['user_id'], again['hobby_id']))
        reset(control)
        authorize(config)
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar))
        session = probe(config, 'session', opener=opener)
        reset(control)
        authorize(config)
        new_session = probe(config, 'session', opener=opener)
        check('session_cookie_invalidated', not new_session['existing'] and new_session['session_hash'] != session['session_hash'])
        reset(control)
        authorize(config)
        with ThreadPoolExecutor() as threads:
            active = threads.submit(probe, config, 'delay', milliseconds=500)
            wait_active(config)
            started = time.monotonic()
            reset(control)
            check('active_request_drained', time.monotonic() - started >= .3 and active.result()['ok'])
        reset(control)
        reset(control)
        check('repeated_idempotent_resets', True)
        # Fixed benign HTTP fixtures only; this is not the locked smoke or an Agent run.
        _, reference = target('fresh-reference', 1, reference=True)
        sql_ids = ['BenchmarkTest00344', 'BenchmarkTest00436', 'BenchmarkTest00192', 'BenchmarkTest00008',
                   'BenchmarkTest00025', 'BenchmarkTest00026', 'BenchmarkTest00038', 'BenchmarkTest00105', 'BenchmarkTest00018']
        xss_ids = [t.case_id for t in original.truth if t.vulnerability_class == 'cross-site-scripting'][:4]
        expected_by_case = {}
        for case_id in xss_ids + sql_ids:
            op = original.map(next(t for t in original.truth if t.case_id == case_id))
            expected = response(reference, op)
            expected_by_case[case_id] = expected
            reset(control)
            authorize(config, op.servlet_path)
            actual = response(config, op)
            matched = expected == actual
            report['http_parity'].append({'case_id': case_id, 'status': 'PASS' if matched else 'FAIL',
                                         'fresh': expected, 'reset': actual})
            check('http_parity_' + case_id, matched)
        reset(control)
        for case_id, phase in (('BenchmarkTest00018', 'A-insert'), ('BenchmarkTest00344', 'B-after-reset')):
            op = original.map(next(t for t in original.truth if t.case_id == case_id))
            authorize(config, op.servlet_path)
            actual = response(config, op)
            check('Case_' + phase, actual == expected_by_case[case_id])
            reset(control)  # verifies identity advancement is undone before B.
        check('Case_A_reset_Case_B', True)
        current = json.loads(docker('inspect', config['container_id']))[0]
        check('no_container_or_Tomcat_restart', current['State']['StartedAt'] == original_start
              and all(r['boot_id'] == control.boot for r in report['reset_receipts']))
        # Real controller/runner integration on a production installation. The
        # injected launcher makes fixed HTTP fixture calls only, with no model.
        production_state, production = target('runner-production', 5, test_probes=False)
        from benchmarks.scenario1.core.runner import run
        production_settings = RuntimeSettings(production['target'], '/benchmark', True, 'external-reset')
        for case_id in ('BenchmarkTest00113', xss_ids[0]):
            manifest = select(Dataset(dataset), 'focused-' + case_id, case_id=case_id)
            launched = []
            def launcher(payload, _):
                launched.append(payload['operational']['case_id'])
                response(production, decode(OperationalCaseInput, payload['operational']))
                return -9, False  # Deliberate model-free worker failure; never scored TP/TN.
            run_dir = run(manifest, production_settings, destination / ('runner-' + case_id), launcher=launcher,
                          reset_controller=ResetController(production_state))
            receipts = [json.loads(p.read_text()) for p in (run_dir / 'reset-evidence').glob('*.json')]
            check('production_runner_' + case_id, launched == [case_id]
                  and {r['phase'] for r in receipts} == {'block', 'before', 'authorize', 'after', 'idle'}
                  and all(r['status'] == 'verified' for r in receipts)
                  and not (run_dir / 'blocked.json').exists())
        # A timeout and an unaccounted transaction poison separate owned targets.
        for failure, offset in (('drain-timeout', 2), ('unaccounted-transaction', 3), ('unknown-client-outcome', 4)):
            failed_state, failed_config = target(failure, offset)
            failed_control = ResetController(failed_state)
            reset(failed_control)
            authorize(failed_config)
            if failure == 'unaccounted-transaction':
                probe(failed_config, 'unaccounted')
                try:
                    failed_control.reset()
                    check(failure, False)
                except ResetBlocked:
                    check(failure, True)
            else:
                with ThreadPoolExecutor() as threads:
                    running = threads.submit(probe, failed_config, 'delay', milliseconds=12000 if failure == 'drain-timeout' else 600)
                    wait_active(failed_config)
                    if failure == 'unknown-client-outcome':
                        failed_control.timeout = .05
                    try:
                        failed_control.reset()
                        check(failure, False)
                    except ResetBlocked:
                        check(failure, True)
                    check(failure + '_gate_closed', _http_status(failed_config['target'] + '/benchmark/') == 503)
                    running.result()
            check(failure + '_new_case_denied', _http_status(failed_config['target'] + '/benchmark/') == 503)
        report['verdict'] = 'PARTIAL'
        return True
    except Exception as err:
        report['error_type'] = type(err).__name__
        report['diagnostic_traceback'] = traceback.format_exc()
        for state in owned:
            config = json.loads(state.read_text())
            # Stack traces contain class/method metadata, not database values.
            try:
                dump = docker('exec', config['container_id'], 'bash', '-lc',
                    'jcmd $(pgrep -f org.apache.catalina.startup.Bootstrap | head -1) Thread.print')
                (destination / (state.stem + '-thread-dump.txt')).write_text(dump)
            except Exception:
                pass
        return False
    finally:
        durations = report['reset_receipts']
        if durations:
            report['median_internal_seconds'] = statistics.median(r['internal_seconds'] for r in durations)
            report['median_end_to_end_seconds'] = statistics.median(r['end_to_end_seconds'] for r in durations)
        report['cleanup'] = []
        for state in reversed(owned):
            try:
                cleanup(state)
                report['cleanup'].append({'status': 'PASS'})
            except Exception as err:
                report['cleanup'].append({'status': 'FAIL', 'error_type': type(err).__name__, 'diagnostic_traceback': traceback.format_exc()})
        write_new(destination / 'verification.json', report)
        print(json.dumps({'verdict': report['verdict'], 'passed': sum(c['status'] == 'PASS' for c in report['checks']),
                          'failed': sum(c['status'] == 'FAIL' for c in report['checks']),
                          'error_type': report.get('error_type'),
                          'median_internal_seconds': report.get('median_internal_seconds'),
                          'median_end_to_end_seconds': report.get('median_end_to_end_seconds')}))


def _http_status(url):
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            return response.status
    except urllib.error.HTTPError as err:
        return err.code


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dataset', type=Path, required=True)
    parser.add_argument('--war', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--image', default='kagent-experiment:kagent-s1-build-62da4de4df96')
    parser.add_argument('--port', type=int, default=18180)
    args = parser.parse_args()
    raise SystemExit(0 if verify(args.dataset, args.war, args.output, args.image, args.port) else 1)
