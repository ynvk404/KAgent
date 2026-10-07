"""Sequential parent orchestrator owns truth, schedule, process lifecycle and recorder."""
from __future__ import annotations

from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
import uuid

from benchmarks.common.contracts import (CaseExecution, OperationalCaseInput, RunManifest,
                                        RuntimeSettings, decode, digest, file_hash, write_new, read_json)
from benchmarks.common.recorder import Recorder
from .runtime import CAPABILITY, REPO


def reproducibility() -> dict:
    def git(*args):
        proc = subprocess.run(['git', '-C', str(REPO), *args], capture_output=True, text=True)
        return proc.stdout.strip() if proc.returncode == 0 else None
    return {'kagent_commit': git('rev-parse', 'HEAD'), 'kagent_dirty': bool(git('status', '--porcelain')),
            'python': platform.python_version(), 'platform': platform.platform(),
            'skills': {str(p.relative_to(REPO)): file_hash(p)
                       for cls in ('sql-injection', 'cross-site-scripting')
                       for p in sorted((REPO / 'skills' / cls).rglob('*')) if p.is_file()},
            'capability_profile': CAPABILITY}


def validate_runtime(manifest: RunManifest, settings: RuntimeSettings):
    if not settings.authorized_lab:
        raise ValueError('explicit --authorized-lab declaration required')
    if manifest.dataset.get('state_mutating_cases') and settings.target_state != 'external-reset':
        raise ValueError('selected servlets mutate target state; require --target-state external-reset and operator snapshots/resets')


def envelope(op: dict, settings: RuntimeSettings, run_id: str, execution_id: str, workspace: Path, output: Path) -> dict:
    decode(OperationalCaseInput, op)
    return {'operational': op, 'settings': asdict(settings), 'run_id': run_id, 'execution_id': execution_id,
            'workspace': str(workspace), 'output': str(output)}


def launch_worker(envelope: dict, seconds: float) -> tuple[int, bool]:
    env = dict(os.environ)
    env['PYTHONPATH'] = str(REPO)
    env['KAGENT_PROJECT_ROOT'] = envelope['workspace']
    env.pop('KAgent_TRACE_AGENT', None)
    proc = subprocess.Popen([sys.executable, '-m', 'benchmarks.scenario1.worker'], cwd=REPO, env=env,
                            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        proc.communicate(json.dumps(envelope).encode(), timeout=seconds)
        return proc.returncode, False
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        return proc.returncode, True
    except BaseException:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        raise


def run(manifest: RunManifest, settings: RuntimeSettings, destination: Path, *, fail_fast=False, launcher=launch_worker) -> Path:
    validate_runtime(manifest, settings)
    destination = destination.resolve()
    if destination.exists():
        raise ValueError('run directory already exists; history cannot be overwritten or resumed')
    destination.mkdir(parents=True, mode=0o700)
    bound = replace(manifest, runtime=asdict(settings), reproducibility=reproducibility())
    write_new(destination / 'manifest.json', asdict(bound))
    recorder = Recorder(destination / 'events.jsonl', manifest.run_id)
    operations = {o['case_id']: o for o in manifest.operational}
    for case_id in manifest.execution_order:
        recorder.append('scheduled', case_id, 'scheduled', data={'operational_hash': digest(operations[case_id]),
                                                               'manifest_hash': digest(asdict(bound))})
    for case_id in manifest.execution_order:
        execution_id = uuid.uuid4().hex
        output = destination / 'results' / f'{case_id}.json'
        workspace = destination / 'workspaces' / execution_id
        output.parent.mkdir(exist_ok=True, mode=0o700)
        recorder.append('started', case_id, 'started', execution_id=execution_id,
                        data={'workspace_ref': str(workspace.relative_to(destination))})
        wall = time.monotonic()
        failure = None
        executed = None
        try:
            code, timeout = launcher(envelope(operations[case_id], settings, manifest.run_id, execution_id, workspace, output),
                                     settings.timeout_seconds + 60)  # finite setup/drain grace
            status = 'timeout' if timeout else 'setup-error' if code == 70 else 'crashed' if code else None
            if status is None:
                executed = decode(CaseExecution, read_json(output))
                if (executed.run_id, executed.case_id, executed.execution_id) != (manifest.run_id, case_id, execution_id):
                    raise ValueError('worker export identity mismatch')
                status = executed.status
                if status not in {'completed', 'timeout', 'runtime-error', 'provider-error', 'budget-exhausted', 'setup-error'}:
                    raise ValueError('worker exported nonfinal status')
            else:
                failure = f'worker-exit-{code}'
        except Exception as err:
            status, failure = 'setup-error', type(err).__name__
            executed = None
        data = {'wall_seconds': time.monotonic() - wall, 'error': failure,
                'result_ref': str(output.relative_to(destination)) if output.exists() else None,
                'result_sha256': file_hash(output) if output.exists() else None}
        if executed is not None:
            data['runtime_metadata'] = {k: executed.runtime_metadata.get(k) for k in ('provider', 'model', 'capability_profile')}
            exported = executed.result
            if exported and isinstance(exported['workflow'].get('validation_results'), list):
                results = exported['workflow']['validation_results']
                current = next((r for r in results if isinstance(r, dict) and r.get('result_id') == exported['result_id']), None)
                data['canonical_summary'] = {k: exported.get(k) for k in ('session_id', 'objective_id', 'candidate_id', 'result_id')}
                data['canonical_summary'].update(outcome=current.get('outcome') if current else None,
                                                 attempt_id=current.get('attempt_id') if current else None)
        recorder.append('runtime-finished', case_id, status, execution_id=execution_id, data=data)
        if fail_fast and status != 'completed':
            # Untouched cases remain scheduled. Evaluator marks them not-run/fail-fast.
            remaining = manifest.execution_order[manifest.execution_order.index(case_id) + 1:]
            for skipped in remaining:
                recorder.append('evaluated', skipped, 'not-run', data={'partition': 'not-run', 'reason': 'fail-fast',
                                                                      'evaluation_identity': 'fail-fast-v1'})
            break
    return destination
