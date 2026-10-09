"""Sequential parent orchestrator owns truth, schedule, process lifecycle and recorder."""
from __future__ import annotations

from dataclasses import asdict, replace
from contextlib import nullcontext
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
import uuid
from importlib.metadata import distributions

from benchmarks.common.contracts import (CaseExecution, OperationalCaseInput, RunManifest,
                                        RuntimeSettings, decode, digest, file_hash, write_new, read_json)
from benchmarks.common.recorder import Recorder
from .classification import RunKind, write_run_classification
from .runtime import CAPABILITY, REPO
from .storage import allocate_run, bind_storage, resolve_run
from ..reset.client import ResetBlocked, persist


def reproducibility() -> dict:
    def git(*args):
        proc = subprocess.run(['git', '-C', str(REPO), *args], capture_output=True, text=True)
        return proc.stdout.strip() if proc.returncode == 0 else None
    dirty = git('status', '--porcelain')
    return {'kagent_commit': git('rev-parse', 'HEAD'), 'kagent_dirty': bool(dirty) if dirty is not None else None,
            'python': platform.python_version(), 'platform': platform.platform(),
            'skills': {str(p.relative_to(REPO)): file_hash(p)
                       for cls in ('sql-injection', 'cross-site-scripting')
                       for p in sorted((REPO / 'skills' / cls).rglob('*')) if p.is_file()},
            'source_snapshot_version': 1,
            'runtime_files': {str(p.relative_to(REPO)): file_hash(p)
                              for p in sorted({
                                  *REPO.joinpath('src').rglob('*.py'),
                                  *REPO.joinpath('benchmarks/common').rglob('*.py'),
                                  *REPO.joinpath('benchmarks/scenario1').rglob('*.py'),
                                  *REPO.joinpath('benchmarks/scenario1/reset/java').rglob('*.java'),
                                  *REPO.joinpath('benchmarks/scenario1/reset/tests').rglob('*.java'),
                                  REPO / 'benchmarks/scenario1/reset/run-target.sh',
                                  *(REPO / name for name in ('pyproject.toml', 'requirements.txt', 'pyrightconfig.json')),
                              }) if p.is_file() and not p.is_symlink()
                              and not p.is_relative_to(REPO / 'benchmarks/scenario1/reset/evidence')},
            'dependencies': sorted((d.metadata['Name'], d.version) for d in distributions()
                                   if d.metadata['Name']),
            'capability_profile': CAPABILITY}


def validate_runtime(manifest: RunManifest, settings: RuntimeSettings, *, verified_reset=False):
    if not settings.authorized_lab:
        raise ValueError('explicit --authorized-lab declaration required')
    if manifest.dataset.get('state_mutating_cases') and not verified_reset:
        raise ValueError('selected servlets mutate target state; HTTP-only profile has no verified per-case '
                         'isolation/readback/cleanup. external-reset is only a declaration; selection must exclude these cases')


def validate_run_kind(manifest: RunManifest, kind: RunKind):
    if kind not in {'development', 'official'}:
        raise ValueError('run kind must be development or official')
    if manifest.mode == 'smoke' and kind == 'official':
        raise ValueError('smoke run cannot be official')


def envelope(op: dict, settings: RuntimeSettings, run_id: str, execution_id: str, workspace: Path, output: Path) -> dict:
    decode(OperationalCaseInput, op)
    return {'operational': op, 'settings': asdict(settings), 'run_id': run_id, 'execution_id': execution_id,
            'workspace': str(workspace), 'output': str(output)}


def launch_worker(envelope: dict, seconds: float) -> tuple[int, bool]:
    env = dict(os.environ)
    env['PYTHONPATH'] = str(REPO)
    env['KAGENT_PROJECT_ROOT'] = envelope['workspace']
    env.pop('KAgent_TRACE_AGENT', None)
    proc = subprocess.Popen([sys.executable, '-m', 'benchmarks.scenario1.core.worker'], cwd=REPO, env=env,
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


def run(manifest: RunManifest, settings: RuntimeSettings, destination: Path, *, run_kind: RunKind = 'development',
        fail_fast=False, launcher=launch_worker, reset_controller=None, reset_audit: Path | None = None,
        resume_from: Path | None = None, observer=None, invocation_metadata: dict | None = None) -> Path:
    ownership = reset_controller.ownership() if reset_controller is not None else nullcontext()
    with ownership:
        try:
            return _run(manifest, settings, destination, run_kind=run_kind, fail_fast=fail_fast, launcher=launcher,
                        reset_controller=reset_controller, reset_audit=reset_audit, resume_from=resume_from,
                        observer=observer, invocation_metadata=invocation_metadata)
        except BaseException:
            if reset_controller is not None:
                reset_controller.block()
            raise


def _run(manifest: RunManifest, settings: RuntimeSettings, destination: Path, *, run_kind: RunKind,
         fail_fast, launcher, reset_controller, reset_audit, resume_from, observer, invocation_metadata) -> Path:
    def observe(row):
        if observer is not None:
            try:
                observer(row)
            except Exception:
                pass  # Presentation failures never affect admission or scheduling.

    def receipt(case_id, phase, operation):
        return persist(destination, case_id, phase, operation, observer=observe)
    validate_runtime(manifest, settings, verified_reset=reset_controller is not None)
    if launcher is launch_worker and reset_controller is None:
        raise ResetBlocked('production execution requires --reset-state or --container with verified logical reset')
    validate_run_kind(manifest, run_kind)
    public = Path(os.path.abspath(destination))
    if resume_from is not None:
        resume_from = resolve_run(resume_from)
    destination = allocate_run(public)
    admission_error = None
    if reset_controller is not None:
        try:
            persist(destination, manifest.execution_order[0], 'block', reset_controller.begin)
        except BaseException as err:
            # Retain the normal immutable manifest/scheduled history and blocker
            # even when initial closure fails; no worker will be admitted.
            admission_error = err
    repro = reproducibility()
    if invocation_metadata is not None:
        repro['invocation'] = invocation_metadata
    bound = replace(manifest, runtime=asdict(settings), reproducibility=repro)
    write_new(destination / 'manifest.json', asdict(bound))
    classification = write_run_classification(destination, run_kind)
    bind_storage(destination, public)
    audit_hash = file_hash(reset_audit) if reset_audit else None
    write_new(destination / 'reset-policy.json', {
        'enabled': reset_controller is not None,
        'mode': 'logical-reset-all-cases' if reset_controller is not None else 'offline-injected-launcher',
        'scope_verdict': 'PARTIAL',
        'external_effects_restoration_verified': False,
        'audit_role': 'historical-context-only',
        'audit_sha256': audit_hash,
        'resume_from': str(resume_from.resolve()) if resume_from else None,
        'resume_policy': 'new immutable run; reset and reverify; never append or trust prior target state'})
    # Resume preserves the exact locked manifest and re-executes it in a new run.
    # Existing recorder/evaluator history is immutable; no partial result is trusted.
    if resume_from is not None:
        previous = decode(RunManifest, read_json(resume_from / 'manifest.json'))
        for name in ('dataset', 'truth', 'operational', 'execution_order', 'seed', 'mode'):
            if getattr(previous, name) != getattr(manifest, name):
                raise ResetBlocked('resume selection identity mismatch')
    recorder = Recorder(destination / 'events.jsonl', manifest.run_id)
    operations = {o['case_id']: o for o in manifest.operational}
    for case_id in manifest.execution_order:
        recorder.append('scheduled', case_id, 'scheduled', data={'operational_hash': digest(operations[case_id]),
                                                               'manifest_hash': classification.manifest_identity})
    for case_id in manifest.execution_order:
        if reset_controller is not None:
            try:
                if admission_error is not None:
                    raise admission_error
                if hasattr(reset_controller, 'identity_verified'):
                    persist(destination, case_id, 'identity', lambda: reset_controller.check_identity(manifest, settings))
                else:
                    reset_controller.check_identity(manifest, settings)
                if reset_audit and file_hash(reset_audit) != audit_hash:
                    raise ResetBlocked('historical audit evidence changed during run')
                receipt(case_id, 'before', reset_controller.reset)
                persist(destination, case_id, 'authorize', lambda: reset_controller.authorize(operations[case_id], settings))
            except BaseException as err:
                reset_controller.block()
                block_run(destination, recorder, manifest, case_id, 'admission', type(err).__name__,
                          detail=str(err) if isinstance(err, ResetBlocked) else None)
                if not isinstance(err, Exception):
                    raise
                break
        execution_id = uuid.uuid4().hex
        output = destination / 'results' / f'{case_id}.json'
        workspace = destination / 'workspaces' / execution_id
        output.parent.mkdir(exist_ok=True, mode=0o700)
        recorder.append('started', case_id, 'started', execution_id=execution_id,
                        data={'workspace_ref': str(workspace.relative_to(destination))})
        observe(recorder.rows[-1])
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
        except BaseException as err:
            if reset_controller is not None:
                try:
                    persist(destination, case_id, 'interrupted', reset_controller.reset)
                except BaseException:
                    pass
                reset_controller.block()
                block_run(destination, recorder, manifest, case_id, 'interrupted', type(err).__name__)
            raise
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
        observe(recorder.rows[-1])
        if reset_controller is not None:
            try:
                receipt(case_id, 'after', reset_controller.reset)
            except BaseException as err:
                reset_controller.block()
                following = manifest.execution_order[manifest.execution_order.index(case_id) + 1:]
                block_run(destination, recorder, manifest, following[0] if following else None,
                          'after', type(err).__name__)
                if not isinstance(err, Exception):
                    raise
                break
        if fail_fast and status != 'completed':
            # Untouched cases remain scheduled. Evaluator marks them not-run/fail-fast.
            remaining = manifest.execution_order[manifest.execution_order.index(case_id) + 1:]
            for skipped in remaining:
                recorder.append('evaluated', skipped, 'not-run', data={'partition': 'not-run', 'reason': 'fail-fast',
                                                                      'evaluation_identity': 'fail-fast-v1'})
                observe(recorder.rows[-1])
            break
    if reset_controller is not None and not (destination / 'blocked.json').exists():
        try:
            # The last case's verified 'after' reset is the final reset. Never
            # publish idle from a finally block or after uncertain execution.
            persist(destination, case_id, 'idle', reset_controller.idle)
        except BaseException as err:
            reset_controller.block()
            block_run(destination, recorder, manifest, None, 'idle', type(err).__name__)
            if not isinstance(err, Exception):
                raise
    return destination


def block_run(destination, recorder, manifest, next_case, phase, error, *, detail=None):
    write_new(destination / 'blocked.json', {'status': 'blocked', 'phase': phase, 'error': error,
                                            'next_case': next_case, 'reason': 'unverified target state or boundary',
                                            'detail': detail})
    if next_case is not None:
        for case_id in manifest.execution_order[manifest.execution_order.index(next_case):]:
            # An interrupted case remains started, retaining the evaluator's
            # existing interrupted-execution treatment. Only untouched cases are not-run.
            records = [row for row in recorder.rows if row['case_id'] == case_id]
            if records[-1]['kind'] == 'scheduled':
                recorder.append('evaluated', case_id, 'not-run', data={'partition': 'not-run',
                    'reason': 'fail-fast', 'block_reason': 'reset-blocked', 'evaluation_identity': 'fail-fast-v1'})
