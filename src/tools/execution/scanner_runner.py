"""Managed trusted-host jobs, separate from the ordinary Worker/broker path.

Containment covers orderly runtime lifecycle and trusted binaries/process groups.
It does not cover controller SIGKILL or a malicious child escaping its session.
"""
from __future__ import annotations

import asyncio
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
import inspect
from pathlib import Path
import re
import signal as signals
import time
from typing import Any, Callable, Coroutine, TYPE_CHECKING
import uuid
from src.async_io import run_sync, check_worker

from src.permission.runtime.execution import ExecutionBlocked
from src.engagement.state import format_tcp_ports
from src.tools.common.outcome import ToolOutput
from src.tools.discovery.scanner_results import MAX_DATASET, ParsedScan, clean, encode, parse_scan
from src.tools.execution.scanner_files import PrivateJob, ScannerStorageLimit

if TYPE_CHECKING:
    from src.tools.execution.scanners import ScannerBinding, ScannerPlan

# Deliberately build-specific: other installed binaries are unavailable until
# their local wire/config/resource/lifecycle acceptance is recorded. No probing
# executable, unreviewed flags, or network is inferred from a display version.
SUPPORTED_BUILDS = {
    'nmap': {'dfdfb438e214b82f1a8701d9ca94eca0156c710a663261f1bd595f98a53662fc': '7.98'},
    'ffuf': {'98691701fc3d6a7e5c68baa5fbbcd48650177017e47ea54d5eae94cfe731b0c3': '2.1.0-dev'},
}
POLL_SECONDS = 0.05
TERM_GRACE = 0.2
DRAIN_SECONDS = 1.0
# Like the result cache, saturation limits new publication without deleting
# evidence that a saved session may still reference. Per-job bytes stay bounded.
MAX_RETAINED_JOBS = 32
MAX_MANIFEST_BYTES = 32 * 1024


@dataclass(slots=True)
class ScannerResult:
    """Transient producer object. Never deserialize this from tool text."""
    envelope: dict[str, Any]
    dataset: bytes
    record_ids: frozenset[str]
    plan: ScannerPlan
    manifest_sha256: str | None = None
    observation_fingerprints: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScannerHooks:
    started: Callable[[str, ScannerPlan, float], Coroutine[Any, Any, None] | None]
    finished: Callable[[ScannerResult], None]


hooks: ContextVar[ScannerHooks | None] = ContextVar('scanner_runtime_hooks', default=None)


def normalize(data: bytes, plan: ScannerPlan, secrets: tuple[str, ...]) -> tuple[ParsedScan, bytes, tuple[str, ...]]:
    """Pure worker operation; no runtime authority, hooks or filesystem commits."""
    parsed = parse_scan(data, plan) if data else ParsedScan(validity='missing', coverage_complete=False)
    retained, retained_bytes = [], 0
    for row in parsed.records:
        for key, value in row.items():
            if isinstance(value, str):
                row[key] = clean(value, 16384, secrets)
        size = len(encode(row)) + 1
        if retained_bytes + size > plan.resources.normalized_bytes:
            parsed.dataset_truncated = True
            parsed.validity = 'partial'
            parsed.coverage_complete = False
            parsed.reason = 'normalized_output_limit'
            break
        retained.append(row)
        retained_bytes += size
    parsed.records = retained
    from src.workflow.discovery.scanner import observation_fingerprints
    dataset = parsed.dataset()
    return parsed, dataset, observation_fingerprints(dataset, plan.semantic_key)


def diagnostic_stream(buffer, secrets: tuple[str, ...]) -> dict[str, Any]:
    """Keep bounded native faults/frames, never echo arbitrary scanner payloads.

    Regex redaction alone cannot recognize an unlabelled response/word/secret.
    Unclassified lines are counted and omitted. Go frames lose arguments and
    local source paths; known fault labels and OS errors retain useful cause.
    """
    lines = []
    omitted = 0
    native_fault = False
    faults = {'concurrent map writes', 'concurrent map read and map write',
              'concurrent map iteration and map write', 'out of memory',
              'all goroutines are asleep - deadlock!'}
    system_errors = ('resource temporarily unavailable', 'too many open files', 'cannot allocate memory',
                     'permission denied', 'no space left on device', 'connection refused', 'i/o timeout')
    for line in buffer.render().splitlines():
        line = clean(line, 2048, secrets).strip()
        safe = None
        # Native terminal progress can share a line with a crash. Do not
        # require the fault label to be the first bytes of that line.
        fault = re.search(r'\b(fatal error|panic|runtime error):\s*(.*)', line)
        if fault is not None and fault[1] == 'fatal error':
            native_fault = True
            cause = fault[2].strip()
            safe = 'fatal error: ' + (cause if cause in faults else '[unclassified diagnostic redacted]')
        elif fault is not None:
            native_fault = True
            cause = ('runtime error: ' if fault[1] == 'runtime error' else '') + fault[2].strip()
            safe = 'panic: ' + (cause if re.fullmatch(
                r'runtime error: (?:invalid memory address or nil pointer dereference|'
                r'(?:index|slice) bounds out of range[0-9 :\[\]-]*(?:with (?:length|capacity) [0-9]+)?)', cause)
                else '[unclassified diagnostic redacted]')
        elif re.match(r'(?:SIGSEGV|SIGABRT|SIGBUS|SIGILL|SIGFPE):', line):
            native_fault = True
            safe = line.partition(':')[0] + ': [native signal details redacted]'
        elif re.fullmatch(r'goroutine [0-9]+ \[[A-Za-z ,]+\]:', line):
            native_fault = True
            safe = 'native Go stack: [goroutine metadata redacted]'
        elif native_fault and re.match(r'github\.com/ffuf/ffuf(?:/v[0-9]+)?/', line):
            # Function arguments and source locations can contain payloads.
            frame = line.rsplit('(', 1)[0]
            if re.fullmatch(r'[a-zA-Z0-9_./*()-]+', frame):
                safe = 'frame: ' + frame
        else:
            errors = [error for error in system_errors if error in line.lower()]
            if errors:
                safe = 'system error: ' + ', '.join(errors)
        if safe is None or sum(len(item) + 1 for item in lines) + len(safe) > 2048:
            omitted += 1
        else:
            lines.append(safe)
    return {'bytes': buffer.total, 'text': '\n'.join(lines), 'omitted_lines': omitted,
            'capture_truncated': buffer.total > buffer.cap, 'untrusted': True}


def normalize_capture(data: bytes, plan: ScannerPlan, secrets: tuple[str, ...], out, err):
    parsed, dataset, fingerprints = normalize(data, plan, secrets)
    # Pumps have been joined. Diagnostic minimization is also CPU work over
    # untrusted text and belongs to the same owned, side-effect-free worker.
    return parsed, dataset, fingerprints, diagnostic_stream(out, secrets), diagnostic_stream(err, secrets)


async def join_owned(task: asyncio.Task) -> Any:
    """Join an owned cleanup/spawn task despite repeated caller cancellation."""
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            continue
    return task.result()


class ScannerRuntime:
    def __init__(self):
        self.task: asyncio.Task | None = None
        self.closed = False
        self.generation = 0

    def invalidate(self) -> None:
        self.generation += 1
        if self.task is not None and not self.task.done():
            self.task.cancel()

    async def drain(self, *, close: bool = False) -> None:
        caller = asyncio.current_task()
        cancellation_count = caller.cancelling() if caller is not None else 0
        self.invalidate()
        self.closed |= close
        task = self.task
        if task is not None and not task.done():
            try:
                await join_owned(task)
            except asyncio.CancelledError:
                pass
        if caller is not None and caller.cancelling() > cancellation_count:
            raise asyncio.CancelledError

    async def run(self, binding: ScannerBinding, tool: Any, args: dict[str, Any], abort: Any) -> ToolOutput:
        if self.closed:
            raise ExecutionBlocked('blocked: scanner runtime closed')
        if self.task is not None and not self.task.done():
            raise ExecutionBlocked('Scanner is busy. Only one job can run at a time. Retry with a new invocation.')
        assert tool.scanner_plan is not None
        task = asyncio.create_task(_execute(binding, tool, args, abort), name='trusted-scanner-job')
        self.task = task
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            task.cancel()
            try:
                await join_owned(task)
            except asyncio.CancelledError:
                pass
            raise
        finally:
            if self.task is task and task.done():
                self.task = None


async def terminate(proc: asyncio.subprocess.Process, pumps: list[asyncio.Task]) -> None:
    from src.tools.execution.shell import kill_process_group
    # Signal the group even when the leader already exited. Descendants may
    # hold stdout/stderr and proc.wait() need not have completed yet.
    try:
        os.killpg(proc.pid, 0)
    except ProcessLookupError:
        pass
    else:
        kill_process_group(proc.pid)
        await asyncio.sleep(TERM_GRACE)
        kill_process_group(proc.pid, signals.SIGKILL)
    try:
        await asyncio.wait_for(proc.wait(), DRAIN_SECONDS)
        await asyncio.wait_for(asyncio.gather(*pumps), DRAIN_SECONDS)
    except asyncio.TimeoutError:
        for task in pumps:
            task.cancel()
        await asyncio.gather(*pumps, return_exceptions=True)
        # Close pipe transports only after bounded drain. No output is streamed.
        for stream in (proc.stdout, proc.stderr):
            transport = getattr(stream, '_transport', None)
            if transport is not None:
                transport.close()
        if proc.returncode is None:
            raise RuntimeError('scanner leader could not be reaped')


def publish(binding: ScannerBinding, plan: ScannerPlan, job_id: str, envelope: dict[str, Any], dataset: bytes,
            session_id: str, *, check: Callable[[], None] | None = None) -> str | None:
    if len(dataset) > MAX_DATASET:
        raise ScannerStorageLimit('scanner artifact retention limit reached')
    session = hashlib.sha256(session_id.encode()).hexdigest()
    private = PrivateJob(binding.policy.root, ('.kagent', 'scanners', session, job_id),
                         max_siblings=MAX_RETAINED_JOBS, check=check)
    committed = False
    try:
        private.write('normalized.jsonl', dataset)
        relative = private.path.relative_to(binding.policy.root).as_posix()
        artifacts = {**envelope['artifacts'], 'manifest': relative + '/manifest.json',
                     'normalized': relative + '/normalized.jsonl', 'dataset_sha256': hashlib.sha256(dataset).hexdigest()}
        # No receipt, authority epoch/grant ID, raw argv/config/diagnostics, or
        # execution tokens survive. Manifest-last is the publication commit.
        manifest = encode({**{k: v for k, v in envelope.items() if k != 'records'}, 'artifacts': artifacts})
        if len(manifest) > MAX_MANIFEST_BYTES:
            raise ScannerStorageLimit('scanner artifact retention limit reached')
        # Prepare the manifest privately, then linearize manifest-last visibility
        # against the existing turn owner and live scanner authority.
        private.write('manifest.json', manifest)
        os.fsync(private.fds[-1])
        committed = True
        envelope['artifacts'].update(artifacts)
        return hashlib.sha256(manifest).hexdigest()
    finally:
        private.close(remove=not committed)


async def publish_async(binding, plan, job_id, envelope, dataset, session_id, *, check=None):
    result = await run_sync(publish, binding, plan, job_id, envelope, dataset, session_id, check=check)
    if check is not None:
        check()
    return result


async def _execute(binding: ScannerBinding, tool: Any, args: dict[str, Any], abort: Any) -> ToolOutput:
    from src.tools.execution.shell import HeadTailBuffer
    plan: ScannerPlan = tool.scanner_plan
    policy = binding.policy
    session_id = policy.session_id or policy.engagement.http_permissions.session_id
    version = SUPPORTED_BUILDS.get(plan.scanner, {}).get(plan.binary.sha256)
    if version is None:
        raise ExecutionBlocked('Unsupported scanner build. Local binary acceptance is required.')
    policy.revalidate_active(tool, args, abort)
    job_id = 'scan_' + uuid.uuid4().hex
    generation = binding.runtime.generation
    runtime_hooks = hooks.get()
    private: PrivateJob | None = None
    scratch: list[PrivateJob] = []
    proc: asyncio.subprocess.Process | None = None
    pumps: list[asyncio.Task] = []
    checkpoint_task: asyncio.Task | None = None
    out, err = HeadTailBuffer(plan.resources.capture_bytes), HeadTailBuffer(plan.resources.capture_bytes)
    raw = b''
    reason, status = 'process_exit', 'completed'
    cancelled = False
    spawned_at: float | None = None
    started_at: str | None = None
    started = time.monotonic()
    deadline = started + plan.timeout_seconds

    async def pump(stream, buffer):
        while chunk := await stream.read(16384):
            buffer.push(chunk)

    try:
        parts = tuple(Path(plan.directory).relative_to(policy.root).parts)
        if len(parts) != 4 or parts[:3] != ('.kagent', 'tmp', 'scanners'):
            raise ExecutionBlocked('blocked: unmanaged scanner scratch path')
        def prepare_scratch():
            check_worker()
            policy.revalidate_active(tool, args, abort)
            prepared = PrivateJob(policy.root, parts)
            scratch.append(prepared)
            prepared.write(plan.output_name, b'')
            if plan.wordlist is not None:
                prepared.write('words.txt', plan.wordlist.data)
            for directory in ('home', 'xdg', 'tmp'):
                prepared.mkdir(directory)
            return prepared
        private = await run_sync(prepare_scratch)
        # No inherited proxy, LD, provider, Python, ffufrc or Nmap overrides.
        environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                       'HOME': str(private.path / 'home'), 'XDG_CONFIG_HOME': str(private.path / 'xdg'),
                       'TMPDIR': str(private.path / 'tmp'), 'GOMEMLIMIT': '1GiB'}
        policy.revalidate_active(tool, args, abort)
        await run_sync(private.validate)
        async def spawn_current():
            assert private is not None
            # This task can be scheduled after the caller's last check. Check
            # again inside the owner immediately before the Linux exec handoff.
            policy.revalidate_active(tool, args, abort)
            await run_sync(private.validate)
            policy.revalidate_active(tool, args, abort)
            if time.monotonic() >= deadline:
                raise TimeoutError('scanner deadline before spawn')
            return await asyncio.create_subprocess_exec(*plan.command,
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                cwd=plan.directory, env=environment, start_new_session=True, umask=0o077)
        spawn = asyncio.create_task(spawn_current())
        try:
            proc = await asyncio.shield(spawn)
        except asyncio.CancelledError:
            # Spawn owns creation. A late child must be recovered before the
            # cancellation can release the slot or close its owning runtime.
            proc = await join_owned(spawn)
            raise
        assert proc is not None
        spawned_at = time.monotonic()
        started_at = datetime.now(UTC).isoformat()
        assert proc.stdout is not None and proc.stderr is not None
        pumps = [asyncio.create_task(pump(proc.stdout, out)), asyncio.create_task(pump(proc.stderr, err))]
        policy.revalidate_active(tool, args, abort)
        if runtime_hooks is not None:
            checkpoint = runtime_hooks.started(job_id, plan, spawned_at)
            if inspect.isawaitable(checkpoint):
                checkpoint_task = asyncio.create_task(checkpoint, name='scanner-running-checkpoint')
        while proc.returncode is None:
            policy.revalidate_active(tool, args, abort)
            if checkpoint_task is not None and checkpoint_task.done():
                checkpoint_task.result()
            if binding.runtime.generation != generation:
                raise ExecutionBlocked('blocked: scanner runtime invalidated')
            if time.monotonic() >= deadline:
                status, reason = 'failed', 'timeout'
                break
            if await run_sync(private.size, plan.output_name) >= plan.resources.file_bytes:
                status, reason = 'failed', 'machine_output_limit'
                break
            await asyncio.sleep(POLL_SECONDS)
        if proc.returncode is not None and proc.returncode != 0:
            status, reason = 'failed', 'nonzero_exit'
    except asyncio.CancelledError:
        task = asyncio.current_task()
        cancelled = bool(task is not None and task.cancelling())
        status, reason = 'cancelled', 'task_cancelled' if cancelled else 'abort_requested'
    except (ExecutionBlocked, PermissionError):
        status, reason = 'cancelled' if getattr(abort, 'aborted', False) else 'failed', 'authority_changed'
    except Exception:
        status, reason = (('cancelled', 'abort_requested') if getattr(abort, 'aborted', False)
                          else ('failed', 'setup_or_execution_failure'))
    finally:
        if proc is not None:
            cleanup = asyncio.create_task(terminate(proc, pumps), name='scanner-process-cleanup')
            try:
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    cancelled, status, reason = True, 'cancelled', 'task_cancelled'
                    await join_owned(cleanup)
            except Exception:
                status, reason = 'failed', 'cleanup_failed'
                binding.runtime.closed = True
        if checkpoint_task is not None:
            # A slow session writer cannot delay active authority/deadline
            # monitoring or process teardown. Join it after stopping the child
            # and before terminal state can replace the running snapshot.
            try:
                try:
                    await asyncio.shield(checkpoint_task)
                except asyncio.CancelledError:
                    cancelled, status, reason = True, 'cancelled', 'task_cancelled'
                    await join_owned(checkpoint_task)
            except Exception:
                status, reason = 'failed', 'checkpoint_failed'
        if private is None and scratch:
            private = scratch[0]
        if private is not None:
            try:
                raw = await run_sync(private.read, plan.output_name, plan.resources.file_bytes)
            except asyncio.CancelledError:
                cancelled, status, reason = True, 'cancelled', 'task_cancelled'
            except Exception:
                if status == 'completed':
                    status, reason = 'failed', 'machine_output_unavailable'
            finally:
                try:
                    await run_sync(private.close, remove=True)
                except asyncio.CancelledError:
                    cancelled, status, reason = True, 'cancelled', 'task_cancelled'
                except Exception:
                    status, reason = 'failed', 'scratch_cleanup_failed'
    # Final revalidation closes the exit/publish race without discarding useful
    # sanitized observations from a failed/revoked/cancelled historical job.
    try:
        policy.revalidate_active(tool, args, abort)
    except (Exception, asyncio.CancelledError):
        if status == 'completed':
            status, reason = 'failed', 'authority_changed'
    secrets = tuple(policy.internal_secret_values())
    # Parsing, redaction, sorting and JSONL encoding share one owned worker.
    # Join on cancellation: the thread cannot outlive the job/slot. It has no
    # authority to publish, and the controller rechecks authority after joining.
    parsing = asyncio.create_task(asyncio.to_thread(normalize_capture, raw, plan, secrets, out, err), name='scanner-normalization')
    try:
        parsed, dataset, fingerprints, stdout_diagnostic, stderr_diagnostic = await asyncio.shield(parsing)
    except asyncio.CancelledError:
        cancelled, status, reason = True, 'cancelled', 'task_cancelled'
        parsed, dataset, fingerprints, stdout_diagnostic, stderr_diagnostic = await join_owned(parsing)
    publication_allowed = True
    try:
        policy.revalidate_active(tool, args, abort)
        if binding.runtime.generation != generation:
            raise ExecutionBlocked('blocked: scanner runtime invalidated')
        if cancelled:
            raise asyncio.CancelledError
    except (Exception, asyncio.CancelledError):
        # Historical terminal outcome may still close its running checkpoint;
        # observations parsed under retired authority cannot be committed late.
        parsed = ParsedScan(validity='discarded', coverage_complete=False)
        dataset = b''
        fingerprints = ()
        publication_allowed = False
        if status == 'completed':
            status, reason = 'failed', 'authority_changed'
    if parsed.validity != 'valid' or parsed.dataset_truncated:
        if status == 'completed':
            status, reason = ('partial' if parsed.records else 'failed',
                              'normalized_output_limit' if parsed.reason == 'normalized_output_limit' else 'parse_failure')
    if parsed.reason and status == 'completed':
        status, reason = 'partial', ('native_timeout' if 'timeout' in parsed.reason else 'parse_incomplete')
    if status != 'completed':
        parsed.coverage_complete = False
    error_kind = ('cancelled' if status == 'cancelled' else 'timeout' if reason in {'timeout', 'native_timeout'}
                  else 'policy_block' if reason == 'authority_changed' else 'tool_exception')
    options = {'timeout_seconds': plan.timeout_seconds, 'rate': args.get('rate')}
    if plan.scanner == 'ffuf':
        options.update(threads=args.get('threads', 40), request_timeout_seconds=args.get('request_timeout_seconds', 10),
            calibration=args.get('calibration', False), match_status=plan.argv[plan.argv.index('-mc') + 1],
            filter_status=(plan.argv[plan.argv.index('-fc') + 1] if '-fc' in plan.argv else None),
            filter_size=args.get('filter_size'))
    envelope = {'schema_version': 1, 'permission_unit': 'scanner_job', 'job_id': job_id, 'scanner': plan.scanner,
        'plan_digest': plan.digest, 'semantic_key': plan.semantic_key,
        'binary': {'sha256': plan.binary.sha256, 'version': version},
        'resource_profile': plan.resources.version,
        'options': options,
        'target': {'origin': clean(plan.origin.as_url(), secrets=secrets), 'address': plan.address,
                   'ports': list(plan.ports) if len(plan.ports) <= 32 else None,
                   'port_set': format_tcp_ports(plan.ports)[:512],
                   'port_set_sha256': hashlib.sha256(format_tcp_ports(plan.ports).encode()).hexdigest(),
                   'template': clean(args.get('url', ''), 2048, secrets=secrets) or None},
        'wordlist': {'id': plan.wordlist.name, 'sha256': plan.wordlist.sha256} if plan.wordlist else None,
        'execution': {'status': status, 'exit_code': proc.returncode if proc else None, 'reason': reason,
                      'started_at': started_at, 'finished_at': datetime.now(UTC).isoformat(),
                      'duration_ms': round((time.monotonic() - (spawned_at or started)) * 1000)},
        'parse': {'status': parsed.validity, 'partial': status != 'completed' or parsed.validity != 'valid',
                  'coverage_complete': parsed.coverage_complete},
        'summary': {'unique_records': len(parsed.records), 'returned_records': min(10, len(parsed.records)),
                    'rejected_records': parsed.rejected, 'duplicates': parsed.duplicates, 'conflicts': parsed.conflicts},
        'records': parsed.records[:10],
        'truncation': {'summary': len(parsed.records) > 10 or len(format_tcp_ports(plan.ports)) > 512
                       or len(args.get('url', '')) > 2048, 'dataset': parsed.dataset_truncated,
                       'diagnostics': out.total > out.cap or err.total > err.cap},
        'artifacts': {'manifest': None, 'normalized': None, 'result_refs': [], 'retrieval': 'unavailable'},
        'raw_source': {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)},
        'error': None if status == 'completed' else {'category': error_kind, 'retryable': reason not in {'authority_changed', 'cleanup_failed'},
                                                    'message': reason},
        'diagnostics': {'stdout_bytes': out.total, 'stderr_bytes': err.total,
            'stdout': stdout_diagnostic if status != 'completed' else None,
            'stderr': stderr_diagnostic if status != 'completed' else None,
            'resources': {**asdict(plan.resources), 'cpu_seconds': plan.timeout_seconds + 5,
                          'timeout_seconds': plan.timeout_seconds, 'core_bytes': 0, 'go_memory_target_bytes': 1024**3}}}
    manifest_hash = None
    publication_discarded = False
    if publication_allowed:
        try:
            def current_publication():
                policy.revalidate_active(tool, args, abort)
                if binding.runtime.generation != generation:
                    raise ExecutionBlocked('blocked: scanner runtime invalidated')
            manifest_hash = await publish_async(binding, plan, job_id, envelope, dataset, session_id,
                                               check=current_publication)
            current_publication()
        except asyncio.CancelledError:
            cancelled = True
            status, reason, error_kind = 'cancelled', 'task_cancelled', 'cancelled'
            publication_discarded = True
        except ScannerStorageLimit:
            envelope['artifacts'].update(retrieval='retrieval_limited',
                publication_error='scanner artifact retention limit reached')
        except (ExecutionBlocked, PermissionError):
            status, reason, error_kind = 'failed', 'authority_changed', 'policy_block'
            publication_discarded = True
        except Exception:
            envelope['artifacts']['retrieval'] = 'unavailable'
            envelope['artifacts']['publication_error'] = 'private scanner artifacts unavailable'
    if publication_discarded:
        # The envelope already owns a sample slice. Clearing only parsed.records
        # leaves stale samples/counts and a successful ToolOutput after revoke.
        parsed = ParsedScan(validity='discarded', coverage_complete=False)
        dataset, fingerprints, manifest_hash = b'', (), None
        envelope['execution'].update(status=status, reason=reason)
        envelope['records'] = []
        envelope['summary'].update(unique_records=0, returned_records=0)
        envelope['parse'].update(status='discarded', partial=True, coverage_complete=False)
        envelope['artifacts'].update(manifest=None, normalized=None, retrieval='unavailable', result_refs=[])
        envelope['artifacts'].pop('dataset_sha256', None)
        envelope['error'] = {'category': error_kind, 'retryable': reason != 'authority_changed', 'message': reason}
    produced = ScannerResult(envelope, dataset, frozenset(row['id'] for row in parsed.records), plan, manifest_hash, fingerprints)
    if runtime_hooks is not None:
        runtime_hooks.finished(produced)
    # Budget includes metadata. Trimming samples does not change dataset facts.
    while len(encode(envelope)) > 12 * 1024 and envelope['records']:
        envelope['records'].pop()
        envelope['summary']['returned_records'] = len(envelope['records'])
        envelope['truncation']['summary'] = True
    if len(encode(envelope)) > 12 * 1024:
        envelope['options'] = {'sha256': hashlib.sha256(encode(options)).hexdigest(), 'detail': 'effective options in private manifest'}
        envelope['truncation']['summary'] = True
    output = ToolOutput(encode(envelope).decode(), status='observation' if status == 'completed' else
        'cancelled' if status == 'cancelled' else 'error', error_kind=None if status == 'completed' else error_kind)
    output.scanner_result = produced
    if cancelled:
        raise asyncio.CancelledError
    return output
