"""Bounded historical scanner handoff. No execution or authorization state."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field, asdict
import hashlib
import json
import re
from typing import Any

from src.tools.discovery.scanner_results import clean
from src.tools.execution.scanner_files import read_private

MAX_JOBS = 32
MAX_TRIAGE = 128
# Append-only progress history saturates rather than forgetting known observations
# and crediting a later subset again. Digests contain no scanner text or secrets.
MAX_OBSERVATION_FACTS = 8192


def observation_scope(objective_id: str | None, origin: str) -> str:
    return hashlib.sha256(json.dumps([objective_id, origin]).encode()).hexdigest()


def observation_fingerprints(dataset: bytes, semantic_key: str) -> tuple[str, ...]:
    # Called in the normalization worker. A saturated ledger conservatively
    # stops crediting observations; it never evicts a digest to make room.
    rows = dataset.splitlines()
    return tuple(hashlib.sha256(json.dumps([semantic_key, json.loads(line)], sort_keys=True,
        separators=(',', ':')).encode()).hexdigest() for line in rows[:MAX_OBSERVATION_FACTS])


@dataclass(slots=True)
class ScannerJob:
    job_id: str
    semantic_key: str
    target_origin: str
    objective_id: str | None
    scanner: str
    execution: dict[str, Any]
    parse: dict[str, Any]
    counts: dict[str, Any]
    artifacts: dict[str, Any]
    manifest_sha256: str | None
    wordlist: dict[str, Any] | None
    port_set: str
    sample_ids: list[str] = field(default_factory=list)
    dispositions: dict[str, dict[str, str]] = field(default_factory=dict)
    remaining: dict[str, str] | None = None
    options: dict[str, Any] = field(default_factory=dict)
    binary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Any) -> ScannerJob | None:
        try:
            if not isinstance(value, dict) or len(json.dumps(value)) > 48 * 1024:
                return None
            job = cls(**deepcopy(value))
            if (not re.fullmatch(r'scan_[0-9a-f]{32}', job.job_id)
                    or not re.fullmatch(r'[0-9a-f]{64}', job.semantic_key)
                    or job.scanner not in {'nmap', 'ffuf'}
                    or not isinstance(job.target_origin, str) or len(job.target_origin) > 2048
                    or (job.objective_id is not None and (not isinstance(job.objective_id, str) or len(job.objective_id) > 256))
                    or any(not isinstance(item, dict) for item in (job.execution, job.parse, job.counts, job.artifacts, job.dispositions))
                    or len(job.dispositions) > MAX_TRIAGE or not isinstance(job.sample_ids, list) or len(job.sample_ids) > 10
                    or any(not re.fullmatch(r'sr_[0-9a-f]{24}', item) for item in [*job.dispositions, *job.sample_ids])
                    or any(not isinstance(row, dict) or set(row) != {'disposition', 'reason'}
                           or row['disposition'] not in {'selected', 'handled', 'deferred', 'dropped'}
                           or not isinstance(row['reason'], str) or len(row['reason']) > 240 for row in job.dispositions.values())
                    or job.execution.get('status') not in {'running', 'completed', 'partial', 'failed', 'cancelled', 'interrupted'}):
                return None
            if job.remaining is not None and (not isinstance(job.remaining, dict)
                    or job.remaining.get('disposition') not in {'deferred', 'dropped'}
                    or not isinstance(job.remaining.get('reason'), str) or not 1 <= len(job.remaining['reason']) <= 240):
                return None
            if (job.manifest_sha256 is not None and not re.fullmatch(r'[0-9a-f]{64}', job.manifest_sha256)
                    or any(type(number) is not int or not 0 <= number <= 16 * 1024**2 for number in job.counts.values())
                    or not isinstance(job.port_set, str) or len(job.port_set) > 512):
                return None
            if not isinstance(job.options, dict) or not isinstance(job.binary, dict):
                return None
            job.options = {key: value for key, value in job.options.items() if key in {
                'timeout_seconds', 'rate', 'threads', 'request_timeout_seconds', 'calibration', 'match_status', 'filter_status', 'filter_size'}}
            job.binary = {key: value for key, value in job.binary.items() if key in {'sha256', 'version'}}
            # Hydration accepts only historical facts. Unknown receipt/PID/
            # authority fields cannot hitch a ride through an old session.
            job.execution = {key: job.execution[key] for key in ('status', 'exit_code', 'reason', 'duration_ms', 'started_at', 'finished_at') if key in job.execution}
            job.parse = {key: job.parse[key] for key in ('status', 'partial', 'coverage_complete') if key in job.parse}
            job.artifacts = {key: job.artifacts[key] for key in
                ('manifest', 'normalized', 'dataset_sha256', 'retrieval', 'result_refs', 'workflow_limited',
                 'retrieval_error', 'publication_error') if key in job.artifacts}
            refs = job.artifacts.get('result_refs', [])
            if not isinstance(refs, list) or len(refs) > 32 or any(not isinstance(ref, str) or not re.fullmatch(r'tr_[0-9a-f]{32}', ref) for ref in refs):
                return None
            if job.execution['status'] == 'running':
                job.execution.update(status='interrupted', reason='historical_restore')
                job.parse.update(partial=True, coverage_complete=False)
            return job
        except (TypeError, ValueError, AttributeError):
            return None

    @property
    def unresolved_selected(self) -> int:
        return sum(row['disposition'] == 'selected' for row in self.dispositions.values())

    def projection(self, *, detail: bool = False) -> dict[str, Any]:
        total = self.counts.get('unique_records', 0)
        reason_limit, id_limit, ref_limit = (240, 128, 32) if detail else (96, 64, 8)
        wordlist = None
        if isinstance(self.wordlist, dict):
            identifier = str(self.wordlist.get('id', ''))
            digest = self.wordlist.get('sha256')
            wordlist = {'id': clean(identifier, id_limit),
                        'sha256': digest if isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest) else None,
                        'id_truncated': len(identifier) > id_limit}
        remaining = None
        if self.remaining:
            remaining = {'disposition': self.remaining['disposition'],
                         'reason': clean(self.remaining['reason'], reason_limit),
                         'reason_truncated': len(self.remaining['reason']) > reason_limit}
        selected = [{'record_id': key, 'reason': clean(row['reason'], 96), 'reason_truncated': len(row['reason']) > 96}
                    for key, row in sorted(self.dispositions.items()) if row['disposition'] == 'selected']
        return {'job_id': self.job_id, 'scanner': self.scanner, 'semantic_key': self.semantic_key,
                'wordlist': wordlist, 'ports': clean(self.port_set, 128),
                'status': self.execution.get('status'), 'partial': self.parse.get('partial'),
                'coverage_complete': self.parse.get('coverage_complete'), 'records': total,
                'unresolved_selected': self.unresolved_selected,
                'selected': selected[:2], 'selected_omitted': max(0, len(selected) - 2),
                'read_more': {'action': 'list', 'job_id': self.job_id, 'scanner_offset': 0},
                'untriaged': max(0, total - len(self.dispositions)) if not self.remaining else 0,
                'remaining': remaining, 'refs': self.artifacts.get('result_refs', [])[:ref_limit],
                'refs_omitted': max(0, len(self.artifacts.get('result_refs', [])) - ref_limit),
                'retrieval': self.artifacts.get('retrieval', 'unavailable'),
                **{key: clean(str(self.artifacts[key]), 96) for key in ('retrieval_error', 'publication_error')
                   if key in self.artifacts}}

    def dataset(self, root) -> bytes:
        relative = self.artifacts.get('normalized')
        manifest = self.artifacts.get('manifest')
        if (not isinstance(relative, str) or not isinstance(manifest, str)
                or not relative.startswith('.kagent/scanners/') or not manifest.startswith('.kagent/scanners/')):
            raise ValueError('scanner dataset unavailable')
        missing: FileNotFoundError | None = None
        data = b''
        for path, digest, cap in ((relative, self.artifacts.get('dataset_sha256'), 8 * 1024**2),
                                  (manifest, self.manifest_sha256, 32 * 1024)):
            try:
                payload = read_private(root, path, cap)
            except FileNotFoundError as exc:
                missing = exc
                continue
            # Verify surviving artifacts even if their counterpart is missing.
            # Missing evidence must never conceal corruption or unsafe files.
            if hashlib.sha256(payload).hexdigest() != digest:
                raise ValueError('scanner artifact integrity failure')
            if path == relative:
                data = payload
        if missing is not None:
            raise missing
        return data

    def can_retire_selected(self, record_ids: Any, disposition: Any, *, remaining: Any = False) -> bool:
        """Historical retirement cannot introduce records or claim analysis."""
        return (remaining is False and disposition in ('deferred', 'dropped')
                and isinstance(record_ids, list) and 0 < len(record_ids) <= MAX_TRIAGE
                and all(isinstance(key, str)
                        and self.dispositions.get(key, {}).get('disposition') == 'selected'
                        for key in record_ids))

    def triage(self, root, record_ids: list[str], disposition: str, reason: str, *, remaining: bool = False) -> None:
        if (disposition not in {'selected', 'handled', 'deferred', 'dropped'}
                or not isinstance(reason, str) or not reason.strip() or len(reason) > 240
                or not isinstance(record_ids, list) or len(record_ids) > MAX_TRIAGE
                or any(not isinstance(item, str) for item in record_ids)):
            raise ValueError('scanner triage requires at most 128 record IDs, a disposition and a bounded reason')
        if remaining and (record_ids or disposition not in {'deferred', 'dropped'}):
            raise ValueError('remaining records may only be deferred/dropped with a reason')
        missing_artifact = False
        try:
            ids = {json.loads(row)['id'] for row in self.dataset(root).splitlines()}
        except FileNotFoundError:
            # Membership was verified when these IDs became selected. Missing
            # evidence may retire that work with an explicit limitation; it
            # cannot establish membership for new IDs or claim analysis.
            if not self.can_retire_selected(record_ids, disposition, remaining=remaining):
                raise
            ids = set(record_ids)
            missing_artifact = True
        if not set(record_ids) <= ids or (not record_ids and not remaining):
            raise ValueError('scanner record IDs must belong to the verified retained dataset')
        if len(set(self.dispositions) | set(record_ids)) > MAX_TRIAGE:
            raise ValueError('Scanner triage state limit reached. Use aggregate deferred/dropped for the remaining records.')
        safe_reason = clean(reason, 240)
        if missing_artifact:
            self.artifacts.update(retrieval='unavailable', retrieval_error='missing_artifact')
        if remaining:
            self.remaining = {'disposition': disposition, 'reason': safe_reason}
        else:
            for record_id in record_ids:
                self.dispositions[record_id] = {'disposition': disposition, 'reason': safe_reason}


def relevant_jobs(jobs: dict[str, ScannerJob], origin: str | None, objective_id: str | None) -> list[ScannerJob]:
    rows = [row for row in jobs.values() if row.target_origin == origin and row.objective_id == objective_id]
    # The latest invocation always survives the handoff. Then unresolved work,
    # newest first, followed by recent reusable results. Insertion order is the
    # session's historical order; no model timestamp controls this ranking.
    rows.reverse()
    return rows[:1] + sorted(rows[1:], key=lambda row: bool(row.unresolved_selected), reverse=True)


def project_jobs(jobs: dict[str, ScannerJob], origin: str | None, objective_id: str | None) -> str:
    rows = relevant_jobs(jobs, origin, objective_id)
    result = []
    for row in rows[:5]:
        item = row.projection()
        if len(json.dumps([*result, item], separators=(',', ':'))) > 3600:
            break
        result.append(item)
    if result:
        result[0]['jobs_omitted'] = len(rows) - len(result)
        if len(rows) > len(result):
            result[0]['read_more_jobs'] = {'action': 'list', 'scanner_offset': len(result)}
    return json.dumps(result, separators=(',', ':')) if result else ''
