"""Parent-only reader projections; never copy a frozen workflow or worker metadata."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re

from benchmarks.common.contracts import RunManifest, decode, digest, file_hash, read_json
from benchmarks.common.recorder import read_records, validate_lifecycle
from benchmarks.scenario1.core.storage import PUBLIC_SCHEMA, read_storage
from src.redaction.redact import apply_evidence, redact_payload
from .loader import _counter, _diagnostic, _mapping, _safe_identity, presentation_id
from .model import ReportModel
from .findings import finding_file


def json_bytes(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def _text(value: str) -> str:
    # Text is presentation only. Drop local filesystem references as well as
    # credentials; no worker/provider configuration is ever consulted here.
    value = apply_evidence(value)
    return re.sub(r'(?<![\w])(?:[A-Za-z]:[\\/]|/(?:home|mnt|tmp|root|Users|var)/)[^\s"<>]*',
                  '[local-path]', value)


def _input(op: dict) -> dict:
    # Named pair values need a keyed mapping for the production secret redactor.
    def pairs(rows):
        return [[_text(name), _text(str(redact_payload({name: value})[name]))] for name, value in rows]
    return {
        'method': op['method'], 'servlet_path': _text(op['servlet_path']),
        'input_location': op['input_location'], 'input_component': op['input_component'],
        'input_name': _text(op['input_name']), 'content_type': _text(op['content_type']) if op['content_type'] else None,
        'query': pairs(op['query']), 'body': pairs(op['body']),
        'headers': {_text(k): _text(str(v)) for k, v in redact_payload(op['headers']).items()},
        'cookies': {_text(k): '[REDACTED]' for k in op['cookies']},
    }


def _evidence(export: dict, cid: str, files: dict[str, bytes], version: int) -> tuple[dict | None, list[dict]]:
    result = next((r for r in export['workflow'].get('validation_results', [])
                   if isinstance(r, dict) and r.get('result_id') == export['result_id']), None)
    if result is None:
        return None, []
    # Free-form rationale/decisions are internal. Export only observed assessment
    # identity and the production acceptance projection, without claiming a seal.
    assessment = {'source': 'agent' if result.get('assessment_source') == 'agent' else None,
                  'accepted_at_freeze': export['accepted_at_freeze'],
                  'result_id': presentation_id('result', export['result_id']),
                  'canonical_assessment_binding': _safe_identity(result.get('assessment_binding'))}
    selected = []
    entries = result.get('evidence_manifest', [])
    if len(entries) > 32:
        raise ValueError('selected evidence exceeds the canonical 32-source bound')
    for i, entry in enumerate(entries):
        source = entry.get('source') if isinstance(entry, dict) else None
        if not isinstance(source, dict) or source.get('source_kind') not in {'native-http', 'imported-capture'}:
            continue
        bound = {k: v for k, v in source.items() if k not in {'role', 'required'}}
        if digest(bound) != entry.get('hash'):
            raise ValueError('selected evidence source binding mismatch')
        body = bytes.fromhex(source.get('body', ''))
        # Selected primary response text is a bounded, sanitized derivative, not
        # the canonical body. Both raw and public hashes make that explicit.
        excerpt = _text(body[:8192].decode('utf-8', errors='replace')).encode()
        ref = f'results/evidence/{cid}-{i}.txt'
        if version == 1:
            files[ref] = excerpt
        selected.append({
            'public_ref': ref.removeprefix('results/'), 'public_sha256': hashlib.sha256(excerpt).hexdigest(),
            'canonical_ref': f'results/{cid}.json',
            'canonical_pointer': f'/result/workflow/validation_results/{export["workflow"]["validation_results"].index(result)}/evidence_manifest/{i}',
            'source_id': presentation_id('source', str(source.get('id'))),
            'canonical_source_sha256': entry['hash'], 'canonical_body_sha256': hashlib.sha256(body).hexdigest(),
            'source_kind': source['source_kind'], 'byte_range': [0, min(len(body), 8192)],
            'sanitized': True, 'truncated': len(body) > 8192,
        })
        if version >= 2:
            item = selected[-1]
            del item['public_ref']
            content = excerpt[:8192].decode('utf-8', errors='ignore')
            item.update(content=content, content_encoding='utf-8',
                        public_sha256=hashlib.sha256(content.encode()).hexdigest(),
                        truncated=len(body) > 8192 or len(excerpt) > 8192,
                        observation_ref=presentation_id('observation', str(source.get('id'))),
                        role=entry.get('role') if entry.get('role') in {
                            'baseline', 'probe', 'control', 'imported', 'primary', 'trigger',
                            'readback', 'cleanup', 'auxiliary'} else None,
                        http_status=_counter(source.get('status')),
                        response_complete=source.get('complete') if type(source.get('complete')) is bool else None,
                        upstream_truncated=source.get('truncated') if type(source.get('truncated')) is bool else None,
                        request_sha256=_safe_identity(source.get('request_hash')),
                        response_sha256=_safe_identity(source.get('response_hash')),
                        method=source.get('method') if source.get('method') in {'GET', 'POST', 'HEAD'} else None)
    return assessment, selected


def _usage(execution) -> dict:
    """Expose bounded numeric telemetry only, including provider-reported cache use."""
    llm = _mapping(execution.metrics.get('llm')) if execution and execution.metrics else {}
    output = {}
    for name in ('input_tokens', 'output_tokens', 'total_tokens'):
        token = _mapping(_mapping(llm.get('tokens')).get(name))
        output[name] = {key: _counter(token.get(key)) for key in ('observed_sum', 'known_requests', 'requests')}
        output[name]['complete'] = token.get('complete') if type(token.get('complete')) is bool else None
    requests = llm.get('requests')
    has_ledger = isinstance(requests, list)
    requests = requests if isinstance(requests, list) else []
    for name in ('cached_input_tokens', 'cache_creation_input_tokens'):
        values = [_counter(row.get('usage', {}).get(name))
                  if isinstance(row, dict) and isinstance(row.get('usage'), dict) else None for row in requests]
        known = [v for v in values if v is not None]
        complete = bool(requests) and llm.get('request_records_complete') is True and len(known) == len(requests)
        output[name] = {'total': sum(known) if complete else None,
                        'observed_sum': sum(known) if known else None,
                        'known_requests': len(known) if has_ledger else None,
                        'requests': len(requests) if has_ledger else None,
                        'complete': complete if has_ledger else None}
    return output


def result_files(root: Path, model: ReportModel, *, version: int = 3,
                 compact_findings: bool = True) -> dict[str, bytes]:
    manifest = decode(RunManifest, read_json(root / 'manifest.json'))
    rows, _ = read_records(root / 'events.jsonl')
    histories = validate_lifecycle(rows)
    files: dict[str, bytes] = {}
    operations = {op['case_id']: op for op in manifest.operational}
    truths = {truth['case_id']: truth for truth in manifest.truth}
    for cid, summary in zip(manifest.execution_order, model.cases):
        finish = next((row for row in histories[cid] if row['kind'] == 'runtime-finished'), None)
        execution = None
        canonical = None
        if finish and finish['data'].get('result_ref'):
            canonical = {'result_ref': f'results/{cid}.json',
                         'result_sha256': finish['data'].get('result_sha256'),
                         'observed_result_sha256': file_hash(root / 'results' / f'{cid}.json')
                             if (root / 'results' / f'{cid}.json').is_file() else None,
                         'execution_id': presentation_id('execution', finish['execution_id'])}
            execution = _diagnostic(root / 'results' / f'{cid}.json', manifest.run_id, cid,
                                    finish['execution_id'], canonical['result_sha256'])
        assessment, evidence = (None, [])
        if execution and execution.result and summary['evaluator_partition'] in {'evaluable', 'unresolved'}:
            assessment, evidence = _evidence(execution.result, cid, files, version)
        projection = {
            'schema': f'scenario1-public-case-v{version}', 'case_id': cid,
            'run_id': presentation_id('run', manifest.run_id),
            'manifest_identity': model.metadata['manifest_identity'],
            'evaluation_identity': model.metadata['evaluation_identity'],
            'input': _input(operations[cid]),
            'ground_truth': {'vulnerability_class': truths[cid]['vulnerability_class'],
                             'expected_vulnerable': truths[cid]['expected_vulnerable'], 'cwe': truths[cid]['cwe']},
            **{k: v for k, v in summary.items() if k != 'case_id'},
            'assessment': assessment, 'canonical': canonical, 'selected_evidence': evidence,
        }
        if version >= 2:
            workflow = execution.result.get('workflow', {}) if execution and execution.result else {}
            persisted = workflow.get('persisted_findings')
            cid_internal = execution.result.get('candidate_id') if execution and execution.result else None
            projection.update(usage=_usage(execution),
                persisted_finding=bool(persisted.get(cid_internal)) if isinstance(persisted, dict) else None,
                conclusion={'outcome': summary['agent_outcome'],
                            'agent_limitations': None,
                            'evaluator_reason': summary['evaluator_reason'],
                            'free_form_conclusion': None,
                            'note': 'Free-form agent prose and tool transcripts are not in the public projection.'},
                tool_diagnostics={'blocked': summary['tool_blocked'], 'failed': summary['tool_failed'],
                                  'individual_operations': None})
        if version >= 3:
            projection['finding'] = finding_file(root, execution, cid, summary['evaluator_partition'], files,
                                                 sanitize=_text, public_id=presentation_id,
                                                 compact=compact_findings)
            projection['persisted_finding'] = (
                None if projection['finding']['status'] == 'unknown'
                else projection['finding']['status'] == 'persisted')
        projection['projection_binding'] = digest(projection)
        files[f'results/{cid}.json'] = json_bytes(projection)
    return files


def index_file(root: Path, public: Path, model: ReportModel, files: dict[str, bytes]) -> bytes:
    descriptor = read_storage(root)
    index = {key: descriptor[key] for key in ('storage_id', 'manifest_sha256', 'manifest_identity')}
    index['run_id'] = presentation_id('run', descriptor['run_id'])
    index.update(schema=PUBLIC_SCHEMA, evaluation_identity=model.metadata['evaluation_identity'],
                 internal_ref=os.path.relpath(root, public),
                 files={ref: hashlib.sha256(raw).hexdigest() for ref, raw in sorted(files.items())})
    index['binding'] = digest(index)
    return json_bytes(index)
