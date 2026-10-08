"""Pure v1 evaluation bindings; no execution runtime or publication dependencies."""
from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path

from benchmarks.common.contracts import CaseExecution, RunManifest, decode, digest, file_hash, read_json

EVALUATOR = 'offline-agent-assessment-v1'


def evaluation_identity(manifest: RunManifest, rows: list[dict], partial: bool,
                        orphan_exports: list[dict]) -> str:
    # Preserve the original v1 encoding, including omission of an empty orphan list.
    identity_input = [EVALUATOR, asdict(manifest), [e for e in rows if e['kind'] != 'evaluated'], partial]
    if orphan_exports:
        identity_input.append(orphan_exports)
    return digest(identity_input)


def orphan_binding(directory: Path, cid: str, run_id: str, execution_id: str) -> dict:
    path = directory / 'results' / f'{cid}.json'
    try:
        raw = read_json(path)
    except (json.JSONDecodeError, UnicodeError):
        export_state = 'incomplete'
    else:
        orphan = decode(CaseExecution, raw)
        if (orphan.run_id, orphan.case_id, orphan.execution_id) != (run_id, cid, execution_id):
            raise ValueError('orphan execution export identity mismatch')
        export_state = 'diagnostic'
    return {'case_id': cid, 'execution_id': execution_id,
            'result_ref': str(path.relative_to(directory)), 'result_sha256': file_hash(path),
            'export_state': export_state}


def validate_recorded_evaluations(records: list[dict], histories: dict, identity: str) -> None:
    for record in records:
        previous = next((e for e in histories[record['case_id']] if e['kind'] == 'evaluated'), None)
        if previous:
            data = previous['data']
            if data.get('evaluation_identity') not in {identity, 'fail-fast-v1'}:
                raise ValueError('conflicting evaluation identity/version')
            if data.get('partition') != record['partition'] or data.get('reason') != record['reason']:
                raise ValueError('conflicting recorded evaluation')
            if data.get('evaluation_identity') != 'fail-fast-v1' and any(data.get(k) != v for k, v in record.items()):
                raise ValueError('conflicting evaluation record fields')
