"""Single parent writer, fsync per record. Recovery never edits history."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import uuid

from .contracts import PROTOCOL, SCENARIO, SCHEMA, STATUSES, PARTITIONS, identifier, parse_json

KINDS = ("scheduled", "started", "runtime-finished", "evaluated")
KEYS = {"schema_version", "scenario", "protocol_version", "run_id", "case_id", "execution_id",
        "record_id", "sequence", "utc", "kind", "status", "data"}


def read_records(path: Path) -> tuple[list[dict], bool]:
    """Ignore only a final non-newline-terminated fragment, even if valid JSON."""
    if not path.exists():
        return [], False
    lines = path.read_bytes().splitlines(keepends=True)
    partial = bool(lines and not lines[-1].endswith(b'\n'))
    if partial:
        lines = lines[:-1]
    rows = []
    for i, line in enumerate(lines):
        try:
            row = parse_json(line)
        except (ValueError, UnicodeError) as err:
            raise ValueError(f"JSONL corruption at complete record {i + 1}") from err
        if (not isinstance(row, dict) or set(row) != KEYS or type(row['schema_version']) is not int
                or row['schema_version'] != SCHEMA or row['scenario'] != SCENARIO
                or row['protocol_version'] != PROTOCOL or type(row['sequence']) is not int or row['sequence'] != i + 1
                or row['kind'] not in KINDS or row['status'] not in STATUSES or not isinstance(row['data'], dict)):
            raise ValueError(f"invalid lifecycle schema/sequence at record {i + 1}")
        for key in ('run_id', 'case_id', 'record_id'):
            identifier(row[key])
        if row['execution_id'] is not None:
            identifier(row['execution_id'])
        try:
            offset = datetime.fromisoformat(row['utc']).utcoffset()
            if offset is None or offset.total_seconds() != 0:
                raise ValueError("timestamp must be UTC")
        except (ValueError, AttributeError, TypeError) as err:
            raise ValueError("invalid lifecycle timestamp") from err
        rows.append(row)
    validate_lifecycle(rows)
    return rows, partial


def validate_lifecycle(rows: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    records = set()
    executions = set()
    run = None
    runtime_started = False
    for row in rows:
        if row['record_id'] in records or (run is not None and row['run_id'] != run):
            raise ValueError("duplicate record or mixed run identity")
        records.add(row['record_id'])
        run = row['run_id']
        case = grouped.setdefault(row['case_id'], [])
        kind = row['kind']
        previous = case[-1]['kind'] if case else None
        if kind == 'scheduled':
            if previous or runtime_started or row['status'] != 'scheduled' or row['execution_id'] is not None:
                raise ValueError("schedule must be unique and precede every worker")
        elif kind == 'started':
            runtime_started = True
            if previous != 'scheduled' or row['status'] != 'started' or not row['execution_id'] or row['execution_id'] in executions:
                raise ValueError("invalid/duplicate execution start")
            executions.add(row['execution_id'])
        elif kind == 'runtime-finished':
            if previous != 'started' or row['execution_id'] != case[-1]['execution_id'] or row['status'] in {'scheduled', 'started', 'not-run'}:
                raise ValueError("invalid/duplicate runtime completion")
        elif kind == 'evaluated':
            if previous not in {'scheduled', 'started', 'runtime-finished'}:
                raise ValueError("duplicate/invalid evaluation transition")
            if row['execution_id'] != case[-1]['execution_id']:
                raise ValueError("evaluation execution mismatch")
            if row['data'].get('partition') not in PARTITIONS or not row['data'].get('reason') or not row['data'].get('evaluation_identity'):
                raise ValueError('invalid evaluation record')
        case.append(row)
    return grouped


class Recorder:
    def __init__(self, path: Path, run_id: str):
        self.path, self.run_id = path, identifier(run_id)
        self.rows, partial = read_records(path)
        if partial:
            raise ValueError("partial JSONL tail: evaluate read-only; appending/resume prohibited")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def append(self, kind: str, case_id: str, status: str, *, execution_id: str | None = None, data: dict | None = None):
        if kind not in KINDS or status not in STATUSES or (data is not None and not isinstance(data, dict)):
            raise ValueError('invalid lifecycle kind/status/data')
        if execution_id is not None:
            identifier(execution_id)
        row = dict(schema_version=SCHEMA, scenario=SCENARIO, protocol_version=PROTOCOL,
                   run_id=self.run_id, case_id=identifier(case_id), execution_id=execution_id,
                   record_id=uuid.uuid4().hex, sequence=len(self.rows) + 1,
                   utc=datetime.now(timezone.utc).isoformat(), kind=kind, status=status, data=data or {})
        validate_lifecycle([*self.rows, row])
        encoded = json.dumps(row, allow_nan=False).encode() + b'\n'
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, 'ab') as stream:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            current, partial = read_records(self.path)
            if partial or current != self.rows:
                raise ValueError('recorder ownership/history changed; concurrent writing prohibited')
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        self.rows.append(row)
