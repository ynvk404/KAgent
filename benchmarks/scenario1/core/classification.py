"""Operator run designation, independent of the selection manifest and evaluator."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
import re
from typing import Literal

from benchmarks.common.contracts import RunManifest, decode, digest, identifier, parse_json, read_json, write_new

RECORD_NAME = 'run-classification.json'
SCHEMA_VERSION = 1
RunKind = Literal['development', 'official']


@dataclass(frozen=True)
class RunClassification:
    run_id: str
    classification: RunKind
    manifest_sha256: str
    manifest_identity: str
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        identifier(self.run_id)
        if not isinstance(self.classification, str) or self.classification not in {'development', 'official'}:
            raise ValueError('invalid run classification')
        for value in (self.manifest_sha256, self.manifest_identity):
            if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
                raise ValueError('invalid manifest binding hash')
        if type(self.schema_version) is not int or self.schema_version != SCHEMA_VERSION:
            raise ValueError('unsupported run classification schema')


@dataclass(frozen=True)
class RunDesignation:
    classification: Literal['development', 'official', 'unknown']
    qualifier: Literal['smoke'] | None
    declared: bool


def _final_manifest(directory: Path) -> tuple[RunManifest, str, str]:
    path = directory / 'manifest.json'
    if path.is_symlink() or path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError('untrusted/oversized manifest artifact')
    final_bytes = path.read_bytes()
    manifest = decode(RunManifest, parse_json(final_bytes))
    return manifest, hashlib.sha256(final_bytes).hexdigest(), digest(asdict(manifest))


def write_run_classification(directory: Path, kind: RunKind) -> RunClassification:
    manifest, raw_hash, identity = _final_manifest(directory)
    if manifest.mode == 'smoke' and kind == 'official':
        raise ValueError('smoke run cannot be official')
    record = RunClassification(manifest.run_id, kind, raw_hash, identity)
    write_new(directory / RECORD_NAME, asdict(record))
    return record


def read_run_designation(directory: Path) -> RunDesignation:
    """Read declared designation, or interpret legacy runs without claiming official status."""
    manifest, raw_hash, identity = _final_manifest(directory)
    path = directory / RECORD_NAME
    if path.is_symlink():
        raise ValueError('untrusted run classification artifact')
    if not path.exists():
        return (RunDesignation('development', 'smoke', False) if manifest.mode == 'smoke'
                else RunDesignation('unknown', None, False))
    raw = read_json(path)
    if not isinstance(raw, dict) or set(raw) != set(RunClassification.__dataclass_fields__):
        raise ValueError('malformed run classification fields')
    record = RunClassification(**raw)
    if (record.run_id, record.manifest_sha256, record.manifest_identity) != (manifest.run_id, raw_hash, identity):
        raise ValueError('run classification manifest binding mismatch')
    if manifest.mode == 'smoke' and record.classification == 'official':
        raise ValueError('smoke run cannot be official')
    return RunDesignation(record.classification, None, True)
