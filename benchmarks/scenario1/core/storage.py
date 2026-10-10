"""Scenario 1 paths and fail-closed resolution of legacy, internal and public runs."""
from __future__ import annotations

from dataclasses import asdict
import os
from pathlib import Path
import re
import uuid

from benchmarks.common.contracts import RunManifest, decode, digest, file_hash, read_json, write_new
from src.paths import project_data_root

STORAGE_SCHEMA = 'scenario1-storage-v1'
PUBLIC_SCHEMA = 'scenario1-public-results-v5'


def storage_root() -> Path:
    return project_data_root() / 'benchmarks' / 'scenario1'


def allocate_run(public: Path) -> Path:
    if public.exists() or public.is_symlink():
        raise ValueError('run directory already exists; history cannot be overwritten or resumed')
    base = storage_root()
    project = base.parents[2]
    if public == project or public.is_relative_to(project / '.kagent'):
        raise ValueError('public output occupies internal storage namespace')
    for directory in (base.parents[1], base.parent, base, base / 'runs'):
        if directory.is_symlink():
            raise ValueError('internal storage namespace cannot be a symlink')
    root = base / 'runs' / uuid.uuid4().hex
    root.mkdir(parents=True, mode=0o700)
    for name in ('results', 'evaluations', 'reset-evidence', 'workspaces', 'publications'):
        (root / name).mkdir(mode=0o700)
    return root


def bind_storage(root: Path, public: Path) -> None:
    manifest = decode(RunManifest, read_json(root / 'manifest.json'))
    write_new(root / 'storage.json', {
        'schema': STORAGE_SCHEMA, 'storage_id': root.name, 'run_id': manifest.run_id,
        'manifest_sha256': file_hash(root / 'manifest.json'), 'manifest_identity': digest(asdict(manifest)),
        'public_ref': os.path.relpath(public, root),
    })


def read_storage(root: Path) -> dict:
    raw = read_json(root / 'storage.json')
    if (not isinstance(raw, dict) or set(raw) != {
            'schema', 'storage_id', 'run_id', 'manifest_sha256', 'manifest_identity', 'public_ref'}
            or raw['schema'] != STORAGE_SCHEMA or raw['storage_id'] != root.name
            or not re.fullmatch('[0-9a-f]{32}', root.name)
            or root.parent.parts[-4:] != ('.kagent', 'benchmarks', 'scenario1', 'runs')
            or not isinstance(raw['public_ref'], str) or Path(raw['public_ref']).is_absolute()):
        raise ValueError('invalid internal storage descriptor')
    manifest = decode(RunManifest, read_json(root / 'manifest.json'))
    if (raw['run_id'], raw['manifest_sha256'], raw['manifest_identity']) != (
            manifest.run_id, file_hash(root / 'manifest.json'), digest(asdict(manifest))):
        raise ValueError('internal storage manifest binding mismatch')
    for directory in (root, *list(root.parents)[:4]):
        if directory.is_symlink():
            raise ValueError('untrusted internal storage namespace')
    for name in ('results', 'evaluations', 'reset-evidence', 'workspaces', 'publications'):
        if (root / name).is_symlink() or not (root / name).is_dir():
            raise ValueError('missing/untrusted internal storage namespace')
    from .classification import read_run_designation
    if not read_run_designation(root).declared:
        raise ValueError('new execution has no run classification')
    return raw


def public_destination(root: Path) -> Path:
    return Path(os.path.abspath(root / read_storage(root)['public_ref']))


def evaluation_root(root: Path) -> Path:
    return root / 'evaluations' if (root / 'storage.json').exists() else root


def resolve_run(path: Path) -> Path:
    # Keep the lexical public path: WSL may publish its entire completed tree
    # with an exclusive symlink. index.internal_ref is relative to that path.
    public = Path(os.path.abspath(path))
    root = public.resolve()
    internal_shape = root.parent.parts[-4:] == ('.kagent', 'benchmarks', 'scenario1', 'runs')
    if (root / 'storage.json').exists() or (root / 'storage.json').is_symlink() or internal_shape:
        read_storage(root)
        return root
    index_path = root / 'results' / 'index.json'
    if (index_path.exists() or index_path.is_symlink() or not (root / 'manifest.json').exists()
            or ((root / 'report').exists() and not (root / 'events.jsonl').exists())):
        index = read_json(index_path)
        if (not isinstance(index, dict) or set(index) != {
                'schema', 'storage_id', 'run_id', 'manifest_sha256', 'manifest_identity',
                'evaluation_identity', 'internal_ref', 'files', 'binding'}
                or index['schema'] not in {'scenario1-public-results-v1', 'scenario1-public-results-v2',
                                          'scenario1-public-results-v3', 'scenario1-public-results-v4', PUBLIC_SCHEMA}
                or index['binding'] != digest({k: v for k, v in index.items() if k != 'binding'})
                or not isinstance(index['internal_ref'], str) or Path(index['internal_ref']).is_absolute()):
            raise ValueError('invalid public results descriptor')
        # Normalize '..' lexically BEFORE following a published root symlink.
        canonical = Path(os.path.abspath(public / index['internal_ref'])).resolve()
        descriptor = read_storage(canonical)
        if any(index[key] != descriptor[key] for key in (
                'storage_id', 'manifest_sha256', 'manifest_identity')):
            raise ValueError('public/canonical storage binding mismatch')
        from ..reporting.loader import load_report, presentation_id
        if index['run_id'] != presentation_id('run', descriptor['run_id']):
            raise ValueError('public/canonical run identity mismatch')
        version = int(index['schema'].rsplit('v', 1)[1])
        files = index['files']
        if not isinstance(files, dict) or not files:
            raise ValueError('missing public integrity bindings')
        namespaces = {'report', 'results'}
        if version == 2:
            namespaces.add('index.html')
        if version >= 4 and any(ref.startswith('findings/') for ref in index['files']):
            namespaces.add('findings')
        if {p.name for p in root.iterdir()} != namespaces:
            raise ValueError('unexpected public run entry')
        entries = list(root.rglob('*'))
        if any(p.is_symlink() for p in entries):
            raise ValueError('untrusted public artifact namespace')
        actual = {p.relative_to(root).as_posix() for p in entries if p.is_file()}
        if actual != {*files, 'results/index.json'}:
            raise ValueError('unexpected/missing public artifact')
        for ref, hashed in files.items():
            relative = Path(ref)
            target = root / relative
            if (relative.is_absolute() or '..' in relative.parts or not relative.parts
                    or (relative.parts[0] not in ({'report', 'results', 'findings'} if version >= 4 else {'report', 'results'})
                        and not (version == 2 and ref == 'index.html'))
                    or target.is_symlink()
                    or not target.resolve().is_relative_to(root) or file_hash(target) != hashed):
                raise ValueError('public artifact integrity mismatch')
        identity = index['evaluation_identity']
        if not isinstance(identity, str) or not re.fullmatch('[0-9a-f]{64}', identity):
            raise ValueError('invalid public evaluation identity')
        evaluation = read_json(canonical / 'evaluations' / f'evaluation-{identity}.json')
        if evaluation.get('evaluation_identity') != identity or evaluation.get('run_id') != descriptor['run_id']:
            raise ValueError('public evaluation binding mismatch')
        # Validate the existing evaluator/lifecycle bindings without rescoring,
        # then require public cases and selected evidence to be their exact
        # parent-side projection. Rewriting an index hash cannot bless a
        # different canonical execution, truth label or evidence derivative.
        from ..reporting.projection import result_files
        model = load_report(canonical, canonical / 'evaluations' / f'evaluation-{identity}.json')
        expected = result_files(canonical, model, version=1 if version == 1 else 3 if version >= 4 else 2,
                                compact_findings=version >= 5)
        if version >= 3:
            from ..reporting.charts import render_charts
            from ..reporting.tables import render_tables
            required = {f'report/{ref}' for ref in (*render_tables(model), *render_charts(model), 'report.json')}
            if set(files) != required | set(expected):
                raise ValueError('unexpected/missing public report component')
        for ref, contents in expected.items():
            if (root / ref).read_bytes() != contents:
                raise ValueError('public/canonical projection binding mismatch')
        return canonical
    # A genuine legacy run has its own manifest and no new-layout descriptor.
    decode(RunManifest, read_json(root / 'manifest.json'))
    return root
