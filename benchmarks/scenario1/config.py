"""Small operator-lab TOML resolver. A saved lab declaration is not approval."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import tomllib
import uuid

from benchmarks.common.contracts import RunManifest, file_hash
from src.paths import project_artifact_root
from .core.dataset import SELECTION_MODES

DEFAULT_CONFIG = Path(__file__).with_name('config.local.toml')
SECTIONS = {
    'lab': {'dataset', 'target', 'context_path', 'target_state', 'container',
            'ingress_container', 'reset_war', 'authorized_lab'},
    'manifests': {'smoke', 'official'},
    'output': {'root'},
    'limits': {'timeout', 'http_requests', 'tool_calls', 'agent_calls'},
}
PATH_KEYS = {'dataset', 'reset_war'}


def _path(value: str, base: Path) -> Path:
    path = Path(value).expanduser()
    # Normalize '..' without concealing final symlinks from existing file guards.
    return Path(os.path.abspath(base / path))


def resolve_config(args: argparse.Namespace, invocation: list[str]) -> dict:
    """Resolve a two-mode run; complete explicit invocations need no TOML."""
    if args.mode not in SELECTION_MODES:
        raise ValueError('run mode must be smoke or official')
    config_path = args.config
    if config_path is None and any(getattr(args, key) is None
                                   for key in ('dataset', 'target', 'context_path', 'target_state', 'manifest')):
        config_path = DEFAULT_CONFIG
    args.run_kind = 'official' if args.mode == 'official' else 'development'
    values: dict = {}
    metadata: dict = {'profile': args.mode, 'configuration_sha256': None}
    supplied = {word.split('=', 1)[0] for word in invocation if word.startswith('--')}
    # argparse accepts unambiguous long-option abbreviations; they are overrides too.
    options = {'--' + key.replace('_', '-') for key in vars(args)}
    for option in tuple(supplied):
        matches = [known for known in options if known.startswith(option)]
        if len(matches) == 1:
            supplied.add(matches[0])
    if config_path is not None:
        if config_path.is_symlink() or not config_path.is_file():
            raise ValueError('Scenario 1 config missing/untrusted; copy config.example.toml to config.local.toml or use --config')
        if config_path.stat().st_size > 65536:
            raise ValueError('Scenario 1 config exceeds 64 KiB')
        try:
            raw_config = config_path.read_bytes()
            values = tomllib.loads(raw_config.decode('utf-8'))
        except (tomllib.TOMLDecodeError, UnicodeError):
            raise ValueError('invalid Scenario 1 TOML; check syntax in the selected config') from None
        if set(values) - set(SECTIONS):
            raise ValueError('unknown Scenario 1 TOML section; use lab, manifests, output, limits')
        for section, row in values.items():
            if not isinstance(row, dict) or set(row) - SECTIONS[section]:
                raise ValueError(f'invalid keys in Scenario 1 [{section}]')
            for key, value in row.items():
                expected = bool if key == 'authorized_lab' else (int, float) if key == 'timeout' else int if section == 'limits' else str
                if type(value) not in (expected if isinstance(expected, tuple) else (expected,)):
                    raise ValueError(f'invalid type for [{section}].{key}')
                if isinstance(value, str) and not value.strip() and key != 'context_path':
                    raise ValueError(f'empty value for [{section}].{key}')
        lab = values.get('lab', {})
        if lab.get('authorized_lab') is not True:
            raise ValueError('config must explicitly describe an authorized lab: [lab] authorized_lab = true; execution still requires --authorized-lab')
        base = config_path.resolve().parent
        for key, value in {**lab, **values.get('limits', {})}.items():
            if key == 'authorized_lab':
                continue
            if '--reset-state' in supplied and key in {'container', 'ingress_container', 'reset_war'}:
                continue
            if '--' + key.replace('_', '-') not in supplied:
                setattr(args, key, _path(value, base) if key in PATH_KEYS else value)
        if not args.manifest:
            selected = values.get('manifests', {}).get(args.mode)
            if selected is None:
                raise ValueError(f'[manifests].{args.mode} must name an explicitly frozen manifest')
            args.manifest = _path(selected, base)
        metadata['configuration_sha256'] = hashlib.sha256(raw_config).hexdigest()
    for key in ('dataset', 'target', 'context_path', 'target_state'):
        if getattr(args, key) is None:
            raise ValueError(f'missing --{key.replace("_", "-")}; supply it or configure [lab]')
    if not args.manifest:
        raise ValueError('run requires a frozen --manifest matching --mode smoke or official')
    if not args.dataset.is_dir():
        raise ValueError('--dataset must name an existing BenchmarkJava directory')
    for key in ('manifest', 'reset_war', 'reset_state', 'reset_audit'):
        path = getattr(args, key)
        if path is not None and (path.is_symlink() or not path.is_file()):
            raise ValueError(f'--{key.replace("_", "-")} must name an existing regular file')
    if args.container and args.reset_state:
        raise ValueError('--container and --reset-state are mutually exclusive')
    if args.output is None:
        base = config_path.resolve().parent if config_path else Path.cwd()
        root = (_path(values['output']['root'], base) if values.get('output', {}).get('root')
                else project_artifact_root() / 'benchmarks')
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        args.output = root / f'scenario1-{args.mode}-{stamp}-{uuid.uuid4().hex[:12]}'
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('run directory already exists; refusing to overwrite')
    metadata['effective_configuration'] = {
        key: str(value) if isinstance(value, Path) else value
        for key in ('dataset', 'target', 'context_path', 'target_state', 'container',
                    'ingress_container', 'reset_war', 'reset_state', 'reset_audit', 'resume_from',
                    'manifest', 'output', 'run_kind', 'fail_fast',
                    'timeout', 'http_requests', 'tool_calls', 'agent_calls')
        for value in [getattr(args, key)]}
    metadata['selection_file_sha256'] = file_hash(args.manifest) if args.manifest else None
    metadata['reset_war_sha256'] = file_hash(args.reset_war) if args.reset_war else None
    return metadata


def validate_profile(manifest: RunManifest, mode: str) -> None:
    if mode not in SELECTION_MODES:
        raise ValueError('run mode must be smoke or official')
    count = 12 if mode == 'smoke' else 40
    if manifest.mode != SELECTION_MODES[mode] or len(manifest.execution_order) != count:
        raise ValueError(f'{mode} mode requires the frozen {count}-case {mode} manifest')
