"""Headless entrypoint. list/select/dry-run/evaluate cannot execute target traffic."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
import uuid

from benchmarks.common.contracts import DEFAULT_SEED, RunManifest, RuntimeSettings, decode, write_new, read_json
from .dataset import Dataset, select


def parser():
    p = argparse.ArgumentParser(description='KAgent Scenario 1 supplied-input SQLi/XSS benchmark')
    commands = p.add_subparsers(dest='command', required=True)
    listing = commands.add_parser('list')
    listing.add_argument('--dataset', required=True, type=Path)
    listing.add_argument('--map', action='store_true', help='also validate all operational mappings')
    selection = commands.add_parser('select')
    selection.add_argument('--dataset', required=True, type=Path)
    selection.add_argument('--mode', choices=['default', 'reduced'], default='default')
    selection.add_argument('--seed', type=int, default=DEFAULT_SEED)
    selection.add_argument('--case')
    selection.add_argument('--output', required=True, type=Path)
    running = commands.add_parser('run')
    running.add_argument('--dataset', required=True, type=Path, help='read-only verification of pinned source hashes')
    source = running.add_mutually_exclusive_group(required=True)
    source.add_argument('--manifest', type=Path)
    source.add_argument('--case')
    running.add_argument('--target', required=True)
    running.add_argument('--context-path', required=True, help='explicit deployment context, e.g. /benchmark')
    running.add_argument('--authorized-lab', action='store_true')
    running.add_argument('--target-state', required=True, choices=['confirmation-only', 'external-reset'])
    running.add_argument('--deployment-metadata')
    running.add_argument('--timeout', type=float, default=180)
    running.add_argument('--http-requests', type=int, default=24)
    running.add_argument('--tool-calls', type=int, default=80)
    running.add_argument('--agent-calls', type=int, default=24)
    running.add_argument('--dry-run', action='store_true')
    running.add_argument('--fail-fast', action='store_true')
    running.add_argument('--output', type=Path)
    evaluation = commands.add_parser('evaluate')
    evaluation.add_argument('--run', required=True, type=Path)
    return p


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == 'evaluate':
            from .evaluate import evaluate
            report = evaluate(args.run)
            print(json.dumps({'run_id': report['run_id'], 'incomplete': report['incomplete'],
                              **report['metrics']['overall']}, indent=2))
            counts = report['metrics']['overall']
            return 2 if counts['invalid-result'] else 3 if report['incomplete'] else 4 if counts['execution-failed'] else 0
        dataset = Dataset(args.dataset)
        if args.command == 'list':
            for truth in dataset.truth:
                row = asdict(truth)
                if args.map:
                    row['operational'] = asdict(dataset.map(truth))
                print(json.dumps(row))
            return 0
        if args.command == 'select':
            manifest = select(dataset, uuid.uuid4().hex, args.mode, args.seed, args.case)
            write_new(args.output, asdict(manifest))
            print(f'Selected {len(manifest.execution_order)} cases; manifest: {args.output}')
            return 0
        if args.manifest:
            manifest = decode(RunManifest, read_json(args.manifest))
            dataset.verify(manifest)
        else:
            manifest = select(dataset, uuid.uuid4().hex, case_id=args.case)
        settings = RuntimeSettings(args.target, args.context_path, args.authorized_lab, args.target_state,
                                   args.timeout, args.http_requests, args.tool_calls, args.agent_calls,
                                   args.deployment_metadata)
        from .runner import run, validate_runtime
        validate_runtime(manifest, settings)
        if args.dry_run:
            print(json.dumps({'dry_run': True, 'cases': manifest.execution_order, 'runtime': asdict(settings),
                              'mapping_version': manifest.mapping_version, 'dataset_version': dataset.version}, indent=2))
            return 0
        destination = args.output or Path('artifacts/benchmarks') / manifest.run_id
        run(manifest, settings, destination, fail_fast=args.fail_fast)
        from .evaluate import evaluate
        report = evaluate(destination)
        print(json.dumps({'artifacts': str(destination), **report['metrics']['overall']}, indent=2))
        return 2 if report['metrics']['overall']['invalid-result'] else 4 if report['metrics']['overall']['execution-failed'] else 0
    except (ValueError, OSError, KeyError) as err:
        # Configuration/mapping errors contain no credentials; runtime errors only exported as types.
        print(f'benchmark error: {err}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
