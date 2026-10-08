"""Persist existing audit evidence, without rerunning the source audit."""
from pathlib import Path
import argparse
import hashlib
import json

from .install import COMMIT


def recover(source: Path, destination: Path):
    matrix = json.loads(source.read_text())
    if matrix.get('dataset_commit') != COMMIT or len(matrix['rows']) != 504:
        raise ValueError('historical coverage identity mismatch')
    rows = matrix['rows']
    if len({row['case_id'] for row in rows}) != 504:
        raise ValueError('historical coverage contains duplicate case IDs')
    result = {'source_commit': COMMIT, 'provenance': 'Historical source analysis; not deployment certification',
              'primary_reset_handoff': 'Unavailable in supplied recovery directories',
              'historical_matrix_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
              'source_bounded': {row['case_id']: row['servlet_sha256'] for row in rows
                                 if row['input_reaches_sql_text'] is False},
              'blocked_external_effects': [row['case_id'] for row in rows if row['input_reaches_sql_text']],
              'representatives': {row['mechanism']: row['case_id'] for row in reversed(rows)}}
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise ValueError('evidence already exists; overwrite refused')
    destination.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'source_bounded': len(result['source_bounded']),
                      'blocked_external_effects': len(result['blocked_external_effects'])}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    recover(args.source, args.output)
