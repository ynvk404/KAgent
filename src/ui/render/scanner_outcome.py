"""Small presentation of controller-admitted scanner facts; no raw stdout."""
from __future__ import annotations

from src.ui.render.sanitize import sanitize_text


def scanner_text(summary: dict) -> str:
    execution, parse, counts = summary['execution'], summary['parse'], summary['summary']
    target = summary['target']
    scope = target.get('template') or target.get('origin', '')
    options = ('wordlist ' + summary['wordlist']['id'] if summary.get('wordlist') else
               'ports ' + target.get('port_set', ''))
    lines = [f"{summary['scanner']} · {execution['status']} · {scope}",
             f"  {options} · {execution['duration_ms']} ms · {counts['unique_records']} observations",
             f"  Parse: {parse['status']} · coverage: " +
             ('complete' if parse['coverage_complete'] is True else 'incomplete' if parse['coverage_complete'] is False else 'unknown')]
    for row in summary.get('records', [])[:3]:
        if 'url' in row:
            lines.append(f"  {row['status']} {row['url']} · {row['length']} bytes · scanner reported")
        else:
            lines.append(f"  {row['address']}:{row['port']}/tcp {row['state']} · service hint {row.get('service_hint') or 'unknown'}")
    if summary.get('error'):
        lines.append('  Reason: ' + str(summary['error']['message']))
    manifest = summary.get('artifacts', {}).get('manifest')
    if manifest:
        lines.append('  Manifest: ' + manifest)
    return sanitize_text('\n'.join(lines))
