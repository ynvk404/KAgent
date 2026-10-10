"""Read-only export of persisted findings bound to the latest case assessment."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from benchmarks.common.contracts import identifier
from benchmarks.scenario1.core.canonical import projection
from src.findings.store import read_report_bytes, render, report_bytes
from src.redaction.redact import apply_evidence
from src.target.origin import HTTPOrigin
from src.workflow.assessment import accepted_result
from src.workflow.review import confirmation_binding
from src.workflow.state import validation_result_fingerprint


def finding_file(root: Path, execution, case_id: str, partition: str, files: dict[str, bytes], *,
                 sanitize: Callable[[str], str], public_id: Callable[[str, str], str]) -> dict:
    """A confirmation alone never creates a finding or authorizes report export."""
    def status(value, reason=None):
        return {'status': value, 'report_ref': None, 'reason': reason}

    if execution is None or execution.result is None:
        return status('unknown', 'missing-result')
    export = execution.result
    workflow = export.get('workflow', {})
    cid = export.get('candidate_id')
    rows = [row for row in workflow.get('validation_results', []) if row.get('candidate_id') == cid]
    if not rows:
        return status('unknown', 'missing-assessment')
    if rows[-1].get('outcome') != 'confirmed':
        return status('not-applicable')
    if partition != 'evaluable':
        return status('unknown', 'assessment-not-evaluable')
    state = projection(workflow)
    latest = state.latest_result(cid)
    candidate = state.candidates[cid]
    if (latest is None or latest.result_id is None or export.get('result_id') != latest.result_id
            or export.get('accepted_at_freeze') is not True
            or not accepted_result(state, candidate, latest)):
        return status('unknown', 'assessment-not-accepted')
    if workflow.get('persisted_findings', {}).get(cid) != validation_result_fingerprint(latest):
        return status('pending', 'not-persisted-for-current-result')

    # Only this execution's canonical directory is eligible. Never follow a
    # workspace/ancestor symlink or search other executions for a matching ID.
    directory = root / 'workspaces' / identifier(execution.execution_id) / 'artifacts' / 'findings'
    for path in (directory, *directory.parents):
        if path == root:
            break
        if path.is_symlink():
            raise ValueError('unsafe finding directory')
    if not directory.exists():
        return status('pending', 'report-missing')
    matches = []
    marker = f'- **Candidate ID:** {cid}'.encode()
    for path in sorted(directory.glob('*.md')):
        raw = report_bytes(path)
        if marker in raw.splitlines():
            matches.append((raw, read_report_bytes(raw, slug=path.stem)))
    if len(matches) != 1:
        return status('pending', 'report-missing' if not matches else 'report-ambiguous')
    _, finding = matches[0]
    try:
        matches_endpoint = (HTTPOrigin.from_url(finding.url) == HTTPOrigin.from_url(candidate.target or '')
                            and urlsplit(finding.url).path == urlsplit(candidate.endpoint or '').path)
    except ValueError:
        matches_endpoint = False
    if (finding.candidate_id != cid or finding.canonical_class != candidate.candidate_class
            or finding.confirmation_binding != confirmation_binding(state, cid)
            or finding.binding_version != latest.assessment_contract_version
            or finding.assessment_result_id != latest.result_id
            or finding.assessment_attempt_id != latest.attempt_id
            or finding.assessment_source != latest.assessment_source
            or finding.evidence_refs != latest.evidence_refs
            or not matches_endpoint
            or (candidate.method and finding.method != candidate.method)
            or (candidate.parameter and finding.parameter != candidate.parameter)
            or finding.severity != latest.assessment.get('severity')
            or finding.observed_impact != apply_evidence(latest.assessment.get('observed_impact', '')).strip('\n')):
        return status('pending', 'report-stale')

    # Render a selected derivative, rather than copying arbitrary source Markdown.
    # Internal IDs become public IDs; provider/session data never enters it.
    text_fields = ('title', 'url', 'observed_impact', 'potential_impact', 'parameter',
                   'payload', 'method', 'responseExcerpt', 'curl', 'remediation',
                   'vulnerabilityType', 'createdAt', 'canonical_class')
    public = replace(finding, **{key: sanitize(value) if value is not None else None
                                for key in text_fields for value in [getattr(finding, key)]},
                     candidate_id=public_id('candidate', cid),
                     evidence_refs=[public_id('evidence', ref) for ref in latest.evidence_refs],
                     assessment_result_id=public_id('result', latest.result_id),
                     assessment_attempt_id=public_id('attempt', latest.attempt_id) if latest.attempt_id else None,
                     cwe=[sanitize(value) for value in finding.cwe] if finding.cwe else None,
                     owasp=[sanitize(value) for value in finding.owasp] if finding.owasp else None,
                     classification_provenance=None)
    ref = f'findings/{identifier(case_id)}.md'
    files[ref] = sanitize(render(public)).encode('utf-8')
    return {'status': 'persisted', 'report_ref': f'../{ref}', 'reason': None}
