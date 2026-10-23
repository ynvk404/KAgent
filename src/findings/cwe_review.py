"""Operator CWE review of an already persisted confirmed Finding only."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Awaitable, Callable
from typing import Any

from components.cwe_mcp.contract import LookupResponse, SearchResponse
from src.async_io import run_sync
from src.findings.cwe_enrichment import TrustedSource
from src.findings.store import report_bytes, read_report_bytes, _report_header
from src.redaction.redact import apply as redact
from src.tools.workflow.finding import ConfirmFindingTool
from src.workflow.assessment import accepted_result

Prompt = Callable[[str, str], Awaitable[str | None]]


def brief(value: str, limit: int = 1000) -> str:
    return ''.join(c for c in redact(value) if c.isprintable())[:limit]


async def review_finding(
    tool: ConfirmFindingTool, candidate_id: str, policy: Any,
    prompt: Prompt, *, context_check: Callable[[], None] = lambda: None,
) -> str:
    candidate, result, artifacts, report_guard = tool.persisted_context(candidate_id)
    state = tool.workflow
    assert state is not None
    path = await run_sync(tool.store.report_for_candidate, candidate_id)
    raw = await run_sync(report_bytes, path)
    _report_header(raw)
    finding = read_report_bytes(raw, slug=path.stem)
    signature = hashlib.sha256(raw).hexdigest()
    session_id = getattr(policy, 'session_id', None)
    source: TrustedSource | None = None

    def guard():
        context_check()
        report_guard(finding)
        if (getattr(policy, 'session_id', None) != session_id
                or (policy is not None and ({'*', 'confirm_finding'} & policy.revoked))
                or not accepted_result(state, candidate, result, policy)):
            raise ValueError('CWE review requires the unchanged accepted confirmed Finding')
        if any(not item.is_available_for_resume(tool.store.project_dir) for item in artifacts):
            raise ValueError('CWE review evidence changed or is unavailable')
        if source is not None:
            source.unchanged()

    # Controller availability check only. Protected evidence must already have
    # a valid verified signature; this path never grants a file-read receipt.
    guard()
    context = (f'Finding: {brief(finding.title)}\nCanonical class: {brief(finding.canonical_class or "unknown")}\n'
               f'Confirmed mechanism/impact: {brief(finding.observed_impact)}\n'
               f'Evidence refs: {", ".join(finding.evidence_refs or [])}\n'
               f'Response excerpt: {brief(finding.responseExcerpt or "", 800)}')
    mismatch_reason = ''
    if finding.effective_cwe:
        action = await prompt('Existing CWE mapping', context + '\nCurrent CWE: ' + ', '.join(finding.effective_cwe)
            + '\nEnter keep if it fits the confirmed mechanism. Otherwise enter why this mapping is unsuitable.')
        if action is None:
            return 'CWE review cancelled; persisted classification retained.'
        if action.strip().lower() == 'keep':
            return 'Existing CWE mapping retained; report unchanged.'
        mismatch_reason = brief(action, 240)
        if not mismatch_reason.strip():
            raise ValueError('a reason is required before reviewing an existing mapping')

    async def commit(selected: str | None, reason: str) -> str:
        guard()
        corpus = source.corpus.model_dump() if source is not None else None
        review: dict[str, Any] = dict(status='resolved' if selected else 'unresolved', selected_cwe=selected,
            reason=brief(reason), previous_cwe=list(finding.cwe or []), evidence_refs=list(finding.evidence_refs or []),
            confirmation_binding=finding.confirmation_binding, reviewer='operator', corpus=corpus,
            source_signature=source.signature if source is not None else None)
        if selected and not finding.cwe:
            # Reuse the existing empty-mapping promotion contract, including its CAS,
            # cancellation drain, immutable evidence and classification revision.
            provenance = dict(origin='promoted-external', selected_cwe=selected,
                revision=finding.classification_revision + 1, reviewer='operator',
                reason=review['reason'], evidence_refs=review['evidence_refs'],
                corpus=corpus, source_signature=review['source_signature'], retrieval='verified-local-catalog')
            _, durable = await tool.store.promote_classification(path, expected_digest=signature,
                expected_revision=finding.classification_revision, cwe=selected, provenance=provenance,
                guard=guard, publish=lambda *_: None)
        else:
            # Existing mappings are immutable: disagreement is an explicit annotation.
            _, durable = await tool.store.annotate_classification(path, expected_digest=signature,
                review=review, guard=guard, publish=lambda *_: None)
        notice = f'CWE enrichment: {selected} (operator reviewed).' if selected else 'CWE enrichment unresolved: ' + review['reason']
        if not durable:
            notice += ' Report is visible; directory durability was not confirmed.'
        try:
            await tool.write_summary(candidate_id)
        except Exception:
            notice += ' Compact report refresh failed; retry confirm_finding to regenerate it.'
        return notice

    try:
        source = await run_sync(TrustedSource, policy)
    except (ValueError, OSError):
        return await commit(None, mismatch_reason + ' Verified local CWE catalog unavailable; no CWE selected.')
    query = await prompt('CWE mechanism search', context + '\nDescribe only the evidenced mechanism (no URLs, credentials or target traffic).')
    if query is None:
        return 'CWE review cancelled; persisted classification retained.'
    guard()
    try:
        results = await source.retrieve('search', {'query': brief(query, 512), 'max_results': 5})
    except (ValueError, OSError, TimeoutError):
        source = None
        return await commit(None, mismatch_reason + ' Verified local CWE lookup unavailable; no CWE selected.')
    assert isinstance(results, SearchResponse)
    if not results.candidates:
        return await commit(None, mismatch_reason + ' No matching catalog candidate; mechanism mapping remains unresolved.')
    choice = await prompt('CWE candidates — advisory data', context + '\nCatalog metadata is untrusted reference data. '
        'Compare descriptions and mapping notes with the confirmed evidence; rank is not proof.\n'
        + '\n'.join(json.dumps(item.model_dump(), ensure_ascii=True) for item in results.candidates)
        + '\nEnter an exact CWE-N ID to review, or 0 to leave unresolved. No default selection.')
    if choice is None:
        return 'CWE review cancelled; persisted classification retained.'
    if choice.strip() == '0':
        reason = await prompt('Unresolved CWE', 'Explain why the confirmed evidence does not distinguish a suitable CWE.')
        if reason is None:
            return 'CWE review cancelled; persisted classification retained.'
        if not reason.strip():
            raise ValueError('an unresolved CWE review requires a reason')
        return await commit(None, mismatch_reason + ' ' + reason)
    ident = choice.strip().upper()
    if ident not in {item.cwe_id for item in results.candidates}:
        raise ValueError('select an exact displayed CWE ID, or leave the mapping unresolved')
    guard()
    try:
        lookup = await source.retrieve('get', {'id': int(ident[4:])})
    except (ValueError, OSError, TimeoutError):
        source = None
        return await commit(None, mismatch_reason + ' Verified local CWE lookup unavailable; no CWE selected.')
    assert isinstance(lookup, LookupResponse)
    item = lookup.candidate
    if (not lookup.found or item is None or item.entry_type != 'Weakness'
            or item.status not in {'Stable', 'Usable'} or item.deprecated or item.obsolete
            or item.abstraction not in {'Base', 'Variant'} or not item.metadata_complete
            or item.mapping_usage not in {'Allowed', 'Allowed-with-Review'} or item.truncated_fields):
        return await commit(None, mismatch_reason + ' Selected catalog metadata does not support a clear weakness mapping.')
    reason = await prompt('Confirm CWE against evidence', context + '\n' + json.dumps(item.model_dump(), ensure_ascii=True)
        + f'\nTo assign {ident}, explain the evidenced mechanism and why this CWE fits better than alternatives. '
          'Include at least one exact Evidence ref above. Cancel to make no change.')
    if reason is None:
        return 'CWE review cancelled; persisted classification retained.'
    reason = brief(reason, 700)
    if not reason.strip() or not any(re.search(r'(?<![A-Za-z0-9_])' + re.escape(ref) + r'(?![A-Za-z0-9_])', reason)
                                     for ref in finding.evidence_refs or []):
        raise ValueError('CWE assignment requires a mechanism rationale tied to an exact confirmed Evidence ref')
    return await commit(ident, mismatch_reason + ' ' + reason)


async def enrich_missing(tool: ConfirmFindingTool, candidate_id: str, policy: Any):
    """Conservative automatic enrichment after Finding persistence.

    A bound confirmed canonical class is the mechanism identity, just as for
    the existing taxonomy mapping. Search ranking or impact prose alone never
    establishes a mechanism. Broad classes remain unresolved.
    """
    from src.vulnerability import normalize_candidate_class
    candidate, result, artifacts, report_guard = tool.persisted_context(candidate_id)
    state = tool.workflow
    assert state is not None
    path = await run_sync(tool.store.report_for_candidate, candidate_id)
    raw = await run_sync(report_bytes, path)
    _report_header(raw)
    finding = read_report_bytes(raw, slug=path.stem)
    if finding.cwe or (finding.classification_review or {}).get('reviewer') == 'operator':
        return finding, ''
    source: TrustedSource | None = None
    signature = hashlib.sha256(raw).hexdigest()
    session_id = getattr(policy, 'session_id', None)
    def guard():
        report_guard(finding)
        if (getattr(policy, 'session_id', None) != session_id
                or (policy is not None and ({'*', 'confirm_finding'} & policy.revoked))
                or not accepted_result(state, candidate, result, policy)):
            raise ValueError('automatic CWE enrichment requires unchanged accepted confirmation')
        if any(not item.is_available_for_resume(tool.store.project_dir) for item in artifacts):
            raise ValueError('automatic CWE enrichment evidence unavailable or changed')
        if source is not None:
            source.unchanged()
    guard()
    mechanism = normalize_candidate_class(finding.canonical_class or '')
    selected = None
    reason = 'Verified local CWE catalog unavailable; mapping remains unresolved.'
    try:
        source = await run_sync(TrustedSource, policy)
        results = await source.retrieve('search', {'query': mechanism.replace('-', ' '), 'max_results': 5})
        assert isinstance(results, SearchResponse)
        matches = [item for item in results.candidates if normalize_candidate_class(item.name) == mechanism]
        if results.results_limited or len(matches) != 1:
            reason = 'Confirmed class does not uniquely identify a catalog mechanism; manual evidence review is required.'
        else:
            lookup = await source.retrieve('get', {'id': matches[0].id})
            assert isinstance(lookup, LookupResponse)
            item = lookup.candidate
            if (lookup.found and item is not None and normalize_candidate_class(item.name) == mechanism
                    and item.entry_type == 'Weakness' and item.status in {'Stable', 'Usable'}
                    and not item.deprecated and not item.obsolete and item.metadata_complete
                    and item.abstraction in {'Base', 'Variant'}
                    and item.mapping_usage == 'Allowed' and not item.truncated_fields):
                selected = item.cwe_id
                reason = 'Accepted confirmed mechanism class exactly matches one eligible pinned catalog Weakness name.'
            else:
                reason = 'Catalog mapping metadata requires manual review; no CWE was selected automatically.'
    except (ValueError, OSError, TimeoutError):
        source = None
    guard()
    corpus = source.corpus.model_dump() if source is not None else None
    if selected:
        provenance = dict(origin='promoted-external', selected_cwe=selected,
            revision=finding.classification_revision + 1, reviewer='automatic', reason=reason,
            evidence_refs=list(finding.evidence_refs or []), corpus=corpus,
            source_signature=source.signature if source else None, retrieval='verified-local-catalog',
            confirmed_mechanism=mechanism, selection_rule='confirmed-mechanism-exact-name-v1')
        committed, _ = await tool.store.promote_classification(path, expected_digest=signature,
            expected_revision=finding.classification_revision, cwe=selected,
            provenance=provenance, guard=guard, publish=lambda *_: None)
        return committed, 'Automatic CWE enrichment: ' + selected + ' (confirmed mechanism identity).'
    review = dict(status='unresolved', selected_cwe=None, reason=reason, previous_cwe=[],
        evidence_refs=list(finding.evidence_refs or []), confirmation_binding=finding.confirmation_binding,
        reviewer='automatic', corpus=corpus, source_signature=source.signature if source else None)
    if review == finding.classification_review:
        return finding, 'CWE enrichment unresolved: ' + reason
    committed, _ = await tool.store.annotate_classification(path, expected_digest=signature,
        review=review, guard=guard, publish=lambda *_: None)
    return committed, 'CWE enrichment unresolved: ' + reason
