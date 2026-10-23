"""Offline review joins existing confirmed reports to a pinned local catalog."""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from types import SimpleNamespace
from typing import Any, cast

import pytest

from components.cwe_mcp import catalog
from components.cwe_mcp.contract import EXPECTED_MANIFEST
from src.findings import cwe_enrichment as enrichment
from src.findings.cwe_review import review_finding
from src.findings.presentation import render_summary
from src.findings.store import Finding, read_report, report_bytes
from src.permission.permission import AlwaysAllow
from src.workflow.state import WorkflowState
from tests.cwe.conftest import entry, xml_document
from tests.cwe.test_enrichment import scenario
from tests.security.test_execution_policy import runtime
from tests.tools.test_finding import _tool, _valid_args, _workflow as workflow


def mapping_review(finding: Finding) -> dict[str, Any]:
    assert finding.classification_review is not None
    return finding.classification_review


def provenance(finding: Finding) -> dict[str, Any]:
    assert finding.classification_provenance is not None
    return finding.classification_provenance


def proof_refs(finding: Finding) -> list[str]:
    assert finding.evidence_refs
    return finding.evidence_refs


async def persisted(scenario, kind='access-control', *, old_cwe=None):
    tool, store = _tool(scenario.policy.root, candidate_class=kind)
    await tool.run(_valid_args(tool), None, AlwaysAllow())
    cid = next(iter(workflow(tool).candidates))
    path = store.report_for_candidate(cid)
    if old_cwe:
        # Historical fixture with an unsuitable mapping; production never edits it.
        original = b''.join(line for line in report_bytes(path).splitlines(keepends=True) if not line.startswith(b'- **CWE review:**'))
        path.write_bytes(original.replace(b'- **URL:**', ('- **CWE:** ' + old_cwe + '\n- **URL:**').encode(), 1))
    return tool, cid, path


def answers(*values):
    calls = []
    async def prompt(title, question):
        calls.append((title, question))
        assert len(calls) <= len(values), 'unexpected prompt'
        return values[len(calls) - 1]
    return prompt, calls


def unchanged_proof(before, after):
    first, second = asdict(before), asdict(after)
    for key in ('cwe', 'classification_provenance', 'classification_revision', 'classification_review'):
        first.pop(key); second.pop(key)
    assert first == second


async def test_existing_suitable_mapping_needs_no_catalog_or_reclassification(scenario):
    tool, cid, path = await persisted(scenario, 'sqli')
    raw = report_bytes(path)
    snapshot = deepcopy(workflow(tool).to_dict())
    scenario.policy.cwe_mcp_deployment_path = None
    prompt, calls = answers('keep')
    notice = await review_finding(tool, cid, scenario.policy, prompt)
    assert 'retained' in notice and len(calls) == 1
    assert read_report(path).cwe == ['CWE-89'] and report_bytes(path) == raw
    assert workflow(tool).to_dict() == snapshot


@pytest.mark.parametrize('query', ['missing authorization', 'CWE-862'])
async def test_missing_mapping_uses_existing_promotion_with_explicit_evidence_review(scenario, query):
    tool, cid, path = await persisted(scenario)
    before = read_report(path)
    state = deepcopy(workflow(tool).to_dict())
    ref = proof_refs(before)[0]
    prompt, calls = answers(query, 'CWE-862', f'{ref}: object access omits authorization, matching the missing check mechanism.')
    notice = await review_finding(tool, cid, scenario.policy, prompt)
    after = read_report(path)
    assert 'CWE-862' in notice and after.cwe == ['CWE-862'] and after.classification_revision == 1
    assert after.classification_origin == 'promoted-external' and after.classification_review is None
    assert provenance(after)['retrieval'] == 'verified-local-catalog'
    assert provenance(after)['evidence_refs'] == before.evidence_refs
    unchanged_proof(before, after)
    assert workflow(tool).to_dict() == state and len(list(path.parent.glob('*.md'))) == 1
    assert 'rank is not proof' in calls[1][1] and ref in calls[2][1]


async def test_unsuitable_existing_mapping_is_annotated_without_replacing_it(scenario):
    tool, cid, path = await persisted(scenario, old_cwe='CWE-79')
    before, raw = read_report(path), report_bytes(path)
    snapshot = deepcopy(workflow(tool).to_dict())
    ref = proof_refs(before)[0]
    prompt, _ = answers('The confirmed mechanism is missing authorization, not script execution.',
                        'missing authorization', 'CWE-862', f'{ref}: the request reaches an object without the authorization check described in CWE-862.')
    await review_finding(tool, cid, scenario.policy, prompt)
    after = read_report(path)
    assert after.cwe == ['CWE-79'] and after.classification_revision == before.classification_revision
    assert after.effective_cwe == ['CWE-862'] and mapping_review(after)['status'] == 'resolved'
    assert mapping_review(after)['previous_cwe'] == ['CWE-79']
    assert mapping_review(after)['confirmation_binding'] == before.confirmation_binding
    assert b''.join(row for row in report_bytes(path).splitlines(keepends=True) if not row.startswith(b'- **CWE review:**')) == raw
    unchanged_proof(before, after)
    assert workflow(tool).to_dict() == snapshot
    summary = render_summary(after)
    assert 'CWE-862' in summary and 'Original CWE mapping' in summary and 'CWE-79' in summary


@pytest.mark.parametrize('old_cwe', [None, 'CWE-79'])
async def test_ambiguous_catalog_results_stay_unresolved_with_reason(scenario, old_cwe):
    tool, cid, path = await persisted(scenario, old_cwe=old_cwe)
    values = ['The old mapping does not match the authorization mechanism.'] if old_cwe else []
    prompt, _ = answers(*values, 'authorization', '0', 'Evidence does not distinguish an absent check from an incorrect check.')
    await review_finding(tool, cid, scenario.policy, prompt)
    finding = read_report(path)
    assert finding.cwe == ([old_cwe] if old_cwe else None)
    assert finding.effective_cwe == [] and mapping_review(finding)['status'] == 'unresolved'
    assert 'does not distinguish' in mapping_review(finding)['reason']
    assert mapping_review(finding)['selected_cwe'] is None


async def test_catalog_unavailable_records_limitation_without_guessing(scenario):
    tool, cid, path = await persisted(scenario)
    before = read_report(path)
    scenario.policy.cwe_mcp_deployment_path = None
    prompt, calls = answers()
    notice = await review_finding(tool, cid, scenario.policy, prompt)
    finding = read_report(path)
    assert not calls and finding.cwe is None and finding.effective_cwe == []
    assert mapping_review(finding)['corpus'] is None
    assert 'unavailable' in notice and 'unavailable' in mapping_review(finding)['reason']
    unchanged_proof(before, finding)


async def test_second_ranked_cwe_is_not_replaced_by_the_first_search_hit(scenario, monkeypatch):
    raw = xml_document(entry(862) + entry(863, name='Incorrect Authorization'))
    identity = EXPECTED_MANIFEST.corpus.model_copy(update={'xml_sha256': hashlib.sha256(raw).hexdigest()})
    pin = EXPECTED_MANIFEST.model_copy(update={'corpus': identity})
    monkeypatch.setattr(catalog, 'EXPECTED_MANIFEST', pin)
    monkeypatch.setattr(enrichment, 'EXPECTED_MANIFEST', pin)
    monkeypatch.setattr(enrichment, 'EXPECTED_CORPUS', identity)
    (scenario.deployment / 'corpus/cwec_v4.20.xml').write_bytes(raw)
    (scenario.deployment / 'manifest.json').write_text(json.dumps(pin.model_dump()))
    tool, cid, path = await persisted(scenario)
    ref = proof_refs(read_report(path))[0]
    prompt, calls = answers('authorization', 'CWE-863', f'{ref}: an authorization check exists but grants the incorrect object scope; the selected mechanism is incorrect authorization.')
    await review_finding(tool, cid, scenario.policy, prompt)
    assert calls[1][1].index('CWE-862') < calls[1][1].index('CWE-863')
    assert read_report(path).cwe == ['CWE-863']


@pytest.mark.parametrize('fault', ['no-rationale', 'foreign-ref', 'cancel', 'invalid-choice', 'evidence-changed', 'report-changed'])
async def test_no_assignment_without_unchanged_confirmed_evidence_and_explicit_choice(scenario, fault):
    tool, cid, path = await persisted(scenario)
    raw = report_bytes(path)
    finding = read_report(path)
    async def prompt(title, question):
        if title == 'CWE mechanism search': return 'missing authorization'
        if title == 'CWE candidates — advisory data':
            return '1' if fault == 'invalid-choice' else 'CWE-862'
        if fault == 'cancel': return None
        if fault == 'evidence-changed':
            artifact = workflow(tool).evidence[proof_refs(finding)[0]]
            (tool.store.project_dir / artifact.path).write_text('changed evidence')
        if fault == 'report-changed': path.write_bytes(raw + b'\noperator update\n')
        if fault == 'no-rationale': return ''
        if fault == 'foreign-ref': return 'ev_foreign: a mechanism without owned evidence'
        return proof_refs(finding)[0] + ': confirmed mechanism matches missing authorization.'
    if fault == 'cancel':
        assert 'cancelled' in await review_finding(tool, cid, scenario.policy, prompt)
    else:
        with pytest.raises(ValueError):
            await review_finding(tool, cid, scenario.policy, prompt)
    assert read_report(path).cwe is None
    if fault != 'report-changed': assert report_bytes(path) == raw


async def test_enrichment_cannot_create_a_finding_from_a_candidate(scenario):
    tool, _ = _tool(scenario.policy.root, candidate_class='access-control')
    cid = next(iter(workflow(tool).candidates))
    prompt, calls = answers()
    with pytest.raises(ValueError, match='persisted finding required'):
        await review_finding(tool, cid, scenario.policy, prompt)
    assert not calls and not list(tool.store.dir.glob('*.md'))


@pytest.mark.parametrize('old_cwe', [None, 'CWE-79'])
async def test_session_restore_and_confirm_retry_preserve_enrichment(scenario, old_cwe):
    tool, cid, path = await persisted(scenario, old_cwe=old_cwe)
    ref = proof_refs(read_report(path))[0]
    values = ['The persisted mapping does not match the confirmed authorization evidence.'] if old_cwe else []
    prompt, _ = answers(*values, 'missing authorization', 'CWE-862', f'{ref}: the object is accessible without authorization, matching the missing check.')
    await review_finding(tool, cid, scenario.policy, prompt)
    raw = report_bytes(path)
    tool.workflow = WorkflowState.from_dict(json.loads(json.dumps(workflow(tool).to_dict())))
    assert workflow(tool).finding_is_persisted(cid) and workflow(tool).eligible_for_finding(cid)
    await tool.run(_valid_args(tool), None, AlwaysAllow())
    assert report_bytes(path) == raw and read_report(path).effective_cwe == ['CWE-862']
    assert len(list(path.parent.glob('*.md'))) == 1


async def test_later_promotion_clears_an_unresolved_annotation(scenario):
    tool, cid, path = await persisted(scenario)
    prompt, _ = answers('authorization', '0', 'Not enough mechanism evidence yet.')
    await review_finding(tool, cid, scenario.policy, prompt)
    ref = proof_refs(read_report(path))[0]
    prompt, _ = answers('missing authorization', 'CWE-862', f'{ref}: reviewed proof shows the missing authorization check, fitting CWE-862.')
    await review_finding(tool, cid, scenario.policy, prompt)
    finding = read_report(path)
    assert finding.cwe == ['CWE-862'] and finding.effective_cwe == ['CWE-862'] and finding.classification_review is None


async def test_controller_does_not_open_unverified_protected_evidence(scenario, monkeypatch):
    from src.workflow.evidence.artifacts import EvidenceArtifact
    tool, cid, path = await persisted(scenario)
    raw = report_bytes(path)
    monkeypatch.setattr(EvidenceArtifact, 'is_available_for_resume', lambda *args: False)
    prompt, calls = answers()
    with pytest.raises(ValueError, match='evidence changed or is unavailable'):
        await review_finding(tool, cid, scenario.policy, prompt)
    assert not calls and report_bytes(path) == raw


async def test_cwe_command_runs_without_model_and_never_emits_a_new_finding(scenario):
    import asyncio
    from src.target.target import Target
    from src.ui.commands.slash_handler import handle_slash
    tool, cid, path = await persisted(scenario)
    ref = proof_refs(read_report(path))[0]
    prompt, _ = answers('authorization', 'CWE-862', f'{ref}: the evidence proves a missing authorization check on object access.')
    dispatched = []
    app = SimpleNamespace(_skill_task=None, dispatch=dispatched.append)
    app.agent = SimpleNamespace(workflow=workflow(tool), target=Target('https://target.test'),
        engagement_state=scenario.policy.engagement, tools={'confirm_finding': tool}, prompter=scenario.prompter,
        is_running=lambda: False)
    async def prompt_text(request):
        assert request.scrollable and request.initial_value == ''
        return await prompt(request.header, request.question)
    app.prompt_text = prompt_text
    assert handle_slash(cast(Any, app), '/cwe ' + cid)
    await asyncio.wait_for(app._skill_task, 5)
    assert read_report(path).cwe == ['CWE-862']
    assert any('CWE enrichment: CWE-862' in action.entry.text for action in dispatched)
    assert not any('Finding saved' in action.entry.text for action in dispatched)


async def test_review_annotation_is_rendered_in_pdf_report_without_eligibility_changes(tmp_path):
    from tests.report.test_builder import finding_fixture, resources, source
    from src.findings.store import render
    from src.report.builder import build_report
    state, candidate, result, finding, path = finding_fixture(tmp_path)
    finding.cwe = ['CWE-79']
    finding.classification_review = dict(status='resolved', selected_cwe='CWE-862',
        reason='ev_one: confirmed object access omitted the authorization check.', previous_cwe=['CWE-79'],
        evidence_refs=finding.evidence_refs, confirmation_binding=finding.confirmation_binding,
        reviewer='operator', corpus={'name': 'CWE', 'version': '4.20'}, source_signature='a' * 64)
    path.write_text(render(finding))
    before = deepcopy(state.to_dict())
    report = build_report(source(state), resources(tmp_path))
    assert report.finding_count == 1 and report.unfinalized_count == 0
    details = dict(report.findings[0].details)
    assert details['CWE'] == 'CWE-862' and details['Original CWE mapping'] == 'CWE-79'
    assert 'resolved' in details['CWE enrichment'] and state.to_dict() == before


async def test_stale_ui_context_cannot_commit_review(scenario):
    tool, cid, path = await persisted(scenario)
    raw = report_bytes(path)
    stale = False
    async def prompt(title, question):
        nonlocal stale
        stale = True
        return 'authorization'
    def context_check():
        if stale: raise ValueError('context changed')
    with pytest.raises(ValueError, match='context changed'):
        await review_finding(tool, cid, scenario.policy, prompt, context_check=context_check)
    assert report_bytes(path) == raw
