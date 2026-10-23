"""Automatic enrichment uses confirmed mechanism identity, never search rank."""
from copy import deepcopy
import hashlib
import json

import pytest

from components.cwe_mcp import catalog
from components.cwe_mcp.contract import EXPECTED_MANIFEST, SearchResponse
from src.findings import cwe_enrichment as enrichment
from src.findings.cwe_review import enrich_missing
from src.findings.store import read_report, report_bytes
from src.permission.permission import AlwaysAllow
from src.workflow.state import WorkflowState
from tests.cwe.conftest import entry, xml_document
from tests.cwe.test_enrichment import scenario
from tests.cwe.test_finding_review import persisted, unchanged_proof, mapping_review, provenance
from tests.security.test_execution_policy import runtime
from tests.tools.test_finding import _tool, _valid_args, _workflow as workflow


def configure(scenario, monkeypatch, entries):
    raw = xml_document(entries)
    identity = EXPECTED_MANIFEST.corpus.model_copy(update={'xml_sha256': hashlib.sha256(raw).hexdigest()})
    pin = EXPECTED_MANIFEST.model_copy(update={'corpus': identity})
    monkeypatch.setattr(catalog, 'EXPECTED_MANIFEST', pin)
    monkeypatch.setattr(enrichment, 'EXPECTED_MANIFEST', pin)
    monkeypatch.setattr(enrichment, 'EXPECTED_CORPUS', identity)
    (scenario.deployment / 'corpus/cwec_v4.20.xml').write_bytes(raw)
    (scenario.deployment / 'manifest.json').write_text(json.dumps(pin.model_dump()))


async def test_confirm_finding_automatically_attempts_missing_mapping_and_records_unavailable(scenario):
    tool, cid, path = await persisted(scenario)
    finding = read_report(path)
    assert finding.cwe is None and finding.classification_revision == 0
    assert mapping_review(finding)['reviewer'] == 'automatic'
    assert mapping_review(finding)['status'] == 'unresolved'
    assert 'unavailable' in mapping_review(finding)['reason']
    assert workflow(tool).finding_is_persisted(cid) and workflow(tool).eligible_for_finding(cid)


async def test_existing_taxonomy_mapping_is_preserved_without_lookup(scenario, monkeypatch):
    def forbidden(*args): raise AssertionError('existing mappings must not be reclassified automatically')
    monkeypatch.setattr(enrichment.TrustedSource, '__init__', forbidden)
    tool, cid, path = await persisted(scenario, 'sqli')
    finding = read_report(path)
    assert finding.cwe == ['CWE-89'] and finding.classification_origin == 'verified-local'
    assert finding.classification_review is None


async def test_precisely_confirmed_mechanism_gets_unique_catalog_mapping(scenario):
    tool, cid, path = await persisted(scenario, 'missing-authorization')
    before, state = read_report(path), deepcopy(workflow(tool).to_dict())
    after, notice = await enrich_missing(tool, cid, scenario.policy)
    assert after.cwe == ['CWE-862'] and 'CWE-862' in notice
    assert provenance(after)['reviewer'] == 'automatic'
    assert provenance(after)['confirmed_mechanism'] == 'missing-authorization'
    assert provenance(after)['evidence_refs'] == before.evidence_refs
    assert provenance(after)['corpus']['xml_sha256'] == enrichment.EXPECTED_CORPUS.xml_sha256
    unchanged_proof(before, after)
    assert workflow(tool).to_dict() == state and len(list(path.parent.glob('*.md'))) == 1


async def test_broad_confirmed_class_is_not_inferred_from_a_single_search_hit(scenario):
    tool, cid, path = await persisted(scenario, 'access-control')
    after, _ = await enrich_missing(tool, cid, scenario.policy)
    assert after.cwe is None and after.effective_cwe == []
    assert mapping_review(after)['status'] == 'unresolved'
    assert 'uniquely identify' in mapping_review(after)['reason']


@pytest.mark.parametrize('problem', ['duplicate-name', 'mapping-review-required', 'incomplete'])
async def test_ambiguous_or_restricted_catalog_metadata_never_assigns_cwe(scenario, monkeypatch, problem):
    entries = (entry(862) + entry(863) if problem == 'duplicate-name' else
               entry(862, usage='Allowed-with-Review') if problem == 'mapping-review-required' else entry(862, notes=False))
    configure(scenario, monkeypatch, entries)
    tool, cid, path = await persisted(scenario, 'missing-authorization')
    after, _ = await enrich_missing(tool, cid, scenario.policy)
    assert after.cwe is None and mapping_review(after)['status'] == 'unresolved'
    assert after.classification_revision == 0 and not after.classification_provenance


async def test_automatic_mapping_follows_mechanism_identity_instead_of_first_rank(scenario, monkeypatch):
    configure(scenario, monkeypatch, entry(862, name='Incorrect Authorization for Object') + entry(863, name='Incorrect Authorization'))
    tool, cid, path = await persisted(scenario, 'incorrect-authorization')
    source = enrichment.TrustedSource(scenario.policy)
    results = await source.retrieve('search', {'query': 'incorrect authorization'})
    assert isinstance(results, SearchResponse)
    assert results.candidates[0].cwe_id == 'CWE-862'
    after, _ = await enrich_missing(tool, cid, scenario.policy)
    assert after.cwe == ['CWE-863']


async def test_normal_registry_confirm_flow_uses_local_catalog_without_a_new_tool(scenario):
    tool, store = _tool(scenario.policy.root, candidate_class='missing-authorization')
    scenario.registry.register(tool)
    cid = next(iter(workflow(tool).candidates))
    output = await scenario.registry.execute('confirm_finding', _valid_args(tool, url='http://127.0.0.1:3000/fixture'), None, scenario.prompter)
    finding = read_report(store.report_for_candidate(cid))
    assert finding.cwe == ['CWE-862'] and 'Automatic CWE enrichment: CWE-862' in output
    assert not any('cwe' in item['function']['name'] for item in scenario.registry.as_llm_tools())


@pytest.mark.parametrize('mechanism', ['missing-authorization', 'access-control'])
async def test_automatic_annotation_and_mapping_survive_restore_without_reclassification(scenario, mechanism):
    tool, cid, path = await persisted(scenario, mechanism)
    after, _ = await enrich_missing(tool, cid, scenario.policy)
    raw = report_bytes(path)
    tool.workflow = WorkflowState.from_dict(json.loads(json.dumps(workflow(tool).to_dict())))
    if after.cwe:
        await tool.run(_valid_args(tool), None, AlwaysAllow())
    else:
        await enrich_missing(tool, cid, scenario.policy)
    assert report_bytes(path) == raw
    assert workflow(tool).finding_is_persisted(cid) and workflow(tool).eligible_for_finding(cid)


async def test_automatic_enrichment_cannot_create_a_report(scenario):
    tool, _ = _tool(scenario.policy.root, candidate_class='missing-authorization')
    cid = next(iter(workflow(tool).candidates))
    with pytest.raises(ValueError, match='persisted finding required'):
        await enrich_missing(tool, cid, scenario.policy)
    assert not list(tool.store.dir.glob('*.md'))


async def test_manual_unresolved_review_is_not_overridden_automatically(scenario, monkeypatch):
    from src.findings.cwe_review import review_finding
    from tests.cwe.test_finding_review import answers
    tool, cid, path = await persisted(scenario, 'missing-authorization')
    prompt, _ = answers('missing authorization', '0', 'Evidence does not establish the specific check failure sufficiently.')
    await review_finding(tool, cid, scenario.policy, prompt)
    raw = report_bytes(path)
    def forbidden(*args): raise AssertionError('manual decisions require manual reassessment')
    monkeypatch.setattr(enrichment.TrustedSource, '__init__', forbidden)
    finding, _ = await enrich_missing(tool, cid, scenario.policy)
    assert finding.cwe is None and report_bytes(path) == raw
    assert mapping_review(finding)['reviewer'] == 'operator'


@pytest.mark.parametrize('fault', ['evidence', 'session', 'revoked'])
async def test_automatic_lookup_cannot_commit_after_its_context_changes(scenario, monkeypatch, fault):
    tool, cid, path = await persisted(scenario, 'missing-authorization')
    raw = report_bytes(path)
    search = catalog.Catalog.search
    def changed(self, args):
        result = search(self, args)
        if fault == 'evidence':
            proof = next(iter(workflow(tool).evidence.values()))
            (tool.store.project_dir / proof.path).write_text('proof changed during lookup')
        elif fault == 'session': scenario.policy.session_id = 'different-session'
        else: scenario.policy.revoked.add('confirm_finding')
        return result
    monkeypatch.setattr(catalog.Catalog, 'search', changed)
    with pytest.raises(ValueError):
        await enrich_missing(tool, cid, scenario.policy)
    assert read_report(path).cwe is None and report_bytes(path) == raw


async def test_confirm_rechecks_evidence_after_automatic_lookup(scenario, monkeypatch):
    notified = []
    tool, store = _tool(scenario.policy.root, candidate_class='missing-authorization',
                        notifier=lambda *args: notified.append(args))
    scenario.registry.register(tool)
    cid = next(iter(workflow(tool).candidates))
    search = catalog.Catalog.search
    def changed(self, args):
        results = search(self, args)
        proof = next(iter(workflow(tool).evidence.values()))
        (tool.store.project_dir / proof.path).write_text('proof changed during automatic enrichment')
        return results
    monkeypatch.setattr(catalog.Catalog, 'search', changed)
    with pytest.raises(ValueError, match='evidence artifact changed during CWE enrichment'):
        await scenario.registry.execute('confirm_finding',
            _valid_args(tool, url='http://127.0.0.1:3000/fixture'), None, scenario.prompter)
    assert not notified and read_report(store.report_for_candidate(cid)).cwe is None
