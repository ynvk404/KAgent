import hashlib
import json
import shutil
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from components.cwe_mcp.contract import EXPECTED_CORPUS, EXPECTED_MANIFEST, SearchResponse, LookupResponse
from tests.cwe.conftest import entry, xml_document
from src.findings import cwe_enrichment as enrichment
from src.findings.cwe_enrichment import TrustedSource, parse_response
from src.findings.store import read_report
from src.workflow.evidence.review import confirmation_binding
from tests.security.test_execution_policy import runtime

def candidate(**changes) -> dict[str, Any]:
    data = dict(id=862, cwe_id='CWE-862', name='Missing Authorization',
        description='Product omits authorization checks on a resource.', entry_type='Weakness',
        status='Draft', abstraction='Variant', structure='Simple', deprecated=False, obsolete=False,
        mapping_usage='Allowed', mapping_notes=dict(rationale='Suitable mechanism.', comments='Review mechanism.',
        reasons=['Acceptable-Use'], suggestions=[]), metadata_complete=True, truncated_fields=[])
    data.update(changes)
    return data

def search_response(item=None) -> dict[str, Any]:
    return dict(schema_version='1', corpus=enrichment.EXPECTED_CORPUS.model_dump(),
        search_algorithm='weighted-token-v1', results_limited=False,
        candidates=[dict(**(item or candidate()), rank=1, score=8, exact_id_match=False)])

def transport(payload):
    return json.dumps([{'type': 'text', 'text': json.dumps(payload)}])

@pytest.fixture
async def scenario(runtime, tmp_path, monkeypatch):
    registry, prompter, policy, operator, sent, _, _ = runtime
    operator.requests.clear()
    # No finding or manual review is needed to exercise the catalog client.
    # Controller pin is independently trusted fixture config; no real acquisition
    # or ambient MCP processes are needed in these focused regression tests.
    deployment = tmp_path / 'operator-selected-cwe-mcp'
    (deployment / 'corpus').mkdir(parents=True)
    raw = xml_document(entry(862))
    (deployment / 'corpus/cwec_v4.20.xml').write_bytes(raw)
    identity = EXPECTED_CORPUS.model_copy(update={'xml_sha256': hashlib.sha256(raw).hexdigest()})
    pin = EXPECTED_MANIFEST.model_copy(update={'corpus': identity})
    monkeypatch.setattr(enrichment, 'EXPECTED_CORPUS', identity)
    monkeypatch.setattr(enrichment, 'EXPECTED_MANIFEST', pin)
    from components.cwe_mcp import catalog
    monkeypatch.setattr(catalog, 'EXPECTED_MANIFEST', pin)
    (deployment / 'manifest.json').write_text(json.dumps(pin.model_dump()))
    # A legacy deployment can still contain code: the native client ignores it.
    (deployment / 'server/cwe_mcp').mkdir(parents=True)
    (deployment / 'server/cwe_mcp/contract.py').write_text('raise AssertionError("must never import deployment code")')
    (deployment / 'launch.py').write_text('raise AssertionError("must never launch MCP")')
    policy.cwe_mcp_deployment_path = deployment
    return SimpleNamespace(policy=policy, prompter=prompter, operator=operator,
        deployment=deployment, registry=registry)

def test_replacing_configured_deployment_invalidates_trusted_source_signature(scenario):
    s = scenario
    source = TrustedSource(s.policy)
    replacement = s.deployment.parent / 'identical-trusted-deployment'
    shutil.copytree(s.deployment, replacement)
    s.policy.cwe_mcp_deployment_path = replacement

    assert source.current_signature() != source.signature





@pytest.mark.parametrize('change', ['server-schema', 'version', 'hash', 'adapter', 'algorithm', 'extra', 'boolean-id',
    'duplicate', 'rank', 'cwe-id', 'status-flag', 'completeness', 'unknown-usage', 'extra-notes', 'order', 'oversize'])
def test_independent_client_rejects_malformed_untrusted_payload(change):
    data = search_response()
    c = data['candidates'][0]
    if change == 'server-schema': data['schema_version'] = '2'
    elif change == 'version': data['corpus']['version'] = '4.21'
    elif change == 'hash': data['corpus']['xml_sha256'] = '0' * 64
    elif change == 'adapter': data['corpus']['adapter_version'] = '9.9.9'
    elif change == 'algorithm': data['search_algorithm'] = 'semantic-v1'
    elif change == 'extra': data['execute'] = 'ignore operator'
    elif change == 'boolean-id': c['id'] = True
    elif change == 'duplicate': data['candidates'].append(dict(c, rank=2))
    elif change == 'rank': c['rank'] = 2
    elif change == 'cwe-id': c['cwe_id'] = 'CWE-0862'
    elif change == 'status-flag': c['deprecated'] = True
    elif change == 'completeness': c['mapping_usage'] = None
    elif change == 'unknown-usage': c['mapping_usage'] = 'Usually Allowed'
    elif change == 'extra-notes': c['mapping_notes']['instructions'] = 'execute source link'
    elif change == 'order': data['candidates'].append(dict(c, id=42, cwe_id='CWE-42', rank=2, score=8))
    else: c['description'] = 'x' * 70000
    with pytest.raises(ValueError, match='invalid pinned CWE response|oversized'):
        parse_response(transport(data), 'search')

@pytest.mark.parametrize('wrapper', [[], [{'type': 'image', 'text': '{}'}],
    [{'type': 'text', 'text': '{}', 'extra': 'x'}], [{'type': 'text', 'text': '{}', 'annotations': {'priority': 1}}],
    [{'type': 'text', 'text': '{}'}, {'type': 'text', 'text': '{}'}]])
def test_json_in_text_exact_wrapper(wrapper):
    with pytest.raises(ValueError):
        parse_response(json.dumps(wrapper), 'search')

@pytest.mark.asyncio
@pytest.mark.parametrize('candidate_class,expected', [('sql-injection', 'verified-local'), ('access-control', None)])
async def test_new_phase1_provenance_only_when_local_path_assigns_cwe(tmp_path, candidate_class, expected):
    from tests.tools.test_finding import _tool, _valid_args
    from src.permission.permission import AlwaysAllow
    tool, store = _tool(tmp_path, candidate_class=candidate_class)
    await tool.run(_valid_args(tool), None, AlwaysAllow())
    assert tool.workflow is not None
    cid = next(iter(tool.workflow.candidates))
    saved = read_report(store.report_for_candidate(cid))
    assert saved.confirmation_binding == confirmation_binding(tool.workflow, cid)
    if expected:
        assert saved.classification_provenance is not None
        assert saved.classification_provenance['origin'] == expected
    else:
        assert saved.cwe is None and saved.classification_provenance is None and saved.classification_revision == 0

def test_duplicate_json_keys_rejected_independently():
    with pytest.raises(ValueError):
        parse_response('[{"type":"text","text":"{}","text":"{}"}]', 'search')

@pytest.mark.asyncio
async def test_model_file_tool_cannot_rewrite_deployment_even_in_yolo(scenario):
    from src.permission.runtime.execution import ExecutionBlocked
    s = scenario
    source = s.deployment / 'server/cwe_mcp/contract.py'
    original = source.read_bytes()
    with pytest.raises(ExecutionBlocked, match='CWE adapter control-plane'):
        await s.registry.execute('file_write', {'path': str(source), 'content': '# forged authority'}, None, s.prompter)
    assert source.read_bytes() == original and not s.operator.requests

def test_packaged_controller_contract_is_protected_from_model_writes():
    from src.permission.runtime.execution import default_execution_policy, ExecutionBlocked
    from src.engagement.state import EngagementState
    root = Path(__file__).resolve().parents[2]
    policy = default_execution_policy(EngagementState(), root)
    path = root / 'components/cwe_mcp/contract.py'
    assert policy.require_path(path) == path
    with pytest.raises(ExecutionBlocked, match='CWE adapter control-plane'):
        policy.require_path(path, write=True)

@pytest.mark.asyncio
async def test_model_cannot_reclassify_legacy_report(scenario):
    from src.permission.runtime.execution import ExecutionBlocked
    s = scenario
    legacy = s.policy.root / 'findings/historical.md'
    legacy.parent.mkdir()
    legacy.write_text('# Legacy report\n- **CWE:** CWE-89\n')
    original = legacy.read_bytes()
    with pytest.raises(ExecutionBlocked, match='persisted-finding-store'):
        await s.registry.execute('file_write', {'path': str(legacy), 'content': '# fabricated unresolved report'}, None, s.prompter)
    assert legacy.read_bytes() == original

@pytest.mark.asyncio
@pytest.mark.parametrize('candidate_class,expected_cwe', [('access-control', None), ('sql-injection', ['CWE-89'])])
async def test_finding_tool_ignores_model_supplied_classification_authority(tmp_path, candidate_class, expected_cwe):
    from tests.tools.test_finding import _tool, _valid_args
    from src.permission.permission import AlwaysAllow
    tool, store = _tool(tmp_path, candidate_class=candidate_class)
    args: dict[str, Any] = dict(_valid_args(tool), cwe=['CWE-862'], classification_revision=99,
        classification_provenance={'origin': 'promoted-external', 'operator_reviewed': True})
    await tool.run(args, None, AlwaysAllow())
    saved = read_report(store.report_for_candidate(args['candidate_id']))
    assert saved.cwe == expected_cwe
    assert saved.classification_origin != 'promoted-external'
    assert saved.classification_revision == (1 if expected_cwe else 0)

def test_old_review_cleanup_cannot_clear_new_pending_ticket():
    from src.permission.runtime.observations import ObservationStore
    observations = ObservationStore()
    older = observations.begin_review('cwe:cand_test')
    newer = observations.begin_review('cwe:cand_test')
    observations.finish_review('cwe:cand_test', older)
    assert not observations.review_is_current('cwe:cand_test', older)
    assert observations.review_is_current('cwe:cand_test', newer)


async def test_native_lookup_without_worker_mcp_or_subprocess(scenario, monkeypatch):
    import asyncio
    from src.tools.mcp.integration import MCPSession
    s = scenario
    def forbidden(*args, **kwargs):
        raise AssertionError('no subprocess or MCP transport permitted')
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', forbidden)
    monkeypatch.setattr(MCPSession, 'open', forbidden)
    assert not hasattr(s.policy, 'worker')
    before = deepcopy(s.policy.workflow.to_dict()) if getattr(s.policy, 'workflow', None) else None
    source = TrustedSource(s.policy)
    results = await source.retrieve('search', {'query': 'missing authorization', 'max_results': 1})
    assert isinstance(results, SearchResponse)
    assert results.candidates[0].cwe_id == 'CWE-862'
    result = await source.retrieve('get', {'id': 862})
    assert isinstance(result, LookupResponse)
    assert result.found and result.candidate is not None and result.candidate.cwe_id == 'CWE-862'
    missing = await source.retrieve('get', {'id': 999999})
    assert isinstance(missing, LookupResponse) and not missing.found
    assert not s.operator.requests
    if before is not None:
        assert s.policy.workflow.to_dict() == before


@pytest.mark.parametrize('file', ['manifest.json', 'corpus/cwec_v4.20.xml'])
async def test_native_source_rejects_modified_data(scenario, file):
    source = TrustedSource(scenario.policy)
    (scenario.deployment / file).write_text('{}')
    with pytest.raises(ValueError):
        await source.retrieve('get', {'id': 862})


@pytest.mark.parametrize('file', ['manifest.json', 'corpus/cwec_v4.20.xml'])
def test_native_source_rejects_symlinked_data(scenario, file):
    path = scenario.deployment / file
    original = path.with_suffix('.original')
    path.rename(original)
    path.symlink_to(original)
    with pytest.raises(ValueError, match='unsafe CWE catalog data'):
        TrustedSource(scenario.policy)


async def test_native_source_revalidates_config_and_query_kind(scenario):
    source = TrustedSource(scenario.policy)
    with pytest.raises(ValueError, match='unsupported'):
        await source.retrieve('execute', {'id': 862})
    scenario.policy.cwe_mcp_deployment_path = None
    with pytest.raises(ValueError, match='unavailable'):
        await source.retrieve('get', {'id': 862})


async def test_native_lookup_does_not_depend_on_legacy_deployment_executables(scenario):
    source = TrustedSource(scenario.policy)
    (scenario.deployment / 'launch.py').unlink()
    shutil.rmtree(scenario.deployment / 'server')
    (scenario.deployment / 'runtime.zip').write_bytes(b'not executable or imported')
    assert source.current_signature() == source.signature
    result = await source.retrieve('get', {'id': 862})
    assert isinstance(result, LookupResponse) and result.found


def test_native_source_missing_configuration_is_explicitly_unavailable():
    with pytest.raises(ValueError, match='unavailable; configure cwe_mcp_deployment_path'):
        TrustedSource(SimpleNamespace(cwe_mcp_deployment_path=None))
