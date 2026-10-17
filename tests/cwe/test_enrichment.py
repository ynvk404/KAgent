import asyncio
import hashlib
import json
import shutil
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from components.cwe_mcp.contract import EXPECTED_CORPUS, EXPECTED_MANIFEST, GET_SCHEMA, SEARCH_SCHEMA, SearchResponse
from src.config.config import MCPServerConfig
from src.findings import cwe_enrichment as enrichment
from src.findings.cwe_enrichment import TrustedSource, parse_response
from src.findings.store import read_report
from src.permission.permission import UserControlledRefusal
from src.tools.mcp.integration import MCPSession, MCPTool
from src.workflow.review import confirmation_binding
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
    (deployment / 'server/cwe_mcp').mkdir(parents=True)
    (deployment / 'corpus').mkdir()
    raw = b'Synthetic pinned corpus fixture; no target data.'
    (deployment / 'corpus/cwec_v4.20.xml').write_bytes(raw)
    identity = EXPECTED_CORPUS.model_copy(update={'xml_sha256': hashlib.sha256(raw).hexdigest()})
    pin = EXPECTED_MANIFEST.model_copy(update={'corpus': identity})
    monkeypatch.setattr(enrichment, 'EXPECTED_CORPUS', identity)
    monkeypatch.setattr(enrichment, 'EXPECTED_MANIFEST', pin)
    (deployment / 'manifest.json').write_text(json.dumps(pin.model_dump()))
    for file in ('launch.py', 'server/cwe_mcp/__init__.py', 'server/cwe_mcp/contract.py',
                 'server/cwe_mcp/catalog.py', 'server/cwe_mcp/server.py'):
        (deployment / file).write_text('# Reviewed synthetic fixture code\n')
    policy.cwe_mcp_deployment_path = deployment
    policy.worker = SimpleNamespace(summary=lambda: 'isolated fixture worker',
                                   cwe_mcp_deployment_path=deployment)
    remote = SimpleNamespace(item=candidate(), calls=[], closed=0, block=None, opened=asyncio.Event(),
                             cleanup=asyncio.Event(), fail=None, search_override=None, lookup_override=None)
    class Session:
        server_name = 'cwe_catalog'
        async def call_tool(self, name, args, cancel_event=None):
            assert policy.nested_allowed()
            remote.calls.append((name, deepcopy(args)))
            if remote.block:
                remote.opened.set()
                try:
                    await remote.block.wait()
                finally:
                    remote.cleanup.set()
            if remote.fail:
                raise remote.fail
            payload = (remote.search_override or search_response(remote.item)) if name == 'search_cwe' else (
                remote.lookup_override or dict(schema_version='1', corpus=identity.model_dump(), found=True, candidate=remote.item))
            return {'isError': False, 'content': [{'type': 'text', 'text': json.dumps(payload)}]}
        async def close(self):
            remote.closed += 1
        def is_closed(self):
            return False
    async def open_session(*args, **kwargs):
        assert kwargs['worker'] is policy.worker and policy.nested_allowed()
        return Session()
    monkeypatch.setattr(MCPSession, 'open', open_session)
    cfg = MCPServerConfig('cwe_catalog', '/usr/bin/python3', ['-I', '-B', enrichment.DEPLOYMENT_LAUNCH])
    for name, schema in [('search_cwe', SEARCH_SCHEMA), ('get_cwe', GET_SCHEMA)]:
        tool = MCPTool(Session(), 'mcp_cwe_catalog_'+name, name, '', deepcopy(schema))
        tool._server = deepcopy(cfg)
        tool._execution_policy = policy
        registry.register(tool)
    return SimpleNamespace(policy=policy, prompter=prompter, operator=operator, remote=remote,
        deployment=deployment, registry=registry)


def test_replacing_configured_deployment_invalidates_trusted_source_signature(scenario):
    s = scenario
    source = TrustedSource(s.registry, s.policy)
    replacement = s.deployment.parent / 'identical-trusted-deployment'
    shutil.copytree(s.deployment, replacement)
    s.policy.cwe_mcp_deployment_path = replacement
    s.policy.worker.cwe_mcp_deployment_path = replacement

    assert source.current_signature() != source.signature


def test_worker_deployment_change_invalidates_source_and_policy_stamp(scenario):
    from src.permission.runtime.execution import ExecutionBlocked
    s = scenario
    source = TrustedSource(s.registry, s.policy)
    stamp = s.policy.stamp()
    s.policy.worker.cwe_mcp_deployment_path = s.deployment.parent / 'different-deployment'

    assert s.policy.stamp() != stamp
    with pytest.raises(ExecutionBlocked, match='policy-worker-mismatch'):
        source.current_signature()


@pytest.mark.asyncio
async def test_worker_policy_deployment_mismatch_prevents_registry_dispatch(scenario):
    from src.permission.runtime.execution import ExecutionBlocked
    s = scenario
    s.policy.worker.cwe_mcp_deployment_path = s.deployment.parent / 'different-deployment'
    used = s.policy.used
    with pytest.raises(ExecutionBlocked, match='policy-worker-mismatch'):
        await s.registry.execute(enrichment.GET_TOOL, {'id': 862}, None, s.prompter)
    assert not s.remote.calls and s.policy.used == used and s.policy.active == 0


@pytest.mark.asyncio
async def test_worker_path_change_during_initialize_closes_without_rpc(scenario, monkeypatch):
    from src.permission.runtime.execution import ExecutionBlocked
    s = scenario
    session = s.registry.get(enrichment.GET_TOOL)._session
    async def changed_open(*args, **kwargs):
        s.policy.worker.cwe_mcp_deployment_path = s.deployment.parent / 'different-deployment'
        return session
    monkeypatch.setattr(MCPSession, 'open', changed_open)
    with pytest.raises(ExecutionBlocked, match='receipt changed during initialization'):
        await s.registry.execute(enrichment.GET_TOOL, {'id': 862}, None, s.prompter)
    assert not s.remote.calls and s.remote.closed == 1 and s.policy.active == 0


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
