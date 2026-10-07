import asyncio
import hashlib
import json
import shutil
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from typing import Any

import pytest

from components.cwe_mcp.contract import (EXPECTED_CORPUS, EXPECTED_MANIFEST, GET_SCHEMA, SEARCH_SCHEMA,
                                        Candidate, SearchResponse)
from src.config.config import MCPServerConfig
from src.findings import cwe_enrichment as enrichment
from src.findings.cwe_enrichment import (Enrichment, TrustedSource, mechanism_query, parse_response,
                                        promotable, plain_data)
from src.findings.store import Store, read_report, report_bytes, Finding
from src.permission.permission import Decision, UserControlledRefusal
from src.tools.mcp.integration import MCPSession, MCPTool
from src.tools.workflow.finding import ConfirmFindingTool
from src.ui.commands.cwe_enrichment import enrich_cwe
from src.ui.commands.result_review import review_result
from src.workflow.review import review_snapshot, confirmation_binding
from tests.security.test_execution_policy import runtime, ORIGIN
from tests.security.test_operator_review import setup_review, command


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
    app, state, cand, _, ref, output = await setup_review(runtime, tmp_path)
    await review_result(app, command(cand))
    store = Store(project_directory=tmp_path)
    notifier = []
    finding_tool = ConfirmFindingTool(store, lambda finding, path: notifier.append((finding, path)), state)
    registry.register(finding_tool)
    await registry.execute('confirm_finding', dict(title='Missing authorization on resource', candidate_id=cand.id,
        severity='low', url=ORIGIN+'/fixture', observed_impact='Evidence-backed boundary failure.',
        potential_impact='No additional impact assessed.'), None, prompter)
    path = store.report_for_candidate(cand.id)
    assert read_report(path).cwe is None
    operator.requests.clear()
    output.clear()
    notifier.clear()
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
    app.prompt_text = AsyncMock(return_value='1')
    return SimpleNamespace(app=app, state=state, cand=cand, ref=ref, path=path, store=store,
        policy=policy, prompter=prompter, operator=operator, notifier=notifier, remote=remote,
        output=output, deployment=deployment, registry=registry)


@pytest.mark.asyncio
async def test_explicit_command_only_classification_and_retry_resume(scenario):
    s = scenario
    before = read_report(s.path)
    raw = report_bytes(s.path)
    result_snapshot = review_snapshot(s.state, s.cand.id)
    used = s.policy.used
    await enrich_cwe(s.app, [s.cand.id])
    assert s.output[-1].entry.kind == 'system', s.output[-1]
    after = read_report(s.path)
    assert after.cwe == ['CWE-862'] and after.classification_revision == 1
    assert after.classification_provenance is not None
    assert after.classification_provenance['origin'] == 'promoted-external'
    assert after.classification_provenance['operator_reviewed'] is True
    assert after.classification_provenance['corpus'] == enrichment.EXPECTED_CORPUS.model_dump()
    assert [x[0] for x in s.remote.calls] == ['search_cwe', 'get_cwe']
    assert s.policy.used > used and s.policy.active == 0
    assert [r.tool for r in s.operator.requests] == ['enrich_cwe_review']
    assert s.app.prompt_text.await_count == 1
    assert 'not confidence or proof' in s.app.prompt_text.call_args.args[0].question
    assert review_snapshot(s.state, s.cand.id) == result_snapshot
    for field in before.__dataclass_fields__:
        if field not in {'cwe', 'classification_provenance', 'classification_revision'}:
            assert getattr(after, field) == getattr(before, field)
    assert raw.split(b'## Observed impact', 1)[1] == report_bytes(s.path).split(b'## Observed impact', 1)[1]
    assert s.notifier[-1][0] == after
    retry = before
    retry.title = 'New proposed retry title'
    assert await Store(project_directory=s.store.project_dir).save(retry) == str(s.path)
    assert retry == after and retry.classification_provenance == after.classification_provenance
    # A fresh store restores promoted state on resume; no network or LLM calls.
    resumed = read_report(Store(project_directory=s.store.project_dir).report_for_candidate(s.cand.id))
    assert resumed == after and len(s.remote.calls) == 2
    await enrich_cwe(s.app, [s.cand.id])
    assert len(s.remote.calls) == 2 and s.app.prompt_text.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['verified-local', 'promoted-external', 'legacy'])
async def test_classified_reports_never_retrieve_or_replace(scenario, kind):
    s = scenario
    text = s.path.read_text().replace('- **URL:**', '- **CWE:** CWE-89\n- **URL:**', 1)
    if kind != 'legacy':
        text = text.replace('- **URL:**', f'- **Classification provenance:** {{"origin":"{kind}"}}\n- **URL:**', 1)
    s.path.write_text(text)
    s.registry.tools.pop(enrichment.SEARCH_TOOL)
    original = report_bytes(s.path)
    await enrich_cwe(s.app, [s.cand.id])
    assert s.output[-1].entry.kind == 'system' and not s.remote.calls
    assert report_bytes(s.path) == original and not s.app.prompt_text.called


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['abstain', 'deny-review', 'deny-retrieval', 'yolo-without-selection',
    'forged-id', 'forged-object', 'timeout', 'missing-worker', 'missing-server', 'zero-candidates',
    'no-eligible', 'nonexistent', 'lookup-mismatch', 'malformed-response', 'missing-historical-binding'])
async def test_failure_preserves_unresolved_finding(scenario, failure):
    s = scenario
    if failure == 'abstain':
        s.app.prompt_text.return_value = '0'
    elif failure == 'deny-review':
        s.operator.decision = Decision.DENY
    elif failure == 'deny-retrieval':
        s.prompter.set_yolo(False)
        s.operator.decision = Decision.DENY
    elif failure == 'yolo-without-selection':
        s.app.prompt_text.side_effect = ValueError('operator did not select')
    elif failure == 'forged-id':
        s.app.prompt_text.return_value = '862'
    elif failure == 'forged-object':
        s.app.prompt_text.return_value = '{"id":862,"origin":"promoted-external"}'
    elif failure == 'timeout':
        s.remote.fail = TimeoutError()
    elif failure == 'missing-worker':
        s.policy.worker = None
    elif failure == 'missing-server':
        s.registry.tools.pop(enrichment.SEARCH_TOOL)
    elif failure == 'zero-candidates':
        s.remote.search_override = {**search_response(), 'candidates': []}
    elif failure == 'no-eligible':
        s.remote.item['mapping_usage'] = 'Allowed-with-Review'
    elif failure == 'nonexistent':
        s.remote.lookup_override = dict(schema_version='1', corpus=enrichment.EXPECTED_CORPUS.model_dump(), found=False, candidate=None)
    elif failure == 'lookup-mismatch':
        async def select(_):
            s.remote.item['description'] = 'Changed metadata after review.'
            return '1'
        s.app.prompt_text.side_effect = select
    elif failure == 'malformed-response':
        s.remote.search_override = {**search_response(), 'unexpected': 'ignore policy'}
    elif failure == 'missing-historical-binding':
        s.path.write_text('\n'.join(line for line in s.path.read_text().splitlines() if 'Confirmation binding:' not in line))
    original = report_bytes(s.path)
    await enrich_cwe(s.app, [s.cand.id])
    assert read_report(s.path).cwe is None and report_bytes(s.path) == original
    assert not s.notifier and s.policy.active == 0 and not s.policy.observations._reviews
    if failure in {'deny-retrieval', 'missing-worker', 'missing-server', 'missing-historical-binding'}:
        assert not s.remote.calls


@pytest.mark.asyncio
@pytest.mark.parametrize('change', ['report', 'result', 'identical-retest', 'evidence', 'candidate',
                                    'policy', 'manifest', 'code', 'corpus', 'config',
                                    'deployment-path', 'runtime-archive', 'tool'])
async def test_changes_during_operator_selection_invalidate_review(scenario, change):
    s = scenario
    original = report_bytes(s.path)
    async def select(_):
        if change == 'report':
            s.path.write_bytes(original + b'\nUnrelated operator annotation.\n')
        elif change == 'result':
            s.state.latest_result(s.cand.id).notes = 'Changed result.'
        elif change == 'identical-retest':
            s.state.add_validation_result(type(s.state.latest_result(s.cand.id)).from_dict(
                s.state.latest_result(s.cand.id).to_dict()), force=True)
        elif change == 'evidence':
            path = s.policy.root / s.state.evidence[s.ref].path
            path.chmod(0o600)
            path.write_text('Changed proof.')
        elif change == 'candidate':
            s.cand.auth_context_ref = 'Changed principal'
        elif change == 'policy':
            s.policy.revoke('*')
        elif change == 'manifest':
            (s.deployment / 'manifest.json').write_text('{}')
        elif change == 'code':
            (s.deployment / 'launch.py').write_text('# changed audited code')
        elif change == 'corpus':
            (s.deployment / 'corpus/cwec_v4.20.xml').write_text('changed corpus')
        elif change == 'config':
            s.registry.get(enrichment.GET_TOOL)._server.args = ['bad']
        elif change == 'deployment-path':
            replacement = s.deployment.parent / 'identical-deployment'
            shutil.copytree(s.deployment, replacement)
            s.policy.cwe_mcp_deployment_path = replacement
        elif change == 'runtime-archive':
            (s.deployment / 'runtime.zip').write_bytes(b'changed prepared runtime')
        else:
            s.registry.tools.pop(enrichment.GET_TOOL)
        return '1'
    s.app.prompt_text.side_effect = select
    await enrich_cwe(s.app, [s.cand.id])
    assert s.output[-1].entry.kind == 'error' and read_report(s.path).cwe is None
    assert len(s.remote.calls) == 1 and not s.notifier and s.policy.active == 0


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


@pytest.mark.asyncio
async def test_overlapping_old_review_cannot_overwrite_new_promotion(scenario):
    s = scenario
    opened, release = asyncio.Event(), asyncio.Event()
    selections = 0
    async def select(_):
        nonlocal selections
        selections += 1
        if selections == 1:
            opened.set()
            await release.wait()
        return '1'
    s.app.prompt_text.side_effect = select
    first = asyncio.create_task(enrich_cwe(s.app, [s.cand.id]))
    await asyncio.wait_for(opened.wait(), 3)
    await enrich_cwe(s.app, [s.cand.id])
    committed = report_bytes(s.path)
    release.set()
    await first
    assert read_report(s.path).cwe == ['CWE-862'] and report_bytes(s.path) == committed
    assert len(s.notifier) == 1


@pytest.mark.asyncio
async def test_cancelled_mcp_and_dialog_cleanup(scenario):
    s = scenario
    s.remote.block = asyncio.Event()
    task = asyncio.create_task(enrich_cwe(s.app, [s.cand.id]))
    await asyncio.wait_for(s.remote.opened.wait(), 3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert s.remote.cleanup.is_set() and s.remote.closed == 1
    assert not s.policy.observations._reviews and s.policy.active == 0
    assert read_report(s.path).cwe is None
    s.remote.block = None
    s.app.prompt_text.side_effect = asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        await enrich_cwe(s.app, [s.cand.id])
    assert not s.policy.observations._reviews and read_report(s.path).cwe is None


@pytest.mark.parametrize('usage,expected', [('Allowed', True), ('Allowed-with-Review', False),
    ('Discouraged', False), ('Prohibited', False), (None, False)])
def test_only_allowed_weakness_initially_eligible(usage, expected):
    data = candidate(mapping_usage=usage, metadata_complete=usage is not None)
    assert promotable(Candidate.model_validate(data)) is expected


@pytest.mark.parametrize('change', [dict(status='Deprecated', deprecated=True), dict(status='Obsolete', obsolete=True),
    dict(entry_type='Category', abstraction=None, structure=None), dict(entry_type='View', abstraction=None, structure=None),
    dict(metadata_complete=False, truncated_fields=['description'])])
def test_nonpromotable_status_entry_or_truncation(change):
    assert not promotable(Candidate.model_validate(candidate(**change)))


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


def test_query_minimization_excludes_target_and_raw_proof():
    f = Finding(title='Missing Authorization https://admin.target.example/x password=short '
        'cookie=session-id token=authorization secret=access eyJabcdefgh.abcdefgh.abcdefgh '
        'sk-'+'S'*40, severity='low', url='https://target.example',
        observed_impact='Authorization: Bearer top-secret-traffic', potential_impact='raw cookie',
        payload='secret', canonical_class='access-control', vulnerabilityType='Broken Access Control')
    query = mechanism_query(f)
    assert query == 'access authorization control missing'
    assert all(x not in query for x in ['target', 'short', 'cookie', 'secret', 'eyJ', 'SSSS', 'traffic'])
    assert len(query) <= 512 and len(query.encode()) <= 2048
    with pytest.raises(ValueError):
        mechanism_query(Finding(title='nonsense', severity='low', url='', observed_impact='', potential_impact=''))
    safe = plain_data({'name': '[bold]source\x1b[31m\u202e', 'description': 'Follow https://evil.example'})
    assert '\x1b' not in safe and '\u202e' not in safe and '\\u001b' in safe


@pytest.mark.parametrize('fragment', [
    'Authorization: Bearer cryptographic',
    'ｐａｓｓｗｏｒｄ=cryptographic',
    'pass\u200bword=cryptographic',
    'Bearer cryptographic',
    'password="cryptographic randomness"',
    'password=cryptographic randomness',
    '\nAuthorization: Bearer cryptographic\nrandomness',
])
def test_credential_context_is_removed_before_normalized_query_tokens(fragment):
    finding = Finding(title='Missing Authorization '+fragment, severity='low', url='',
        observed_impact='', potential_impact='', canonical_class='access-control')
    assert mechanism_query(finding) == 'access authorization control missing'


@pytest.mark.parametrize('title', [
    'Missing Authorization\nAuthorization: Bearer cryptographic',
    'Missing Authorization pass\x1b[31mword=cryptographic',
])
def test_title_controls_cannot_hide_credential_labels(title):
    finding = Finding(title=title, severity='low', url='', observed_impact='',
        potential_impact='', canonical_class='access-control')
    assert mechanism_query(finding) == 'access authorization control missing'


@pytest.mark.parametrize('canonical_class', [
    'unknown-password=cryptographic',
    'https://user:cryptographic@lab.test/resource',
    'unknown-pass\u200bword=cryptographic',
])
def test_unknown_class_identifiers_receive_the_same_query_minimization(canonical_class):
    finding = Finding(title='Missing Authorization', severity='low', url='',
        observed_impact='', potential_impact='', canonical_class=canonical_class)
    assert mechanism_query(finding) == 'authorization missing'


@pytest.mark.asyncio
async def test_tui_shutdown_cancels_and_drains_promotion_before_commit(scenario, monkeypatch):
    import threading
    from src.findings import store as store_module
    from src.ui.commands.slash_handler import handle_slash
    from tests.ui.test_app import make_app

    s = scenario
    app = make_app()
    app.agent = s.app.agent
    app.prompt_text = s.app.prompt_text
    app.dispatch = s.app.dispatch
    before = report_bytes(s.path)
    entered, release = asyncio.Event(), threading.Event()
    loop = asyncio.get_running_loop()
    prepare = store_module._prepare_classification

    def stalled_prepare(path, raw):
        loop.call_soon_threadsafe(entered.set)
        if not release.wait(5):
            raise TimeoutError('test did not release preparation')
        return prepare(path, raw)

    monkeypatch.setattr(store_module, '_prepare_classification', stalled_prepare)
    assert handle_slash(app, '/enrich-cwe '+s.cand.id)
    await asyncio.wait_for(entered.wait(), 3)
    pending = next(t for t in asyncio.all_tasks() if getattr(t.get_coro(), '__name__', None) == 'enrich_cwe')
    shutdown = asyncio.create_task(app.on_unmount())
    try:
        # Give shutdown its cancellation boundary while preparation is held.
        await asyncio.sleep(0)
    finally:
        release.set()
        await asyncio.gather(shutdown, pending, return_exceptions=True)
    assert report_bytes(s.path) == before
    assert pending.cancelled()
    assert not s.notifier and s.policy.active == 0 and not s.policy.observations._reviews
    assert not list(s.path.parent.glob('.cwe-*.tmp'))


@pytest.mark.asyncio
@pytest.mark.parametrize('change', ['url', 'endpoint', 'method', 'parameter', 'duplicate-header'])
async def test_initial_report_candidate_binding_is_checked_before_retrieval(scenario, change):
    s = scenario
    raw = s.path.read_text()
    if change == 'url': raw = raw.replace(ORIGIN, 'http://other-origin.test')
    elif change == 'endpoint': raw = raw.replace('/fixture', '/wrong-path')
    elif change == 'method': raw = raw.replace('- **Method:** GET', '- **Method:** POST')
    elif change == 'parameter': raw = raw.replace('- **Parameter:** id', '- **Parameter:** user')
    else: raw = raw.replace('- **Severity:** low', '- **Severity:** low\n- **Severity:** high')
    s.path.write_text(raw)
    await enrich_cwe(s.app, [s.cand.id])
    assert s.output[-1].entry.kind == 'error' and not s.remote.calls and read_report(s.path).cwe is None


@pytest.mark.asyncio
async def test_notifier_failure_never_undoes_visible_promotion(scenario):
    s = scenario
    def broken(*_):
        raise RuntimeError('notifier unavailable')
    s.registry.get('confirm_finding').notifier = broken
    await enrich_cwe(s.app, [s.cand.id])
    assert s.output[-1].entry.kind == 'system' and read_report(s.path).cwe == ['CWE-862']


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
async def test_evidence_receipt_uses_existing_readonly_workflow_action(scenario, monkeypatch):
    s = scenario
    prepared = []
    original = s.policy.prepare
    def prepare(tool, args):
        if tool.name() == 'workflow':
            prepared.append(deepcopy(args))
            assert args['action'] == 'list'
        return original(tool, args)
    monkeypatch.setattr(s.policy, 'prepare', prepare)
    await enrich_cwe(s.app, [s.cand.id])
    assert prepared and s.output[-1].entry.kind == 'system' and s.policy.active == 0


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
async def test_model_cannot_reclassify_legacy_report_before_operator_command(scenario):
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


@pytest.mark.parametrize('title,expected', [
    ('Missing Authorization\x1b[31m\u202e', 'access authorization control missing'),
    ('Ａｕｔｈｏｒｉｚａｔｉｏｎ Bypass Through User-Controlled Key',
     'access authorization bypass control controlled key user'),
    ('😀' * 100000, 'access control'),
    ('authorization ' * 100000, 'access authorization control'),
    ('https://user:password@lab.test/cryptographic eyJabc.def.cryptographic', 'access control'),
])
def test_adversarial_query_keeps_bounded_mechanism_vocabulary(title, expected):
    finding = Finding(title=title, severity='low', url='', observed_impact='',
        potential_impact='', canonical_class='access-control')
    assert mechanism_query(finding) == expected


def test_old_review_cleanup_cannot_clear_new_pending_ticket():
    from src.permission.runtime.observations import ObservationStore
    observations = ObservationStore()
    older = observations.begin_review('cwe:cand_test')
    newer = observations.begin_review('cwe:cand_test')
    observations.finish_review('cwe:cand_test', older)
    assert not observations.review_is_current('cwe:cand_test', older)
    assert observations.review_is_current('cwe:cand_test', newer)


@pytest.mark.asyncio
@pytest.mark.parametrize('promoted', [False, True])
async def test_actual_session_resume_keeps_report_authoritative_without_retrieval(scenario, tmp_path, promoted):
    from src.session.store import Store as SessionStore
    s = scenario
    if promoted:
        await enrich_cwe(s.app, [s.cand.id])
        assert read_report(s.path).cwe == ['CWE-862']
    report = report_bytes(s.path)
    session = SessionStore.new_with_id(tmp_path / 'sessions', 'cwe-resume')
    await session.save([], workflow=s.state, engagement_state=s.policy.engagement)
    s.remote.calls.clear()
    loaded = session.load()
    assert review_snapshot(loaded.workflow, s.cand.id) == review_snapshot(s.state, s.cand.id)
    assert report_bytes(s.path) == report and not s.remote.calls
    if promoted:
        s.app.agent.workflow = loaded.workflow
        await enrich_cwe(s.app, [s.cand.id])
        assert report_bytes(s.path) == report and not s.remote.calls
