import asyncio
import json
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import httpx
import pytest

from src.browser.store import CaptureStore
from src.tools.common.browser_capture import register_browser_capture_tools
from src.tools.discovery.content import ContentDiscoveryTool
from src.tools.common.capabilities import CapabilityInventory
from src.permission.runtime.execution import ExecutionBlocked, default_execution_policy
from src.permission.permission import UserControlledRefusal, Decision, YoloPrompter
from src.engagement.state import EngagementState
from src.tools.common.registry import Registry
from src.tools.workflow.workflow_tool import WorkflowTool
from src.tools.workflow.finding import ConfirmFindingTool
from src.workflow.state import Candidate, WorkflowState
from src.coverage.store import CoverageStore
from src.findings.store import Store as FindingsStore
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.ui.commands.slash_handler import handle_slash
from src.findings.classification import classify
from tests.security.test_repair_runtime import lab, Operator, worker_for


@pytest.mark.asyncio
async def test_capture_scope_filter_get_clear_and_revoke(lab):
    registry, p, policy, operator, origin, _ = lab
    store = CaptureStore()
    store.ingest({'url': origin + '/in', 'id':'in', 'respBody':'LAB_CANARY'})
    store.ingest({'url':'http://outside.invalid/out', 'id':'out', 'respBody':'FAKE_OUTSIDE_CANARY'})
    store.ingest_snapshot({'url':'http://outside.invalid/', 'documentCookie':'FAKE_OUTSIDE_COOKIE'})
    register_browser_capture_tools(registry.register, store)
    result = await registry.execute('browser_capture_requests', {}, None, p)
    assert 'outside.invalid' not in result and '/in' in result
    with pytest.raises(ExecutionBlocked, match='capture-origin'):
        await registry.execute('browser_capture_get', {'id':'wr:out'}, None, p)
    assert 'FAKE_OUTSIDE_COOKIE' not in await registry.execute('browser_capture_snapshot', {}, None, p)
    await registry.execute('browser_capture_clear', {}, None, p)
    assert store.get_request('wr:out') is not None and store.get_request('wr:in') is None
    assert operator.calls == 0


@pytest.mark.asyncio
async def test_discovery_reader_obeys_policy_response_cap(lab):
    registry, p, policy, operator, origin, requests = lab
    from dataclasses import replace
    rights = policy.engagement.http_permissions
    grant = next(iter(rights.grants.values()))
    rights.grants[grant.origin] = replace(grant, limits=replace(grant.limits, response_bytes=4))
    tool = ContentDiscoveryTool(Target(origin), policy.engagement, CapabilityInventory(), lambda:'minimal')
    receipt = policy.prepare(tool, {'paths':['new'], 'backend':'native'})
    token = policy.start(receipt, tool, {'paths':['new'], 'backend':'native'}, None)
    try:
        async with httpx.AsyncClient(trust_env=False) as client:
            result = await tool._read_probe(client, origin + '/new?q=1%3D1', 10)
        assert result['body_truncated']
        item = next(iter(policy.observations._items.values()))
        assert len(item.body) == 4 and not item.complete
    finally:
        policy.stop(token)
    assert len(requests) == 1 and operator.calls == 0


@pytest.mark.asyncio
async def test_real_ffuf_runs_through_scoped_broker(lab):
    import shutil
    registry, p, policy, operator, origin, requests = lab
    await worker_for(policy)
    assert shutil.which('ffuf'), 'existing installed ffuf required for this acceptance'
    from tests.tools.test_discovery_tools import make_workflow
    workflow = make_workflow(phase='enumeration', origin=origin)
    registry.register(ContentDiscoveryTool(Target(origin), policy.engagement, CapabilityInventory(), lambda:'full', workflow))
    result = await registry.execute('content_discovery', {'paths':['new'], 'mode':'auto', 'max_requests':6, 'rate_limit':2}, None, p)
    assert '"backend": "ffuf"' in result or '"backend":"ffuf"' in result
    assert 'ffuf failed' not in result and len(requests) >= 3
    assert operator.calls == 0


CLASSES = ['sql-injection','cross-site-scripting','access-control','authentication','csrf','ssrf','ssti','xxe','path-traversal','command-injection','file-upload','nosql-injection','jwt-misconfiguration','cors-misconfiguration','open-redirect']


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', CLASSES)
async def test_operator_proof_review_separate_from_yolo_tool_approval(lab, tmp_path, kind):
    registry, p, policy, operator, origin, _ = lab
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(candidate_class=kind, target=origin, endpoint='/review', method='GET'))
    skills = SkillRegistry()
    coverage = CoverageStore(str(tmp_path / '.kagent/coverage.json'))
    registry.register(WorkflowTool(state, evidence_root=tmp_path, coverage=coverage))
    registry.register(ConfirmFindingTool(FindingsStore(project_directory=tmp_path), workflow=state))
    (tmp_path / 'proof.txt').write_text('Synthetic proof; human determines class semantics, not model labels.')
    ref = json.loads(await registry.execute('workflow', {'action':'record_evidence','candidate_id':candidate.id,'evidence_path':'proof.txt'}, None, p))['evidence']['id']
    finding_args = {
        'candidate_id': candidate.id, 'title': kind + ' review fixture',
        'severity': 'critical', 'url': origin + '/review',
        'observed_impact': 'MODEL CLAIM', 'potential_impact': 'No additional impact assessed.',
        'vulnerabilityType': 'FORGED TYPE', 'cwe': ['CWE-999999'], 'owasp': ['A99:2099'],
    }
    # Classification metadata never supplies proof or substitutes for review.
    with pytest.raises(Exception, match='not eligible'):
        await registry.execute('confirm_finding', finding_args, None, p)
    assert not state.finding_is_persisted(candidate.id) and operator.calls == 0
    output = []
    agent = SimpleNamespace(prompter=p, workflow=state, tools=registry, skills=skills, save=AsyncMock())
    app = SimpleNamespace(agent=agent, dispatch=output.append)
    operator.decision = Decision.ALLOW_ONCE
    assert handle_slash(cast(Any, app), f'/review-result {candidate.id} confirmed low Synthetic observed impact')
    for _ in range(50):
        if output:
            break
        await asyncio.sleep(.01)
    latest = state.latest_result(candidate.id)
    assert output and latest is not None and latest.outcome == 'confirmed', output
    result = policy.observations.result(candidate.id, (ref,), policy.engagement.http_permissions.epoch, candidate)
    assert result.verification_source == 'operator-reviewed'
    assert operator.calls == 1  # conclusion review even in YOLO, not a tool dialog
    assert (await coverage.list())[0].status == 'failed'
    found = await registry.execute('confirm_finding', finding_args, None, p)
    assert 'written to' in found and state.finding_is_persisted(candidate.id)
    assert operator.calls == 1
    classification = classify(kind)
    assert classification is not None
    reports = list((tmp_path / 'artifacts/findings').glob('*.md'))
    assert len(reports) == 1
    report = reports[0].read_text(encoding='utf-8')
    assert f'**Vulnerability Type:** {classification.type}' in report
    for label, values in (('CWE', classification.cwe), ('OWASP', classification.owasp)):
        if values:
            assert f'**{label}:** {", ".join(values)}' in report
        else:
            assert f'**{label}:**' not in report
    assert 'CWE-999999' not in report and 'A99:2099' not in report and 'FORGED TYPE' not in report
    assert 'MODEL CLAIM' not in report and 'Synthetic observed impact' in report
    # Retry through the same production gates preserves the original snapshot.
    await registry.execute('confirm_finding', {**finding_args, 'title': 'Retry renamed'}, None, p)
    assert reports[0].read_text(encoding='utf-8') == report
    assert len(list(reports[0].parent.glob('*.md'))) == 1 and operator.calls == 1


@pytest.mark.asyncio
async def test_exact_http_deny_does_not_deny_other_request_or_future_turn(lab):
    registry, p, policy, operator, origin, requests = lab
    from src.permission.runtime.invocations import review_turn
    with review_turn():
        p.set_yolo(False)
        with pytest.raises(UserControlledRefusal):
            await registry.execute('http', {'url':origin+'/one', 'phase':'recon'}, None, p)
        operator.decision = Decision.ALLOW_ONCE
        await registry.execute('http', {'url':origin+'/two', 'phase':'recon'}, None, p)
        p.set_yolo(True)
        with pytest.raises(UserControlledRefusal):
            await registry.execute('http', {'url':origin+'/one', 'phase':'validation'}, None, p)
    # OFF keeps its independent private-host gate: deny + exact approval +
    # first private-host approval. The declined ON retry opens no extra gate.
    assert len(requests) == 1 and operator.calls == 3
    await registry.execute('http', {'url':origin+'/one', 'phase':'validation'}, None, p)
    assert len(requests) == 2 and operator.calls == 3
