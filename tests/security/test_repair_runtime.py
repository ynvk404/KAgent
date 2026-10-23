import asyncio
import json
import sys
import shutil
from decimal import Decimal
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest

from src.engagement.state import EngagementState
from src.permission.runtime.execution import default_execution_policy, ExecutionBlocked
from src.permission.permission import Decision, YoloPrompter
from src.tools.common.registry import Registry
from src.tools.execution.shell import ShellTool
from src.tools.execution.plugin import CommandPluginTool
from src.tools.http.http_tool import HTTPTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.skills.registry import Registry as SkillRegistry
from src.tools.workflow.finding import ConfirmFindingTool
from src.tools.mcp.integration import discover_mcp_tools
from src.config.config import PluginConfig, MCPServerConfig
from src.coverage.store import CoverageStore
from src.findings.store import Store as FindingsStore
from src.target.target import Target
from src.workflow.assessment import accepted_result
from tests.security.test_agent_assessment import ASSESSMENT
from src.workflow.state import Candidate, WorkflowObjective, WorkflowState
from tests.security.test_execution_policy import runtime, ORIGIN, REAL_CLIENT
from src.llm.runtime.validation_budget import ValidationBudget, ValidationBudgetExceeded, BudgetTransport


class Operator:
    def __init__(self, decision=Decision.DENY):
        self.calls = 0
        self.decision = decision

    async def ask(self, request, signal=None):
        self.calls += 1
        return self.decision


@pytest.fixture
def sqli_runtime(runtime, monkeypatch):
    """Native workflow dispatch with the same fixture bodies, without sockets."""
    registry, p, policy, operator, requests, _, _ = runtime

    def handler(request):
        requests.append(request)
        rows = [{'id': 'TEST_ONLY', 'name': 'fixture'}] if '1=1' in request.url.params.get('q', '') else []
        return httpx.Response(200, json={'data': rows}, request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: REAL_CLIENT(
        transport=httpx.MockTransport(handler), **kwargs))
    return registry, p, policy, operator, ORIGIN, requests


@pytest.fixture
async def lab(tmp_path):
    requests = []
    async def serve(reader, writer):
        head = await reader.readuntil(b'\r\n\r\n')
        requests.append(head)
        target = head.split(b' ')[1].decode()
        query = parse_qs(httpx.URL(target).query.decode())
        value = query.get('q', [''])[0]
        rows = [{'id': 'TEST_ONLY', 'name': 'fixture'}] if '1=1' in value else []
        data = json.dumps({'data': rows}).encode()
        writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(data)).encode() + b'\r\nConnection: close\r\n\r\n' + data)
        await writer.drain()
        writer.close()
    server = await asyncio.start_server(serve, '127.0.0.1', 0)
    origin = f'http://127.0.0.1:{server.sockets[0].getsockname()[1]}'
    state = EngagementState()
    state.initialize_target(origin)
    policy = default_execution_policy(state, tmp_path)
    operator = Operator()
    p = YoloPrompter(operator, True)
    p.bind_execution_policy(policy)
    registry = Registry()
    registry.register(HTTPTool(Target(origin), state))
    try:
        yield registry, p, policy, operator, origin, requests
    finally:
        server.close()
        await server.wait_closed()






MCP_SERVER = r'''
import json,sys,urllib.request
for line in sys.stdin:
    msg=json.loads(line); ident=msg.get('id'); method=msg.get('method')
    if ident is None: continue
    if method=='initialize':
        result={'protocolVersion':msg['params']['protocolVersion'],'capabilities':{'tools':{}},'serverInfo':{'name':'fixture','version':'1'}}
    elif method=='tools/list':
        result={'tools':[{'name':'fetch','description':'fixture','inputSchema':{'type':'object','properties':{'url':{'type':'string'}},'required':['url']}}]}
    elif method=='tools/call':
        try: text=urllib.request.urlopen(msg['params']['arguments']['url'],timeout=10).read().decode(); error=False
        except Exception: text='blocked fixture transport'; error=True
        result={'content':[{'type':'text','text':text}],'isError':error}
    else: result={}
    print(json.dumps({'jsonrpc':'2.0','id':ident,'result':result}),flush=True)
'''




@pytest.mark.asyncio
async def test_production_sqli_chain_and_protected_certificate_resume(sqli_runtime, tmp_path):
    registry, p, policy, operator, origin, requests = sqli_runtime
    journal = tmp_path / '.kagent/permissions/repair-session.json'
    policy.load_journal(journal)
    workflow = WorkflowState()
    candidate, _ = workflow.add_candidate(Candidate(candidate_class='sql-injection', target=origin, endpoint='/search', method='GET', parameter='q', location='query'))
    coverage = CoverageStore(str(tmp_path / '.kagent/coverage.json'))
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    registry.register(WorkflowTool(workflow, target=Target(origin), skills=skills, coverage=coverage, evidence_root=tmp_path, session_id="repair-session"))
    assert json.loads(await registry.execute('workflow', {'action':'start_validation','candidate_id':candidate.id}, None, p))['ok']
    registry.register(ConfirmFindingTool(FindingsStore(project_directory=tmp_path), workflow=workflow))
    for predicate in ['1=1', '1=2', '1=1', '1=2']:
        url = str(httpx.URL(origin + '/search', params={'q': f"fixture')) OR ({predicate})--"}))
        await registry.execute('http', {'url': url, 'phase': 'validation'}, None, p)
    ids = list(policy.observations._items)
    (tmp_path / 'proof.txt').write_text('Synthetic repeated SQL boolean observations; no sensitive data.')
    ref = json.loads(await registry.execute('workflow', {'action':'record_evidence', 'candidate_id':candidate.id, 'evidence_path':'proof.txt'}, None, p))['evidence']['id']
    result = json.loads(await registry.execute('workflow', {'action':'record_result', 'candidate_id':candidate.id, 'skill_name':'sql-injection', 'outcome':'confirmed', 'evidence_refs':[ref], 'observation_ids':ids, 'assessment':ASSESSMENT}, None, p))
    assert result['eligible_for_confirm_finding'] and (await coverage.list())[0].status == 'failed'
    found = await registry.execute('confirm_finding', {'candidate_id':candidate.id, 'title':'Synthetic boolean fixture', 'url':origin+'/search', 'severity':'critical', 'observed_impact':'MODEL OVERCLAIM', 'potential_impact':'No additional impact assessed.'}, None, p)
    assert 'written to' in found and workflow.finding_is_persisted(candidate.id)
    reports = list((tmp_path / 'artifacts/findings').glob('*.md'))
    assert len(reports) == 1
    assert 'MODEL OVERCLAIM' not in reports[0].read_text()
    restored = default_execution_policy(policy.engagement, tmp_path)
    restored.load_journal(journal)
    resumed = WorkflowState.from_dict(workflow.to_dict())
    assert accepted_result(resumed, resumed.candidates[candidate.id], resumed.latest_result(candidate.id), restored)
    assert not restored._receipts and restored.used == policy.used
    candidate.parameter = 'changed'
    assert not accepted_result(workflow, candidate, workflow.latest_result(candidate.id), restored)
    assert len(requests) == 4 and not operator.requests


@pytest.mark.asyncio
async def test_boolean_sqli_runtime_admits_sources_without_four_observation_semantic_gate(sqli_runtime, tmp_path):
    registry, p, policy, _, origin, requests = sqli_runtime
    state = WorkflowState(objective=WorkflowObjective(
        id='sqli-assessment', mode='whole_target', target_origin=origin,
    ))
    candidate, _ = state.add_candidate(Candidate(
        candidate_class='sql-injection', target=origin, endpoint='/search',
        method='GET', parameter='q', location='query',
        objective_id='sqli-assessment',
    ))
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    registry.register(WorkflowTool(state, target=Target(origin), skills=skills, evidence_root=tmp_path))
    from tests.helpers.workflow import prepare_validation_prerequisites
    tool = registry.get('workflow')
    assert isinstance(tool, WorkflowTool)
    await prepare_validation_prerequisites(tool, candidate.id)
    (tmp_path / 'proof.txt').write_text('Bounded SQL boolean proof; no sensitive data.')
    ref = json.loads(await registry.execute('workflow', {
        'action': 'record_evidence', 'candidate_id': candidate.id,
        'evidence_path': 'proof.txt',
    }, None, p))['evidence']['id']

    assert json.loads(await registry.execute('workflow', {'action':'start_validation','candidate_id':candidate.id}, None, p))['ok']
    async def probe(predicate):
        url = str(httpx.URL(origin + '/search', params={'q': f"fixture')) OR ({predicate})--"}))
        await registry.execute('http', {'url': url, 'phase': 'validation'}, None, p)

    for predicate in ('1=1', '1=2', '1=1'):
        await probe(predicate)
    args = {
        'action': 'record_result', 'candidate_id': candidate.id,
        'skill_name': 'sql-injection', 'outcome': 'confirmed',
        'techniques': ['boolean-based'], 'evidence_refs': [ref],
        'observation_ids': list(policy.observations._items), 'assessment':ASSESSMENT,
    }
    result = json.loads(await registry.execute('workflow', args, None, p))
    assert result['result']['outcome'] == 'confirmed'
    assert result['eligible_for_confirm_finding']
    assert candidate.status == 'validated' and len(requests) == 3
    assert not policy.observations._verifiers


@pytest.mark.asyncio
@pytest.mark.parametrize('technique', ['error-based', 'time-based'])
async def test_other_sqli_techniques_without_sources_reject_terminal(sqli_runtime, tmp_path, technique):
    registry, p, _, _, origin, _ = sqli_runtime
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(
        candidate_class='sql-injection', target=origin, endpoint='/search',
        method='GET', parameter='q', location='query',
    ))
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    registry.register(WorkflowTool(state, target=Target(origin), skills=skills, evidence_root=tmp_path))
    assert json.loads(await registry.execute('workflow', {
        'action': 'start_validation', 'candidate_id': candidate.id}, None, p))['ok']
    (tmp_path / 'proof.txt').write_text('Bounded unverified SQLi attempt.')
    ref = json.loads(await registry.execute('workflow', {
        'action': 'record_evidence', 'candidate_id': candidate.id,
        'evidence_path': 'proof.txt',
    }, None, p))['evidence']['id']
    result = await registry.execute('workflow', {
        'action': 'record_result', 'candidate_id': candidate.id,
        'skill_name': 'sql-injection', 'outcome': 'confirmed',
        'techniques': [technique], 'evidence_refs': [ref],
        'observation_ids': [],
    }, None, p)
    assert result.startswith('error:') and not state.validation_results
    assert candidate.status == 'validating'


def test_budget_persists_limits_and_never_resets_on_resume(tmp_path):
    path = tmp_path / 'budget.json'
    b = ValidationBudget(path, 'deepseek-flash')
    b.begin_session()
    request = httpx.Request('POST', 'https://api.deepseek.com/chat/completions', json={'model':'deepseek-flash'})
    for _ in range(5):
        row = b.reserve(request)
        b.settle(row, {'prompt_tokens':100, 'completion_tokens':100})
    with pytest.raises(ValidationBudgetExceeded, match='attempt limit'):
        b.reserve(request)
    restored = ValidationBudget(path, 'deepseek-flash')
    assert len(restored.state['attempts']) == 5 and restored.cost == b.cost
    restored.continue_after_trial()
    restored.begin_session(); restored.begin_session()
    with pytest.raises(ValidationBudgetExceeded, match='sessions'):
        restored.begin_session()
    for _ in range(55):
        row = restored.reserve(request)
        restored.settle(row, {'prompt_tokens':1, 'completion_tokens':1})
    with pytest.raises(ValidationBudgetExceeded, match='attempt limit'):
        restored.reserve(request)
    assert restored.cost < Decimal('1')


@pytest.mark.asyncio
async def test_budget_unknown_usage_and_concurrent_reservations_before_transport(tmp_path):
    b = ValidationBudget(tmp_path / 'budget.json', 'deepseek-flash')
    b.begin_session()
    entered = asyncio.Event()
    calls = []
    async def handle(request):
        calls.append(request)
        await entered.wait()
        return httpx.Response(200, json={'choices': []})
    transport = BudgetTransport(b, httpx.MockTransport(handle))
    request = httpx.Request('POST', 'https://api.deepseek.com/chat/completions', json={'model':'deepseek-flash'})
    tasks = [asyncio.create_task(transport.handle_async_request(request)) for _ in range(3)]
    await asyncio.sleep(.05)
    assert len(calls) == 2 and b.cost < Decimal('1')
    entered.set()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    assert isinstance(results[2], ValidationBudgetExceeded)
    with pytest.raises(ValidationBudgetExceeded, match='usage unavailable'):
        b.continue_after_trial()
    assert len(b.state['attempts']) == 2
