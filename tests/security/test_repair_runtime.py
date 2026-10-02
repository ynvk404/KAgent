import asyncio
import json
import sys
import shutil
from decimal import Decimal
from urllib.parse import parse_qs

import httpx
import pytest

from src.engagement.state import EngagementState
from src.permission.execution import default_execution_policy, ExecutionBlocked
from src.permission.permission import Decision, YoloPrompter
from src.permission.worker import OfflineWorker
from src.tools.registry import Registry
from src.tools.shell import ShellTool
from src.tools.plugin import CommandPluginTool
from src.tools.http import HTTPTool
from src.tools.workflow import WorkflowTool
from src.tools.finding import ConfirmFindingTool
from src.tools.mcp_integration import discover_mcp_tools
from src.config.config import PluginConfig, MCPServerConfig
from src.coverage.store import CoverageStore
from src.findings.store import Store as FindingsStore
from src.target.target import Target
from src.workflow.state import Candidate, WorkflowState
from src.llm.validation_budget import ValidationBudget, ValidationBudgetExceeded, BudgetTransport


class Operator:
    def __init__(self, decision=Decision.DENY):
        self.calls = 0
        self.decision = decision

    async def ask(self, request, signal=None):
        self.calls += 1
        return self.decision


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


async def worker_for(policy):
    if sys.platform != 'linux' or not shutil.which('bwrap'):
        pytest.skip('real worker requires installed Linux bubblewrap')
    worker = await OfflineWorker.available(policy.root, policy.protected)
    assert worker is not None
    policy.worker = worker
    return worker


@pytest.mark.asyncio
@pytest.mark.parametrize('group', ['shell', 'plugin'])
async def test_real_broker_valid_payload_and_outside_scope_no_dispatch(lab, group):
    registry, p, policy, operator, origin, requests = lab
    await worker_for(policy)
    if group == 'shell':
        registry.register(ShellTool())
        args = {'command': f'curl -fsS --max-time 10 "{origin}/new?q=1%3D1"'}
        result = await registry.execute(group, args, None, p)
        assert 'TEST_ONLY' in result
        result = await registry.execute(group, {'command': 'curl -sS --max-time 10 http://outside.invalid:6550/no'}, None, p)
    else:
        code = 'import json,sys,urllib.request; d=json.load(sys.stdin); print(urllib.request.urlopen(d["url"], timeout=10).read().decode())'
        registry.register(CommandPluginTool(PluginConfig(name=group, command='/usr/bin/python3', args=['-c', code])))
        result = await registry.execute(group, {'url': origin + '/new?q=1%3D1'}, None, p)
        assert 'TEST_ONLY' in result
        with pytest.raises(RuntimeError, match='403'):
            await registry.execute(group, {'url': 'http://outside.invalid:6550/no'}, None, p)
    assert len(requests) == 1 and operator.calls == 0
    policy.engagement.http_permissions.deny_session()
    if group == 'shell':
        result = await registry.execute(group, args, None, p)
        assert 'TEST_ONLY' not in result
    else:
        with pytest.raises(RuntimeError):
            await registry.execute(group, {'url': origin + '/new?q=1%3D1'}, None, p)
    assert len(requests) == 1


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
async def test_real_stdio_mcp_startup_and_scoped_call_yolo_on_off(lab):
    registry, p, policy, operator, origin, requests = lab
    await worker_for(policy)
    discovered = await discover_mcp_tools(MCPServerConfig(name='fixture', command='/usr/bin/python3', args=['-u', '-c', MCP_SERVER]), execution_policy=policy)
    try:
        tool = discovered['tools'][0]
        registry.register(tool)
        result = await registry.execute(tool.name(), {'url': origin + '/mcp?q=1%3D1'}, None, p)
        assert 'TEST_ONLY' in result and operator.calls == 0
        with pytest.raises(RuntimeError, match='blocked fixture'):
            await registry.execute(tool.name(), {'url': 'http://outside.invalid/'}, None, p)
        assert len(requests) == 1
        p.set_yolo(False)
        with pytest.raises(ExecutionBlocked.__bases__[0]):
            await registry.execute(tool.name(), {'url': origin + '/off'}, None, p)
        assert len(requests) == 1 and operator.calls == 1
    finally:
        await discovered['session'].close()


@pytest.mark.asyncio
async def test_production_sqli_chain_and_protected_certificate_resume(lab, tmp_path):
    registry, p, policy, operator, origin, requests = lab
    journal = tmp_path / '.kagent/permissions/repair-session.json'
    policy.load_journal(journal)
    workflow = WorkflowState()
    candidate, _ = workflow.add_candidate(Candidate(candidate_class='sql-injection', target=origin, endpoint='/search', method='GET', parameter='q', location='query'))
    coverage = CoverageStore(str(tmp_path / '.kagent/coverage.json'))
    registry.register(WorkflowTool(workflow, target=Target(origin), coverage=coverage, evidence_root=tmp_path))
    registry.register(ConfirmFindingTool(FindingsStore(project_directory=tmp_path), workflow=workflow))
    for predicate in ['1=1', '1=2', '1=1', '1=2']:
        url = str(httpx.URL(origin + '/search', params={'q': f"fixture')) OR ({predicate})--"}))
        await registry.execute('http', {'url': url, 'phase': 'validation'}, None, p)
    ids = list(policy.observations._items)
    (tmp_path / 'proof.txt').write_text('Synthetic repeated SQL boolean observations; no sensitive data.')
    ref = json.loads(await registry.execute('workflow', {'action':'record_evidence', 'candidate_id':candidate.id, 'evidence_path':'proof.txt'}, None, p))['evidence']['id']
    result = json.loads(await registry.execute('workflow', {'action':'record_result', 'candidate_id':candidate.id, 'skill_name':'sql-injection', 'outcome':'confirmed', 'evidence_refs':[ref], 'observation_ids':ids}, None, p))
    assert result['eligible_for_confirm_finding'] and (await coverage.list())[0].status == 'failed'
    found = await registry.execute('confirm_finding', {'candidate_id':candidate.id, 'title':'Synthetic boolean fixture', 'url':origin+'/search', 'severity':'critical', 'observed_impact':'MODEL OVERCLAIM', 'potential_impact':'No additional impact assessed.'}, None, p)
    assert 'written to' in found and workflow.finding_is_persisted(candidate.id)
    reports = list((tmp_path / 'artifacts/findings').glob('*.md'))
    assert len(reports) == 1
    assert 'MODEL OVERCLAIM' not in reports[0].read_text()
    restored = default_execution_policy(policy.engagement, tmp_path)
    restored.load_journal(journal)
    certificate = restored.observations.result(candidate.id, (ref,), 'new-resume-epoch', candidate)
    assert certificate is not None and certificate.verification_source.startswith('runtime:')
    assert not restored._receipts and restored.used == policy.used
    candidate.parameter = 'changed'
    assert restored.observations.result(candidate.id, (ref,), 'new-resume-epoch', candidate) is None
    assert len(requests) == 4 and operator.calls == 0


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
