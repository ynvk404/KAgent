"""Real pinned-corpus acceptance check; isolated test config, no active config writes.

Run with venv-linux/bin/python -m scripts.check_cwe_mcp. No target HTTP is sent.
The only durable output is bounded acceptance metadata under artifacts/.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from mcp import ClientSession

from components.cwe_mcp.contract import EXPECTED_CORPUS, SEARCH_SCHEMA, GET_SCHEMA, LookupResponse
from src.config.config import MCPServerConfig
from src.engagement.state import EngagementState
from src.findings.cwe_enrichment import Enrichment, parse_response
from src.findings.store import Store, read_report
from src.permission.permission import Decision, YoloPrompter, UserControlledRefusal
from src.permission.runtime.execution import default_execution_policy
from src.permission.worker.worker import OfflineWorker
from src.skills.registry import Registry as Skills
from src.tools.common.registry import Registry
from src.tools.mcp import integration
from src.tools.workflow.finding import ConfirmFindingTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.ui.commands.result_review import review_result
from src.workflow.state import Candidate, ValidationResult, WorkflowState

CONFIG_ENTRY = {'name': 'cwe_catalog', 'command': '/usr/bin/python3',
                'args': ['-I', '-B', '/work/cwe-mcp-deployment/launch.py']}

class Operator:
    def __init__(self):
        self.decision = Decision.DENY
        self.requests = []
    async def ask(self, request, signal=None):
        self.requests.append(request.tool)
        return self.decision

async def connect(root, *, scope=None):
    engagement = EngagementState()
    if scope:
        engagement.add_origin(scope)
    policy = default_execution_policy(engagement, root)
    policy.worker = await OfflineWorker.available(root, policy.protected)
    if policy.worker is None:
        raise RuntimeError('BLOCKED: existing isolated worker unavailable')
    operator = Operator()
    prompter = YoloPrompter(operator, True)
    prompter.bind_execution_policy(policy)
    cfg = MCPServerConfig(**CONFIG_ENTRY)
    prepare_times, handshake_times = [], []
    real_prepare = policy.worker.prepare
    async def measured_prepare(*args, **kwargs):
        start = time.monotonic()
        try:
            return await real_prepare(*args, **kwargs)
        finally:
            prepare_times.append(time.monotonic() - start)
    policy.worker.prepare = measured_prepare
    real_initialize = ClientSession.initialize
    async def measured_initialize(self, *args, **kwargs):
        start = time.monotonic()
        try:
            return await real_initialize(self, *args, **kwargs)
        finally:
            handshake_times.append(time.monotonic() - start)
    ClientSession.initialize = measured_initialize
    try:
        start = time.monotonic()
        discovered = await integration.discover_mcp_tools(cfg, execution_policy=policy)
        elapsed = time.monotonic() - start
    finally:
        ClientSession.initialize = real_initialize
    registry = Registry()
    for tool in discovered['tools']:
        registry.register(tool)
    assert registry.names() == ['mcp_cwe_catalog_get_cwe', 'mcp_cwe_catalog_search_cwe']
    search_tool, get_tool = registry.get('mcp_cwe_catalog_search_cwe'), registry.get('mcp_cwe_catalog_get_cwe')
    assert search_tool is not None and get_tool is not None
    assert search_tool.schema() == SEARCH_SCHEMA
    assert get_tool.schema() == GET_SCHEMA
    metrics: dict[str, Any] = dict(cold_discovery_seconds=elapsed, worker_prepare_seconds=prepare_times[0],
                   initialization_seconds=handshake_times[0], initialization_budget_seconds=integration.HANDSHAKE_TIMEOUT_S)
    assert handshake_times[0] < integration.HANDSHAKE_TIMEOUT_S
    return registry, prompter, policy, operator, discovered['session'], metrics


def worker_pids(root):
    matching = set()
    for path in Path('/proc').glob('[0-9]*/cmdline'):
        try:
            raw = path.read_bytes()
            if b'--ro-bind' in raw and str(root).encode()+b'\x00' in raw:
                matching.add(int(path.parent.name))
        except (OSError, ValueError):
            continue
    return matching


async def assert_cleanup(root, baseline):
    for _ in range(40):
        if worker_pids(root) <= baseline:
            return
        await asyncio.sleep(0.05)
    raise AssertionError('isolated MCP child remained after invocation cleanup')


async def checks(root):
    registry, prompter, policy, operator, session, metrics = await connect(root)
    try:
        search = parse_response(await registry.execute('mcp_cwe_catalog_search_cwe',
            {'query': 'missing authorization', 'max_results': 5}, None, prompter), 'search')
        exact = parse_response(await registry.execute('mcp_cwe_catalog_get_cwe', {'id': 862}, None, prompter), 'get')
        assert search.corpus == exact.corpus == EXPECTED_CORPUS
        assert isinstance(exact, LookupResponse)
        assert exact.found and exact.candidate is not None
        assert exact.candidate.id == 862 and exact.candidate.mapping_usage == 'Allowed-with-Review'
        # No target/grant exists: the calls complete in the isolated namespace
        # without runtime acquisition, authorized HTTP, or research retrieval.
        assert not policy.engagement.http_permissions.grants
        assert not operator.requests
        used = policy.used
        prompter.set_yolo(False)
        try:
            await registry.execute('mcp_cwe_catalog_get_cwe', {'id': 863}, None, prompter)
        except UserControlledRefusal:
            pass
        else:
            raise AssertionError('normal permission denial did not prevent dispatch')
        assert policy.used == used and policy.active == 0
        prompter.set_yolo(True)
        # Verify protection/read-only mounts and network namespace directly with
        # the existing worker; no authority or mount rules are changed.
        diagnostic = ("import os,socket; from pathlib import Path; "
            "assert not list(Path('/work/.kagent').iterdir()); "
            "assert Path('/proc/net/route').read_text().count('\\n') <= 1; "
            "assert 'eth0' not in Path('/proc/net/dev').read_text(); "
            "assert not Path('/work/venv-linux/pyvenv.cfg').exists(); "
            "exec(\"try:\\n Path('/work/cwe-mcp-deployment/write-probe').write_text('no')\\n"
            "except OSError as e:\\n assert e.errno == 30\\nelse:\\n raise AssertionError('deployment writable')\"); "
            "print('isolation active')")
        command, argv = await policy.worker.prepare('/usr/bin/python3', ['-I', '-B', '-c', diagnostic])
        child = await asyncio.create_subprocess_exec(command, *argv, stdout=asyncio.subprocess.PIPE,
                                                     stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(child.communicate(), 10)
        assert child.returncode == 0, stderr.decode(errors='replace')
        assert stdout.strip() == b'isolation active'
        # Controlled host-side delivery stall AFTER a real server lookup tests
        # cancellation/timeout cleanup without changing the read-only server.
        original_call = ClientSession.call_tool
        entered = asyncio.Event()
        async def stalled_call(self, *args, **kwargs):
            result = await original_call(self, *args, **kwargs)
            entered.set()
            await asyncio.Future()
            return result
        ClientSession.call_tool = stalled_call
        baseline = worker_pids(root)
        try:
            task = asyncio.create_task(registry.execute('mcp_cwe_catalog_get_cwe', {'id': 862}, None, prompter))
            await asyncio.wait_for(entered.wait(), 50)
            task.cancel()
            try:
                await asyncio.wait_for(task, 10)
            except asyncio.CancelledError:
                pass
            else:
                raise AssertionError('cancel did not propagate')
            assert policy.active == 0
            await assert_cleanup(root, baseline)
            entered.clear()
            old_timeout = integration.MCP_CALL_TIMEOUT_S
            # Timeout includes the real call plus the deliberately held delivery.
            integration.MCP_CALL_TIMEOUT_S = 3.0
            try:
                await registry.execute('mcp_cwe_catalog_get_cwe', {'id': 862}, None, prompter)
            except TimeoutError:
                pass
            else:
                raise AssertionError('timeout did not propagate')
            finally:
                integration.MCP_CALL_TIMEOUT_S = old_timeout
            assert policy.active == 0
            await assert_cleanup(root, baseline)
        finally:
            ClientSession.call_tool = original_call
        metrics.update(real_registry_search=True, real_registry_get=True, corpus_verified=True,
            normal_permission_denial=True, no_http_grants=True, isolation_active=True,
            cancellation_cleanup=True, timeout_cleanup=True)
        return metrics
    finally:
        await session.close()


async def operator_flow(root):
    origin = 'http://127.0.0.1:65534'  # Synthetic state only: no target interaction.
    registry, prompter, policy, operator, session, metrics = await connect(root, scope=origin)
    try:
        state = WorkflowState()
        candidate, _ = state.add_candidate(Candidate(candidate_class='access-control', target=origin,
                                                     endpoint='/synthetic-resource', method='GET'))
        skills = Skills()
        skills.load_dir(Path(__file__).resolve().parents[1] / 'skills')
        workflow_tool = WorkflowTool(state, skills=skills, evidence_root=root)
        registry.register(workflow_tool)
        proof = root / 'synthetic-proof.txt'
        proof.write_text('Synthetic reproducible authorization bypass through user-controlled resource key. No HTTP traffic, tokens or credentials.')
        payload = json.loads(await registry.execute('workflow', {'action': 'record_evidence',
            'candidate_id': candidate.id, 'evidence_path': proof.name}, None, prompter))
        ref = payload['evidence']['id']
        state.add_validation_result(ValidationResult(candidate.id, 'access-control', 'confirmed',
                                                     evidence_refs=[ref], repeatable=True))
        async def save():
            (root / 'test-session.json').write_text(json.dumps(state.to_dict()))
        output = []
        agent = SimpleNamespace(workflow=state, tools=registry, prompter=prompter, skills=skills, save=save)
        app = SimpleNamespace(agent=agent, dispatch=output.append)
        operator.decision = Decision.ALLOW_ONCE
        await review_result(app, [candidate.id, 'confirmed', 'low', 'Synthetic authorization bypass through user-controlled key.'])
        assert output[-1].entry.kind == 'system', output[-1]
        store = Store(project_directory=root)
        notifications = []
        finding_tool = ConfirmFindingTool(store, lambda f, p: notifications.append(f), state)
        registry.register(finding_tool)
        await registry.execute('confirm_finding', dict(candidate_id=candidate.id, title='Authorization Bypass Through User-Controlled Key',
            severity='low', url=origin+'/synthetic-resource', observed_impact='Synthetic mechanism.',
            potential_impact='No additional impact assessed.'), None, prompter)
        path = store.report_for_candidate(candidate.id)
        assert read_report(path).cwe is None
        operator.requests.clear()
        selected = 0
        async def abstain(candidates):
            nonlocal selected
            selected += 1
            return None
        await Enrichment(agent, store, candidate.id).run(abstain, lambda *_: None)
        assert read_report(path).cwe is None and not operator.requests and selected == 1
        # YOLO retrieval still cannot bypass operator selection/fit review.
        operator.decision = Decision.DENY
        async def choose(candidates):
            assert candidates and all(c.mapping_usage == 'Allowed' for c in candidates)
            return next(i for i, c in enumerate(candidates, 1) if c.id == 639)
        await Enrichment(agent, store, candidate.id).run(choose, lambda *_: None)
        assert read_report(path).cwe is None and operator.requests == ['enrich_cwe_review']
        operator.decision = Decision.ALLOW_ONCE
        result = await Enrichment(agent, store, candidate.id).run(choose, lambda f, p: notifications.append(f))
        committed = read_report(path)
        assert committed.cwe and committed.classification_provenance is not None
        assert committed.classification_provenance['origin'] == 'promoted-external'
        assert notifications[-1] == committed
        retry = await registry.execute('confirm_finding', dict(candidate_id=candidate.id, title='Retry proposal',
            severity='low', url=origin+'/synthetic-resource', observed_impact='Synthetic mechanism.',
            potential_impact='No additional impact assessed.'), None, prompter)
        assert committed.cwe[0] in retry and read_report(path) == committed
        metrics.update(explicit_operator_flow=True, yolo_cannot_promote=True, persisted_retry=True,
                       promoted_cwe=committed.cwe[0], commit_message=result)
        return metrics
    finally:
        await session.close()


async def main():
    repository = Path(__file__).resolve().parents[1]
    deployment = repository / 'cwe-mcp-deployment'
    if not deployment.is_dir():
        raise RuntimeError('BLOCKED: run explicit pinned CWE setup first')
    report = {'repository_mount': await checks(repository)}
    with tempfile.TemporaryDirectory(prefix='kagent-cwe-acceptance-') as directory:
        root = Path(directory)
        # Copy regular files; no hardlinks/symlinks into the hidden host env.
        shutil.copytree(deployment, root / 'cwe-mcp-deployment')
        report['isolated_operator_flow'] = await operator_flow(root)
    destination = repository / 'artifacts/cwe-integration.json'
    destination.parent.mkdir(exist_ok=True)
    destination.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    asyncio.run(main())
