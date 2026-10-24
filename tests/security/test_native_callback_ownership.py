import asyncio
import json

import httpx
import pytest

from src.llm.core.types import ToolCall, FunctionCall
from src.tools.discovery.service import ServiceDiscoveryTool
from src.tools.discovery.content import ContentDiscoveryTool
from src.workflow.state import WorkflowObjective, WorkflowState
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from tests.helpers.direct_runtime import agent_runtime


@pytest.mark.parametrize('boundary', ['objective', 'objective_in_place', 'target', 'reset', 'resume', 'same_id_state', 'permission'])
@pytest.mark.parametrize('producer', ['service', 'content', 'http'])
@pytest.mark.parametrize('success', [False, True])
async def test_late_native_callback_does_not_credit_replacement(tmp_path, monkeypatch, boundary, producer, success):
    rt = agent_runtime(tmp_path, 'http://127.0.0.1:43210', FakeClient([]), enumeration=producer == 'content')
    entered, release = asyncio.Event(), asyncio.Event()

    async def hold():
        entered.set()
        await release.wait()

    if producer == 'service':
        tool = ServiceDiscoveryTool(rt.target, rt.state, workflow=rt.agent.workflow)
        async def dns(*args):
            return ['127.0.0.1'], None
        async def scan(*args):
            await hold()
            return [], 'success' if success else 'error', None if success else 'synthetic failure'
        monkeypatch.setattr(tool, '_resolve_execution_addresses', dns)
        monkeypatch.setattr(tool, '_scan_sockets', scan)
        rt.agent.tools.register(tool)
        pending = rt.agent.tools.execute('service_discovery', {}, FakeSignal(), rt.prompter)
    elif producer == 'content':
        tool = ContentDiscoveryTool(rt.target, rt.state, workflow=rt.agent.workflow)
        async def probe(client, url, *args):
            await hold()
            if not success:
                return None, 'timeout'
            return dict(url=url, status=404, content_length=7, body_hash='same', title=None), None
        async def no_delay(*args):
            return True
        monkeypatch.setattr(tool, '_probe', probe)
        monkeypatch.setattr('src.tools.discovery.content.sleep_or_abort', no_delay)
        rt.agent.tools.register(tool)
        pending = rt.agent.tools.execute('content_discovery', {'paths': ['fixture']}, FakeSignal(), rt.prompter)
    else:
        rt.agent.tools.get('http').workflow = rt.agent.workflow
        real = httpx.AsyncClient
        async def transport(request):
            await hold()
            if not success:
                raise httpx.ReadError('synthetic failure', request=request)
            return httpx.Response(200, headers={'content-type': 'text/html'}, content=b'<a href="/">fixture</a>', request=request)
        monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: real(transport=httpx.MockTransport(transport), **kw))
        call = ToolCall('held-http', FunctionCall('http', json.dumps({'url': '/', 'phase': 'recon'})))
        parsed = rt.agent.parse_tool_call(call)
        rt.agent._tool_call_event(call, parsed)
        pending = rt.agent.run_parsed_tool_call(call, parsed, FakeSignal())
    await rt.agent.save()
    task = asyncio.create_task(pending)
    await asyncio.wait_for(entered.wait(), 5)
    if boundary == 'reset':
        await rt.agent.reset()
        rt.agent.workflow.objective = WorkflowObjective('replacement', 'whole_target', rt.target.base_url())
    elif boundary == 'resume':
        rt.agent.resume_saved()
    elif boundary == 'target':
        await rt.agent.set_target_base_url('http://127.0.0.1:43211')
        rt.agent.workflow.objective = WorkflowObjective('replacement', 'whole_target', rt.target.base_url())
    elif boundary == 'objective':
        rt.agent.workflow.objective = WorkflowObjective('replacement', 'whole_target', rt.target.base_url())
    elif boundary == 'objective_in_place':
        assert rt.agent.workflow.objective is not None
        rt.agent.workflow.objective.id = 'replacement'
    elif boundary == 'same_id_state':
        rt.agent.workflow.replace_from(WorkflowState.from_dict(rt.agent.workflow.to_dict()))
    else:
        rt.policy.revision += 1
    if producer == 'content' and not rt.agent.workflow.is_next_phase('enumeration'):
        from tests.helpers.workflow import record_completed_phase
        objective = rt.agent.workflow.objective
        assert objective is not None
        record_completed_phase(rt.agent.workflow, 'recon', objective_id=objective.id,
            target_origin=rt.target.base_url(), artifact_ref='artifacts/recon/fixture/summary.md')
    facts = rt.agent.workflow.to_dict()
    coverage = rt.agent.workflow.to_dict()['phase_coverage']
    release.set()
    # Stale completion remains a terminal tool result, without attributing its
    # observations or coverage to the new objective.
    await asyncio.wait_for(task, 5)
    assert rt.agent.workflow.to_dict() == facts
    assert rt.agent.workflow.to_dict()['phase_coverage'] == coverage
    await rt.agent.save()
    restored = rt.agent.store.load().workflow
    assert restored.to_dict() == facts
    assert restored.to_dict()['phase_coverage'] == coverage
