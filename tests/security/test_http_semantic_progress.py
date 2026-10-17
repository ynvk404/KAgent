import httpx

from src.agent.agent import WholeTargetStallTracker
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from tests.integration.test_scanner_agent_handoff import agent_runtime


async def test_real_response_content_counts_but_fresh_ids_and_query_values_do_not(tmp_path, monkeypatch):
    rt = agent_runtime(tmp_path, 'http://127.0.0.1:43210', FakeClient([]))
    rt.agent.tools.get('http').workflow = rt.agent.workflow
    real = httpx.AsyncClient
    content = b'same fixture body'
    async def transport(request):
        return httpx.Response(200, headers={'content-type': 'text/plain'}, content=content, request=request)
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: real(transport=httpx.MockTransport(transport), **kw))
    tracker = WholeTargetStallTracker()
    assert rt.agent.workflow.objective is not None
    tracker.set_scope(rt.agent.workflow.generation, rt.agent.workflow.objective.id)
    for index in range(6):
        before = rt.agent.workflow.progress_facts()
        await rt.agent.tools.execute('http', {'url': f'/?q={index}', 'phase': 'recon'}, FakeSignal(), rt.prompter)
        result = tracker.record_iteration(new_facts=rt.agent.workflow.progress_facts() - before, activity_fingerprints=[])
        assert result == ('structured_progress' if index == 0 else 'no_progress')
    assert tracker.consecutive_no_progress == 5
    content = b'new reproducible response content'
    before = rt.agent.workflow.progress_facts()
    await rt.agent.tools.execute('http', {'url': '/?q=last', 'phase': 'recon'}, FakeSignal(), rt.prompter)
    assert tracker.record_iteration(new_facts=rt.agent.workflow.progress_facts() - before, activity_fingerprints=[]) == 'structured_progress'
    assert tracker.consecutive_no_progress == 0
    await rt.agent.save()
    assert rt.agent.store.load().workflow.progress_facts() == rt.agent.workflow.progress_facts()
