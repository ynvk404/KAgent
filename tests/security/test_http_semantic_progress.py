import httpx

from tests.helpers.agent_fakes import FakeClient, FakeSignal
from tests.helpers.direct_runtime import agent_runtime


async def test_http_coverage_deduplicates_content_and_preserves_new_sources(tmp_path, monkeypatch):
    rt = agent_runtime(tmp_path, 'http://127.0.0.1:43210', FakeClient([]))
    rt.agent.tools.get('http').workflow = rt.agent.workflow
    real = httpx.AsyncClient
    content = b'same fixture body'
    async def transport(request):
        return httpx.Response(200, headers={'content-type': 'text/plain'}, content=content, request=request)
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: real(transport=httpx.MockTransport(transport), **kw))
    assert rt.agent.workflow.objective is not None
    def sources():
        row = rt.agent.workflow.phase_coverage_record('recon', 'reachability')
        return list(row.source_fingerprints) if row else []
    first = None
    for index in range(6):
        await rt.agent.tools.execute('http', {'url': f'/?q={index}', 'phase': 'recon'}, FakeSignal(), rt.prompter)
        if first is None:
            first = sources()
            assert first
        assert sources() == first
    content = b'new reproducible response content'
    assert first is not None
    await rt.agent.tools.execute('http', {'url': '/?q=last', 'phase': 'recon'}, FakeSignal(), rt.prompter)
    assert set(sources()) > set(first)
    await rt.agent.save()
    assert rt.agent.store.load().workflow.to_dict() == rt.agent.workflow.to_dict()
