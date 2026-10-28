"""Scripted Agent dispatch with synthetic HTTP transformations; no live services.

These authored decisions test guidance delivery, retained-response readback,
adaptation and existing evidence/outcome contracts. They do not measure whether
an unscripted LLM diagnoses syntax correctly or observe browser execution.
"""
from copy import deepcopy
import hashlib
from html import escape, unescape
import json
from urllib.parse import urlencode

import httpx
import pytest

from src.agent.agent import AgentRunOptions
from src.agent.events import MaxStepsError
from src.findings.store import Store as FindingStore
from src.tools.workflow.finding import ConfirmFindingTool
from src.workflow.assessment import accepted_result
from tests.helpers.agent_fakes import FakeSignal, ScriptedModel, collect
from tests.helpers.burp_selection import ORIGIN, ingest, make_runtime
from tests.security.test_execution_policy import runtime as assessment_runtime  # noqa: F401


@pytest.mark.parametrize(('path', 'placement'), [
    ('stop-invalid', 'inline'), ('adapt-script', 'inline'), ('adapt-handler', 'inline'),
    ('inert-adapt', 'inline'), ('inert-ruled-out', 'inline'),
    ('adapt-script', 'attribute'), ('adapt-script', 'comment'),
    ('adapt-script', 'style'), ('adapt-script', 'data-block'),
])
async def test_scripted_returned_code_review_adapts_or_records_honest_gap(
    tmp_path, monkeypatch, path, placement,
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('KAGENT_PROJECT_ROOT', str(tmp_path))
    requests = []
    real_client = httpx.AsyncClient
    template, boundary = {
        'inline': ("<script>const value='{input}';</script>", '</script>'),
        'attribute': ('<input value="{input}" data-tail="t">', '">'),
        'comment': ('<!--{input}-->', '-->'),
        'style': ('<style>p{color:{input}}</style>', '</style>'),
        'data-block': ('<script type="application/json">{"value":"{input}"}</script>', '</script>'),
    }[placement]

    def respond(request):
        requests.append(request)
        submitted = request.url.params['q']
        value = submitted.replace('\\', '\\\\').replace("'", "\\'")
        if path == 'inert-ruled-out':
            # This negative fixture also neutralizes the evidenced outer HTML
            # boundary. Quote escaping alone would leave that hypothesis open.
            value = value.replace('<', r'\u003C')
        heading = escape(submitted, quote=True).replace('&#x27;', '&apos;')
        body = ("<html><body><h1>" + heading + "</h1>"
                + template.replace('{input}', value) + "</body></html>")
        return httpx.Response(200, text=body, headers={'Content-Type': 'text/html'}, request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: real_client(
        transport=httpx.MockTransport(respond), **kwargs))
    runtime = make_runtime(tmp_path, session_id='returned-code-fixture')
    capture = ingest(runtime, 'returned-code', path='/fixture?q=control', status=200,
                     responseBody=template.replace('{input}', 'control'))
    runtime.agent.select_burp_captures()
    runtime.registry.register(ConfirmFindingTool(FindingStore(project_directory=tmp_path),
                                                lambda *_: None, runtime.workflow))
    inert = path.startswith('inert-')
    initial_probe = ("';document.title=731942;//" if inert
                     else boundary + "<script>document.title='synthetic-proof'</script>")
    structural = '</script><i data-probe=fixture></i>'
    adapted = (boundary + '<script>document.title=731942</script>' if path in {'adapt-script', 'inert-adapt'}
               else '</script><button onclick="document.title=731942">fixture</button>')
    outcome = {'stop-invalid': 'insufficient-evidence', 'adapt-script': 'confirmed',
               'adapt-handler': 'browser-required', 'inert-adapt': 'confirmed',
               'inert-ruled-out': 'not-confirmed'}[path]
    observations, bodies = [], []
    candidate = None

    def script():
        nonlocal candidate
        yield 'browser_capture_get', {'id': capture['id'],
                                     'baseline_request_ref': capture['baseline_request_ref']}
        loaded = yield 'load_skill', {'name': 'cross-site-scripting'}
        assert 'Actual returned bytes → Parser context → Effective code' in loaded
        candidate = json.loads((yield 'workflow', {
            'action': 'record_candidate', 'candidate_class': 'xss', 'endpoint': '/fixture',
            'method': 'GET', 'parameter': 'q', 'location': 'query',
            'test_case': 'reflected:input-to-' + placement,
            'source_ref': capture['id'], 'baseline_request_ref': capture['baseline_request_ref'],
        }))['candidate']['id']
        started_feedback = yield 'workflow', {'action': 'start_validation', 'candidate_id': candidate}
        assert started_feedback.startswith('{'), started_feedback
        started = json.loads(started_feedback)
        attempt = started['validation_context']['attempt_id']
        if inert:
            assert 'valid but inert code' in loaded
            assert 'continue the owned attempt without asking the user to repeat the same' in loaded
        values = ['control', initial_probe]
        if path == 'inert-ruled-out':
            values.append(structural)
        elif path != 'stop-invalid':
            values.append(adapted)
        for value in values:
            feedback = yield 'http', {'url': '/fixture?' + urlencode({'q': value}),
                                     'phase': 'validation', 'max_response_bytes': 4096}
            assert 'HTTP/1.1 200' in feedback, feedback
            oid = next(reversed(runtime.policy.observations._items))
            assert runtime.workflow.latest_result(candidate) is None
            readback = yield 'read_http_observation', {
                'observation_id': oid, 'start_char': 0, 'max_chars': 1000}
            assert '\n' in readback, readback
            metadata, body = readback.split('\n', 1)
            assert json.loads(metadata)['complete'] is True
            assert body == runtime.policy.observations._items[oid].body.decode()
            assert runtime.policy.observations._items[oid].attempt_id == attempt
            observations.append(oid)
            bodies.append(body)
            if value == initial_probe:
                if inert:
                    assert r"const value='\';document.title=731942;//';" in body
                else:
                    assert r"document.title=\'synthetic-proof\'" in body
                # The authored model preserves this failure and the same attempt;
                # it does not call confirmed or reinterpret escaped code as intact.
                assert not runtime.workflow.eligible_for_finding(candidate)
            elif value == adapted:
                assert 'document.title=731942' in body
                assert "\\'" not in body
            elif value == structural:
                assert r'\u003C/script>\u003Ci data-probe=fixture>\u003C/i>' in body
                assert body.count('<script>') == 1  # No new markup at either reflection.
        reason = {
            'stop-invalid': 'Invalid effective JS after escaping; operator baseline-plus-one-probe limit '
                            'is reached, so the supported alternate expression remains untested.',
            'adapt-script': 'Complete ordinary HTML response has an adapted valid inline marker; '
                            'no policy blocker in the fixture; browser execution was not observed.',
            'adapt-handler': 'Adapted handler has valid code but its click/branch was not observed; '
                             'necessary browser proof is unavailable.',
            'inert-adapt': 'The literal-escape probe remains string data; an independent HTML-context '
                           'hypothesis is resolved by the new captured inline marker. No browser execution observed.',
            'inert-ruled-out': 'The literal probe remains string data and the distinct outer HTML-boundary '
                              'probe returns JS-escaped less-than characters. The heading is HTML-encoded. '
                              'These observations resolve the supported boundaries of this captured sink; '
                              'no claim is made about other sinks or untested consumers.',
        }[path]
        proof = ('Raw retained observations:\n'
                 + '\n'.join(f'{oid}: {body}' for oid, body in zip(observations, bodies))
                 + '\nAnalysis (not a raw response): ' + reason)
        yield 'file_write', {'path': str(tmp_path / 'proof.md'), 'content': proof}
        evidence = json.loads((yield 'workflow', {'action': 'record_evidence',
            'candidate_id': candidate, 'evidence_path': 'proof.md',
            'observation_ids': observations}))['evidence']['id']
        result = json.loads((yield 'workflow', {
            'action': 'record_result', 'candidate_id': candidate, 'attempt_id': attempt,
            'skill_name': 'cross-site-scripting', 'outcome': outcome,
            'observation_ids': observations, 'evidence_refs': [evidence],
            'mutation_performed': False, 'cleanup_state': 'not-required',
            'cleanup_status': 'Synthetic stateless GET fixture; nothing persisted.',
            'notes': 'Retained failed variant: ' + bodies[1],
            'deferred_reason': reason if outcome != 'confirmed' else None,
            'assessment': {
                'hypothesis': 'Reflected input in ' + placement + ' can leave data and expose executable code.',
                'criteria': 'Review returned bytes, effective code, trigger and policy separately.',
                'limitations': 'Mock HTTP and scripted decisions; no browser or live model.',
                'observed_impact': reason, 'severity': 'low',
                'completed_attempt': outcome == 'not-confirmed',
            },
        }))
        assert result['ok']
        if outcome == 'confirmed':
            yield 'confirm_finding', {'candidate_id': candidate,
                'title': 'Synthetic returned-code assessment', 'url': ORIGIN + '/fixture',
                'severity': 'low', 'observed_impact': reason,
                'potential_impact': 'No deeper impact was tested.'}

    class InspectModel(ScriptedModel):
        def __init__(self):
            super().__init__(script(), prefix='returned-code')
            self.requests = []

        async def chat(self, request, signal=None):
            self.requests.append(deepcopy(request))
            return await super().chat(request, signal)

    model = InspectModel()
    runtime.agent.set_client(model)
    trace = collect()
    goal = 'Test the selected request for XSS.'
    if path == 'stop-invalid':
        goal += ' Limit HTTP testing to a baseline and one probe; finalize from captured evidence.'
    await runtime.agent.run(goal, FakeSignal(), trace['sink'],
                            AgentRunOptions(max_steps=16))
    assert model.consumed and not model.errors
    assert not [event for event in trace['events'] if event.type == 'error']
    assert [request.url.params['q'] for request in requests] == (
        ['control', initial_probe] if path == 'stop-invalid'
        else ['control', initial_probe, structural if path == 'inert-ruled-out' else adapted])
    assert len(runtime.workflow.attempts) == 1
    assert candidate is not None
    result = runtime.workflow.latest_result(candidate)
    assert result is not None and result.outcome == outcome
    adverse = r"const value='\';document.title=731942;//';" if inert else r"document.title=\'synthetic-proof\'"
    assert adverse in (result.notes or '')
    proof = (tmp_path / 'proof.md').read_text()
    assert '&apos;' in proof and 'Analysis (not a raw response):' in proof
    assert all(f'{oid}: {body}' in proof for oid, body in zip(observations, bodies))
    assert {entry['source']['id'] for entry in result.evidence_manifest} == set(observations)
    assert runtime.workflow.finding_is_persisted(candidate) is (outcome == 'confirmed')
    coverage = await runtime.coverage.list()
    assert len(coverage) == (1 if outcome in {'confirmed', 'not-confirmed'} else 0)
    if outcome == 'not-confirmed':
        assert coverage[0].status == 'passed'
    if outcome == 'confirmed':
        assert result.coverage_synced
        assert accepted_result(runtime.workflow, runtime.workflow.candidates[candidate], result, runtime.policy)
    # Check the input for the terminal decision, not merely an earlier load.
    # This normal-flow fixture does not compact history or measure LLM attention.
    result_index = next(index for index, (name, args) in enumerate(model.calls)
                        if name == 'workflow' and args.get('action') == 'record_result')
    decision_input = model.requests[result_index]
    playbooks = [message.content for message in decision_input.messages
                 if message.role == 'tool' and message.name == 'load_skill']
    assert len(playbooks) == 1
    guidance = ' '.join(playbooks[0].split())
    for rule in (
        'Actual returned bytes → Parser context → Effective code',
        '**Before ending validation**',
        'essential distinct hypothesis still supported by observations',
        'continue the owned attempt without asking the user to repeat the same goal',
        'matching unresolved or bounded negative outcome',
        'Raw response excerpts must preserve the retained observation representation',
        'Label any decoded/effective-code representation separately as analysis',
        'Once a boundary is actually crossed, rebuild the context model for the new unit',
        'do not carry the old delimiter requirement into the new context',
        'expected observation if true, expected observation if false',
    ):
        assert rule in guidance
    assert any(adverse in message.content for message in decision_input.messages
               if message.role == 'tool')


@pytest.mark.parametrize('stop', ['budget', 'permission', 'unresolved'])
async def test_essential_hypothesis_stays_unresolved_when_continuation_stops(tmp_path, monkeypatch, stop):
    """Exercise real resource/permission gates without new production outcome rules."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('KAGENT_PROJECT_ROOT', str(tmp_path))
    requests = []
    real_client = httpx.AsyncClient

    def respond(request):
        requests.append(request)
        value = request.url.params['q'].replace('\\', '\\\\').replace("'", "\\'")
        return httpx.Response(200, text="<script>const value='" + value + "';</script>",
                              headers={'Content-Type': 'text/html'}, request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: real_client(
        transport=httpx.MockTransport(respond), **kwargs))
    rt = make_runtime(tmp_path, session_id='hypothesis-stop-fixture')
    capture = ingest(rt, 'stop', path='/fixture?q=control', status=200,
                     responseBody="<script>const value='control';</script>")
    rt.agent.select_burp_captures()
    candidate = None

    def script():
        nonlocal candidate
        yield 'browser_capture_get', {'id': capture['id'],
                                     'baseline_request_ref': capture['baseline_request_ref']}
        yield 'load_skill', {'name': 'cross-site-scripting'}
        candidate = json.loads((yield 'workflow', {
            'action': 'record_candidate', 'candidate_class': 'xss', 'endpoint': '/fixture',
            'method': 'GET', 'parameter': 'q', 'location': 'query',
            'source_ref': capture['id'], 'baseline_request_ref': capture['baseline_request_ref'],
        }))['candidate']['id']
        started = json.loads((yield 'workflow', {'action': 'start_validation', 'candidate_id': candidate}))
        if stop == 'budget':
            model.runtime_stop = (6, started['validation_context']['attempt_id'])
        yield 'http', {'url': '/fixture?' + urlencode({'q': "';document.title=731942;//"}),
                      'phase': 'validation', 'max_response_bytes': 4096}
        oid = next(reversed(rt.policy.observations._items))
        feedback = yield 'read_http_observation', {'observation_id': oid, 'start_char': 0, 'max_chars': 1000}
        assert r"const value='\';document.title=731942;//';" in feedback
        if stop == 'budget':
            raise AssertionError('The native iteration limit must stop before another scripted action')
        if stop == 'permission':
            rt.policy.revoked.add('http')
            refusal = yield 'http', {'url': '/fixture?q=distinct-hypothesis', 'phase': 'validation'}
            assert 'revoked' in refusal.lower(), refusal
        outcome = 'authorization-required' if stop == 'permission' else 'insufficient-evidence'
        reason = ('HTTP capability revoked with an essential hypothesis still open.' if stop == 'permission'
                  else 'Current observations do not yet support a discriminating next request; interpretation unresolved.')
        result = json.loads((yield 'workflow', {'action': 'record_result', 'candidate_id': candidate,
            'skill_name': 'cross-site-scripting', 'outcome': outcome, 'deferred_reason': reason}))
        assert result['ok']

    model = ScriptedModel(script(), prefix='hypothesis-stop')
    rt.agent.set_client(model)
    trace = collect()
    await rt.agent.run('Test the selected request for XSS.', FakeSignal(), trace['sink'],
                       AgentRunOptions(max_steps=6 if stop == 'budget' else 10))
    assert model.consumed and not model.errors
    assert not [event for event in trace['events']
                if event.type == 'error' and not isinstance(event.err, MaxStepsError)]
    assert candidate is not None and len(requests) == 1
    result = rt.workflow.latest_result(candidate)
    assert result is not None
    assert result.outcome == ('authorization-required' if stop == 'permission' else 'insufficient-evidence')
    assert not rt.workflow.eligible_for_finding(candidate) and not await rt.coverage.list()
    assert not rt.workflow.persisted_findings
    if stop == 'budget':
        assert trace['events'][-1].stop_reason == 'max_steps'


@pytest.mark.parametrize('reconstructed', [False, True])
async def test_owned_raw_excerpt_hash_rejects_decoded_reconstruction(assessment_runtime, tmp_path,
                                                                  monkeypatch, reconstructed):
    """Existing optional excerpt bindings validate bytes, not free-form proof meaning."""
    from tests.security.test_agent_assessment import setup
    from tests.security.test_execution_policy import REAL_CLIENT

    raw = '<h1>marker&apos;</h1>'
    body = '<html><body>' + raw + '</body></html>'
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: REAL_CLIENT(
        transport=httpx.MockTransport(lambda request: httpx.Response(
            200, text=body, headers={'Content-Type': 'text/html'}, request=request)), **kwargs))
    state, candidate, _, args, oid = await setup(assessment_runtime, tmp_path)
    registry, prompter, policy, *_ = assessment_runtime
    source = policy.observations._items[oid]
    retained = source.body.decode()
    assert retained == body
    excerpt = retained[retained.index('<h1>'):retained.index('</h1>') + len('</h1>')]
    proof = 'Raw retained excerpt:\n' + excerpt + '\nDecoded analysis (not raw):\n' + unescape(excerpt)
    (tmp_path / 'fidelity.md').write_text(proof)
    registered = json.loads(await registry.execute('workflow', {'action': 'record_evidence',
        'candidate_id': candidate.id, 'evidence_path': 'fidelity.md', 'observation_ids': [oid]}, None, prompter))
    args['evidence_refs'] = [registered['evidence']['id']]
    start = source.body.index(raw.encode())
    args['assessment']['excerpts'] = [{'source_id': oid, 'start': start, 'end': start + len(raw.encode()),
        'sha256': hashlib.sha256((unescape(raw) if reconstructed else raw).encode()).hexdigest()}]
    args['outcome'] = 'not-confirmed'
    response = await registry.execute('workflow', args, None, prompter)
    if reconstructed:
        assert 'EXCERPT_MISMATCH' in response
        assert not state.validation_results
    else:
        assert json.loads(response)['ok']
        latest = state.latest_result(candidate.id)
        assert latest is not None and latest.evidence_manifest[0]['source']['body'] == source.body.hex()
        assert (tmp_path / registered['evidence']['path']).read_text() == proof
