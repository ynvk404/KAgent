"""Offline lan-25 regressions: triage is not request discovery or validation.

Saved constant-expression responses are replayed by MockTransport, producing new
owned observations. No target, provider, old evidence ownership or secrets are used.
"""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
from httpx import AsyncClient
import pytest

from src.agent.decision_planner import build_whole_target_plan
from src.findings.store import Store as FindingStore
from src.skills.artifacts import completion_artifact_path
from src.tools.execution.shell import ShellTool, BashTool
from src.tools.workflow.finding import ConfirmFindingTool
from src.workflow.assessment import accepted_result, candidate_binding
from src.workflow.state import Candidate, WorkflowObjective, WorkflowState
from tests.agent.test_validation_continuation import (  # noqa: F401
    InspectModel, compact_with_misleading_summary, execute, offline, workflow,
)
from tests.helpers.burp_selection import make_runtime
from tests.helpers.workflow import record_phase_coverage_for_test
from tests.security.test_agent_assessment import ASSESSMENT


FIXTURE = json.loads((Path(__file__).parents[1] / 'fixtures/lan25-request-discovery.json').read_text())
STEP = 'Inspect the retained client login call site to identify its method, JSON field names and media type.'
REASON = 'The selected credential-query hypothesis has inferred request context; no POST was observed.'


async def call(rt, action, **args):
    output = await rt.registry.execute('workflow', {'action': action, **args}, None, rt.prompter)
    parsed = json.loads(output)
    assert parsed.get('ok'), output
    return parsed


async def prepare(rt, *, complete_analysis=True):
    """Real completion actions with explicitly skipped offline discovery coverage."""
    for phase, name in [('recon', 'recon'), ('enumeration', 'web-enumeration'),
                        ('input_analysis', 'web-input-analysis')]:
        skill = rt.skills.get(name)
        assert skill is not None and skill.completion_artifact
        path = rt.policy.root / completion_artifact_path(skill.completion_artifact, rt.target.base_url())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('Offline partial inventory: inferred requests are unverified; no live assessment.')
        if phase == 'input_analysis' and not complete_analysis:
            continue
        await record_phase_coverage_for_test(rt.workflow_tool, phase)
        await call(rt, 'complete_skill', skill_name=name,
                   no_inputs_discovered=phase == 'input_analysis')


async def hypothesis(rt, geometry=None, **changes):
    geometry = geometry or FIXTURE['inferred_inputs'][0]
    item = (await call(rt, 'record_input', **geometry))['input']
    args = {'candidate_class': 'sql-injection', 'input_id': item['id'],
            'signals': ['Inferred credential-query hypothesis; server consumption remains unverified.'],
            'status': 'deferred', 'deferred_reason': REASON, 'discovery_next_step': STEP, **changes}
    candidate = (await call(rt, 'record_candidate', **args))['candidate']
    await call(rt, 'set_input_disposition', input_id=item['id'], disposition='analyzed', analysis_complete=True,
               disposition_reason='Passive triage complete; inferred request remains a discovery hypothesis.')
    return item['id'], candidate['id']


def plan(rt):
    result = build_whole_target_plan(rt.skills.list_enabled(), rt.agent._planner_context())
    assert result is not None
    return result


@pytest.mark.parametrize('complete_analysis', [False, True])
async def test_selected_inferred_context_remains_actionable_after_analyzed_and_restore(offline, complete_analysis):
    rt, sent = offline
    await prepare(rt, complete_analysis=complete_analysis)
    rt.workflow.objective.add_requested_goal('sqli')
    iid, cid = await hypothesis(rt)
    candidate = rt.workflow.candidates[cid]
    assert rt.workflow.attack_surface_inputs[iid].disposition == 'analyzed'
    assert rt.agent._whole_target_state()[0] == 'actionable'
    assert f'candidate-discovery:{cid}' in rt.agent._whole_target_state()[1]
    assert plan(rt).candidate_id == cid and plan(rt).recommended_skill == 'web-input-analysis'
    assert rt.workflow.objective.requested_goals[0].status == 'in_progress'
    context = rt.agent._planner_context()
    assert next(c for c in context.candidates if c.id == cid).validation_ready is False
    assert rt.workflow_tool.validation_handoff(cid, rt.policy)['next_action'] == 'discover_request'
    view = rt.agent._workflow_request_view('Continue.', rt.registry.as_llm_tools())
    assert any('request-discovery step' in m.content for m in view.blocks)
    assert any('missing schema alone is not operator-only' in m.content for m in view.blocks)
    assert any('discovery_next_step (plan, not evidence)' in m.content for m in view.blocks)

    # Enrichment and a completed global analysis marker cannot erase the work.
    enriched = await call(rt, 'record_candidate', candidate_class='sqli', input_id=iid,
                          signals=['Additional planning note, not observed schema.'])
    assert enriched['candidate']['discovery_next_step'] == STEP
    restored = WorkflowState.from_dict(rt.workflow.to_dict())
    assert restored.candidate_discovery_pending(restored.candidates[cid])
    assert restored.candidates[cid].id == cid
    await rt.agent.save()
    assert rt.store.load().workflow.candidates[cid].discovery_next_step == STEP
    assert candidate_binding(candidate) == candidate_binding(replace(candidate, discovery_next_step=None))
    before = deepcopy(rt.workflow.to_dict())
    refused = await rt.registry.execute('workflow', {'action': 'start_validation', 'candidate_id': cid}, None, rt.prompter)
    assert 'error' in refused and rt.workflow.to_dict() == before and not sent
    assert not rt.workflow.eligible_for_finding(cid)


async def test_inferred_unselected_feedback_inputs_need_no_discovery_or_validation(offline):
    rt, sent = offline
    await prepare(rt, complete_analysis=False)
    for geometry in FIXTURE['inferred_inputs'][2:]:
        recorded = await call(rt, 'record_input', **geometry)
        iid = recorded['input']['id']
        assert recorded['provenance']['kind'] == 'unverified'
        await call(rt, 'set_input_disposition', input_id=iid, disposition='analyzed', analysis_complete=True,
                   disposition_reason='Passive triage: inferred body; no selected SQL hypothesis; operation untested.')
        details = await call(rt, 'get_input', input_id=iid)
        assert details['provenance']['kind'] == 'unverified'
    await call(rt, 'complete_skill', skill_name='web-input-analysis')
    assert rt.agent._whole_target_state()[0] == 'completed'
    assert not rt.workflow.candidates and not rt.workflow.attempts and not sent
    assert not rt.workflow.persisted_findings and not await rt.coverage.list()


async def test_discovery_outcome_updates_then_clears_work_without_promoting_provenance(offline, tmp_path):
    rt, sent = offline
    await prepare(rt)
    iid, cid = await hypothesis(rt)
    next_step = 'Test the inferred JSON login shape with synthetic values to distinguish media/field rejection.'

    def script():
        yield 'load_skill', {'name': 'web-input-analysis'}
        yield workflow('record_candidate', candidate_class='sqli', input_id=iid, status='deferred',
                       deferred_reason=REASON, discovery_next_step=next_step)
        yield 'http', {'url': '/rest/user/login', 'method': 'POST', 'phase': 'recon',
                      'headers': {'Content-Type': 'application/json'},
                      'body': '{"email":"synthetic@example.invalid","password":"synthetic-value"}',
                      'max_response_bytes': 1024}
        # The first request supplied no field-consumption evidence. Advance to
        # a different question instead of leaving the executed POST as a retry.
        yield workflow('record_candidate', candidate_class='sqli', input_id=iid, status='deferred',
                       deferred_reason='Generic JSON response did not establish the request contract.',
                       discovery_next_step='Inspect the root HTML for a login form and its method/field controls.')
        assert rt.workflow.candidates[cid].discovery_next_step != next_step
        yield 'http', {'url': '/', 'method': 'GET', 'phase': 'recon', 'max_response_bytes': 1024}
        yield 'file_write', {'path': str(tmp_path / 'request-review.md'), 'content':
            'Inferred POST JSON email/password. A synthetic request was submitted; '
            'the generic mock response does not verify field consumption or SQL behavior.'}
        yield workflow('record_candidate', candidate_class='sqli', input_id=iid, status='deferred',
                       deferred_reason='No further useful hypothesis from available sources; field consumption remains unverified.',
                       discovery_next_step=None)

    model = InspectModel(script())
    done = await execute(rt, model, steps=30)
    assert done.stop_reason == 'workflow_blocked' and done.agent_loop_llm_calls == 7
    assert model.consumed and len(sent) == 2 and len({str(r.url) for r in sent}) == 2
    assert any('not a generic "awaiting schema" reason' in ' '.join(m.content.split())
               for m in model.requests[1].messages if m.role == 'tool' and m.name == 'load_skill')
    assert rt.workflow.candidates[cid].discovery_next_step is None
    assert not rt.workflow.candidate_discovery_pending(rt.workflow.candidates[cid])
    assert not rt.workflow.attempts and not rt.workflow.validation_results
    assert (await call(rt, 'get_input', input_id=iid))['provenance']['kind'] == 'unverified'
    assert 'Inferred' in (tmp_path / 'request-review.md').read_text()
    assert rt.agent._whole_target_state()[0] == 'blocked'


async def test_resolution_must_explicitly_clear_step_before_queuing(offline):
    rt, sent = offline
    await prepare(rt)
    iid, cid = await hypothesis(rt)
    before = deepcopy(rt.workflow.to_dict())
    error = await rt.registry.execute('workflow', {'action': 'record_candidate', 'candidate_class': 'sqli',
        'input_id': iid, 'status': 'queued', 'deferred_reason': None}, None, rt.prompter)
    assert 'INVALID_DISCOVERY_HANDOFF' in error and rt.workflow.to_dict() == before
    await call(rt, 'record_candidate', candidate_class='sqli', input_id=iid, status='queued',
               deferred_reason=None, discovery_next_step=None)
    assert rt.workflow.candidates[cid].status == 'queued'
    assert rt.workflow_tool.validation_handoff(cid, rt.policy)['next_action'] == 'start_validation'
    assert plan(rt).recommended_skill == 'sql-injection' and not sent


@pytest.mark.parametrize('load_skill', [False, True])
async def test_executed_discovery_requires_reconciliation_across_compaction_and_resume(offline, tmp_path, load_skill):
    rt, sent = offline
    await prepare(rt)
    iid, cid = await hypothesis(rt)
    candidate = rt.workflow.candidates[cid]
    binding = candidate_binding(candidate)

    def script():
        if load_skill:
            yield 'load_skill', {'name': 'web-input-analysis'}
        yield workflow('list', candidate_id=cid)
        assert candidate.discovery_attempt_ref is None  # Bookkeeping is not investigation.
        yield 'http', {'url': '/', 'phase': 'recon', 'max_response_bytes': 1024}
        assert candidate.discovery_attempt_ref
        assert rt.workflow_tool.validation_handoff(cid, rt.policy)['next_action'] == 'reconcile_discovery'
        # Both ordinary enrichment and restating the old plan preserve the
        # runtime marker, so neither advertises the executed work as fresh.
        yield workflow('record_candidate', candidate_class='sqli', input_id=iid,
                       signals=['Returned generic source did not establish the request schema.'])
        yield workflow('record_candidate', candidate_class='sqli', input_id=iid,
                       status='deferred', deferred_reason=REASON, discovery_next_step=STEP)

    model = InspectModel(script())
    done = await execute(rt, model, steps=5 if load_skill else 4)
    assert model.consumed and done.stop_reason == 'max_steps' and len(sent) == 1
    attempt_ref = candidate.discovery_attempt_ref
    assert attempt_ref and candidate_binding(candidate) == binding
    assert 'reconcile its outcome' in plan(rt).guidance and 'Do not replay it' in plan(rt).guidance
    assert 'Choose a useful authorized investigation' not in plan(rt).guidance
    view = rt.agent._workflow_request_view('Continue.', rt.registry.as_llm_tools())
    assert any('investigated, not fresh work' in m.content for m in view.blocks)
    assert not rt.workflow.attempts and not rt.workflow.validation_results
    assert (await call(rt, 'get_input', input_id=iid))['provenance']['kind'] == 'unverified'
    await compact_with_misleading_summary(rt)
    await rt.agent.save()
    resumed = make_runtime(tmp_path, session_id=rt.store.id)
    resumed.agent.resume_saved()
    candidate = resumed.workflow.candidates[cid]
    assert candidate.discovery_attempt_ref == attempt_ref
    assert candidate.discovery_next_step == STEP and 'Do not replay it' in plan(resumed).guidance
    assert resumed.workflow_tool.validation_handoff(cid, resumed.policy)['next_action'] == 'reconcile_discovery'
    assert resumed.agent._whole_target_state()[0] == 'actionable'

    # The LLM selects a distinct question from the observed limitation.
    await call(resumed, 'record_candidate', candidate_class='sqli', input_id=iid,
               status='deferred', deferred_reason='Generic root response left fields unknown.',
               discovery_next_step='Review retained API documentation for the operation field contract.')
    assert candidate.discovery_attempt_ref is None
    assert resumed.workflow_tool.validation_handoff(cid, resumed.policy)['next_action'] == 'discover_request'
    await call(resumed, 'record_candidate', candidate_class='sqli', input_id=iid,
               status='deferred', deferred_reason='Available sources exhausted; request contract remains unknown.',
               discovery_next_step=None)
    assert candidate.discovery_next_step is None and candidate.discovery_attempt_ref is None
    assert resumed.agent._whole_target_state()[0] == 'blocked'


async def test_failed_investigation_does_not_attest_a_returned_result(offline, monkeypatch):
    rt, sent = offline
    await prepare(rt)
    _, cid = await hypothesis(rt)

    async def fail(*args, **kwargs):
        raise ValueError('Synthetic failure before execution')

    monkeypatch.setattr(rt.http, 'run', fail)

    def script():
        yield 'load_skill', {'name': 'web-input-analysis'}
        result = yield 'http', {'url': '/', 'phase': 'recon'}
        assert 'Synthetic failure' in result

    model = InspectModel(script())
    await execute(rt, model, steps=2)
    assert model.consumed and not sent
    assert rt.workflow.candidates[cid].discovery_attempt_ref is None
    assert rt.workflow_tool.validation_handoff(cid, rt.policy)['next_action'] == 'discover_request'


@pytest.mark.parametrize('tool_type', [ShellTool, BashTool])
async def test_completed_source_review_with_nonzero_exit_requires_reconciliation(offline, tool_type):
    rt, sent = offline
    await prepare(rt)
    _, cid = await hypothesis(rt)
    tool = tool_type()
    rt.registry.register(tool)

    def script():
        yield 'load_skill', {'name': 'web-input-analysis'}
        result = yield tool.name(), {'command': 'cat absent-request-contract.txt'}
        assert 'absent-request-contract.txt' in result

    model = InspectModel(script())
    await execute(rt, model, steps=2)
    assert model.consumed and not sent
    assert rt.workflow.candidates[cid].discovery_attempt_ref
    assert rt.workflow_tool.validation_handoff(cid, rt.policy)['next_action'] == 'reconcile_discovery'
    assert not rt.workflow.attempts and not rt.workflow.persisted_findings


async def test_discovery_result_only_marks_its_scheduled_candidate(offline):
    rt, sent = offline
    await prepare(rt)
    _, first = await hypothesis(rt, priority='high')
    _, sibling = await hypothesis(rt, FIXTURE['inferred_inputs'][1], priority='low')
    assert plan(rt).candidate_id == first

    def script():
        yield 'http', {'url': '/', 'phase': 'recon', 'max_response_bytes': 1024}

    model = InspectModel(script())
    await execute(rt, model, steps=1)
    assert model.consumed and len(sent) == 1
    assert rt.workflow.candidates[first].discovery_attempt_ref
    assert rt.workflow.candidates[sibling].discovery_attempt_ref is None
    assert rt.workflow.candidates[first].status == rt.workflow.candidates[sibling].status == 'deferred'
    assert not rt.workflow.attempts and not rt.workflow.persisted_findings


async def test_result_cannot_consume_a_replaced_discovery_plan(offline, monkeypatch):
    rt, sent = offline
    await prepare(rt)
    iid, cid = await hypothesis(rt)
    original = rt.http.run
    new_step = 'Inspect retained documentation to distinguish missing fields from an unsupported media type.'

    async def replace_while_running(*args, **kwargs):
        await call(rt, 'record_candidate', candidate_class='sqli', input_id=iid, status='deferred',
                   deferred_reason='The Agent selected a different request-context question.', discovery_next_step=new_step)
        return await original(*args, **kwargs)

    monkeypatch.setattr(rt.http, 'run', replace_while_running)

    def script():
        yield 'http', {'url': '/', 'phase': 'recon', 'max_response_bytes': 1024}

    model = InspectModel(script())
    await execute(rt, model, steps=1)
    assert model.consumed and len(sent) == 1
    assert rt.workflow.candidates[cid].discovery_next_step == new_step
    assert rt.workflow.candidates[cid].discovery_attempt_ref is None
    assert rt.workflow_tool.validation_handoff(cid, rt.policy)['next_action'] == 'discover_request'


@pytest.mark.parametrize('mode', ['whole_target', 'direct', 'none'])
async def test_explicit_null_without_discovery_is_an_optional_noop(offline, mode):
    rt, sent = offline
    if mode == 'none':
        rt.workflow.objective = None
    else:
        rt.workflow.objective.mode = mode
    args = dict(candidate_class='sqli', endpoint='/optional', method='GET', parameter='q', location='query')
    candidate = (await call(rt, 'record_candidate', **args))['candidate']
    repeated = (await call(rt, 'record_candidate', **args, discovery_next_step=None))['candidate']
    assert repeated == candidate
    restored = Candidate.from_dict({**candidate, 'discovery_next_step': None, 'discovery_attempt_ref': None})
    assert restored is not None and restored.to_dict() == candidate
    assert not sent


async def test_null_is_optional_in_assigned_validation_mode(offline):
    rt, sent = offline
    args = dict(candidate_class='sqli', endpoint='/assigned', method='GET', parameter='q', location='query')
    candidate = (await call(rt, 'record_candidate', **args))['candidate']
    rt.workflow.objective = WorkflowObjective('assigned-objective', 'candidate_validation',
        rt.target.base_url(), candidate_id=candidate['id'])
    repeated = (await call(rt, 'record_candidate', **args, discovery_next_step=None))['candidate']
    assert repeated == candidate and not sent


async def test_existing_deferral_without_step_stays_blocked_and_backward_compatible(offline):
    rt, sent = offline
    await prepare(rt)
    _, cid = await hypothesis(rt, discovery_next_step=None)
    original = rt.workflow.candidates[cid].to_dict()
    assert 'discovery_next_step' not in original
    restored = Candidate.from_dict(original)
    assert restored is not None and restored.to_dict() == original
    assert not rt.workflow.candidate_discovery_pending(restored)
    assert rt.agent._whole_target_state()[0] == 'blocked' and not sent


async def test_real_authentication_rejection_remains_blocked_not_rediscovered(offline, monkeypatch):
    rt, _ = offline
    await prepare(rt)
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(401, text='UnauthorizedError: No Authorization header was found', request=request)), **kw))
    geometry = {'endpoint': '/protected-operation', 'method': 'POST', 'parameter': 'value', 'location': 'json'}
    iid, cid = await hypothesis(rt, geometry, status='queued', deferred_reason=None, discovery_next_step=None)
    await call(rt, 'start_validation', candidate_id=cid)
    response = await rt.registry.execute('http', {'url': '/protected-operation', 'method': 'POST',
        'phase': 'validation', 'body': '{}', 'max_response_bytes': 1024}, None, rt.prompter)
    assert '401' in response
    await call(rt, 'record_result', candidate_id=cid, skill_name='sql-injection', outcome='blocked',
               deferred_reason='Observed missing-Authorization middleware rejection; protected handler access unavailable.')
    assert rt.workflow_tool.validation_handoff(cid, rt.policy)['next_action'] == 'resolve_dependency'
    # Optional null on ordinary assessed-candidate enrichment is also a no-op.
    await call(rt, 'record_candidate', candidate_class='sqli', input_id=iid, discovery_next_step=None)
    before = deepcopy(rt.workflow.to_dict())
    error = await rt.registry.execute('workflow', {'action': 'record_candidate', 'candidate_class': 'sqli',
        'input_id': iid, 'status': 'deferred', 'deferred_reason': 'Missing token',
        'discovery_next_step': STEP}, None, rt.prompter)
    assert 'error' in error and rt.workflow.to_dict() == before
    assert rt.agent._whole_target_state()[0] == 'blocked' and not rt.workflow.persisted_findings


@pytest.mark.parametrize('complete_analysis', [False, True])
async def test_lan25_search_confirms_and_persists_before_unresolved_discovery(offline, monkeypatch, tmp_path, complete_analysis):
    rt, sent = offline
    await prepare(rt, complete_analysis=complete_analysis)
    rows = FIXTURE['search']

    def respond(request):
        sent.append(request)
        q = request.url.params.get('q')
        row = next(r for r in rows if parse_qs(urlsplit(r['path_query']).query)['q'][0] == q)
        return httpx.Response(row['status'], json=row['body'], request=request)

    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: AsyncClient(transport=httpx.MockTransport(respond), **kw))
    item = (await call(rt, 'record_input', method='GET', endpoint='/rest/products/search', parameter='q', location='query'))['input']
    cid = (await call(rt, 'record_candidate', candidate_class='sqli', input_id=item['id'], priority='high',
                      signals=['Recorded lan-25 controlled expression hypothesis; offline replay only.']))['candidate']['id']
    await call(rt, 'set_input_disposition', input_id=item['id'], disposition='analyzed', analysis_complete=True)
    _, login = await hypothesis(rt)
    assert plan(rt).candidate_id == cid and plan(rt).recommended_skill == 'sql-injection'
    rt.registry.register(ConfirmFindingTool(FindingStore(project_directory=tmp_path), lambda *_: None, rt.workflow))
    oids = []

    def script():
        yield workflow('start_validation', candidate_id=cid)
        yield 'load_skill', {'name': 'sql-injection'}
        for row in rows:
            yield 'http', {'url': row['path_query'], 'phase': 'validation', 'max_response_bytes': 1024}
            oids.append(next(reversed(rt.policy.observations._items)))
        yield 'file_write', {'path': str(tmp_path / 'proof.md'), 'content':
            'Offline replay of lan-25 UNION constants and arithmetic: three complete responses contain the controlled row of 49s.'}
        evidence = json.loads((yield workflow('record_evidence', candidate_id=cid, evidence_path='proof.md', observation_ids=oids)))
        assert evidence['ok']
        result = json.loads((yield workflow('record_result', candidate_id=cid, skill_name='sql-injection', outcome='confirmed',
            evidence_refs=[evidence['evidence']['id']], observation_ids=oids, assessment=ASSESSMENT,
            mutation_performed=False, repeatable=True, techniques=['bounded UNION controlled evaluation'])))
        assert result['ok'] and plan(rt).candidate_id == cid and 'confirm_finding' in plan(rt).guidance
        yield 'confirm_finding', {'candidate_id': cid, 'title': 'Offline product-search SQLi replay',
            'url': rt.target.base_url() + '/rest/products/search', 'severity': 'low',
            'observed_impact': ASSESSMENT['observed_impact'], 'potential_impact': 'No live impact validation.'}

    model = InspectModel(script())
    done = await execute(rt, model, steps=9)
    assert done.stop_reason == 'max_steps' and model.consumed and len(sent) == 3
    result = rt.workflow.latest_result(cid)
    assert result is not None and accepted_result(rt.workflow, rt.workflow.candidates[cid], result, rt.policy)
    assert rt.workflow.finding_is_persisted(cid) and len(list((tmp_path / 'artifacts/findings').glob('*.md'))) == 1
    assert len(await rt.coverage.list()) == 1
    assert rt.workflow.candidate_discovery_pending(rt.workflow.candidates[login])
    assert rt.workflow.candidates[login].discovery_attempt_ref is None
    assert plan(rt).candidate_id == login and plan(rt).recommended_skill == 'web-input-analysis'
    assert rt.agent._whole_target_state()[0] == 'actionable'


def test_loaded_guidance_keeps_discovery_provenance_and_non_candidate_discretion():
    text = ' '.join((Path(__file__).parents[2] / 'skills/web-input-analysis/SKILL.md').read_text().split())
    for clause in ['Missing schema alone is not an operator dependency', 'not a generic "awaiting schema" reason',
                   'reconcile its outcome before another discovery request', 'inferred input you intentionally do not select',
                   'independently admitted Candidates proceed first', 'does not verify server consumption']:
        assert clause in text


def test_discovery_annotations_are_redacted_and_do_not_change_evidence_binding():
    token = 'secret-discovery-token-0123456789abcdef'
    candidate = Candidate('sqli', endpoint='/hypothesis', method='POST', status='deferred',
                          deferred_reason='Missing request contract',
                          discovery_next_step='Inspect retained call-site metadata; Authorization: Bearer ' + token)
    assert token not in json.dumps(candidate.to_dict())
    assert candidate_binding(candidate) == candidate_binding(replace(candidate, discovery_next_step=None))
