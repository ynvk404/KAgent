"""Offline prompt/context regressions, not a measurement of LLM compliance.

The scripted answer deliberately stays untouched: accuracy is model guidance,
not a runtime prose validator. Historical lan-22 files are never loaded/written.
"""
from copy import deepcopy
import json
from pathlib import Path
import re
import sqlite3

import httpx
from httpx import AsyncClient
import pytest

from src.agent.system_prompt import BuildOptions, build_system_prompt, render_workflow
from src.agent.validation_guidance import render_validation_guidance
from src.llm.core.reasoning import ReasoningLevel
from src.llm.core.types import ChatResponse, Message
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry
from src.target.target import Target
from src.ui.core.outcomes import runtime_facts
from src.workflow.state import WorkflowMode, WorkflowObjective
from src.workflow.validation.route import ValidationRoute
from tests.agent.test_validation_continuation import candidate_for, offline  # noqa: F401
from tests.helpers.agent_fakes import FakeClient, FakeSignal, seed_compactable_history
from tests.helpers.burp_selection import ORIGIN
from tests.helpers.discovery_calls import execute
from tests.scenarios.offline_checkpoint import offline_checkpoint  # noqa: F401


ROOT = Path(__file__).resolve().parents[2]


def normalized(text):
    return ' '.join(text.replace('`', '').lower().split())


@pytest.mark.parametrize('profile', ['full', 'compact'])
def test_claim_checkpoint_reaches_both_prompt_profiles(profile):
    prompt = build_system_prompt(BuildOptions(Registry(), False, Target(ORIGIN), prompt_profile=profile))
    # Pin the policy delivered to the model, independently of Markdown wrapping.
    checkpoint = normalized(prompt).split('# factual accuracy', 1)[1].split('# ', 1)[0]
    for distinction in ('observed', 'documented', 'inferred', 'untested', 'unresolved',
                        'executed', 'intended', 'request metadata', 'response body',
                        'method', 'status', 'media type', 'counting unit',
                        'paths', 'operations', 'http requests', 'checkpoint', 'canonical'):
        assert distinction in checkpoint
    assert re.search(r'untested.{0,100}(?:absence|nonexistence)', checkpoint)
    assert re.search(r'(?:empty|no).{0,60}evidence_refs.{0,100}(?:not|never).{0,100}raw observations', checkpoint)


@pytest.mark.parametrize('profile', ['full', 'compact'])
def test_reporting_guidance_distinguishes_counts_and_inferred_context(profile):
    # Delivery contract only: this does not generate or validate an LLM report.
    prompt = build_system_prompt(BuildOptions(Registry(), False, Target(ORIGIN), prompt_profile=profile))
    checkpoint = normalized(prompt).split('# factual accuracy', 1)[1].split('# ', 1)[0]
    for rule in (
        r'candidate counts.{0,100}scoped workflow totals.{0,100}distinct ids',
        r'not input counts.{0,80}page lengths',
        r'counting unit.{0,40}exclusions',
        r'direct.{0,60}http calls.{0,100}native discovery requests.{0,80}calibration',
        r'owned validation requests.{0,80}phase annotations.{0,50}not.{0,50}ownership',
        r'truncated tool previews.{0,50}not complete execution records',
        r'retained results.{0,80}permitted readers.{0,100}omit unsupported numerical precision',
        r'never send http.{0,60}repair reporting',
        r'classifications.{0,60}redirects.{0,80}calibrated wildcard/spa',
        r'analyzed inputs.{0,70}not verified request schemas.{0,40}server consumption',
        r'response content-type.{0,40}not establish request content-type',
    ):
        assert re.search(rule, checkpoint), rule


@pytest.mark.parametrize('profile', ['full', 'compact'])
def test_reporting_guidance_requires_real_operator_context_and_severity_reasoning(profile):
    prompt = build_system_prompt(BuildOptions(Registry(), False, Target(ORIGIN), prompt_profile=profile))
    checkpoint = normalized(prompt).split('# factual accuracy', 1)[1].split('# ', 1)[0]
    for rule in (
        r'operator accounts, credentials and interactions.{0,80}actual session input.{0,40}bound exchanges',
        r'authorizations.{0,40}runtime authorization records',
        r'never invent.{0,100}accounts.{0,100}operator refusals',
        r'severity remains your judgment.{0,100}justify.{0,100}assessment.{0,50}proof',
        r'assessment criteria.{0,50}taxonomy.{0,80}demonstrated capabilities.{0,80}assumptions.{0,40}uncertainty',
        r'potential impact ceiling.{0,80}lab identity.{0,70}does not justify severity',
        r'unverified downstream impact conditional',
        r'no additional exploitation.{0,60}required solely.{0,60}severity label',
    ):
        assert re.search(rule, checkpoint), rule


@pytest.mark.parametrize('profile', ['full', 'compact'])
def test_empty_coding_session_does_not_pay_for_target_assessment_guidance(profile):
    prompt = build_system_prompt(BuildOptions(Registry(), False, None, prompt_profile=profile))
    assert '# Factual accuracy' not in prompt
    workflow = WorkflowObjective('offline', 'direct', ORIGIN)
    from src.workflow.state import WorkflowState
    resumed = build_system_prompt(BuildOptions(Registry(), False, None, prompt_profile=profile,
        workflow=WorkflowState(objective=workflow)))
    assert '# Factual accuracy' in resumed


async def test_loaded_sql_guidance_has_a_discriminating_decision_chain():
    registry = Registry()
    registry.load_dir(ROOT / 'skills')
    skill = normalized(await LoadSkillTool(registry).run({'name': 'sql-injection'}))
    chain = skill.split('observation → hypothesis → oracle → expected result → falsifier → next decision', 1)[1]
    example = chain.split('## runtime completion contract', 1)[0]
    for concept in ('competing', 'prefix', 'suffix', 'parenthes', 'new information',
                    'same prediction', 'known match', 'unexecuted', 'discriminating',
                    'remaining uncertainty', 'real stop reason'):
        assert concept in example
    login = skill.split('on an authentication endpoint', 1)[1].split('### 2b.', 1)[0]
    assert 'required repetitions' in login and 'single http request' in login
    assert 'do not replay' in login and 'separately authorized' in login
    finding = skill.split('when a login differential naturally returns', 1)[1].split('do not call', 1)[0]
    assert 'token issued' in finding and 'validity' in finding and 'unverified' in finding
    assert 'describe the demonstrated impact as obtained a valid administrative session' not in finding


@pytest.mark.parametrize('action', ['start_validation', 'resume_owned', 'finalize_owned'])
def test_transient_validation_hint_keeps_reasoning_and_finalization_separate(action):
    owned = action != 'start_validation'
    handoff = dict(next_action=action, candidate_id='cand_fixture',
        attempt_id='attempt_fixture' if owned else None, attempt_status='active' if owned else None,
        owned_active=owned, probing_stopped=action == 'finalize_owned',
        recovery=dict(status='none', rejections=0, rejection_limit=2, repair_turns=0, repair_turn_limit=3))
    hint = normalized(render_validation_guidance(handoff, ValidationRoute('expert', 'sql-injection'), frozenset()))
    if action == 'finalize_owned':
        assert 'probing has stopped' in hint
        assert 'next discriminating probe' not in hint
    else:
        assert 'observation → hypothesis → oracle → expected result → falsifier → next decision' in hint
        assert 'competing' in hint and 'same prediction' in hint


@pytest.mark.parametrize('mode', ['direct', 'whole_target'])
@pytest.mark.parametrize('stop', ['max_steps', 'workflow_blocked', 'final_response'])
async def test_synthesis_has_executed_sources_and_honest_status_guidance(offline, mode: WorkflowMode, stop):
    rt, sent = offline
    rt.workflow.objective = WorkflowObjective('lan22-fixture', mode, ORIGIN)
    rt.workflow.objective.add_requested_goal('sql-injection')
    cid = await candidate_for(rt, ready=mode == 'whole_target')
    await execute(rt, 'load_skill', {'name': 'sql-injection'})
    await execute(rt, 'workflow', {'action': 'start_validation', 'candidate_id': cid})
    for q in ('normal', 'fixture%20AND%201=1'):
        await execute(rt, 'http', {'url': '/fixture?q=' + q, 'phase': 'validation'})
    if stop != 'max_steps':
        await execute(rt, 'workflow', {'action': 'record_result', 'candidate_id': cid,
            'skill_name': 'sql-injection', 'outcome': 'insufficient-evidence',
            'deferred_reason': 'Only control and intended TRUE executed; oracle unresolved.'})
    before_sources = deepcopy(rt.policy.observations._items)
    answer = 'Scripted unverified prose remains unchanged.'
    client = FakeClient([ChatResponse(Message('assistant', answer), 'stop')])
    rt.agent.set_client(client)
    await rt.agent._whole_target_synthesis(rt.agent.history.copy(), FakeSignal(), lambda _: None,
        thinking_enabled=False, reasoning_level=ReasoningLevel.OFF,
        requested_reasoning_level=ReasoningLevel.OFF, stop_reason=stop,
        instruction='Report current bounded assessment.', max_steps=2)
    request = client.requests[-1]
    instructions = normalized(' '.join(m.content for m in request.messages if m.role == 'system'))
    assert 'executed' in instructions and 'intended' in instructions
    assert 'false request' in instructions and 'unexecuted' in instructions
    assert 'raw observations' in instructions and 'evidence_refs' in instructions
    result = rt.workflow.latest_result(cid)
    assert result and result.outcome == 'insufficient-evidence' and not result.evidence_refs
    projection = render_workflow(rt.workflow)
    assert 'candidate_status=deferred' in projection and 'attempt_status=unresolved' in projection
    assert 'finding_persisted=False' in projection and 'registered proof' in projection
    assert not rt.workflow.eligible_for_finding(cid) and not rt.workflow.persisted_findings
    assert rt.policy.observations._items == before_sources and len(sent) == 2
    assert request.tools is None
    if mode == 'whole_target':
        assert rt.agent.history[-1].content == answer
    else:
        # Existing Direct mode reports its typed incomplete-goal summary.
        assert 'incomplete/partial' in rt.agent.history[-1].content
        assert result.result_id in rt.agent.history[-1].content


async def test_compaction_gets_exact_goal_and_preserves_workflow_on_resume(offline):
    rt, _ = offline
    rt.workflow.objective = WorkflowObjective('lan22-fixture', 'whole_target', ORIGIN)
    rt.workflow.objective.add_requested_goal('sql-injection')
    before = rt.workflow.to_dict()
    seed_compactable_history(rt.agent)
    client = FakeClient([ChatResponse(Message('assistant',
        '## Current objective\n- SQL injection only.\n## Open TODOs\n- Preserve unresolved evidence.'), 'stop')])
    rt.agent.set_client(client)
    await rt.agent.compact_in_place(FakeSignal())
    prompt = client.requests[0].messages[0].content
    canonical = json.loads(prompt.split('Canonical objective from runtime (summary cannot replace it):\n', 1)[1])
    assert canonical['requested_goals'] == [{'class': 'sql-injection', 'status': 'pending'}]
    instructions = normalized(prompt)
    for concept in ('never add', 'whole_target', 'raw observations', 'registered proof',
                    'redacted', 'request bytes', 'hypotheses', 'unexecuted'):
        assert concept in instructions
    assert rt.workflow.to_dict() == before
    rt.agent.resume_saved()
    assert rt.agent.workflow.to_dict() == before


@pytest.mark.parametrize('reason', [None, '', '   ', 'Oracle unresolved.'])
async def test_tui_omits_empty_reason_without_changing_unresolved_outcome(offline, reason):
    rt, _ = offline
    cid = await candidate_for(rt)
    await execute(rt, 'load_skill', {'name': 'sql-injection'})
    await execute(rt, 'workflow', {'action': 'start_validation', 'candidate_id': cid})
    await execute(rt, 'workflow', {'action': 'record_result', 'candidate_id': cid,
        'skill_name': 'sql-injection', 'outcome': 'insufficient-evidence'})
    result = rt.workflow.latest_result(cid)
    assert result is not None
    result.deferred_reason = reason
    before = rt.workflow.to_dict()
    facts = runtime_facts(rt.agent, None, ())
    # Final blocker entries/counts now come from the same read-only Runtime
    # projection as termination, rather than a separate UI outcome projection.
    assert facts.blockers == rt.agent.whole_target_projection()[2]
    if reason and reason.strip():
        assert reason.strip() in '\n'.join(facts.blockers)
    else:
        assert 'Reason:' not in '\n'.join(facts.blockers)
    assert result.outcome == 'insufficient-evidence'
    assert rt.workflow.to_dict() == before and facts.incomplete == 1 and facts.validations == 0


def test_synthetic_parser_position_does_not_determine_outer_parentheses():
    # Two hypothetical queries produce the same parser position. Neither is a
    # reconstruction of the target's implementation.
    with sqlite3.connect(':memory:') as db:
        for template in ("SELECT 1 WHERE 'seed' LIKE '%{value}%'",
                         "SELECT 1 WHERE ('seed' LIKE '%{value}%')"):
            with pytest.raises(sqlite3.OperationalError, match=r'near "\)": syntax error'):
                db.execute(template.format(value="seed') AND '1'='1"))


def test_reference_pack_counters_and_search_predictions_are_consistent():
    pack = json.loads((ROOT / 'benchmarks/fixtures/lan22_accuracy.json').read_text())
    cases = {row['id']: row for row in pack['cases']}
    assert len(cases) == 8 and all(row['rubric'] and row['task'] for row in cases.values())
    counts = cases['counting-units']['context']
    assert counts['unique_discovery_paths'] + counts['wildcard_baseline_requests'] == counts['discovery_http_requests']
    assert counts['direct_http_tool_calls'] + counts['discovery_http_requests'] == counts['native_http_sources']
    assert cases['canonical-goal-and-checkpoint']['context']['requested_goals'] == ['sql-injection']
    login = cases['login-evidence']['context']
    assert login['owned_observations'] == len(login['statuses']) == 2
    assert not login['registered_proof_refs'] and login['persisted_findings'] == 0
    # These hypothetical SQLite templates illustrate why a generic equality
    # cannot be assumed TRUE after insertion into a wildcard search.
    with sqlite3.connect(':memory:') as db:
        query = "SELECT 1 WHERE 'apple' LIKE '%{value}%'"
        assert db.execute(query.format(value='apple')).fetchall() == [(1,)]
        assert db.execute(query.format(value="apple' AND '1'='1")).fetchall() == []
        assert db.execute(query.format(value="apple' AND '1'='2")).fetchall() == []
        assert db.execute(query.format(value="apple' AND '1' LIKE '1")).fetchall() == [(1,)]
        assert db.execute(query.format(value="apple' AND '1' LIKE '2")).fetchall() == []


async def test_http_response_and_controller_request_preview_stay_separate(offline, monkeypatch):
    rt, _ = offline
    # AsyncClient was imported before the fixture's patch. Both handlers are
    # pure MockTransport responses; neither constructs a network connection.
    body = '<html>Sequelize SQLite stack trace; no query text</html>'
    def respond(request):
        return httpx.Response(500, text=body, headers={'content-type': 'text/html'}, request=request)
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: AsyncClient(transport=httpx.MockTransport(respond), **kw))
    await execute(rt, 'load_skill', {'name': 'web-enumeration'})
    result = await execute(rt, 'http', {'url': '/fixture', 'method': 'GET', 'phase': 'recon',
        'headers': {'Content-Type': 'application/json'}})
    response, request = str(result.result).split('[End HTTP response; following text is request metadata]', 1)
    assert 'HTTP/1.1 500' in response and 'content-type: text/html' in response
    assert body in response and 'Effective request preview' not in response
    assert 'GET ' in request and 'application/json' in request
    observation = next(iter(rt.policy.observations._items.values()))
    assert observation.body.decode() == body and observation.method == 'GET' and observation.status == 500
