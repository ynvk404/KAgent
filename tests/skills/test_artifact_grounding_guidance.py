"""Loaded guidance contracts, plus an offline inventory preservation check.

These assertions verify instructions delivered to the model, not model compliance
or a semantic classifier for artifacts, SQL statements or vulnerability outcomes.
"""
from copy import deepcopy
import json
from pathlib import Path
import re

import pytest

from src.agent.action_guidance import render_action_guidance
from src.agent.decision_planner import PlannerCandidate, PlannerContext
from src.agent.validation_guidance import render_validation_guidance
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry
from src.tools.workflow.action_view import ActionView
from src.workflow.validation.route import ValidationRoute
from tests.helpers.discovery_calls import attribution, execute
from tests.scenarios.offline_checkpoint import offline_checkpoint  # noqa: F401
from tests.skills.test_inline_openapi_guidance import SPEC, retained_initializer


@pytest.fixture
def skills():
    registry = Registry()
    registry.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    return registry


async def loaded(skills, name):
    return ' '.join((await LoadSkillTool(skills).run({'name': name})).replace('`', '').lower().split())


@pytest.mark.parametrize('name', ['recon', 'web-enumeration', 'web-input-analysis', 'sql-injection'])
async def test_artifact_write_has_a_local_claim_to_source_checkpoint(skills, name):
    text = await loaded(skills, name)
    checkpoint = re.search(r'before file_write(.{0,900})', text)
    assert checkpoint, 'Ground claims at the write, not only at later result admission'
    # These are the dimensions to reconcile, not an exact paragraph or wrapping.
    for dimension in (r'source|reference', r'method', r'endpoint|url', r'status',
                      r'response (?:media type|content-type)', r'body marker|excerpt',
                      r'capture flags|completeness.*truncation', r'confidence|certainty'):
        assert re.search(dimension, checkpoint[1]), f'{name}: missing write checkpoint dimension {dimension}'


async def test_inventory_secret_omission_cannot_remove_evidenced_field_names(skills):
    text = await loaded(skills, 'web-enumeration')
    early = text.split('large responses:', 1)[0]
    assert not re.search(r'omit passwords\s*,\s*tokens\s*,\s*cookies', early)
    assert re.search(r'(?:retain|keep).{0,70}field names.{0,100}(?:redact|omit).{0,50}(?:secret )?values', early)


async def test_retention_read_range_and_current_context_are_separate(skills):
    text = await loaded(skills, 'web-enumeration')
    assert re.search(r'content-length.{0,100}(?:not|never).{0,90}(?:read|inspect)', text)
    assert re.search(r'retained.{0,80}completeness.{0,120}(?:range|portion).{0,140}context', text)
    assert re.search(r'(?:metadata-only|status 200).{0,180}(?:not|never).{0,100}(?:calibrat|spa|body)', text)
    assert re.search(r'(?:observations?|documents?).{0,100}(?:prevail|override|take precedence).{0,100}(?:llm|summar)', text)


async def test_documented_triage_does_not_require_reaching_an_auth_gate(skills):
    text = await loaded(skills, 'web-input-analysis')
    assert re.search(r'(?:bearer|security).{0,100}declaration.{0,140}(?:not|never).{0,110}(?:blocked|prerequisite)', text)
    assert re.search(r'passive triage.{0,100}(?:analyzed|suffic)', text)


async def test_sql_plan_is_falsifiable_and_empty_results_do_not_explain_evaluation(skills):
    text = await loaded(skills, 'sql-injection')
    planning = text.split('runtime completion contract', 1)[0]
    assert re.search(r'before (?:each )?(?:http|probe).{0,170}hypothesis.{0,230}(?:falsif|contradict|abandon)', planning)
    assert re.search(r'data:\[\].{0,160}(?:not|neither).{0,170}literal.{0,130}evaluat', text)
    pair = text.split('2a. boolean-based', 1)[1].split('2b. time-based', 1)[0]
    assert re.search(r'(?:do not|need not).{0,60}(?:send|execute|force).{0,60}false.{0,150}compatibility', pair)
    assert re.search(r'pair.{0,65}(?:not executed|unexecuted|not performed)', pair)


async def test_sql_adjustments_start_at_first_signal_and_use_executed_shapes(skills):
    text = await loaded(skills, 'sql-injection')
    syntax = text.split('1b. syntax-sensitivity', 1)[1].split('detecting second-order', 1)[0]
    assert re.search(r'three after the initial signal.{0,180}input analysis', syntax)
    assert re.search(r'first confirmation.{0,100}(?:counts|consumes)', syntax)
    assert re.search(r'(?:phase|recaptur).{0,170}(?:not|never).{0,65}reset', syntax)
    assert re.search(r'executed requests.{0,180}proposal.values', syntax)
    assert re.search(r'benign control.{0,120}predicate flip.{0,120}repetition.{0,160}(?:not|excluded)', syntax)
    assert re.search(r'all techniques.{0,80}(?:share|same).{0,70}allowance', syntax)
    assert re.search(r'benign control.{0,80}cannot exempt.{0,70}syntax.shape change', syntax)


async def test_sql_control_capture_and_replay_reference_are_separate(skills):
    text = await loaded(skills, 'sql-injection')
    baseline = text.split('1a. establish a clean baseline', 1)[1].split('1b.', 1)[0]
    assert re.search(r'baseline capture.{0,100}(?:not|different|distinct).{0,90}baseline_request_ref', baseline)
    assert re.search(r'(?:not|never).{0,60}(?:invent|create|derive).{0,50}replay.{0,80}observation id', baseline)
    assert re.search(r'(?:necessary|needed).{0,90}control.{0,160}(?:active|owned) attempt', baseline)
    assert re.search(r'missing validation step.{0,200}(?:manifest|retriev)', baseline)


async def test_sql_write_checkpoint_reconciles_allowance_labels_and_status_layers(skills):
    text = await loaded(skills, 'sql-injection')
    checkpoint = text.split('before writing proof and calling', 1)[1].split('standard result entry template', 1)[0]
    assert re.search(r'(?:allowance|adjustment).{0,160}(?:used|remaining).{0,160}exhausted', checkpoint)
    assert re.search(r'intended.{0,100}(?:not|never).{0,100}(?:control|positive)', checkpoint)
    for layer in ('candidate status', 'validationresult outcome', 'goal status', 'finding eligibility'):
        assert layer in checkpoint
    assert re.search(r'phase 3.{0,200}sqli-2.{0,140}(?:not-confirmed|insufficient-evidence)', checkpoint)
    assert re.search(r'partial.{0,80}(?:catalog|product).{0,90}(?:not|never).{0,60}full catalog', text)


@pytest.mark.parametrize('action', ['start_validation', 'resume_owned', 'finalize_owned'])
def test_sql_continuation_delivers_planning_or_local_closure(action):
    owned = action != 'start_validation'
    handoff = {'next_action': action, 'candidate_id': 'can_fixture',
               'attempt_id': 'attempt_fixture' if owned else None,
               'attempt_status': 'active' if owned else None, 'owned_active': owned,
               'probing_stopped': action == 'finalize_owned',
               'recovery': {'status': 'none', 'rejections': 0, 'rejection_limit': 2,
                            'repair_turns': 0, 'repair_turn_limit': 3}}
    text = render_validation_guidance(handoff, ValidationRoute('expert', 'sql-injection'), frozenset()).lower()
    if action == 'finalize_owned':
        assert 'local finalization' in text and 'probing has stopped' in text
        assert re.search(r'(?:used|remaining).{0,100}(?:allowance|adjustment)', text)
        assert 'candidate status' in text and 'validationresult outcome' in text
        assert 'capture a necessary' not in text
    else:
        assert re.search(r'(?:select|choose).{0,140}technique.{0,170}oracle', text)
        assert re.search(r'control.{0,160}(?:active|owned) attempt', text)
        assert re.search(r'full query.{0,100}(?:not required|unnecessary)', text)
        assert re.search(r'(?:falsif|discriminating)', text)
        assert re.search(r'boolean[^.\n]*confirmation[^.\n]*(?:only|conditional)', text)


@pytest.mark.parametrize('completed', [frozenset({'recon'}), frozenset({'recon', 'enumeration'})])
def test_discovery_hints_only_read_missing_context(completed):
    context = PlannerContext(objective_mode='whole_target', completed_phases=completed)
    text = render_action_guidance(ActionView.for_objective(context.objective_mode), context)
    assert re.search(r'(?:list|read).{0,120}only.{0,80}missing', text.lower())
    assert len(text) < (3800 if len(completed) == 1 else 2600)


@pytest.mark.parametrize('owned', [False, True])
def test_ledger_hint_uses_owned_attempt_branch(owned):
    context = PlannerContext(objective_mode='whole_target',
        candidates=(PlannerCandidate('can_fixture', 'sql-injection', 'validating'),))
    text = render_action_guidance(ActionView.for_objective(context.objective_mode), context, owned_active=owned)
    if owned:
        assert 'list only missing metadata' in text
        assert 'record_attempt_state' in text and 'record_result for the active attempt' in text
    else:
        assert 'no owned active attempt' in text and 'record_attempt_state' not in text


@pytest.mark.parametrize('action,owned', [('start_validation', False), ('resume_owned', True), ('finalize_owned', True)])
def test_sql_continuation_preserves_cross_phase_allowance_without_granting_probes(action, owned):
    handoff = {'next_action': action, 'candidate_id': 'can_fixture',
               'attempt_id': 'attempt_fixture' if owned else None,
               'attempt_status': 'active' if owned else None, 'owned_active': owned,
               'probing_stopped': action == 'finalize_owned',
               'recovery': {'status': 'none', 'rejections': 0, 'rejection_limit': 2,
                            'repair_turns': 0, 'repair_turn_limit': 3}}
    route = ValidationRoute('expert', 'sql-injection')
    text = render_validation_guidance(handoff, route, frozenset()).lower()
    assert re.search(r'initial signal.{0,100}input analysis', text)
    assert re.search(r'first confirmation.{0,100}counts', text)
    assert re.search(r'recaptur.{0,70}(?:not|never).{0,50}reset', text)
    if owned:
        if action == 'resume_owned':
            assert 'do not open a replacement' in text
        else:
            assert 'local finalization' in text
    else:
        assert 'before any validation probes' in text
    if action == 'finalize_owned':
        assert 'probing has stopped' in text


async def test_documented_secret_fields_keep_identity_without_operation_or_replay(tmp_path, monkeypatch):
    # Existing synthetic OpenAPI and native MockTransport fixture. Review and
    # server resolution here are test-authored facts, not an extraction engine.
    spec = deepcopy(SPEC)
    schema = spec['paths']['/widgets']['post']['requestBody']['content']['application/json']['schema']
    schema['properties']['password'] = {'type': 'string', 'format': 'password'}
    runtime, source, requests = await retained_initializer(
        tmp_path, monkeypatch, 'SwaggerUIBundle({spec: ' + json.dumps(spec) + '});')
    sample = json.dumps({'label': 'inert', 'password': 'synthetic-secret-canary'})
    for field in schema['properties']:
        await execute(runtime, 'workflow', {'action': 'record_input', 'method': 'POST',
            'endpoint': '/service/v4/widgets', 'parameter': field, 'location': 'json',
            'input_type': 'string', 'content_type': 'application/json', 'sample_payload': sample,
            'source_attribution': attribution(source, f'paths./widgets.post.requestBody.{field}')})
    inputs = list(runtime.workflow.attack_surface_inputs.values())
    assert {item.parameter for item in inputs} == {'label', 'password'}
    assert all(item.method == 'POST' and item.endpoint.endswith('/service/v4/widgets')
               and item.content_type == 'application/json' and item.disposition == 'pending' for item in inputs)
    assert all(item.source_ref is item.baseline_request_ref is item.auth_context_ref is None for item in inputs)
    assert all(json.loads(item.sample_payload)['password'] == '[REDACTED]' for item in inputs)
    assert 'synthetic-secret-canary' not in json.dumps(runtime.workflow.to_dict())
    assert len([link for link in runtime.workflow.discovery_provenance.values() if link.input_id]) == 2
    assert len(requests) == 1 and requests[0].method == 'GET'
    assert not runtime.workflow.candidates and not runtime.workflow.attempts and not runtime.workflow.evidence
