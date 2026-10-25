"""Source uncertainty and operator context without network or inferred POSTs."""
import json
import pytest

from src.tools.common.ask import AskUserTool
from tests.helpers.discovery_calls import captured, execute
from tests.tools.test_lan2021_input_questions import dependency, Operator, runtime  # noqa: F401


async def test_unsourced_login_is_explicitly_unverified(tmp_path):
    rt, _ = await captured(tmp_path)
    output = await execute(rt, 'workflow', {'action': 'record_input', 'method': 'POST',
        'endpoint': '/session', 'parameter': 'email', 'location': 'json', 'content_type': 'application/json'})
    data = json.loads(output.result)
    assert data['provenance']['kind'] == 'unverified'
    assert data['provenance']['authentication_requirement'] == 'unknown'
    detail = json.loads((await execute(rt, 'workflow', {'action': 'get_input', 'input_id': data['input']['id']})).result)
    assert detail['provenance'] == data['provenance']
    assert not rt.workflow.attempts


async def test_dependency_question_names_inputs_and_exclusion_scope(runtime):
    prompter, policy, state, item = dependency(runtime)
    operator = Operator()
    args = {'questions': [{'question': 'What should happen to this input?', 'input_ids': [item.id],
        'dependency_kind': 'scope', 'dependency_basis': 'Operator decision about assessment coverage; no authentication claim.'}]}
    await AskUserTool(operator).run(args, None, prompter)
    shown = operator.questions[0].question
    assert 'POST /private/order' in shown and 'lines' in shown
    assert 'untested' in shown and 'Exclude' in shown
    assert 'unverified' in shown and 'authentication' in shown
    assert item.disposition == 'blocked' and not state.validation_results


async def test_unverified_access_assumption_is_labelled_as_agent_report(runtime):
    prompter, _, state, item = dependency(runtime)
    operator = Operator()
    before = state.to_dict()
    await AskUserTool(operator).run({'questions': [{'question': 'Is authenticated access needed for this input?',
        'input_ids': [item.id], 'dependency_kind': 'access',
        'dependency_basis': 'Assumed from a credential-shaped field; needs operator clarification.'}]}, None, prompter)
    shown = operator.questions[0].question
    assert 'unverified' in shown and 'authentication requirements are unknown' in shown
    assert 'Agent-reported' in shown and 'does not grant execution permission' in shown
    assert state.to_dict() == before and item.disposition == 'blocked'


@pytest.mark.parametrize('kind,basis', [('access', ''), ('access', ' '), ('access', 'x' * 601),
                                        ('authentication-confirmed', 'A claimed dependency.')])
async def test_input_question_still_requires_a_bounded_dependency_declaration(runtime, kind, basis):
    prompter, policy, _, item = dependency(runtime)
    operator = Operator()
    with pytest.raises(ValueError, match='dependency_kind'):
        await AskUserTool(operator).run({'questions': [
            {'question': 'An otherwise valid question'},
            {'question': 'Clarify this input', 'input_ids': [item.id],
             'dependency_kind': kind, 'dependency_basis': basis}]}, None, prompter)
    assert not operator.questions and not policy.input_questions


async def test_cross_endpoint_source_is_rejected_instead_of_relabelled(tmp_path):
    rt, source = await captured(tmp_path)
    result = await execute(rt, 'workflow', {'action': 'record_input', 'method': 'POST',
        'endpoint': '/different', 'parameter': 'email', 'location': 'json',
        'source_ref': source.retained_ref}, success=False)
    assert result.status == 'error'
    assert not rt.workflow.objective_inputs()


async def test_candidate_receipt_uses_actual_source_size_instead_of_signal_prose(tmp_path):
    body = '{"status":"success","data":[]}'
    rt, source = await captured(tmp_path, body)
    recorded = json.loads((await execute(rt, 'workflow', {'action': 'record_input', 'method': 'GET',
        'endpoint': '/app/document.html', 'parameter': 'q', 'location': 'query', 'source_ref': source.retained_ref})).result)
    result = await execute(rt, 'workflow', {'action': 'record_candidate', 'candidate_class': 'sqli',
        'input_id': recorded['input']['id'], 'observation_ids': [source.retained_ref],
        'signals': ['Unverified model prose incorrectly claims 370 response bytes.']})
    actual = json.loads(result.result)['analysis_observations'][0]
    assert actual['retained_body_bytes'] == len(body.encode())
    assert actual['request_url'].endswith('/app/document.html')
    assert actual['response_hash'] and not actual['terminal_evidence']


async def test_mixed_provenance_question_is_compact_with_complete_existing_audit(runtime):
    from copy import deepcopy
    from src.workflow.discovery.attribution import record_attributed_input
    from src.workflow.discovery.inventory import SourceRecord
    from src.workflow.state import AttackSurfaceInput
    from tests.helpers.discovery_calls import attribution

    prompter, policy, state, unknown = dependency(runtime)
    objective = state.objective
    assert objective is not None and objective.target_origin is not None
    source = state.admit_discovery(SourceRecord(objective.id, objective.target_origin,
        'http', 'obs-fixture-schema', 'a' * 64, retained_ref='obs-fixture-schema',
        document_url=objective.target_origin + '/schema.json'))
    documented, _, _ = record_attributed_input(state, AttackSurfaceInput(objective.id,
        objective.target_origin, method='POST', endpoint='/orders', parameter='items',
        location='json', input_type='array', content_type='application/json'),
        attribution(source, '/paths/~1orders/post/requestBody/items'), generation=state.generation)
    linked, _ = state.add_attack_surface_input(AttackSurfaceInput(objective.id,
        objective.target_origin, method='GET', endpoint='/private/search', parameter='q',
        location='query', baseline_request_ref='fixture-request'))
    sibling, _ = state.add_attack_surface_input(AttackSurfaceInput(objective.id,
        objective.target_origin, method='POST', endpoint='/orders', parameter='other', location='json'))
    rows = [unknown, documented, linked]
    reasons = {row.id: f'Dependency for {row.parameter}: ' + 'Detailed Agent-reported uncertainty. ' * 9 for row in rows}
    for row in rows:
        state.set_input_disposition(row.id, 'blocked', reason=reasons[row.id])
        assert row.disposition_reason is not None
        reasons[row.id] = row.disposition_reason
    basis = 'Operator clarification after bounded review. ' * 10
    original = 'Which context should be used for these exact inputs?'
    options = [{'label': 'Keep blocked', 'description': 'Retain unresolved work.'},
               {'label': 'Exclude', 'description': 'Leave only these inputs untested.'}]
    args = {'questions': [{'question': original, 'input_ids': [row.id for row in rows],
        'dependency_kind': 'request_context', 'dependency_basis': basis, 'options': options}]}
    before = deepcopy(state.to_dict())
    grants = deepcopy(policy.engagement.http_permissions.grants)
    operator = Operator()
    tool = AskUserTool(operator)
    result = json.loads(await tool.run(args, None, prompter))
    display = operator.questions[0].question
    audit = result['answers'][0]['question']
    assert display.startswith(original) and len(display) < len(audit) * 0.5
    assert 'Agent-reported dependency: request_context' in display
    for row, label in [(unknown, 'unverified request contract'),
                       (documented, 'document-attributed; request unverified'),
                       (linked, 'request-linked; field consumption unverified')]:
        line = next(line for line in display.splitlines() if row.id in line)
        assert row.method in line and row.parameter in line and row.location in line and label in line
        assert reasons[row.id] in audit and reasons[row.id] not in display
    assert basis.strip() in audit and basis.strip() not in display
    assert source.id in audit and 'authentication_requirement' in audit
    assert sibling.id not in display and sibling.id not in audit
    assert 'untested' in display and 'does not grant execution permission' in display
    assert [(o.label, o.description) for o in operator.questions[0].options] == [
        (o['label'], o['description']) for o in options]
    assert audit in policy.input_question_texts.values()
    assert json.loads(await tool.run(args, None, prompter)) == result and len(operator.questions) == 1
    assert state.to_dict() == before and policy.engagement.http_permissions.grants == grants


async def test_cancelled_dependency_retains_retry_and_legacy_cached_answer(runtime):
    import asyncio
    from copy import deepcopy
    from src.permission.runtime.execution import ExecutionBlocked

    prompter, policy, state, item = dependency(runtime)
    before = deepcopy(state.to_dict())

    class CancelledOperator(Operator):
        async def ask(self, q, signal=None):
            self.questions.append(q)
            raise asyncio.CancelledError()

    args = {'questions': [{'question': 'Clarify this dependency?', 'input_ids': [item.id],
        'dependency_kind': 'request_context', 'dependency_basis': 'Unknown request contract after review.'}]}
    operator = CancelledOperator()
    tool = AskUserTool(operator)
    with pytest.raises(asyncio.CancelledError):
        await tool.run(args, None, prompter)
    with pytest.raises(ExecutionBlocked, match='operator retry required'):
        await tool.run(args, None, prompter)
    assert len(operator.questions) == 1 and list(policy.input_questions.values()) == [None]
    policy.retry()
    tool = AskUserTool(Operator())
    await tool.run(args, None, prompter)
    key = next(iter(policy.input_questions))
    # Previously cached expanded text is returned as-is, with its original answer.
    legacy = 'Previously cached original expanded question.'
    policy.input_question_texts[key] = legacy
    args['questions'][0]['question'] = 'Reworded question?'
    result = json.loads(await tool.run(args, None, prompter))
    assert result == {'answers': [{'question': legacy, 'answer': 'Keep blocked'}]}
    assert state.to_dict() == before and item.disposition == 'blocked'
