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
