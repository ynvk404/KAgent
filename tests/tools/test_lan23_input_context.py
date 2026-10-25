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


async def test_unverified_input_cannot_be_presented_as_an_access_prerequisite(runtime):
    prompter, _, state, item = dependency(runtime)
    operator = Operator()
    with pytest.raises(ValueError, match='unverified'):
        await AskUserTool(operator).run({'questions': [{'question': 'Supply valid credentials or exclude?',
            'input_ids': [item.id], 'dependency_kind': 'access',
            'dependency_basis': 'Assumed from a credential-shaped field.'}]}, None, prompter)
    assert not operator.questions and item.disposition == 'blocked'


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
