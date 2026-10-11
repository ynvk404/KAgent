"""Action contracts reject ignored inputs while preserving legacy assertions."""
import json

import pytest

from src.permission.permission import AlwaysAllow
from src.target.target import Target
from src.tools.workflow.workflow_tool import ACTIONS, ACTION_INPUTS, ACTION_REQUIRED, WorkflowTool
from src.tools.common.outcome import ToolOutput
from src.workflow.state import WorkflowState, WorkflowObjective


@pytest.mark.parametrize('action', ACTIONS)
async def test_unsupported_input_is_rejected_before_any_action_mutates(action):
    state = WorkflowState()
    tool = WorkflowTool(state)
    before = state.to_dict()
    args = {'action': action, **{key: 'fixture' for key in ACTION_REQUIRED.get(action, ())},
            'unexpected_argument': 'secret-value-not-for-errors'}
    output = await tool.run(args, None, AlwaysAllow())
    assert isinstance(output, ToolOutput)
    assert output.status == 'error' and output.error_kind == 'invalid_args'
    assert f'{action} does not accept unexpected_argument' in output
    assert 'omit' in output and 'secret-value-not-for-errors' not in output
    assert state.to_dict() == before


def test_flat_schema_explains_actions_and_runtime_reference_ownership():
    tool = WorkflowTool(WorkflowState())
    schema = tool.schema()
    assert set(ACTION_INPUTS) == set(ACTIONS)
    assert 'additionalProperties' not in schema
    contract = schema['properties']['action']['description']
    for action, fields in ACTION_INPUTS.items():
        row = next(line for line in contract.splitlines() if line.startswith(action + '('))
        advertised = {field.rstrip('*') for field in row.partition('(')[2].removesuffix(')').split(',') if field}
        assert advertised == set(fields) & schema['properties'].keys()
        required = {field.rstrip('*') for field in row.partition('(')[2].removesuffix(')').split(',') if field.endswith('*')}
        assert required == set(ACTION_REQUIRED.get(action, ()))
    assert 'record_candidate must omit them and objective_id' in tool.description()
    assert 'cannot assign an attempt' in schema['properties']['attempt_id']['description']
    assert 'cannot assign an attempt' not in schema['properties']['candidate_class'].get('description', '')
    assert 'objective_id' not in schema['properties']
    assert not {'oneOf', 'anyOf', 'allOf', 'if', 'then', 'else'} & schema.keys()


def test_description_examples_use_the_same_contract_and_returned_candidate_reference():
    tool = WorkflowTool(WorkflowState())
    examples = [json.loads(line) for line in tool.description().splitlines() if line.startswith('{')]
    assert [example['action'] for example in examples] == ['record_candidate', 'start_validation']
    for example in examples:
        action = example['action']
        assert set(example) - {'action'} <= set(ACTION_INPUTS[action])
        assert set(ACTION_REQUIRED.get(action, ())) <= example.keys()
    assert not {'candidate_id', 'objective_id', 'attempt_id'} & examples[0].keys()
    assert examples[1]['candidate_id'] == '<returned candidate.id>'


async def test_legacy_input_ownership_assertions_never_override_runtime():
    origin = 'https://fixture.test'
    state = WorkflowState(objective=WorkflowObjective('objective-fixture', 'whole_target', origin))
    tool = WorkflowTool(state, target=Target(origin))
    args = {'action': 'record_input', 'objective_id': 'objective-fixture', 'target_origin': origin,
            'target': origin, 'endpoint': '/search', 'method': 'GET', 'parameter': 'q',
            'source': 'validation-feedback'}
    created = json.loads(await tool.run(args, None, AlwaysAllow()))
    assert created['input']['objective_id'] == 'objective-fixture'
    assert created['input']['target_origin'] == origin
    assert created['input']['source_ref'] is None
    assert 'source' not in created['input']
    before = state.to_dict()
    for change in [{'objective_id': 'other'}, {'target_origin': 'https://other.test'},
                   {'target': 'https://other.test', 'target_origin': ''}]:
        output = await tool.run({**args, **change}, None, AlwaysAllow())
        assert output.startswith('error:')
        assert state.to_dict() == before
