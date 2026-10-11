"""DeepSeek payloads through the real compatible client, without live requests."""
from copy import deepcopy
import json

import httpx
import pytest

from src.config.config import Config
from src.llm.core.factory import new_from_config
from src.llm.core.types import ChatRequest, Message, parsed_args
from src.llm.providers import DEEPSEEK_DEFAULT_MODEL
from src.llm.providers.openai import OpenAIClient
from src.permission.permission import AlwaysAllow
from src.target.target import Target
from src.tools.common.registry import Registry
from src.tools.workflow.workflow_tool import ACTION_INPUTS, WorkflowTool
from src.workflow.state import WorkflowObjective, WorkflowState


@pytest.mark.parametrize('backend', ['openai-compat', 'deepseek'])
async def test_deepseek_chat_receives_single_flat_workflow_contract(backend, monkeypatch):
    cfg = Config(backend=backend, base_url='https://api.deepseek.com',
                 model=DEEPSEEK_DEFAULT_MODEL, api_keys={backend: 'synthetic-key'})
    client = new_from_config(cfg)
    assert isinstance(client, OpenAIClient) and client.name() == backend
    origin = 'https://fixture.test'
    state = WorkflowState(objective=WorkflowObjective('objective-fixture', 'direct', origin))
    tool = WorkflowTool(state, target=Target(origin))
    registry = Registry()
    registry.register(tool)
    specs = registry.as_llm_tools()
    original = deepcopy(specs)
    args = {'action': 'record_candidate', 'candidate_class': 'sql-injection',
            'endpoint': '/login', 'method': 'POST', 'parameter': 'email'}
    captured = []

    def respond(request):
        assert str(request.url) == 'https://api.deepseek.com/chat/completions'
        captured.append(json.loads(request.content))
        return httpx.Response(200, json={'choices': [{'finish_reason': 'tool_calls', 'message': {
            'role': 'assistant', 'content': None, 'tool_calls': [{'id': 'call-fixture', 'type': 'function',
                'function': {'name': 'workflow', 'arguments': json.dumps(args)}}]}}]})

    monkeypatch.setattr('src.llm.providers.openai.new_provider_async_client',
        lambda: httpx.AsyncClient(transport=httpx.MockTransport(respond)))
    request = ChatRequest(client.model(), [Message('user', 'Record the supplied candidate')], tools=specs)
    response = await client.chat(request)
    assert len(captured) == 1 and specs == original
    assert captured[0]['tools'] == original
    function = captured[0]['tools'][0]['function']
    assert function['name'] == 'workflow' and len(captured[0]['tools']) == 1
    assert 'strict' not in function
    schema = function['parameters']
    assert schema['type'] == 'object' and schema['required'] == ['action']
    assert not {'oneOf', 'anyOf', 'allOf', 'if', 'then', 'else', 'additionalProperties'} & schema.keys()
    contract = schema['properties']['action']['description']
    creation = next(line for line in contract.splitlines() if line.startswith('record_candidate('))
    assert {field.rstrip('*') for field in creation.partition('(')[2][:-1].split(',')} == set(ACTION_INPUTS['record_candidate'])
    assert not {'objective_id', 'candidate_id', 'attempt_id'} & set(ACTION_INPUTS['record_candidate'])
    assert client.encode_request(request, True)['tools'] == captured[0]['tools']
    assert response.message.tool_calls is not None
    call = response.message.tool_calls[0]
    assert call.function.name == 'workflow'
    output = json.loads(await registry.execute('workflow', parsed_args(call.function), None, AlwaysAllow()))
    assert output['ok'] is True and output['candidate']['objective_id'] == 'objective-fixture'
    assert len(state.candidates) == 1
