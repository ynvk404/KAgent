"""Coverage presentation does not rewrite the request's endpoint/identity."""
from copy import deepcopy

import pytest

from src.agent.events import ToolCallEvent
from src.ui.core.admission import call_metadata
from src.ui.core.state import AgentEventAction, SetBusy, initial_state, reducer
from src.ui.widgets.banner import BannerData


@pytest.mark.parametrize('endpoint,method,expected', [
    ('GET /rest/products/search', None, 'GET /rest/products/search'),
    ('post /rest/products/search', None, 'POST /rest/products/search'),
    ('/rest/products/search', 'GET', 'GET /rest/products/search'),
    ('GET /rest/products/search?q=private#secret', 'GET', 'GET /rest/products/search'),
    ('GET https://user:private@fixture.test/rest/products/search?q=private', None, 'GET /rest/products/search'),
])
def test_coverage_endpoint_method_is_displayed_once(endpoint, method, expected):
    args = {'action': 'list', 'endpoint': endpoint}
    if method:
        args['method'] = method
    event = ToolCallEvent(id='coverage-fixture', name='coverage', args=args)
    original = deepcopy(event)
    metadata = call_metadata(event)
    assert metadata.activity == expected and event == original
    state = reducer(initial_state('', BannerData('', '', '')), SetBusy(True))
    state = reducer(state, AgentEventAction(event))
    assert state.running_tool and state.running_tool.endswith(expected)
    assert 'GET GET' not in state.running_tool and 'private' not in state.running_tool
    assert event == original and metadata == call_metadata(original)
