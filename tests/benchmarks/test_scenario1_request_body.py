"""Offline regressions for the benchmark/native HTTP request-body boundary."""
from dataclasses import replace
from email.message import Message
from io import BytesIO
import json

import pytest

from benchmarks.scenario1.core.runtime import candidate_arguments, request_fixture
from src.engagement.state import EngagementState
from src.target.target import Target
from src.tools.http.http_tool import HTTPTool
from tests.benchmarks.test_scenario1 import op, settings


@pytest.fixture
def native_tool(settings):
    engagement = EngagementState()
    engagement.initialize_target(settings.target)
    return HTTPTool(Target(settings.target), engagement)


@pytest.mark.parametrize('method', ['GET', 'POST'])
def test_no_form_body_omits_optional_native_argument(op, settings, native_tool, method):
    case = replace(op, method=method)
    args = request_fixture(case, settings)
    assert 'body' not in args
    assert args['method'] == method
    assert args['url'] == settings.target + '/benchmark/fixture?q=bar'
    assert args['headers'] == {}
    tool = native_tool
    tool.validate_args(args)
    assert tool._prepare_with_diff(args)[1].content == b''
    template = json.loads(candidate_arguments(case, settings)['request_template'])
    assert template == args


@pytest.mark.parametrize('pairs,encoded', [
    ([['q', '']], 'q='),
    ([['q', 'a b+&é'], ['q', 'second']], 'q=a+b%2B%26%C3%A9&q=second'),
])
def test_form_body_preserves_blank_values_encoding_and_duplicates(op, settings, native_tool, pairs, encoded):
    case = replace(op, method='POST', body=pairs, input_location='body',
                   content_type='application/x-www-form-urlencoded')
    args = request_fixture(case, settings)
    assert args['body'] == encoded
    assert args['headers']['Content-Type'] == case.content_type
    tool = native_tool
    tool.validate_args(args)
    assert tool._prepare_with_diff(args)[1].content == encoded.encode('utf-8')
    assert json.loads(candidate_arguments(case, settings)['request_template']) == args


def test_native_explicit_empty_string_is_valid_but_null_is_rejected(op, settings, native_tool):
    tool = native_tool
    args = {**request_fixture(op, settings), 'body': ''}
    tool.validate_args(args)
    assert args['body'] == ''
    assert tool._prepare_with_diff(args)[1].content == b''
    with pytest.raises(ValueError, match='body must be a string'):
        tool.validate_args({**args, 'body': None})


@pytest.mark.parametrize('pairs,explicit_empty,expected', [
    ([], False, None),
    ([], True, b''),
    ([['q', '']], False, b'q='),
    ([['q', 'a b+']], False, b'q=a+b%2B'),
])
def test_reset_verification_consumer_preserves_body_presence(
        op, settings, monkeypatch, pairs, explicit_empty, expected):
    from benchmarks.scenario1.reset import verify
    case = replace(op, body=pairs)
    if explicit_empty:
        fixture = {**request_fixture(case, settings), 'body': ''}
        monkeypatch.setattr(verify, 'request_fixture', lambda *_: fixture)
    requests = []

    class OfflineResponse(BytesIO):
        status = 200
        headers = Message()

    class OfflineOpener:
        def open(self, request, *, timeout):
            requests.append(request)
            return OfflineResponse(b'offline')

    monkeypatch.setattr(verify.urllib.request, 'build_opener', lambda *_: OfflineOpener())
    result = verify.response({'target': settings.target}, case)
    assert result['status'] == 200
    assert len(requests) == 1
    assert requests[0].data == expected
    assert requests[0].method == case.method
