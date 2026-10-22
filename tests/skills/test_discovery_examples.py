"""Discovery playbook examples use native scoped HTTP."""
import json
from pathlib import Path
import re

import pytest

from src.engagement.state import EngagementState
from src.target.target import Target
from src.tools.http.http_tool import HTTPTool

SKILLS = Path(__file__).resolve().parents[2] / 'skills'


def calls(skill):
    text = (SKILLS / skill / 'SKILL.md').read_text()
    return [json.loads(block) for block in re.findall(r'```json\s*\n(.*?)\n```', text, re.S)]


@pytest.mark.parametrize('skill', ['recon', 'web-enumeration'])
def test_http_examples_prepare_native_scoped_requests_without_shell(skill):
    origin = 'http://127.0.0.1:3000'
    state = EngagementState()
    state.add_origin(origin)
    tool = HTTPTool(Target(origin), state)
    examples = [row for row in calls(skill) if row['tool'] == 'http']
    assert examples
    for example in examples:
        args = example['arguments']
        action, request = tool.prepare(args)
        assert args['phase'] == 'recon' and 0 < args['max_response_bytes'] <= 8192
        assert str(request.url).startswith(origin + '/') and action.redirect_limit == 0
        assert request.method in {'GET', 'OPTIONS', 'POST'}
        if request.method == 'POST':
            assert request.url.path == '/graphql'
            assert json.loads(request.content)['query'] == '{__schema{types{name}}}'


def test_known_metadata_examples_use_native_get_requests():
    examples = [row['arguments'] for row in calls('web-enumeration') if row['tool'] == 'http']
    paths = {row['url'] for row in examples if row.get('method') == 'GET'}
    assert {'/robots.txt', '/sitemap.xml', '/.well-known/security.txt'} <= paths
