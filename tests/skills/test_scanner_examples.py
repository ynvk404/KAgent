"""Skill examples must describe calls that the actual typed adapters accept."""
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

import pytest

from src.engagement.state import EngagementState
from src.engagement.state import parse_tcp_ports
from src.target.target import Target
from src.tools.execution.scanners import validate_scanner_args
from src.tools.http.http_tool import HTTPTool

SKILLS = Path(__file__).resolve().parents[2] / 'skills'


def calls(skill):
    text = (SKILLS / skill / 'SKILL.md').read_text()
    return [json.loads(block) for block in re.findall(r'```json\s*\n(.*?)\n```', text, re.S)]


@pytest.mark.parametrize('skill,scanner', [('recon', 'nmap'), ('web-enumeration', 'ffuf')])
def test_scanner_tool_examples_use_real_typed_arguments(skill, scanner):
    examples = [row for row in calls(skill) if row['tool'] == 'shell']
    assert examples
    for example in examples:
        args = example['arguments']
        assert args['scanner'] == scanner
        validate_scanner_args(args)
        assert not {'command', 'argv', 'wordlist_path', 'words', 'extra_args'} & args.keys()


def test_ffuf_examples_cover_root_observed_prefix_and_wildcard_filters():
    args = [row['arguments'] for row in calls('web-enumeration') if row['tool'] == 'shell']
    assert any(urlsplit(row['url']).path == '/FUZZ' and row['wordlist_id'] == 'dirb-small' for row in args)
    assert any(urlsplit(row['url']).path == '/api/FUZZ' and row['wordlist_id'] == 'api-words' for row in args)
    assert any(row.get('calibration') is True and row.get('filter_size') for row in args)


def test_nmap_examples_distinguish_effective_port_and_explicit_scope():
    args = [row['arguments'] for row in calls('recon') if row['tool'] == 'shell']
    assert any(parse_tcp_ports(row['ports']) == (3000,) for row in args)
    assert any(parse_tcp_ports(row['ports']) == (3000, 8080) for row in args)
    assert all(row['target'] == '127.0.0.1' for row in args)


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
