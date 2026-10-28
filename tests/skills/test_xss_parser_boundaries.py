"""Loaded XSS guidance and constrained, synthetic parser contrasts.

HTMLParser fixtures cover ordinary HTML/script-data cases, not the full HTML5
tokenizer (in particular its escaped/double-escaped script states). Node checks
syntax only. These unit tests do not execute JavaScript, invoke an LLM/browser,
validate target evidence or measure whether a live Agent follows the playbook.
"""
from __future__ import annotations

import asyncio
from html import escape
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import parse_qs, urlencode

import pytest

from src.permission.permission import AlwaysAllow
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry
from src.tools.skills.payloads import ReadPayloadsTool


@pytest.fixture(scope='module')
def guidance():
    registry = Registry()
    registry.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    skill = asyncio.run(LoadSkillTool(registry).run({'name': 'cross-site-scripting'}))

    async def read_corpus():
        tool = ReadPayloadsTool(registry)
        args = {'skill': 'cross-site-scripting', 'file': 'payloads.txt', 'limit': 5000}
        chunks = []
        while True:
            output = await tool.run(args, None, AlwaysAllow())
            rendered, footer = output.rsplit('\nContinuation: ', 1)
            page = json.loads(footer)
            size = page['end_char'] - page['start_char']
            chunks.append(rendered.split('\n', 1)[1][:size])
            if page['next_start_char'] is None:
                return ''.join(chunks)
            call = json.loads(rendered.splitlines()[0].split('Next page: ', 1)[1])
            assert call['tool'] == 'read_payloads'
            args = call['arguments']  # Use only the reader's published continuation.

    corpus = asyncio.run(read_corpus())
    assert corpus == (Path(__file__).resolve().parents[2] / 'skills' /
                      'cross-site-scripting' / 'payloads.txt').read_text(encoding='utf-8')
    return skill, corpus


def compact(text: str) -> str:
    return ' '.join(text.split()).lower()


def boundaries(guidance) -> str:
    return compact(guidance[0].split('**Parser boundaries', 1)[1]
                   .split('### Context traces', 1)[0])


def test_loaded_analysis_flow_locates_each_occurrence_before_selecting_probes(guidance):
    section = compact(guidance[0].split('## 2. Determine', 1)[1].split('### Context traces', 1)[0])
    steps = ['locate reflection', 'identify context', 'identify parser boundaries',
             'analyze transformations', 'select probe', 'compare responses', 'evaluate evidence']
    positions = [section.index(step) for step in steps]
    assert positions == sorted(positions)
    for requirement in (
        'each relevant occurrence', 'response type', 'surrounding prefix/suffix',
        'a neutralized occurrence does not settle another',
        'benign control', 'uncertain delimiter or escape character', 'including backslash',
        'predicting returned structure before sending', 'same request/session conditions',
        'rule out only the hypothesis', 'one escaped payload does not rule out',
    ):
        assert requirement in section


@pytest.mark.parametrize(('placement', 'requirements'), [
    ('html text / attribute', ('character references become data', 'same pass', 'later consumer')),
    ('inline script', ('html script-data tokenization', 'js lexing', 'backtick/interpolation',
                       'without neutralizing the enclosing html boundary')),
    ('external javascript', ('without an enclosing html script-data parser', 'verify loading/consumer')),
    ('event-handler attribute', ('character-reference decoding', 'js handler parsing', 'actual trigger')),
    ('json response / embedded data block', ('standalone json is data', 'outer html boundary',
                                           'json parsing/readback is not execution')),
    ('dom sink', ('insertion/evaluation api', '`textcontent`', 'not observed execution')),
])
def test_loaded_context_table_distinguishes_parser_paths(guidance, placement, requirements):
    rows = [compact(line) for line in guidance[0].splitlines() if line.startswith('| ')]
    row = next(row for row in rows if row.startswith('| ' + placement))
    assert all(requirement in row for requirement in requirements)


class HtmlTrace(HTMLParser):
    """Observe structure/data only; never treat these tokens as execution proof."""

    def __init__(self, source: str):
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.data: list[str] = []
        self.script_data: list[str] = []
        self.in_script = False
        self.feed(source)
        self.close()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))
        if tag == 'script':
            self.in_script = True

    def handle_endtag(self, tag: str) -> None:
        if tag == 'script':
            self.in_script = False

    def handle_data(self, data: str) -> None:
        self.data.append(data)
        if self.in_script:
            self.script_data.append(data)


@pytest.mark.parametrize('context', ['text', 'attribute'])
def test_encoded_html_remains_data_in_its_original_context(guidance, context):
    assert 'character references become data, not new markup or attribute delimiters' in boundaries(guidance)
    value = 'm"\'><i data-probe=trace7></i>'
    encoded = escape(value, quote=True)
    if context == 'text':
        trace = HtmlTrace('<p>' + encoded + '</p>')
        assert trace.tags == [('p', {})]
        assert ''.join(trace.data) == value
    else:
        trace = HtmlTrace('<input value="' + encoded + '" data-tail="t">')
        assert trace.tags == [('input', {'value': value, 'data-tail': 't'})]


@pytest.mark.parametrize('quote', ["'", '"', '`'], ids=['single', 'double', 'template'])
@pytest.mark.parametrize('transform', ['quotes-only', 'html-less-than', 'js-less-than', 'escaped-slash'])
def test_js_escaping_and_outer_html_boundary_are_independent(guidance, quote, transform):
    section = boundaries(guidance)
    assert 'even inside a js string, template literal or comment' in section
    assert 'html script escaped/double-escaped states can change that interpretation' in section
    # Escape the chosen JS delimiter and backslashes, without claiming this
    # minimal fixture transformation is a general-purpose sanitizer.
    value = "m'\"`\\x</script><i data-probe=trace7></i>"
    transformed = value.replace('\\', '\\\\').replace(quote, '\\' + quote)
    assert '\\' + quote in transformed and '\\\\' in transformed
    if transform == 'html-less-than':
        transformed = transformed.replace('<', '&lt;')
    elif transform == 'js-less-than':
        transformed = transformed.replace('<', r'\u003C')
    elif transform == 'escaped-slash':
        transformed = transformed.replace('</', r'<\/')
    source = 'const value=' + quote + transformed + quote + ';'
    trace = HtmlTrace('<script>' + source + '</script>')
    if transform == 'quotes-only':
        assert [tag for tag, _ in trace.tags] == ['script', 'i']
        assert ''.join(trace.script_data) != source  # HTML ended the script first.
    else:
        assert [tag for tag, _ in trace.tags] == ['script']
        assert ''.join(trace.script_data) == source  # No invented early decoding.


@pytest.mark.parametrize('script_type', ['', 'application/json'])
def test_inline_data_block_retains_html_boundary_without_proving_execution(guidance, script_type):
    assert 'a non-executable script type is not execution proof' in boundaries(guidance)
    value = '</script><i data-probe=trace7></i>'
    source = '<script type="' + script_type + '">' + json.dumps(value) + '</script>'
    trace = HtmlTrace(source)
    assert [tag for tag, _ in trace.tags] == ['script', 'i']
    # The injected marker is an inert element. No JavaScript was executed.
    assert trace.tags[1] == ('i', {'data-probe': 'trace7'})


@pytest.mark.parametrize('value', ['trace7', '</script><i data-probe=trace7></i>', "m'\\tail"])
def test_external_js_has_no_html_end_tag_boundary(guidance, value):
    assert "does not close the loading page's script element" in boundaries(guidance)
    node = shutil.which('node')
    if node is None:
        pytest.skip('Optional syntax-only JavaScript checks require an existing node binary')
    source = 'const value=' + json.dumps(value) + ';'
    result = subprocess.run([node, '--check', '--input-type=commonjs'], input=source,
                            text=True, capture_output=True, timeout=5, check=False)
    assert result.returncode == 0, result.stderr
    assert HtmlTrace('<script src="/asset.js"></script>').script_data == []
    # Syntax acceptance is not proof that the resource is loaded or executed.


def test_json_reflection_is_data_until_a_separate_consumer_is_evidenced(guidance):
    section = boundaries(guidance)
    assert 'standalone json is data without an evidenced execution sink' in section
    value = '</script><i data-probe=trace7></i>'
    response = json.dumps({'value': value})
    assert json.loads(response) == {'value': value}
    assert 'do not transfer a json api assessment to a separate sink' in section


def test_corpus_keeps_parser_selection_open_and_accounts_for_marker_transformations(guidance):
    skill = compact(guidance[0])
    corpus = compact(' '.join(line.lstrip('# ').strip() for line in guidance[1].splitlines()))
    for requirement in (
        'not a fixed selection algorithm', 'compose only boundaries justified by captured syntax',
        'quote escaping can invalidate a newly introduced script',
        'quote-free marker', 'record the exact expected title string',
    ):
        assert requirement in skill
    for requirement in (
        'benign control', 'include backslash', 'no fixed character set or payload order',
        'one escaped occurrence does not settle another', 'external javascript',
        'inert structural control', 'quote-free equivalent', 'browser-required when needed',
    ):
        assert requirement in corpus
    assert 'portswigger' not in skill + corpus


def test_parser_findings_do_not_relax_evidence_or_browser_requirements(guidance):
    section = boundaries(guidance)
    assert 'unresolved transformations/consumer context remain `insufficient-evidence`' in section
    assert 'necessary unobserved browser step remains `browser-required`' in section
    skill = compact(guidance[0])
    for requirement in (
        'structural injection is not observed execution',
        'neither raw reflection nor html fragment parsing alone establishes execution',
        'deterministic http proof establishes exploitability under step 3, not observed browser execution',
        'both `confirmed` and `not-confirmed` require usable primary observations',
        'current candidate/attempt ownership and registered immutable evidence',
        'no browser-execution capability is available in the current runtime',
        'do not attempt to simulate or infer browser execution',
    ):
        assert requirement in skill


def test_loaded_context_model_and_probe_predictions_do_not_require_all_layers(guidance):
    """Static instruction delivery; authored parser fixtures below are separate."""
    skill = compact(guidance[0])
    for requirement in (
        'model only evidenced layers', 'submitted value → encoded request',
        'server/template transformations', 'do not assume a second decode',
        'add layers only when observations make them relevant',
        'method, input binding, session and response identity',
        'expected observation if true', 'expected observation if false',
        'why that difference resolves a current uncertainty',
        'alternatives predict the same visible result',
        'once a boundary is actually crossed, rebuild the context model for the new unit',
        'carry forward transformations visible in its bytes',
        'do not carry the old delimiter requirement into the new context',
        'a simpler harmless expression avoids the transformed syntax',
        'keep the assigned scope fixed', 'do not narrow the original candidate hypothesis',
    ):
        assert requirement in skill


def test_loaded_failure_interpretation_keeps_inert_invalid_and_unobserved_separate(guidance):
    section = compact(guidance[0].split('After any non-confirming probe', 1)[1]
                      .split('Interpret the result according', 1)[0])
    for requirement in (
        'http silence is not a diagnosis', 'input absent or sink not reached',
        'invalid comparison', 'encoded, escaped, sanitized or removed',
        'valid but inert data/code', 'uncalled function or unreachable branch',
        'boundary crossed, new code invalid', 'preserve structural success',
        'runnable structure, trigger unobserved', 'missing browser-only proof',
        'enforced csp or embedding restriction', 'report-only is not enforcement',
        'http cannot distinguish the possibilities', 'another permitted http observation',
    ):
        assert requirement in section


@pytest.mark.parametrize('value', ['%3Cscript%3E', '&lt;script&gt;', r"\'", '+%26'])
def test_request_decoding_and_html_decoding_are_distinct_operations(value):
    encoded_request = urlencode({'q': value})
    received = parse_qs(encoded_request)['q'][0]
    assert received == value
    # A single request decode cannot manufacture literal markup from an already
    # percent-encoded value. HTML text decodes character references, not URLs.
    trace = HtmlTrace('<p>' + received + '</p>')
    assert trace.tags == [('p', {})]
    if value == '&lt;script&gt;':
        assert trace.data == ['<script>']
    else:
        assert ''.join(trace.data) == value


HISTORICAL_CONTEXTS = json.loads((Path(__file__).resolve().parents[1] / 'fixtures' /
                                'xss-returned-contexts.json').read_text(encoding='utf-8'))


@pytest.mark.parametrize('case', HISTORICAL_CONTEXTS, ids=lambda case: case['case'])
def test_retained_historical_contexts_separate_structure_from_effective_syntax(case):
    """Minimal verbatim excerpts, never replayed against a target or executed."""
    node = shutil.which('node')
    if node is None:
        pytest.skip('Optional syntax-only JavaScript checks require an existing node binary')
    source = case['script_excerpt']
    trace = HtmlTrace(source)
    assert parse_qs(case['encoded_request_query'])['search'] == [case['submitted']]
    assert case['response_headers']['content-type'].startswith('text/html')
    new_scripts = trace.script_data[1:]
    handlers = [attrs['onerror'] for tag, attrs in trace.tags if tag == 'img' and 'onerror' in attrs]
    if new_scripts or handlers:
        # The application's trailing source is now HTML text too; its quoted
        # image markup can create an extra inert img. Assess executable units
        # rather than ignoring suffix bytes or requiring an exact tag inventory.
        assert sum(tag == 'script' for tag, _ in trace.tags) == (2 if new_scripts else 1)
        assert len(new_scripts) + len(handlers) == 1
        intended = re.search(r"document\.title='[^']+'", case['submitted'])
        assert intended is not None
        syntax = subprocess.run([node, '--check', '--input-type=commonjs'], input=intended[0],
                                text=True, capture_output=True, timeout=5, check=False)
        assert syntax.returncode == 0  # Valid submitted expression, invalid returned code.
        for effective in new_scripts + handlers:
            assert effective is not None and r"\'" in effective
            code = 'function handler(event){' + effective + '}' if handlers else effective
            syntax = subprocess.run([node, '--check', '--input-type=commonjs'], input=code,
                                    text=True, capture_output=True, timeout=5, check=False)
            assert syntax.returncode != 0 and 'SyntaxError' in syntax.stderr
    else:
        assert [tag for tag, _ in trace.tags] == ['script']
        effective = trace.script_data[0]
        assert r"var searchTerms = '\\\';alert(1)//';" in effective
        syntax = subprocess.run([node, '--check', '--input-type=commonjs'], input=effective,
                                text=True, capture_output=True, timeout=5, check=False)
        assert syntax.returncode == 0  # Marker remains string data, not a statement.
