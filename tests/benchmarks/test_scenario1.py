"""Offline benchmark tests: production authority is never patched or seeded."""
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import asdict, replace
import json
from pathlib import Path
import re

import httpx
import pytest

from benchmarks.common.contracts import (CaseExecution, GroundTruth, OperationalCaseInput, RunManifest,
    RuntimeMetrics, RuntimeSettings, decode, digest, file_hash, write_new)
from benchmarks.common.metrics import distribution, llm_metrics
from benchmarks.common.recorder import Recorder, read_records
from benchmarks.scenario1.canonical import inspect_case_evidence, inspect_export
from benchmarks.scenario1.dataset import Dataset, MappingError, parse_truth, select
from benchmarks.scenario1.evaluate import confusion, evaluate
from benchmarks.scenario1.runner import envelope, run
from benchmarks.scenario1.runtime import (build_agent, candidate_arguments, execute_case, prompt,
                                          request_fixture, execution_status)
from src.llm.core.client import Client
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.llm.runtime.metrics import RequestMetrics, TokenUsage

ORIGIN = 'http://127.0.0.1:3000'


@pytest.fixture(autouse=True)
def isolated_project_environment(tmp_path, monkeypatch):
    # The embedding adapter configures the worker's project environment. Restore
    # it after each test so subsequent production responsibility groups stay isolated.
    monkeypatch.setenv('KAGENT_PROJECT_ROOT', str(tmp_path))


@pytest.fixture
def settings():
    return RuntimeSettings(ORIGIN, '/benchmark', True, 'confirmation-only', timeout_seconds=10)


@pytest.fixture
def op():
    return OperationalCaseInput('BenchmarkTest00001', 'cross-site-scripting', 'GET', '/fixture',
                                [['q', 'bar']], [], {}, {}, 'query', 'q')


def make_dataset(root: Path, per_stratum=21):
    (root / 'data').mkdir(parents=True)
    java = root / 'src/main/java/org/owasp/benchmark/testcode'
    java.mkdir(parents=True)
    html = root / 'src/main/webapp/fixture'
    html.mkdir(parents=True)
    truth = ['# test name, category, real vulnerability, cwe, Benchmark version: 1.2, fixture']
    crawler = ['<benchmarkSuite version="1.2">']
    index = 0
    for cls, cwe in [('sqli', 89), ('xss', 79)]:
        for vulnerable in ('true', 'false'):
            for _ in range(per_stratum):
                index += 1
                name = f'BenchmarkTest{index:05d}'
                truth.append(f'{name},{cls},{vulnerable},{cwe}')
                crawler.append(f'<benchmarkTest tcName="{name}" tcType="SERVLET" URL="https://localhost:8443/benchmark/fixture/{name}"><formparam name="{name}" value="bar"/></benchmarkTest>')
                (java / f'{name}.java').write_text(f'@WebServlet(value = "/fixture/{name}")\npublic void doGet() {{ doPost(request, response); }}\npublic void doPost() {{ String param = request.getParameter("{name}"); }}')
                (html / f'{name}.html').write_text(f'<form method="POST" action="/benchmark/fixture/{name}"></form>')
    (root / 'expectedresults-1.2.csv').write_text('\n'.join(truth) + '\n')
    (root / 'data/benchmark-crawler-http.xml').write_text('\n'.join(crawler) + '</benchmarkSuite>')
    return Dataset(root)


@pytest.mark.parametrize('bad', ['BenchmarkTest00001,xss,unknown,79', 'bad,xss,true,79',
                                'BenchmarkTest00001,xss,true,89', 'BenchmarkTest00001,xss,true'])
def test_truth_malformed(tmp_path, bad):
    p = tmp_path / 'truth'
    p.write_text('# test name, Benchmark version: 1.2\n' + bad)
    with pytest.raises(ValueError):
        parse_truth(p)


def test_duplicate_truth(tmp_path):
    p = tmp_path / 'truth'
    p.write_text('# Benchmark version: 1.2\n' + 'BenchmarkTest00001,xss,true,79\n' * 2)
    with pytest.raises(ValueError, match='duplicate'):
        parse_truth(p)


def test_selection_versions_hashes_and_no_replacement(tmp_path):
    d = make_dataset(tmp_path)
    default = select(d, 'run')
    assert len(default.truth) == 80
    first = select(d, 'run', 'reduced')
    d.truth.reverse()
    assert select(d, 'run', 'reduced') == first
    assert select(d, 'run', 'reduced', seed=5).execution_order != first.execution_order
    assert decode(RunManifest, asdict(first)) == first
    d.verify(first)
    with pytest.raises(ValueError):
        decode(RunManifest, {**asdict(first), 'schema_version': 2})
    with pytest.raises(ValueError):
        replace(first, execution_order=first.execution_order * 2)
    chosen = first.execution_order[0]
    source = tmp_path / 'src/main/java/org/owasp/benchmark/testcode' / f'{chosen}.java'
    source.write_text(source.read_text().replace('getParameter', 'unknownReader'))
    with pytest.raises(ValueError, match='changed'):
        d.verify(first)
    with pytest.raises(MappingError, match=chosen):
        select(Dataset(tmp_path), 'run', 'reduced')


def test_smoke_selection_is_balanced_and_deterministic(tmp_path):
    d = make_dataset(tmp_path)
    manifest = select(d, 'smoke-run', 'smoke', seed=91)
    assert len(manifest.truth) == 12
    assert {key: sum(row['vulnerability_class'] == cls and row['expected_vulnerable'] is vulnerable
                     for row in manifest.truth)
            for key, (cls, vulnerable) in {
                'sqli/vulnerable': ('sql-injection', True), 'sqli/safe': ('sql-injection', False),
                'xss/vulnerable': ('cross-site-scripting', True), 'xss/safe': ('cross-site-scripting', False),
            }.items()} == {'sqli/vulnerable': 3, 'sqli/safe': 3, 'xss/vulnerable': 3, 'xss/safe': 3}
    assert select(d, 'smoke-run', 'smoke', seed=91) == manifest
    changed_seed = select(d, 'smoke-run', 'smoke', seed=92)
    assert changed_seed.execution_order != manifest.execution_order
    d.verify(manifest)


def test_manifest_verification_reloads_authoritative_truth(tmp_path):
    d = make_dataset(tmp_path)
    manifest = select(d, 'run', 'reduced')
    changed_id = manifest.truth[0]['case_id']
    truth_path = tmp_path / 'expectedresults-1.2.csv'
    lines = truth_path.read_text().splitlines()
    for index, line in enumerate(lines):
        if line.startswith(changed_id + ','):
            fields = line.split(',')
            fields[2] = 'false' if fields[2] == 'true' else 'true'
            lines[index] = ','.join(fields)
            break
    else:
        raise AssertionError('selected truth row not found')
    truth_path.write_text('\n'.join(lines) + '\n')
    with pytest.raises(ValueError):
        d.verify(manifest)


@pytest.mark.parametrize('tamper,reason', [
    ('selection', 'truth rows'), ('order', 'execution order'), ('truth', 'truth rows'),
    ('operational', 'operational rows'), ('artifact-hash', 'artifact changed or omitted'),
    ('artifact-set', 'artifact changed or omitted'), ('mutation-safety', 'derived metadata'),
    ('dataset-counts', 'derived metadata'), ('dataset-version', 'dataset identity'),
])
def test_manifest_verification_reconstructs_selection_and_metadata(tmp_path, tamper, reason):
    d = make_dataset(tmp_path)
    manifest = select(d, 'run', 'reduced')
    raw = deepcopy(asdict(manifest))
    if tamper == 'selection':
        selected = {row['case_id'] for row in raw['truth']}
        other = next(row for row in d.truth if row.case_id not in selected
                     and row.vulnerability_class == 'sql-injection' and row.expected_vulnerable)
        replaced_id = raw['truth'][0]['case_id']
        raw['truth'][0] = asdict(other)
        raw['operational'][0] = asdict(d.map(other))
        raw['execution_order'] = [other.case_id if case_id == replaced_id else case_id
                                  for case_id in raw['execution_order']]
    elif tamper == 'order':
        raw['execution_order'].reverse()
    elif tamper == 'truth':
        raw['truth'][0]['source_ref'] = 'expectedresults-1.2.csv:999'
    elif tamper == 'operational':
        location = raw['operational'][0]['input_location']
        pairs = raw['operational'][0][location]
        pairs[0][1] = 'hand-edited'
    elif tamper == 'artifact-hash':
        ref = next(iter(raw['dataset']['artifacts']))
        raw['dataset']['artifacts'][ref] = 'f' * 64
    elif tamper == 'artifact-set':
        raw['dataset']['artifacts'].pop(next(iter(raw['dataset']['artifacts'])))
    elif tamper == 'mutation-safety':
        raw['dataset']['state_mutating_cases'] = ['BenchmarkTest99999']
    elif tamper == 'dataset-counts':
        raw['dataset']['counts']['sql-injection/vulnerable'] += 1
    elif tamper == 'dataset-version':
        raw['dataset']['version'] = '9.9'
    edited = decode(RunManifest, raw)
    with pytest.raises(ValueError, match=reason):
        d.verify(edited)


def test_insufficient_strata(tmp_path):
    with pytest.raises(ValueError, match='insufficient'):
        select(make_dataset(tmp_path, 9), 'run', 'reduced')


@pytest.mark.parametrize('tag,reader,location,method', [
    ('header', 'request.getHeader("q")', 'header', 'POST'),
    ('cookie', 'request.getCookies(); c.getName().equals("q")', 'cookie', 'POST'),
    ('getparam', 'request.getParameter("q")', 'query', 'GET'),
    ('formparam', 'request.getParameter("q")', 'body', 'POST')])
def test_request_source_mapping(tmp_path, tag, reader, location, method):
    d = make_dataset(tmp_path, 1)
    name = d.truth[0].case_id
    node = d.requests[name]
    node[0].tag = tag
    node[0].set('name', 'q')
    p = tmp_path / 'src/main/java/org/owasp/benchmark/testcode' / f'{name}.java'
    p.write_text(f'@WebServlet(value = "/fixture/{name}")\npublic void doGet() {{ doPost(request, response); }}\npublic void doPost() {{ {reader}; }}')
    (tmp_path / f'src/main/webapp/fixture/{name}.html').write_text(f'<form method="{method}" action="/benchmark/fixture/{name}"></form>')
    op = d.map(d.truth[0])
    assert (op.input_location, op.input_name, op.method) == (location, 'q', method)


def test_input_name_mapping_and_ambiguity(tmp_path):
    d = make_dataset(tmp_path, 1)
    name = d.truth[0].case_id
    d.requests[name][0].set('name', 'bar')
    d.requests[name][0].set('value', name)
    p = tmp_path / f'src/main/java/org/owasp/benchmark/testcode/{name}.java'
    p.write_text(f'@WebServlet(value = "/fixture/{name}")\npublic void doPost() {{ request.getParameterNames(); request.getParameterValues(name); value.equals("{name}"); }}')
    assert d.map(d.truth[0]).input_component == 'name'
    d.cache.clear()
    p.write_text(p.read_text().replace(name + '");', 'missing");'))
    with pytest.raises(MappingError):
        d.map(d.truth[0])


def query_mapping_dataset(root, query, value='second', tag='getparam', duplicate=None):
    dataset = make_dataset(root, 1)
    truth = dataset.truth[0]
    node = dataset.requests[truth.case_id]
    node.set('URL', node.attrib['URL'] + ('?' + query if query else ''))
    node[0].tag = tag
    node[0].set('name', 'q')
    node[0].set('value', value)
    if duplicate is not None:
        child = deepcopy(node[0])
        child.set('value', duplicate)
        node.append(child)
    source = root / f'src/main/java/org/owasp/benchmark/testcode/{truth.case_id}.java'
    source.write_text(source.read_text().replace(f'getParameter("{truth.case_id}")', 'getParameter("q")'))
    form = root / f'src/main/webapp/fixture/{truth.case_id}.html'
    if tag == 'getparam':
        form.write_text(form.read_text().replace('POST', 'GET'))
    return dataset, truth


@pytest.mark.parametrize('query,tag,duplicate,reason', [
    ('q=first', 'getparam', None, 'conflicting URL query/crawler'),
    ('q=second&q=second', 'getparam', None, 'duplicate URL query'),
    ('q=first&q=second', 'getparam', None, 'duplicate URL query'),
    ('%71=first&q=second', 'getparam', None, 'duplicate URL query'),
    ('q=second', 'getparam', 'second', 'duplicate crawler'),
    ('', 'getparam', 'first', 'duplicate crawler'),
    ('', 'formparam', 'second', 'duplicate crawler'),
    ('q=second', 'formparam', None, 'URL query/form'),
])
def test_mapping_rejects_conflicting_and_ambiguous_query_occurrences(tmp_path, query, tag, duplicate, reason):
    dataset, truth = query_mapping_dataset(tmp_path, query, tag=tag, duplicate=duplicate)
    with pytest.raises(MappingError, match=f'{truth.case_id}:.*{reason}'):
        dataset.map(truth)
    assert truth.case_id not in dataset.cache


@pytest.mark.parametrize('query,value,expected', [
    ('q=second', 'second', [['q', 'second']]),
    ('q=', '', [['q', '']]),
    ('before=one&%71=second&after=two', 'second', [['before', 'one'], ['q', 'second'], ['after', 'two']]),
    ('before=one', 'second', [['before', 'one'], ['q', 'second']]),
])
def test_mapping_reconciles_identical_query_metadata_once(tmp_path, settings, query, value, expected):
    dataset, truth = query_mapping_dataset(tmp_path, query, value=value)
    mapped = dataset.map(truth)
    assert mapped.query == expected
    assert (mapped.method, mapped.input_name, mapped.input_location) == ('GET', 'q', 'query')
    wire_pairs = httpx.URL(request_fixture(mapped, settings)['url']).params.multi_items()
    assert wire_pairs == [tuple(pair) for pair in expected]


def test_operational_envelope_no_truth(op, settings, tmp_path):
    raw = envelope(asdict(op), settings, 'run', 'ex', tmp_path / 'workspace', tmp_path / 'output')
    text = json.dumps(raw) + json.dumps(candidate_arguments(op, settings)) + prompt('cand_abc', op)
    for forbidden in ('expected_vulnerable', 'ground_truth', 'expectedresults', 'vulnerable', 'safe_label'):
        assert forbidden not in text
    with pytest.raises(ValueError):
        decode(OperationalCaseInput, {**asdict(op), 'expected_vulnerable': True})
    assert request_fixture(op, settings)['url'] == ORIGIN + '/benchmark/fixture?q=bar'


def test_recorder_append_only_and_recovery(tmp_path):
    p = tmp_path / 'events.jsonl'
    r = Recorder(p, 'run')
    with pytest.raises(ValueError, match='kind/status/data'):
        r.append('unknown', 'case', 'scheduled')
    with pytest.raises(ValueError, match='kind/status/data'):
        r.append('scheduled', 'case', 'unknown')
    assert not p.exists()
    r.append('scheduled', 'case', 'scheduled')
    first = p.read_bytes()
    r.append('started', 'case', 'started', execution_id='ex')
    assert p.read_bytes().startswith(first)
    with pytest.raises(ValueError):
        r.append('started', 'case', 'started', execution_id='ex2')
    r.append('runtime-finished', 'case', 'completed', execution_id='ex')
    with pytest.raises(ValueError):
        r.append('runtime-finished', 'case', 'completed', execution_id='ex')
    with p.open('ab') as f:
        f.write(b'{"partial":')
    rows, partial = read_records(p)
    assert partial and len(rows) == 3
    with pytest.raises(ValueError, match='partial'):
        Recorder(p, 'run')
    corrupt = tmp_path / 'bad.jsonl'
    corrupt.write_bytes(first + b'broken\n' + first)
    with pytest.raises(ValueError, match='corruption'):
        read_records(corrupt)


def test_metrics_and_status_separation():
    metrics = [RequestMetrics('1', 'now', 1, 'fake', 'model', 'agent_loop', 'v1', None, None, 'success', TokenUsage(2, total_tokens=5)),
               RequestMetrics('2', 'now', 1, 'fake', 'model', 'agent_loop', 'v1', None, None, 'success')]
    usage = llm_metrics(metrics, None)['tokens']['total_tokens']
    assert usage == {'total': None, 'observed_sum': 5, 'known_requests': 1, 'requests': 2, 'complete': False}
    assert distribution([])['mean'] is None and distribution([1, 2, 3])['p95'] == 3
    assert execution_status({'stop_reason': 'final_response'}, []) == 'completed'
    assert execution_status({'stop_reason': 'client_error'}, ['ValueError']) == 'provider-error'
    assert execution_status({'stop_reason': 'final_response'}, ['OSError']) == 'runtime-error'
    assert execution_status({'stop_reason': 'max_steps'}, []) == 'budget-exhausted'
    assert execution_status({'stop_reason': 'workflow_completed'}, [], timed_out=True) == 'timeout'
    assert [confusion(v, o) for v, o in [(True, 'confirmed'), (True, 'not-confirmed'), (False, 'confirmed'), (False, 'not-confirmed')]] == ['TP', 'FN', 'FP', 'TN']
    with pytest.raises(ValueError):
        confusion(True, 'browser-required')


ASSESSMENT = {'hypothesis': 'Marker reaches an executable response position',
              'criteria': 'Compare bounded baseline and harmless marker response',
              'limitations': 'Only this designated input was tested', 'observed_impact': 'Bounded fixture response',
              'severity': 'low', 'completed_attempt': True}


class ScriptedClient(Client):
    """Fake only model I/O. Extract opaque IDs from actual production context/results."""
    def __init__(self, outcome='confirmed', mode='normal', skill='cross-site-scripting', name_case=None):
        self.outcome, self.mode = outcome, mode
        self.skill = skill
        self.name_case = name_case
        self.step = 0
        self.requests = []
        self.candidate = None
        self.attempt = None
        self.observations = []
        self.evidence = None

    def name(self):
        return 'scripted'

    def model(self):
        return 'offline'

    def tool(self, name, args):
        return ChatResponse(Message('assistant', '', tool_calls=[ToolCall(str(self.step), FunctionCall(name, json.dumps(args)))]), 'tool_calls')

    async def chat(self, request, signal=None):
        self.requests.append(request)
        if self.mode == 'timeout':
            await asyncio.sleep(30)
        if self.mode == 'provider-error':
            raise ValueError('scripted provider failure')
        if self.mode == 'empty':
            return ChatResponse(Message('assistant', 'Unable to assess; no structured result.'), 'stop')
        text = '\n'.join(m.content for m in request.messages)
        match = re.search(r'cand_[0-9a-f]{20}', text)
        assert match is not None
        self.candidate = match.group()
        for message in request.messages:
            if message.role != 'tool':
                continue
            self.observations.extend(x for x in re.findall(r'\[runtime observation: ([^\]]+)\]', message.content) if x not in self.observations)
            try:
                payload = json.loads(message.content)
                if 'validation_context' in payload:
                    self.attempt = payload['validation_context']['attempt_id']
                if 'evidence' in payload:
                    self.evidence = payload['evidence']['id']
            except ValueError:
                pass
        self.step += 1
        if self.step == 1:
            return self.tool('load_skill', {'name': self.skill})
        if self.step == 2:
            return self.tool('workflow', {'action': 'start_validation', 'candidate_id': self.candidate, 'assessment': ASSESSMENT})
        if self.step in (3, 4):
            if self.name_case == 'replacement':
                name, value = ('q', 'bar') if self.step == 3 else ('q_mutated', 'bar')
            elif self.name_case == 'unrelated':
                name, value = 'other', 'bar'
            else:
                name = 'q'
                value = 'baseline' if self.step == 3 else '%27' if self.skill == 'sql-injection' else '%3Cscript%3Edocument.title%3D%22marker%22%3C/script%3E'
            return self.tool('http', {'method': 'GET', 'url': ORIGIN + '/benchmark/fixture?' + name + '=' + value, 'phase': 'validation'})
        if self.step == 5:
            return self.tool('file_write', {'path': 'artifacts/proof.md', 'content': 'Bounded baseline and harmless executable marker response compared.'})
        if self.step == 6:
            return self.tool('workflow', {'action': 'record_evidence', 'candidate_id': self.candidate, 'evidence_path': 'artifacts/proof.md', 'observation_ids': self.observations})
        if self.step == 7:
            return self.tool('workflow', {'action': 'record_result', 'candidate_id': self.candidate,
                'skill_name': self.skill, 'outcome': 'insufficient-evidence' if self.mode == 'revisions' else self.outcome,
                **({'attempt_id': self.attempt} if self.attempt else {}),
                'observation_ids': self.observations, 'evidence_refs': [self.evidence], 'assessment': ASSESSMENT})
        if self.mode == 'revisions':
            if self.step == 8:
                return self.tool('workflow', {'action': 'start_validation', 'candidate_id': self.candidate, 'assessment': ASSESSMENT})
            if self.step == 9:
                return self.tool('http', {'url': ORIGIN + '/benchmark/fixture?q=newmarker', 'phase': 'validation'})
            if self.step == 10:
                return self.tool('file_write', {'path': 'artifacts/proof2.md', 'content': 'Additional bounded fixture response assessed.'})
            if self.step == 11:
                return self.tool('workflow', {'action': 'record_evidence', 'candidate_id': self.candidate,
                                             'evidence_path': 'artifacts/proof2.md', 'observation_ids': self.observations[-1:]})
            if self.step == 12:
                return self.tool('workflow', {'action': 'record_result', 'candidate_id': self.candidate,
                    'skill_name': 'cross-site-scripting', 'outcome': self.outcome,
                    'observation_ids': self.observations[-1:], 'evidence_refs': [self.evidence], 'assessment': ASSESSMENT})
        if self.mode == 'late-error':
            raise ValueError('scripted failure after terminal result')
        if self.mode == 'late-timeout':
            await asyncio.sleep(30)
        return ChatResponse(Message('assistant', 'Finished supplied-input validation with the recorded bounded assessment.'), 'stop')


@pytest.fixture
def mock_http(monkeypatch):
    real = httpx.AsyncClient
    requests = []
    def handler(request):
        requests.append(request)
        marker = request.url.params.get('q', '')
        return httpx.Response(200, content=f'<html>{marker}</html>'.encode(), headers={'Content-Type': 'text/html'}, request=request)
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    return requests


@pytest.mark.asyncio
@pytest.mark.parametrize('outcome', ['confirmed', 'not-confirmed', 'browser-required', 'blocked',
                                    'insufficient-evidence', 'deferred', 'authorization-required'])
async def test_real_agent_native_assessment(tmp_path, monkeypatch, op, settings, mock_http, outcome):
    monkeypatch.chdir(tmp_path)
    client = ScriptedClient(outcome)
    execution = await execute_case(op, settings, tmp_path, 'run', 'ex', client)
    assert execution.status == 'completed', asdict(execution)
    assert len(mock_http) == 2
    exported = execution.result
    assert exported is not None and execution.metrics is not None
    assert exported['workflow']['objective']['mode'] == 'candidate_validation'
    value, error = inspect_export(exported, run_id='run', case_id=op.case_id, execution_id='ex',
                                 candidate_args=candidate_arguments(op, settings), target=ORIGIN + '/benchmark')
    assert error is None and value == outcome
    if outcome in {'confirmed', 'not-confirmed'}:
        assert inspect_case_evidence(exported, op=op, candidate_args=candidate_arguments(op, settings)) is None
    assert exported['accepted_at_freeze'] == (outcome in {'confirmed', 'not-confirmed'})
    assert execution.metrics['agent_seconds'] > 0 and execution.metrics['setup_seconds'] >= 0
    assert execution.metrics['first_terminal_seconds'] is None or execution.metrics['first_terminal_seconds'] <= execution.metrics['agent_seconds']
    for request in client.requests:
        assert 'expected_vulnerable' not in str(request)
    assert execution.runtime_metadata['yolo'] is False
    recorded_run(tmp_path / 'recorded', single_manifest(op, settings), execution)
    report = evaluate(tmp_path / 'recorded')
    assert report['records'][0]['partition'] == ('evaluable' if outcome in {'confirmed', 'not-confirmed'} else 'unresolved')
    if outcome == 'not-confirmed':
        assert report['metrics']['overall']['FN'] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(('name_case', 'partition'), [
    ('replacement', 'evaluable'),
    ('unrelated', 'invalid-result'),
])
async def test_name_component_requires_recorded_baseline_replacement(
        tmp_path, monkeypatch, settings, mock_http, name_case, partition):
    op_name = OperationalCaseInput('BenchmarkTest00001', 'cross-site-scripting', 'GET', '/fixture',
                                    [['q', 'bar']], [], {}, {}, 'query', 'q', 'name')
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    execution = await execute_case(op_name, settings, workspace, 'run', 'ex',
                                   ScriptedClient(skill='cross-site-scripting', name_case=name_case))
    assert execution.result is not None and execution.result['accepted_at_freeze']
    root = tmp_path / f'run-{name_case}'
    recorded_run(root, single_manifest(op_name, settings), execution)
    report = evaluate(root)
    assert report['records'][0]['partition'] == partition
    if name_case == 'unrelated':
        assert report['records'][0]['reason'] == 'evidence-case-binding:missing-name-mutation-semantics'
    else:
        result = execution.result['workflow']['validation_results'][-1]
        bindings = [entry['source']['source_details']['scenario1_case_binding']
                    for entry in result['evidence_manifest'] if entry['source']['source_kind'] == 'native-http']
        assert any(binding.get('name_mutation', {}).get('field_name_sha256')
                   for binding in bindings)


@pytest.mark.asyncio
@pytest.mark.parametrize('mode,status', [('timeout', 'timeout'), ('provider-error', 'provider-error'), ('empty', 'completed'), ('late-error', 'provider-error')])
async def test_execution_failures_never_negative(tmp_path, monkeypatch, op, settings, mock_http, mode, status):
    monkeypatch.chdir(tmp_path)
    timeout = .05 if mode == 'timeout' else 10
    ex = await execute_case(op, replace(settings, timeout_seconds=timeout), tmp_path, 'run', 'ex', ScriptedClient(mode=mode))
    assert ex.status == status
    assert ex.result is not None
    if mode == 'late-error':
        assert ex.result['result_id'] and ex.result['accepted_at_freeze']
    if mode == 'empty':
        assert ex.result['result_id'] is None
    recorded_run(tmp_path / 'recorded', single_manifest(op, settings), ex)
    report = evaluate(tmp_path / 'recorded')
    assert report['records'][0]['partition'] == ('unresolved' if mode == 'empty' else 'execution-failed')


@pytest.mark.asyncio
async def test_multiple_native_revisions_one_final_export(tmp_path, monkeypatch, op, settings, mock_http):
    monkeypatch.chdir(tmp_path)
    ex = await execute_case(op, settings, tmp_path, 'run', 'ex', ScriptedClient(mode='revisions'))
    assert ex.status == 'completed' and ex.result is not None
    assert len(ex.result['workflow']['validation_results']) == 2
    assert ex.result['latest_position'] == 1
    value, error = inspect_export(ex.result, run_id='run', case_id=op.case_id, execution_id='ex',
                                  candidate_args=candidate_arguments(op, settings), target=ORIGIN + '/benchmark')
    assert error is None and value == 'confirmed'


@pytest.mark.asyncio
async def test_runtime_io_failure_after_terminal(tmp_path, monkeypatch, op, settings, mock_http):
    from src.session.store import Store
    original = Store.save
    async def failing(self, messages, target=None, memory=None, workflow=None, engagement_state=None):
        if workflow and workflow.validation_results:
            raise OSError('offline injected filesystem failure')
        return await original(self, messages, target, memory, workflow, engagement_state)
    monkeypatch.setattr(Store, 'save', failing)  # Only external filesystem I/O is fake.
    monkeypatch.chdir(tmp_path)
    ex = await execute_case(op, settings, tmp_path, 'run', 'ex', ScriptedClient())
    assert ex.status == 'runtime-error' and ex.result is not None and ex.result['result_id']


@pytest.mark.asyncio
async def test_terminal_then_timeout_and_no_background_execution(tmp_path, monkeypatch, op, settings, mock_http):
    monkeypatch.chdir(tmp_path)
    # Allow normal file/checkpoint I/O to finish before exercising the deliberately
    # stalled final model request. This checks failure precedence, not I/O speed.
    ex = await execute_case(op, settings, tmp_path, 'run', 'ex', ScriptedClient(mode='late-timeout'))
    assert ex.status == 'timeout' and ex.result is not None and ex.result['accepted_at_freeze']
    count = len(mock_http)
    await asyncio.sleep(.02)
    assert len(mock_http) == count


@pytest.mark.asyncio
async def test_native_request_budget_exhaustion(tmp_path, monkeypatch, op, settings, mock_http):
    monkeypatch.chdir(tmp_path)
    ex = await execute_case(op, replace(settings, http_requests=1), tmp_path, 'run', 'ex', ScriptedClient())
    assert ex.status == 'budget-exhausted'
    assert len(mock_http) == 1


def single_manifest(op, settings, vulnerable=True):
    return RunManifest('run', {'version': '1.2', 'artifacts': {'truth.csv': 'a' * 64}},
        [asdict(GroundTruth(op.case_id, op.vulnerability_class, vulnerable, 79, 'truth.csv:2'))],
        [asdict(op)], [op.case_id], 1729, 'single', asdict(settings))


def recorded_run(root, manifest, ex):
    root.mkdir(exist_ok=True)
    write_new(root / 'manifest.json', asdict(manifest))
    p = root / 'results' / f'{ex.case_id}.json'
    write_new(p, asdict(ex))
    rec = Recorder(root / 'events.jsonl', manifest.run_id)
    rec.append('scheduled', ex.case_id, 'scheduled', data={'operational_hash': digest(manifest.operational[0]), 'manifest_hash': digest(asdict(manifest))})
    rec.append('started', ex.case_id, 'started', execution_id=ex.execution_id)
    rec.append('runtime-finished', ex.case_id, ex.status, execution_id=ex.execution_id,
               data={'result_ref': str(p.relative_to(root)), 'result_sha256': file_hash(p)})


def rewrite_result_sources(exported, edit):
    """Re-seal synthetic frozen evidence while preserving production contracts."""
    from src.workflow.assessment import digest as source_digest, seal
    from src.workflow.state import ValidationResult
    raw = deepcopy(exported)
    workflow = raw['workflow']
    result_index = next(i for i, row in enumerate(workflow['validation_results'])
                        if row['result_id'] == raw['result_id'])
    result = workflow['validation_results'][result_index]
    sources = [entry['source'] for entry in result['evidence_manifest']]
    edit(sources, result, workflow)
    for entry in result['evidence_manifest']:
        row = deepcopy(entry['source'])
        row.pop('role', None)
        row.pop('required', None)
        entry['hash'] = source_digest(row)
    validation = ValidationResult.from_dict(result)
    assert validation is not None
    validation.assessment_binding = seal(validation)
    workflow['validation_results'][result_index] = validation.to_dict()
    return raw


def schedule_run(root, manifest):
    root.mkdir()
    write_new(root / 'manifest.json', asdict(manifest))
    recorder = Recorder(root / 'events.jsonl', manifest.run_id)
    operations = {row['case_id']: row for row in manifest.operational}
    for cid in manifest.execution_order:
        recorder.append('scheduled', cid, 'scheduled', data={
            'operational_hash': digest(operations[cid]), 'manifest_hash': digest(asdict(manifest))})
    return recorder


def diagnostic_execution(op, execution_id='ex'):
    return CaseExecution('run', op.case_id, execution_id, 'completed', 'final_response', None,
                         asdict(RuntimeMetrics(1, 0, 0, None, {}, {}, 0)), {})


@pytest.mark.parametrize('partial_tail', [False, True])
@pytest.mark.parametrize('torn_export', [False, True])
def test_interrupted_parent_preserves_orphan_export_without_scoring(tmp_path, op, settings, partial_tail, torn_export):
    root = tmp_path / 'run'
    recorder = schedule_run(root, single_manifest(op, settings))
    recorder.append('started', op.case_id, 'started', execution_id='ex')
    output = root / 'results' / f'{op.case_id}.json'
    if torn_export:
        output.parent.mkdir()
        output.write_bytes(b'{"run_id":"run","case_id":')
    else:
        write_new(output, asdict(diagnostic_execution(op)))
    if partial_tail:
        with (root / 'events.jsonl').open('ab') as stream:
            stream.write(b'{"kind":"runtime-finished"')
    history, contents = (root / 'events.jsonl').read_bytes(), output.read_bytes()
    report = evaluate(root)
    assert report['incomplete'] and report['partial_tail_ignored'] == partial_tail
    assert report['records'][0]['partition'] == 'execution-failed'
    assert report['records'][0]['reason'] == 'interrupted-after-start'
    counts = report['metrics']['overall']
    assert counts['scheduled'] == counts['started'] == counts['execution-failed'] == 1
    assert counts['completed'] == counts['evaluable'] == 0 and counts['evaluability'] == 0
    assert all(counts[k] == 0 for k in ('TP', 'FN', 'FP', 'TN'))
    assert counts['agent_seconds_by_status'] == {}
    assert report['orphan_exports'] == [{'case_id': op.case_id, 'execution_id': 'ex',
        'result_ref': f'results/{op.case_id}.json', 'result_sha256': file_hash(output),
        'export_state': 'incomplete' if torn_export else 'diagnostic'}]
    assert output.read_bytes() == contents
    if partial_tail:
        assert (root / 'events.jsonl').read_bytes() == history
    else:
        assert (root / 'events.jsonl').read_bytes().startswith(history)
    published_history = (root / 'events.jsonl').read_bytes()
    assert evaluate(root) == report
    assert (root / 'events.jsonl').read_bytes() == published_history


@pytest.mark.parametrize('change', ['run_id', 'case_id', 'execution_id', 'schema', 'symlink',
                                   'unstarted', 'extra', 'duplicate-key', 'nonfinite', 'oversized'])
def test_orphan_recovery_rejects_conflicting_or_unexpected_exports(tmp_path, op, settings, change):
    root = tmp_path / 'run'
    recorder = schedule_run(root, single_manifest(op, settings))
    if change != 'unstarted':
        recorder.append('started', op.case_id, 'started', execution_id='ex')
    output = root / 'results' / f'{op.case_id}.json'
    raw = asdict(diagnostic_execution(op))
    if change in {'run_id', 'case_id', 'execution_id'}:
        raw[change] = 'wrong'
    elif change == 'schema':
        raw['schema_version'] = 99
    write_new(output, raw)
    if change == 'extra':
        write_new(root / 'results' / 'unexpected.json', raw)
    elif change == 'symlink':
        output.unlink()
        outside = tmp_path / 'outside.json'
        write_new(outside, raw)
        output.symlink_to(outside)
    elif change == 'duplicate-key':
        output.write_text('{"run_id":"run","run_id":"wrong"}')
    elif change == 'nonfinite':
        output.write_text('{"metric":NaN}')
    elif change == 'oversized':
        with output.open('r+b') as stream:
            stream.truncate(32 * 1024 * 1024 + 1)
    history = (root / 'events.jsonl').read_bytes()
    with pytest.raises(ValueError):
        evaluate(root)
    assert (root / 'events.jsonl').read_bytes() == history
    assert not list(root.glob('evaluation-*.json'))


def test_orphan_diagnostic_change_cannot_replace_recorded_evaluation(tmp_path, op, settings):
    root = tmp_path / 'run'
    recorder = schedule_run(root, single_manifest(op, settings))
    recorder.append('started', op.case_id, 'started', execution_id='ex')
    output = root / 'results' / f'{op.case_id}.json'
    write_new(output, asdict(diagnostic_execution(op)))
    report = evaluate(root)
    history = (root / 'events.jsonl').read_bytes()
    output.write_bytes(output.read_bytes() + b'\n')
    with pytest.raises(ValueError, match='conflicting evaluation identity'):
        evaluate(root)
    assert (root / 'events.jsonl').read_bytes() == history
    assert read_records(root / 'events.jsonl')[0][-1]['data']['evaluation_identity'] == report['evaluation_identity']


def test_orphan_recovery_preserves_completed_cases_and_whole_schedule(tmp_path, settings):
    manifest = select(make_dataset(tmp_path / 'dataset', 10), 'run', 'reduced')
    manifest = replace(manifest, runtime=asdict(settings))
    root = tmp_path / 'run'
    recorder = schedule_run(root, manifest)
    operations = {row['case_id']: decode(OperationalCaseInput, row) for row in manifest.operational}
    completed, interrupted = manifest.execution_order[:2]
    recorder.append('started', completed, 'started', execution_id='finished')
    finished = diagnostic_execution(operations[completed], 'finished')
    output = root / 'results' / f'{completed}.json'
    write_new(output, asdict(finished))
    recorder.append('runtime-finished', completed, 'completed', execution_id='finished', data={
        'result_ref': f'results/{completed}.json', 'result_sha256': file_hash(output)})
    recorder.append('started', interrupted, 'started', execution_id='interrupted')
    write_new(root / 'results' / f'{interrupted}.json', asdict(diagnostic_execution(operations[interrupted], 'interrupted')))
    with (root / 'events.jsonl').open('ab') as stream:
        stream.write(b'{"kind":"runtime-finished"')
    history = (root / 'events.jsonl').read_bytes()
    report = evaluate(root)
    counts = report['metrics']['overall']
    assert counts['scheduled'] == 40 and counts['started'] == 2 and counts['completed'] == 1
    assert counts['unresolved'] == counts['execution-failed'] == 1 and counts['not-run'] == 38
    assert counts['evaluable'] == 0 and counts['evaluability'] == 0
    assert counts['agent_seconds_by_status'] == {'completed': distribution([1])}
    assert (root / 'events.jsonl').read_bytes() == history


@pytest.mark.asyncio
async def test_parent_final_status_controls_timing_after_terminal_export(tmp_path, monkeypatch, op, settings, mock_http):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    execution = await execute_case(op, settings, workspace, 'run', 'ex', ScriptedClient())
    assert execution.status == 'completed' and execution.result is not None
    assert execution.result['accepted_at_freeze'] and execution.metrics is not None
    duration = execution.metrics['agent_seconds']
    manifest = single_manifest(op, settings)
    for code, timeout, status in ((0, False, 'completed'), (-9, False, 'crashed'), (-15, True, 'timeout')):
        def launcher(payload, seconds):
            raw = asdict(execution)
            raw['execution_id'] = payload['execution_id']
            raw['result']['execution_id'] = payload['execution_id']
            write_new(Path(payload['output']), raw)
            return code, timeout
        root = tmp_path / status
        run(manifest, settings, root, launcher=launcher)
        output = root / 'results' / f'{op.case_id}.json'
        contents = output.read_bytes()
        report = evaluate(root)
        groups = [report['metrics']['overall'], report['metrics']['classes'][op.vulnerability_class],
                  report['metrics']['strata'][f'{op.vulnerability_class}/vulnerable']]
        for group in groups:
            assert group['agent_seconds_by_status'] == {status: distribution([duration])}
            assert group['completed'] == group['evaluable'] == group['TP'] == (status == 'completed')
            assert group['execution-failed'] == (status != 'completed')
        assert report['metrics']['strata'][f'{op.vulnerability_class}/safe']['agent_seconds_by_status'] == {}
        assert json.loads(contents)['status'] == 'completed'
        assert output.read_bytes() == contents
        assert evaluate(root) == report


@pytest.mark.asyncio
async def test_offline_join_invalid_bindings_and_revisions(tmp_path, monkeypatch, op, settings, mock_http):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    ex = await execute_case(op, settings, workspace, 'run', 'ex', ScriptedClient())
    assert ex.result is not None
    manifest = single_manifest(op, settings)
    recorded_run(tmp_path / 'run', manifest, ex)
    report = evaluate(tmp_path / 'run')
    assert report['metrics']['overall']['TP'] == 1
    assert report['metrics']['overall']['fpr'] is None
    before = (tmp_path / 'run/events.jsonl').read_bytes()
    assert evaluate(tmp_path / 'run') == report
    assert (tmp_path / 'run/events.jsonl').read_bytes() == before
    for change in ('session_id', 'objective_id', 'candidate_id', 'result_id', 'latest_position', 'epoch'):
        exported = deepcopy(ex.result)
        exported[change] = 'wrong' if change != 'latest_position' else -1
        _, error = inspect_export(exported, run_id='run', case_id=op.case_id, execution_id='ex',
                                  candidate_args=candidate_arguments(op, settings), target=ORIGIN + '/benchmark')
        assert error, change
    failure = replace(ex, status='runtime-error')
    recorded_run(tmp_path / 'failure', manifest, failure)
    report = evaluate(tmp_path / 'failure')
    assert report['metrics']['overall']['execution-failed'] == 1
    assert report['metrics']['overall']['TP'] == 0
    no_result = replace(ex, result=None)
    recorded_run(tmp_path / 'missing', manifest, no_result)
    assert evaluate(tmp_path / 'missing')['records'][0]['reason'] == 'missing-canonical-result'


@pytest.mark.asyncio
@pytest.mark.parametrize('tamper,reason', [
    ('endpoint', 'wrong-route'), ('parameter', 'wrong-input-name'),
    ('location', 'wrong-input-location'), ('component', 'wrong-input-component'),
    ('candidate', 'candidate ownership mismatch'),
])
async def test_only_exact_case_evidence_is_scoreable(tmp_path, monkeypatch, op, settings, mock_http, tamper, reason):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    execution = await execute_case(op, settings, workspace, 'run', 'ex', ScriptedClient())
    assert execution.result is not None and execution.result['accepted_at_freeze']
    candidate_args = candidate_arguments(op, settings)

    if tamper == 'endpoint':
        def edit(sources, result, workflow):
            urls = []
            for source in sources:
                source['url'] = source['url'].replace('/benchmark/fixture', '/benchmark/other')
                source['request_hash'] = digest(source['url'])
                details = source['source_details']['scenario1_case_binding']
                details['route'] = '/benchmark/other'
                details['request_hash'] = source['request_hash']
                source['role'] = 'auxiliary'
                source['required'] = True
                urls.append({'role': 'auxiliary', 'method': source['method'], 'url': source['url'], 'required': True})
            attempt = workflow['attempts'][result['attempt_id']]
            attempt['related_requests'] = urls
            result['assessment']['attempt'] = {key: value for key, value in attempt.items() if key != 'status'}
        exported = rewrite_result_sources(execution.result, edit)
        _, production_error = inspect_export(exported, run_id='run', case_id=op.case_id, execution_id='ex',
            candidate_args=candidate_args, target=ORIGIN + '/benchmark')
        assert production_error is None  # Same-origin auxiliary evidence passes production admission.
    elif tamper == 'parameter':
        exported = rewrite_result_sources(execution.result,
            lambda sources, _result, _workflow: [s['source_details']['scenario1_case_binding'].__setitem__('input_components', []) for s in sources])
    elif tamper == 'location':
        def edit(sources, _result, _workflow):
            for source in sources:
                for row in source['source_details']['scenario1_case_binding']['input_components']:
                    row['location'] = 'body'
        exported = rewrite_result_sources(execution.result, edit)
    elif tamper == 'component':
        def edit(sources, _result, _workflow):
            for source in sources:
                for row in source['source_details']['scenario1_case_binding']['input_components']:
                    row['component'] = 'name'
        exported = rewrite_result_sources(execution.result, edit)
    else:
        def edit(sources, _result, _workflow):
            for source in sources:
                source['candidate_id'] = 'cand_' + '0' * 20
                source['candidate_binding'] = 'a' * 64
                details = source['source_details']['scenario1_case_binding']
                details['candidate_id'] = source['candidate_id']
                details['candidate_binding'] = source['candidate_binding']
        exported = rewrite_result_sources(execution.result, edit)

    if tamper != 'endpoint':
        _, production_error = inspect_export(exported, run_id='run', case_id=op.case_id, execution_id='ex',
            candidate_args=candidate_args, target=ORIGIN + '/benchmark')
        if tamper == 'candidate':
            assert production_error and 'ownership' in production_error
        else:
            assert production_error is None
    altered_execution = replace(execution, result=exported)
    root = tmp_path / f'run-{tamper}'
    recorded_run(root, single_manifest(op, settings), altered_execution)
    report = evaluate(root)
    assert report['records'][0]['partition'] == 'invalid-result'
    assert reason in report['records'][0]['reason']


@pytest.mark.asyncio
async def test_wrong_http_method_is_not_case_scoreable(tmp_path, monkeypatch, op, settings, mock_http):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    execution = await execute_case(op, settings, workspace, 'run', 'ex', ScriptedClient())
    assert execution.result is not None

    def edit_method(sources, _result, _workflow):
        for source in sources:
            source['method'] = 'POST'
            source['source_details']['scenario1_case_binding']['method'] = 'POST'

    altered = rewrite_result_sources(execution.result, edit_method)
    error = inspect_case_evidence(altered, op=op, candidate_args=candidate_arguments(op, settings))
    assert error == 'evidence-case-binding:wrong-http-method'


def test_parent_crash_and_partial_accounting(tmp_path, op, settings):
    manifest = single_manifest(op, settings)
    run(manifest, settings, tmp_path / 'crash', launcher=lambda *args: (-9, False))
    report = evaluate(tmp_path / 'crash')
    assert report['records'][0]['partition'] == 'execution-failed'
    assert report['records'][0]['reason'] == 'crashed'
    partial = tmp_path / 'partial'
    partial.mkdir()
    write_new(partial / 'manifest.json', asdict(manifest))
    rec = Recorder(partial / 'events.jsonl', 'run')
    rec.append('scheduled', op.case_id, 'scheduled', data={'operational_hash': digest(asdict(op)), 'manifest_hash': digest(asdict(manifest))})
    report = evaluate(partial)
    assert report['incomplete'] and report['metrics']['overall']['not-run'] == 1
    assert report['metrics']['overall']['evaluability'] == 0
    assert report['metrics']['overall']['recall'] is None


@pytest.mark.asyncio
async def test_isolation_and_permission_boundaries(tmp_path, op, settings, mock_http, monkeypatch):
    roots = [tmp_path / 'one', tmp_path / 'two']
    agents = [build_agent(op, settings, root, ScriptedClient()) for root in roots]
    assert agents[0][2] != agents[1][2]
    for (agent, policy, _), root in zip(agents, roots):
        monkeypatch.chdir(root)
        assert agent.memory_store is not None and agent.intelligence is not None
        assert agent.memory_store.personal_dir.is_relative_to(root / '.personal')
        assert agent.intelligence.personal_path.is_relative_to(root / '.personal')
        assert policy.worker is None and not policy.yolo
        assert len(policy.engagement.allowed_origins) == 1
        with pytest.raises(Exception, match='outside'):
            await agent.tools.execute('http', {'url': 'http://127.0.0.2:3000/fixture'}, None, agent.prompter)
        with pytest.raises(Exception, match='outside'):
            await agent.tools.execute('file_read', {'path': str(tmp_path / 'truth.csv')}, None, agent.prompter)
        with pytest.raises(Exception):
            await agent.tools.execute('file_write', {'path': str(root / 'source.py'), 'content': 'x'}, None, agent.prompter)
        assert not mock_http


@pytest.mark.asyncio
async def test_sqli_production_path(tmp_path, monkeypatch, op, settings, mock_http):
    monkeypatch.chdir(tmp_path)
    sql = replace(op, vulnerability_class='sql-injection')
    ex = await execute_case(sql, settings, tmp_path, 'run', 'ex', ScriptedClient(skill='sql-injection'))
    assert ex.status == 'completed' and ex.result is not None
    value, error = inspect_export(ex.result, run_id='run', case_id=sql.case_id, execution_id='ex',
                                  candidate_args=candidate_arguments(sql, settings), target=ORIGIN + '/benchmark')
    assert value == 'confirmed' and error is None


def test_fail_fast_whole_schedule(tmp_path, settings):
    d = make_dataset(tmp_path / 'dataset', 10)
    manifest = select(d, 'run', 'reduced')
    run(manifest, settings, tmp_path / 'run', fail_fast=True, launcher=lambda *args: (-9, False))
    report = evaluate(tmp_path / 'run')
    counts = report['metrics']['overall']
    assert counts['scheduled'] == 40 and counts['started'] == 1
    assert counts['execution-failed'] == 1 and counts['not-run'] == 39
    assert counts['reasons']['fail-fast'] == 39
    assert evaluate(tmp_path / 'run') == report


def test_conflicting_recorder_ownership_and_complete_tail(tmp_path):
    p = tmp_path / 'events.jsonl'
    first = Recorder(p, 'run')
    second = Recorder(p, 'run')
    first.append('scheduled', 'case', 'scheduled')
    with pytest.raises(ValueError, match='ownership'):
        second.append('scheduled', 'other', 'scheduled')
    p.write_bytes(p.read_bytes().rstrip(b'\n'))
    rows, partial = read_records(p)
    assert rows == [] and partial


@pytest.mark.parametrize('change', ['version', 'truth', 'hash', 'duplicates'])
def test_malformed_manifest(tmp_path, op, settings, change):
    raw = asdict(single_manifest(op, settings))
    if change == 'version':
        raw['protocol_version'] = 'unknown'
    elif change == 'truth':
        raw['truth'][0]['expected_vulnerable'] = 'true'
    elif change == 'hash':
        raw['dataset']['artifacts']['truth.csv'] = 'bad'
    else:
        raw['truth'].append(raw['truth'][0])
    with pytest.raises(ValueError):
        decode(RunManifest, raw)


def test_json_duplicate_keys_and_nonfinite(tmp_path):
    from benchmarks.common.contracts import parse_json, RuntimeMetrics
    for value in ('{"schema_version":1,"schema_version":2}', '{"x":NaN}'):
        with pytest.raises(ValueError):
            parse_json(value)
    with pytest.raises(ValueError, match='interval'):
        RuntimeMetrics(1, 1, 1, 2, {}, {}, None)


@pytest.mark.asyncio
async def test_offline_corruption_and_duplicate_export(tmp_path, monkeypatch, op, settings, mock_http):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    ex = await execute_case(op, settings, workspace, 'run', 'ex', ScriptedClient())
    root = tmp_path / 'run'
    recorded_run(root, single_manifest(op, settings), ex)
    output = root / 'results' / f'{op.case_id}.json'
    output.write_text('{"damaged":true}')
    report = evaluate(root, publish=False)
    assert report['records'][0]['partition'] == 'invalid-result' and report['metrics']['overall']['TP'] == 0
    write_new(root / 'results/duplicate.json', {})
    with pytest.raises(ValueError, match='duplicate'):
        evaluate(root)


def test_unexpected_schedule_and_partial_started(tmp_path, op, settings):
    root = tmp_path / 'run'
    root.mkdir()
    manifest = single_manifest(op, settings)
    write_new(root / 'manifest.json', asdict(manifest))
    r = Recorder(root / 'events.jsonl', 'run')
    r.append('scheduled', op.case_id, 'scheduled', data={'operational_hash': digest(asdict(op)), 'manifest_hash': digest(asdict(manifest))})
    r.append('started', op.case_id, 'started', execution_id='ex')
    with (root / 'events.jsonl').open('ab') as f:
        f.write(b'{"incomplete')
    history = (root / 'events.jsonl').read_bytes()
    report = evaluate(root)
    assert report['incomplete'] and report['partial_tail_ignored']
    assert report['records'][0]['reason'] == 'interrupted-after-start'
    assert (root / 'events.jsonl').read_bytes() == history


def test_real_fresh_process_workers_with_fake_external_io(tmp_path, monkeypatch, op, settings):
    import subprocess
    from benchmarks.scenario1.runner import launch_worker
    secure = tmp_path / 'config.json'
    secure.write_text(json.dumps({'backend': 'openai', 'api_keys': {'openai': 'fake-secret-marker'}}))
    monkeypatch.setenv('kagent_CONFIG', str(secure))
    actual_popen = subprocess.Popen
    script = '''
import asyncio, httpx
from benchmarks.scenario1.worker import main
from tests.benchmarks.test_scenario1 import ScriptedClient
real = httpx.AsyncClient
httpx.AsyncClient = lambda **kw: real(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b'bounded fixture', request=r)), **kw)
asyncio.run(main(client_factory=lambda cfg: ScriptedClient()))
'''
    pids = []
    def start(cmd, **kwargs):
        proc = actual_popen([cmd[0], '-c', script], **kwargs)
        pids.append(proc.pid)
        return proc
    monkeypatch.setattr(subprocess, 'Popen', start)  # Fake only launch-time external I/O choice.
    exports = []
    for i in range(2):
        payload = envelope(asdict(op), settings, 'run', f'ex{i}', tmp_path / f'workspace{i}', tmp_path / f'result{i}.json')
        code, timeout = launch_worker(payload, 30)
        assert code == 0 and not timeout
        output = json.loads((tmp_path / f'result{i}.json').read_text())
        exports.append(output)
        assert output['status'] == 'completed' and 'fake-secret-marker' not in json.dumps(output)
    assert pids[0] != pids[1]
    assert exports[0]['result']['session_id'] != exports[1]['result']['session_id']
    assert exports[0]['result']['epoch'] != exports[1]['result']['epoch']
    assert secure.read_text() == json.dumps({'backend': 'openai', 'api_keys': {'openai': 'fake-secret-marker'}})


def test_cli_dry_run_never_initializes_agent_provider_or_network(tmp_path, monkeypatch, settings):
    from benchmarks.scenario1.__main__ import main
    from src.agent.agent import Agent
    from src.llm.runtime import provider_runtime
    def forbidden(*args, **kw):
        raise AssertionError('dry-run attempted runtime I/O')
    monkeypatch.setattr(Agent, 'run', forbidden)
    monkeypatch.setattr(provider_runtime, 'build_startup_runtime', forbidden)
    monkeypatch.setattr(httpx, 'AsyncClient', forbidden)
    dataset = tmp_path / 'dataset'
    make_dataset(dataset, 1)
    assert main(['run', '--dataset', str(dataset), '--case', 'BenchmarkTest00001', '--target', ORIGIN,
                 '--context-path', '/benchmark', '--authorized-lab', '--target-state', 'confirmation-only', '--dry-run']) == 0
    assert not (tmp_path / 'artifacts').exists()


def test_parent_watchdog_terminates_real_process(tmp_path, monkeypatch, op, settings):
    import subprocess
    from benchmarks.scenario1.runner import launch_worker
    original = subprocess.Popen
    children = []
    def start(cmd, **kwargs):
        proc = original([cmd[0], '-c', 'import time; time.sleep(30)'], **kwargs)
        children.append(proc)
        return proc
    monkeypatch.setattr(subprocess, 'Popen', start)
    payload = envelope(asdict(op), settings, 'run', 'ex', tmp_path / 'workspace', tmp_path / 'result.json')
    code, timeout = launch_worker(payload, .1)
    assert timeout and code != 0 and children[0].poll() is not None


def test_worker_provider_setup_failure_has_safe_trace(tmp_path, monkeypatch, op, settings):
    import subprocess
    from benchmarks.scenario1.runner import launch_worker
    config = tmp_path / 'secure.json'
    config.write_text('{"backend":""}')
    monkeypatch.setenv('kagent_CONFIG', str(config))
    result = tmp_path / 'result.json'
    code, timeout = launch_worker(envelope(asdict(op), settings, 'run', 'ex', tmp_path / 'workspace', result), 30)
    assert code == 0 and not timeout
    ex = decode(CaseExecution, json.loads(result.read_text()))
    assert ex.status == 'setup-error' and ex.runtime_metadata['trace']
    assert ex.runtime_metadata['stage'] == 'provider-initialization'
