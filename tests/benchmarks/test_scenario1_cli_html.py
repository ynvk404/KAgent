"""Offline CLI/UX regressions. No Docker, network transport or real LLM calls."""
from __future__ import annotations

from dataclasses import asdict, replace
import base64
from html.parser import HTMLParser
from io import StringIO
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from benchmarks.common.contracts import CaseExecution, digest, file_hash, read_json, write_new
from benchmarks.common.recorder import read_records
from benchmarks.scenario1 import config
from benchmarks.scenario1.__main__ import main, parser
from benchmarks.scenario1.core import runner
from benchmarks.scenario1.core.dataset import select
from benchmarks.scenario1.core.evaluate import evaluate
from benchmarks.scenario1.core.storage import allocate_run, bind_storage, resolve_run
from benchmarks.scenario1.progress import Progress
from benchmarks.scenario1.reporting import writer
from benchmarks.scenario1.reporting.loader import load_report
from benchmarks.scenario1.reporting.projection import _evidence, _usage, index_file, json_bytes, result_files
from tests.benchmarks.test_scenario1 import make_dataset, op, settings, single_manifest
from tests.benchmarks.test_scenario1_reset import Controller
from tests.benchmarks.test_scenario1_storage import frozen, html_payload
from tests.benchmarks.test_scenario1_reporting import _fixture


@pytest.fixture
def lab(tmp_path):
    dataset = make_dataset(tmp_path / 'dataset', per_stratum=10)
    for name, mode in (('smoke', 'smoke'), ('official', 'reduced')):
        write_new(tmp_path / f'{name}.json', asdict(select(dataset, name, mode)))
    (tmp_path / 'reset.war').write_bytes(b'offline fixture')
    path = tmp_path / 'lab.toml'
    path.write_text('''[lab]
dataset = "dataset"
target = "http://127.0.0.1:18080"
context_path = "/benchmark"
target_state = "external-reset"
authorized_lab = true
container = "explicit-fixture"
ingress_container = "explicit-ingress"
reset_war = "reset.war"
[manifests]
smoke = "smoke.json"
official = "official.json"
[output]
root = "public"
[limits]
timeout = 9
http_requests = 5
tool_calls = 11
agent_calls = 6
''')
    return path, dataset


@pytest.mark.parametrize('mode,count,kind', [('smoke', 12, 'development'), ('official', 40, 'official')])
def test_short_profiles_default_config_and_explicit_ack(lab, monkeypatch, capsys, mode, count, kind):
    path, _ = lab
    monkeypatch.setattr(config, 'DEFAULT_CONFIG', path)
    invocation = ['run', '--mode', mode, '--authorized-lab', '--dry-run']
    args = parser().parse_args(invocation)
    meta = config.resolve_config(args, invocation)
    assert args.manifest == path.parent / f'{mode}.json'
    assert args.run_kind == kind
    assert args.timeout == 9 and args.http_requests == 5
    assert args.container == 'explicit-fixture' and args.reset_war == path.parent / 'reset.war'
    assert meta['selection_file_sha256'] == file_hash(args.manifest)
    assert meta['configuration_sha256'] == file_hash(path)
    assert main(invocation) == 0
    output = json.loads(capsys.readouterr().out)
    assert len(output['cases']) == count
    assert output['runtime']['authorized_lab'] is True
    assert main(['run', '--mode', mode, '--dry-run']) == 2
    assert 'explicit --authorized-lab declaration required' in capsys.readouterr().err
    assert not (path.parent / 'public').exists()


def test_cli_override_precedence_and_unique_paths(lab):
    path, _ = lab
    invocation = ['run', '--mode', 'smoke', '--config', str(path), '--timeout=23',
                  '--target', 'http://127.0.0.1:18081', '--http-requests', '7', '--authorized-lab']
    first, second = [parser().parse_args(invocation) for _ in range(2)]
    config.resolve_config(first, invocation)
    config.resolve_config(second, invocation)
    assert first.timeout == 23 and first.http_requests == 7
    assert first.target == 'http://127.0.0.1:18081'
    assert first.output != second.output and first.output.parent == path.parent / 'public'
    first.output.mkdir(parents=True)
    explicit = invocation + ['--output', str(first.output)]
    with pytest.raises(ValueError, match='refusing to overwrite'):
        config.resolve_config(parser().parse_args(explicit), explicit)
    abbreviated = invocation + ['--tool-call', '15']
    args = parser().parse_args(abbreviated)
    config.resolve_config(args, abbreviated)
    assert args.tool_calls == 15


@pytest.mark.parametrize('mutation,message', [
    ('invalid', 'invalid Scenario 1 TOML'), ('section', 'unknown Scenario 1 TOML section'),
    ('type', 'invalid type'), ('dataset', '--dataset'), ('war', '--reset-war'),
    ('manifest', '--manifest'), ('authorization', 'explicitly describe an authorized lab'),
    ('missing-official', 'explicitly frozen manifest'),
])
def test_config_errors_fail_before_execution(lab, monkeypatch, capsys, mutation, message):
    path, _ = lab
    value = path.read_text()
    changes = {'invalid': '[broken', 'section': value + '\n[secrets]\nkey="hidden"',
               'type': value.replace('timeout = 9', 'timeout = true'),
               'dataset': value.replace('dataset = "dataset"', 'dataset = "missing"'),
               'war': value.replace('reset.war', 'missing.war'),
               'manifest': value.replace('official.json', 'missing.json'),
               'authorization': value.replace('authorized_lab = true', 'authorized_lab = false'),
               'missing-official': value.replace('official = "official.json"', '')}
    path.write_text(changes[mutation])
    monkeypatch.setattr(runner, 'run', lambda *_a, **_kw: pytest.fail('execution reached'))
    assert main(['run', '--mode', 'official', '--config', str(path), '--authorized-lab']) == 2
    assert message in capsys.readouterr().err


def test_missing_config_and_profile_conflicts(lab, monkeypatch, capsys):
    path, _ = lab
    monkeypatch.setattr(config, 'DEFAULT_CONFIG', path.parent / 'missing.toml')
    assert main(['run', '--mode', 'smoke']) == 2
    assert 'copy config.example.toml' in capsys.readouterr().err
    for extra, message in [(['--run-kind', 'official'], 'classifications conflict'),
                           (['--case', 'BenchmarkTest00001'], 'frozen --manifest'),
                           (['--manifest', str(path.parent / 'official.json')], '12-case smoke')]:
        assert main(['run', '--mode', 'smoke', '--config', str(path), '--authorized-lab', '--dry-run', *extra]) == 2
        assert message in capsys.readouterr().err
    assert main(['run', '--mode', 'official', '--config', str(path), '--manifest', str(path.parent / 'smoke.json'), '--authorized-lab', '--dry-run']) == 2
    assert 'frozen reduced 40-case' in capsys.readouterr().err


def test_legacy_long_form_and_no_silent_config(lab, monkeypatch, capsys):
    path, dataset = lab
    monkeypatch.setattr(config, 'DEFAULT_CONFIG', path)
    assert main(['run', '--dataset', str(dataset.root), '--manifest', str(path.parent / 'smoke.json'),
                 '--target', 'http://127.0.0.1:18080', '--context-path', '/benchmark', '--target-state',
                 'confirmation-only', '--authorized-lab', '--dry-run']) == 0
    assert json.loads(capsys.readouterr().out)['runtime']['timeout_seconds'] == 180


def test_unfrozen_or_changed_official_manifest_rejected(lab, capsys):
    path, _ = lab
    manifest = read_json(path.parent / 'official.json')
    manifest['execution_order'].reverse()
    (path.parent / 'official.json').write_bytes(json_bytes(manifest))
    assert main(['run', '--mode', 'official', '--config', str(path), '--authorized-lab', '--dry-run']) == 2
    assert 'deterministic execution order' in capsys.readouterr().err


def test_toml_paths_preserve_symlink_rejection_and_reset_override(lab, capsys):
    path, _ = lab
    (path.parent / 'smoke-link.json').symlink_to('smoke.json')
    path.write_text(path.read_text().replace('smoke = "smoke.json"', 'smoke = "smoke-link.json"'))
    assert main(['run', '--mode', 'smoke', '--config', str(path), '--authorized-lab', '--dry-run']) == 2
    assert '--manifest must name an existing regular file' in capsys.readouterr().err
    path.write_text(path.read_text().replace('smoke-link.json', 'smoke.json'))
    state = path.parent / 'reset-state.json'
    write_new(state, {})
    invocation = ['run', '--mode', 'smoke', '--config', str(path), '--reset-state', str(state)]
    args = parser().parse_args(invocation)
    config.resolve_config(args, invocation)
    assert args.container is None and args.reset_war is None and args.ingress_container is None


@pytest.mark.parametrize('status,partition', [('completed', 'unresolved'), ('provider-error', 'execution-failed')])
def test_progress_is_real_lifecycle_and_keeps_json(tmp_path, monkeypatch, capsys, op, settings, status, partition):
    monkeypatch.setattr(runner, 'reproducibility', lambda: {'offline': True})
    stream = StringIO()  # Non-TTY receives ordinary flushed lines, no terminal escapes.
    manifest = single_manifest(op, settings)
    progress = Progress(manifest, settings, 'development', stream)
    def launcher(payload, _):
        write_new(Path(payload['output']), asdict(CaseExecution('run', op.case_id,
                  payload['execution_id'], status, None, None, None, {})))
        return 0, False
    root = runner.run(manifest, settings, tmp_path / 'public', launcher=launcher,
                      reset_controller=Controller(), observer=progress, invocation_metadata={'configuration_sha256': 'a' * 64})
    report = evaluate(root)
    progress.evaluated(report)
    text = stream.getvalue()
    assert f'[01/01] {op.case_id} | XSS' in text
    assert text.index('Reset before') < text.index('Agent running') < text.index('Result export') < text.index('Reset after')
    assert f'Execution      {status}' in text and 'evaluation pending' in text
    assert partition in text and 'Total elapsed:' in text and '\x1b' not in text
    assert read_json(root / 'manifest.json')['reproducibility']['invocation']['configuration_sha256'] == 'a' * 64
    assert [row['kind'] for row in read_records(root / 'events.jsonl')[0]] == ['scheduled', 'started', 'runtime-finished', 'evaluated']
    progress({'kind': 'evaluated', 'case_id': op.case_id, 'data': {'partition': 'invalid-result', 'reason': 'invalid-result'}})
    assert 'Evaluator      invalid-result' in stream.getvalue()


def test_reset_failure_and_observer_failure_do_not_change_execution(tmp_path, monkeypatch, op, settings):
    monkeypatch.setattr(runner, 'reproducibility', lambda: {})
    manifest = single_manifest(op, settings)
    stream = StringIO()
    progress = Progress(manifest, settings, 'development', stream)
    controller = Controller(fail=1)
    root = runner.run(manifest, settings, tmp_path / 'blocked', reset_controller=controller,
                      launcher=lambda *_: pytest.fail('worker admitted'), observer=progress)
    progress.evaluated(evaluate(root))
    assert 'Reset before  BLOCKED' in stream.getvalue()
    assert 'not-run' in stream.getvalue() and 'Agent running' not in stream.getvalue()
    def broken_observer(_):
        raise BrokenPipeError('closed progress')
    root = runner.run(manifest, settings, tmp_path / 'second', launcher=lambda *_: (-9, False), observer=broken_observer)
    assert evaluate(root)['records'][0]['partition'] == 'execution-failed'


@pytest.mark.parametrize('progress', ['auto', 'none'])
def test_cli_stdout_json_and_progress_stderr(tmp_path, monkeypatch, capsys, op, settings, progress):
    dataset = make_dataset(tmp_path / 'dataset')
    manifest = select(dataset, 'run', case_id=dataset.truth[0].case_id)
    write_new(tmp_path / 'selection.json', asdict(manifest))
    reset_state = tmp_path / 'state.json'
    write_new(reset_state, {})
    from benchmarks.scenario1.reset import client
    monkeypatch.setattr(client, 'ResetController', lambda _: Controller())
    monkeypatch.setattr(runner, 'reproducibility', lambda: {})
    real = runner.run
    monkeypatch.setattr(runner, 'run', lambda *a, **kw: real(*a, **kw, launcher=lambda *_: (-9, False)))
    assert main(['run', '--dataset', str(dataset.root), '--manifest', str(tmp_path / 'selection.json'),
                 '--target', settings.target, '--context-path', settings.context_path, '--authorized-lab',
                 '--target-state', 'external-reset', '--reset-state', str(reset_state), '--progress', progress]) == 4
    out = capsys.readouterr()
    assert json.loads(out.out)['execution-failed'] == 1
    assert ('KAgent — Scenario 1 Benchmark' in out.err) == (progress == 'auto')


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.tags = []
        self.scripts = []
        self.script = None
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if tag == 'script':
            self.script = {'attrs': attrs, 'text': ''}
            self.scripts.append(self.script)

    def handle_endtag(self, tag):
        if tag == 'script':
            self.script = None

    def handle_data(self, data):
        if self.script is not None:
            self.script['text'] += data


def test_offline_html_all_charts_metrics_and_no_extra_files(tmp_path, op, settings):
    root, public, *_ = frozen(tmp_path, op, settings)
    before = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    writer.write_report(root)
    payload = html_payload(public)
    assert len(payload['cases']) == 1 and payload['cases'][0]['case_id'] == op.case_id
    assert 'T2C' not in payload['thesis_tables_and_captions']  # No unfinished execution in this fixture.
    assert 'T3' in payload['thesis_tables_and_captions']
    files = {p.relative_to(public).as_posix() for p in public.rglob('*') if p.is_file()}
    svgs = {f for f in files if f.endswith('.svg')}
    assert len(svgs) == 8
    assert files == {*svgs, 'index.html', 'results/index.json', f'results/{op.case_id}.json'}
    text = (public / 'index.html').read_text()
    document = Document(text)
    assert sum(tag == 'svg' for tag, _ in document.tags) == 8
    assert len(document.scripts) == 2
    assert all(not any(key.startswith('on') for key in attrs) for _, attrs in document.tags)
    assert all(not any(re.match(r'^(?:https?:)?//', value) for key, value in attrs.items() if key in {'src', 'href'}) for _, attrs in document.tags)
    assert 'fetch(' not in text and 'XMLHttpRequest' not in text and 'innerHTML' not in text
    assert 'connect-src &#x27;none&#x27;' in text
    assert payload['metadata']['lifecycle_counts'] == {'scheduled': 1, 'started': 1, 'completed': 1}
    assert 'NA' in text and 'Cache hit/miss counts: NA' in text
    rows = payload['resource_statistics']
    for field in ('input_tokens', 'output_tokens', 'total_tokens', 'llm_calls', 'tool_executed',
                  'tool_result_events', 'http_admitted', 'http_dispatch_attempts', 'agent_seconds',
                  'wall_seconds', 'cached_input_tokens', 'cache_creation_input_tokens'):
        assert sum(row[1] == field for row in rows) == 3
    assert next(row for row in rows if row[:2] == ['Overall', 'input_tokens'])[3] is None
    assert next(row for row in rows if row[:2] == ['Overall', 'output_tokens'])[3] == '7'
    for ref, raw in before.items():
        assert (root / ref).read_bytes() == raw
    assert resolve_run(public) == root
    second = tmp_path / 'second'
    writer.write_report(root, second)
    assert (second / 'index.html').read_bytes() == (public / 'index.html').read_bytes()


def test_embedded_hostile_evidence_is_bounded_redacted_and_inert(tmp_path, op, settings):
    root, public, *_ = frozen(tmp_path, op, settings)
    files = result_files(root, load_report(root))
    case = json.loads(files[f'results/{op.case_id}.json'])
    secret = 'sk-' + 'S' * 40
    hostile = '</script><script>globalThis.pwned=true</script><img src="https://bad.invalid" onerror="alert(1)">'
    body = (hostile + '\napi_key=' + secret + '\n/home/operator/private\n' + 'x' * 10000).encode()
    source = {'id': 'observation', 'source_kind': 'native-http', 'body': body.hex(), 'status': 200,
              'method': 'GET', 'complete': True, 'truncated': False}
    export = {'workflow': {'validation_results': [{'result_id': 'result',
              'evidence_manifest': [{'source': source, 'hash': digest(source)}]}]},
              'result_id': 'result', 'accepted_at_freeze': True}
    _, evidence = _evidence(export, op.case_id, {}, 2)
    case['selected_evidence'] = evidence
    from benchmarks.scenario1.reporting.charts import render_charts
    from benchmarks.scenario1.reporting.html import render_html
    html = render_html(load_report(root), [case], render_charts(load_report(root)), output_files=[]).decode()
    assert secret not in html and '/home/operator/private' not in html
    assert hostile not in html and '&lt;script&gt;globalThis.pwned' in html
    document = Document(html)
    assert len(document.scripts) == 2 and not any(tag == 'img' for tag, _ in document.tags)
    embedded = json.loads(document.scripts[0]['text'])
    proof = embedded['cases'][0]['selected_evidence'][0]
    assert hostile in proof['content'] and proof['truncated'] is True
    assert len(proof['content'].encode()) <= 8192 and 'public_ref' not in proof
    assert proof['public_sha256'] == hashlib.sha256(proof['content'].encode()).hexdigest()
    assert proof['canonical_body_sha256'] == hashlib.sha256(body).hexdigest()
    assert proof['canonical_source_sha256'] == digest(source)
    assert proof['http_status'] == 200 and proof['byte_range'] == [0, 8192]
    node = shutil.which('node')
    if node:
        script = tmp_path / 'report.js'
        script.write_text(document.scripts[1]['text'])
        checked = subprocess.run([node, '--check', str(script)], capture_output=True, text=True)
        assert checked.returncode == 0, checked.stderr


@pytest.mark.parametrize('complete,values,expected', [
    (True, [0, 3], 3), (True, [3, None], None), (False, [3, 4], None),
])
def test_cache_telemetry_only_provider_reported_complete_totals(op, complete, values, expected):
    execution = type('Diagnostic', (), {'metrics': {'llm': {
        'request_records_complete': complete,
        'requests': [{'usage': {'cached_input_tokens': v, 'cache_creation_input_tokens': 0}} for v in values],
    }}})()
    usage = _usage(execution)
    assert usage['cached_input_tokens']['total'] == expected
    assert usage['cached_input_tokens']['observed_sum'] == sum(v for v in values if v is not None)
    assert usage['cache_creation_input_tokens']['total'] == (0 if complete else None)
    assert _usage(None)['cached_input_tokens']['total'] is None
    assert _usage(None)['cached_input_tokens']['requests'] is None


def test_all_official_cases_pagination_filters_sorting_and_details(lab, tmp_path, settings):
    _, dataset = lab
    manifest = replace(select(dataset, 'official-view', 'reduced'), runtime=asdict(settings))
    first, second, third = manifest.execution_order[:3]
    legacy, _ = _fixture(tmp_path, manifest, classification='official',
        partitions={first: 'not-run', second: 'unresolved', third: 'invalid-result'})
    public = tmp_path / 'official-report'
    root = allocate_run(public)
    for path in legacy.rglob('*'):
        if path.is_file():
            ref = path.relative_to(legacy)
            target = root / 'evaluations' / ref if ref.name.startswith('evaluation-') else root / ref
            target.parent.mkdir(exist_ok=True, parents=True)
            target.write_bytes(path.read_bytes())
    bind_storage(root, public)
    writer.write_report(root)
    payload = html_payload(public)
    assert [c['case_id'] for c in payload['cases']] == manifest.execution_order
    assert len(list((public / 'report/charts').glob('*.svg'))) == 10
    text = (public / 'index.html').read_text()
    document = Document(text)
    bodies = [attrs for tag, attrs in document.tags if tag == 'tbody' and 'data-case' in attrs]
    assert len(bodies) == 40
    assert payload['metadata']['lifecycle_counts']['completed'] == 39
    csp = next(attrs['content'] for tag, attrs in document.tags if tag == 'meta' and attrs.get('http-equiv') == 'Content-Security-Policy')
    for style in re.findall(r'<style>(.*?)</style>', text, re.DOTALL):
        hashed = base64.b64encode(hashlib.sha256(style.encode()).digest()).decode()
        assert f"'sha256-{hashed}'" in csp
    hashed = base64.b64encode(hashlib.sha256(document.scripts[1]['text'].encode()).digest()).decode()
    assert f"'sha256-{hashed}'" in csp
    node = shutil.which('node')
    if not node:
        pytest.skip('Node unavailable for report interaction verification')
    # Execute the actual report script against a small DOM surface, with no network.
    harness = '''const assert=require('node:assert/strict');
const controls=Object.fromEntries(['search','class-filter','partition-filter'].map(id=>[id,{value:'',listeners:{},addEventListener(event,fn){this.listeners[event]=fn;}}]));
const table={tBodies:fixture.cases.map(c=>({dataset:{case:c.case_id,class:c.vulnerability_class,partition:c.evaluator_partition,search:Object.values(c).join(' ').toLowerCase()},hidden:false})),appendChild(body){this.tBodies.splice(this.tBodies.indexOf(body),1);this.tBodies.push(body);}};
const counter={textContent:''};
const details=Object.fromEntries(fixture.cases.map((c,i)=>['case-detail-'+i,{open:false}]));
const opens=fixture.cases.map((c,i)=>({dataset:{detail:'case-detail-'+i},listeners:{},addEventListener(event,fn){this.listeners[event]=fn;},setAttribute(){}}));
const sorts=['case_id','agent_seconds'].map(key=>({dataset:{sort:key},listeners:{},addEventListener(event,fn){this.listeners[event]=fn;}}));
const document={getElementById(id){if(id==='cases')return table;if(id==='visible-count')return counter;if(id==='report-data')return {textContent:JSON.stringify(fixture)};return controls[id]||details[id];},querySelectorAll(selector){return selector==='.open-case'?opens:sorts;}};
function runReport(){SCRIPT_BODY}
runReport();
assert.equal(counter.textContent,'40 cases visible');
controls.search.value=fixture.cases[0].case_id;controls.search.listeners.input();
assert.equal(table.tBodies.filter(b=>!b.hidden).length,1);
controls.search.value='';controls['class-filter'].value='sql-injection';controls.search.listeners.input();
assert.equal(table.tBodies.filter(b=>!b.hidden).length,20);
controls['class-filter'].value='';controls['partition-filter'].value='not-run';controls.search.listeners.input();
assert.equal(table.tBodies.filter(b=>!b.hidden).length,1);
sorts[0].listeners.click();
assert.deepEqual(table.tBodies.map(b=>b.dataset.case),fixture.cases.map(c=>c.case_id).sort((a,b)=>a.localeCompare(b)));
sorts[0].listeners.click();
assert.deepEqual(table.tBodies.map(b=>b.dataset.case),fixture.cases.map(c=>c.case_id).sort((a,b)=>b.localeCompare(a)));
sorts[1].listeners.click();assert.equal(table.tBodies.at(-1).dataset.case,fixture.cases[0].case_id);
opens[0].listeners.click();assert.equal(details['case-detail-0'].open,true);
opens[0].listeners.click();assert.equal(details['case-detail-0'].open,false);
'''
    script = tmp_path / 'interactions.js'
    script.write_text('const fixture=' + json.dumps(payload) + ';\n' + harness.replace('SCRIPT_BODY', document.scripts[1]['text']))
    checked = subprocess.run([node, str(script)], capture_output=True, text=True)
    assert checked.returncode == 0, checked.stderr


def test_opt_in_companions_and_legacy_v1_resolution(tmp_path, op, settings):
    root, public, *_ = frozen(tmp_path, op, settings)
    writer.write_report(root, export_csv=True)
    assert {'summary.csv', 'per-case.csv', 'partitions.csv', 'abnormal-analysis-template.csv',
            'thesis-tables.md', 'report.json'} <= {p.name for p in (public / 'report').iterdir()}
    assert resolve_run(public) == root
    legacy_public = tmp_path / 'legacy-public'
    model = load_report(root)
    files = {f'report/{name}': raw for name, raw in writer._render(model).items()}
    files.update(result_files(root, model, version=1))
    index = json.loads(index_file(root, legacy_public, model, files))
    index['schema'] = 'scenario1-public-results-v1'
    index['binding'] = digest({k: v for k, v in index.items() if k != 'binding'})
    files['results/index.json'] = json_bytes(index)
    for ref, raw in files.items():
        target = legacy_public / ref
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    assert resolve_run(legacy_public) == root
    assert read_json(legacy_public / 'results' / f'{op.case_id}.json')['schema'] == 'scenario1-public-case-v1'


def test_rebound_embedded_evidence_cannot_bypass_canonical_projection(tmp_path, op, settings):
    root, public, *_ = frozen(tmp_path, op, settings)
    writer.write_report(root)
    path = public / 'results' / f'{op.case_id}.json'
    case = read_json(path)
    case['selected_evidence'] = [{'content': 'invented evidence'}]
    case['projection_binding'] = digest({k: v for k, v in case.items() if k != 'projection_binding'})
    path.write_bytes(json_bytes(case))
    index_path = public / 'results/index.json'
    index = read_json(index_path)
    index['files'][f'results/{op.case_id}.json'] = file_hash(path)
    index['binding'] = digest({k: v for k, v in index.items() if k != 'binding'})
    index_path.write_bytes(json_bytes(index))
    with pytest.raises(ValueError, match='public/canonical projection binding mismatch'):
        resolve_run(public)
