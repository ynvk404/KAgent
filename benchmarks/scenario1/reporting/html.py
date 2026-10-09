"""Offline, self-contained report over frozen sanitized public projections only."""
from __future__ import annotations

import base64
import hashlib
from html import escape
import json
import math
import re

from benchmarks.common.contracts import CLASSES, PARTITIONS
from .aggregate import groups, rate_parts
from .thesis import format_decimal, render_thesis_tables, resource_summary

RESOURCE_FIELDS = (
    'input_tokens', 'output_tokens', 'total_tokens', 'cached_input_tokens',
    'cache_creation_input_tokens', 'llm_calls', 'tool_proposed', 'tool_executed',
    'tool_blocked', 'tool_failed', 'tool_result_events', 'http_admitted',
    'http_dispatch_attempts', 'agent_seconds', 'wall_seconds',
)
CASE_FIELDS = (
    'case_id', 'vulnerability_class', 'expected_vulnerable', 'agent_outcome',
    'evaluator_partition', 'confusion', 'final_status', 'agent_seconds', 'wall_seconds',
    'input_tokens', 'output_tokens', 'total_tokens', 'llm_calls', 'tool_proposed',
    'tool_executed', 'tool_blocked', 'tool_failed', 'tool_result_events',
    'http_admitted', 'http_dispatch_attempts', 'evaluator_reason',
)
METHOD = (
    'Execution completed is a parent lifecycle status, not an evaluator verdict. Evaluable means a completed '
    'execution with an accepted agent assessment. Unresolved, execution-failed, invalid-result and not-run '
    'are excluded from TP/TN/FP/FN; they are never substituted for TN or FN.',
    'TP/TN/FP/FN compare the agent assessment with benchmark ground truth only. A TP is not independent '
    'verification of exploit impact. Observed HTTP evidence, agent conclusion and evaluator classification '
    'are displayed separately. Ground truth is used only after execution.',
    'Recall = TP/(TP+FN); Precision = TP/(TP+FP); FPR = FP/(FP+TN); '
    'Evaluability = evaluable/scheduled. A zero denominator gives NA. SQLi and XSS use their own denominators.',
    'Agent time covers Agent.run and its drained background work, excluding setup, freeze/export and teardown. '
    'Worker wall time covers parent launch through export parsing, excluding resets; it is not agent time. '
    'Total benchmark wall time is unavailable in historical frozen records; worker times must not be substituted.',
    'Token totals require usage for every recorded LLM request and a complete request ledger. '
    'Input, output and total tokens are independent provider measurements; total is never inferred by summing '
    'input/output. Observed partial sums are shown separately and excluded from complete-total statistics.',
    'Cache read (cached_input_tokens) and cache write (cache_creation_input_tokens) are provider-reported tokens '
    'from the existing request ledger. Missing fields or incomplete request coverage give NA, not zero. '
    'Cache hit/miss request counts are unavailable; token counts do not imply such counts. Providers or older '
    'records that omit cache usage leave a collection gap.',
    'LLM calls are application requests, including compaction and final synthesis, not transport retries. '
    'Tools proposed, executed, blocked, failed and result events have separate boundaries. Executed counts '
    'calls admitted to execution, including failures, excluding the harness Candidate creation. '
    'HTTP admitted counts permission reservations; dispatch attempts count transport handoffs and retries '
    'and do not certify receipt by the server.',
    'Resource sample sizes are n/N available measurements / scheduled cases, including retained measurements '
    'for unsuccessful executions. A total exists only when every scheduled case has a measurement and N > 0. '
    'Mean/median/p95 use available measurements, never missing-as-zero. Completed-case chart medians use only '
    'parent-completed cases; p95 is nearest-rank ceil(0.95*n), which can be the maximum in a small sample.',
    'Selected evidence is bounded sanitized response text, not a raw transcript or full request/response. '
    'Byte ranges refer to original canonical bodies; public SHA-256 binds UTF-8 content after sanitization. '
    'Canonical source and body hashes, pointers and pseudonymous observation references preserve provenance. '
    'Free-form internal reasoning and individual tool transcripts are withheld; absent finding information is NA.',
    'Source revisions and provider/model identities follow the existing pseudonymous public metadata policy. '
    'Manifest, evaluation, dataset and configuration hashes bind the frozen input and effective limits. '
    'Official is an operator designation, not scientific certification. Logical reset coverage is partial: '
    'external filesystem/process/LDAP effects and full ORM cache parity are not certified.',
)

STYLE = """
:root{font-family:system-ui,sans-serif;color:#172335;background:#f4f6f9;line-height:1.5}
body{margin:0}main{max-width:1400px;margin:auto;padding:24px}h1{margin-bottom:4px}
h2{margin-top:0}section{background:white;border:1px solid #dce2e9;border-radius:10px;padding:22px;margin:20px 0}
nav{display:flex;gap:14px;flex-wrap:wrap}a{color:#195cc8}p{max-width:100ch}.muted{color:#526174}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{padding:9px;text-align:left;border-bottom:1px solid #e1e6ed;vertical-align:top}
th{background:#eef3fa;white-space:nowrap}button,input,select{font:inherit;padding:7px;border:1px solid #b5c2d3;border-radius:5px;background:white;color:inherit}
button,summary{cursor:pointer}label{display:inline-flex;gap:8px;align-items:center;margin:4px 12px 8px 0}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,500px),1fr));gap:20px}
figure{margin:0;border:1px solid #dce2e9;padding:12px;min-width:0}figure svg{width:100%;height:auto}
figcaption{font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;background:#f3f6fa;padding:12px;border-radius:5px}
.details td{padding:0 12px 14px}details{margin:8px 0}summary{font-weight:600}.badge{font-weight:600}
.details details{max-width:min(88vw,1250px)}
[hidden]{display:none!important}footer{color:#526174;font-size:13px}
@media(max-width:600px){main{padding:10px}section{padding:12px}h1{font-size:24px}}
@media print{body{background:white}main{max-width:none;padding:0}section{break-inside:avoid;border:0;padding:8px}nav,.controls,button{display:none}pre{font-size:9px}figure{break-inside:avoid}table{font-size:9px}}
"""
SCRIPT = """
const table=document.getElementById('cases');
const search=document.getElementById('search');
const cls=document.getElementById('class-filter');
const part=document.getElementById('partition-filter');
function filter(){let count=0;for(const body of table.tBodies){const show=body.dataset.search.includes(search.value.toLowerCase())&&(!cls.value||body.dataset.class===cls.value)&&(!part.value||body.dataset.partition===part.value);body.hidden=!show;if(show)count++;}document.getElementById('visible-count').textContent=count+' cases visible';}
for(const control of [search,cls,part])control.addEventListener('input',filter);
for(const button of document.querySelectorAll('.open-case'))button.addEventListener('click',()=>{const detail=document.getElementById(button.dataset.detail);detail.open=!detail.open;button.setAttribute('aria-expanded',String(detail.open));});
const data=JSON.parse(document.getElementById('report-data').textContent);
const cases=new Map(data.cases.map(row=>[row.case_id,row]));
let direction=1,last='';
for(const button of document.querySelectorAll('[data-sort]'))button.addEventListener('click',()=>{const key=button.dataset.sort;direction=last===key?-direction:1;last=key;const bodies=Array.from(table.tBodies);bodies.sort((a,b)=>{const x=cases.get(a.dataset.case)[key],y=cases.get(b.dataset.case)[key];if(x==null)return y==null?0:1;if(y==null)return -1;const cmp=typeof x==='number'&&typeof y==='number'?x-y:String(x).localeCompare(String(y));return direction*cmp;});for(const body of bodies)table.appendChild(body);});
filter();
"""


def _cell(value):
    if value is None:
        return 'NA'
    if type(value) is bool:
        return 'Yes' if value else 'No'
    return escape(str(value))


def _pre(value):
    return '<pre>' + escape(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)) + '</pre>'


def _table(headers, rows):
    return '<div class="scroll"><table><thead><tr>' + ''.join('<th>' + escape(h) + '</th>' for h in headers) + '</tr></thead><tbody>' + ''.join(
        '<tr>' + ''.join('<td>' + _cell(v) + '</td>' for v in row) + '</tr>' for row in rows) + '</tbody></table></div>'


def _resources(cases):
    rows = []
    for label, cls in (('SQLi', CLASSES[0]), ('XSS', CLASSES[1]), ('Overall', None)):
        selected = [row for row in cases if cls is None or row['vulnerability_class'] == cls]
        for metric in RESOURCE_FIELDS:
            measured = []
            for row in selected:
                value = row.get(metric)
                if metric in {'cached_input_tokens', 'cache_creation_input_tokens'}:
                    value = row['usage'][metric]['total']
                measured.append({('agent_seconds' if metric == 'wall_seconds' else metric): value,
                                 'total_tokens_complete': row.get('total_tokens_complete')})
            stats = resource_summary(measured, 'agent_seconds' if metric == 'wall_seconds' else metric)
            total = stats.total if type(stats.total) is not float or math.isfinite(stats.total) else None
            rows.append([label, metric, stats.coverage, total,
                         *[format_decimal(v) for v in (stats.mean, stats.median, stats.p95)]])
    return rows


def render_html(model, cases: list[dict], charts: dict[str, bytes], *, output_files: list[str]) -> bytes:
    """All content is escaped; only locally generated chart SVG is inserted as markup."""
    resources = _resources(cases)
    thesis = render_thesis_tables(model).decode('utf-8')
    payload = {'metadata': model.metadata, 'metrics': model.metrics, 'cases': cases,
               'resource_statistics': [[str(v) if v is not None else None for v in row] for row in resources],
               'methodology': METHOD, 'thesis_tables_and_captions': thesis, 'output_files': output_files}
    # Inert JSON cannot close its script element, including hostile evidence.
    embedded = json.dumps(payload, sort_keys=True, ensure_ascii=True, allow_nan=False).replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e')
    script_hash = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    inline_charts = {}
    styles = [STYLE]
    for index, (name, raw) in enumerate(sorted(charts.items())):
        chart_id = f'chart-{index}'
        def scoped_style(match):
            css = re.sub(r'([^{}]+)\{', lambda rule: ','.join(
                f'#{chart_id} {selector.strip()}' for selector in rule[1].split(',')) + '{', match[1])
            styles.append(css)
            return '<style>' + css + '</style>'
        svg = re.sub(r'<style>(.*?)</style>', scoped_style, raw.decode('utf-8'), flags=re.DOTALL)
        inline_charts[name] = svg.replace('<svg ', f'<svg id="{chart_id}" ', 1)
    style_sources = ' '.join("'sha256-" + base64.b64encode(hashlib.sha256(css.encode()).digest()).decode() + "'" for css in sorted(set(styles)))
    csp = f"default-src 'none'; script-src 'sha256-{script_hash}'; style-src {style_sources}; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
    parts = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             f'<meta http-equiv="Content-Security-Policy" content="{escape(csp, quote=True)}">',
             '<title>KAgent — Scenario 1 Benchmark</title><style>' + STYLE + '</style></head><body><main>',
             '<h1>KAgent — Scenario 1 Benchmark</h1>',
             '<p class="badge">' + escape(f'{"Smoke" if model.metadata["mode"] == "smoke" else model.metadata["mode"].title()} / {model.metadata["classification"].title()}') + '</p>',
             '<nav><a href="#overview">Overview</a><a href="#charts">Charts</a><a href="#resources">Resources</a><a href="#case-results">Cases &amp; evidence</a><a href="#methodology">Methodology</a></nav>',
             '<section id="overview"><h2>Overview</h2>',
             '<p>Frozen post-run evaluation. Execution completion, agent assessment and benchmark classification are separate.</p>']
    overview = []
    for label, group in groups(model):
        overview.append([label, *[group[k] for k in ('scheduled', 'evaluable', *PARTITIONS[1:], 'TP', 'TN', 'FP', 'FN')]])
    parts.append(_table(('Class', 'Scheduled', 'Evaluable', 'Unresolved', 'Failed', 'Invalid', 'Not run', 'TP', 'TN', 'FP', 'FN'), overview))
    counts = model.metadata['lifecycle_counts']
    parts.append('<p>Scheduled: ' + _cell(counts['scheduled']) + ' · Started: ' + _cell(counts['started']) + ' · Execution completed: ' + _cell(counts['completed']) + ' · Execution state: ' + _cell(model.metadata.get('execution_state')) + '</p>')
    rate_rows = []
    for label, group in groups(model):
        for name in ('recall', 'precision', 'fpr', 'evaluability'):
            n, d = rate_parts(group, name)
            rate_rows.append([label, name, 'NA' if group[name] is None else f'{100 * group[name]:.2f}%', n, d])
    parts.append(_table(('Class', 'Metric', 'Value', 'Numerator', 'Denominator'), rate_rows))
    parts.append('<h3>Dataset provenance</h3>' + _pre({k: model.metadata[k] for k in ('dataset', 'dataset_identity', 'manifest_sha256', 'manifest_identity', 'evaluation_identity')}) + '</section>')
    parts.append('<section id="charts"><h2>Charts</h2><p>All charts are embedded below. Standalone SVG links work offline.</p><div class="charts">')
    for name, raw in sorted(charts.items()):
        title = name.rsplit('/', 1)[-1].removesuffix('.svg').replace('-', ' ').title()
        parts.append('<figure><figcaption>' + escape(title) + '</figcaption>' + inline_charts[name] + '<a download href="report/' + escape(name, quote=True) + '">Standalone SVG</a></figure>')
    parts.append('</div></section><section id="resources"><h2>Resource usage</h2><p>n/N = measured / scheduled cases. Totals require every case; distributions use available measurements. NA means unavailable. Times are seconds.</p>')
    parts.append(_table(('Class', 'Measurement', 'n/N', 'Complete total', 'Mean', 'Median', 'p95'), resources))
    coverage = []
    for label, cls in (('SQLi', CLASSES[0]), ('XSS', CLASSES[1]), ('Overall', None)):
        selected = [c for c in cases if cls is None or c['vulnerability_class'] == cls]
        for field in ('input_tokens', 'output_tokens', 'total_tokens'):
            coverage.append([label, field, sum(c[field + '_complete'] is True for c in selected),
                             sum(c[field + '_complete'] is False for c in selected),
                             sum(c[field + '_complete'] is None for c in selected), len(selected)])
    parts.append(_table(('Class', 'Token measurement', 'Complete', 'Partial', 'Unknown', 'Scheduled'), coverage))
    completed_rows = []
    for label, cls in (('SQLi', CLASSES[0]), ('XSS', CLASSES[1]), ('Overall', None)):
        selected = [c for c in cases if c['final_status'] == 'completed' and (cls is None or c['vulnerability_class'] == cls)]
        for field in ('agent_seconds', 'total_tokens'):
            stat = resource_summary(selected, field)
            completed_rows.append([label, field, stat.coverage, *[format_decimal(v) for v in (stat.mean, stat.median, stat.p95)], stat.minimum, stat.maximum])
    parts.append('<h3>Completed-case distributions used by the thesis charts</h3>' + _table(('Class', 'Measurement', 'n/completed', 'Mean', 'Median', 'p95', 'Min', 'Max'), completed_rows))
    parts.append('<p>Cache read/write tokens are reported only where present in the provider request ledger. Cache hit/miss counts: NA — not collected. Partial sums and request coverage appear in each case.</p></section>')
    parts.append('<section id="case-results"><h2>Per-case results and evidence</h2><div class="controls"><label>Search <input id="search" type="search"></label><label>Class <select id="class-filter"><option value="">All</option><option value="sql-injection">SQLi</option><option value="cross-site-scripting">XSS</option></select></label><label>Partition <select id="partition-filter"><option value="">All</option>' + ''.join('<option>' + escape(p) + '</option>' for p in PARTITIONS) + '</select></label><span id="visible-count"></span></div>')
    parts.append('<p>Click a case to expand its details. Column buttons sort; missing values sort last. Details remain accessible without JavaScript.</p><div class="scroll"><table id="cases"><thead><tr>')
    parts.extend('<th><button data-sort="' + field + '">' + escape(field.replace('_', ' ')) + '</button></th>' for field in CASE_FIELDS)
    parts.append('</tr></thead>')
    for index, case in enumerate(cases):
        detail_id = f'case-detail-{index}'
        searchable = ' '.join(str(case.get(k) or '') for k in CASE_FIELDS).lower()
        attrs = {'case': case['case_id'], 'class': case['vulnerability_class'], 'partition': case['evaluator_partition'], 'search': searchable}
        parts.append('<tbody ' + ' '.join(f'data-{key}="{escape(value, quote=True)}"' for key, value in attrs.items()) + '><tr>')
        parts.append(f'<td><button class="open-case" data-detail="{detail_id}" aria-expanded="false">{escape(case["case_id"])}</button></td>')
        parts.extend('<td>' + _cell(case.get(field)) + '</td>' for field in CASE_FIELDS[1:])
        parts.append(f'</tr><tr class="details"><td colspan="{len(CASE_FIELDS)}"><details id="{detail_id}"><summary>Details: {escape(case["case_id"])}</summary>')
        for title, data in (
            ('1. Benchmark ground truth (post-run only)', case['ground_truth']),
            ('Original execution input (sanitized)', case['input']),
            ('2. Agent assessment and limitations', {'conclusion': case['conclusion'], 'assessment': case['assessment'], 'persisted_finding': case['persisted_finding']}),
            ('4. Evaluator classification', {k: case[k] for k in ('evaluator_partition', 'evaluator_reason', 'confusion', 'final_status', 'worker_status')}),
            ('Token completeness, partial measurements and cache coverage', case['usage']),
            ('Tool failures and blocked operations', case['tool_diagnostics']),
            ('Canonical identity bindings', case['canonical']),
        ):
            parts.append('<h3>' + escape(title) + '</h3>' + _pre(data))
        parts.append('<h3>3. Actual observed evidence (sanitized)</h3>')
        if not case['selected_evidence']:
            parts.append('<p>NA — no eligible selected HTTP evidence in the frozen public projection.</p>')
        for item in case['selected_evidence']:
            parts.append(_pre({k: v for k, v in item.items() if k != 'content'}))
            parts.append('<pre>' + escape(item['content']) + '</pre>')
        parts.append('</details></td></tr></tbody>')
    parts.append('</table></div></section><section id="methodology"><h2>Reproducibility and methodology</h2>')
    parts.extend('<p>' + escape(text) + '</p>' for text in METHOD)
    parts.append('<h3>Complete public runtime metadata</h3>' + _pre(model.metadata))
    parts.append('<details><summary>Original thesis tables and figure captions</summary><pre>' + escape(thesis) + '</pre></details>')
    parts.append('</section><footer>Sanitized projection; canonical execution data remains in project-local internal storage.</footer>')
    parts.append('<script type="application/json" id="report-data">' + embedded + '</script><script>' + SCRIPT + '</script></main></body></html>')
    return ''.join(parts).encode('utf-8')
