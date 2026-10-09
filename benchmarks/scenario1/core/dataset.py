"""Truth stays in the parent. Mapping inspects request plumbing, not sinks."""
from __future__ import annotations

from dataclasses import asdict
import csv
from html.parser import HTMLParser
from pathlib import Path
import re
import subprocess
from urllib.parse import parse_qsl, urlsplit
import xml.etree.ElementTree as ET

from benchmarks.common.contracts import (CLASSES, DEFAULT_SEED, GroundTruth, MAPPING,
                                        OperationalCaseInput, RunManifest, SELECTION, digest, file_hash)

TRUTH = 'expectedresults-1.2.csv'
CRAWLER = 'data/benchmark-crawler-http.xml'
JAVA = 'src/main/java/org/owasp/benchmark/testcode'
HELPER = 'src/main/java/org/owasp/benchmark/helpers/SeparateClassRequest.java'
DATASET_CATEGORIES = {'cmdi', 'crypto', 'hash', 'ldapi', 'pathtraver', 'securecookie',
                      'sqli', 'trustbound', 'weakrand', 'xpathi', 'xss'}
# Public names map to the existing v1 wire values; hashes/identities stay intact.
SELECTION_MODES = {'smoke': 'smoke', 'official': 'reduced'}


class MappingError(ValueError):
    pass


class Forms(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.forms.append(attrs)


def parse_truth(path: Path) -> tuple[str, list[GroundTruth]]:
    lines = path.read_text(encoding='utf-8-sig').splitlines()
    if not lines or not lines[0].startswith('#'):
        raise ValueError('missing Benchmark truth header')
    version = re.search(r'Benchmark version:\s*([^,\s]+)', lines[0])
    if not version:
        raise ValueError('missing dataset version')
    seen = set()
    results = []
    for number, row in enumerate(csv.reader(lines[1:]), 2):
        if len(row) != 4 or not re.fullmatch(r'BenchmarkTest\d{5}', row[0]) or row[1] not in DATASET_CATEGORIES or row[2] not in {'true', 'false'} or not row[3].isdigit():
            raise ValueError(f'malformed truth row {number}')
        if row[0] in seen:
            raise ValueError(f'duplicate truth row {row[0]}')
        seen.add(row[0])
        cls = {'sqli': CLASSES[0], 'xss': CLASSES[1]}.get(row[1])
        if cls:
            results.append(GroundTruth(row[0], cls, row[2] == 'true', int(row[3]), f'{TRUTH}:{number}'))
    return version.group(1), sorted(results, key=lambda r: r.case_id)


class Dataset:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.version, self.truth = parse_truth(self.root / TRUTH)
        crawler = ET.parse(self.root / CRAWLER).getroot()
        if crawler.tag != 'benchmarkSuite' or crawler.get('version') != self.version:
            raise MappingError('crawler/truth dataset version mismatch')
        self.requests = {}
        for node in crawler:
            name = node.get('tcName')
            if not name or name in self.requests or node.tag != 'benchmarkTest' or node.get('tcType') != 'SERVLET':
                raise MappingError('invalid/duplicate crawler case')
            self.requests[name] = node
        self.hashes = {ref: file_hash(self.root / ref) for ref in (TRUTH, CRAWLER)}
        self.cache: dict[str, OperationalCaseInput] = {}
        self.state_effects: dict[str, bool] = {}

    def read(self, ref: str) -> str:
        path = self.root / ref
        if not path.is_file():
            raise MappingError(f'missing mapping artifact {ref}')
        self.hashes[ref] = file_hash(path)
        return path.read_text()

    def map(self, truth: GroundTruth) -> OperationalCaseInput:
        name = truth.case_id
        if name in self.cache:
            return self.cache[name]
        try:
            return self._map(truth)
        except (ValueError, KeyError, IndexError) as err:
            raise MappingError(f'{name}: {err}') from err

    def _map(self, truth: GroundTruth) -> OperationalCaseInput:
        name = truth.case_id
        node = self.requests[name]
        url = urlsplit(node.attrib['URL'])
        source = self.read(f'{JAVA}/{name}.java')
        # Read only plumbing into the mapper; none of this source reaches the worker.
        servlet = re.findall(r'@WebServlet\(value\s*=\s*"([^"]+)"\)', source)
        if len(servlet) != 1 or not url.path.endswith(servlet[0]):
            raise MappingError('servlet/crawler path mismatch')
        context = url.path[:-len(servlet[0])]
        if not context or not context.startswith('/'):
            raise MappingError('missing deployment context in crawler')
        query = [[k, v] for k, v in parse_qsl(url.query, keep_blank_values=True)]
        url_query = dict(query)
        if len(url_query) != len(query):
            raise MappingError('ambiguous duplicate URL query parameter')
        body: list[list[str]] = []
        headers, cookies = {}, {}
        locations = {'getparam': 'query', 'formparam': 'body', 'header': 'header', 'cookie': 'cookie'}
        entries = []
        parameter_names = {'query': set(), 'body': set()}
        for child in node:
            if child.tag not in locations or set(child.attrib) != {'name', 'value'}:
                raise MappingError('unsupported crawler input metadata')
            loc, key, val = locations[child.tag], child.attrib['name'], child.attrib['value']
            entries.append((loc, key, val))
            if loc in {'query', 'body'}:
                if key in parameter_names[loc]:
                    raise MappingError('ambiguous duplicate crawler parameter')
                parameter_names[loc].add(key)
                if key in url_query:
                    if loc == 'body':
                        raise MappingError('ambiguous URL query/form parameter mapping')
                    if url_query[key] != val:
                        raise MappingError('conflicting URL query/crawler parameter mapping')
                    # Identical URL/child metadata describes one occurrence.
                else:
                    (query if loc == 'query' else body).append([key, val])
            else:
                dest = headers if loc == 'header' else cookies
                if key in dest:
                    raise MappingError('duplicate header/cookie mapping')
                dest[key] = val
        kinds = {e[0] for e in entries}
        if len(kinds) != 1:
            raise MappingError('ambiguous mixed crawler source locations')
        location = next(iter(kinds))
        # Verify named access, map access, enumeration-of-names, or request helper.
        component = 'value'
        selected = []
        if location == 'header':
            accessed = set(re.findall(r'request\.getHeaders?\("([^"]+)"\)', source))
            selected = [e for e in entries if e[1] in accessed]
        elif location == 'cookie':
            if 'request.getCookies()' not in source:
                raise MappingError('crawler cookie has no servlet cookie reader')
            accessed = set(re.findall(r'getName\(\)\.equals\("([^"]+)"\)', source))
            selected = [e for e in entries if e[1] in accessed]
        else:
            accessed = set(re.findall(r'(?:request\.getParameter(?:Values)?|map\.get|scr\.getThe(?:Parameter|Value))\("([^"]+)"\)', source))
            if 'scr.getThe' in source:
                helper = self.read(HELPER)
                if not re.search(r'getTheParameter\(String p\).*?return request.getParameter\(p\);', helper, re.S):
                    raise MappingError('unsupported request helper implementation')
                if not re.search(r'getTheValue\(String p\).*?return "bar";', helper, re.S):
                    raise MappingError('unsupported constant fixture helper')
            if 'request.getParameterNames()' in source:
                markers = set(re.findall(r'value\.equals\("([^"]+)"\)', source))
                selected = [e for e in entries if e[2] in markers]
                component = 'name'
            elif 'request.getQueryString()' in source:
                if location != 'query':
                    raise MappingError('getQueryString requires query mapping')
                markers = set(re.findall(r'String paramval\s*=\s*"([^"]+)"\s*\+\s*"="', source))
                selected = [e for e in entries if e[1] in markers]
            else:
                selected = [e for e in entries if e[1] in accessed]
        if len(selected) != 1:
            raise MappingError('request input reader is missing or ambiguous')
        if 'public void doPost(' not in source:
            raise MappingError('unsupported servlet method mapping')
        delegated = bool(re.search(r'public void doGet\(.*?\{\s*doPost\(request, response\);\s*\}', source, re.S))
        method = 'GET' if location == 'query' and delegated else 'POST'
        if location == 'query' and not delegated:
            raise MappingError('query mapping GET does not delegate to input handler')
        html_ref = f'src/main/webapp{servlet[0]}.html'
        if (self.root / html_ref).exists():
            forms = Forms()
            forms.feed(self.read(html_ref))
            matching = [f for f in forms.forms if f.get('action') == url.path]
            if len(matching) != 1 or matching[0].get('method', 'GET').upper() != method:
                raise MappingError('HTML/crawler/servlet request method mismatch')
        elif location in {'body', 'cookie'}:
            raise MappingError('missing form method metadata')
        op = OperationalCaseInput(name, truth.vulnerability_class, method, servlet[0], query, body,
                                  headers, cookies, location, selected[0][1], component,
                                  'application/x-www-form-urlencoded' if body else None)
        # Target state requirement stays parent-side; no sink hints go to Agent.
        self.state_effects[name] = bool(re.search(r'\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b|\.executeUpdate\(', source, re.I))
        self.cache[name] = op
        return op

    def identity(self) -> dict:
        commit = subprocess.run(['git', '-C', str(self.root), 'rev-parse', 'HEAD'], capture_output=True, text=True)
        dirty = subprocess.run(['git', '-C', str(self.root), 'status', '--porcelain'], capture_output=True, text=True)
        return {'version': self.version, 'git_commit': commit.stdout.strip() if commit.returncode == 0 else None,
                'dirty': bool(dirty.stdout) if dirty.returncode == 0 else None,
                'artifacts': dict(sorted(self.hashes.items())), 'mapping_version': MAPPING,
                'counts': {f'{cls}/{"vulnerable" if vulnerable else "safe"}': sum(t.vulnerability_class == cls and t.expected_vulnerable == vulnerable for t in self.truth)
                           for cls in CLASSES for vulnerable in (True, False)},
                'state_mutating_cases': sorted(k for k, v in self.state_effects.items() if v)}

    def verify(self, manifest: RunManifest):
        """Rebuild the complete declared selection and compare its derived state."""
        authoritative = Dataset(self.root)
        try:
            if manifest.mode == 'single':
                if len(manifest.truth) != 1:
                    raise ValueError('single manifest requires one case')
                expected = select(authoritative, manifest.run_id, seed=manifest.seed,
                                  case_id=manifest.truth[0].get('case_id'))
            else:
                expected = select(authoritative, manifest.run_id, mode=manifest.mode, seed=manifest.seed)
        except MappingError as err:
            raise ValueError(f'dataset artifact changed or mapping invalid: {err}') from err

        # The runtime/reproducibility snapshots are added by the runner. All
        # selection, dataset identity, mapping, and schedule fields are derived
        # again here from the authoritative dataset.
        for field in ('dataset', 'truth', 'operational', 'execution_order', 'seed', 'mode',
                      'selection_version', 'mapping_version', 'protocol_version', 'scenario',
                      'schema_version'):
            if getattr(manifest, field) != getattr(expected, field):
                if field == 'dataset':
                    current_artifacts = expected.dataset.get('artifacts', {})
                    declared_artifacts = manifest.dataset.get('artifacts', {})
                    for ref, current_hash in current_artifacts.items():
                        if declared_artifacts.get(ref) != current_hash:
                            raise ValueError(f'dataset artifact changed or omitted: {ref}')
                    if set(declared_artifacts) != set(current_artifacts):
                        raise ValueError('dataset artifact set differs from authoritative selection')
                    raise ValueError('dataset identity or derived metadata differs from authoritative dataset')
                if field == 'execution_order':
                    raise ValueError('manifest deterministic execution order differs from declared selection')
                if field == 'truth':
                    raise ValueError('manifest truth rows differ from declared selection')
                if field == 'operational':
                    raise ValueError('manifest operational rows differ from authoritative mapping')
                raise ValueError(f'manifest {field} differs from declared selection')


def select(dataset: Dataset, run_id: str, mode='smoke', seed=DEFAULT_SEED, case_id: str | None = None) -> RunManifest:
    # Explicit legacy modes and single-case mapping remain available for reading
    # historical artifacts and internal reset diagnostics, never as CLI choices.
    mode = SELECTION_MODES.get(mode, mode)
    # Pin only artifacts actually used by this selection, independent of previous calls.
    dataset.hashes = {ref: file_hash(dataset.root / ref) for ref in (TRUTH, CRAWLER)}
    dataset.cache.clear()
    dataset.state_effects.clear()
    if case_id:
        selected = [t for t in dataset.truth if t.case_id == case_id]
        if len(selected) != 1:
            raise ValueError('unknown or unsupported case ID')
        mode = 'single'
    else:
        if mode not in {'default', 'reduced', 'smoke'}:
            raise ValueError('unknown selection mode')
        n = {'default': 20, 'reduced': 10, 'smoke': 3}[mode]
        selected = []
        for cls in CLASSES:
            for vulnerable in (True, False):
                pool = sorted((t for t in dataset.truth if t.vulnerability_class == cls and t.expected_vulnerable == vulnerable), key=lambda t: t.case_id)
                if len(pool) < n:
                    raise ValueError(f'insufficient stratum {cls}/{vulnerable}: {len(pool)} < {n}')
                selected.extend(sorted(pool, key=lambda t: (digest([SELECTION, seed, 'select', cls, vulnerable, t.case_id]), t.case_id))[:n])
    selected.sort(key=lambda t: t.case_id)
    ops = [dataset.map(t) for t in selected]  # Every selected mapping must succeed. Never replace.
    order = sorted((t.case_id for t in selected), key=lambda id: (digest([SELECTION, seed, 'order', id]), id))
    return RunManifest(run_id, dataset.identity(), [asdict(t) for t in selected], [asdict(o) for o in ops], order, seed, mode)
