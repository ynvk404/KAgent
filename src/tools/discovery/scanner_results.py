"""Pure bounded machine-output parsers. Scanner observations are untrusted data."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Any, TYPE_CHECKING
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET
from xml.parsers import expat

from src.engagement.state import normalize_tcp_ip
from src.redaction.redact import redact_payload

if TYPE_CHECKING:
    from src.tools.execution.scanners import ScannerPlan

MAX_SOURCE = 16 * 1024**2
MAX_DATASET = 8 * 1024**2
MAX_RECORDS = 65535


def encode(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()


def clean(value: str, limit: int = 8192, secrets: tuple[str, ...] = ()) -> str:
    # Remove ANSI before removing controls, including OSC hyperlinks.
    value = re.sub(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)', '', value)
    value = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', value)
    value = ''.join(c for c in value if c.isprintable())[:limit]
    for secret in secrets:
        if secret:
            value = value.replace(secret, '[REDACTED]')
    return str(redact_payload(value))


@dataclass(slots=True)
class ParsedScan:
    records: list[dict[str, Any]] = field(default_factory=list)
    validity: str = 'valid'
    rejected: int = 0
    duplicates: int = 0
    conflicts: int = 0
    dataset_truncated: bool = False
    coverage_complete: bool | None = None
    reason: str | None = None
    _bytes: int = 0
    _seen: dict[str, bytes] = field(default_factory=dict, repr=False)

    def add(self, record: dict[str, Any], identity: Any) -> None:
        key = hashlib.sha256(encode(identity)).hexdigest()[:24]
        payload = encode(record)
        previous = self._seen.get(key)
        if previous is not None:
            if previous == payload:
                self.duplicates += 1
            else:
                self.conflicts += 1
                self.validity = 'partial'
            return
        record['id'] = 'sr_' + key
        row = encode(record)
        if len(self.records) >= MAX_RECORDS or self._bytes + len(row) + 1 > MAX_DATASET:
            self.dataset_truncated = True
            self.validity = 'partial'
            return
        self._bytes += len(row) + 1
        self._seen[key] = payload
        self.records.append(record)

    def reject(self) -> None:
        self.rejected += 1
        self.validity = 'partial'
        self.coverage_complete = False

    def dataset(self) -> bytes:
        return b''.join(encode(row) + b'\n' for row in self.records)


def bounded_xml(data: bytes) -> ET.Element:
    if not data or len(data) > MAX_SOURCE:
        raise ValueError('missing/oversized XML')
    parser = expat.ParserCreate()
    depth = 0
    nodes = 0

    def start(_name, attrs):
        nonlocal depth, nodes
        depth += 1
        nodes += 1
        if depth > 32 or nodes > 800000 or any(len(k) + len(v) > 16384 for k, v in attrs.items()):
            raise ValueError('XML complexity limit')

    def end(_name):
        nonlocal depth
        depth -= 1

    def doctype(name, system, public, subset):
        if name != 'nmaprun' or system or public or subset:
            raise ValueError('unsafe XML declaration')

    def unsafe(*_args):
        raise ValueError('XML entities/external resources are forbidden')

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.StartDoctypeDeclHandler = doctype
    parser.EntityDeclHandler = unsafe
    parser.ExternalEntityRefHandler = unsafe
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.Parse(data, True)
    # ElementTree neither executes stylesheet PIs nor fetches XSL/DTDs. Feed
    # finite chunks: a single C tree-building call can hold the worker's GIL
    # across a large document even when the caller offloads to a thread.
    tree = ET.XMLParser()
    for offset in range(0, len(data), 64 * 1024):
        tree.feed(data[offset:offset + 64 * 1024])
    root = tree.close()
    if root.tag != 'nmaprun':
        raise ValueError('not an Nmap XML document')
    return root


def parse_nmap(data: bytes, plan: ScannerPlan) -> ParsedScan:
    parsed = ParsedScan()
    try:
        root = bounded_xml(data)
    except (ValueError, ET.ParseError, expat.ExpatError, RecursionError):
        return ParsedScan(validity='invalid', coverage_complete=False, reason='invalid or unsafe Nmap XML')
    allowed_ports = frozenset(plan.ports)
    ports_seen = set()
    for host in root.findall('host'):
        try:
            addresses = [normalize_tcp_ip(row.attrib['addr']) for row in host.findall('address')
                         if row.get('addrtype') in {'ipv4', 'ipv6'}]
            if addresses != [plan.address]:
                raise ValueError
        except (ValueError, KeyError):
            parsed.reject()
            continue
        if host.get('timedout', '').lower() in {'true', '1'}:
            parsed.coverage_complete = False
            parsed.reason = 'Nmap reported host timeout'
        for port in host.findall('./ports/port'):
            try:
                number = int(port.attrib['portid'])
                state = port.find('state')
                if (port.get('protocol') != 'tcp' or number not in allowed_ports or state is None
                        or state.get('state') not in {'open', 'closed', 'filtered', 'unfiltered', 'open|filtered', 'closed|filtered'}):
                    raise ValueError
                service = port.find('service')
                record = {'address': plan.address, 'port': number, 'protocol': 'tcp',
                          'state': state.get('state'), 'reason': clean(state.get('reason', ''), 128),
                          'service_hint': clean(service.get('name', ''), 128) if service is not None else None}
                parsed.add(record, (plan.address, number, 'tcp'))
                ports_seen.add(number)
            except (ValueError, KeyError, TypeError):
                parsed.reject()
    finished = root.find('./runstats/finished')
    successful = finished is not None and finished.get('exit') == 'success'
    # Extraports are aggregates, never fabricated per-port closed records.
    if parsed.coverage_complete is not False:
        parsed.coverage_complete = bool(successful and ports_seen == allowed_ports
                                        and not parsed.rejected and not parsed.conflicts and not parsed.dataset_truncated)
    return parsed


def bounded_json(data: bytes) -> Any:
    if not data or len(data) > MAX_SOURCE:
        raise ValueError('missing/oversized JSON')
    depth, quoted, escaped = 0, False, False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 32:
                raise ValueError('JSON nesting limit')
        elif byte in (93, 125):
            depth -= 1

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result

    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def parse_ffuf(data: bytes, plan: ScannerPlan) -> ParsedScan:
    parsed = ParsedScan(coverage_complete=None)
    try:
        document = bounded_json(data)
        rows = document['results']
        if not isinstance(rows, list) or len(rows) > 2 * MAX_RECORDS:
            raise ValueError
    except (ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        return ParsedScan(validity='invalid', coverage_complete=False, reason='invalid ffuf JSON')
    assert plan.wordlist is not None
    words = set(plan.wordlist.data.decode().splitlines())
    transport = plan.argv[plan.argv.index('-u') + 1]
    template_path = urlsplit(transport).path
    for row in rows:
        try:
            inputs = row['input']
            word = inputs.get('FUZZ') if isinstance(inputs, dict) else None
            if not isinstance(word, str) or word not in words:
                raise ValueError
            url = row['url']
            # Numeric URL must be exactly the reviewed template substitution.
            # No trust or authorization is derived from reported URLs/config.
            if not isinstance(url, str) or len(url) > 16384 or url != transport.replace('FUZZ', word):
                raise ValueError
            metrics = [row[key] for key in ('status', 'length', 'words', 'lines')]
            if (any(type(n) is not int or not 0 <= n <= 2**63 - 1 for n in metrics)
                    or not 100 <= metrics[0] <= 599):
                raise ValueError
            logical = plan.origin.as_url() + template_path.replace('FUZZ', word)
            record: dict[str, Any] = dict(zip(('status', 'length', 'words', 'lines'), metrics))
            record.update(url=clean(logical, 16384), verification='scanner_reported')
            parsed.add(record, (plan.origin.as_url(), 'GET', template_path.replace('FUZZ', word)))
        except (ValueError, KeyError, TypeError):
            parsed.reject()
    # With match-all and no calibration/filters every successful word response
    # should be represented. The tested dev build can lose JSON rows under
    # concurrency despite a zero-error native progress line. Surface the gap;
    # never fill it from stdout or invent records/request counts.
    if (plan.argv[plan.argv.index('-mc') + 1] == 'all'
            and not {'-ac', '-fc', '-fs'} & set(plan.argv)):
        represented = {row['url'] for row in parsed.records}
        expected = {clean(plan.origin.as_url() + template_path.replace('FUZZ', word), 16384) for word in words}
        if represented != expected:
            parsed.validity = 'partial'
            parsed.coverage_complete = False
            parsed.reason = 'missing_word_observations'
    # ffuf's output does not attest all sends/errors/internal timeout. Exit 0
    # plus valid JSON is insufficient for full intended-pass coverage.
    return parsed


def parse_scan(data: bytes, plan: ScannerPlan) -> ParsedScan:
    result = parse_nmap(data, plan) if plan.scanner == 'nmap' else parse_ffuf(data, plan)
    result.records.sort(key=lambda row: row['id'])
    return result
