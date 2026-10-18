"""Pure bounded syntax extraction from already admitted bytes. No I/O or LLM.

Values, defaults, examples, credentials and response schemas never enter the
output. Occurrences live in provenance; legacy input identity stays unchanged.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
import json
from typing import Any
from urllib.parse import unquote_plus, urljoin, urlsplit

from src.target.input_admission import canonical_endpoint, identity_text
from src.target.origin import HTTPOrigin
from .discovery import fingerprint, MAX_SOURCE_RECORDS

MAX_DOCUMENT_BYTES = 65536
MAX_HTML_NODES = 4096
MAX_EXTRACTED_RECORDS = MAX_SOURCE_RECORDS - 1  # reserve the admitted source operation


@dataclass(frozen=True, slots=True)
class ExtractedRecord:
    url: str
    method: str | None
    locator: str
    parameter: str | None = None
    location: str | None = None
    input_type: str | None = None
    content_type: str | None = None
    occurrence: int = 0
    required: bool | None = None


@dataclass
class Extraction:
    records: list[ExtractedRecord] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    bounds: dict[str, int] = field(default_factory=lambda: {
        'max_bytes': MAX_DOCUMENT_BYTES, 'max_nodes': MAX_HTML_NODES, 'max_records': MAX_EXTRACTED_RECORDS})
    not_applicable: bool = False
    stop_reason: str | None = None

    def issue(self, reason: str):
        if reason not in self.limitations:
            if len(self.limitations) < 15:
                self.limitations.append(reason)
            elif 'additional extraction limitations omitted' not in self.limitations:
                self.limitations.append('additional extraction limitations omitted')

    def add(self, row: ExtractedRecord):
        if len(self.records) >= MAX_EXTRACTED_RECORDS:
            self.issue('max_records=255 reached; remaining syntax omitted')
            return
        self.records.append(row)

    @property
    def content_identity(self):
        # Facts, not parser positions or document member order. Keep duplicate
        # controls as a multiset; raw query order remains part of each URL.
        # Provenance separately preserves exact locators and occurrences.
        rows = [{key: value for key, value in asdict(row).items() if key not in {'locator', 'occurrence'}}
                for row in self.records]
        return fingerprint('', sorted(rows, key=lambda row: json.dumps(row, sort_keys=True)))


def document_text(body: bytes, result: Extraction, complete: bool) -> str:
    if len(body) > MAX_DOCUMENT_BYTES:
        result.issue('max_bytes=65536 reached; document prefix only')
    if not complete:
        result.issue('admitted source bytes incomplete or truncated')
    try:
        return body[:MAX_DOCUMENT_BYTES].decode('utf-8-sig')
    except UnicodeError:
        result.issue('invalid UTF-8; replacement decoding used')
        return body[:MAX_DOCUMENT_BYTES].decode('utf-8-sig', errors='replace')


def resolved_url(raw: str, base: str, origin: str, result: Extraction) -> str | None:
    try:
        if not isinstance(raw, str) or any(ord(char) < 32 or ord(char) == 127 for char in raw):
            raise ValueError
        raw = raw.strip(' ')
        parts = urlsplit(raw)
        if parts.fragment or '#' in raw:
            result.issue('client-route fragment reference excluded')
            return None
        absolute = urljoin(base, raw)
        if HTTPOrigin.from_url(absolute).as_url() != origin:
            result.issue('external or non-HTTP URL excluded; no scope expansion')
            return None
        return canonical_endpoint(absolute, origin)
    except ValueError:
        result.issue('invalid or sensitive URL excluded')
        return None


def add_query(result: Extraction, url: str, method: str | None, locator: str):
    if method is None:
        if urlsplit(url).query:
            result.issue('query names retained only when operation method is known')
        return
    for index, part in enumerate(urlsplit(url).query.split('&')):
        if not part:
            continue
        try:
            # Never decode, retain or hash the value. Preserve duplicate order
            # as provenance occurrences and raw query spelling in the URL.
            name = identity_text(unquote_plus(part.split('=', 1)[0], errors='strict'), 'parameter', required=True)
            result.add(ExtractedRecord(url, method, locator, name, 'query', occurrence=index))
        except (ValueError, UnicodeError):
            result.issue('invalid or sensitive query parameter name excluded')


class _HTML(HTMLParser):
    def __init__(self, result: Extraction):
        super().__init__(convert_charrefs=True)
        self.result = result
        self.nodes = 0
        self.elements: list[tuple[str, dict[str, str], int]] = []
        self.form_depth = 0

    def handle_starttag(self, tag, attrs):
        self.nodes += 1
        if self.nodes > MAX_HTML_NODES:
            self.result.issue('max_nodes=4096 reached; remaining HTML omitted')
            return
        names = [name for name, _ in attrs]
        if len(set(names)) != len(names):
            self.result.issue('duplicate HTML attributes; first attribute retained')
        values = {}
        for name, value in attrs:
            # Explicit allow-list: no value, text, data-* or credential-bearing
            # form defaults survive the parser's temporary attribute event.
            if name in {'href', 'src', 'action', 'method', 'enctype', 'name', 'type', 'form', 'id', 'required', 'disabled',
                        'formaction', 'formmethod', 'formenctype'} and name not in values:
                values[name] = value or ''
        if tag == 'form':
            self.form_depth += 1
            if self.form_depth > 1:
                self.result.issue('nested form syntax is ambiguous')
        self.elements.append((tag, values, self.nodes))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        self.nodes += 1
        if self.nodes > MAX_HTML_NODES:
            self.result.issue('max_nodes=4096 reached; remaining HTML omitted')
            return
        if tag == 'form':
            if self.form_depth == 0:
                self.result.issue('unmatched form close tag')
            self.form_depth = max(0, self.form_depth - 1)
            self.elements.append(('/form', {}, self.nodes))


def extract_html(body: bytes, document_url: str, *, complete: bool = True) -> Extraction:
    result = Extraction()
    origin = HTTPOrigin.from_url(document_url).as_url()
    document_url = canonical_endpoint(document_url, origin)
    text = document_text(body, result, complete)
    parser = _HTML(result)
    try:
        parser.feed(text)
        if parser.rawdata.strip():
            result.issue('incomplete HTML tag or entity')
        parser.close()
    except (ValueError, RecursionError):
        result.issue('malformed HTML parser input')
    if parser.form_depth:
        result.issue('unclosed form; source may be malformed or truncated')
    if parser.rawdata.strip():
        result.issue('incomplete HTML tag or entity')
    if not parser.elements and text.strip():
        result.not_applicable = True
    base = document_url
    for tag, attrs, _ in parser.elements:
        if tag == 'base' and 'href' in attrs:
            try:
                raw = attrs['href']
                if any(ord(char) < 32 or ord(char) == 127 for char in raw):
                    raise ValueError
                proposed = urljoin(document_url, raw)
                # External bases may resolve references, but never grant scope.
                HTTPOrigin.from_url(proposed)
                if urlsplit(proposed).username is not None or '#' in proposed:
                    raise ValueError
                base = proposed
            except ValueError:
                result.issue('malformed HTML base; actual document URL retained')
            break
    active_form: tuple[str | None, str | None, str | None, str] | None = None
    ambiguous_forms = 'nested form syntax is ambiguous' in result.limitations
    for tag, attrs, index in parser.elements:
        locator = f'html:{index}:{tag}'
        for name in ('href', 'src'):
            if tag == 'base' or name not in attrs:
                continue
            url = resolved_url(attrs[name], base, origin, result)
            if url is not None:
                # href/src establish a resource reference, not necessarily an
                # executed GET. HTML navigation/resource retrieval uses GET.
                method = 'GET' if tag in {'a', 'area', 'link', 'script', 'img', 'iframe', 'audio', 'video', 'source', 'embed', 'track', 'input'} else None
                result.add(ExtractedRecord(url, method, locator))
                add_query(result, url, method, locator)
        if tag == 'form':
            action = attrs.get('action')
            url = resolved_url(action, base, origin, result) if action else document_url
            raw_method = attrs.get('method', 'get').lower()
            method = raw_method.upper() if raw_method in {'get', 'post'} else None
            if method is None:
                result.issue('unsupported or uncertain form method; controls not promoted to inputs')
            media = attrs.get('enctype', 'application/x-www-form-urlencoded').lower()
            if media not in {'application/x-www-form-urlencoded', 'multipart/form-data', 'text/plain'}:
                result.issue('unsupported form enctype; browser default not inferred')
                media = None
            active_form = (url, method, media, locator)
            if url is not None:
                result.add(ExtractedRecord(url, method, locator, content_type=media))
                if method != 'GET': add_query(result, url, method, locator)
        elif tag == '/form':
            active_form = None
        elif tag in {'input', 'select', 'textarea', 'button'} and 'name' in attrs:
            if ambiguous_forms:
                continue
            if 'form' in attrs:
                result.issue('explicit form-owner association unsupported; control excluded')
                continue
            if any(key in attrs for key in ('formaction', 'formmethod', 'formenctype')):
                result.issue('submit control overrides unsupported; control excluded')
                continue
            if active_form is None:
                continue
            url, method, media, form_locator = active_form
            if url is None or method is None or media is None or 'disabled' in attrs:
                continue
            try:
                name = identity_text(attrs['name'], 'parameter', required=True)
                input_type = identity_text(attrs.get('type', tag).lower(), 'input_type')
                result.add(ExtractedRecord(url, method, form_locator, name,
                    'query' if method == 'GET' else 'form', input_type, media, index, 'required' in attrs))
            except ValueError:
                result.issue('invalid or sensitive control name/type excluded')
    return result


def apply_extraction(state, source_id: str, extraction: Extraction, *, generation: str,
                     retained_ref: str, retained_hash: str, document_url: str):
    """Stage existing admission on a detached snapshot; publish once, no await.

    Invalid individual syntax is excluded with a limitation. A graph/binding
    failure rejects the entire proposal. No auth/baseline/source_ref is copied.
    """
    from copy import deepcopy
    from .discovery import EndpointRecord, ProvenanceRecord
    from .state import AttackSurfaceInput
    source = state.discovery_source(source_id, generation=generation, retained_ref=retained_ref)
    if (not source.selected or source.retained_ref != retained_ref or source.retained_hash != retained_hash
            or source.document_url != document_url or source.kind not in {'http', 'capture'}):
        raise ValueError('selected source bytes/URL/provenance mismatch; never substitute another source')
    if len(extraction.records) > MAX_EXTRACTED_RECORDS:
        raise ValueError('extraction proposal exceeds source record bound')
    trial = deepcopy(state)
    endpoints, provenance = [], []
    for record in extraction.records:
        try:
            endpoint = EndpointRecord(source.objective_id, source.target_origin, record.url, record.method)
            item = None
            if record.parameter is not None:
                proposal = AttackSurfaceInput(source.objective_id, source.target_origin, method=record.method,
                    endpoint=record.url, parameter=record.parameter, location=record.location,
                    input_type=record.input_type, content_type=(None if record.method == 'GET'
                        and record.location == 'query' else record.content_type))
                # Validate provenance before admitting an input on the snapshot;
                # an invalid item must not leave an unlinked input behind.
                ProvenanceRecord(source.id, endpoint.id, proposal.id, record.locator,
                                  record.occurrence, record.required, record.content_type)
                item, _ = trial.add_attack_surface_input(proposal)
            link = ProvenanceRecord(source.id, endpoint.id, item.id if item else None,
                                     record.locator, record.occurrence, record.required, record.content_type)
        except ValueError:
            extraction.issue('extracted item failed canonical admission; no context borrowed')
            continue
        endpoints.append(endpoint)
        provenance.append(link)
    trial.admit_discovery(source, tuple(endpoints), tuple(provenance))
    limitations = tuple(dict.fromkeys((*source.limitations, *extraction.limitations)))[:16]
    disposition = 'partial' if limitations else 'not_applicable' if extraction.not_applicable else 'processed'
    updated = trial.update_discovery_source(source.id, generation=trial.generation,
        disposition=disposition, limitations=limitations, bounded_stop=False,
        processing_bounds=tuple(extraction.bounds.items()), content_identity=extraction.content_identity,
        stop_reason='bounded syntax extraction limited' if limitations else
                    (extraction.stop_reason or 'document has no supported request syntax') if extraction.not_applicable else None)
    # Preserve untouched historical object identities and all execution stores.
    inputs = {key: state.attack_surface_inputs[key] if key in state.attack_surface_inputs
              and state.attack_surface_inputs[key] == item else item for key, item in trial.attack_surface_inputs.items()}
    if (state.endpoints != trial.endpoints or state.discovery_provenance != trial.discovery_provenance
            or state.discovery_sources != trial.discovery_sources or state.attack_surface_inputs != inputs):
        state.endpoints = trial.endpoints
        state.discovery_sources = trial.discovery_sources
        state.discovery_provenance = trial.discovery_provenance
        state.attack_surface_inputs = inputs
        state._invalidate_inventory_reviews(None)
        state.mark_committed()
    return updated
