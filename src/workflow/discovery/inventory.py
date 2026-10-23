"""Bounded discovery metadata. These records convey neither proof nor rights.

Request-context source_ref remains on Input/Candidate. Discovery provenance
uses independent ds_/ep_/pv_ references and never supplies replay context.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
from typing import Any

from src.redaction.redact import apply as redact
from src.target.input_admission import canonical_endpoint, identity_text
from src.target.origin import HTTPOrigin

MAX_ENDPOINTS = 4096
MAX_SOURCES = 128
MAX_PROVENANCE = 8192
MAX_SOURCE_RECORDS = 256
MAX_SOURCE_REASON_LENGTH = 240
SOURCE_KINDS = frozenset({'native', 'ffuf', 'nmap', 'capture', 'http'})
SOURCE_STATES = frozenset({'pending', 'processed', 'partial', 'blocked', 'not_applicable'})
BOUND_NAMES = frozenset({'max_bytes', 'max_nodes', 'max_records', 'max_paths', 'max_operations',
                         'max_parameters', 'max_schema_nodes', 'max_ref_depth'})


def fingerprint(prefix: str, value: Any) -> str:
    return prefix + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                              ensure_ascii=True).encode()).hexdigest()


def exact(value: Any, *, maximum: int = 500) -> str:
    if (not isinstance(value, str) or not value or len(value) > maximum
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or redact(value) != value or '[REDACTED' in value.upper()):
        raise ValueError('discovery metadata requires bounded, non-secret exact text')
    return value


def notes(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)) or len(values) > 16:
        raise ValueError('at most 16 discovery limitations are allowed')
    if any(not isinstance(value, str) or len(value) > 240 for value in values):
        raise ValueError('discovery limitations must be bounded strings')
    return tuple(dict.fromkeys(redact(value) for value in values))


def check_id(value: str, prefix: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(prefix + r'[0-9a-f]{64}', value):
        raise ValueError('invalid exact discovery reference')


@dataclass(frozen=True, slots=True)
class EndpointRecord:
    objective_id: str
    target_origin: str
    url: str
    method: str | None = None
    id: str = ''

    def __post_init__(self):
        exact(self.objective_id, maximum=80)
        origin = HTTPOrigin.from_url(self.target_origin).as_url()
        url = canonical_endpoint(self.url, origin)
        method = identity_text(self.method, 'method')
        if method is not None:
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", method):
                raise ValueError('endpoint method must be an HTTP token')
            method = method.upper()
        identity = fingerprint('ep_', [self.objective_id, origin, url, method])
        if self.id and self.id != identity:
            raise ValueError('endpoint reference does not match its operation')
        object.__setattr__(self, 'target_origin', origin)
        object.__setattr__(self, 'url', url)
        object.__setattr__(self, 'method', method)
        object.__setattr__(self, 'id', identity)

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SourceRecord:
    objective_id: str
    target_origin: str
    kind: str
    locator: str
    retained_hash: str
    document_url: str | None = None
    retained_ref: str | None = None
    scanner_job_id: str | None = None
    # Preserve historical extractor identity; manual attribution does not set it.
    content_identity: str | None = None
    selected: bool = False
    disposition: str = 'pending'
    limitations: tuple[str, ...] = ()
    stop_reason: str | None = None
    bounded_stop: bool = False
    processing_bounds: tuple[tuple[str, int], ...] = ()
    id: str = ''

    def __post_init__(self):
        exact(self.objective_id, maximum=80)
        exact(self.locator)
        origin = HTTPOrigin.from_url(self.target_origin).as_url()
        if self.kind not in SOURCE_KINDS or self.disposition not in SOURCE_STATES:
            raise ValueError('invalid discovery source kind/disposition')
        if not isinstance(self.retained_hash, str) or not re.fullmatch(r'[0-9a-f]{64}', self.retained_hash):
            raise ValueError('source requires the exact retained content hash')
        if self.content_identity is not None:
            check_id(self.content_identity, '')
        url = canonical_endpoint(self.document_url, origin) if self.document_url is not None else None
        if self.retained_ref is not None:
            exact(self.retained_ref)
        if self.scanner_job_id is not None:
            if not re.fullmatch(r'scan_[0-9a-f]{32}', self.scanner_job_id):
                raise ValueError('invalid scanner job reference')
        if (self.kind in {'ffuf', 'nmap'}) != (self.scanner_job_id is not None):
            raise ValueError('scanner provenance requires its exact job reference')
        if type(self.selected) is not bool or type(self.bounded_stop) is not bool:
            raise ValueError('source selection/bounded stop must be boolean')
        limits = notes(self.limitations)
        if (not isinstance(self.processing_bounds, (tuple, list)) or len(self.processing_bounds) > len(BOUND_NAMES)
                or any(not isinstance(pair, (tuple, list)) or len(pair) != 2
                       or pair[0] not in BOUND_NAMES or type(pair[1]) is not int
                       or not 1 <= pair[1] <= 16 * 1024**2 for pair in self.processing_bounds)):
            raise ValueError('processing bounds require known names and bounded positive integers')
        bounds = tuple(sorted(tuple(pair) for pair in self.processing_bounds))
        if len({key for key, _ in bounds}) != len(bounds):
            raise ValueError('duplicate processing bound')
        if isinstance(self.stop_reason, str) and len(self.stop_reason) > MAX_SOURCE_REASON_LENGTH:
            raise ValueError(f'source_reason length {len(self.stop_reason)} exceeds maximum {MAX_SOURCE_REASON_LENGTH}')
        reason = exact(self.stop_reason, maximum=MAX_SOURCE_REASON_LENGTH) if self.stop_reason is not None else None
        if self.disposition in {'partial', 'blocked', 'not_applicable'} and not reason:
            raise ValueError('source disposition requires a bounded stop reason')
        if self.bounded_stop and (self.disposition != 'partial' or not reason or not limits or not bounds):
            raise ValueError('bounded stop requires partial state, explicit bounds and reason')
        if self.disposition == 'processed' and limits:
            raise ValueError('limited source cannot be processed-complete')
        identity = fingerprint('ds_', [self.objective_id, origin, self.kind, self.locator,
                                      self.retained_hash, url, self.retained_ref, self.scanner_job_id])
        if self.id and self.id != identity:
            raise ValueError('source reference does not match retained provenance')
        object.__setattr__(self, 'id', identity)
        object.__setattr__(self, 'target_origin', origin)
        object.__setattr__(self, 'document_url', url)
        object.__setattr__(self, 'limitations', limits)
        object.__setattr__(self, 'processing_bounds', bounds)

    @property
    def unresolved(self) -> bool:
        return self.selected and (self.disposition in {'pending', 'blocked'}
                                 or (self.disposition == 'partial' and not self.bounded_stop))

    def to_dict(self):
        row = asdict(self)
        row['limitations'] = list(self.limitations)
        row['processing_bounds'] = [list(pair) for pair in self.processing_bounds]
        return row


@dataclass(frozen=True, slots=True)
class ProvenanceRecord:
    source_id: str
    endpoint_id: str
    input_id: str | None = None
    locator: str = 'operation'
    occurrence: int = 0
    required: bool | None = None
    media_type: str | None = None
    id: str = ''

    def __post_init__(self):
        check_id(self.source_id, 'ds_')
        check_id(self.endpoint_id, 'ep_')
        if self.input_id is not None:
            exact(self.input_id, maximum=80)
        exact(self.locator, maximum=240)
        if type(self.occurrence) is not int or not 0 <= self.occurrence <= 10000:
            raise ValueError('invalid provenance occurrence')
        if self.required is not None and type(self.required) is not bool:
            raise ValueError('invalid provenance required flag')
        media = identity_text(self.media_type, 'content_type')
        object.__setattr__(self, 'media_type', media)
        identity = fingerprint('pv_', [self.source_id, self.endpoint_id, self.input_id,
                                      self.locator, self.occurrence, self.required, media])
        if self.id and self.id != identity:
            raise ValueError('provenance reference does not match its linkage')
        object.__setattr__(self, 'id', identity)

    def to_dict(self):
        return asdict(self)


def restore_discovery(state, value: dict) -> None:
    """Additive hydration, all-or-nothing for the new linkage graph.

    Never use admission to reconstruct historical processing or guess IDs.
    Legacy inputs/attempts/results are deliberately left alone.
    """
    from ..state import normalize_media_type
    invalid = value.get('discovery_restore_invalid', False)
    state.discovery_restore_invalid = invalid if type(invalid) is bool else True
    try:
        groups = []
        for name, cls, cap in (('endpoints', EndpointRecord, MAX_ENDPOINTS),
                               ('discovery_sources', SourceRecord, MAX_SOURCES),
                               ('discovery_provenance', ProvenanceRecord, MAX_PROVENANCE)):
            rows = value.get(name, [])
            if not isinstance(rows, list) or len(rows) > cap:
                raise ValueError('invalid discovery inventory')
            parsed = {}
            for raw in rows:
                if not isinstance(raw, dict) or not raw.get('id'):
                    raise ValueError('persisted discovery record requires its original ID')
                row = cls(**raw)
                if row.id in parsed:
                    raise ValueError('duplicate discovery reference')
                parsed[row.id] = row
            groups.append(parsed)
        endpoints, sources, provenance = groups
        for source in sources.values():
            if source.scanner_job_id is not None:
                job = state.scanner_jobs.get(source.scanner_job_id)
                if job is not None and (job.get('objective_id') != source.objective_id
                        or job.get('target_origin') != source.target_origin or job.get('scanner') != source.kind
                        or (job.get('artifacts') or {}).get('dataset_sha256') != source.retained_hash):
                    raise ValueError('persisted scanner/source mismatch')
        counts: dict[str, int] = {}
        for row in provenance.values():
            source, endpoint = sources.get(row.source_id), endpoints.get(row.endpoint_id)
            if (source is None or endpoint is None or source.objective_id != endpoint.objective_id
                    or source.target_origin != endpoint.target_origin):
                raise ValueError('persisted discovery ownership mismatch')
            counts[row.source_id] = counts.get(row.source_id, 0) + 1
            if counts[row.source_id] > MAX_SOURCE_RECORDS:
                raise ValueError('persisted source exceeds bound')
            if row.input_id is not None:
                item = state.attack_surface_inputs.get(row.input_id)
                if (item is None or item.objective_id != source.objective_id
                        or item.target_origin != source.target_origin or item.method != endpoint.method
                        or canonical_endpoint(item.endpoint, item.target_origin) != endpoint.url
                        or (row.media_type is not None and item.content_type is not None
                            and normalize_media_type(row.media_type) != normalize_media_type(item.content_type))):
                    raise ValueError('persisted discovery input mismatch')
        state.endpoints, state.discovery_sources, state.discovery_provenance = endpoints, sources, provenance
    except (ValueError, TypeError, AttributeError):
        # Corrupt new records must not leave a partially valid graph or a
        # no-candidate review that silently ignores discarded relevant work.
        state.discovery_restore_invalid = True
        if state.objective is not None:
            for goal in state.objective.requested_goals:
                if goal.status == 'no_candidate':
                    state.set_requested_goal_status(goal, 'pending', reason='Discovery metadata is invalid; review sources again.')


def native_handoff(state, produced, call_id: str) -> SourceRecord | None:
    """Called only by the native publication hook after its existing guard."""
    from src.tools.discovery.content import NativeDiscoveryResult
    if (type(produced) is not NativeDiscoveryResult or produced.owner.state is not state
            or not produced.owner.current()):
        raise ValueError('stale native source owner')
    objective = state.objective
    if objective is None or objective.mode != 'whole_target':
        return None
    payload = json.loads(produced.full_text)
    ref = produced.reference
    source = SourceRecord(objective.id, payload['origin'], 'native',
        ref.result_ref if ref else 'inline:' + call_id,
        ref.sha256 if ref else hashlib.sha256(produced.full_text.encode()).hexdigest(),
        retained_ref=ref.result_ref if ref else None)
    endpoints, links, limitations = [], [], []
    for index, row in enumerate(payload['discovered'][:MAX_SOURCE_RECORDS]):
        if row.get('verified') is not True:
            limitations.append('unverified native row excluded')
            continue
        try:
            url = payload['origin'] + payload['base_path'].rstrip('/') + '/' + row['path']
            endpoint = EndpointRecord(objective.id, source.target_origin, url, 'GET')
            endpoints.append(endpoint)
            links.append(ProvenanceRecord(source.id, endpoint.id, locator='discovered', occurrence=index))
        except (ValueError, KeyError, TypeError):
            limitations.append('invalid native operation excluded')
    if len(payload['discovered']) > MAX_SOURCE_RECORDS:
        limitations.append('native metadata limit: 256 discovered rows; retained result contains remaining rows')
    if not payload.get('complete'):
        limitations.append('native discovery run was incomplete; raw execution status remains authoritative')
    if ref is None:
        limitations.append('retained result unavailable; full sanitized source remains inline')
    from dataclasses import replace
    source = replace(source, disposition='partial' if limitations else 'processed',
                     limitations=tuple(dict.fromkeys(limitations)),
                     stop_reason='native handoff limited' if limitations else None)
    return state.admit_discovery(source, tuple(endpoints), tuple(links))


def observation_handoff(state, item) -> SourceRecord | None:
    """Metadata from the controller's already validated scoped HTTP output."""
    objective = state.objective
    if objective is None or objective.mode != 'whole_target':
        return None
    if item.objective_id is not None and item.objective_id != objective.id:
        raise ValueError('foreign observation objective')
    if item.source_kind not in {'native-http', 'imported-capture'}:
        raise ValueError('unsupported HTTP discovery producer')
    capture = item.source_kind == 'imported-capture'
    source = SourceRecord(objective.id, objective.target_origin, 'capture' if capture else 'http',
        (item.source_details or {})['capture_id'] if capture else item.id,
        item.retained_hash, document_url=item.url, retained_ref=item.id,
        limitations=('retained response incomplete or truncated',) if not item.complete or item.truncated else ())
    endpoint = EndpointRecord(objective.id, source.target_origin, item.url, item.method)
    return state.admit_discovery(source, (endpoint,), (ProvenanceRecord(source.id, endpoint.id),))


def source_progress_identity(state, source: SourceRecord) -> str:
    if source.content_identity is not None:
        return source.content_identity
    links = [row for row in state.discovery_provenance.values() if row.source_id == source.id]
    operations = sorted({(state.endpoints[row.endpoint_id].url, state.endpoints[row.endpoint_id].method or '')
                         for row in links})
    return fingerprint('', [source.kind, source.document_url, operations])


def discovery_page(state, args: dict[str, Any]) -> dict[str, Any]:
    """Bounded read-only projection. Cursors confer no source read rights."""
    import base64
    view = args.get('view')
    if view not in {'sources', 'endpoints', 'provenance'}:
        raise ValueError('invalid discovery view')
    source_filter = args.get('discovery_source_id')
    if source_filter is not None:
        state.discovery_source(source_filter, generation=state.generation)
    sources = {row.id for row in state.objective_sources()}
    links = [row for row in state.discovery_provenance.values()
             if row.source_id in sources and (source_filter is None or row.source_id == source_filter)]
    if view == 'sources':
        rows = sorted(state.objective_sources(), key=lambda row: (not row.unresolved, row.id))
    elif view == 'endpoints':
        linked = {row.endpoint_id for row in links}
        rows = sorted((row for row in state.objective_endpoints()
                       if source_filter is None or row.id in linked), key=lambda row: row.id)
    else:
        rows = sorted(links, key=lambda row: row.id)
    limit = args.get('limit', 8)
    if type(limit) is not int or not 1 <= limit <= 25:
        raise ValueError('discovery limit must be an integer from 1 through 25')
    objective = state.objective
    binding = fingerprint('', [state.generation, objective.id if objective else None, view, source_filter,
                               [row.to_dict() for row in rows]])
    offset = 0
    cursor = args.get('discovery_cursor')
    if cursor is not None:
        try:
            if not isinstance(cursor, str) or len(cursor) > 256:
                raise ValueError
            token = json.loads(base64.b64decode(cursor.encode('ascii'), altchars=b'-_', validate=True))
            if (not isinstance(token, list) or len(token) != 2 or token[0] != binding
                    or type(token[1]) is not int or not 0 < token[1] < len(rows)):
                raise ValueError
            offset = token[1]
        except (ValueError, TypeError, UnicodeError):
            raise ValueError('stale/invalid discovery cursor; restart this view without discovery_cursor') from None
    count = min(limit, len(rows) - offset)
    while True:
        end = offset + count
        next_cursor = (base64.urlsafe_b64encode(json.dumps([binding, end]).encode()).decode()
                       if end < len(rows) else None)
        shown = []
        for row in rows[offset:end]:
            item = row.to_dict()
            if isinstance(row, SourceRecord):
                item = {key: item[key] for key in ('id', 'kind', 'disposition', 'selected', 'bounded_stop', 'retained_ref')}
                item['unresolved'] = row.unresolved
                item['limitations_count'] = len(row.limitations)
            shown.append(item)
        page = {'ok': True, 'view': view, 'total': len(rows), 'returned': count, 'complete': next_cursor is None,
                'discovery_restore_invalid': state.discovery_restore_invalid,
                'next_discovery_cursor': next_cursor, view: shown}
        if len(json.dumps(page, ensure_ascii=True).encode()) <= 16 * 1024:
            return page
        count -= 1
        if count < 1:
            raise ValueError('discovery row exceeds listing budget; read exact record metadata')
