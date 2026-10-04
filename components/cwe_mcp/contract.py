"""Strict wire schemas shared by the offline server and independently checked client."""
from __future__ import annotations

import json
import re
import unicodedata
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

XML_SHA256 = '1f5a78bd62e00f86436b4fe32d5034a57e8f0da88e4063b2072b664ae510912e'
ZIP_SHA256 = '3976f599e5e5200219a3108bb896d06e2a88fbb293369e1883cb423a5e9d7d50'
NAMESPACE = 'http://cwe.mitre.org/cwe-7'
SCHEMA_IDENTITY = 'http://cwe.mitre.org/data/xsd/cwe_schema_v7.3.xsd'
ADAPTER_VERSION = '1.0.0'
ALGORITHM = 'weighted-token-v1'
RESPONSE_BYTES = 65536
XML_BYTES = 32 * 1024 * 1024
STATUSES = {'Deprecated', 'Draft', 'Incomplete', 'Obsolete', 'Stable', 'Usable'}
ABSTRACTIONS = {'Pillar', 'Class', 'Base', 'Variant', 'Compound'}
STRUCTURES = {'Simple', 'Chain', 'Composite'}
USAGES = {'Allowed', 'Allowed-with-Review', 'Discouraged', 'Prohibited'}

class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid', frozen=True)

ID = Annotated[int, Field(ge=1, le=999999)]
Text512 = Annotated[str, Field(max_length=512)]
Text1024 = Annotated[str, Field(max_length=1024)]
Hash = Annotated[str, Field(pattern=r'^[a-f0-9]{64}$', max_length=64)]

class CorpusIdentity(StrictModel):
    name: Literal['CWE']
    version: Literal['4.20']
    date: Literal['2026-04-30']
    schema_version: Literal['7.3']
    xml_sha256: Hash
    adapter_version: Annotated[str, Field(min_length=1, max_length=32, pattern=r'^[a-zA-Z0-9._-]+$')]

EXPECTED_CORPUS = CorpusIdentity(name='CWE', version='4.20', date='2026-04-30',
                               schema_version='7.3', xml_sha256=XML_SHA256, adapter_version=ADAPTER_VERSION)

class Manifest(StrictModel):
    manifest_schema_version: Literal['1']
    corpus: CorpusIdentity
    xml_namespace: Literal['http://cwe.mitre.org/cwe-7']
    schema_identity: Literal['http://cwe.mitre.org/data/xsd/cwe_schema_v7.3.xsd']
    search_algorithm: Literal['weighted-token-v1']

EXPECTED_MANIFEST = Manifest(manifest_schema_version='1', corpus=EXPECTED_CORPUS,
                             xml_namespace=NAMESPACE, schema_identity=SCHEMA_IDENTITY,
                             search_algorithm=ALGORITHM)

class Suggestion(StrictModel):
    id: ID
    comment: Text512

class MappingNotes(StrictModel):
    rationale: Text1024
    comments: Text1024
    reasons: Annotated[list[Annotated[str, Field(max_length=256)]], Field(max_length=16)]
    suggestions: Annotated[list[Suggestion], Field(max_length=16)]

    @model_validator(mode='after')
    def combined_bound(self):
        if sum(map(len, [self.rationale, self.comments, *self.reasons,
                         *(s.comment for s in self.suggestions)])) > 4096:
            raise ValueError('mapping guidance exceeds bound')
        return self

class Candidate(StrictModel):
    id: ID
    cwe_id: Annotated[str, Field(pattern=r'^CWE-[1-9][0-9]{0,5}$', max_length=10)]
    name: Text512
    description: Text1024
    entry_type: Literal['Weakness', 'Category', 'View']
    status: Literal['Deprecated', 'Draft', 'Incomplete', 'Obsolete', 'Stable', 'Usable']
    abstraction: Literal['Pillar', 'Class', 'Base', 'Variant', 'Compound'] | None
    structure: Literal['Simple', 'Chain', 'Composite'] | None
    deprecated: bool
    obsolete: bool
    mapping_usage: Literal['Allowed', 'Allowed-with-Review', 'Discouraged', 'Prohibited'] | None
    mapping_notes: MappingNotes
    metadata_complete: bool
    truncated_fields: Annotated[list[Annotated[str, Field(max_length=64)]], Field(max_length=16)]

    @model_validator(mode='after')
    def consistency(self):
        if (self.cwe_id != f'CWE-{self.id}' or self.deprecated != (self.status == 'Deprecated')
                or self.obsolete != (self.status == 'Obsolete')):
            raise ValueError('inconsistent candidate identity/status')
        if self.entry_type == 'Weakness':
            if self.abstraction is None or self.structure is None:
                raise ValueError('weakness attributes required')
        elif self.abstraction is not None or self.structure is not None:
            raise ValueError('category/view attributes must be null')
        allowed = {'name', 'description', 'mapping_notes.rationale', 'mapping_notes.comments',
                   'mapping_notes.reasons', 'mapping_notes.suggestions'}
        if len(set(self.truncated_fields)) != len(self.truncated_fields) or not set(self.truncated_fields) <= allowed:
            raise ValueError('invalid truncation markers')
        complete = bool(self.name.strip() and self.description.strip() and self.mapping_usage
                        and self.mapping_notes.rationale.strip() and self.mapping_notes.comments.strip()
                        and self.mapping_notes.reasons and all(x.strip() for x in self.mapping_notes.reasons)
                        and not self.truncated_fields)
        if self.metadata_complete != complete:
            raise ValueError('inconsistent completeness')
        return self

class SearchCandidate(Candidate):
    rank: Annotated[int, Field(ge=1, le=5)]
    score: Annotated[int, Field(ge=0, le=416)]
    exact_id_match: bool

class SearchResponse(StrictModel):
    schema_version: Literal['1']
    corpus: CorpusIdentity
    search_algorithm: Literal['weighted-token-v1']
    results_limited: bool
    candidates: Annotated[list[SearchCandidate], Field(max_length=5)]

    @model_validator(mode='after')
    def ordering(self):
        ids = [c.id for c in self.candidates]
        if len(ids) != len(set(ids)):
            raise ValueError('duplicate candidates')
        keys = [(-int(c.exact_id_match), -c.score, c.id) for c in self.candidates]
        if (keys != sorted(keys) or sum(c.exact_id_match for c in self.candidates) > 1
                or any(c.rank != i or c.entry_type != 'Weakness' or (not c.score and not c.exact_id_match)
                       for i, c in enumerate(self.candidates, 1))):
            raise ValueError('inconsistent ranking')
        return self

class LookupResponse(StrictModel):
    schema_version: Literal['1']
    corpus: CorpusIdentity
    found: bool
    candidate: Candidate | None

    @model_validator(mode='after')
    def presence(self):
        if self.found != (self.candidate is not None):
            raise ValueError('inconsistent lookup')
        return self

SEARCH_SCHEMA = {'type': 'object', 'additionalProperties': False,
                 'properties': {'query': {'type': 'string', 'minLength': 1, 'maxLength': 512},
                                'max_results': {'type': 'integer', 'minimum': 1, 'maximum': 5, 'default': 5}},
                 'required': ['query']}
GET_SCHEMA = {'type': 'object', 'additionalProperties': False,
              'properties': {'id': {'type': 'integer', 'minimum': 1, 'maximum': 999999}}, 'required': ['id']}

def tokens(text: str) -> frozenset[str]:
    """NFKC, casefold, maximal Unicode alphanumeric runs (underscore separates)."""
    normalized = unicodedata.normalize('NFKC', text).casefold()
    return frozenset(re.findall(r'[^\W_]+', normalized, flags=re.UNICODE))

def validate_query(query: object) -> str:
    if (not isinstance(query, str) or not 1 <= len(query) <= 512 or not query.strip()
            or len(query.encode('utf-8')) > 2048
            or any(unicodedata.category(c).startswith('C') for c in query)
            or len(tokens(query)) > 32):
        raise ValueError('invalid query')
    return query

def strict_json(text: str):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid JSON constant')))

def wire_text(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
