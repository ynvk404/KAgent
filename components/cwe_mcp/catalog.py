"""Bounded local parsing and deterministic lexical search. No I/O after startup."""
from __future__ import annotations

import hashlib
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from .contract import (ABSTRACTIONS, ALGORITHM, EXPECTED_MANIFEST, Manifest, NAMESPACE,
                       SCHEMA_IDENTITY, STATUSES, STRUCTURES, USAGES, XML_BYTES,
                       Candidate, LookupResponse, SearchResponse, tokens, strict_json, validate_query)

class CatalogError(ValueError):
    pass

def text(element):
    return ' '.join(' '.join(element.itertext()).split()) if element is not None else ''

class Catalog:
    def __init__(self, xml_path: Path, manifest_path: Path):
        try:
            if not 0 < manifest_path.stat().st_size <= 4096:
                raise ValueError('manifest size')
            manifest = Manifest.model_validate(strict_json(manifest_path.read_text('utf-8')))
            if manifest != EXPECTED_MANIFEST:
                raise ValueError('manifest identity')
            if not 0 < xml_path.stat().st_size <= XML_BYTES:
                raise ValueError('XML size')
            with xml_path.open('rb') as stream:
                raw = stream.read(XML_BYTES + 1)
            self._load(raw, manifest)
        except (OSError, ValueError, ET.ParseError, RecursionError) as exc:
            raise CatalogError('pinned corpus invalid') from exc

    def _load(self, raw: bytes, manifest: Manifest):
        # Refuse non-UTF8, DTDs and entities before Expat; no URL resolution.
        decoded = raw.decode('utf-8')
        if (len(raw) > XML_BYTES or hashlib.sha256(raw).hexdigest() != manifest.corpus.xml_sha256
                or re.search(r'<!\s*(?:DOCTYPE|ENTITY)', decoded, re.I)):
            raise ValueError('XML integrity')
        parser = ET.XMLPullParser(events=('start', 'end'))
        depth = count = 0
        for offset in range(0, len(raw), 65536):
            parser.feed(raw[offset:offset + 65536])
            for event_data in parser.read_events():
                event = event_data[0]
                depth += 1 if event == 'start' else -1
                count += event == 'start'
                if depth > 64 or count > 500000:
                    raise ValueError('XML structure bound')
        parser.close()
        root = ET.fromstring(raw)
        ns = '{' + NAMESPACE + '}'
        if (root.tag != ns + 'Weakness_Catalog' or root.get('Name') != 'CWE'
                or root.get('Version') != manifest.corpus.version or root.get('Date') != manifest.corpus.date
                or root.get('{http://www.w3.org/2001/XMLSchema-instance}schemaLocation', '').split()
                != [NAMESPACE, SCHEMA_IDENTITY]):
            raise ValueError('catalog identity')
        groups = {'Weaknesses': 'Weakness', 'Categories': 'Category', 'Views': 'View',
                  'External_References': 'External_Reference'}
        if ([e.tag for e in root] != [ns + g for g in groups]
                or any(e.tag != ns + groups[group.tag[len(ns):]] for group in root for e in group)):
            raise ValueError('unsupported catalog structure')
        self.identity = manifest.corpus
        self.entries = {}
        self.index = {}
        for group in list(root)[:3]:
            for entry in group:
                item = self._entry(entry, ns)
                if item.id in self.entries:
                    raise ValueError('duplicate ID')
                self.entries[item.id] = item
                if item.entry_type == 'Weakness':
                    alternate = ' '.join(text(e) for e in entry.findall(ns+'Alternate_Terms/'+ns+'Alternate_Term/'+ns+'Term'))
                    self.index[item.id] = (tokens(entry.get('Name', '')), tokens(alternate),
                                           tokens(text(entry.find(ns+'Description'))))
        if not self.index:
            raise ValueError('empty catalog')

    @staticmethod
    def _entry(e, ns):
        kind = e.tag[len(ns):]
        raw_id = e.get('ID', '')
        if not re.fullmatch(r'[1-9][0-9]{0,5}', raw_id) or not e.get('Name', '').strip() or e.get('Status') not in STATUSES:
            raise ValueError('mandatory attributes')
        if kind == 'Weakness' and (e.get('Abstraction') not in ABSTRACTIONS or e.get('Structure') not in STRUCTURES):
            raise ValueError('weakness enums')
        if kind == 'View' and e.get('Type') not in {'Implicit', 'Explicit', 'Graph'}:
            raise ValueError('view type')
        truncated = []
        remaining = 4096
        def bounded(value, cap, field, guidance=False):
            nonlocal remaining
            limit = min(cap, remaining) if guidance else cap
            if len(value) > limit:
                if field not in truncated:
                    truncated.append(field)
            result = value[:limit]
            if guidance:
                remaining -= len(result)
            return result
        def one(parent, name):
            children = parent.findall(ns+name) if parent is not None else []
            if len(children) > 1:
                raise ValueError('duplicate metadata')
            return children[0] if children else None
        notes = one(e, 'Mapping_Notes')
        usage = text(one(notes, 'Usage')) or None
        if usage is not None and usage not in USAGES:
            raise ValueError('mapping usage')
        rationale = bounded(text(one(notes, 'Rationale')), 1024, 'mapping_notes.rationale', True)
        comments = bounded(text(one(notes, 'Comments')), 1024, 'mapping_notes.comments', True)
        reasons_root = one(notes, 'Reasons')
        reasons = []
        if reasons_root is not None:
            for i, reason in enumerate(reasons_root):
                if reason.tag != ns+'Reason' or reason.get('Type') not in {
                    'Abstraction', 'Category', 'View', 'Deprecated', 'Potential Deprecation',
                    'Frequent Misuse', 'Frequent Misinterpretation', 'Multiple Use', 'CWE Overlap',
                    'Acceptable-Use', 'Potential Major Changes', 'Other',
                }:
                    raise ValueError('mapping reason')
                if i < 16:
                    reasons.append(bounded(' '.join(filter(None, [reason.get('Type'), text(reason)])),
                                           256, 'mapping_notes.reasons', True))
                elif 'mapping_notes.reasons' not in truncated:
                    truncated.append('mapping_notes.reasons')
        suggestions_root = one(notes, 'Suggestions')
        suggestions = []
        if suggestions_root is not None:
            for i, suggestion in enumerate(suggestions_root):
                if suggestion.tag != ns+'Suggestion' or not re.fullmatch(r'[1-9][0-9]{0,5}', suggestion.get('CWE_ID', '')):
                    raise ValueError('mapping suggestion')
                if i < 16:
                    suggestions.append({'id': int(suggestion.get('CWE_ID')), 'comment': bounded(
                        suggestion.get('Comment', ''), 512, 'mapping_notes.suggestions', True)})
                elif 'mapping_notes.suggestions' not in truncated:
                    truncated.append('mapping_notes.suggestions')
        name = bounded(e.get('Name'), 512, 'name')
        description = bounded(text(one(e, {'Weakness': 'Description', 'Category': 'Summary', 'View': 'Objective'}[kind])),
                              1024, 'description')
        complete = bool(name.strip() and description.strip() and usage and rationale.strip()
                        and comments.strip() and reasons and all(r.strip() for r in reasons) and not truncated)
        return Candidate.model_validate(dict(id=int(raw_id), cwe_id=f'CWE-{raw_id}', name=name,
            description=description, entry_type=kind, status=e.get('Status'),
            abstraction=e.get('Abstraction') if kind == 'Weakness' else None,
            structure=e.get('Structure') if kind == 'Weakness' else None,
            deprecated=e.get('Status') == 'Deprecated', obsolete=e.get('Status') == 'Obsolete',
            mapping_usage=usage, mapping_notes=dict(rationale=rationale, comments=comments,
                reasons=reasons, suggestions=suggestions), metadata_complete=complete, truncated_fields=truncated))

    def search(self, args: dict) -> dict:
        if not isinstance(args, dict) or not set(args) <= {'query', 'max_results'} or 'query' not in args:
            raise ValueError('invalid arguments')
        query = validate_query(args['query'])
        limit = args.get('max_results', 5)
        if type(limit) is not int or not 1 <= limit <= 5:
            raise ValueError('invalid result limit')
        deadline = time.monotonic() + 2
        query_tokens = tokens(query)
        exact = re.fullmatch(r'CWE-([1-9][0-9]{0,5})', query.strip())
        exact_id = int(exact[1]) if exact else None
        matches = []
        for ident, (name, alternate, description) in self.index.items():
            if time.monotonic() >= deadline:
                raise TimeoutError('query budget')
            score = sum(8 * (t in name) + 4 * (t in alternate) + (t in description) for t in query_tokens)
            is_exact = ident == exact_id
            if score or is_exact:
                matches.append((is_exact, score, ident))
        matches.sort(key=lambda row: (-int(row[0]), -row[1], row[2]))
        candidates = [dict(**self.entries[ident].model_dump(), rank=i, score=score, exact_id_match=is_exact)
                      for i, (is_exact, score, ident) in enumerate(matches[:limit], 1)]
        return SearchResponse.model_validate(dict(schema_version='1', corpus=self.identity.model_dump(),
            search_algorithm=ALGORITHM, results_limited=len(matches) > len(candidates), candidates=candidates)).model_dump()

    def get(self, args: dict) -> dict:
        if (not isinstance(args, dict) or set(args) != {'id'} or type(args['id']) is not int
                or not 1 <= args['id'] <= 999999):
            raise ValueError('invalid arguments')
        item = self.entries.get(args['id'])
        return LookupResponse(schema_version='1', corpus=self.identity, found=item is not None, candidate=item).model_dump()
