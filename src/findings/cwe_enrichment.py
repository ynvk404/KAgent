"""Pinned local CWE retrieval; never assigns finding classifications.

Uses the packaged parser, never code from the configured data deployment.
The legacy config key cwe_mcp_deployment_path now selects data only.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from components.cwe_mcp.catalog import Catalog
from components.cwe_mcp.contract import (EXPECTED_CORPUS, EXPECTED_MANIFEST,
    RESPONSE_BYTES, LookupResponse, Manifest, SearchResponse, strict_json)
from src.async_io import run_sync
from src.workflow.evidence.review import digest


class TrustedSource:
    """Read-only local catalog with independently pinned identity and bounds."""
    def __init__(self, policy: Any):
        self.policy = policy
        self.signature = self.current_signature()
        deployment = Path(policy.cwe_mcp_deployment_path)
        self._catalog = Catalog(deployment / 'corpus/cwec_v4.20.xml', deployment / 'manifest.json')
        self.corpus = self._catalog.identity
        self.unchanged()

    def current_signature(self) -> str:
        deployment = getattr(self.policy, "cwe_mcp_deployment_path", None)
        if not isinstance(deployment, Path):
            raise ValueError('pinned local CWE catalog unavailable; configure cwe_mcp_deployment_path')
        if (not deployment.is_absolute() or deployment.resolve() != deployment or not deployment.is_dir()):
            raise ValueError('unsafe CWE deployment')
        fingerprints = []
        try:
            for name, cap in [('manifest.json', 4096), ('corpus/cwec_v4.20.xml', 32 * 1024 * 1024)]:
                path = deployment / name
                if path.resolve() != path or not path.is_file() or not 0 < path.stat().st_size <= cap:
                    raise ValueError('unsafe CWE catalog data')
                with path.open('rb') as stream:
                    raw = stream.read(cap + 1)
                if len(raw) > cap:
                    raise ValueError('oversized CWE catalog data')
                if name == 'manifest.json':
                    try:
                        manifest = Manifest.model_validate(strict_json(raw.decode('utf-8')))
                    except (ValueError, TypeError, RecursionError) as exc:
                        raise ValueError('invalid reviewed CWE manifest') from exc
                    if manifest != EXPECTED_MANIFEST:
                        raise ValueError('reviewed CWE manifest identity mismatch')
                else:
                    if hashlib.sha256(raw).hexdigest() != EXPECTED_CORPUS.xml_sha256:
                        raise ValueError('reviewed CWE corpus changed')
                fingerprints.append(hashlib.sha256(raw).hexdigest())
        except OSError as exc:
            raise ValueError('pinned local CWE catalog data unavailable') from exc
        return digest([str(deployment), fingerprints])

    def unchanged(self):
        if self.current_signature() != self.signature:
            raise ValueError('CWE source configuration changed during lookup')

    async def retrieve(self, kind: str, args: dict):
        # Owned blocking I/O leaves the event loop responsive and joins on cancel.
        # Queries contain only bounded mechanism text or an integer CWE ID.
        def lookup():
            if kind not in {'search', 'get'}:
                raise ValueError('unsupported CWE lookup kind')
            self.unchanged()
            payload = self._catalog.search(args) if kind == 'search' else self._catalog.get(args)
            self.unchanged()
            return validate_payload(payload, kind)
        return await run_sync(lookup)


def validate_payload(payload: Any, kind: str) -> SearchResponse | LookupResponse:
    try:
        if kind not in {'search', 'get'}:
            raise ValueError('unsupported lookup kind')
        if len(json.dumps(payload, ensure_ascii=True).encode('utf-8')) > RESPONSE_BYTES:
            raise ValueError('oversized CWE response')
        response = SearchResponse.model_validate(payload) if kind == 'search' else LookupResponse.model_validate(payload)
        if response.corpus != EXPECTED_CORPUS:
            raise ValueError('CWE corpus identity mismatch')
        if isinstance(response, SearchResponse) and any(c.exact_id_match for c in response.candidates):
            raise ValueError('unexpected exact-ID search flag')
        return response
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError('invalid pinned CWE response') from exc


def parse_response(output: str, kind: str) -> SearchResponse | LookupResponse:
    # Registry returns JSON text wrapping MCP content, not structuredContent.
    if not isinstance(output, str) or len(output.encode('utf-8')) > RESPONSE_BYTES * 2:
        raise ValueError('oversized CWE transport content')
    try:
        blocks = strict_json(output)
        if (not isinstance(blocks, list) or len(blocks) != 1 or not isinstance(blocks[0], dict)
                or not {'type', 'text'} <= set(blocks[0])
                or not set(blocks[0]) <= {'type', 'text', 'annotations', 'meta', '_meta'}
                or blocks[0]['type'] != 'text' or not isinstance(blocks[0]['text'], str)
                or any(value is not None for key, value in blocks[0].items() if key not in {'type', 'text'})):
            raise ValueError('expected exactly one plain MCP text block')
        # Use the actual payload + canonical MCP wrapper, including JSON escapes.
        envelope = {'content': blocks, 'isError': False}
        if len(json.dumps(envelope, ensure_ascii=True, separators=(',', ':')).encode('utf-8')) > RESPONSE_BYTES:
            raise ValueError('oversized CWE MCP response')
        payload = strict_json(blocks[0]['text'])
        return validate_payload(payload, kind)
    except (ValueError, TypeError, RecursionError) as exc:
        # Do not include Pydantic's input_value (untrusted source text) in errors.
        raise ValueError('invalid pinned CWE response') from exc
