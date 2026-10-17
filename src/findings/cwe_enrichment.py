"""Pinned CWE catalog client validation for standalone deployment checks.

These helpers validate retrieval only; they never assign finding classifications.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import Any

from components.cwe_mcp.contract import (EXPECTED_CORPUS, EXPECTED_MANIFEST,
    GET_SCHEMA, SEARCH_SCHEMA, RESPONSE_BYTES, LookupResponse, Manifest,
    SearchResponse, strict_json)
from src.tools.common.registry import Registry
from src.tools.mcp.integration import MCPTool
from src.tools.mcp.cwe_deployment import (
    CWE_MCP_ARGS,
    CWE_MCP_COMMAND,
    CWE_MCP_LAUNCH_PATH,
    CWE_MCP_SERVER_NAME,
    require_matching_cwe_deployment,
)
from src.workflow.review import digest

SEARCH_TOOL = 'mcp_cwe_catalog_search_cwe'
GET_TOOL = 'mcp_cwe_catalog_get_cwe'
DEPLOYMENT_LAUNCH = CWE_MCP_LAUNCH_PATH


class TrustedSource:
    """Expected identity comes from reviewed deployment/config, never payloads."""
    def __init__(self, registry: Registry, policy: Any):
        self.registry, self.policy = registry, policy
        self.search = registry.get(SEARCH_TOOL)
        self.lookup = registry.get(GET_TOOL)
        self.signature = self.current_signature()

    def current_signature(self) -> str:
        tools = []
        for expected, tool, remote, schema in (
            (SEARCH_TOOL, self.search, 'search_cwe', SEARCH_SCHEMA),
            (GET_TOOL, self.lookup, 'get_cwe', GET_SCHEMA),
        ):
            if (type(tool) is not MCPTool or self.registry.get(expected) is not tool
                    or tool.name() != expected or tool._remote_name != remote
                    or tool._session.server_name != 'cwe_catalog'
                    or tool._execution_policy is not self.policy or tool.cfg is None
                    or tool.cfg.name != CWE_MCP_SERVER_NAME or tool.cfg.command != CWE_MCP_COMMAND
                    or tuple(tool.cfg.args) != CWE_MCP_ARGS or tool.cfg.env
                    or tool.schema() != schema):
                raise ValueError('designated pinned CWE MCP configuration unavailable or changed')
            tools.append(asdict(tool.cfg))
        deployment = require_matching_cwe_deployment(self.policy, self.policy.worker)
        if (deployment is None or not deployment.is_absolute() or deployment.is_symlink()
                or deployment.resolve() != deployment or not deployment.is_dir()):
            raise ValueError('unsafe CWE deployment')
        manifest_path = deployment / 'manifest.json'
        if manifest_path.is_symlink() or not 0 < manifest_path.stat().st_size <= 4096:
            raise ValueError('invalid reviewed manifest')
        try:
            manifest = Manifest.model_validate(strict_json(manifest_path.read_text('utf-8')))
        except ValueError as exc:
            raise ValueError('invalid reviewed CWE manifest') from exc
        if manifest != EXPECTED_MANIFEST:
            raise ValueError('reviewed manifest identity mismatch')
        files = ['launch.py', 'manifest.json', *('server/cwe_mcp/'+name for name in
                 ('__init__.py', 'contract.py', 'catalog.py', 'server.py'))]
        fingerprints: list[str | None] = []
        for name in files:
            path = deployment / name
            if path.resolve() != path or not path.is_file() or path.stat().st_size > 131072:
                raise ValueError('unsafe CWE deployment file')
            fingerprints.append(hashlib.sha256(path.read_bytes()).hexdigest())
        xml_path = deployment / 'corpus/cwec_v4.20.xml'
        if xml_path.resolve() != xml_path or not 0 < xml_path.stat().st_size <= 32 * 1024 * 1024:
            raise ValueError('unsafe CWE deployment corpus')
        with xml_path.open('rb') as stream:
            xml_hash = hashlib.sha256(stream.read(32 * 1024 * 1024 + 1)).hexdigest()
        if xml_hash != EXPECTED_CORPUS.xml_sha256:
            raise ValueError('reviewed CWE deployment corpus changed')
        fingerprints.append(xml_hash)
        archive = deployment / 'runtime.zip'
        if archive.exists():
            if archive.resolve() != archive or not archive.is_file() or archive.stat().st_size > 64 * 1024 * 1024:
                raise ValueError('unsafe CWE runtime archive')
            with archive.open('rb') as stream:
                fingerprints.append(hashlib.file_digest(stream, 'sha256').hexdigest())
        else:
            fingerprints.append(None)
        return digest([tools, fingerprints, manifest.model_dump(), str(deployment)])

    def unchanged(self):
        if self.current_signature() != self.signature:
            raise ValueError('CWE source configuration changed during lookup')

    async def retrieve(self, kind: str, args: dict, prompter: Any):
        self.unchanged()
        tool = SEARCH_TOOL if kind == 'search' else GET_TOOL
        output = await self.registry.execute(tool, args, None, prompter)
        self.unchanged()
        return parse_response(output, kind)


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
        response = (SearchResponse.model_validate(payload) if kind == 'search'
                    else LookupResponse.model_validate(payload))
        if response.corpus != EXPECTED_CORPUS:
            raise ValueError('CWE corpus identity mismatch')
        if isinstance(response, SearchResponse) and any(c.exact_id_match for c in response.candidates):
            # Mechanism queries constructed by this consumer are never exact IDs.
            raise ValueError('unexpected exact-ID search flag')
        return response
    except (ValueError, TypeError, RecursionError) as exc:
        # Do not include Pydantic's input_value (untrusted source text) in errors.
        raise ValueError('invalid pinned CWE response') from exc
