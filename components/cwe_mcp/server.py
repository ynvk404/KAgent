"""Read-only stdio MCP entry point. No HTTP, downloads, application writes or logs."""
from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, TextContent, Tool

from .catalog import Catalog, CatalogError
from .contract import GET_SCHEMA, SEARCH_SCHEMA, RESPONSE_BYTES, wire_text

def envelope(payload: dict, error=False):
    return CallToolResult(content=[TextContent(type='text', text=wire_text(payload))], isError=error)

def envelope_size(result):
    # Reserve JSON-RPC framing/request-ID space beyond the actual serialized
    # result. KAgent's SDK uses small integer request IDs.
    return 1024 + len(result.model_dump_json(by_alias=True, exclude_none=True).encode('utf-8'))

def error_result(code):
    return envelope({'schema_version': '1', 'error': {'code': code, 'message': {
        'INVALID_ARGUMENT': 'Invalid tool arguments.', 'QUERY_TIMEOUT': 'Operation budget exceeded.',
        'RESPONSE_LIMIT': 'Response bound exceeded.', 'CORPUS_INVALID': 'Pinned corpus invalid.',
        'INTERNAL_ERROR': 'Catalog operation failed.'}[code]}}, True)

def execute(catalog, name, arguments):
    started = time.monotonic()
    try:
        if name not in {'search_cwe', 'get_cwe'}:
            return error_result('INVALID_ARGUMENT')
        payload = catalog.search(arguments) if name == 'search_cwe' else catalog.get(arguments)
        result = envelope(payload)
        while envelope_size(result) > RESPONSE_BYTES:
            if name != 'search_cwe' or not payload['candidates']:
                return error_result('RESPONSE_LIMIT')
            payload['candidates'].pop()
            payload['results_limited'] = True
            result = envelope(payload)
        if time.monotonic() - started > 2:
            return error_result('QUERY_TIMEOUT')
        return result
    except TimeoutError:
        return error_result('QUERY_TIMEOUT')
    except (ValueError, TypeError, UnicodeError):
        return error_result('INVALID_ARGUMENT')
    except Exception:
        return error_result('INTERNAL_ERROR')

async def main(root: Path):
    logging.disable(logging.CRITICAL)
    try:
        catalog = Catalog(root / 'corpus/cwec_v4.20.xml', root / 'manifest.json')
    except CatalogError:
        # Startup errors never include paths, queries or tracebacks.
        import sys
        sys.stderr.write('CORPUS_INVALID: pinned corpus invalid.\n')
        return 1
    server = Server('cwe_catalog', version='1.0.0')
    @server.list_tools()
    async def list_tools():
        return [Tool(name='search_cwe', description='Search pinned local CWE by lexical score.', inputSchema=SEARCH_SCHEMA),
                Tool(name='get_cwe', description='Look up an exact ID in pinned local CWE.', inputSchema=GET_SCHEMA)]
    @server.call_tool(validate_input=False)
    async def call_tool(name, arguments):
        return execute(catalog, name, arguments)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())
    return 0
