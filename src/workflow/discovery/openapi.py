"""Minimum JSON OpenAPI 3 request syntax. No YAML, JS, response inference or I/O."""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin

from src.target.origin import HTTPOrigin
from src.target.input_admission import canonical_endpoint, identity_text
from .extraction import Extraction, ExtractedRecord, document_text, resolved_url

MAX_PATHS = 64
MAX_OPERATIONS = 128
MAX_PARAMETERS = 256
MAX_SCHEMA_NODES = 1024
MAX_REF_DEPTH = 8
MAX_SCHEMA_DEPTH = 16
METHODS = frozenset({'get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace'})


def extract_openapi(body: bytes, document_url: str, *, complete: bool = True) -> Extraction:
    result = Extraction()
    result.bounds.update(max_paths=MAX_PATHS, max_operations=MAX_OPERATIONS, max_parameters=MAX_PARAMETERS,
                         max_schema_nodes=MAX_SCHEMA_NODES, max_ref_depth=MAX_REF_DEPTH)
    origin = HTTPOrigin.from_url(document_url).as_url()
    document_url = canonical_endpoint(document_url, origin)
    text = document_text(body, result, complete)

    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError('duplicate JSON member')
            obj[key] = value
        return obj

    try:
        document = json.loads(text, object_pairs_hook=unique,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid JSON number')))
    except (ValueError, UnicodeError, RecursionError):
        result.issue('malformed, duplicate-member or truncated JSON document')
        return result
    if not isinstance(document, dict) or not re.fullmatch(r'3\.(?:0|1)\.\d+', str(document.get('openapi', ''))):
        result.not_applicable = True
        return result
    paths = document.get('paths')
    if not isinstance(paths, dict):
        result.issue('OpenAPI paths object unavailable')
        return result
    node_count = 0
    parameter_count = 0
    operation_count = 0

    def resolve(node: Any, chain: tuple[str, ...] = ()) -> tuple[dict | None, tuple[str, ...]]:
        nonlocal node_count
        node_count += 1
        if node_count > MAX_SCHEMA_NODES:
            result.issue('max_schema_nodes=1024 reached')
            return None, chain
        if not isinstance(node, dict):
            result.issue('unsupported or malformed OpenAPI object')
            return None, chain
        ref = node.get('$ref')
        if ref is None:
            return node, chain
        if not isinstance(ref, str) or not ref.startswith('#/'):
            result.issue('external or unsupported reference excluded; no fetch')
            return None, chain
        if ref in chain:
            result.issue('local reference cycle excluded')
            return None, chain
        if len(chain) >= MAX_REF_DEPTH:
            result.issue('max_ref_depth=8 reached')
            return None, chain
        if re.search(r'~(?![01])', ref):
            result.issue('invalid local JSON Pointer')
            return None, chain
        current = document
        try:
            for raw in ref[2:].split('/'):
                key = raw.replace('~1', '/').replace('~0', '~')
                if isinstance(current, dict):
                    current = current[key]
                elif isinstance(current, list) and re.fullmatch(r'0|[1-9][0-9]*', key):
                    current = current[int(key)]
                else:
                    raise KeyError
        except (KeyError, IndexError):
            result.issue('unavailable local reference')
            return None, chain
        if set(node) - {'$ref', 'description', 'summary'}:
            result.issue('reference siblings unsupported by minimum extractor')
        return resolve(current, (*chain, ref))

    def servers(value: Any) -> list[str]:
        if value is None:
            return [origin]
        if not isinstance(value, list) or not value:
            result.issue('empty or malformed servers; operation base uncertain')
            return []
        if len(value) > 8:
            result.issue('server alternatives limit=8 reached')
        output = []
        for server in value[:8]:
            if not isinstance(server, dict) or not isinstance(server.get('url'), str):
                result.issue('invalid server URL excluded')
                continue
            url = server['url']
            if '{' in url or '}' in url or '?' in url:
                result.issue('server variables/query unsupported; operation base uncertain')
                continue
            resolved = resolved_url(url, document_url, origin, result)
            if resolved is not None and resolved not in output:
                output.append(resolved.rstrip('/'))
        return output

    def parameter_rows(raw: Any, chain: tuple[str, ...]) -> dict[tuple[str, str], dict]:
        nonlocal parameter_count
        output = {}
        if not isinstance(raw, list):
            result.issue('parameters must be a bounded array')
            return output
        for node in raw[:MAX_PARAMETERS]:
            parameter_count += 1
            if parameter_count > MAX_PARAMETERS:
                result.issue('max_parameters=256 reached')
                break
            node, _ = resolve(node, chain)
            if node is None:
                continue
            try:
                name = identity_text(node.get('name'), 'parameter', required=True)
                location = node.get('in')
                if not isinstance(location, str) or location not in {'path', 'query', 'header', 'cookie'}:
                    raise ValueError
            except ValueError:
                result.issue('invalid or sensitive parameter declaration excluded')
                continue
            key = (location, name)
            if key in output:
                result.issue('duplicate parameter declaration excluded')
                continue
            output[key] = node
        if len(raw) > MAX_PARAMETERS:
            result.issue('max_parameters=256 reached')
        return output

    def schema_fields(schema: Any, url: str, method: str, media: str, locator: str,
                      chain: tuple[str, ...], prefix: tuple[str, ...] = (), depth: int = 0):
        if depth > MAX_SCHEMA_DEPTH:
            result.issue('schema depth limit=16 reached')
            return
        node, chain = resolve(schema, chain)
        if node is None:
            return
        if any(key in node for key in ('allOf', 'oneOf', 'anyOf', 'if', 'then', 'else', 'additionalProperties')):
            result.issue('composed or dynamic schema fields unsupported')
        props = node.get('properties', {})
        if not isinstance(props, dict):
            result.issue('request properties must be an object')
            return
        if node.get('type') == 'array':
            result.issue('array item fields require a concrete request selector; no indices invented')
            return
        required = node.get('required', [])
        valid_required = isinstance(required, list) and all(isinstance(key, str) for key in required)
        if not valid_required:
            result.issue('malformed required array; field requirement uncertain')
        for index, (name, field_schema) in enumerate(props.items()):
            if node_count >= MAX_SCHEMA_NODES or len(result.records) >= result.bounds['max_records']:
                result.issue('schema node/record bound reached; remaining properties omitted')
                break
            try:
                identity_text(name, 'parameter', required=True)
                parts = (*prefix, name)
                parameter = name if not prefix else '/' + '/'.join(part.replace('~', '~0').replace('/', '~1') for part in parts)
                identity_text(parameter, 'parameter', required=True)
                field_node, field_chain = resolve(field_schema, chain)
                if field_node is None:
                    continue
                kind = field_node.get('type')
                if kind is not None and (not isinstance(kind, str) or kind not in {'string', 'number', 'integer', 'object', 'array', 'boolean', 'null'}):
                    result.issue('schema type union/unknown type retained as uncertain')
                    kind = None
                location = 'json' if media == 'application/json' or media.endswith('+json') else 'form'
                result.add(ExtractedRecord(url, method, locator, parameter, location, kind, media, index,
                                           name in required if valid_required else None))
                if location == 'json' and 'properties' in field_node:
                    schema_fields(field_node, url, method, media, locator, field_chain, parts, depth + 1)
            except (ValueError, TypeError):
                result.issue('invalid or sensitive request schema field excluded')

    for path_index, (path, raw_path) in enumerate(paths.items()):
        if path_index >= MAX_PATHS:
            result.issue('max_paths=64 reached')
            break
        if not isinstance(path, str) or not path.startswith('/') or '?' in path or '#' in path:
            result.issue('invalid operation path excluded')
            continue
        path_item, path_chain = resolve(raw_path)
        if path_item is None:
            continue
        shared_parameters = parameter_rows(path_item.get('parameters', []), path_chain)
        for method, raw_operation in path_item.items():
            if method not in METHODS:
                if method.lower() in METHODS:
                    result.issue('non-canonical duplicate/uppercase HTTP operation excluded')
                continue
            operation_count += 1
            if operation_count > MAX_OPERATIONS:
                result.issue('max_operations=128 reached')
                break
            operation, operation_chain = resolve(raw_operation, path_chain)
            if operation is None:
                continue
            parameters = {**shared_parameters, **parameter_rows(operation.get('parameters', []), operation_chain)}
            operation_servers = operation.get('servers', path_item.get('servers', document.get('servers')))
            for base in servers(operation_servers):
                url = resolved_url(base + path, origin + '/', origin, result)
                if url is None:
                    continue
                locator = f'openapi:paths:{path_index}:{method}'
                result.add(ExtractedRecord(url, method.upper(), locator))
                for occurrence, ((location, name), parameter) in enumerate(parameters.items()):
                    if location == 'path' and '{' + name + '}' not in path:
                        result.issue('path parameter does not match operation template')
                        continue
                    schema, _ = resolve(parameter.get('schema', {}), operation_chain)
                    kind = schema.get('type') if schema else None
                    if kind is not None and (not isinstance(kind, str) or kind not in {'string', 'number', 'integer', 'object', 'array', 'boolean', 'null'}):
                        result.issue('parameter schema type union/unknown type retained as uncertain')
                        kind = None
                    required = parameter.get('required')
                    if required is not None and type(required) is not bool:
                        result.issue('parameter required flag uncertain')
                        required = None
                    result.add(ExtractedRecord(url, method.upper(), locator, name, location, kind,
                                               occurrence=occurrence, required=required))
                if 'requestBody' not in operation:
                    continue
                request, request_chain = resolve(operation['requestBody'], operation_chain)
                if request is None:
                    continue
                content = request.get('content')
                if not isinstance(content, dict):
                    result.issue('requestBody content unavailable')
                    continue
                if len(content) > 8:
                    result.issue('request media alternatives limit=8 reached')
                for media, value in list(content.items())[:8]:
                    try:
                        media = identity_text(media, 'content_type', required=True)
                        if media is None or not isinstance(value, dict):
                            raise ValueError
                        result.add(ExtractedRecord(url, method.upper(), locator, content_type=media))
                        if media in {'application/json', 'application/x-www-form-urlencoded', 'multipart/form-data'} or media.endswith('+json'):
                            schema_fields(value.get('schema', {}), url, method.upper(), media, locator, request_chain)
                        else:
                            result.issue('request media schema unsupported; no field serialization inferred')
                    except ValueError:
                        result.issue('invalid request media declaration excluded')
    return result
