"""Operator-only classification controller. Retrieval and promotion are independent.

No model-facing tool, direct MCP session, proof certificate, ValidationResult,
coverage mutation or durable query/candidate cache exists here.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import unicodedata
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

from components.cwe_mcp.contract import (ALGORITHM, EXPECTED_CORPUS, EXPECTED_MANIFEST,
    GET_SCHEMA, SEARCH_SCHEMA, RESPONSE_BYTES, Candidate, LookupResponse, Manifest,
    SearchResponse, strict_json, tokens, validate_query)
from src.findings.store import Finding, Store, read_report, report_bytes, classification_header
from src.target.origin import HTTPOrigin
from src.permission.permission import Decision, PermissionRequest
from src.permission.runtime.execution import policy_for
from src.redact.redact import apply_evidence
from src.tools.common.registry import Registry
from src.tools.mcp.integration import MCPTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.evidence import verify_evidence_reads
from src.workflow.review import digest, review_snapshot

SEARCH_TOOL = 'mcp_cwe_catalog_search_cwe'
GET_TOOL = 'mcp_cwe_catalog_get_cwe'
DEPLOYMENT_LAUNCH = '/work/cwe-mcp-deployment/launch.py'


def promotable(candidate: Candidate) -> bool:
    # Maturity is independent of mapping permission; Variant is an abstraction.
    return (candidate.entry_type == 'Weakness' and candidate.status not in {'Deprecated', 'Obsolete'}
            and candidate.metadata_complete and not candidate.truncated_fields
            and candidate.mapping_usage == 'Allowed')


def mechanism_query(finding: Finding) -> str:
    """Only mechanism vocabulary from persisted class/title is sent.

    Tokens outside the fixed vocabulary, URLs and credential-labelled fragments
    are excluded before the existing conservative redactor. Unlabelled dictionary
    words remain indistinguishable from mechanism words. No evidence/impact body
    is read into the query. This is lexical minimization, never mechanism inference.
    """
    vocabulary = tokens('access control authorization authentication missing improper incorrect bypass '
        'privilege escalation unauthenticated unauthorized sensitive information disclosure exposure '
        'injection sql command os code script cross site scripting request forgery server side '
        'template traversal path directory file upload unsafe unrestricted deserialization csrf ssrf '
        'ssti xss idor session fixation weak password cryptographic race redirect arbitrary resource '
        'permissions origin neutralization special elements object identifier reference untrusted input '
        'output encoding validation credentials logout expiry expiration cookie insecure randomness '
        'business logic integrity workflow rate limit denial service memory read write user controlled key')
    # Normalize before identifying labels, just as tokens() does. Strip format
    # controls so they cannot split a credential label. Once a label appears,
    # discard the remaining fragment: header schemes, quoted/multiword values
    # and continuation lines must not become mechanism words. Unknown canonical
    # class identifiers are model-controlled too, so use the same minimizer.
    pieces = []
    for raw in (finding.canonical_class or '', finding.title):
        piece = unicodedata.normalize('NFKC', raw[:512])
        piece = re.sub(r'(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]', '', piece)
        piece = ''.join(' ' if c.isspace() else c for c in piece
                        if c.isspace() or not unicodedata.category(c).startswith('C'))
        credential = re.search(r'(?i)\b(?:(?:authorization|cookie|set-cookie|password|passwd|pwd|api[-_]?key|'
                               r'secret|token|session|jwt)\s*[:=]|bearer\s+)', piece)
        if credential:
            piece = piece[:credential.start()]
        pieces.append(re.sub(r'(?i)(?:[a-z][a-z0-9+.-]*://\S+|\beyJ\S+)', '', piece))
    selected = sorted(set().union(*(tokens(piece) & vocabulary for piece in pieces)))[:32]
    query = apply_evidence(' '.join(selected))[:512]
    return validate_query(query)


def plain_data(value: Any) -> str:
    """JSON escapes terminal controls and line breaks; UI renders plain Text."""
    return json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2)


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
                    or tool.cfg.name != 'cwe_catalog' or tool.cfg.command != '/usr/bin/python3'
                    or tool.cfg.args != ['-I', '-B', DEPLOYMENT_LAUNCH] or tool.cfg.env
                    or tool.schema() != schema):
                raise ValueError('designated pinned CWE MCP configuration unavailable or changed')
            tools.append(asdict(tool.cfg))
        deployment = self.policy.root / 'cwe-mcp-deployment'
        if deployment.is_symlink() or deployment.resolve() != deployment:
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
        fingerprints = []
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
        return digest([tools, fingerprints, manifest.model_dump()])

    def unchanged(self):
        if self.current_signature() != self.signature:
            raise ValueError('CWE source configuration changed during review')

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


class Enrichment:
    """Ephemeral controller review state for one explicit operator invocation."""
    def __init__(self, agent: Any, store: Store, candidate_id: str):
        self.agent, self.store, self.cid = agent, store, candidate_id
        policy = policy_for(agent.prompter)
        if policy is None:
            raise ValueError('CWE enrichment requires the existing execution policy')
        self.policy = policy
        self.path = store.report_for_candidate(candidate_id)
        self.finding = read_report(self.path)
        self.report_digest = hashlib.sha256(report_bytes(self.path)).hexdigest()
        self.revision = self.finding.classification_revision
        self.ticket = ''
        self.source: TrustedSource | None = None

    @contextmanager
    def evidence_receipt(self):
        # Evidence reads use the existing workflow adapter/receipt; no workflow
        # operation is invoked and no result/proof/coverage is written.
        tool = self.agent.tools.get('workflow')
        if type(tool) is not WorkflowTool or tool.state is not self.agent.workflow:
            raise ValueError('workflow evidence adapter unavailable')
        args = {'action': 'list', 'candidate_id': self.cid, 'limit': 1}
        receipt = self.policy.prepare(tool, args)
        token = None
        try:
            token = self.policy.start(receipt, tool, args, None)
            yield
        finally:
            if token is not None:
                self.policy.stop(token)
            self.policy.finish_review(receipt)

    def guard(self):
        task = asyncio.current_task()
        if task is not None and task.cancelling():
            raise asyncio.CancelledError
        state = self.agent.workflow
        candidate = state.candidates.get(self.cid)
        result = state.latest_result(self.cid)
        if (candidate is not self.candidate or result is not self.result
                or not state.eligible_for_finding(self.cid)
                or review_snapshot(state, self.cid) != self.binding
                or self.policy.stamp() != self.stamp
                or not self.policy.observations.review_is_current('cwe:'+self.cid, self.ticket)):
            raise ValueError('CWE review result/candidate/policy changed or superseded')
        if self.source is not None:
            self.source.unchanged()
        if hashlib.sha256(report_bytes(self.path)).hexdigest() != self.report_digest:
            raise ValueError('CWE reviewed report changed')
        if self.store.report_for_candidate(self.cid) != self.path:
            raise ValueError('CWE reviewed report identity changed')
        for artifact in self.artifacts:
            self.policy.require_evidence(artifact, self.policy.root)
            if not artifact.is_resolvable(self.policy.root, sensitive_read_approved=True):
                raise ValueError('CWE reviewed evidence changed')

    async def check_evidence(self):
        with self.evidence_receipt():
            if not await verify_evidence_reads(self.artifacts, self.policy.root, self.agent.prompter, None,
                                                approved_paths=self.approved_paths):
                raise ValueError('CWE reviewed evidence unavailable')
            self.guard()

    async def run(self, choose: Callable[[tuple[Candidate, ...]], Awaitable[int | None]],
                  publish: Callable[[Finding, str], None]) -> str:
        if self.finding.candidate_id != self.cid:
            raise ValueError('persisted finding Candidate identity mismatch')
        # Local-first: even legacy classified findings return before source,
        # review, proof reads or taxonomy. Existing primary CWE is immutable.
        if self.finding.cwe:
            return f'Finding already has a persisted CWE ({self.finding.classification_origin}); classification preserved.'
        classification_header(report_bytes(self.path))
        state = self.agent.workflow
        self.candidate = state.candidates.get(self.cid)
        self.result = state.latest_result(self.cid)
        if (self.candidate is None or self.result is None or not state.eligible_for_finding(self.cid)
                or self.finding.canonical_class != self.candidate.candidate_class
                or self.finding.evidence_refs != self.result.evidence_refs
                or self.finding.confirmation_binding != review_snapshot(state, self.cid)):
            raise ValueError('persisted finding cannot be bound to current confirmed result/evidence')
        if self.candidate.target and HTTPOrigin.from_url(self.finding.url) != HTTPOrigin.from_url(self.candidate.target):
            raise ValueError('persisted finding target differs from Candidate')
        if self.candidate.endpoint:
            endpoint = re.sub(r'^\s*(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+', '',
                              self.candidate.endpoint, count=1, flags=re.I)
            template = re.escape(urlparse(endpoint).path).replace(r'\{', '{').replace(r'\}', '}')
            template = re.sub(r'\{[^{}]+\}', r'[^/]+', template)
            if not re.fullmatch(template, urlparse(self.finding.url).path):
                raise ValueError('persisted finding endpoint differs from Candidate')
        if ((self.candidate.method and self.finding.method != self.candidate.method)
                or (self.candidate.parameter and self.finding.parameter != self.candidate.parameter)):
            raise ValueError('persisted finding method/parameter differs from Candidate')
        self.policy.engagement.require_in_scope(self.candidate.target or '')
        self.binding = review_snapshot(state, self.cid)
        self.stamp = self.policy.stamp()
        self.artifacts = [state.evidence[ref] for ref in self.result.evidence_refs]
        self.approved_paths: set[str] = set()
        self.ticket = self.policy.observations.begin_review('cwe:'+self.cid)
        try:
            await self.check_evidence()
            self.source = TrustedSource(self.agent.tools, self.policy)
            response = await self.source.retrieve('search', {'query': mechanism_query(self.finding), 'max_results': 5}, self.agent.prompter)
            assert isinstance(response, SearchResponse)
            candidates = tuple(Candidate.model_validate({k: v for k, v in c.model_dump().items()
                if k not in {'rank', 'score', 'exact_id_match'}}) for c in response.candidates if promotable(c))
            await self.check_evidence()
            if not candidates:
                return 'No review-eligible CWE candidates; finding remains unresolved.'
            candidate_digest = digest([c.model_dump() for c in candidates])
            index = await choose(tuple(c.model_copy(deep=True) for c in candidates))
            await self.check_evidence()
            if index is None:
                return 'CWE review abstained; finding remains unresolved.'
            if type(index) is not int or not 1 <= index <= len(candidates):
                raise ValueError('only a displayed controller-owned candidate may be selected')
            selected = candidates[index - 1]
            review = getattr(self.agent.prompter, 'operator_review_prompter', lambda: self.agent.prompter)()
            decision = await review.ask(PermissionRequest(tool='enrich_cwe_review',
                summary=f'Review mechanism fit for {selected.cwe_id}', no_session_cache=True,
                detail=('Classification only; ranking is a lexical search score, never confidence or proof.\n'
                        'Allow once explicitly confirms that this CWE describes the evidenced mechanism. '
                        'Severity, impact, evidence, proof and OWASP remain unchanged.\n'
                        f'Persisted class: {self.finding.canonical_class}\n'
                        f'Source: cwe_catalog; {plain_data(EXPECTED_CORPUS.model_dump())}\n'
                        f'Reviewed candidate (plain source data):\n{plain_data(selected.model_dump())}')), None)
            await self.check_evidence()
            if decision != Decision.ALLOW_ONCE:
                return 'CWE mechanism review declined; finding remains unresolved.'
            exact = await self.source.retrieve('get', {'id': selected.id}, self.agent.prompter)
            assert isinstance(exact, LookupResponse)
            await self.check_evidence()
            if not exact.found or exact.candidate is None or exact.candidate != selected or not promotable(exact.candidate):
                raise ValueError('exact CWE lookup does not match reviewed classification metadata')
            provenance = dict(origin='promoted-external', operator_reviewed=True,
                selected_cwe=selected.cwe_id, server='cwe_catalog', search_tool=SEARCH_TOOL, lookup_tool=GET_TOOL,
                corpus=EXPECTED_CORPUS.model_dump(), search_algorithm=ALGORITHM, revision=self.revision + 1,
                binding_digest=digest([str(self.path), self.report_digest, self.binding,
                    [e.to_dict() for e in self.artifacts], candidate_digest, selected.model_dump(),
                    self.source.signature, self.ticket, self.stamp]))
            # No report lock is held during dialogs or MCP calls. The receipt
            # remains active while temp preparation/final integrity checks run.
            with self.evidence_receipt():
                _, durable = await self.store.promote_classification(self.path,
                    expected_digest=self.report_digest, expected_revision=self.revision,
                    cwe=selected.cwe_id, provenance=provenance, guard=self.guard, publish=publish)
            return (f'Persisted CWE classification: {selected.cwe_id}. '
                    + ('Report and directory fsync completed.' if durable else
                       'Replacement is visible; directory durability could not be confirmed.'))
        finally:
            self.policy.observations.finish_review('cwe:'+self.cid, self.ticket)
