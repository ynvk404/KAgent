"""Local extraction of a selected admitted source under the Registry receipt.

The invocation controller is runtime-only, like native/scanner publication hooks.
No model/session payload can install a reader or restore source authorization.
"""
from contextvars import ContextVar
import hashlib
from typing import Any

from src.permission.runtime.execution import ExecutionBlocked, policy_for
from src.permission.network.grants import check_cancelled
from src.target.input_admission import canonical_endpoint
from src.workflow.assessment import digest, source_row
from src.workflow.extraction import extract_html, apply_extraction

controller: ContextVar[tuple[Any, str] | None] = ContextVar('discovery_source_controller', default=None)


def read_admitted_source(agent, tool, source, prompter, *, require_receipt=True):
    """Reuse current policy, admitted ObservationStore and scoped capture path."""
    from src.tools.http.http_tool import HTTPTool
    from src.tools.common.browser_capture import BrowserCaptureGetTool
    from src.browser.scoped_store import ScopedCaptureStore
    from src.tools.common.tool_result import ReadHTTPObservation
    policy = policy_for(prompter)
    if (agent is None or agent.workflow is not tool.state or agent.tools.get('workflow') is not tool
            or policy is None or policy is not policy_for(agent.prompter)
            or (require_receipt and not policy.nested_allowed())):
        raise ExecutionBlocked('blocked: source extraction requires its current controller and Registry receipt')
    if source.kind not in {'http', 'capture'}:
        raise ValueError('source has no admitted HTML/JSON response bytes; inspect its original discovery dataset')
    capability = 'http' if source.kind == 'http' else 'browser_capture_get'
    if ({'*', capability, 'read_http_observation'} & policy.revoked
            or not agent.is_tool_allowed(capability).ok):
        raise ExecutionBlocked('blocked: original discovery source capability unavailable or revoked')
    policy.require_network(source.document_url)
    item = policy.observations._items.get(source.retained_ref)
    if (item is None or item.retained_hash != source.retained_hash
            or item.epoch != policy.engagement.http_permissions.epoch
            or (item.source_details or {}).get('analysis_session') != (
                policy.session_id or policy.engagement.http_permissions.session_id)
            or item.objective_id not in {None, source.objective_id}
            or digest(source_row(item)) != item.retained_hash
            or hashlib.sha256(item.body).hexdigest() != item.response_hash
            or canonical_endpoint(item.url, source.target_origin) != source.document_url):
        raise ExecutionBlocked('blocked: exact admitted source bytes/session/integrity unavailable; no replacement lookup')
    if item.candidate_id is not None:
        # Retain existing attempt ownership, supersession and context checks.
        ReadHTTPObservation(agent).validate_rights({'observation_id': item.id, 'start_char': 0, 'max_chars': 1},
                                                   prompter, receipt=require_receipt)
    elif policy.generic_validation is not None and policy.generic_validation.restricted():
        raise ExecutionBlocked('blocked: unowned discovery source cannot be borrowed by a validation attempt')
    source_tool = agent.tools.get(capability)
    if source.kind == 'http':
        if (type(source_tool) is not HTTPTool or source_tool.workflow is not tool.state
                or source_tool.target is not agent.target or source_tool.engagement is not policy.engagement
                or item.source_kind != 'native-http' or item.producer != 'http'):
            raise ExecutionBlocked('blocked: admitted HTTP source adapter changed')
    else:
        if type(source_tool) is not BrowserCaptureGetTool or item.source_kind != 'imported-capture':
            raise ExecutionBlocked('blocked: admitted capture source adapter changed')
        capture = ScopedCaptureStore(source_tool.store, policy).get_request(source.locator)
        if (capture is None or capture.id != (item.source_details or {}).get('capture_id')
                or capture.received_at != (item.source_details or {}).get('received_at')
                or capture.url != item.url or capture.method != item.method
                or hashlib.sha256((capture.response_body or '').encode()[:65536]).hexdigest() != item.response_hash):
            raise ExecutionBlocked('blocked: exact scoped capture binding changed; recapture required')
    if any(secret.encode() in item.body for secret in agent._managed_http_secrets()):
        raise ExecutionBlocked('blocked: source contains a known internal secret')
    return item


def process_source(tool, args, signal, prompter):
    check_cancelled(signal)
    context = controller.get()
    if context is None:
        raise ExecutionBlocked('blocked: source extraction controller unavailable')
    agent, invocation_scope = context
    from src.agent.scope import runtime_scope
    if runtime_scope(agent) != invocation_scope:
        raise ExecutionBlocked('blocked: source extraction invocation generation/scope changed during review')
    source = tool.state.discovery_source(args['discovery_source_id'], generation=tool.state.generation,
                                         retained_ref=args['retained_ref'])
    if not source.selected:
        raise ValueError('select the exact source before bounded extraction')
    item = read_admitted_source(agent, tool, source, prompter)
    if args['extractor'] not in {'html', 'openapi'}:
        raise ValueError('unsupported source extractor')
    from src.workflow.openapi import extract_openapi
    from src.workflow.extraction import Extraction
    from src.workflow.state import normalize_media_type
    extractor = extract_html if args['extractor'] == 'html' else extract_openapi
    media = {normalize_media_type(value) for key, value in item.response_headers if key.lower() == 'content-type'}
    if args['extractor'] == 'html' and media and not media <= {'text/html', 'application/xhtml+xml'}:
        extraction = Extraction(not_applicable=True, stop_reason='observed response media is not HTML')
    else:
        extraction = extractor(item.body, source.document_url, complete=item.complete and not item.truncated)
    check_cancelled(signal)
    return apply_extraction(tool.state, source.id, extraction, generation=tool.state.generation,
                            retained_ref=item.id, retained_hash=source.retained_hash, document_url=source.document_url)
