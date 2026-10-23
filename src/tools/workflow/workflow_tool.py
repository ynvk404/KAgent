from __future__ import annotations

from src.async_io import run_sync
from src.workflow.evidence.source import bind_source

import json
import hashlib
import re
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urljoin, urlsplit

from src.paths import project_root
from src.permission.permission import Prompter, UserControlledRefusal
from src.permission.runtime.execution import policy_for
from src.tools.execution.file import gate_sensitive_path
from src.redaction.redact import apply as redact, redact_payload
from src.coverage.store import CoverageStore, CoverageStatus
from src.coverage.context import project_candidate_coverage
from src.target.target import Target
from src.target.input_admission import admit_input_fields, identity_text, canonical_endpoint
from src.workflow.discovery.input_view import input_page, input_summary
from src.workflow.discovery.inventory import MAX_SOURCE_REASON_LENGTH
from src.workflow.state import (
    CANDIDATE_STATUSES,
    CLEANUP_STATES,
    INPUT_DISPOSITIONS,
    PHASE_COVERAGE_DIMENSIONS,
    PHASE_COVERAGE_STATUSES,
    VALIDATION_OUTCOMES,
    Candidate,
    AttackSurfaceInput,
    PhaseCoverageStatus,
    WorkflowPhase,
    ValidationResult,
    CleanupState,
    WorkflowState,
    candidate_origin,
    normalize_target_origin,
    validation_result_fingerprint,
)
from src.workflow.evidence.artifacts import EvidenceArtifact, verify_evidence_reads, check_proof_references
from src.workflow.evidence.source import EvidenceSource
from src.workflow.assessment import (start_attempt, references, resolve_sources, candidate_binding,
                                     seal, accepted_result, check_excerpts, DuplicateRequestAssociation)
import uuid
from src.workflow.evidence.errors import EvidenceSubmissionError
from src.skills.registry import (
    Registry as SkillRegistry,
    Skill,
    normalize_candidate_class,
    normalize_metadata_name,
)
from src.skills.artifacts import completion_artifact_path, resolve_canonical_artifact

from src.tools.common.outcome import ToolOutput
from src.tools.common.types import Tool, arg_bool, arg_number, arg_string
from src.workflow.validation.route import (
    GENERIC_VALIDATOR, generic_admission, resolve_validation_route,
)
from src.workflow.validation.probe import ProbeProposal
from src.workflow.validation.context import resolve_validation_context
from src.tools.http.http_tool import HTTPTool


ACTIONS = (
    "select_source",
    "get_source",
    "get_endpoint",
    "set_source_disposition",
    "get_input",
    "record_input",
    "set_input_disposition",
    "link_input_candidate",
    "record_candidate",
    "record_evidence",
    "start_validation",
    "record_attempt_state",
    "record_result",
    "sync_coverage",
    "record_phase_coverage",
    "complete_skill",
    "review_no_candidate",
    "list",
)
DEFAULT_LIST_LIMIT = 8
MAX_LIST_LIMIT = 25
MAX_LIST_COMPLETED_SKILLS = 20
LIST_TEXT_LIMIT = 200
ACTION_REQUIRED = {
    'select_source': ('discovery_source_id',),
    'get_source': ('discovery_source_id',),
    'get_endpoint': ('endpoint_id',),
    'set_source_disposition': ('discovery_source_id', 'source_disposition', 'source_reason'),
    'get_input': ('input_id',),
    'set_input_disposition': ('input_id', 'disposition'),
    'link_input_candidate': ('input_id', 'candidate_id'),
    'record_candidate': ('candidate_class',),
    'record_evidence': ('candidate_id', 'evidence_path'),
    'start_validation': ('candidate_id',),
    'record_attempt_state': ('candidate_id', 'mutation_state', 'effect_basis'),
    'record_result': ('candidate_id', 'skill_name', 'outcome'),
    'sync_coverage': ('candidate_id',),
    'record_phase_coverage': ('phase', 'coverage_dimension', 'coverage_status'),
    'complete_skill': ('skill_name',),
    'review_no_candidate': ('goal_id',),
}
ACTION_INPUTS = {
    'select_source': ('discovery_source_id', 'retained_ref'),
    'get_source': ('discovery_source_id',),
    'get_endpoint': ('endpoint_id',),
    'set_source_disposition': ('discovery_source_id', 'retained_ref', 'source_disposition', 'source_reason',
                               'source_limitations', 'source_bounds', 'acknowledge_bounded_stop'),
    'get_input': ('input_id',),
    # Legacy ownership fields are equality assertions; source is an ignored
    # informational label retained for existing validation-feedback callers.
    'record_input': ('objective_id', 'target_origin', 'target', 'endpoint', 'method', 'parameter',
                     'location', 'input_type', 'content_type', 'sample_payload',
                     'baseline_request_ref', 'auth_context_ref', 'source_ref', 'source', 'source_attribution'),
    'set_input_disposition': ('input_id', 'disposition', 'disposition_reason'),
    'link_input_candidate': ('input_id', 'candidate_id'),
    'record_candidate': ('candidate_class', 'target', 'endpoint', 'method', 'parameter', 'location',
                         'test_case', 'priority', 'signals', 'baseline_request_ref', 'auth_context_ref',
                         'content_type', 'request_template', 'source_ref', 'source_skill', 'status',
                         'input_id', 'current_phase'),
    'record_evidence': ('candidate_id', 'evidence_path', 'observation_ids'),
    'start_validation': ('candidate_id', 'probe', 'related_requests', 'assessment'),
    'record_attempt_state': ('candidate_id', 'attempt_id', 'mutation_state', 'effect_basis',
                             'mutation_performed', 'cleanup_state', 'cleanup_status', 'observation_ids'),
    'record_result': ('candidate_id', 'skill_name', 'outcome', 'attempt_id', 'evidence_refs',
                      'observation_ids', 'techniques', 'repeatable', 'confirmation', 'mutation_performed',
                      'cleanup_status', 'cleanup_state', 'deferred_reason', 'notes', 'assessment', 'force'),
    'sync_coverage': ('candidate_id',),
    'record_phase_coverage': ('phase', 'coverage_dimension', 'coverage_status', 'coverage_reason'),
    'complete_skill': ('skill_name', 'artifact_ref', 'no_inputs_discovered', 'current_phase'),
    'review_no_candidate': ('goal_id', 'artifact_ref'),
    'list': ('candidate_id', 'status', 'candidate_class', 'limit', 'observation_offset',
             'view', 'input_limit', 'input_cursor', 'input_disposition', 'discovery_cursor', 'discovery_source_id'),
}
_STATUS_PRIORITY = {"validating": 0, "queued": 1, "new": 2}



class WorkflowTool(Tool):
    """Small runtime bridge between skill playbooks and structured state."""

    def __init__(
        self,
        state: WorkflowState,
        target: Target | None = None,
        coverage: CoverageStore | None = None,
        skills: SkillRegistry | None = None,
        evidence_root: Path | None = None,
        session_id: str | None = None,
        http_tool: HTTPTool | None = None,
    ) -> None:
        self.state = state
        self.target = target
        self.coverage = coverage
        self.skills = skills
        self.evidence_root = evidence_root or project_root()
        self.session_id = session_id
        self.http_tool = http_tool
        from src.permission.runtime.observations import ObservationStore
        self.observations = ObservationStore()
        self.active_attempt = None
        self.evidence_epoch = "epoch_" + uuid.uuid4().hex
        if http_tool is not None:
            http_tool.evidence_store = self.observations

    def name(self) -> str:
        return "workflow"

    def description(self) -> str:
        return (
            "record_result needs candidate_id, skill_name and outcome. "
            "Runtime owns IDs/scope; record_candidate must omit them and objective_id. "
            "Use returned IDs, real evidence; omit secrets. "
            "Only start_validation enters validating. Usable owned sources -> file_write redacted proof outside artifacts/findings -> record_evidence -> copy evidence.id (ev_...) -> "
            "record_result -> confirm_finding (accepted confirmed only). "
            "start_validation establishes/resumes an attempt before validation probes; it does not send probe.values "
            "or adopt captures made before start. For a new expert attempt, complete prerequisites, read the current "
            "validator with load_skill and prepare known primary/supplementary request roles before start_validation. "
            "force is supported only by record_result for explicit retests, never by start_validation. "
            "Active-attempt conflict: list validating work; record its honest result "
            "or insufficient-evidence/deferred with reason before starting another candidate. "
            "mutation_performed: verified writes; cleanup needs separate authority. Samples aren't replay baselines.\n"
            "For primary-only validation, prefer start_validation with candidate_id alone when the Candidate covers "
            "the primary request and current prerequisites are met. Whole-target new Attempts require completed Recon, Enumeration and Input Analysis and a linked analyzed input; Direct, candidate-validation and owned active Attempt recovery keep their existing admission. Generic still needs an admitted probe/proposal. "
            "related_requests is optional supplementary method/URL associations, not individual payload observations.\n"
            '{"action":"record_candidate","candidate_class":"sqli","endpoint":"/login","method":"POST","parameter":"email"}\n'
            '{"action":"start_validation","candidate_id":"<returned candidate.id>"}'
        )

    def schema(self) -> dict[str, Any]:
        optional_string = {"type": "string"}
        schema = {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": list(ACTIONS)},
                "candidate_id": {
                    "type": "string",
                },
                "goal_id": {
                    "type": "string",
                },
                "probe": ProbeProposal.schema(),
                "attempt_id": optional_string,
                "related_requests": {"type": "array", "maxItems": 16, "items": {
                    "type": "object", "properties": {
                        "role": {"type": "string", "enum": ['baseline', 'control', 'trigger', 'readback', 'cleanup', 'auxiliary']},
                        "method": {"type": "string", "enum": ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'DELETE']},
                        "url": {"type": "string", "minLength": 1, "maxLength": 2000},
                        "required": {"type": "boolean"}},
                    "required": ['role', 'method', 'url'], "additionalProperties": False}},
                "assessment": {"type": "object"},
                "input_id": optional_string,
                "discovery_source_id": optional_string,
                "source_attribution": {
                    "type": "object",
                    "description": "Optional manual declaration of a field read in an admitted HTTP/capture document. Metadata only; never request context, extraction proof, read permission or test evidence.",
                    "properties": {
                        "discovery_source_id": {"type": "string"},
                        "retained_ref": {"type": "string"},
                        "retained_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                        "document_location": {"type": "string", "minLength": 1, "maxLength": 233,
                            "description": "Exact non-secret field location: JSON pointer, HTML selector or visible JS binding. No traffic, values or credentials."},
                    },
                    "required": ["discovery_source_id", "retained_ref", "retained_hash", "document_location"],
                    "additionalProperties": False,
                },
                "endpoint_id": optional_string,
                "retained_ref": optional_string,
                "discovery_cursor": optional_string,
                "source_disposition": {"type": "string", "enum": ['pending', 'processed', 'partial', 'blocked', 'not_applicable']},
                "source_reason": {"type": "string", "maxLength": MAX_SOURCE_REASON_LENGTH},
                "source_limitations": {"type": "array", "maxItems": 16, "items": {"type": "string", "maxLength": 240}},
                "source_bounds": {"type": "object", "additionalProperties": {"type": "integer", "minimum": 1}},
                "acknowledge_bounded_stop": {"type": "boolean"},
                "view": {"type": "string", "enum": ["all", "inputs", "sources", "endpoints", "provenance"],
                         "description": "list view; inputs returns only a bounded input page (16 KiB maximum)."},
                "input_limit": {"type": "integer", "minimum": 1, "maximum": 25,
                                "description": "Inputs per page, default 20; independent of candidate limit."},
                "input_cursor": optional_string,
                "input_disposition": {"type": "string", "enum": sorted(INPUT_DISPOSITIONS)},
                "input_type": optional_string,
                "content_type": {
                    "type": "string",
                    "maxLength": 200,
                    "description": "Request body media type, never the response Content-Type. Omit for query-only requests.",
                },
                "sample_payload": {
                    "type": "string",
                    "maxLength": 4000,
                },
                "disposition": {"type": "string", "enum": sorted(INPUT_DISPOSITIONS)},
                "disposition_reason": optional_string,
                "candidate_class": optional_string,
                "target": {
                    "type": "string",
                },
                "endpoint": optional_string,
                "method": optional_string,
                "parameter": optional_string,
                "location": optional_string,
                "test_case": {
                    "type": "string",
                },
                "priority": {"type": "string", "enum": ["high", "medium", "low"]},
                "evidence_path": {
                    "type": "string",
                },
                "observation_ids": {"type": "array", "items": {"type": "string"}},
                "signals": {"type": "array", "items": {"type": "string"}},
                "baseline_request_ref": optional_string,
                "auth_context_ref": optional_string,
                "source_ref": optional_string,
                "request_template": {
                    "type": "string",
                    "maxLength": 4000,
                },
                "source_skill": optional_string,
                "status": {
                    "type": "string",
                    "enum": sorted(CANDIDATE_STATUSES),
                },
                "skill_name": {
                    "type": "string",
                },
                "outcome": {
                    "type": "string",
                    "enum": sorted(VALIDATION_OUTCOMES),
                },
                "evidence_refs": {"type": "array", "items": {"type": "string"}},
                "techniques": {"type": "array", "items": {"type": "string"}},
                "repeatable": {"type": "boolean"},
                "confirmation": {
                    "type": "object",
                },
                "mutation_performed": {"type": ["boolean", "null"]},
                "mutation_state": {"type": "string", "enum": ["unknown", "possible", "reported-write",
                                      "verified-write", "no-mutation-established"]},
                "effect_basis": optional_string,
                "observation_offset": {"type": "integer", "minimum": 0},
                "cleanup_status": optional_string,
                "cleanup_state": {
                    "type": "string",
                    "enum": sorted(CLEANUP_STATES),
                },
                "deferred_reason": optional_string,
                "notes": optional_string,
                "force": {
                    "type": "boolean",
                },
                "no_inputs_discovered": {
                    "type": "boolean",
                },
                "current_phase": optional_string,
                "phase": {
                    "type": "string",
                    "enum": sorted(PHASE_COVERAGE_DIMENSIONS),
                },
                "coverage_dimension": {
                    "type": "string",
                },
                "coverage_status": {
                    "type": "string",
                    "enum": sorted(PHASE_COVERAGE_STATUSES),
                },
                "coverage_reason": {
                    "type": "string",
                },
                "artifact_ref": {
                    "type": "string",
                },
                "limit": {
                    "type": "number",
                },
            },
            "required": ["action"],
        }
        properties = {key: dict(field) for key, field in schema['properties'].items()}
        schema['properties'] = properties
        # Flat descriptions are portable on the current DeepSeek Chat
        # Completions path. No unverified union/conditional or strict mode.
        properties['action']['description'] = (
            'Action fields (* required); omit others.\n' + '\n'.join(
                action + '(' + ','.join(
                    key + ('*' if key in ACTION_REQUIRED.get(action, ()) else '')
                    for key in fields if key in properties) + ')'
                for action, fields in ACTION_INPUTS.items()))
        descriptions = {
            'phase': 'record_phase_coverage only: recon or enumeration. Input analysis closes through input dispositions and complete_skill.',
            'coverage_dimension': '; '.join(
                phase + ': ' + ', '.join(dimensions)
                for phase, dimensions in PHASE_COVERAGE_DIMENSIONS.items()),
            'test_case': 'Stable distinct hypothesis/sink identity, not a payload variant. For evidenced API/DOM/stored XSS hypotheses sharing an input, use distinct test_case values before start_validation.',
            'candidate_id': (
                'Required for record_evidence, start_validation, and record_result. '
                'For primary-only start_validation, prefer candidate_id alone when the Candidate covers the primary request '
                'and current prerequisites are met. Runtime resolves Candidate context; do not repeat endpoint/method or '
                'assign runtime identity, infer missing body/auth/credentials/templates, or bypass Generic probe/proposal admission. '
                'Example: {"action":"start_validation","candidate_id":"<returned candidate.id>"}'),
            'attempt_id': 'Runtime ID from start_validation; cannot assign an attempt. record_result only; omit from record_evidence.',
            'assessment': 'hypothesis,criteria,limitations,completed_attempt,observed_impact,severity.',
            'evidence_path': 'Existing project proof file, written first with file_write outside artifacts/findings. Registration reads this file; it does not create it. Use returned evidence.id (ev_...) in record_result.evidence_refs, never the path.',
            'evidence_refs': 'Canonical ev_... IDs returned as evidence.id by record_evidence for this Candidate. Never a file path or obs_ ID.',
            'request_template': 'Redacted body skeleton; mark {INJECTION_POINT}.',
            'status': 'Registration/list status; not used by record_result. Only start_validation owns validating; never register validating.',
            'observation_ids': 'Exact HTTP/authoritative evidence IDs matching candidate, attempt and request. Terminal sources: complete, untruncated, completed.',
            'outcome': 'Required for record_result.',
            'related_requests': (
                'Optional supplementary request associations for start_validation; a single legacy explicit primary association remains valid. '
                'Each normalized method and resolved/redacted URL has one association across all roles and required values. '
                'Different bodies, payloads or identities on the same key are separate HTTP observations, not associations. '
                'This is not a list of baseline/TRUE/FALSE/trigger steps or individual HTTP invocations. '
                'required defaults to true, except cleanup defaults to false; cleanup still needs separate authorization. '
                'Omit a redundant primary declaration only when the Candidate covers it and no supplementary obligation is lost. '
                'Preserve required supplementary evidence; resolve conflicts by restating intent, never invent URLs or auto-merge. '
                'For a Candidate POST /comments with supplementary GET /comments/123 readback: '
                '{"action":"start_validation","candidate_id":"<returned candidate.id>",'
                '"related_requests":[{"role":"readback","method":"GET","url":"/comments/123"}]}'),
            'coverage_reason': 'Non-performed: reason; observed: source/limitations.',
            'force': 'record_result only, explicit retest only; never pass to start_validation.',
        }
        for key, description in descriptions.items():
            properties[key]['description'] = description
        return schema

    def requires_permission(self) -> bool:
        return False

    def context_reduction_policy(self) -> str:
        """Keep same-turn workflow mutations intact for the next LLM call."""
        return "preserve"

    async def run(self, args, signal, prompter):
        generation = self.state.generation
        async with self.state.mutation_lock:
            if self.state.generation != generation:
                return self._typed_result("error: workflow generation changed while waiting")
            before = self.state.to_dict()
            revision = self.state.committed_revision
            try:
                return await self._run(args, signal, prompter)
            finally:
                # Also cover attempt/evidence/coverage metadata committed by
                # actions that exit through cancellation rather than a receipt.
                if (self.state.generation == generation and self.state.committed_revision == revision
                        and self.state.to_dict() != before):
                    self.state.mark_committed()

    async def _run(
        self,
        args: dict[str, Any],
        signal: Any,
        prompter: Prompter,
    ) -> str:
        action = arg_string(args, 'action')
        if action not in ACTIONS:
            return ToolOutput('error: action must be one of: ' + ', '.join(ACTIONS),
                              status='error', error_kind='invalid_args')
        if action == 'record_candidate' and 'objective_id' in args:
            return ToolOutput('error: objective_id is assigned by the runtime; omit it from record_candidate',
                              status='error', error_kind='invalid_args')
        unsupported = sorted(set(args) - {'action', *ACTION_INPUTS[action]})
        if unsupported:
            return ToolOutput('error: ' + action + ' does not accept ' + ', '.join(unsupported)
                              + '; omit these arguments (runtime identities cannot be assigned)'
                              + ('; force is record_result-only for explicit retests, not a start/recovery override. '
                                 'Inspect list for current attempt, prerequisites and recovery; Continue cannot reset its budget.'
                                 if action == 'start_validation' and 'force' in unsupported else ''),
                              status='error', error_kind='invalid_args')
        missing = [key for key in ACTION_REQUIRED.get(action, ()) if not arg_string(args, key)]
        if missing:
            if action == 'record_evidence' and 'evidence_path' in missing:
                return self._workflow_error('record_evidence requires ' + ', '.join(missing),
                    code='MISSING_EVIDENCE_PATH', category='argument_error',
                    next_action='Write minimal redacted proof with file_write outside artifacts/findings, then pass that existing project-relative file as evidence_path. Registration returns evidence.id (ev_...) for record_result.evidence_refs.')
            if action == 'get_input':
                return ToolOutput('error: get_input requires exact input_id from record_input/list',
                                  status='error', error_kind='invalid_args')
            return ToolOutput('error: ' + action + ' requires ' + ', '.join(missing),
                              status='error', error_kind='invalid_args')
        if 'related_requests' in args:
            related = args['related_requests']
            if (not isinstance(related, list) or len(related) > 16 or any(
                    not isinstance(row, dict) or not {'role', 'method', 'url'} <= set(row)
                    or set(row) - {'role', 'method', 'url', 'required'}
                    or any(not isinstance(row[key], str) or not row[key] or len(row[key]) > 2000
                           for key in ('role', 'method', 'url'))
                    or row['role'] not in {'baseline', 'control', 'trigger', 'readback', 'cleanup', 'auxiliary'}
                    or row['method'].upper() not in {'GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'DELETE'}
                    or not isinstance(row.get('required', True), bool) for row in related)):
                return ToolOutput('error: related_requests needs at most 16 objects with bounded role/method/url and optional boolean required',
                                  status='error', error_kind='invalid_args')
        policy = policy_for(prompter)
        if policy is not None:
            policy.bind_validation_context(self.state, self.skills, self.target)
        action = arg_string(args, "action")
        if (policy is not None and policy.session_id is not None and self.session_id != policy.session_id
                and action in {"start_validation", "record_attempt_state", "record_evidence", "record_result"}):
            return self._typed_result("error: workflow/runtime session identity mismatch")
        if action in {'select_source', 'get_source', 'get_endpoint', 'set_source_disposition'}:
            result = self._discovery_action(action, args)
        elif action == "get_input":
            result = self._get_input(args)
        elif action == "record_input":
            result = self._record_input(args, prompter)
        elif action == "set_input_disposition":
            result = self._set_input_disposition(args)
        elif action == "link_input_candidate":
            result = self._link_input_candidate(args)
        elif action == "record_candidate":
            result = self._record_candidate(args, policy)
        elif action == "record_evidence":
            result = await self._record_evidence(args, prompter, signal)
        elif action == "start_validation":
            result = await self._start_validation(args, prompter, signal)
        elif action == "record_attempt_state":
            result = self._record_attempt_state(args, policy)
        elif action == "record_result":
            result = await self._record_result(args, prompter, signal)
        elif action == "sync_coverage":
            policy = policy_for(prompter)
            latest = self.state.latest_result(arg_string(args, "candidate_id"))
            if latest is not None and latest.skill_name == GENERIC_VALIDATOR:
                try:
                    self._require_generic(latest.candidate_id, policy)
                except ValueError as err:
                    return self._typed_result(f"error: {err}")
            latest = self.state.latest_result(arg_string(args, "candidate_id"))
            candidate = self.state.candidates.get(arg_string(args, "candidate_id"))
            if candidate is None or not accepted_result(self.state, candidate, latest, policy):
                return self._typed_result("error: inadmissible result cannot sync tested coverage")
            assert latest is not None
            before = (self.state.generation, deepcopy(self.state.to_dict()))
            stamp = policy.stamp() if policy else None
            if not await verify_evidence_reads([self.state.evidence[ref] for ref in latest.evidence_refs],
                    self.evidence_root, prompter, signal):
                return self._typed_result("error: coverage evidence changed/unavailable")
            if (self.state.generation, self.state.to_dict()) != before or (policy and policy.stamp() != stamp):
                return self._typed_result("error: coverage submission changed during evidence read")
            result = await self._sync_coverage_action(args)
        elif action == "record_phase_coverage":
            if policy_for(prompter) is not None:
                objective = self.state.objective
                phase = arg_string(args, "phase")
                dimension = arg_string(args, "coverage_dimension")
                requested = arg_string(args, "coverage_status")
                if objective is None or objective.mode != "whole_target":
                    return self._typed_result("error: phase coverage requires an active whole-target objective")
                if objective.target_origin != normalize_target_origin(self._active_target()):
                    return self._typed_result("error: phase coverage must match the active objective and target")
                if phase not in PHASE_COVERAGE_DIMENSIONS:
                    return self._coverage_argument_error(phase, dimension)
                if dimension not in PHASE_COVERAGE_DIMENSIONS[phase]:
                    return self._coverage_argument_error(phase, dimension)
                if requested not in PHASE_COVERAGE_STATUSES:
                    return self._typed_result("error: coverage_status is invalid")
                existing = self.state.phase_coverage_record(
                    cast(WorkflowPhase, phase), dimension,
                )
                if existing is not None and existing.status == "performed":
                    if requested in {"performed", "observed"}:
                        completed = phase in self.state.completed_phases(objective)
                        return ToolOutput(json.dumps({
                            "ok": True, "phase": phase, "dimension": dimension,
                            "requested_status": requested, "status": "performed",
                            "changed": False, "already_recorded": True,
                            "phase_completed": completed,
                            "message": (
                                "Already recorded as performed; phase is already completed."
                                if completed else "Already recorded as performed."
                            ),
                        }), status="success")
                    return self._typed_result("error: runtime-attested performed coverage cannot be replaced by a model claim")
                if requested == "performed":
                    return self._typed_result("error: performed phase coverage requires an execution adapter observation")
            result = self._record_phase_coverage(args)
        elif action == "complete_skill":
            result = self._complete_skill(args, policy)
        elif action == "review_no_candidate":
            result = await self._review_no_candidate(args, prompter, signal)
        elif action == "list":
            result = self._list(args, policy)
        else:
            result = f"error: action must be one of: {', '.join(ACTIONS)}"
        return self._typed_result(result)

    @staticmethod
    def _typed_result(result: str) -> str:
        """Preserve string compatibility while exposing semantic failures."""
        if isinstance(result, ToolOutput):
            return result
        if result.startswith("error:"):
            return ToolOutput(result, status="error", error_kind="workflow_state")
        try:
            payload = json.loads(result)
        except (TypeError, ValueError):
            return result
        if isinstance(payload, dict) and payload.get("ok") is False:
            return ToolOutput(result, status="error", error_kind="tool_exception")
        return result

    @staticmethod
    def _workflow_error(message: str, *, code: str, category: str,
                        next_action: str, **context: Any) -> ToolOutput:
        """Targeted diagnostics; no retry accounting or additional authority."""
        error = {"code": code, "category": category, "message": redact(message),
                 "next_action": next_action, **context}
        return ToolOutput("error: " + redact(message) + "\n" + json.dumps({"ok": False, "error": error}),
                          status="error", error_kind="invalid_args" if category == "argument_error" else "workflow_state")

    def _coverage_argument_error(self, phase: str, dimension: str) -> ToolOutput:
        if phase not in PHASE_COVERAGE_DIMENSIONS:
            return self._workflow_error("phase must be recon or enumeration",
                code="INVALID_COVERAGE_PHASE", category="argument_error",
                next_action="Use record_phase_coverage for recon/enumeration only. For input_analysis, inspect list, close input dispositions, then complete_skill(web-input-analysis).",
                allowed_phases=list(PHASE_COVERAGE_DIMENSIONS))
        return self._workflow_error(f"unknown {phase} coverage dimension: {dimension}",
            code="INVALID_COVERAGE_DIMENSION", category="argument_error",
            next_action="Inspect existing phase coverage with list; use an exact allowed dimension and an honest status/reason. Do not repeat HTTP just to mark coverage.",
            phase=phase, allowed_dimensions=list(PHASE_COVERAGE_DIMENSIONS[phase]))

    def candidate_proposal(self, args: dict[str, Any]) -> Candidate:
        """Read-only canonical proposal; ownership comes from the active runtime.

        Used by dispatch and presentation recovery, never grants authority.
        """
        candidate_class = arg_string(args, "candidate_class")
        if not candidate_class:
            raise ValueError("record_candidate requires candidate_class")
        candidate_target = arg_string(args, "target") or self._active_target()
        if not candidate_target:
            raise ValueError("record_candidate requires target or an active Agent target")
        objective = self.state.objective
        objective_id: str | None = None
        assigned = None
        if objective is not None and objective.mode == "candidate_validation":
            assigned = self.state.candidates.get(objective.candidate_id or "")
            if assigned is None:
                raise ValueError("assigned validation candidate unavailable")
            if (candidate_origin(candidate_target) != objective.target_origin
                    or candidate_origin(assigned.target) != objective.target_origin):
                raise ValueError("candidate target must match the assigned validation origin")
            # Re-record in the controller-owned identity context. Omitted
            # request fields retain the assigned context; explicit changes
            # still face fingerprint and full binding checks below.
            objective_id = assigned.objective_id
            args = {**{key: getattr(assigned, key) for key in (
                "endpoint", "method", "parameter", "location", "test_case",
                "baseline_request_ref", "auth_context_ref", "content_type",
                "request_template", "source_ref", "source_skill")},
                **{key: value for key, value in args.items() if value is not None}}
        requested_input_id = arg_string(args, "input_id")
        input_item = None
        if requested_input_id and (objective is None or objective.mode != "whole_target"):
            raise ValueError("input_id requires an active whole-target objective")
        if objective is not None and objective.mode == "whole_target":
            if candidate_origin(candidate_target) != objective.target_origin:
                raise ValueError("candidate target must match the active whole-target origin")
            objective_id = objective.id
            if requested_input_id:
                input_item = self.state.attack_surface_inputs.get(requested_input_id)
                if (
                    input_item is None
                    or input_item.objective_id != objective.id
                    or input_item.target_origin != objective.target_origin
                ):
                    raise ValueError("input does not belong to the active whole-target objective")
        elif (
            objective is not None
            and objective.mode == "direct"
            and objective.target_origin is not None
            and candidate_origin(candidate_target) != objective.target_origin
        ):
            raise ValueError("candidate target must match the active direct objective origin")
        if objective is not None and objective.mode == "direct":
            objective_id = objective.id
        endpoint, method, normalization_error = self._normalize_method_endpoint(
            args.get("endpoint"), args.get("method")
        )
        if normalization_error:
            raise ValueError(normalization_error)
        candidate = Candidate(
            candidate_class=candidate_class,
            target=candidate_target,
            endpoint=(
                endpoint if endpoint is not None
                else input_item.endpoint if input_item is not None else None
            ),
            method=(
                method if method is not None
                else input_item.method if input_item is not None else None
            ),
            parameter=(
                args.get("parameter") if args.get("parameter") is not None
                else input_item.parameter if input_item is not None else None
            ),
            location=(
                args.get("location") if args.get("location") is not None
                else input_item.location if input_item is not None else None
            ),
            test_case=args.get("test_case"),
            priority=args.get("priority"),
            signals=args.get("signals", []),
            baseline_request_ref=(args.get("baseline_request_ref")
                                  if args.get("baseline_request_ref") is not None
                                  else input_item.baseline_request_ref if input_item is not None else None),
            auth_context_ref=(args.get("auth_context_ref")
                              if args.get("auth_context_ref") is not None
                              else input_item.auth_context_ref if input_item is not None else None),
            content_type=(
                args.get("content_type")
                if args.get("content_type") is not None
                else input_item.content_type if input_item is not None else None
            ),
            # A sanitized sample is descriptive context, not an explicit
            # mutation template. Only the caller supplies that representation.
            request_template=args.get("request_template"),
            source_ref=(args.get("source_ref") if args.get("source_ref") is not None
                        else input_item.source_ref if input_item is not None else None),
            source_skill=args.get("source_skill"),
            objective_id=objective_id,
            identity_media_type=assigned.identity_media_type if assigned else None,
            status=args.get("status", "queued"),
        )
        if assigned is not None:
            from dataclasses import replace
            try:
                # The constructor validates legacy fingerprints too; no ID is
                # forced onto a different request or baseline/auth identity.
                candidate = replace(candidate, id=assigned.id)
            except ValueError:
                pass  # Keep the different fingerprint for the assigned gate.
        return candidate

    def _record_candidate(self, args: dict[str, Any], policy=None) -> str:
        try:
            candidate = self.candidate_proposal(args)
            existing = self.state.candidates.get(candidate.id)
            if existing is None or candidate_binding(existing) != candidate_binding(candidate):
                self._validate_input_http_source({**candidate.to_dict(),
                    "target_origin": candidate_origin(candidate.target)}, policy)
                self._validate_replay_baseline(candidate, policy)
        except (TypeError, ValueError) as err:
            return f"error: {err}"
        candidate_class = candidate.candidate_class
        objective = self.state.objective
        assigned = self.state.candidates.get(objective.candidate_id or "") if (
            objective is not None and objective.mode == "candidate_validation") else None
        if (objective is not None and objective.mode == "candidate_validation"
                and (assigned is None or candidate.id != assigned.id
                     or candidate_binding(candidate) != candidate_binding(assigned))):
            return self._workflow_error("candidate does not match the assigned validation input",
                code="OBJECTIVE_CANDIDATE_MISMATCH", category="immutable_state_conflict",
                next_action="Continue the assigned candidate; independent inputs require operator intent in a separate objective.")
        requested_input_id = arg_string(args, "input_id")
        validators = self.skills.validators_for_class(candidate_class) if self.skills else []
        route = resolve_validation_route(self.skills, candidate_class)
        supported = len(validators) == 1 if self.skills else None
        validator_resolution = "unique" if route.kind == "expert" else route.kind
        if supported is False:
            candidate.status = "deferred"
        try:
            reason = route.reason
            if route.kind == "generic":
                reason = generic_admission(candidate, self.state, self.skills, self.target, policy)
                if reason is None:
                    assert policy is not None
                    reason = (policy.generic_validation.admission_reason(
                        policy.generic_validation.http_tool, candidate.id)
                        if candidate.id in self.state.candidates else
                        "generic context-needed: concrete proposal and verified endpoint/action context required")
                supported = reason is None
                candidate.status = "queued" if supported else "deferred"
            elif route.kind != "expert" and self.skills is not None:
                candidate.status = "deferred"
            stored, created = self.state.add_candidate(candidate, input_id=requested_input_id or None)
            input_id = arg_string(args, "input_id")
            if input_id:
                self.state.link_input_candidate(input_id, stored.id)
            if objective is not None and objective.mode in {"direct", "whole_target"}:
                for goal in objective.requested_goals:
                    if goal.candidate_class == stored.candidate_class:
                        self.state.link_requested_goal_candidate(goal.id, stored.id)
            if not created and self.skills and self.state.latest_result(stored.id) is None:
                if supported is False and stored.status in {"new", "queued"}:
                    stored = self.state.set_candidate_status(stored.id, "deferred")
                elif supported and route.kind == "expert" and stored.status == "deferred":
                    stored = self.state.set_candidate_status(stored.id, "queued")
        except (TypeError, ValueError) as err:
            return f"error: {err}"
        phase = arg_string(args, "current_phase")
        if phase:
            self.state.current_phase = phase[:80]
        return json.dumps(
            {
                "ok": True,
                "created": created,
                "candidate": stored.to_dict(),
                "supported": supported,
                "validator_resolution": validator_resolution,
                "validator_reason": reason,
                "recommended_skills": [skill.name for skill in validators],
                "proof_source_path": (
                    str(policy.generic_validation.proof_path(stored).relative_to(policy.root))
                    if validator_resolution == "generic" and policy is not None else None
                ),
            },
            indent=2,
        )

    def _discovery_action(self, action: str, args: dict[str, Any]) -> str:
        try:
            objective = self.state.objective
            if (objective is None or objective.mode != 'whole_target'
                    or candidate_origin(self._active_target()) != objective.target_origin):
                raise ValueError('discovery metadata requires the active whole-target origin')
            if action == 'get_endpoint':
                endpoint = self.state.endpoints.get(args['endpoint_id'])
                if (endpoint is None or endpoint.objective_id != objective.id
                        or endpoint.target_origin != objective.target_origin):
                    raise ValueError('unknown/current-objective endpoint ID; never guess a replacement')
                return json.dumps({'ok': True, 'endpoint': endpoint.to_dict()})
            source = self.state.discovery_source(args['discovery_source_id'], generation=self.state.generation,
                                                  retained_ref=args.get('retained_ref'))
            if action == 'select_source':
                source = self.state.update_discovery_source(source.id, generation=self.state.generation, selected=True)
            elif action == 'set_source_disposition':
                bounds = args.get('source_bounds', {})
                if not isinstance(bounds, dict):
                    raise ValueError('source_bounds must be an object of explicit processing limits')
                limits = args.get('source_limitations', source.limitations)
                if not isinstance(limits, (list, tuple)):
                    raise ValueError('source_limitations must be a bounded list')
                source = self.state.update_discovery_source(source.id, generation=self.state.generation,
                    disposition=args['source_disposition'], stop_reason=args['source_reason'],
                    limitations=tuple(limits),
                    processing_bounds=tuple(bounds.items()) if bounds else source.processing_bounds,
                    bounded_stop=args.get('acknowledge_bounded_stop', False))
            return json.dumps({'ok': True, 'discovery_source': source.to_dict(), 'unresolved': source.unresolved})
        except (ValueError, TypeError, KeyError) as err:
            return f'error: {err}'

    def _get_input(self, args: dict[str, Any]) -> str:
        input_id = arg_string(args, "input_id")
        if not input_id:
            return "error: get_input requires exact input_id"
        item = self.state.attack_surface_inputs.get(input_id)
        if item is None:
            return f"error: unknown input: {input_id}"
        objective = self.state.objective
        if objective is None or item.objective_id != objective.id:
            return "error: input does not belong to the active objective"
        active_origin = candidate_origin(self._active_target())
        if (item.target_origin != objective.target_origin
                or active_origin is None or item.target_origin != active_origin):
            return "error: input does not belong to the active target origin"
        if item.endpoint and candidate_origin(urljoin(item.target_origin + "/", item.endpoint)) != active_origin:
            return "error: input endpoint does not belong to the active target origin"
        # Constructors enforce canonical redaction and the 4000-character
        # sample bound. This opt-in read never hydrates runtime captures.
        return json.dumps({"ok": True, "input": item.to_dict()}, indent=2)

    def _record_input(self, args: dict[str, Any], prompter=None) -> str:
        objective = self.state.objective
        if objective is None or objective.mode != "whole_target":
            return "error: record_input requires an active whole-target objective"
        supplied_objective_id = args.get("objective_id")
        if supplied_objective_id and supplied_objective_id != objective.id:
            return (
                "error: objective_id is assigned by the runtime and does not "
                "match the active whole-target objective"
            )
        if self.target is None or self.target.empty():
            return "error: record_input requires an active target"
        target_origin = normalize_target_origin(self.target.base_url())
        if target_origin != objective.target_origin:
            return "error: active target does not match the whole-target objective"
        supplied_origin = args.get("target_origin") or args.get("target")
        if supplied_origin:
            try:
                supplied_target_origin = normalize_target_origin(str(supplied_origin))
            except ValueError as err:
                return f"error: {err}"
            if supplied_target_origin != target_origin:
                return "error: supplied target does not match the active whole-target origin"
        try:
            # The shorthand parser must not strip unsafe raw identity text
            # before the shared admission boundary can inspect it.
            identity_text(args.get("endpoint"), "endpoint", required=True)
            identity_text(args.get("method"), "method")
        except ValueError as err:
            return f"error: {err}"
        endpoint, method, normalization_error = self._normalize_method_endpoint(
            args.get("endpoint"), args.get("method")
        )
        if normalization_error:
            return f"error: {normalization_error}"
        try:
            admitted = admit_input_fields({
                **args, "objective_id": objective.id, "target_origin": target_origin,
                "method": method, "endpoint": endpoint,
            }, base_url=self.target.base_url())
            self._validate_input_http_source(admitted, policy_for(prompter))
            item = AttackSurfaceInput(
                objective_id=objective.id,
                target_origin=target_origin or "",
                method=admitted["method"],
                endpoint=admitted["endpoint"],
                parameter=admitted["parameter"],
                location=args.get("location"),
                input_type=args.get("input_type"),
                content_type=args.get("content_type"),
                sample_payload=args.get("sample_payload"),
                baseline_request_ref=args.get("baseline_request_ref"),
                auth_context_ref=args.get("auth_context_ref"),
                source_ref=args.get("source_ref"),
            )
            existing = self.state.attack_surface_inputs.get(item.id)
            if existing is None and item.baseline_request_ref:
                # Reuse the state's canonical identity for legacy IDs. This
                # only recognizes unchanged historical context, never rekeys
                # a row or resolves its stale reference to another capture.
                matches = []
                for row in self.state.objective_inputs():
                    if row.baseline_request_ref != item.baseline_request_ref:
                        continue
                    try:
                        if self.state._canonical_input(row).id == item.id:
                            matches.append(row)
                    except ValueError:
                        continue
                existing = matches[0] if len(matches) == 1 else None
            if existing is None or any(getattr(existing, name) != getattr(item, name) for name in (
                    'method', 'endpoint', 'parameter', 'location', 'content_type',
                    'baseline_request_ref', 'auth_context_ref', 'source_ref')):
                self._validate_replay_baseline(item, policy_for(prompter))
            attribution = None
            if 'source_attribution' in args:
                from src.workflow.discovery.attribution import record_attributed_input
                stored, created, attribution = record_attributed_input(
                    self.state, item, args['source_attribution'], generation=self.state.generation)
            else:
                stored, created = self.state.add_attack_surface_input(item)
        except (TypeError, ValueError) as err:
            return f"error: {err}"
        return json.dumps({"ok": True, "created": created, "input": stored.to_dict(),
                           **({'source_attribution': attribution.to_dict(),
                               'attribution_kind': 'manual_declaration'} if attribution else {})}, indent=2)

    def _validate_replay_baseline(self, proposal, policy) -> None:
        """New replay references resolve through the existing capture namespace.

        Hydration deliberately does not call this boundary: stale history stays
        intact and still cannot obtain replay rights from its persisted text.
        """
        if not proposal.baseline_request_ref:
            return
        from types import SimpleNamespace
        from src.browser.scoped_store import ScopedCaptureStore
        from src.tools.http.request_builder import validate_capture_binding
        tool = self.http_tool
        if (tool is None or tool.workflow is not self.state or tool.target is not self.target
                or tool.capture_store is None or policy is not None and tool.engagement is not policy.engagement):
            raise ValueError("baseline_request_ref replay capture unavailable; observation/source provenance is not a replay baseline")
        try:
            store = ScopedCaptureStore(tool.capture_store, policy) if policy else tool.capture_store
            row = store.resolve_baseline(proposal.baseline_request_ref)
            if row is None:
                raise ValueError("unavailable")
            tool._require_scope(row.url or '')
            if getattr(row, 'auth_context_ref', None) not in (None, proposal.auth_context_ref):
                raise ValueError("identity mismatch")
            context = proposal if isinstance(proposal, Candidate) else SimpleNamespace(
                method=proposal.method, target=proposal.target_origin, endpoint=proposal.endpoint,
                content_type=proposal.content_type)
            # A current metadata reference can be handed off even when its raw
            # bytes are incomplete. Existing validation-context/replay gates
            # still require complete supported bytes before any replay.
            validate_capture_binding(row, context)
        except (ValueError, PermissionError, UserControlledRefusal):
            # No capture URL, credentials or exception prose crosses this gate.
            raise ValueError("baseline_request_ref replay capture unavailable or request/identity binding mismatch; use source_ref for observation provenance") from None

    def _validate_input_http_source(self, admitted: dict[str, Any], policy) -> None:
        """Check admitted discovery metadata, never read/adopt terminal evidence.

        Unowned Recon/capture sources are legitimate request context. They need
        live provenance and scope, not a validation attempt or body-read right.
        Other kinds of request-context reference retain their existing contract.
        """
        ref = admitted.get("source_ref")
        if not ref:
            return
        if ref.startswith('baseline:'):
            raise ValueError("source_ref requires source provenance, not a baseline_request_ref replay capture")
        store = policy.observations if policy else self.observations
        item = store._items.get(ref)
        sources = [source for source in self.state.discovery_sources.values()
                   if source.retained_ref == ref and source.kind in {"http", "capture"}]
        if item is None:
            # Resolve producer metadata first; the reserved namespace only
            # detects unavailable observations, never establishes their kind.
            if sources or ref.startswith("obs_"):
                raise ValueError("HTTP source_ref unavailable; cannot verify request identity")
            return
        if item.source_kind not in {"native-http", "imported-capture"}:
            if item.source_kind == "tool-output" and not sources:
                return
            raise ValueError("source_ref lacks trustworthy HTTP metadata; cannot verify request identity")
        capability = "http" if item.source_kind == "native-http" else "browser_capture_get"
        producer = "http" if capability == "http" else "scoped-capture-bridge"
        if (policy is None or not policy.nested_allowed()
                or {"*", capability, "read_http_observation"} & policy.revoked):
            raise ValueError("HTTP source_ref access unavailable; cannot verify request identity")
        objective = self.state.objective
        from src.workflow.assessment import digest, source_row
        source = next((source for source in sources
                       if objective and source.objective_id == objective.id and source.target_origin == objective.target_origin), None)
        if (item.producer != producer or not item.method or not item.url
                or item.epoch != policy.engagement.http_permissions.epoch
                or (item.source_details or {}).get("analysis_session") != (
                    policy.session_id or policy.engagement.http_permissions.session_id)
                or item.objective_id not in {None, objective.id if objective else None}
                or (sources and source is None)
                or (source is not None and (item.retained_hash != source.retained_hash
                    or source.kind != ("http" if capability == "http" else "capture")))
                or digest(source_row(item)) != item.retained_hash):
            raise ValueError("HTTP source_ref lacks current trustworthy discovery metadata/provenance; cannot verify request identity")
        if source is not None:
            self.state.discovery_source(source.id, generation=self.state.generation, retained_ref=ref)
        try:
            # Only method/origin/path are request-context identity here. Query
            # values may already be redacted and must neither be compared nor
            # prevent verification of the retained non-secret geometry.
            parts = urlsplit(item.url)
            if parts.fragment:
                raise ValueError("HTTP source URL contains a fragment")
            source_url = canonical_endpoint(parts._replace(query="").geturl(), admitted["target_origin"])
        except ValueError:
            raise ValueError("HTTP source_ref origin or URL cannot be verified against input") from None
        policy.require_network(source_url)
        if (source is not None and (not source.document_url
                or urlsplit(source.document_url)._replace(query="").geturl() != source_url)):
            raise ValueError("HTTP source_ref discovery URL metadata mismatch; cannot verify request identity")
        if item.method != admitted["method"]:
            raise ValueError("HTTP source_ref method does not match input")
        if urlsplit(source_url).path != urlsplit(admitted["endpoint"]).path:
            raise ValueError("HTTP source_ref path does not match input")

    @staticmethod
    def _normalize_method_endpoint(
        endpoint: Any,
        method: Any,
    ) -> tuple[Any, Any, str | None]:
        """Accept a common ``GET /path`` shorthand without storing it twice."""
        if not isinstance(endpoint, str):
            return endpoint, method, None
        match = re.match(
            r"^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S.*)$",
            endpoint,
            re.IGNORECASE,
        )
        if match is None:
            return endpoint, method, None
        prefixed_method = match.group(1).upper()
        explicit_method = str(method).strip().upper() if method else ""
        if explicit_method and explicit_method != prefixed_method:
            return endpoint, method, "endpoint method prefix conflicts with method"
        return match.group(2).strip(), prefixed_method, None

    def _set_input_disposition(self, args: dict[str, Any]) -> str:
        try:
            item = self.state.set_input_disposition(
                arg_string(args, "input_id"),
                arg_string(args, "disposition"),  # type: ignore[arg-type]
                reason=arg_string(args, "disposition_reason") or None,
            )
        except (TypeError, ValueError) as err:
            return f"error: {err}"
        return json.dumps({"ok": True, "input": item.to_dict()}, indent=2)

    def _link_input_candidate(self, args: dict[str, Any]) -> str:
        try:
            item = self.state.link_input_candidate(
                arg_string(args, "input_id"), arg_string(args, "candidate_id")
            )
        except ValueError as err:
            return f"error: {err}"
        return json.dumps({"ok": True, "input": item.to_dict()}, indent=2)

    def validation_admission_error(self, candidate_id: str, policy=None) -> str | None:
        """Whole-target new-attempt prerequisites; no mutation or execution authority.

        Historical completion markers retain their existing coverage contract.
        Late source/input obligations do not reopen those phases or prevent a
        bounded validation of an already analyzed, compatible linked input.
        """
        objective = self.state.objective
        if objective is None or objective.mode != "whole_target":
            return None
        candidate = self.state.candidates.get(candidate_id)
        if candidate is None:
            return "Candidate unavailable"
        try:
            self._validate_current_objective_candidate(candidate_id)
        except ValueError:
            return "Candidate must match the current objective and target"
        epoch = policy.engagement.http_permissions.epoch if policy else self.evidence_epoch
        ownership = {
            "candidate_id": candidate.id, "candidate_binding": candidate_binding(candidate),
            "session_id": self.session_id, "objective_id": objective.id, "epoch": epoch,
            "target_origin": candidate_origin(self._active_target()),
            "target_revision": self.target.revision if self.target else None,
            "result_position": sum(r.candidate_id == candidate_id for r in self.state.validation_results),
        }
        if candidate.status == "validating" and any(
            row.get("status") == "active" and all(row.get(key) == value for key, value in ownership.items())
            for row in self.state.attempts.values()
        ):
            return None  # Resume only the same owned active attempt; not a status-only bypass.
        for phase, name in (("recon", "recon"), ("enumeration", "web-enumeration"),
                            ("input_analysis", "web-input-analysis")):
            marker = self.state.phase_completions.get(f"{objective.id}:{phase}")
            if marker is None or phase not in self.state.completed_phases(objective):
                return f"{phase} must complete before a new Whole-target validation attempt"
            readiness = self.phase_completion_readiness(name, artifact_ref=marker.artifact_ref)
            # All prerequisite markers are checked in order above. Historical
            # readiness may be false (already completed, or late sources); only
            # its canonical artifact check applies to this completed pass.
            if not readiness["artifact_valid"]:
                return f"{phase} canonical artifact requires repair before new validation"
        for item in self.state.objective_inputs():
            if candidate_id not in item.candidate_ids or item.disposition != "analyzed":
                continue
            try:
                self.state.validate_input_candidate(item.id, candidate)
            except ValueError:
                continue
            return None
        return "Candidate requires a compatible analyzed input linked in the current objective and target"

    def _validation_prerequisite_error(self, reason: str) -> ToolOutput:
        return self._workflow_error(reason, code="WHOLE_TARGET_VALIDATION_PREREQUISITE",
            category="missing_prerequisite",
            next_action="Inspect current phase readiness and load its playbook. Complete Recon, then Enumeration, then Input Analysis through Workflow with their canonical artifacts and coverage contract; analyze and link this exact input. Early detection and grounded Candidate recording are allowed, not confirmation or impact validation. Loading a skill, writing an artifact or permission approval is not completion. Return to the missing work before retrying. Do not invent completion, source_skill or current_phase receipts. Historical completions do not reopen for late inputs/sources. An owned active Attempt keeps its existing recovery path; Direct and candidate-validation admission are unchanged.")

    def validation_handoff(self, candidate_id: str, policy=None) -> dict[str, Any] | None:
        """Bounded lifecycle metadata, never observations, admission or authority."""
        from src.workflow.assessment import attempt_owner
        from src.workflow.evidence.recovery import (
            current_budget, MAX_EVIDENCE_REJECTIONS, MAX_TERMINAL_REPAIR_TURNS,
        )
        try:
            self._validate_current_objective_candidate(candidate_id)
        except ValueError:
            return None
        candidate = self.state.candidates[candidate_id]
        objective = self.state.objective
        attempt = next((row for row in reversed(list(self.state.attempts.values()))
                        if row.get('candidate_id') == candidate_id
                        and row.get('objective_id') == (objective.id if objective else None)), None)
        epoch = policy.engagement.http_permissions.epoch if policy else self.evidence_epoch
        selector = policy.generic_validation.durable_attempt if policy else self.active_attempt
        owned = bool(attempt and selector == attempt['id'] and attempt_owner(
            self.state, selector, epoch, self.target.revision if self.target else None,
            policy.session_id or self.session_id if policy else self.session_id))
        budget = current_budget(self.state, candidate_id)
        exhausted = bool(budget and (budget['rejections'] >= MAX_EVIDENCE_REJECTIONS
                                     or budget['repair_turns'] >= MAX_TERMINAL_REPAIR_TURNS))
        latest = self.state.latest_result(candidate_id)
        terminal = bool(latest and latest.outcome in {'confirmed', 'not-confirmed'}
                        and not (objective and objective.mode == 'candidate_validation'
                                 and latest.objective_id != objective.id)
                        and candidate.status not in {'queued', 'validating'})
        stopped = bool(attempt and attempt.get('probing_stopped'))
        prerequisite = self.validation_admission_error(candidate_id, policy)
        if terminal:
            action = 'preserve_result'
        elif exhausted:
            action = 'stop_recovery'
        elif owned:
            action = 'finalize_owned' if stopped else 'resume_owned'
        elif latest and latest.outcome in {'blocked', 'browser-required', 'authorization-required', 'deferred'}:
            action = 'resolve_dependency'
        else:
            action = 'repair_prerequisites' if prerequisite else 'start_validation'
        return {
            'candidate_id': candidate_id,
            'attempt_id': attempt['id'] if attempt else None,
            'attempt_status': attempt.get('status') if attempt else None,
            'owned_active': owned, 'probing_stopped': stopped,
            'latest_outcome': latest.outcome if latest else None,
            'next_action': action, 'prerequisite_error': prerequisite,
            'recovery': {
                'status': 'exhausted' if exhausted else 'available',
                'rejections': budget['rejections'] if budget else 0,
                'repair_turns': budget['repair_turns'] if budget else 0,
                'rejection_limit': MAX_EVIDENCE_REJECTIONS,
                'repair_turn_limit': MAX_TERMINAL_REPAIR_TURNS,
                'paused': budget['paused'] if budget else False,
                'closed': budget['closed'] if budget else False,
            },
        }

    async def _start_validation(self, args: dict[str, Any], prompter: Prompter, signal: Any) -> str:
        candidate_id = arg_string(args, "candidate_id")
        try:
            self._validate_current_objective_candidate(candidate_id)
            objective = self.state.objective
            candidate = self.state.candidates.get(candidate_id)
            if objective is not None and objective.mode == "whole_target":
                from src.workflow.evidence.recovery import current_budget, MAX_EVIDENCE_REJECTIONS, MAX_TERMINAL_REPAIR_TURNS
                budget = current_budget(self.state, candidate_id)
                latest = self.state.latest_result(candidate_id)
                if (budget is not None and budget["closed"] and latest is not None
                        and latest.outcome == "insufficient-evidence"
                        and (budget["rejections"] >= MAX_EVIDENCE_REJECTIONS
                             or budget["repair_turns"] >= MAX_TERMINAL_REPAIR_TURNS)):
                    return self._workflow_error("candidate evidence recovery exhausted within this whole-target objective",
                        code="EXHAUSTED_ATTEMPT", category="immutable_state_conflict",
                        next_action="Leave this unresolved result intact. Continue independent actionable work from list, or obtain an explicit operator-selected candidate retest.",
                        candidate_id=candidate_id)
            if candidate is None:
                raise ValueError(f"unknown candidate: {candidate_id}")
            policy = policy_for(prompter)
            if policy is not None:
                policy.generic_validation.idle()
                if any(c.id != candidate_id and c.status == "validating"
                       for c in policy.generic_validation.candidates()):
                    raise ValueError("another generic validation attempt is active")
            # Preserve terminal retest/evidence-read refusals before the new gate.
            latest = self.state.latest_result(candidate_id)
            if latest is None or latest.outcome not in {"confirmed", "not-confirmed"}:
                if reason := self.validation_admission_error(candidate_id, policy):
                    return self._validation_prerequisite_error(reason)
            generic = self._is_generic(candidate)
            if generic:
                self._require_generic(candidate_id, policy)
                assert policy is not None
                assert objective is not None
                boundary = policy.generic_validation
                admitted = boundary.admit_probe(boundary.http_tool, candidate_id, args.get("probe"))
                if any(c.id != candidate_id and c.status == "validating"
                       for c in self.state.candidates.values()):
                    raise ValueError("another validation attempt is active")
                running_retest = (candidate.status == "validating"
                    and boundary.started_candidate == candidate.id
                    and objective is not None and boundary.started_objective == objective.id)
                needs_retest = (self.state.latest_result(candidate_id) is not None and not running_retest
                                or candidate.status in {"dismissed", "validated"})
                if needs_retest:
                    if objective is None or objective.id not in boundary.retest_objectives:
                        raise ValueError("generic terminal/deferred candidate requires an explicit candidate retest")
                if running_retest and boundary.attempt != admitted:
                    raise ValueError("generic active proposal cannot change without explicit retest")
            elif self.skills is not None:
                self._require_unique_validator(candidate.candidate_class)
            elif policy is not None:
                raise ValueError("skill registry unavailable for validator resolution")
            latest = self.state.latest_result(candidate_id)
            if (
                not generic and objective is not None
                and objective.mode == "whole_target"
                and latest is not None
                and latest.outcome in {"confirmed", "not-confirmed"}
                and candidate.status not in {"queued", "validating"}
            ):
                evidence_required = latest.outcome == "confirmed" or bool(
                    latest.evidence_refs
                )
                evidence_invalid = evidence_required and not self.state.evidence_matches(
                    candidate_id, latest.evidence_refs,
                )
                if evidence_required and not evidence_invalid:
                    # Evidence permission can yield. Do not commit against the
                    # pre-await records if canonical state or runtime ownership
                    # changed. Capture/auth availability is read only afterwards.
                    before = (self.state.generation, deepcopy(self.state.to_dict()))
                    policy_stamp = policy.stamp() if policy else None
                    target_revision = self.target.revision if self.target is not None else None
                    route = resolve_validation_route(self.skills, candidate.candidate_class)
                    evidence_invalid = not await verify_evidence_reads([
                        self.state.evidence[reference]
                        for reference in latest.evidence_refs
                        if reference in self.state.evidence
                    ], self.evidence_root, prompter, signal)
                    if (self.state.objective is not objective
                            or self.state.candidates.get(candidate_id) is not candidate
                            or (self.state.generation, self.state.to_dict()) != before
                            or (self.target.revision if self.target is not None else None) != target_revision
                            or resolve_validation_route(self.skills, candidate.candidate_class) != route
                            or policy_for(prompter) is not policy
                            or (policy and policy.stamp() != policy_stamp)):
                        raise ValueError("validation state changed during evidence read; retry start_validation")
                if latest.assessment_contract_version >= 2:
                    evidence_invalid = evidence_invalid or not accepted_result(self.state, candidate, latest, policy)
                if not evidence_invalid:
                    raise ValueError(
                        "terminal candidate cannot be reopened during whole-target continuation; "
                        "request an explicit candidate retest or repair its missing/invalid evidence"
                    )
            # No await from the final checks/observation through bookkeeping
            # and response serialization. This is an event-loop boundary, not
            # a turn-wide lock or a guarantee for the later HTTP invocation.
            self._validate_current_objective_candidate(candidate_id)
            if policy is not None:
                if not policy.validation_context_matches(self.state, self.skills, self.target):
                    raise ValueError("validation runtime context changed during evidence read")
                policy.generic_validation.idle()
                if any(c.id != candidate_id and c.status == "validating"
                       for c in policy.generic_validation.candidates()):
                    raise ValueError("another generic validation attempt is active")
            runtime_http = self.http_tool or (policy.generic_validation.http_tool if policy is not None else None)
            context = resolve_validation_context(
                self.state, candidate_id, target=self._active_target() or None, http_tool=runtime_http,
            ).to_dict()
            # Recheck current artifacts/linkage after any evidence-read await.
            if reason := self.validation_admission_error(candidate_id, policy):
                return self._validation_prerequisite_error(reason)
            attempt = start_attempt(self.state, candidate, self.session_id,
                policy.engagement.http_permissions.epoch if policy else self.evidence_epoch,
                requests=args.get("related_requests"), criteria=args.get("assessment"), target_origin=self._active_target() or None, target_revision=self.target.revision if self.target else None)
            self.active_attempt = attempt["id"]
            from src.workflow.assessment import attempt_owner
            self.observations.owner_provider = lambda: attempt_owner(self.state, self.active_attempt,
                self.evidence_epoch, self.target.revision if self.target else None, self.session_id)
            if policy is not None:
                policy.generic_validation.durable_attempt = attempt["id"]
            context["attempt_id"] = attempt["id"]
            if generic:
                assert policy is not None
                assert objective is not None
                context["probe_intent"] = {
                    "observation": admitted.proposal.observation,
                    "capture": admitted.proposal.capture,
                    "stop": admitted.proposal.stop,
                    "input_path": admitted.proposal.input_path,
                    "occurrence": admitted.proposal.occurrence,
                }
                if needs_retest:
                    boundary.retest_objectives.discard(objective.id)
                boundary.started_candidate = candidate.id
                boundary.started_objective = objective.id
                boundary.attempt = admitted
                boundary.expert_attempt = None
            candidate = self.state.set_candidate_status(candidate_id, "validating")
            if not generic and policy is not None and objective is not None:
                policy.generic_validation.select_expert(candidate)
        except DuplicateRequestAssociation as err:
            # Preserve the legacy text prefix/classification. The JSON is part
            # of the tool text, so string consumers and the next LLM see it.
            envelope = {"ok": False, "error": {
                "code": err.code, "action": "start_validation", "field": err.field,
                "indices": list(err.indices), "message": str(err), "repair_hint": err.repair_hint,
            }}
            return f"error: {err}\n" + json.dumps(envelope, indent=2)
        except ValueError as err:
            message = str(err)
            if message.startswith("active attempt declaration changed"):
                attempt = next((a for a in self.state.attempts.values()
                                if a.get("candidate_id") == candidate_id and a.get("status") == "active"), {})
                return self._workflow_error(message, code="IMMUTABLE_ATTEMPT_DECLARATION",
                    category="immutable_state_conflict", candidate_id=candidate_id, attempt_id=attempt.get("id"),
                    next_action="Resume the existing declaration with start_validation(candidate_id) alone. If the declaration cannot be completed, record its honest unresolved result with a reason; a changed declaration requires an explicit retest. Do not discard required related requests.")
            if message.startswith("unknown candidate"):
                return self._workflow_error(message, code="UNKNOWN_CANDIDATE", category="argument_error",
                    next_action="Use list and copy the exact returned candidate ID for the current objective; do not invent IDs.")
            if message in {"another validation attempt is active", "another generic validation attempt is active"}:
                message += (
                    '. Use workflow(action="list", status="validating") to identify the active candidate. '
                    'Continue that attempt or call record_result for it with its validator skill_name. '
                    'Use confirmed/not-confirmed only with registered proof and usable primary sources; '
                    'otherwise use insufficient-evidence or deferred with deferred_reason/notes explaining '
                    'the limitation (omit evidence_refs/observation_ids when unavailable). '
                    'An accepted unresolved result releases the attempt but leaves its work outstanding. '
                    'Then retry start_validation for the intended candidate; do not auto-close unrelated work '
                    'or attach a new primary sink through related_requests.'
                )
                return self._workflow_error(message, code="ACTIVE_ATTEMPT_CONFLICT",
                    category="immutable_state_conflict",
                    next_action='Use list(status="validating") and the active attempt\'s honest result; do not change its declaration or borrow its evidence.')
            return f"error: {message}"
        return json.dumps({"ok": True, "candidate": candidate.to_dict(),
            "validation_context": context,
            "validator_resolution": "generic" if generic else "unique",
            "proof_source_path": (
                str(policy.generic_validation.proof_path(candidate).relative_to(policy.root))
                if generic and policy is not None else None
            )}, indent=2)

    async def _record_evidence(self, args: dict[str, Any], prompter: Prompter, signal: Any) -> str:
        candidate_id = arg_string(args, "candidate_id")
        if candidate_id not in self.state.candidates:
            return f"error: unknown candidate: {candidate_id}"
        try:
            self._validate_current_objective_candidate(candidate_id)
            policy = policy_for(prompter)
            candidate = self.state.candidates[candidate_id]
            identity = candidate_binding(candidate)
            generation = self.state.generation
            objective = self.state.objective
            target_revision = self.target.revision if self.target else None
            route = resolve_validation_route(self.skills, candidate.candidate_class)
            policy_stamp = policy.stamp() if policy else None
            generic = self._is_generic(candidate)
            snapshot = None
            if generic:
                self._require_generic(candidate_id, policy)
                assert policy is not None
                snapshot = policy.generic_validation.snapshot(candidate_id)
        except ValueError as err:
            return f"error: {err}"
        path = arg_string(args, "evidence_path")
        if not path:
            return "error: record_evidence requires evidence_path"
        try:
            source = self.evidence_root.resolve() / path
            if not source.resolve().is_relative_to(self.evidence_root.resolve()):
                raise ValueError("evidence path must stay inside the project")
            if generic:
                assert policy is not None
                if source.absolute() != policy.generic_validation.proof_path(candidate):
                    raise ValueError("generic evidence source restricted to candidate proof.md")
            async with bind_source(source, self.evidence_root) as source_binding:
                real = await gate_sensitive_path(prompter, str(source), "read evidence source", signal)
                def ensure_current():
                    from src.permission.network.grants import check_cancelled
                    check_cancelled(signal)
                    if (self.state.generation != generation
                            or self.state.candidates.get(candidate_id) is not candidate
                            or candidate_binding(candidate) != identity or self.state.objective is not objective
                            or (self.target.revision if self.target else None) != target_revision
                            or resolve_validation_route(self.skills, candidate.candidate_class) != route
                            or policy_for(prompter) is not policy or (policy and policy.stamp() != policy_stamp)):
                        raise ValueError("candidate/objective/route/policy changed during evidence read")
                ensure_current()
                artifact = await EvidenceArtifact.capture_immutable_snapshot_async(
                    candidate_id, real, self.evidence_root, sensitive_read_approved=True,
                    original_path=str(source), source_binding=source_binding, publication_check=ensure_current,
                )
                ensure_current()
                if snapshot is not None:
                    assert policy is not None
                    policy.generic_validation.unchanged(candidate_id, snapshot)
                if "source_kind" in args or "assessment_source" in args:
                    raise ValueError("proof file provenance cannot be promoted by model labels")
                ids = references(args.get("observation_ids", []), "observation_ids")
                aid = policy.generic_validation.durable_attempt if policy else self.active_attempt
                selected = resolve_sources(policy, self.state, candidate, self.state.attempts.get(aid) if aid is not None else None, ids,
                    terminal=False, negative=False, store=self.observations) if ids else []
                check_proof_references(await artifact.read_verified_async(self.evidence_root, sensitive_read_approved=True), candidate_id, ids)
                previous = self.state.evidence_sources.get(artifact.id)
                if previous is not None and previous != ids:
                    raise EvidenceSubmissionError("IMMUTABLE_PARENT_CONFLICT", "immutable derived evidence source association changed")
                await run_sync(source_binding.validate)
                ensure_current()
                self.state.add_evidence(artifact)
                if ids:
                    self.state.evidence_sources[artifact.id] = ids
                for entry in selected:
                    self.state.selected_sources[entry["source"]["id"]] = entry
                while len(self.state.selected_sources) > 256 or len(json.dumps(self.state.selected_sources)) > 16 * 1024 * 1024:
                    del self.state.selected_sources[next(iter(self.state.selected_sources))]
        except UserControlledRefusal:
            raise
        except EvidenceSubmissionError as err:
            return err.response("record_evidence")
        except FileNotFoundError:
            return self._workflow_error('evidence source file does not exist',
                code='MISSING_EVIDENCE_FILE', category='missing_prerequisite',
                next_action='First create the parent directory and write minimal redacted proof with file_write outside artifacts/findings. Then record_evidence with that existing evidence_path and the current Attempt owned observation_ids. Copy returned evidence.id (ev_...) into record_result.evidence_refs. Registration does not create the source file or a Finding.')
        except (OSError, ValueError) as err:
            return f"error: {err}"
        return json.dumps({"ok": True, "evidence": artifact.to_dict(), "evidence_kind": "derived", "primary_parents": ids}, indent=2)

    def _record_attempt_state(self, args, policy):
        from src.workflow.assessment import attempt_owner, attempt_effects, require_idle_attempt, require_usable_source, require_cleanup_evidence
        cid = arg_string(args, "candidate_id")
        try:
            self._validate_current_objective_candidate(cid)
            aid = policy.generic_validation.durable_attempt if policy else self.active_attempt
            attempt = self.state.attempts.get(aid) if aid is not None else None
            if (not attempt or attempt["candidate_id"] != cid
                    or args.get("attempt_id", aid) != aid
                    or attempt_owner(self.state, aid,
                        policy.engagement.http_permissions.epoch if policy else self.evidence_epoch,
                        self.target.revision if self.target else None, self.session_id) is None):
                raise ValueError("current active attempt ownership required")
            metadata = attempt_effects(self.state, attempt, policy.observations if policy else self.observations)
            require_idle_attempt(attempt, policy)
            mutation = args.get("mutation_state")
            flags = {"unknown": None, "possible": None, "reported-write": True,
                     "verified-write": True, "no-mutation-established": False}
            if (mutation not in flags or not isinstance(args.get("effect_basis"), str)
                    or not args["effect_basis"].strip() or len(args["effect_basis"]) > 2000):
                raise ValueError("mutation_state and explicit effect_basis required")
            flag = flags[mutation]
            if metadata["mutation_performed"] is True and flag is not True:
                raise ValueError("unresolved acknowledged writes cannot be erased by a later declaration")
            if "mutation_performed" in args and args["mutation_performed"] is not flag:
                raise ValueError("mutation declaration is inconsistent")
            if self._is_generic(self.state.candidates[cid]) and flag is True:
                raise ValueError("generic mutation/impact validation unavailable")
            ids = references(args.get("observation_ids", []), "observation_ids")
            sources = resolve_sources(policy, self.state, self.state.candidates[cid], attempt, ids,
                                      terminal=False, negative=False, store=self.observations)
            if mutation not in {"unknown", "possible"}:
                if not sources:
                    raise ValueError("established effects require owned primary observations")
                for row in sources:
                    require_usable_source(row["source"])
            if mutation == "verified-write" and not (
                    any(row["source"].get("role") == "readback" for row in sources)
                    and any(row["source"].get("role") != "readback" for row in sources)):
                raise ValueError("verified mutation requires owned independent readback")
            if flag is False and any(row["status"] != "completed" for row in attempt["effects"]["dispatches"]):
                raise ValueError("failed dispatch effects remain unknown")
            declaration = ValidationResult(cid, "attempt-bookkeeping", "insufficient-evidence",
                mutation_performed=flag, cleanup_state=args.get("cleanup_state"),
                cleanup_status=args.get("cleanup_status"))
            declaration.validate_cleanup_submission()
            if declaration.cleanup_state == "succeeded":
                require_cleanup_evidence(sources)
            from src.redaction.redact import apply_evidence
            attempt["effects"]["declaration"] = {
                "mutation_state": mutation, "effect_basis": apply_evidence(args["effect_basis"])[:2000],
                "mutation_performed": flag, "cleanup_state": declaration.cleanup_state,
                "cleanup_status": declaration.cleanup_status, "observation_ids": ids}
            # Pin only selected, checked sources using the existing bounded
            # evidence storage; eviction must not erase an acknowledged write.
            for entry in sources:
                self.state.selected_sources[entry["source"]["id"]] = entry
            while len(self.state.selected_sources) > 256 or len(json.dumps(self.state.selected_sources)) > 16 * 1024 * 1024:
                del self.state.selected_sources[next(iter(self.state.selected_sources))]
            self.state.mark_committed()
            return json.dumps({"ok": True, "attempt_id": aid, "effects": attempt["effects"]["declaration"]})
        except (TypeError, ValueError) as err:
            return f"error: {err}"

    def _result_effect_fields(self, args, policy):
        from src.workflow.assessment import attempt_effects, require_idle_attempt
        aid = policy.generic_validation.durable_attempt if policy else self.active_attempt
        attempt = self.state.attempts.get(aid) if aid is not None else None
        if attempt and attempt.get("candidate_id") == args.get("candidate_id") and attempt.get("status") == "active":
            metadata = attempt_effects(self.state, attempt, policy.observations if policy else self.observations)
            require_idle_attempt(attempt, policy)
            boundary = policy.generic_validation if policy else None
            if (metadata["mutation_performed"] is None and boundary is not None
                    and boundary.started_candidate == attempt["candidate_id"]
                    and boundary.attempt is not None
                    and boundary.contexts.get(attempt["candidate_id"]) == boundary.attempt
                    and not any(row["tool"] != "http" for row in attempt["effects"]["admissions"])):
                # The existing trusted controller bound these exact input-only
                # values. This is not a GET/status/model-derived effect claim.
                metadata = {"mutation_performed": False, "cleanup_state": "not-required",
                            "cleanup_status": "Controller-verified input-only probe context"}
        else:
            metadata = {"mutation_performed": None, "cleanup_state": "unknown", "cleanup_status": None}
            latest = self.state.latest_result(args.get("candidate_id"))
            if attempt and latest and latest.attempt_id == aid:
                metadata = {k: getattr(latest, k) for k in metadata}
        if "mutation_performed" in args:
            if metadata["mutation_performed"] is True and args["mutation_performed"] is not True:
                raise ValueError("mutation submission contradicts owned attempt effects")
            if args["mutation_performed"] is False and attempt and attempt.get("status") == "active" and any(
                    row["status"] != "completed" for row in attempt.get("effects", {}).get("dispatches", [])):
                raise ValueError("failed dispatch effects remain unknown")
            # Explicit legacy-compatible submissions are declarations, never
            # effects inferred from GET/200 or from missing fields.
            return {"mutation_performed": args["mutation_performed"],
                    "cleanup_state": args.get("cleanup_state"), "cleanup_status": args.get("cleanup_status")}
        return {k: args.get(k, v) for k, v in metadata.items()}

    async def _record_result(self, args: dict[str, Any], prompter: Prompter, signal: Any) -> str:
        try:
            for reserved in ("assessment_source", "assessment_contract_version", "result_id", "assessment_binding", "evidence_manifest", "candidate_binding", "source_kind", "session_id", "objective_id"):
                if reserved in args:
                    raise ValueError("assessment authority/identity fields are controller-owned")
            refs = references(args.get("evidence_refs", []), "evidence_refs", 16)
            ids = references(args.get("observation_ids", []), "observation_ids")
            result = ValidationResult(
                candidate_id=arg_string(args, "candidate_id"),
                skill_name=arg_string(args, "skill_name"),
                outcome=arg_string(args, "outcome"),  # type: ignore[arg-type]
                evidence_refs=refs,
                techniques=args.get("techniques", []),
                repeatable=args.get("repeatable"),
                confirmation=args.get("confirmation"),
                **self._result_effect_fields(args, policy_for(prompter)),
                deferred_reason=args.get("deferred_reason"),
                notes=args.get("notes"),
                recorded_at=datetime.now(UTC).isoformat(),
                session_id=self.session_id,
                objective_id=(self.state.objective.id if self.state.objective else None),
            )
            result.validate_cleanup_submission()
            candidate = self.state.candidates.get(result.candidate_id)
            if candidate is None:
                raise ValueError(f"unknown candidate: {result.candidate_id}")
            self._validate_current_objective_candidate(result.candidate_id)
            generic = result.skill_name == GENERIC_VALIDATOR or self._is_generic(candidate)
            policy = policy_for(prompter)
            before = (self.state.generation, deepcopy(self.state.to_dict()))
            candidate_object = candidate
            target_revision = self.target.revision if self.target else None
            route_before = resolve_validation_route(self.skills, candidate.candidate_class)
            policy_stamp = policy.stamp() if policy else None
            snapshot = None
            if generic:
                self._require_generic(candidate.id, policy)
                assert policy is not None
                policy.generic_validation.idle()
                if result.skill_name != GENERIC_VALIDATOR:
                    raise ValueError("generic result requires reserved validator identifier")
                if result.mutation_performed:
                    raise ValueError("generic mutation/impact validation unavailable")
                snapshot = policy.generic_validation.snapshot(candidate.id)
            if not generic and result.outcome == "confirmed" and not result.evidence_refs:
                raise EvidenceSubmissionError("MISSING_REGISTERED_EVIDENCE", "confirmed result requires an evidence reference")
            if result.evidence_refs and not self.state.evidence_matches(result.candidate_id, result.evidence_refs):
                raise EvidenceSubmissionError("EVIDENCE_REFERENCE_MISMATCH", "evidence references must resolve to this candidate")
            evidence_binding = [self.state.evidence[ref].to_dict() for ref in result.evidence_refs]
            if result.evidence_refs and not await verify_evidence_reads(
                [self.state.evidence[ref] for ref in result.evidence_refs],
                self.evidence_root, prompter, signal,
            ):
                raise EvidenceSubmissionError("EVIDENCE_ARTIFACT_UNAVAILABLE", "evidence artifact changed or is unavailable")
            skill = self.skills.get(result.skill_name) if self.skills else None
            if not generic and self.skills is not None:
                validator = self._require_unique_validator(candidate.candidate_class)
                if result.skill_name != validator.name:
                    raise ValueError(
                        "result skill must be the unique validator for candidate class"
                    )
            elif skill and skill.candidate_classes and candidate.candidate_class not in skill.candidate_classes:
                raise ValueError("result skill does not handle candidate class")
            terminal = result.outcome in {"confirmed", "not-confirmed"}
            aid = policy.generic_validation.durable_attempt if policy is not None else self.active_attempt
            attempt = self.state.attempts.get(aid) if aid is not None else None
            # A closed selector is retained for same-revision retries. It is
            # not an execution owner for a different, unstarted Candidate.
            if (attempt is not None and attempt.get("candidate_id") != candidate.id
                    and attempt.get("status") != "active"
                    and args.get("attempt_id") is None and not ids):
                aid, attempt = None, None
            if attempt is not None and (
                    attempt.get("candidate_binding") != candidate_binding(candidate)
                    or attempt.get("session_id") != self.session_id
                    or attempt.get("objective_id") != result.objective_id
                    or attempt.get("epoch") != (policy.engagement.http_permissions.epoch if policy else self.evidence_epoch)
                    or attempt.get("target_revision") != (self.target.revision if self.target else None)
                    or (attempt.get("status") == "active" and attempt.get("result_position") != sum(r.candidate_id == candidate.id for r in self.state.validation_results))):
                raise EvidenceSubmissionError("ATTEMPT_OWNERSHIP_MISMATCH", "stale active attempt ownership/epoch/target/result position")
            if args.get("attempt_id") is not None and args["attempt_id"] != aid:
                missing_start = not attempt or attempt.get("status") != "active"
                raise EvidenceSubmissionError("MISSING_VALIDATION_START" if missing_start else "ATTEMPT_IDENTITY_MISMATCH",
                    "stale/wrong attempt identity", validation_step=missing_start)
            latest = self.state.latest_result(candidate.id)
            # A transport retry/cleanup update preserves the exact revision.
            # An explicit new start has a different attempt and never dedups.
            retry_fields = ("outcome", "skill_name", "evidence_refs", "techniques", "repeatable",
                            "confirmation", "mutation_performed")
            if (latest is not None and latest.assessment_contract_version >= 2
                    and not arg_bool(args, "force")
                    and latest.session_id == self.session_id and latest.objective_id == result.objective_id
                    and latest.candidate_binding == candidate_binding(candidate)
                    and latest.attempt_id == aid and (attempt is None or attempt.get("status") != "active")
                    and all(getattr(latest, key) == getattr(result, key) for key in retry_fields)):
                expected_ids = [entry["source"]["id"] for entry in latest.evidence_manifest]
                expected_assessment = {k: v for k, v in latest.assessment.items() if k not in {"artifacts", "artifact_sources", "attempt"}}
                if ids != expected_ids or args.get("assessment", {}) != expected_assessment:
                    raise ValueError('Closed attempt assessment changed. Start an explicit retest.')
                if (self.state.generation, self.state.to_dict()) != before or latest.assessment_binding != seal(latest):
                    raise ValueError("stale retry assessment")
                if terminal and not accepted_result(self.state, candidate, latest, policy):
                    raise ValueError("retry assessment evidence unavailable")
                if result.cleanup_state == "succeeded":
                    from src.workflow.assessment import require_cleanup_evidence
                    require_cleanup_evidence(latest.evidence_manifest)
                latest.cleanup_status, latest.cleanup_state = result.cleanup_status, result.cleanup_state
                self.state.set_candidate_status(candidate.id, "validated" if terminal else "deferred")
                if latest.coverage_synced is False:
                    await self._sync_coverage(candidate, latest)
                return json.dumps({"ok": True, "created": False, "result": latest.public_dict(),
                    "eligible_for_confirm_finding": self.state.eligible_for_finding(candidate.id),
                    "coverage_sync": "synced" if latest.coverage_synced else "not-pending"})
            if terminal and (not attempt or attempt.get("status") != "active"):
                raise EvidenceSubmissionError("MISSING_VALIDATION_START",
                    "terminal assessment requires successful start_validation", validation_step=True)
            assessment = args.get("assessment", {})
            if not isinstance(assessment, dict) or len(json.dumps(assessment)) > 6000:
                raise ValueError("assessment must be a bounded object")
            if set(assessment) & {"artifacts", "artifact_sources", "attempt", "assessment_source", "assessment_binding"}:
                raise ValueError("assessment provenance/binding fields are controller-owned")
            if terminal:
                if not refs:
                    raise EvidenceSubmissionError("MISSING_REGISTERED_EVIDENCE", "both terminal outcomes require registered evidence")
                if not all(isinstance(assessment.get(key), str) and assessment[key].strip()
                           for key in ("hypothesis", "criteria", "limitations", "observed_impact", "severity")):
                    raise ValueError("terminal assessment requires hypothesis, criteria, limitations, observed_impact, severity")
                if assessment["severity"] not in {"info", "low", "medium", "high", "critical"}:
                    raise ValueError("invalid assessment severity")
                if result.outcome == "not-confirmed" and assessment.get("completed_attempt") is not True:
                    raise ValueError("negative assessment requires declared completed bounded attempt")
                if generic and (attempt is None or not isinstance(attempt.get("criteria"), dict)
                        or not all(isinstance(attempt["criteria"].get(k), str) and attempt["criteria"][k].strip()
                                   for k in ("hypothesis", "criteria", "limitations"))):
                    raise ValueError('Generic fallback lacks declared criteria. Submit an unresolved result.')
            manifest = resolve_sources(policy, self.state, candidate, attempt, ids,
                terminal=terminal, negative=result.outcome == "not-confirmed", store=self.observations)
            if result.cleanup_state == "succeeded":
                from src.workflow.assessment import require_cleanup_evidence
                require_cleanup_evidence(manifest)
            check_excerpts(assessment, manifest, terminal=terminal)
            if terminal and not any(e["source"]["source_kind"] in {"native-http", "imported-capture"}
                    and e["source"].get("complete") and not e["source"].get("truncated")
                    and e["source"].get("execution_status") == "completed" for e in manifest):
                raise ValueError("tool output claims alone cannot establish target request/response evidence")
            if ((self.state.generation, self.state.to_dict()) != before or self.state.candidates.get(candidate.id) is not candidate_object
                    or (self.target.revision if self.target else None) != target_revision
                    or resolve_validation_route(self.skills, candidate.candidate_class) != route_before
                    or policy_for(prompter) is not policy or (policy and policy.stamp() != policy_stamp)):
                raise ValueError("candidate/objective/route/policy changed during result submission")
            if any(not self.state.evidence[ref].is_available_for_resume(self.evidence_root) for ref in refs):
                raise ValueError("evidence integrity changed during result submission")
            if any(parent not in ids for ref in refs for parent in self.state.evidence_sources.get(ref, [])):
                raise EvidenceSubmissionError("DERIVED_PARENT_MISMATCH", "derived evidence requires its declared primary source parents")
            # Sources are checked again after every evidence permission await.
            result.assessment_contract_version = 2
            result.assessment_source = "agent"
            result.result_id = "result_" + uuid.uuid4().hex
            result.attempt_id = aid
            result.candidate_binding = candidate_binding(candidate)
            result.evidence_manifest = manifest
            result.assessment = {**cast(dict, redact_payload(assessment)), "artifacts": evidence_binding,
                                 "artifact_sources": {ref: list(self.state.evidence_sources.get(ref, [])) for ref in refs},
                                 "attempt": {k:v for k,v in attempt.items() if k != "status"} if attempt else None}
            result.assessment_binding = seal(result)
            coverage_status = self._coverage_status(result)
            if self.coverage is not None and coverage_status:
                result.coverage_synced = False
            if snapshot is not None:
                assert policy is not None
                policy.generic_validation.idle()
                policy.generic_validation.unchanged(candidate.id, snapshot)
                if evidence_binding != [self.state.evidence[ref].to_dict() if ref in self.state.evidence else None
                                        for ref in result.evidence_refs]:
                    raise ValueError("generic evidence ownership/identity changed during result verification")
                if any(not self.state.evidence[ref].is_available_for_resume(self.evidence_root)
                       for ref in result.evidence_refs):
                    raise ValueError("generic evidence integrity changed during result verification")
            if attempt is not None:
                attempt["status"] = "completed" if terminal else "unresolved"
            created = self.state.add_validation_result(
                result,
                force=arg_bool(args, "force"),
            )
            stored = self.state.latest_result(result.candidate_id)
            assert stored is not None
            if generic:
                assert policy is not None
                policy.generic_validation.started_candidate = None
                policy.generic_validation.started_objective = None
                policy.generic_validation.attempt = None
            elif (policy is not None and policy.generic_validation.expert_attempt is not None
                  and policy.generic_validation.expert_attempt[0] == candidate.id):
                policy.generic_validation.expert_attempt = None
        except EvidenceSubmissionError as err:
            return err.response("record_result")
        except (TypeError, ValueError) as err:
            return f"error: {err}"
        sync_error: str | None = None
        if stored.coverage_synced is False:
            try:
                await self._sync_coverage(candidate, stored)
            except (OSError, ValueError) as err:
                sync_error = str(err)
        return json.dumps(
            {
                "ok": True,
                "created": created,
                "eligible_for_confirm_finding": self.state.eligible_for_finding(
                    result.candidate_id
                ),
                "coverage_status": coverage_status if self.coverage is not None else None,
                "coverage_sync": "pending" if stored.coverage_synced is False else (
                    "synced" if stored.coverage_synced else "not-applicable"
                ),
                "coverage_error": sync_error,
                "result": stored.public_dict(),
            },
            indent=2,
        )

    @staticmethod
    def _coverage_status(result: ValidationResult) -> CoverageStatus | None:
        if result.outcome == "confirmed":
            return "failed"
        if result.outcome == "not-confirmed":
            return "passed"
        return None

    async def _sync_coverage(self, candidate: Candidate, result: ValidationResult) -> None:
        from src.permission.runtime.execution import current_policy
        policy = current_policy()
        if not accepted_result(self.state, candidate, result, policy):
            raise ValueError("inadmissible current assessment; coverage remains pending")
        if any(not self.state.evidence[ref].is_available_for_resume(self.evidence_root) for ref in result.evidence_refs):
            raise ValueError("coverage evidence integrity unavailable; coverage remains pending")
        if self.coverage is None:
            return
        status = self._coverage_status(result)
        if status is None:
            return
        endpoint, parameter, context = project_candidate_coverage(self.state, candidate, result)
        active_origin = candidate_origin(self._active_target())
        if active_origin is not None and context.target_origin not in (None, active_origin):
            raise ValueError("coverage candidate differs from active target origin")
        target_revision = self.target.revision if self.target is not None else None
        fingerprint = validation_result_fingerprint(result)
        generation = self.state.generation
        previous = deepcopy(await self.coverage.get(endpoint=endpoint, param=parameter,
            vulnClass=candidate.candidate_class, context=context))
        if (self.state.generation != generation or self.state.latest_result(candidate.id) is not result
                or not accepted_result(self.state, candidate, result, policy)
                or any(not self.state.evidence[ref].is_available_for_resume(self.evidence_root) for ref in result.evidence_refs)):
            raise ValueError("canonical assessment changed before coverage persistence")
        legacy_observation_ids = tuple(
            validation_result_fingerprint(previous)
            for previous in self.state.validation_results
            if previous.candidate_id == candidate.id
        )
        await self.coverage.ensure_validation_mark(
            endpoint=endpoint,
            param=parameter,
            vulnClass=candidate.candidate_class,
            status=status,
            notes=f"result={fingerprint[:20]}",
            observation_id=f"candidate:{candidate.id}",
            legacy_observation_ids=legacy_observation_ids,
            context=context,
        )
        # Loading/flushing the projection may yield. A durable historical row
        # cannot mark a replaced or changed canonical outcome/context synced.
        if (self.state.generation != generation or self.state.latest_result(candidate.id) is not result
                or validation_result_fingerprint(result) != fingerprint
                or project_candidate_coverage(self.state, candidate, result) != (endpoint, parameter, context)
                or (self.target.revision if self.target is not None else None) != target_revision
                or not accepted_result(self.state, candidate, result, policy)
                or any(not self.state.evidence[ref].is_available_for_resume(self.evidence_root) for ref in result.evidence_refs)):
            await self.coverage.rollback_validation_projection(endpoint=endpoint, param=parameter,
                vulnClass=candidate.candidate_class, context=context,
                expected_notes=f"result={fingerprint[:20]}", previous=previous)
            raise ValueError("canonical coverage context changed during persistence; retry sync")
        result.coverage_synced = True
        self.state.mark_committed()

    async def _sync_coverage_action(self, args: dict[str, Any]) -> str:
        candidate_id = arg_string(args, "candidate_id")
        candidate = self.state.candidates.get(candidate_id)
        result = self.state.latest_result(candidate_id)
        if candidate is None or result is None:
            return f"error: no validation result for candidate: {candidate_id}"
        try:
            self._validate_current_objective_candidate(candidate_id)
        except ValueError as err:
            return f"error: {err}"
        if result.coverage_synced is not False:
            return json.dumps({"ok": True, "coverage_sync": "not-pending"})
        try:
            await self._sync_coverage(candidate, result)
        except (OSError, ValueError) as err:
            return json.dumps({"ok": False, "coverage_sync": "pending", "error": str(err)})
        return json.dumps({"ok": True, "coverage_sync": "synced"})

    def validation_completion_error(self, candidate_id: str, policy=None) -> str | None:
        """Resolve validator admission, then evaluate authoritative persisted work."""
        candidate = self.state.candidates.get(candidate_id)
        if candidate is None:
            return "unknown candidate"
        result = self.state.latest_result(candidate_id)
        route = resolve_validation_route(self.skills, candidate.candidate_class)
        if result is not None:
            if result.skill_name == GENERIC_VALIDATOR:
                if route.kind != "generic" or policy is None:
                    return "generic validation proof is unavailable under the current route"
                admission = generic_admission(candidate, self.state, self.skills, self.target, policy)
                if admission:
                    return admission
                objective = self.state.objective
                if objective and objective.id in policy.generic_validation.retest_objectives:
                    return "explicit generic validation/retest remains pending"
            elif route.kind != "expert" or route.skill_name != result.skill_name:
                return route.reason or "recorded expert validator is no longer uniquely resolvable"
        if policy is not None and candidate.target and not policy.engagement.is_in_scope(candidate.target):
            return "candidate is outside current engagement scope"
        origin = self.target.origin() if self.target else None
        reason = self.state.validation_completion_error(
            candidate_id, target_origin=origin.as_url() if origin else None,
            evidence_root=self.evidence_root, policy=policy,
        )
        if reason:
            return reason
        assert result is not None
        if result.skill_name == GENERIC_VALIDATOR:
            return None
        # A custom validator may declare a genuine operational artifact. Shipped
        # validators use immutable proof references and no presentation gate.
        skill = self.skills.get(result.skill_name) if self.skills else None
        if skill and skill.completion_artifact:
            try:
                expected = completion_artifact_path(skill.completion_artifact, self._active_target())
                artifact = resolve_canonical_artifact(self.evidence_root, expected)
                if not artifact.is_file() or artifact.stat().st_size <= 0:
                    return f"operational artifact unavailable:{expected}"
            except (OSError, ValueError):
                return "operational artifact unavailable"
        return None

    def completed_skills(self, policy=None) -> frozenset[str]:
        """Derived validation projection plus historical operational receipts.

        Never store synthetic completion flags: new assignments/retests immediately
        invalidate this projection, while old session markers remain readable.
        """
        validators = {
            skill.name: skill for skill in self.skills.list()
            if skill.stage == "validation" and skill.candidate_classes
        } if self.skills else {}
        completed = self.state.completed_skills - validators.keys()
        objective = self.state.objective
        if objective is None:
            return frozenset(completed)
        assigned = [c for c in self.state.candidates.values()
                    if (c.id == objective.candidate_id if objective.mode == "candidate_validation"
                        else c.objective_id == objective.id)]
        for name, skill in validators.items():
            candidates = [c for c in assigned if c.candidate_class in skill.candidate_classes]
            if not candidates or any(self.validation_completion_error(c.id, policy) for c in candidates):
                continue
            if any(goal.candidate_class in skill.candidate_classes
                   and not any(c.candidate_class == goal.candidate_class for c in candidates)
                   for goal in objective.requested_goals):
                continue
            completed.add(name)
        return frozenset(completed)

    def _complete_skill(self, args: dict[str, Any], policy=None) -> str:
        skill_name = arg_string(args, "skill_name")
        if not skill_name:
            return "error: complete_skill requires skill_name"
        canonical = normalize_metadata_name(skill_name)[:80]
        if canonical == GENERIC_VALIDATOR:
            return "error: generic validator is an internal result identifier, not a skill"
        artifact_ref = arg_string(args, "artifact_ref")
        skill = self.skills.get(canonical) if self.skills else None
        if skill and skill.stage == "validation" and skill.candidate_classes:
            if artifact_ref:
                return "error: vulnerability completion is runtime-managed; artifact_ref is not a completion receipt"
            if canonical not in self.completed_skills(policy):
                return "error: vulnerability validation is runtime-managed; assigned work remains unresolved"
            # Compatibility for old callers, with no mutation or artifact receipt.
            return json.dumps({"ok": True, "skill_name": canonical,
                               "completion_source": "runtime", "phase": None, "artifact_ref": None})
        objective = self.state.objective
        workflow_phase = (
            self._phase_for_skill(canonical, skill)
            if objective is not None and objective.mode == "whole_target" else None
        )
        if workflow_phase is not None:
            readiness = self.phase_completion_readiness(
                canonical,
                artifact_ref=artifact_ref or None,
                no_inputs_discovered=arg_bool(args, "no_inputs_discovered"),
            )
            if not readiness["ready"]:
                already_completed = readiness["reason"] == f"{workflow_phase} phase is already completed"
                return self._workflow_error(readiness['reason'], code="PHASE_NOT_READY",
                    category="immutable_state_conflict" if already_completed else "missing_prerequisite",
                    next_action="Inspect list and phase readiness. Resolve the stated prerequisite, artifact, coverage or input obligation through its existing contract before retrying complete_skill.",
                    readiness=readiness)
            artifact_ref = readiness["artifact_ref"]
            phase_coverage = self.state.phase_coverage.get(
                f"{objective.id}:{workflow_phase}", {}  # type: ignore[union-attr]
            )
            try:
                self.state.record_phase_completion(
                    workflow_phase,
                    objective_id=objective.id,  # type: ignore[union-attr]
                    target_origin=objective.target_origin or "",  # type: ignore[union-attr]
                    artifact_ref=artifact_ref,
                    coverage={
                        key: phase_coverage[key]
                        for key in PHASE_COVERAGE_DIMENSIONS.get(workflow_phase, ())
                    },
                    no_inputs_discovered=(
                        workflow_phase == "input_analysis"
                        and arg_bool(args, "no_inputs_discovered")
                    ),
                )
            except ValueError as err:
                return f"error: {err}"
        elif skill and skill.completion_artifact:
            target = self._active_target()
            try:
                expected = completion_artifact_path(skill.completion_artifact, target)
                artifact = resolve_canonical_artifact(self.evidence_root, expected)
            except ValueError as err:
                return f"error: {err}"
            if artifact_ref:
                try:
                    supplied = resolve_canonical_artifact(
                        self.evidence_root, artifact_ref
                    )
                except ValueError as err:
                    return f"error: {err}"
                if supplied != artifact:
                    return f"error: {canonical} completion requires {expected}"
            try:
                artifact_ready = artifact.is_file() and artifact.stat().st_size > 0
            except OSError:
                artifact_ready = False
            if not artifact_ready:
                return f"error: {canonical} completion requires {expected}"
            artifact_ref = expected
        self.state.completed_skills.add(canonical)
        if artifact_ref:
            self.state.completed_artifacts[canonical] = redact(artifact_ref)[:500]
        display_phase = arg_string(args, "current_phase")
        if display_phase:
            self.state.current_phase = display_phase[:80]
        return json.dumps({
            "ok": True, "skill_name": canonical,
            "phase": workflow_phase,
            "artifact_ref": self.state.completed_artifacts.get(canonical),
        }, indent=2)

    async def _review_no_candidate(self, args: dict[str, Any], prompter: Prompter, signal: Any) -> str:
        generation = self.state.generation
        objective = self.state.objective
        goal_id = arg_string(args, "goal_id")
        if objective is None or objective.mode != "whole_target":
            return "error: review_no_candidate requires an active whole-target objective"
        goal = next((item for item in objective.requested_goals if item.id == goal_id), None)
        if goal is None:
            return "error: review_no_candidate requires a goal_id from the active objective"
        if self.target is None or self.target.empty() or normalize_target_origin(
            self.target.base_url()
        ) != objective.target_origin:
            return "error: active target does not match the whole-target objective"
        prerequisite_error = self.state.no_candidate_review_prerequisite_error(goal)
        if prerequisite_error:
            return f"error: {prerequisite_error}"
        marker = self.state.phase_completions.get(f"{objective.id}:input_analysis")
        if marker is None:
            return "error: input analysis has not completed for the active objective"
        supplied_ref = arg_string(args, "artifact_ref")
        if supplied_ref and supplied_ref != marker.artifact_ref:
            return "error: artifact_ref must match the active input-analysis completion"
        try:
            artifact = resolve_canonical_artifact(self.evidence_root, marker.artifact_ref)
            if not artifact.is_file() or artifact.stat().st_size <= 0:
                return "error: input-analysis review artifact is unavailable"
            await gate_sensitive_path(prompter, str(artifact), "read input-analysis review artifact", signal)
            if (self.state.generation != generation or self.state.objective is not objective or self.target is None
                    or normalize_target_origin(self.target.base_url()) != objective.target_origin):
                return "error: objective or target changed during no-candidate review"
            policy = policy_for(prompter)
            if policy is not None:
                policy.generic_validation.idle()
            with artifact.open("rb") as handle:
                artifact_digest = hashlib.file_digest(handle, "sha256").hexdigest()
            if artifact.stat().st_size <= 0:
                return "error: input-analysis review artifact is unavailable"
            binding = self.state.no_candidate_review_binding(goal, artifact_digest)
            reviewed = self.state.mark_goal_no_candidate(
                goal.id, artifact_ref=marker.artifact_ref, review_binding=binding,
            )
        except (OSError, ValueError) as err:
            return f"error: {err}"
        return json.dumps({
            "ok": True,
            "goal": reviewed.to_dict(),
            "class_specific_validation_performed": False,
        }, indent=2)

    def phase_completion_readiness(
        self, skill_name: str, *, artifact_ref: str | None = None,
        no_inputs_discovered: bool = False,
    ) -> dict[str, Any]:
        """Read-only version of the whole-target phase completion gate."""
        canonical = normalize_metadata_name(skill_name)[:80]
        skill = self.skills.get(canonical) if self.skills else None
        phase = self._phase_for_skill(canonical, skill)
        objective = self.state.objective
        coverage = self.state.phase_coverage.get(
            f"{objective.id}:{phase}", {}
        ) if objective is not None and phase is not None else {}
        required = PHASE_COVERAGE_DIMENSIONS.get(phase or "", ())
        historically_completed = phase in self.state.completed_phases(objective)
        if historically_completed and objective is not None:
            marker = self.state.phase_completions[f"{objective.id}:{phase}"]
            coverage = marker.coverage
            no_inputs_discovered = marker.no_inputs_discovered
        result: dict[str, Any] = {
            "ready": False, "skill_name": canonical, "phase": phase,
            "historically_completed": historically_completed, "artifact_valid": False,
            "prerequisites_valid": False,
            "artifact_ref": None, "no_inputs_discovered": no_inputs_discovered,
            "objective_id": objective.id if objective is not None else None,
            "target_origin": objective.target_origin if objective is not None else None,
            "prerequisites": (
                ("recon",) if phase == "enumeration" else
                ("enumeration",) if phase == "input_analysis" else ()
            ),
            "required_coverage": {
                dimension: coverage[dimension].status if dimension in coverage else None
                for dimension in required
            },
        }

        def reject(reason: str) -> dict[str, Any]:
            result["reason"] = reason
            return result

        if objective is None or objective.mode != "whole_target" or phase is None:
            return reject("phase completion requires an active whole-target objective")
        if objective.target_origin != normalize_target_origin(self._active_target()):
            return reject("phase completion must match the active objective and target")
        if (
            skill is None or self.skills is None
            or (not historically_completed
                and (skill.disable_model_invocation or self.skills.is_disabled(canonical)))
        ):
            return reject(f"{canonical} is unavailable for whole-target phase completion")
        if not skill.completion_artifact:
            return reject(f"{canonical} has no canonical phase artifact")
        try:
            expected = completion_artifact_path(skill.completion_artifact, self._active_target())
            artifact = resolve_canonical_artifact(self.evidence_root, expected)
            if artifact_ref and resolve_canonical_artifact(self.evidence_root, artifact_ref) != artifact:
                return reject(f"{canonical} completion requires {expected}")
            artifact_ready = artifact.is_file() and artifact.stat().st_size > 0
        except ValueError as err:
            return reject(str(err))
        except OSError:
            artifact_ready = False
        result["artifact_ref"] = expected
        if not artifact_ready:
            return reject(f"{canonical} completion requires {expected}")
        result["artifact_valid"] = True
        phases = self.state.completed_phases(objective)
        if phase == "enumeration" and "recon" not in phases:
            return reject("recon must complete before enumeration")
        if phase == "input_analysis" and "enumeration" not in phases:
            return reject("enumeration must complete before input analysis")
        prerequisite_skill = {"enumeration": "recon", "input_analysis": "web-enumeration"}.get(phase)
        if prerequisite_skill is not None:
            prerequisite = self.phase_completion_readiness(prerequisite_skill)
            if not prerequisite["artifact_valid"] or not prerequisite["prerequisites_valid"]:
                return reject(f"{prerequisite['phase']} artifact repair required: {prerequisite['reason']}")
        result["prerequisites_valid"] = True
        if phase in {'enumeration', 'input_analysis'} and (reason := self.state.source_completion_error()):
            result['prerequisites_valid'] = False
            return reject(reason)
        if historically_completed:
            return reject(f"{phase} phase is already completed")
        if phase == "input_analysis":
            if any(item.disposition in {"pending", "blocked"} for item in self.state.objective_inputs()):
                return reject("input analysis cannot complete while an input is pending or blocked")
            if not self.state.objective_inputs() and not no_inputs_discovered:
                return reject("input analysis requires at least one recorded input or no_inputs_discovered=true")
        missing = [dimension for dimension in required if dimension not in coverage]
        if missing:
            return reject(f"{canonical} completion requires explicit coverage for: {', '.join(missing)}")
        unresolved = [
            dimension for dimension in required
            if coverage[dimension].status in {"failed", "cancelled"}
        ]
        if unresolved:
            return reject(
                f"{canonical} has unresolved failed/cancelled coverage: "
                f"{', '.join(unresolved)}; retry or record an explicit skip reason"
            )
        result["ready"] = True
        result["reason"] = "ready"
        return result

    def discovery_artifact_errors(self) -> dict[str, str]:
        """Current operational validity of historical whole-target phases.

        Repair is a file operation through existing permission gates. Historical
        phase/coverage markers are retained; their probes need not run again.
        """
        objective = self.state.objective
        if objective is None or objective.mode != "whole_target":
            return {}
        errors = {}
        for phase, name in (("recon", "recon"), ("enumeration", "web-enumeration"),
                            ("input_analysis", "web-input-analysis")):
            if phase not in self.state.completed_phases(objective):
                continue
            marker = self.state.phase_completions[f"{objective.id}:{phase}"]
            readiness = self.phase_completion_readiness(name, artifact_ref=marker.artifact_ref)
            if not readiness["artifact_valid"]:
                errors[phase] = readiness["reason"]
        return errors

    def next_phase_completion_readiness(self) -> dict[str, Any] | None:
        """Current required phase/repair, shared by controller and presentation."""
        objective = self.state.objective
        if objective is None or objective.mode != "whole_target":
            return None
        errors = self.discovery_artifact_errors()
        completed = self.state.completed_phases(objective)
        for phase, name in (("recon", "recon"), ("enumeration", "web-enumeration"),
                            ("input_analysis", "web-input-analysis")):
            if phase not in completed or phase in errors:
                marker = self.state.phase_completions.get(f"{objective.id}:{phase}")
                return self.phase_completion_readiness(name, artifact_ref=marker.artifact_ref if marker else None)
        return None

    def _record_phase_coverage(self, args: dict[str, Any]) -> str:
        objective = self.state.objective
        if objective is None or objective.mode != "whole_target":
            return "error: phase coverage requires an active whole-target objective"
        phase = arg_string(args, "phase")
        dimension = arg_string(args, "coverage_dimension")
        status = arg_string(args, "coverage_status")
        reason = arg_string(args, "coverage_reason") or None
        if phase not in PHASE_COVERAGE_DIMENSIONS:
            return self._coverage_argument_error(phase, dimension)
        if dimension not in PHASE_COVERAGE_DIMENSIONS[phase]:
            return self._coverage_argument_error(phase, dimension)
        if status not in PHASE_COVERAGE_STATUSES:
            return "error: coverage_status is invalid"
        try:
            changed = self.state.record_phase_coverage(
                cast(WorkflowPhase, phase),
                dimension,
                cast(PhaseCoverageStatus, status),
                objective_id=objective.id,
                target_origin=objective.target_origin or "",
                reason=reason,
            )
        except ValueError as err:
            return f"error: {err}"
        return json.dumps({
            "ok": True,
            "phase": phase,
            "dimension": dimension,
            "status": status,
            "changed": changed,
        })

    def _validate_current_objective_candidate(self, candidate_id: str) -> None:
        objective = self.state.objective
        candidate = self.state.candidates.get(candidate_id)
        if candidate is None:
            if (
                objective is not None
                and objective.mode == "candidate_validation"
                and candidate_id == objective.candidate_id
            ):
                raise ValueError(
                    "active candidate-validation objective references an unknown candidate"
                )
            raise ValueError("unknown candidate")
        if objective is not None and objective.mode == "whole_target":
            if (
                candidate.objective_id != objective.id
                or candidate_origin(candidate.target) != objective.target_origin
            ):
                raise ValueError("candidate does not belong to the active whole-target objective")
        elif objective is not None and objective.mode == "direct":
            if candidate.objective_id != objective.id:
                raise ValueError("candidate lacks provenance for the active direct objective")
            if objective.target_origin is not None and candidate_origin(candidate.target) != objective.target_origin:
                raise ValueError("candidate target does not match the active direct objective")
        elif objective is not None and objective.mode == "candidate_validation":
            if candidate_id != objective.candidate_id:
                raise ValueError(
                    "candidate does not match the active candidate-validation objective"
                )
            candidate = self.state.candidates.get(candidate_id)
            if candidate is None:
                raise ValueError(
                    "active candidate-validation objective references an unknown candidate"
                )
            candidate_target = candidate_origin(candidate.target)
            active_target = candidate_origin(self._active_target())
            if (
                objective.target_origin is not None
                and candidate_target != objective.target_origin
            ) or (active_target is not None and candidate_target != active_target):
                raise ValueError(
                    "candidate target does not match the active candidate-validation objective"
                )

    def _require_unique_validator(self, candidate_class: str) -> Skill:
        if self.skills is None:
            raise ValueError("skill registry is unavailable for validator resolution")
        route = resolve_validation_route(self.skills, candidate_class)
        if route.kind != "expert":
            reason = "ambiguous" if route.kind == "ambiguous" else "unavailable"
            raise ValueError(
                f"Candidate class {candidate_class} has {reason} validator mapping. "
                "Exactly one enabled validation skill is required."
            )
        validator = self.skills.get(route.skill_name or "")
        if validator is None:
            raise ValueError("resolved expert validator unavailable")
        return validator

    def _is_generic(self, candidate: Candidate) -> bool:
        latest = self.state.latest_result(candidate.id)
        route = resolve_validation_route(self.skills, candidate.candidate_class)
        return (route.kind == "generic"
                or bool(latest and latest.skill_name == GENERIC_VALIDATOR))

    def _require_generic(self, candidate_id: str, policy) -> Candidate:
        candidate = self.state.candidates.get(candidate_id)
        if candidate is None:
            raise ValueError(f"unknown candidate: {candidate_id}")
        reason = generic_admission(candidate, self.state, self.skills, self.target, policy)
        if reason:
            raise ValueError(reason)
        return candidate

    @staticmethod
    def _phase_for_skill(canonical: str, skill) -> WorkflowPhase | None:
        if canonical == "recon":
            return "recon"
        if canonical == "web-enumeration":
            return "enumeration"
        if canonical == "web-input-analysis":
            return "input_analysis"
        return None

    def _active_target(self) -> str:
        if self.target is None:
            return ""
        return self.target.base_url() or self.target.name()

    def _list(self, args: dict[str, Any], policy=None) -> str:
        if args.get("view", "all") not in {"all", "inputs", "sources", "endpoints", "provenance"}:
            return "error: unknown list view"
        objective = self.state.objective
        if (objective is not None and objective.mode == "whole_target"
                and candidate_origin(self._active_target()) != objective.target_origin):
            return "error: input listing requires the active objective target origin"
        try:
            if args.get('view') in {'sources', 'endpoints', 'provenance'}:
                from src.workflow.discovery.inventory import discovery_page
                return json.dumps(discovery_page(self.state, args), ensure_ascii=True, separators=(',', ':'))
            inputs = input_page(self.state, args)
        except (ValueError, TypeError) as err:
            return f"error: {err}"
        if args.get("view") == "inputs":
            return json.dumps(inputs, ensure_ascii=True, separators=(",", ":"))
        objective = self.state.objective
        candidate_id = arg_string(args, "candidate_id")
        status = arg_string(args, "status")
        candidate_class = arg_string(args, "candidate_class")

        if status and status not in CANDIDATE_STATUSES:
            return f"error: status must be one of: {', '.join(sorted(CANDIDATE_STATUSES))}"

        requested_limit = arg_number(args, "limit")
        limit = (
            DEFAULT_LIST_LIMIT
            if requested_limit is None
            else max(1, min(MAX_LIST_LIMIT, int(requested_limit)))
        )

        candidates = list(self.state.candidates.values())
        if policy is not None and policy.generic_validation.restricted():
            candidates = [c for c in candidates if policy.generic_validation.belongs(c)]
        objective = self.state.objective
        if objective is not None and objective.mode == "whole_target" and not candidate_id:
            candidates = list(self.state.objective_candidates())
        if candidate_id:
            candidate = self.state.candidates.get(candidate_id)
            if candidate is None:
                return f"error: unknown candidate: {candidate_id}"
            candidates = [candidate]
        else:
            if status:
                candidates = [item for item in candidates if item.status == status]
            if candidate_class:
                canonical_class = normalize_candidate_class(candidate_class)
                candidates = [
                    item
                    for item in candidates
                    if item.candidate_class == canonical_class
                ]
            candidates.sort(key=lambda item: _STATUS_PRIORITY.get(item.status, 3))

        total = len(candidates)
        selected = candidates[:limit]
        offset = args.get("observation_offset", 0)
        if type(offset) is not int or offset < 0:
            return "error: observation_offset must be a nonnegative integer"
        observations = self._observation_inventory(policy, selected)
        latest_results = [
            result
            for candidate in selected
            if (result := self.state.latest_result(candidate.id)) is not None
        ]
        completed_skills = self.completed_skills(policy)
        return json.dumps(
            {
                "ok": True,
                "total": total,
                "returned": len(selected),
                "truncated": total > len(selected),
                "observations": observations[offset:offset + limit],
                "observations_total": len(observations),
                "observations_scope": "Current owned inventory only; zero does not mean session HTTP traffic was lost. Unowned/foreign sources are excluded.",
                "validation_handoffs": [row for item in selected
                    if (row := self.validation_handoff(item.id, policy)) is not None],
                "next_observation_offset": offset + limit if offset + limit < len(observations) else None,
                "current_phase": self.state.current_phase,
                "objective": objective.to_dict() if objective else None,
                "requested_goals": [
                    goal.to_dict() for goal in objective.requested_goals
                ] if objective else [],
                "completed_phases": sorted(self.state.completed_phases()),
                "phase_coverage": {
                    key: {
                        dimension: record.to_dict()
                        for dimension, record in sorted(records.items())
                    }
                    for key, records in sorted(self.state.phase_coverage.items())
                    if objective is not None and key.rpartition(":")[0] == objective.id
                },
                **{key: value for key, value in inputs.items() if key != "ok"},
                "completed_skills_total": len(completed_skills),
                "completed_skills": sorted(completed_skills)[
                    :MAX_LIST_COMPLETED_SKILLS
                ],
                "completed_artifacts": {
                    name: self._brief(path)
                    for name, path in sorted(self.state.completed_artifacts.items())
                    if name in self.state.completed_skills
                },
                "candidates": [
                    self._candidate_summary(item, include_full_request_template=bool(candidate_id))
                    for item in selected
                ],
                "latest_results": [
                    self._result_summary(result) for result in latest_results
                ],
            },
            indent=2,
        )

    def _observation_inventory(self, policy, candidates):
        """Read-only metadata from the current owner; never publish foreign handles."""
        from src.workflow.assessment import digest, source_row
        if (policy is None or self.target is None or not policy.validation_context_matches(self.state, self.skills, self.target)
                or "http" in policy.revoked or "*" in policy.revoked):
            return []
        selected = {c.id: c for c in candidates}
        rows = []
        for item in policy.observations._items.values():
            candidate = selected.get(item.candidate_id)
            attempt = self.state.attempts.get(item.attempt_id)
            if (candidate is None or attempt is None or not self.state.objective
                    or item.attempt_id != policy.generic_validation.durable_attempt
                    or item.source_kind not in {"native-http", "imported-capture"}
                    or item.objective_id != self.state.objective.id
                    or not self.state.candidate_belongs_to_objective(candidate, self.state.objective)
                    or item.session_id != (policy.session_id or self.session_id)
                    or item.epoch != policy.engagement.http_permissions.epoch
                    or attempt.get("target_revision") != self.target.revision
                    or item.candidate_binding != candidate_binding(candidate)
                    or digest(source_row(item)) != item.retained_hash):
                continue
            try:
                policy.require_network(item.url)
                resolve_sources(policy, self.state, candidate, attempt, [item.id],
                                terminal=False, negative=False)
            except (ValueError, PermissionError):
                continue
            rows.append({"observation_id": item.id, "attempt_id": item.attempt_id,
                "method": item.method, "url": item.url, "request_hash": item.request_hash,
                "status": item.status, "elapsed_ms": item.elapsed_ms, "complete": item.complete,
                "execution_status": item.execution_status, "producer": item.producer,
                "source_kind": item.source_kind,
                "truncated": item.truncated, "retained_body_bytes": len(item.body),
                "read_available": attempt.get("status") in {"active", "completed"}
                                  and "read_http_observation" not in policy.revoked})
        return rows

    @staticmethod
    def _candidate_summary(
        candidate: Candidate, *, include_full_request_template: bool = False,
    ) -> dict[str, Any]:
        request_template = candidate.request_template or ""
        template_limit = 4000 if include_full_request_template else 1000
        return {
            "id": candidate.id,
            "candidate_class": candidate.candidate_class,
            "target": WorkflowTool._brief(candidate.target),
            "method": candidate.method,
            "endpoint": WorkflowTool._brief(candidate.endpoint),
            "parameter": WorkflowTool._brief(candidate.parameter),
            "location": WorkflowTool._brief(candidate.location),
            "test_case": WorkflowTool._brief(candidate.test_case),
            "priority": candidate.priority,
            "status": candidate.status,
            "signals": [WorkflowTool._brief(item) for item in candidate.signals[:2]],
            "baseline_request_ref": WorkflowTool._brief(
                candidate.baseline_request_ref
            ),
            "auth_context_ref": WorkflowTool._brief(candidate.auth_context_ref),
            "content_type": candidate.content_type,
            "request_template": request_template[:template_limit] or None,
            "request_template_truncated": len(request_template) > template_limit,
            "source_skill": candidate.source_skill,
            "source_ref": WorkflowTool._brief(candidate.source_ref),
            "objective_id": candidate.objective_id,
        }

    _input_summary = staticmethod(input_summary)

    def _result_summary(self, result: ValidationResult) -> dict[str, Any]:
        from src.workflow.assessment import assessment_provenance
        from src.permission.runtime.execution import current_policy
        candidate = self.state.candidates[result.candidate_id]
        return {
            "candidate_id": result.candidate_id,
            "skill_name": result.skill_name,
            "outcome": result.outcome,
            "assessment_provenance": assessment_provenance(self.state, candidate, result, current_policy()),
            "result_id": result.result_id,
            "attempt_id": result.attempt_id,
            "evidence_refs": [
                WorkflowTool._brief(item) for item in result.evidence_refs[:3]
            ],
            "techniques": [
                WorkflowTool._brief(item) for item in result.techniques[:2]
            ],
            "repeatable": result.repeatable,
            "mutation_performed": result.mutation_performed,
            "cleanup_status": WorkflowTool._brief(result.cleanup_status),
            "cleanup_state": result.cleanup_state,
            "deferred_reason": WorkflowTool._brief(result.deferred_reason),
        }

    @staticmethod
    def _brief(value: str | None) -> str | None:
        if value is None:
            return None
        return value[:LIST_TEXT_LIMIT]
