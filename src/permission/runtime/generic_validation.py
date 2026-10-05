"""Candidate-bound restrictions on existing native executors, without grants."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from dataclasses import dataclass
from urllib.parse import urlsplit
import re

import httpx

from src.workflow.review import digest
from src.workflow.validation_route import (
    GENERIC_VALIDATOR, GENERIC_TOOLS, generic_admission, resolve_validation_route,
)
from src.workflow.probe import ProbeProposal


def request_signature(request):
    return digest([request.method, str(request.url), request.content.hex(),
                   sorted(request.headers.multi_items())])


@dataclass(frozen=True)
class BoundProbe:
    proposal: ProbeProposal
    context: str
    requests: tuple[str, ...]


def candidate_context(candidate):
    raw = candidate.to_dict()
    raw.pop("status")
    return raw


class GenericValidationBoundary:
    def __init__(self, policy, state, skills, target):
        self.policy, self.state, self.skills, self.target = policy, state, skills, target
        self.in_flight: dict[str, int] = {}
        self.retest_objectives: set[str] = set()
        self.started_candidate: str | None = None
        self.started_objective: str | None = None
        self.pending_blockers: dict[str, tuple] = {}
        # Controller-owned verified action facts. Never serialized, model-set,
        # inferred from capture/method, or reconstructed from session text.
        self.contexts: dict[str, BoundProbe] = {}
        self.attempt: BoundProbe | None = None
        self.http_tool = None
        # Bookkeeping status (including restored/model-supplied status) cannot
        # select an executor. Only a successful structured expert start may
        # temporarily select independent expert work in this objective.
        self.expert_attempt: tuple[str, str] | None = None

    def matches(self, state, skills, target):
        return self.state is state and self.skills is skills and self.target is target

    def belongs(self, candidate):
        objective = self.state.objective
        return bool(objective and (
            candidate.id == objective.candidate_id if objective.mode == "candidate_validation"
            else candidate.objective_id == objective.id
        ))

    def is_generic(self, candidate):
        result = self.state.latest_result(candidate.id)
        route = resolve_validation_route(self.skills, candidate.candidate_class)
        return (candidate.id == self.started_candidate or route.kind == "generic"
                or (route.kind != "expert"
                    and result is None and candidate.objective_id is not None)
                or bool(result and result.skill_name == GENERIC_VALIDATOR))

    def candidates(self):
        return [c for c in self.state.candidates.values() if self.belongs(c) and self.is_generic(c)]

    def restricted(self):
        # In-flight restriction survives even a controller objective change.
        if self.in_flight:
            return True
        generic = self.candidates()
        if self.started_candidate is not None:
            started = self.state.candidates.get(self.started_candidate)
            if started is not None and self.belongs(started) and started.status == "validating":
                return True
        if any(c.status == "validating" for c in generic):
            return True
        # A structured expert start can select other whole-target work, but an
        # active skill's permissive tool list cannot lift a generic restriction.
        expert_active = False
        if self.expert_attempt is not None:
            cid, binding = self.expert_attempt
            candidate = self.state.candidates.get(cid)
            expert_active = bool(candidate and self.belongs(candidate)
                and candidate.status == "validating" and not self.is_generic(candidate)
                and resolve_validation_route(self.skills, candidate.candidate_class).kind == "expert"
                and self.expert_binding(candidate) == binding)
        return bool(generic and not expert_active)

    def expert_binding(self, candidate):
        latest = self.state.latest_result(candidate.id)
        return digest([id(candidate), id(self.state.objective), candidate_context(candidate),
                       self.state.objective.to_dict(), self.target.revision,
                       resolve_validation_route(self.skills, candidate.candidate_class).__dict__,
                       latest.to_dict() if latest else None,
                       sum(r.candidate_id == candidate.id for r in self.state.validation_results)])

    def select_expert(self, candidate):
        self.idle()
        self.expert_attempt = (candidate.id, self.expert_binding(candidate))

    def require(self, candidate_id):
        candidate = self.state.candidates.get(candidate_id)
        if candidate is None:
            raise ValueError(f"unknown candidate: {candidate_id}")
        reason = generic_admission(candidate, self.state, self.skills, self.target, self.policy)
        if reason:
            raise ValueError(reason)
        return candidate

    def idle(self):
        if self.in_flight:
            raise ValueError("generic probe in-flight; cannot switch or finish validation")

    def bind_probe_context(self, tool, candidate_id, probe, *, verified_input_only: bool):
        """Trusted controller integration for verified lab endpoint/action facts.

        The caller must have verified the endpoint and *these exact values* do
        not mutate persistent state, change identity, execute commands or cause
        outbound callbacks. A capture, HTTP grant, LLM claim or permission
        answer alone cannot establish this fact. This method narrows native
        execution; it creates no authority, receipts, approval or verifier.
        It is not exposed through workflow/http/ask_user or session loaders.
        """
        self.idle()
        candidate = self.require(candidate_id)
        if verified_input_only is not True:
            raise ValueError("generic endpoint/action effects context unavailable")
        bound = self.compile_probe(tool, candidate, ProbeProposal.parse(probe))
        if (self.attempt is not None and candidate.status == "validating"
                and self.started_objective == self.state.objective.id
                and self.attempt != bound):
            raise ValueError("generic active proposal/context cannot be replaced; finish or explicitly retest")
        self.contexts[candidate_id] = bound
        self.http_tool = tool

    def compile_probe(self, tool, candidate, proposal):
        expected = (candidate.id, self.state.objective.id, self.state.objective.target_origin,
                    candidate.endpoint, candidate.method, candidate.location, candidate.parameter,
                    candidate.baseline_request_ref, candidate.auth_context_ref)
        actual = (proposal.candidate_id, proposal.objective_id, proposal.target_origin,
                  proposal.endpoint, proposal.method, proposal.location, proposal.parameter,
                  proposal.baseline_request_ref, proposal.auth_context_ref)
        if actual != expected:
            raise ValueError("generic proposal candidate/objective/Target/endpoint/method/input/baseline/auth mismatch")
        if candidate.method not in {"GET", "HEAD", "OPTIONS", "POST"}:
            raise ValueError("generic method/impact capability unavailable")
        if candidate.location not in {"query", "header", "form", "json"}:
            raise ValueError("generic input encoding/capability unavailable")
        # Defense in depth even for a trusted context: identity and transport
        # fields cannot be varied through generic comparison requests.
        sensitive = {"authorization", "cookie", "host", "proxy-authorization", "content-length",
                     "transfer-encoding", "connection", "content-type", "content-encoding",
                     "password", "passwd", "role", "roles", "user", "username", "user_id",
                     "userid", "account", "account_id", "token", "api_key", "apikey", "session"}
        sensitive |= {"admin", "isadmin", "is_admin", "privilege", "privileges", "permissions",
                      "csrf", "csrf_token", "xsrf", "otp", "secret", "key", "identity", "principal"}
        tokens = re.findall(r"[a-z_]+", (candidate.parameter or "").lower())
        path_tokens = re.findall(r"[a-z_]+", (proposal.input_path or "").lower())
        if any(token in sensitive for token in (*tokens, *path_tokens)):
            raise ValueError("generic sensitive identity/transport variation unavailable")
        for value in proposal.values:
            # URL data never authorizes a destination. Reserved inert markers
            # are supported; callback/SSRF destinations require expert context.
            urls = re.findall(r"(?:https?://|//)[^\s'\"<>]+", value, re.I)
            if any(urlsplit(url if not url.startswith("//") else "https:" + url).hostname != "example.com"
                   for url in urls):
                raise ValueError("generic outbound/callback URL variation unavailable")
        baseline = self.baseline(tool, candidate)
        content_type = baseline.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if (baseline.headers.get("content-encoding", "identity").lower() != "identity"
                or baseline.content and content_type not in {"application/json", "application/x-www-form-urlencoded"}
                or candidate.location == "form" and content_type != "application/x-www-form-urlencoded"
                or candidate.location == "json" and content_type != "application/json"):
            raise ValueError("generic body encoding/content type unavailable")
        if candidate.method != "POST" and baseline.content:
            raise ValueError("generic retrieval body unavailable")
        from src.tools.http.request_builder import build_captured_request
        row = SimpleNamespace(method=baseline.method, url=str(baseline.url),
            request_headers=[SimpleNamespace(name=k, value=v) for k, v in baseline.headers.multi_items()],
            request_body=baseline.content.decode("utf-8") if baseline.content else None)
        requests = [request_signature(baseline)]
        for value in proposal.values:
            if candidate.location == "header":
                if proposal.occurrence or proposal.input_path:
                    raise ValueError("generic header selectors unavailable")
                if any(char in value for char in ("\r", "\n", "\0")):
                    raise ValueError("generic header framing variation unavailable")
                headers = dict(baseline.headers)
                headers[candidate.parameter.lower()] = value
                variant = httpx.Request(baseline.method, baseline.url, headers=headers, content=baseline.content)
            else:
                variant, _ = build_captured_request(row, candidate, value,
                    occurrence=proposal.occurrence, input_path=proposal.input_path)
            requests.append(request_signature(variant))
        context = digest([id(candidate), id(self.state.objective), candidate_context(candidate), self.state.objective.to_dict(),
                          self.target.revision, request_signature(baseline)])
        return BoundProbe(proposal, context, tuple(requests))

    def admit_probe(self, tool, candidate_id, raw=None):
        candidate = self.require(candidate_id)
        if tool is None:
            raise ValueError("generic context-needed: native HTTP baseline/action context unavailable")
        context = self.contexts.get(candidate_id)
        if raw is None:
            if context is None:
                raise ValueError("generic context-needed: concrete probe and verified endpoint/action context required")
            proposal = context.proposal
        else:
            proposal = ProbeProposal.parse(raw)
        bound = self.compile_probe(tool, candidate, proposal)
        if context is None or bound != context:
            raise ValueError("generic context-needed: proposal/baseline/auth lacks matching verified endpoint/action context")
        return bound

    def admission_reason(self, tool, candidate_id):
        try:
            self.admit_probe(tool, candidate_id)
        except (TypeError, ValueError, UnicodeError) as exc:
            return str(exc)
        return None

    def snapshot(self, candidate_id):
        candidate = self.require(candidate_id)
        return digest([
            candidate.to_dict(), self.state.objective.to_dict(), self.target.revision,
            self.policy.stamp(),
            [(s.name, s.stage, s.candidate_classes, s.disable_model_invocation,
              self.skills.is_disabled(s.name)) for s in self.skills.list()],
            self.state.latest_result(candidate_id).to_dict()
            if self.state.latest_result(candidate_id) else None,
        ])

    def unchanged(self, candidate_id, snapshot):
        if self.snapshot(candidate_id) != snapshot:
            raise ValueError("generic candidate/registry/objective/Target changed during execution")

    def proof_path(self, candidate):
        # Origin-derived target segment; no operator/model supplied pathname.
        from src.findings.store import slugify
        from src.workflow.state import normalize_target_origin
        segment = slugify(normalize_target_origin(candidate.target) or "")
        return self.policy.root / "artifacts/generic-validation" / segment / candidate.id / "proof.md"

    def validate_tool(self, tool, args):
        if not self.restricted():
            return
        name = tool.name()
        if name not in GENERIC_TOOLS:
            raise ValueError(f"generic capability unavailable: {name}")
        if name == "http":
            action, request = tool.prepare(args)
            self.validate_http(tool, args, action, request)
        elif name == "file_write":
            candidates = [c for c in self.candidates() if c.status == "validating"]
            if len(candidates) != 1:
                raise ValueError("generic proof write requires one active candidate")
            candidate = self.require(candidates[0].id)
            expected = self.proof_path(candidate)
            path = Path(args.get("path", "")).expanduser().absolute()
            if path != expected or path.resolve() != expected:
                raise ValueError("generic write restricted to candidate proof.md; symlinks unavailable")
        elif name == "workflow":
            action = args.get("action")
            if (action == "complete_skill" and args.get("skill_name") != GENERIC_VALIDATOR
                    and not any(c.status == "validating" for c in self.candidates())):
                self.idle()
                return  # Existing expert completion/phase gates remain authoritative.
            if action not in {"list", "start_validation", "record_evidence", "record_result",
                              "sync_coverage", "record_candidate", "record_input", "set_input_disposition",
                              "link_input_candidate"}:
                raise ValueError("generic workflow action unavailable")
            cid = args.get("candidate_id")
            if cid and cid in self.state.candidates and action != "start_validation":
                self.require(cid)
            if action in {"start_validation", "record_result"}:
                self.idle()
        elif name == "ask_user":
            # Input collection cannot create a second execution approval path.
            from src.tools.common.ask import is_authorization_scope_question
            import re
            for question in args.get("questions", []):
                text = question.get("question", "") if isinstance(question, dict) else ""
                if (is_authorization_scope_question(text, question.get("header") if isinstance(question, dict) else None)
                        or re.search(r"\b(?:permission|approve|authorize|continue validation|proceed with validation)\b", text, re.I)):
                    raise ValueError("generic execution permission uses runtime gates; no duplicate ask_user approval")
        elif name == "confirm_finding":
            self.require(args.get("candidate_id"))

    def baseline(self, tool, candidate):
        if candidate.baseline_request_ref:
            from src.tools.http.request_builder import _raw_capture, origin_headers
            store = tool.capture_store
            row = ((store.get_request(candidate.baseline_request_ref)
                    or store.get_burp_task(candidate.baseline_request_ref)) if store else None)
            if row is None:
                raise ValueError("generic captured baseline unavailable")
            method, url, headers, body = _raw_capture(row)
            headers = origin_headers(headers)
            if len({key.lower() for key, _ in headers}) != len(headers):
                raise ValueError("generic captured baseline has duplicate headers; expert context required")
            headers = dict(headers)
            if any(k.lower() in {"cookie", "authorization"} for k in headers):
                if not candidate.auth_context_ref or row.auth_context_ref != candidate.auth_context_ref:
                    raise ValueError("generic baseline credentials lack identity binding")
            _, request = tool.prepare({"url": url, "method": method, "headers": headers,
                                       "body": body.decode("utf-8"),
                                       "auth_context_ref": candidate.auth_context_ref})
            if ("authorization" in request.headers and tool.context_store.authorization_for(
                    request, candidate.auth_context_ref) != request.headers["authorization"]
                    or "cookie" in request.headers and tool.context_store.cookie_for(
                    request, candidate.auth_context_ref) != request.headers["cookie"]):
                raise ValueError("generic baseline runtime credentials missing/different; recapture required")
        else:
            _, request = tool.prepare({"url": candidate.endpoint, "method": candidate.method,
                                       "auth_context_ref": candidate.auth_context_ref})
        from src.target.origin import HTTPOrigin
        from urllib.parse import urlsplit
        if candidate.auth_context_ref and not any(k in request.headers for k in ("cookie", "authorization")):
            raise ValueError("generic runtime identity context unavailable; supply credentials/recapture")
        if (request.method != candidate.method
                or HTTPOrigin.from_url(str(request.url)) != HTTPOrigin.from_url(candidate.target)
                or urlsplit(str(request.url)).path != urlsplit(candidate.endpoint).path):
            raise ValueError("generic baseline differs from concrete candidate context")
        return request

    def validate_http(self, tool, args, action, request):
        if self.http_tool is not tool:
            raise ValueError("generic native HTTP executor context differs from admitted proposal")
        candidates = [c for c in self.candidates() if c.status == "validating"]
        if len(candidates) != 1:
            raise ValueError("generic HTTP requires one started candidate; deferred work must stop")
        candidate = self.require(candidates[0].id)
        if self.state.latest_result(candidate.id) is not None and (
                self.started_candidate != candidate.id
                or self.started_objective != self.state.objective.id):
            raise ValueError("generic recorded result cannot reopen probes through saved/requeued status")
        if (args.get("phase") != "validation" or args.get("profile", "native") != "native"
                or args.get("max_redirects", 0) != 0 or action.redirect_limit != 0
                or args.get("candidate_id", candidate.id) != candidate.id
                or args.get("auth_context_ref", candidate.auth_context_ref) != candidate.auth_context_ref):
            raise ValueError("generic HTTP requires native validation, zero redirects and candidate identity")
        if (self.attempt is None or self.started_candidate != candidate.id
                or self.started_objective != self.state.objective.id):
            raise ValueError("generic execution proposal unavailable; saved status grants no probe rights")
        proposal = self.attempt.proposal
        if args.get("candidate_id") and (
                args.get("mutation_value") not in proposal.values
                or args.get("occurrence", 0) != proposal.occurrence
                or args.get("input_path") != proposal.input_path
                or "old_value" in args):
            raise ValueError("generic replay selector/value differs from concrete proposal")
        bound = self.admit_probe(tool, candidate.id, self.attempt.proposal.to_dict())
        if bound != self.attempt or request_signature(request) not in bound.requests:
            raise ValueError("generic request differs from baseline/auth or named bounded input")
        return candidate.id

    def begin_http(self, tool, args, action, request):
        if not self.restricted():
            return None
        cid = self.validate_http(tool, args, action, request)
        snapshot = self.snapshot(cid)
        assert self.attempt is not None
        self.in_flight[cid] = self.in_flight.get(cid, 0) + 1
        return cid, snapshot, self.probe_identity()

    def probe_identity(self):
        if self.attempt is None:
            raise ValueError("generic execution proposal unavailable")
        return digest([self.attempt.proposal.to_dict(), self.attempt.context, self.attempt.requests])

    def recheck_http(self, tool, args, action, probe):
        self.unchanged(*probe[:2])
        if self.attempt is None or self.probe_identity() != probe[2]:
            raise ValueError("generic proposal changed during execution")
        # The socket request is DNS-pinned; compare the original prepared
        # logical action to the current baseline/identity, not the numeric URL.
        request = httpx.Request(action.method, action.url, headers=action.headers, content=action.body)
        self.validate_http(tool, args, action, request)

    def end_http(self, probe):
        if probe:
            cid = probe[0]
            count = self.in_flight[cid] - 1
            if count:
                self.in_flight[cid] = count
            else:
                del self.in_flight[cid]
                pending = self.pending_blockers.pop(cid, None)
                if pending is not None:
                    self.record_blocker(*pending)

    def record_blocker(self, probe, failure):
        """Retain a native denial/exhaustion, so a new invocation cannot retry it.

        This is synchronous bookkeeping after the probe has finished, never a
        vulnerability conclusion or another execution permission request.
        """
        if probe is None:
            return
        cid, snapshot = probe[:2]
        if self.in_flight.get(cid):
            self.pending_blockers[cid] = (probe, failure)
            return
        try:
            self.idle()
            self.unchanged(cid, snapshot)
        except ValueError:
            return  # Changed scope/state belongs to the controller, not this call.
        from src.workflow.state import ValidationResult
        refs = [e.id for e in self.state.evidence.values() if e.candidate_id == cid]
        self.state.add_validation_result(ValidationResult(
            candidate_id=cid, skill_name=GENERIC_VALIDATOR, outcome="blocked",
            evidence_refs=refs, deferred_reason=str(failure),
        ))
        self.started_candidate = self.started_objective = None
        self.attempt = None
