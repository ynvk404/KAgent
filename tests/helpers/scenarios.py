"""M1 offline scenarios: scripted transport, production runtime and stores.

No CLI startup, workflow seeding, synthetic observations or result adoption.
The only controller-only integration is the explicitly named Generic binder.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Generator
from dataclasses import dataclass
import json
from pathlib import Path
from time import perf_counter
from typing import Any
from urllib.parse import urlencode

import httpx

from src.permission.network.grants import HTTPLimits
from src.skills.artifacts import completion_artifact_path
from src.tools.skills.payloads import ReadPayloadsTool
from src.tools.workflow.finding import ConfirmFindingTool
from src.findings.store import Store as FindingStore
from src.workflow.validation.probe import ProbeProposal
from src.workflow.validation.route import GENERIC_VALIDATOR
from tests.helpers.agent_fakes import FakeSignal, ScriptedModel
from tests.helpers.burp_selection import make_runtime

REAL_HTTP_CLIENT = httpx.AsyncClient
Script = Generator[tuple[str, Any], str, None]
SSTI_FINGERPRINTS = ("${7*7}", "{{7*7}}", "<%= 7*7 %>", "*{7*7}", "{{7*'7'}}")
SQLI_VALUES = ("Gifts", "Gifts'", "Gifts' AND 1=1--", "Gifts' AND 1=2--",
               "Gifts' AND 1=1--", "Gifts' AND 1=2--")


@dataclass(frozen=True)
class ExpectedOutcomes:
    outcome: str
    findings: int
    complete: bool
    goal_status: str | None
    route: str = "expert"


@dataclass(frozen=True)
class ScenarioDefinition:
    id: str
    mode: str
    origin: str
    endpoint: str
    method: str
    candidate_class: str
    parameter: str
    input_value: str
    application: FixtureApplication
    script: Callable[[Any, ScenarioDefinition], Script]
    expected: ExpectedOutcomes
    user_input: str
    max_steps: int = 80
    max_calls: int = 100
    timeout: float = 30
    controller_bound: bool = False
    ambiguous: bool = False
    verify: Callable[[ScenarioRun], Awaitable[None]] | None = None
    checkpoint: bool = True
    yolo: bool = False
    http_values: tuple[str, ...] | None = None
    expected_stop: tuple[int, str] | None = None


@dataclass(frozen=True)
class FixtureApplication:
    """Pure fixture behavior, with no network, evaluation, writes or callbacks.

    SSTI is literal reflection. SQLi models a controlled product filter,
    including syntax sensitivity; it is not a real database implementation.
    Generic is a read-only comparison with a stable response.
    """
    kind: str
    origin: str
    endpoint: str
    method: str
    parameter: str

    def request(self, value: str, *, phase: str = "validation") -> dict[str, Any]:
        encoded = urlencode({self.parameter: value})
        if self.method == "GET":
            return {"url": self.endpoint.split("?", 1)[0] + "?" + encoded,
                    "method": "GET", "phase": phase}
        return {"url": self.endpoint, "method": self.method, "phase": phase,
                "body": encoded, "headers": {"Content-Type": "application/x-www-form-urlencoded"}}

    def render(self, value: str) -> tuple[int, bytes, str]:
        if self.kind == "sqli":
            if "1=1" in value:
                return 200, b"fixture products", "text/plain"
            if "1=2" in value:
                return 200, b"empty", "text/plain"
            if value.endswith("'"):
                return 400, b"fixture syntax error", "text/plain"
            return 200, b"fixture products", "text/plain"
        if self.kind == "ssti":
            return 200, ("Literal value: " + value).encode(), "text/plain"
        return 200, b"stable comparison response", "text/plain"

    def verify_input_only(self, probe: ProbeProposal) -> None:
        """Trusted fixture controller checks exact values against pure behavior.

        This fact comes from this fixture's implementation, never model text,
        traffic, permissions or capture. It grants no HTTP execution rights.
        """
        assert self.kind == "generic" and self.method == "GET"
        assert (probe.target_origin, probe.endpoint, probe.method, probe.parameter,
                probe.location) == (self.origin, self.endpoint, "GET", self.parameter, "query")
        assert probe.values == ("variant",)
        assert self.render("variant") == self.render("baseline")

    def landing(self) -> bytes:
        return (f'<html><title>M1 fixture</title><a href="/openapi.json">API</a>'
                f'<form method="{self.method}" action="{self.endpoint}">'
                f'<input name="{self.parameter}" value="Gifts"></form></html>').encode()


class FakeTransport:
    """MockTransport application with an independent, exact request ledger."""
    def __init__(self, definition: ScenarioDefinition):
        self.application = app = definition.application
        self.expected: list[tuple[dict[str, Any], tuple[int, bytes, str]]] = []
        self.sent: list[dict[str, Any]] = []
        self.errors: list[str] = []
        if definition.mode == "whole_target":
            for path in ("/", "/", "/robots.txt", "/sitemap.xml", "/openapi.json"):
                body = app.landing() if path == "/" else (
                    json.dumps({"paths": {app.endpoint: {app.method.lower(): {
                        "parameter": app.parameter}}}}).encode() if path == "/openapi.json" else b"not found")
                status = 404 if path in {"/robots.txt", "/sitemap.xml"} else 200
                media = "text/html" if path == "/" else "application/json" if path == "/openapi.json" else "text/plain"
                self.expected.append(({"url": path, "method": "GET"}, (status, body, media)))
            # One harmless input-analysis marker, not a validator payload set.
            self.expected.append((app.request("Gifts'", phase="recon"), app.render("Gifts'")))
        if definition.http_values is not None:
            values = definition.http_values
        elif definition.ambiguous or (app.kind == "generic" and not definition.controller_bound):
            values: tuple[str, ...] = ()
        elif app.kind == "sqli":
            values = (definition.input_value, *SQLI_VALUES[1:])
        elif app.kind == "ssti":
            values = (definition.input_value, *SSTI_FINGERPRINTS)
        else:
            values = ("baseline", "variant")
        for value in values:
            self.expected.append((app.request(value), app.render(value)))

    def handle(self, request: httpx.Request) -> httpx.Response:
        row = {"method": request.method, "url": str(request.url), "body": request.content.decode()}
        self.sent.append(row)
        try:
            assert len(self.sent) <= len(self.expected), "unexpected extra HTTP"
            args, response = self.expected[len(self.sent) - 1]
            expected = httpx.Request(args["method"], self.application.origin + args["url"],
                                     content=args.get("body", ""), headers=args.get("headers"))
            assert (request.method, request.url, request.content) == (expected.method, expected.url, expected.content), "unexpected HTTP request"
            if "headers" in args:
                assert request.headers["content-type"] == args["headers"]["Content-Type"]
            assert "authorization" not in request.headers and "cookie" not in request.headers
        except AssertionError as error:
            self.errors.append(str(error))
            raise
        status, content, media = response
        return httpx.Response(status, content=content, headers={"Content-Type": media, "Server": "m1-fixture"}, request=request)


def receipt(output: str) -> dict[str, Any]:
    value = json.loads(output)
    assert value.get("ok") is True, output
    return value


def http_observation(output: str) -> dict[str, Any]:
    line = next(line for line in output.splitlines() if line.startswith("Runtime HTTP evidence ("))
    value, _ = json.JSONDecoder().raw_decode(line.split(": ", 1)[1])
    assert value["complete"] and not value["truncated"], output
    return value


def record_candidate(definition: ScenarioDefinition, *, input_id: str | None = None) -> dict[str, Any]:
    args = {"action": "record_candidate", "candidate_class": definition.candidate_class,
            "endpoint": definition.endpoint, "method": definition.method, "parameter": definition.parameter,
            "location": "query" if definition.method == "GET" else "body",
            "signals": ["Concrete fixture input supplied by the operator."]}
    if definition.method != "GET":
        args["content_type"] = "application/x-www-form-urlencoded"
    if input_id:
        args.update(input_id=input_id, source_skill="web-input-analysis",
                    signals=["Baseline products; one syntax marker changed the response shape; not confirmation."])
    return args


def dedicated_validation(runtime, definition, cid: str, *, skill_loaded=False) -> Script:
    app = definition.application
    skill = "sql-injection" if app.kind == "sqli" else "ssti"
    if not skill_loaded:
        loaded = yield "load_skill", {"name": skill}
        assert skill in loaded
    corpus = yield "read_payloads", {"skill": skill, "file": "payloads.txt"}
    assert ("1=1" if skill == "sql-injection" else "{{7*7}}") in corpus
    started = receipt((yield "workflow", {"action": "start_validation", "candidate_id": cid}))
    aid = started["validation_context"]["attempt_id"]
    assert started["validator_resolution"] == "unique"
    values = (definition.input_value, *(SQLI_VALUES[1:] if app.kind == "sqli" else SSTI_FINGERPRINTS))
    observations = []
    for value in values:
        output = yield "http", app.request(value)
        envelope = http_observation(output)
        observations.append(envelope["observation_id"])
        status, body, _ = app.render(value)
        assert body.decode() in output and str(status) in output
    if definition.expected.outcome == "deferred":
        closed = receipt((yield "workflow", {"action": "record_result", "candidate_id": cid,
            "skill_name": skill, "outcome": "deferred", "attempt_id": aid,
            "mutation_performed": False,  # FakeApplication.render is a pure comparison response.
            "deferred_reason": "Bounded observations collected; comparison review intentionally postponed."}))
        assert closed["eligible_for_confirm_finding"] is False
        return
    ids = observations
    impact = ("Controlled predicates repeatedly change the fixture product response." if app.kind == "sqli"
              else "Baseline and all five arithmetic fingerprints are reflected literally; SSTI could not be confirmed.")
    assessment = {"hypothesis": "Input reaches a SQL filter" if app.kind == "sqli" else "Reflected input may be template evaluated",
        "criteria": "Baseline, syntax signal and two complete TRUE/FALSE pairs" if app.kind == "sqli"
                    else "Baseline and five Phase 1 fingerprints; evaluation must differ from literal reflection",
        "limitations": "Offline fixture only; no live target, extraction, introspection or impact validation. No general absence claim.",
        "completed_attempt": True, "observed_impact": impact, "severity": "medium" if app.kind == "sqli" else "info"}
    extra: dict[str, Any] = {}
    if app.kind == "sqli":
        pairs = []
        for repetition in (1, 2):
            sides = {}
            for side, value in (("true", SQLI_VALUES[2]), ("false", SQLI_VALUES[3])):
                status, body, _ = app.render(value)
                sides[side] = {"status": status, "size": len(body), "marker": body.decode()}
            pairs.append({"repetition": repetition, **sides})
        extra = {"repeatable": True, "confirmation": {"kind": "boolean-differential",
                 "request_template": definition.origin + definition.endpoint + "?" + definition.parameter + "=Gifts' AND {predicate}--",
                 "true_predicate": "1=1", "false_predicate": "1=2", "pairs": pairs}}
    result = yield from publish_proof(runtime, cid, aid, ids, skill, definition.expected.outcome,
                                      assessment, ["SQLI-2", "boolean-based"] if app.kind == "sqli" else ["arithmetic-fingerprint"], extra=extra)
    if definition.expected.outcome == "confirmed":
        assert result["eligible_for_confirm_finding"] and not runtime.workflow.finding_is_persisted(cid)
        finding = yield "confirm_finding", finding_arguments(definition, cid, impact)
        assert 'written to ' in finding
    else:
        assert result["eligible_for_confirm_finding"] is False


def finding_arguments(definition, cid, impact):
    return {"candidate_id": cid, "title": "Offline controlled product filter",
            "severity": "medium", "url": definition.origin + definition.endpoint, "method": definition.method,
            "parameter": definition.parameter, "payload": SQLI_VALUES[2], "response_excerpt": "fixture products",
            "observed_impact": impact, "potential_impact": "No additional impact assessed.",
            "curl": "curl '" + definition.origin + definition.application.request(SQLI_VALUES[2])["url"] + "'",
            "remediation": "Use parameterized queries for this input; application implementation was not inspected.",
            "vuln_class": "sqli"}


def publish_proof(runtime, cid, aid, ids, skill, outcome, assessment, techniques, *, path=None, extra=None) -> Generator[tuple[str, dict[str, Any]], str, dict[str, Any]]:
    # Text and IDs come from native captured observations, not fabricated sources.
    path = path or f"artifacts/scenario-proof/{cid}.md"
    proof = f"# Candidate proof\n- candidate_id: {cid}\n- observation_ids: {', '.join(ids)}\n"
    for oid in ids:
        source = runtime.policy.observations._items[oid]
        proof += f"{oid}: {source.method} {source.url}; HTTP {source.status}; {source.body.decode()}\n"
    proof += assessment["observed_impact"] + "\n" + assessment["limitations"] + "\n"
    written = yield "file_write", {"path": str(runtime.policy.root / path), "content": proof}
    assert "error" not in written.lower(), written
    evidence = receipt((yield "workflow", {"action": "record_evidence", "candidate_id": cid,
                                          "evidence_path": path, "observation_ids": ids}))
    assert evidence["evidence_kind"] == "derived" and evidence["primary_parents"] == ids
    return receipt((yield "workflow", {"action": "record_result", "candidate_id": cid,
        "attempt_id": aid, "skill_name": skill, "outcome": outcome,
        "mutation_performed": False,  # These controlled mock applications have no persistent effects.
        "evidence_refs": [evidence["evidence"]["id"]], "observation_ids": ids,
        "assessment": assessment, "techniques": techniques, **(extra or {})}))


def direct_script(runtime, definition) -> Script:
    skill = "sql-injection" if definition.application.kind == "sqli" else "ssti"
    loaded = yield "load_skill", {"name": skill}
    assert skill in loaded
    created = receipt((yield "workflow", record_candidate(definition)))
    assert created["candidate"]["status"] == "queued" and not runtime.workflow.attempts
    assert not runtime.workflow.phase_completions
    yield from dedicated_validation(runtime, definition, created["candidate"]["id"], skill_loaded=True)


def phase_artifact(runtime, name, content) -> Script:
    skill = runtime.skills.get(name)
    assert skill is not None and skill.completion_artifact
    path = completion_artifact_path(skill.completion_artifact, runtime.target.base_url())
    written = yield "file_write", {"path": str(runtime.policy.root / path), "content": content}
    assert "error" not in written.lower(), written
    completed = receipt((yield "workflow", {"action": "complete_skill", "skill_name": name, "artifact_ref": path}))
    assert completed["artifact_ref"] == path


def disposition(phase, dimension, status, reason) -> Script:
    receipt((yield "workflow", {"action": "record_phase_coverage", "phase": phase,
        "coverage_dimension": dimension, "coverage_status": status, "coverage_reason": reason}))


def whole_target_script(runtime, definition) -> Script:
    app = definition.application
    assert not runtime.workflow.phase_completions and not runtime.workflow.candidates
    yield "load_skill", {"name": "recon"}
    recon = http_observation((yield "http", {"url": "/", "method": "GET", "phase": "recon"}))
    yield from disposition("recon", "service_discovery", "not_applicable",
                           "Single declared HTTP origin; its effective port responded. No broader service scope.")
    yield from phase_artifact(runtime, "recon", f"# Recon\nHTTP landing page reachable; Server: m1-fixture.\nSource: {recon['observation_id']}. SSR form and API documentation link.\nSingle numeric origin; no domain or port expansion.\n")
    yield "load_skill", {"name": "web-enumeration"}
    landing = yield "http", {"url": "/", "method": "GET", "phase": "recon"}
    assert f'name="{definition.parameter}"' in landing and app.endpoint in landing
    metadata = []
    for path in ("/robots.txt", "/sitemap.xml", "/openapi.json"):
        output = yield "http", {"url": path, "method": "GET", "phase": "recon"}
        metadata.append(http_observation(output)["observation_id"])
        if path == "/openapi.json":
            assert app.endpoint in output and app.parameter in output
    inventory = receipt((yield "workflow", {"action": "record_input", "endpoint": definition.endpoint,
        "method": definition.method, "parameter": definition.parameter, "location": "query",
        "input_type": "string", "sample_payload": definition.input_value,
        "source_ref": metadata[-1]}))
    iid = inventory["input"]["id"]
    dispositions = (
        ("standard_metadata", "observed", f"robots.txt and sitemap.xml returned 404; reviewed native HTTP {metadata[:2]}. No metadata adapter attestation."),
        ("api_documentation", "observed", f"OpenAPI fixture documents this GET input; native HTTP {metadata[-1]}. No documentation adapter attestation."),
        ("javascript_endpoint_extraction", "not_applicable", "Landing HTML contains no scripts or bundles; API route is documented."),
        ("browser_burp_capture", "skipped", "No browser or Burp transport in this bounded HTTP fixture; client-only behavior untested."),
        ("active_content_discovery", "skipped", "Only documented routes tested; hidden route discovery intentionally omitted from the bounded fixture assessment."),
    )
    for dimension, status, reason in dispositions:
        yield from disposition("enumeration", dimension, status, reason)
    yield from phase_artifact(runtime, "web-enumeration", f"# Inventory\nForm and API: {definition.method} {app.endpoint}, {app.parameter} query string.\nStructured input: {iid}.\nMetadata sources: {metadata}.\nNo JS; browser and hidden routes untested.\n")
    yield "load_skill", {"name": "web-input-analysis"}
    signal = yield "http", app.request("Gifts'", phase="recon")
    assert "fixture syntax error" in signal
    created = receipt((yield "workflow", record_candidate(definition, input_id=iid)))
    cid = created["candidate"]["id"]
    receipt((yield "workflow", {"action": "set_input_disposition", "input_id": iid,
        "disposition": "analyzed", "disposition_reason": "SQL filter hypothesis from a single syntax signal; delegated confirmation."}))
    yield from phase_artifact(runtime, "web-input-analysis", f"# Candidates\nInput: {iid}; Candidate: {cid}; class: sql-injection.\nBaseline products and quote syntax sensitivity are observed; no confirmation yet.\nRecommended validator: sql-injection.\n")
    yield from dedicated_validation(runtime, definition, cid)


def generic_script(runtime, definition) -> Script:
    created = receipt((yield "workflow", record_candidate(definition)))
    assert created["validator_resolution"] == "generic"
    cid = created["candidate"]["id"]
    candidate = runtime.workflow.candidates[cid]
    probe = ProbeProposal(cid, candidate.objective_id, definition.origin, definition.endpoint,
                          definition.method, "query", definition.parameter, ("variant",))
    assessment = {"hypothesis": "Input variant might alter the comparison response",
        "criteria": "Compare baseline and the exact variant once; stable content does not confirm the hypothesis",
        "limitations": "Controller-bound pure offline fixture; no production CLI context binder; no general absence claim.",
        "completed_attempt": True, "observed_impact": "Baseline and variant returned identical complete content.", "severity": "info"}
    if definition.controller_bound:
        definition.application.verify_input_only(probe)
        trace = getattr(runtime, "scenario_trace", None)
        if trace is not None:
            trace.record({"type": "controller", "action": "bind-verified-fixture-probe", "candidate_id": cid,
                          "origin": definition.origin, "values": list(probe.values)})
        runtime.policy.generic_validation.bind_probe_context(runtime.http, cid, probe.to_dict(), verified_input_only=True)
    started = yield "workflow", {"action": "start_validation", "candidate_id": cid,
                                  "probe": probe.to_dict(), "assessment": assessment}
    if not definition.controller_bound:
        assert "context-needed" in started and not runtime.workflow.attempts
        unresolved = receipt((yield "workflow", {"action": "record_result", "candidate_id": cid,
            "skill_name": GENERIC_VALIDATOR, "outcome": "insufficient-evidence",
            "deferred_reason": "context-needed: no trusted production CLI endpoint/action context binder."}))
        assert unresolved["eligible_for_confirm_finding"] is False
        return
    started = receipt(started)
    assert started["validator_resolution"] == "generic"
    ids = []
    for value in ("baseline", "variant"):
        ids.append(http_observation((yield "http", definition.application.request(value)))["observation_id"])
    yield from publish_proof(runtime, cid, started["validation_context"]["attempt_id"], ids,
        GENERIC_VALIDATOR, "not-confirmed", assessment, ["bounded-comparison"], path=started["proof_source_path"])


def ambiguous_script(runtime, definition) -> Script:
    created = receipt((yield "workflow", record_candidate(definition)))
    assert created["validator_resolution"] == "ambiguous" and len(created["recommended_skills"]) == 2
    rejected = yield "workflow", {"action": "start_validation", "candidate_id": created["candidate"]["id"]}
    assert "ambiguous" in rejected and not runtime.workflow.attempts


@dataclass
class ScenarioRun:
    definition: ScenarioDefinition
    runtime: Any
    transport: FakeTransport
    model: ScriptedModel
    trace: Any
    oracle: Any
    elapsed: float
    fresh_runtime: Any = None


class ScenarioRunner:
    def __init__(self, root: Path, monkeypatch, *, defer_trace_redaction: bool = False):
        self.root, self.monkeypatch = root, monkeypatch
        self.defer_trace_redaction = defer_trace_redaction

    def prepare(self, definition: ScenarioDefinition, *, transport=None, mock_transport=True):
        from dataclasses import replace
        # Reuse the capture-selection factory; no parallel runtime assembly.
        runtime = make_runtime(self.root, origin=definition.origin, session_id=definition.id,
                               max_steps=definition.max_steps, max_calls=definition.max_calls, yolo=definition.yolo)
        if definition.ambiguous:
            original = runtime.skills.get("sql-injection")
            assert original is not None
            runtime.skills.add(replace(original, name="second-sql-validator"))
        runtime.registry.register(ReadPayloadsTool(runtime.skills))
        runtime.registry.register(ConfirmFindingTool(FindingStore(project_directory=self.root), workflow=runtime.workflow))
        # Real controller-origin grant, transient and bounded. Registry reviews
        # and private-host checks still execute; ALLOW_ONCE never becomes policy.
        transport = transport if transport is not None else FakeTransport(definition)
        runtime.engagement.http_permissions.activate(definition.origin, HTTPLimits(
            requests=len(transport.expected) + 1, rate=1000, burst=100, concurrency=1))
        if mock_transport:
            self.monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: REAL_HTTP_CLIENT(
                transport=httpx.MockTransport(transport.handle), **kw))
        runtime.scenario_errors = {}
        runtime.scenario_agent_errors = []
        runtime.scenario_snapshots = []
        runtime.scenario_transport = transport
        return runtime, transport

    async def run(self, definition: ScenarioDefinition, *, runtime=None, transport=None,
                  oracle=None, prefix="scenario", drive=None,
                  model_factory: Callable[..., ScriptedModel] = ScriptedModel) -> ScenarioRun:
        from tests.helpers.scenario_oracle import InvariantOracle, TraceRecorder
        if runtime is None:
            runtime, transport = self.prepare(definition)
        assert transport is not None
        model = model_factory(definition.script(runtime, definition), prefix=prefix)
        runtime.scenario_model = model
        runtime.agent.set_client(model)
        oracle = oracle or InvariantOracle(self.root)
        trace = TraceRecorder(runtime, oracle, defer_redaction=self.defer_trace_redaction)
        runtime.scenario_trace = trace
        trace.record({"type": "controller", "action": "runtime-rights-at-turn-start", "yolo": runtime.prompter.is_yolo(),
                      "grant_origins": [origin.as_url() for origin in runtime.engagement.http_permissions.grants]})
        start = perf_counter()
        try:
            operation = (drive(runtime, definition, trace) if drive is not None else
                         runtime.agent.run(definition.user_input, FakeSignal(), trace.record))
            await asyncio.wait_for(operation, definition.timeout)
            trace.sanitize_pending()
            if runtime.agent._background_tasks:
                await asyncio.gather(*tuple(runtime.agent._background_tasks))
            oracle.boundary(runtime, "post-agent")
            if definition.checkpoint:
                await runtime.coverage.flush()
                await runtime.agent.save()
                oracle.boundary(runtime, "saved")
            run = ScenarioRun(definition, runtime, transport, model, trace, oracle, perf_counter() - start)
            if definition.verify is None:
                await oracle.outcomes(run)
            else:
                await definition.verify(run)
            return run
        finally:
            trace.write(self.root / "scenario-trace.json")

    async def resume(self, run: ScenarioRun, *, unchanged=True) -> Any:
        fresh = make_runtime(self.root, origin=run.definition.origin, session_id=run.definition.id,
                             max_steps=run.definition.max_steps, max_calls=run.definition.max_calls, yolo=False)
        fresh.registry.register(ReadPayloadsTool(fresh.skills))
        fresh.registry.register(ConfirmFindingTool(FindingStore(project_directory=self.root), workflow=fresh.workflow))
        assert {"http", "workflow", "load_skill", "read_payloads", "file_write", "confirm_finding"} <= set(fresh.registry.tools)
        assert fresh.policy.max_calls == run.definition.max_calls
        assert fresh.agent._explicit_max_steps == run.definition.max_steps
        assert fresh.agent.client is fresh.client and not fresh.client.requests
        assert not fresh.engagement.http_permissions.grants and not fresh.policy._receipts
        fresh.agent.resume_saved()
        fresh.agent._reconcile_requested_goals()
        run.oracle.boundary(fresh, "fresh-resume", restored=True)
        if unchanged:
            await run.oracle.persisted(run, fresh)
        fresh.scenario_errors = {}
        fresh.scenario_agent_errors = []
        fresh.scenario_snapshots = []
        fresh.scenario_transport = run.transport
        run.fresh_runtime = fresh
        return fresh
