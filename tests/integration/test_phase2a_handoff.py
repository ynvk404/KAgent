"""Offline Phase 2A handoff through registry, canonical state and runtime stores."""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import httpx
import pytest

from src.agent.compaction import remove_workflow_duplicates
from src.agent.system_prompt import render_workflow
from src.browser.store import CaptureStore, MAX_RAW_REQUEST_B64
from src.engagement.state import EngagementState
from src.permission.permission import AlwaysAllow
from src.session.store import Store, SessionMemory
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.common.registry import Registry
from src.tools.http.http_tool import HTTPTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.state import AttackSurfaceInput, Candidate, WorkflowMode, WorkflowObjective, WorkflowState
from src.workflow.validation_context import resolve_validation_context

ORIGIN = "https://target.test"


def runtime(tmp_path, mode: WorkflowMode = "whole_target", state=None, captures=None):
    state = state if state is not None else WorkflowState(objective=WorkflowObjective("handoff2", mode, ORIGIN))
    skills = SkillRegistry()
    skills.load_dir(Path(__file__).resolve().parents[2] / "skills")
    target = Target(ORIGIN)
    engagement = EngagementState()
    engagement.initialize_target(ORIGIN)
    captures = captures if captures is not None else CaptureStore()
    http = HTTPTool(target, engagement, state, captures)
    tool = WorkflowTool(state, target, skills=skills, evidence_root=tmp_path, http_tool=http)
    registry = Registry()
    registry.register(http)
    registry.register(tool)
    return state, registry, http, captures


async def call(registry, action, **args):
    return await registry.execute("workflow", {"action": action, **args}, None, AlwaysAllow())


async def record(registry, action, **args):
    result = json.loads(await call(registry, action, **args))
    assert result["ok"], result
    return result["input" if action == "record_input" else "candidate"]


async def linked(registry, **kwargs):
    item = await record(registry, "record_input", method="POST", endpoint="/api", parameter="q", location="body", **kwargs)
    candidate = await record(registry, "record_candidate", candidate_class="xss", input_id=item["id"])
    item["candidate_ids"] = [candidate["id"]]
    return item, candidate


async def start(registry, candidate):
    response = json.loads(await call(registry, "start_validation", candidate_id=candidate["id"]))
    assert response["ok"], response
    return response


@pytest.mark.asyncio
@pytest.mark.parametrize("media,sample", [
    ("application/json", '{"q":"safe","limit":10}'),
    ("application/json; charset=utf-8", '{"filter":{"q":"safe"},"limit":10}'),
    ("application/x-www-form-urlencoded", "q=safe&limit=10"),
    ("multipart/form-data; boundary=abc", '--abc\r\nContent-Disposition: form-data; name="q"\r\n\r\nsafe\r\n--abc--'),
])
async def test_marker_free_samples_and_explicit_templates_stay_separate(tmp_path, media, sample):
    state, registry, _, _ = runtime(tmp_path)
    item, candidate = await linked(registry, content_type=media, sample_payload=sample)
    response = await start(registry, candidate)
    context = response["validation_context"]
    assert response["candidate"] == {**candidate, "status": "validating"}
    assert context["sample_payload"] == item["sample_payload"] == sample
    assert context["sample_state"] == "known_sanitized"
    assert context["request_template"] is None
    assert context["template_state"] == "unknown"
    assert "{INJECTION_POINT}" not in json.dumps(context)
    assert context["url"] == ORIGIN + "/api"
    assert context["method"] == "POST"
    assert context["content_type"] == media
    assert context["media_type"] == media.split(";")[0]
    assert context["input_ids"] == [item["id"]]
    assert context["baseline"]["state"] == "missing"
    assert context["auth"]["state"] == "unknown"
    template = sample.replace("safe", "{INJECTION_POINT}")
    candidate = await record(registry, "record_candidate", candidate_class="xss", input_id=item["id"], request_template=template,
                             test_case="explicit-template")
    previous = next(c for c in state.candidates.values() if c.status == "validating")
    await call(registry, "record_result", candidate_id=previous.id, skill_name="cross-site-scripting",
               outcome="deferred", deferred_reason="context-only fixture, no execution")
    context = (await start(registry, candidate))["validation_context"]
    assert context["sample_payload"] == sample
    assert context["request_template"] == template
    assert context["template_state"] == "explicit_mutation"
    assert state.attack_surface_inputs[item["id"]].sample_payload == sample


@pytest.mark.asyncio
@pytest.mark.parametrize("location,endpoint,sample", [("query", "/search?q=safe&limit=10", "q=safe&limit=10"),
                                                      ("path", "/items/safe", "/items/safe")])
async def test_query_path_context_does_not_fabricate_templates(tmp_path, location, endpoint, sample):
    _, registry, _, _ = runtime(tmp_path)
    item = await record(registry, "record_input", method="GET", endpoint=endpoint, parameter="q", location=location, sample_payload=sample)
    candidate = await record(registry, "record_candidate", candidate_class="xss", input_id=item["id"])
    context = (await start(registry, candidate))["validation_context"]
    assert context["sample_payload"] == sample
    assert context["url"] == ORIGIN + endpoint
    assert context["location"] == location
    assert context["request_template"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", ["xss", "sql-injection"])
@pytest.mark.parametrize("known", [False, True])
async def test_direct_handoff_requires_no_input_or_recon_and_keeps_unknowns(tmp_path, cls, known):
    state, registry, _, _ = runtime(tmp_path, mode="direct")
    args = dict(method="POST", endpoint="/api", parameter="q", location="body", content_type="application/json",
                request_template='{"q":"{INJECTION_POINT}"}', baseline_request_ref="legacy-ref", auth_context_ref="user") if known else {}
    candidate = await record(registry, "record_candidate", candidate_class=cls, **args)
    context = (await start(registry, candidate))["validation_context"]
    assert context["resolution"] == "candidate_only"
    assert context["input_ids"] == []
    assert context["sample_payload"] is None
    assert context["method"] == ("POST" if known else None)
    assert context["url"] == (ORIGIN + "/api" if known else None)
    assert context["request_template"] == args.get("request_template")
    assert context["baseline"]["state"] == ("stale_or_unbound" if known else "missing")
    assert context["auth"]["available"] is False
    assert not state.attack_surface_inputs
    assert state.completed_phases() == set()
    assert "body" not in context and "selector" not in context
    if not known:
        assert "method_unknown" in context["limitations"]


@pytest.mark.asyncio
@pytest.mark.parametrize("media", ["application/json", "application/json; charset=utf-8"])
async def test_compatible_reverse_links_resolve_deterministically(tmp_path, media):
    state, registry, http, _ = runtime(tmp_path)
    item, candidate = await linked(registry, sample_payload='{"q":"safe"}')
    other = await record(registry, "record_input", method="POST", endpoint=ORIGIN + "/api", parameter="q", location="BODY",
                         input_type="json", content_type=media, sample_payload='{"q":"safe"}')
    result = json.loads(await call(registry, "link_input_candidate", input_id=other["id"], candidate_id=candidate["id"]))
    assert result["ok"]
    before = deepcopy(state.to_dict())
    first = resolve_validation_context(state, candidate["id"], target=ORIGIN, http_tool=http).to_dict()
    state.attack_surface_inputs = dict(reversed(list(state.attack_surface_inputs.items())))
    second = resolve_validation_context(state, candidate["id"], target=ORIGIN, http_tool=http).to_dict()
    assert first == second
    assert first["input_ids"] == sorted([item["id"], other["id"]])
    assert first["content_type"] == media
    assert first["sample_payload"] == '{"q":"safe"}'
    assert first["conflicting_fields"] == []
    assert state.to_dict() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [("method", "PUT"), ("endpoint", "/different"), ("parameter", "other"),
                                          ("location", "query"), ("content_type", "application/x-www-form-urlencoded"),
                                          ("baseline_request_ref", "unbound"), ("auth_context_ref", "admin"),
                                          ("sample_payload", '{"q":"different"}'),
                                          ("content_type", "application/json; charset=latin1")])
async def test_conflicting_reverse_links_withhold_exact_context(tmp_path, field, value):
    state, registry, _, _ = runtime(tmp_path)
    media = "application/json; charset=utf-8" if "charset" in value else "application/json"
    item, candidate = await linked(registry, sample_payload='{"q":"safe"}', content_type=media)
    # Legacy restored/enriched records or in-place corruption must never allow
    # arbitrary-first selection, even though creation/linkage guards reject it.
    other = AttackSurfaceInput("handoff2", ORIGIN, method="POST", endpoint="/api", parameter="q", location="body",
                               input_type="legacy", content_type="application/json", sample_payload='{"q":"safe"}')
    setattr(other, field, value)
    other.candidate_ids.append(candidate["id"])
    state.attack_surface_inputs[other.id] = other
    context = (await start(registry, candidate))["validation_context"]
    assert context["resolution"] == "ambiguous"
    assert field in context["conflicting_fields"]
    assert context[field] is None
    assert "ambiguous_context" in context["limitations"]
    assert not context["baseline"]["available"] and not context["auth"]["available"]
    if field == "sample_payload":
        assert context["input_ids"] == sorted([item["id"], other.id])


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["objective", "origin"])
async def test_foreign_reverse_links_are_not_exposed(tmp_path, fault):
    state, registry, _, _ = runtime(tmp_path)
    _, candidate = await linked(registry, sample_payload='{"q":"safe"}')
    foreign = AttackSurfaceInput("other" if fault == "objective" else "handoff2",
                                 "https://other.test" if fault == "origin" else ORIGIN,
                                 endpoint="/private", sample_payload="foreign-private-sample", candidate_ids=[candidate["id"]])
    state.attack_surface_inputs[foreign.id] = foreign
    response = await start(registry, candidate)
    assert response["validation_context"]["resolution"] == "ambiguous"
    assert "foreign-private-sample" not in json.dumps(response)
    assert foreign.id not in response["validation_context"]["input_ids"]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [1000, 4000])
async def test_exact_lookup_recovers_full_bound_after_compaction_and_session_resume(tmp_path, size):
    state, registry, _, _ = runtime(tmp_path)
    sample = "safe-" + "A" * (size - 5)
    item, candidate = await linked(registry, sample_payload=sample)
    listing = json.loads(await call(registry, "list"))
    assert len(listing["attack_surface_inputs"][0]["sample_payload"]) == 500
    assert listing["attack_surface_inputs"][0]["sample_payload_truncated"]
    prompt = render_workflow(state)
    assert sample not in prompt and "get_input" in prompt
    memory = SessionMemory(todos=[f"{candidate['id']} duplicate handoff"])
    compacted = remove_workflow_duplicates(memory, state)
    assert compacted.todos == []
    lookup = json.loads(await call(registry, "get_input", input_id=item["id"]))
    assert lookup == {"ok": True, "input": item}
    assert len(lookup["input"]["sample_payload"]) == size
    session = Store.new_with_id(tmp_path, "handoff2-resume")
    await session.save([], target=Target(ORIGIN), memory=compacted, workflow=state)
    restored = session.load()
    assert restored.workflow.to_dict() == state.to_dict()
    _, resumed, _, _ = runtime(tmp_path, state=restored.workflow)
    assert json.loads(await call(resumed, "get_input", input_id=item["id"])) == lookup
    assert (await start(resumed, candidate))["validation_context"]["sample_payload"] == sample
    assert "validation_context" not in session.path.read_text()
    assert "validation_context" not in json.dumps(state.to_dict())


@pytest.mark.asyncio
@pytest.mark.parametrize("fault,error", [("unknown", "unknown input"), ("missing", "requires exact input_id"),
                                         ("objective", "active objective"), ("origin", "active target origin"),
                                         ("endpoint", "active target origin"),
                                         ("target", "active target origin"), ("no_objective", "active objective")])
async def test_exact_lookup_ownership_failures(tmp_path, fault, error):
    state, registry, http, _ = runtime(tmp_path)
    item, _ = await linked(registry, sample_payload="private-canonical-sample")
    selected = item["id"]
    if fault == "unknown":
        selected = "unknown"
    elif fault == "missing":
        selected = ""
    elif fault == "objective":
        state.objective = WorkflowObjective("foreign", "whole_target", ORIGIN)
    elif fault == "origin":
        state.attack_surface_inputs[selected].target_origin = "https://other.test"
    elif fault == "endpoint":
        state.attack_surface_inputs[selected].endpoint = "https://other.test/private"
    elif fault == "target":
        http.target.set_base_url("https://other.test")
    elif fault == "no_objective":
        state.objective = None
    result = await call(registry, "get_input", input_id=selected)
    assert result.startswith("error:") and error in result
    assert "private-canonical-sample" not in result


@pytest.mark.asyncio
async def test_lookup_and_handoff_preserve_redaction_without_reading_raw_capture(tmp_path):
    state, registry, _, capture = runtime(tmp_path)
    raw = capture.ingest({"id": "private", "method": "POST", "url": ORIGIN + "/api",
                          "requestHeaders": {"Authorization": "Bearer raw-private-secret"},
                          "requestBody": "raw-body-private-secret"})
    item, candidate = await linked(registry, content_type="application/json",
                                    sample_payload='{"q":"safe","password":"password-private-secret","token":"token-private-secret"}',
                                    baseline_request_ref=raw["baseline_request_ref"])
    output = await call(registry, "get_input", input_id=item["id"])
    context_output = json.dumps(await start(registry, candidate))
    for secret in ("password-private-secret", "token-private-secret", "raw-private-secret", "raw-body-private-secret"):
        assert secret not in output and secret not in context_output
    assert json.loads(output)["input"]["sample_payload"] == state.attack_surface_inputs[item["id"]].sample_payload
    assert "requestHeaders" not in output and "raw_request" not in output
    assert "permission" not in json.loads(output)["input"]


def capture_payload(**kwargs):
    return {"id": "shared", "method": "POST", "url": ORIGIN + "/api",
            "requestHeaders": {"Content-Type": "application/json"}, "requestBody": '{"q":"safe","limit":10}', **kwargs}


@pytest.mark.asyncio
@pytest.mark.parametrize("fault,expected", [("live", "available"), ("clear", "stale_or_unbound"),
                                            ("restart", "stale_or_unbound"), ("mutation", "stale_or_unbound"),
                                            ("oversize", "incomplete_or_unsupported"), ("headers", "incomplete_or_unsupported"),
                                            ("raw", "incomplete_or_unsupported"), ("origin", "unavailable"),
                                            ("encoding", "incomplete_or_unsupported"),
                                            ("url_credentials", "incomplete_or_unsupported"),
                                            ("truncated_body", "incomplete_or_unsupported"),
                                            ("media", "unavailable"), ("method", "unavailable"),
                                            ("provenance", "unavailable")])
async def test_baseline_state_uses_live_binding_and_existing_completeness_guards(tmp_path, fault, expected):
    state, registry, http, captures = runtime(tmp_path)
    payload = capture_payload()
    if fault == "oversize":
        payload["rawRequestB64"] = "A" * (MAX_RAW_REQUEST_B64 + 1)
    elif fault == "headers":
        payload.pop("requestHeaders")
    elif fault == "raw":
        payload["rawRequestB64"] = "UE9TVCAvYXBpIEhUVFAvMS4x"
    elif fault == "origin":
        payload["url"] = "https://other.test/api"
    elif fault == "encoding":
        payload["requestHeaders"]["Content-Encoding"] = "gzip"
    elif fault == "url_credentials":
        payload["url"] = "https://fixture-user:fixture-password@target.test/api"
    elif fault == "truncated_body":
        payload["requestBody"] = "q=" + "A" * (65 * 1024)
    elif fault == "media":
        payload["requestHeaders"]["Content-Type"] = "application/x-www-form-urlencoded"
    elif fault == "method":
        payload["method"] = "PUT"
    row = captures.ingest(payload)
    item, candidate = await linked(registry, content_type="application/json", sample_payload='{"q":"sanitized"}',
                                    baseline_request_ref=row["baseline_request_ref"], source_ref="capture/shared")
    if fault == "clear":
        captures.clear()
        captures.ingest(payload)
    elif fault == "restart":
        http.capture_store = CaptureStore()
        http.capture_store.ingest(payload)
    elif fault == "mutation":
        captured = captures.get_request(row["id"])
        assert captured is not None
        captured.request_body = "changed"
    elif fault == "provenance":
        state.attack_surface_inputs[item["id"]].source_ref = "foreign-source"
    context = (await start(registry, candidate))["validation_context"]
    assert context["baseline"]["state"] == expected
    assert context["baseline"]["available"] is (fault == "live")
    assert context["sample_payload"] == '{"q":"sanitized"}'
    if fault == "live":
        replay = http.prepare({"phase": "validation", "candidate_id": candidate["id"], "mutation_value": "new"})[1]
        assert replay.content == b'{"q":"new","limit":10}'
        captures.ingest({**payload, "status": 201, "respBody": "updated"})
        assert (await start(registry, candidate))["validation_context"]["baseline"]["available"]


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["live", "missing", "expired", "wrong_origin", "wrong_identity", "rotated", "reset"])
async def test_capture_auth_availability_is_independent_of_native_context(tmp_path, fault):
    _, registry, http, captures = runtime(tmp_path)
    raw = captures.ingest(capture_payload(authContextRef="user", requestHeaders={"Content-Type": "application/json", "Cookie": "sid=private-cookie"}))
    _, candidate = await linked(registry, content_type="application/json", auth_context_ref="user", baseline_request_ref=raw["baseline_request_ref"])
    if fault != "missing":
        url = "https://other.test/api" if fault == "wrong_origin" else ORIGIN + "/api"
        request = httpx.Request("POST", url)
        value = "rotated-private-cookie" if fault == "rotated" else "private-cookie"
        cookie = f"sid={value}; Path=/" + ("; Max-Age=0" if fault == "expired" else "")
        http.context_store.extract(request, httpx.Response(200, headers={"Set-Cookie": cookie}, request=request),
                                   "admin" if fault == "wrong_identity" else "user")
    if fault == "reset":
        http.context_store.sync_target(http.target.revision + 1, http.engagement.revision)
    response = await start(registry, candidate)
    context = response["validation_context"]
    assert context["auth_context_ref"] == "user"
    assert context["auth"]["available"]
    assert context["auth"]["reason"] == "captured_credentials_require_permission"
    assert context["baseline"]["available"]
    assert "private-cookie" not in json.dumps(response)
    args = {"phase": "validation", "candidate_id": candidate["id"], "mutation_value": "new"}
    assert http.prepare(args)[1].headers["cookie"] == "sid=private-cookie"
    assert not http.permissions._capture_grants


@pytest.mark.asyncio
async def test_resume_rederives_runtime_state_and_never_recovers_auth_or_raw_traffic(tmp_path):
    state, registry, http, captures = runtime(tmp_path)
    raw = captures.ingest(capture_payload(authContextRef="user", requestHeaders={"Content-Type": "application/json", "Authorization": "Bearer private-live-auth"}))
    item, candidate = await linked(registry, content_type="application/json", sample_payload='{"q":"safe"}',
                                    baseline_request_ref=raw["baseline_request_ref"], auth_context_ref="user")
    request = httpx.Request("POST", ORIGIN + "/api", headers={"Authorization": "Bearer private-live-auth"})
    http.context_store.extract(request, httpx.Response(200, request=request), "user")
    assert (await start(registry, candidate))["validation_context"]["auth"]["available"]
    session = Store.new_with_id(tmp_path, "runtime-resume")
    await session.save([], workflow=state, target=Target(ORIGIN))
    assert "private-live-auth" not in session.path.read_text() and "validation_context" not in session.path.read_text()
    restored = session.load().workflow
    _, registry, _, _ = runtime(tmp_path, state=restored)
    context = (await start(registry, candidate))["validation_context"]
    assert context["baseline"]["state"] == "stale_or_unbound"
    assert not context["auth"]["available"]
    assert json.loads(await call(registry, "get_input", input_id=item["id"]))["input"] == item


@pytest.mark.asyncio
async def test_resolver_and_start_do_not_create_permission_proof_or_generic_action_context(tmp_path):
    state, registry, http, _ = runtime(tmp_path)
    _, candidate = await linked(registry, sample_payload='{"q":"safe"}')
    before = deepcopy(state.to_dict())
    grants = http.permissions.epoch
    context = resolve_validation_context(state, candidate["id"], target=ORIGIN, http_tool=http).to_dict()
    assert state.to_dict() == before
    assert http.permissions.epoch == grants
    for field in ("receipt", "permission", "action_signature", "probe", "proof", "confirmed", "values", "stop"):
        assert field not in context
    context["sample_payload"] = "tampered-view"
    assert state.attack_surface_inputs[next(iter(state.attack_surface_inputs))].sample_payload == '{"q":"safe"}'
    await start(registry, candidate)
    assert state.evidence == {} and state.validation_results == [] and state.persisted_findings == {}


@pytest.mark.asyncio
async def test_actual_tool_transcript_does_not_persist_transient_view_or_feed_compaction(tmp_path):
    from src.agent.compaction import format_history_for_compaction
    from src.llm.core.types import Message
    from src.redaction.redact import redact_payload

    state, registry, _, _ = runtime(tmp_path)
    _, candidate = await linked(registry, sample_payload='{"q":"safe"}')
    output = await call(registry, "start_validation", candidate_id=candidate["id"])
    assert "validation_context" in output
    message = Message(role="tool", name="workflow", content=output, tool_call_id="start-context")
    session = Store.new_with_id(tmp_path, "transient-transcript")
    await session.save([message], target=Target(ORIGIN), workflow=state)
    assert message.content == output  # Current caller still gets the live view.
    stored = session.path.read_text()
    assert "validation_context" not in stored
    resumed = session.load()
    response = json.loads(resumed.messages[0].content)
    assert response["candidate"] == {**candidate, "status": "validating"}
    assert response["validator_resolution"] == "unique"
    compacted = format_history_for_compaction([message], redact_payload=redact_payload)
    assert "validation_context" not in compacted and candidate["id"] in compacted
    _, resumed_registry, _, _ = runtime(tmp_path, state=resumed.workflow)
    assert (await start(resumed_registry, candidate))["validation_context"]["sample_payload"] == '{"q":"safe"}'


@pytest.mark.asyncio
async def test_direct_missing_target_remains_unknown_without_losing_known_endpoint(tmp_path):
    state, registry, _, _ = runtime(tmp_path, state=WorkflowState())
    candidate, _ = state.add_candidate(Candidate("xss", endpoint="/known", parameter="q", location="query"))
    result = json.loads(await call(registry, "start_validation", candidate_id=candidate.id))
    assert result["ok"]
    context = result["validation_context"]
    assert context["target"] is None and context["target_origin"] is None
    assert context["endpoint"] == "/known" and context["url"] is None
    assert context["method"] is None and context["request_template"] is None
    assert "target_origin_unknown" in context["limitations"]
    assert not context["baseline"]["available"]
