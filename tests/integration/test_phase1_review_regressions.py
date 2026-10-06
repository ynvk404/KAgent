"""Offline response binding and persisted identity regressions through consumers."""
from __future__ import annotations

import base64
import json
from copy import deepcopy

import pytest

from src.browser.store import CaptureStore, CapturedRequest, MAX_RAW_REQUEST_B64
from src.permission.runtime.generic_validation import GenericValidationBoundary
from src.session.store import Store
from src.workflow.evidence import EvidenceArtifact
from src.workflow.state import AttackSurfaceInput, Candidate, ValidationResult, WorkflowState
from tests.integration.test_structured_handoff_hardening import (
    ORIGIN, capture_payload, http_tool, record, replay_args, runtime,
)


def baseline_consumers(state, capture, candidate):
    tool = http_tool(state, capture)
    boundary = GenericValidationBoundary(None, state, None, tool.target)
    return tool.prepare(replay_args(candidate.id))[1], boundary.baseline(tool, candidate)


@pytest.mark.parametrize("kind", [None, "burp"])
@pytest.mark.parametrize("update", [
    {"respBody": "changed", "status": 503, "responseHeaders": {"X-Response": "updated"}},
    {"timeStart": 100, "timeEnd": 200, "elapsedMs": 100},
])
def test_variant_response_update_preserves_both_resolvers(kind, update):
    capture = CaptureStore()
    original = capture_payload()
    if kind:
        original["kind"] = kind
    first = capture.ingest(original)
    variant = {**original, "requestBody": '{"q":"old","other":"variant"}'}
    before = capture.ingest(variant)
    assert first["id"] != before["id"]
    assert first["baseline_request_ref"] != before["baseline_request_ref"]
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(
        "xss", target=ORIGIN, method="POST", endpoint="/api", parameter="q", location="body",
        content_type="application/json", baseline_request_ref=before["baseline_request_ref"],
    ))
    replay, baseline = baseline_consumers(state, capture, candidate)
    assert replay.content == b'{"q":"new","other":"variant"}'
    assert baseline.content == variant["requestBody"].encode()
    after = capture.ingest({**variant, **update})
    assert after == before
    replay, baseline = baseline_consumers(state, capture, candidate)
    assert replay.content == b'{"q":"new","other":"variant"}'
    assert baseline.content == variant["requestBody"].encode()
    row = capture.resolve_baseline(before["baseline_request_ref"])
    assert isinstance(row, CapturedRequest)
    assert row.status == update.get("status")
    assert row.elapsed_ms == update.get("elapsedMs")


@pytest.mark.asyncio
@pytest.mark.parametrize("candidate_order", [False, True])
@pytest.mark.parametrize("input_order", [False, True])
async def test_actual_session_hydrates_distinct_media_ids_and_links(tmp_path, candidate_order, input_order):
    state, registry = runtime(tmp_path)
    # Shared geometry and provenance still have distinct persisted media identities.
    args = dict(method="POST", endpoint="/api0", parameter="q", location="body", source_ref="inventory/shared",
                baseline_request_ref="baseline:opaque", auth_context_ref="identity:user")
    known_input = await record(registry, "record_input", **args, content_type="application/json")
    known = await record(registry, "record_candidate", candidate_class="xss", input_id=known_input["id"], signals=["known signal"])
    unknown_input = await record(registry, "record_input", **args)
    unknown = await record(registry, "record_candidate", candidate_class="xss", input_id=unknown_input["id"], signals=["unknown signal"])
    assert known["id"] != unknown["id"] and known_input["id"] != unknown_input["id"]
    # Both candidates can link to the unknown context; preserve multiple links.
    state.link_input_candidate(unknown_input["id"], known["id"])
    for index, candidate in enumerate((known, unknown)):
        proof = f"proof-{index}.md"
        (tmp_path / proof).write_text("Reproducible bounded evidence")
        evidence = EvidenceArtifact.capture(candidate["id"], proof, tmp_path)
        state.add_evidence(evidence)
        state.add_validation_result(ValidationResult(
            candidate["id"], "cross-site-scripting", "confirmed", evidence_refs=[evidence.id], objective_id="handoff",
        ))
        state.mark_finding_persisted(candidate["id"])
    state.set_candidate_status(unknown["id"], "queued")
    expected = deepcopy(state.to_dict())
    session = Store.new_with_id(tmp_path, "distinct-media")
    await session.save([], workflow=state)
    saved = json.loads(session.path.read_text())
    saved["workflow"]["candidates"].sort(key=lambda row: row["content_type"] is None, reverse=candidate_order)
    saved["workflow"]["attack_surface_inputs"].sort(key=lambda row: row["content_type"] is None, reverse=input_order)
    session.path.write_text(json.dumps(saved))
    restored = session.load().workflow
    assert restored.to_dict() == expected
    assert set(restored.candidates) == {known["id"], unknown["id"]}
    assert restored.attack_surface_inputs[known_input["id"]].candidate_ids == [known["id"]]
    assert restored.attack_surface_inputs[unknown_input["id"]].candidate_ids == [unknown["id"], known["id"]]
    assert restored.objective is not None
    assert restored.objective.requested_goals[0].candidate_ids == [known["id"], unknown["id"]]
    for candidate in (known, unknown):
        result = restored.latest_result(candidate["id"])
        assert result is not None and restored.evidence_matches(candidate["id"], result.evidence_refs)
        assert restored.finding_is_persisted(candidate["id"])
    await session.save([], workflow=restored)
    assert json.loads(session.path.read_text())["workflow"] == expected
    assert session.load().workflow.to_dict() == expected


@pytest.mark.parametrize("change", [
    {"method": "GET"}, {"url": ORIGIN + "/api?q=changed"},
    {"requestHeaders": {"Content-Type": "application/json", "X-Context": "changed"}},
    {"requestBody": '{"q":"old","other":"changed"}'},
    {"rawRequestB64": base64.b64encode(b"different raw request").decode()},
    {"authContextRef": "different-identity"},
    {"rawRequestB64": "A" * (MAX_RAW_REQUEST_B64 + 1)},
])
def test_request_identity_changes_get_distinct_bindings(change):
    capture = CaptureStore()
    original = capture.ingest(capture_payload())
    changed = capture.ingest({**capture_payload(), **change})
    assert changed["id"] != original["id"]
    assert changed["baseline_request_ref"] != original["baseline_request_ref"]
    assert capture.resolve_baseline(changed["baseline_request_ref"]) is not None
    # Distinct captured variants coexist; an old ref never resolves the new one.
    old = capture.resolve_baseline(original["baseline_request_ref"])
    assert isinstance(old, CapturedRequest) and old.request_body == capture_payload()["requestBody"]


@pytest.mark.asyncio
@pytest.mark.parametrize("lifecycle", ["live", "clear", "restart", "mutate", "mutate_then_reingest"])
async def test_hydrated_media_ids_never_repair_stale_baselines(tmp_path, lifecycle):
    state, registry = runtime(tmp_path)
    capture = CaptureStore()
    capture.ingest(capture_payload('{"q":"old","other":"original"}'))
    variant = capture_payload('{"q":"old","other":"variant"}')
    captured = capture.ingest(variant)
    args = dict(method="POST", endpoint="/api", parameter="q", location="body",
                baseline_request_ref=captured["baseline_request_ref"], source_ref="capture/shared")
    known_input = await record(registry, "record_input", **args, content_type="application/json")
    known = await record(registry, "record_candidate", candidate_class="xss", input_id=known_input["id"])
    unknown_input = await record(registry, "record_input", **args)
    unknown = await record(registry, "record_candidate", candidate_class="xss", input_id=unknown_input["id"])
    expected = deepcopy(state.to_dict())
    session = Store.new_with_id(tmp_path, "baseline-media")
    await session.save([], workflow=state)
    restored = session.load().workflow
    assert restored.to_dict() == expected
    if lifecycle == "live":
        assert capture.ingest({**variant, "status": 201, "respBody": "response"}) == captured
        # A partial response event addressing the destination preserves its request.
        result = capture.ingest({"id": captured["id"].removeprefix("wr:"), "url": ORIGIN + "/api", "status": 202})
        assert result == captured
        for row in (known, unknown):
            replay, baseline = baseline_consumers(restored, capture, restored.candidates[row["id"]])
            assert replay.content == b'{"q":"new","other":"variant"}'
            assert baseline.content == variant["requestBody"].encode()
        assert restored.to_dict() == expected
        return
    if lifecycle == "clear":
        capture.clear()
        capture.ingest(variant)
    elif lifecycle == "restart":
        capture = CaptureStore()
        capture.ingest(variant)
    else:
        row = capture.get_request(captured["id"])
        assert row is not None
        row.request_body = '{"q":"old","other":"tampered"}'
        if lifecycle == "mutate_then_reingest":
            # Recapturing the mutated identity cannot inherit the invalid digest.
            new = capture.ingest({**capture_payload(row.request_body),
                                  "id": captured["id"].removeprefix("wr:")})
            assert new["id"] == captured["id"]
            assert new["baseline_request_ref"] != captured["baseline_request_ref"]
    for row in (known, unknown):
        candidate = restored.candidates[row["id"]]
        tool = http_tool(restored, capture)
        with pytest.raises(ValueError, match="unavailable.*recapture required"):
            tool.prepare(replay_args(candidate.id))
        boundary = GenericValidationBoundary(None, restored, None, tool.target)
        with pytest.raises(ValueError, match="unavailable.*recapture required"):
            boundary.baseline(tool, candidate)
    assert restored.to_dict() == expected


@pytest.mark.parametrize("incomplete", ["oversize", "truncated_body", "missing_headers", "raw_framing"])
def test_response_update_keeps_incomplete_capture_blocked(incomplete):
    capture = CaptureStore()
    capture.ingest(capture_payload())
    payload = capture_payload('{"q":"old","other":"variant"}')
    if incomplete == "oversize":
        payload["rawRequestB64"] = "A" * (MAX_RAW_REQUEST_B64 + 1)
    elif incomplete == "truncated_body":
        payload["requestBody"] = "q=" + "A" * (65 * 1024)
    elif incomplete == "missing_headers":
        payload.pop("requestHeaders")
    else:
        payload["rawRequestB64"] = base64.b64encode(b"POST /api HTTP/1.1").decode()
    before = capture.ingest(payload)
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(
        "xss", target=ORIGIN, method="POST", endpoint="/api", parameter="q", location="body",
        baseline_request_ref=before["baseline_request_ref"], content_type="application/json",
    ))
    for update in ({}, {"status": 200, "respBody": "response"}):
        assert capture.ingest({**payload, **update}) == before
        tool = http_tool(state, capture)
        for resolve in (lambda: tool.prepare(replay_args(candidate.id)),
                        lambda: GenericValidationBoundary(None, state, None, tool.target).baseline(tool, candidate)):
            with pytest.raises(ValueError, match="size limit|truncated|headers are unavailable|header terminator"):
                resolve()


@pytest.mark.asyncio
async def test_burp_task_response_metadata_preserves_consumer_binding(tmp_path):
    capture = CaptureStore()
    body = b'{"q":"old"}'
    raw = b"POST /api HTTP/1.1\r\nHost: target.test\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n" + body
    ref = capture.ingest_burp_task({"action": "scan", "method": "POST", "url": ORIGIN + "/api",
                                    "rawRequestB64": base64.b64encode(raw).decode()})
    state = WorkflowState()
    candidate, _ = state.add_candidate(Candidate(
        "xss", target=ORIGIN, method="POST", endpoint="/api", parameter="q", location="body",
        baseline_request_ref=ref["baseline_request_ref"], content_type="application/json",
    ))
    task = capture.get_burp_task(ref["id"])
    assert task is not None
    task.notes = "Response metadata updated"
    task.created_at += 1
    replay, baseline = baseline_consumers(state, capture, candidate)
    assert replay.content == b'{"q":"new"}' and baseline.content == body
    session = Store.new_with_id(tmp_path, "burp-consumers")
    await session.save([], workflow=state)
    restored = session.load().workflow
    assert baseline_consumers(restored, capture, restored.candidates[candidate.id])[1].content == body
    capture.clear()
    tool = http_tool(restored, capture)
    with pytest.raises(ValueError, match="unavailable"):
        tool.prepare(replay_args(candidate.id))
    with pytest.raises(ValueError, match="unavailable"):
        GenericValidationBoundary(None, restored, None, tool.target).baseline(tool, restored.candidates[candidate.id])


@pytest.mark.asyncio
@pytest.mark.parametrize("collection", ["candidates", "attack_surface_inputs"])
async def test_session_duplicate_exact_ids_rejected(tmp_path, collection):
    state, registry = runtime(tmp_path)
    item = await record(registry, "record_input", method="POST", endpoint="/api", parameter="q", location="body")
    await record(registry, "record_candidate", candidate_class="xss", input_id=item["id"])
    session = Store.new_with_id(tmp_path, "duplicate")
    await session.save([], workflow=state)
    saved = json.loads(session.path.read_text())
    saved["workflow"][collection].append(deepcopy(saved["workflow"][collection][0]))
    session.path.write_text(json.dumps(saved))
    with pytest.raises(ValueError, match="duplicate persisted"):
        session.load()


@pytest.mark.asyncio
async def test_session_hydration_keeps_malformed_record_filtering_and_goal_errors(tmp_path):
    from src.session.store import SessionLoadError

    session = Store.new_with_id(tmp_path, "corrupt")
    session.path.write_text(json.dumps({"workflow": {
        "candidates": [{"candidate_class": 42}, {"candidate_class": "xss", "signals": "bad"},
                       {"id": "cand_wrong", "candidate_class": "xss"}],
        "attack_surface_inputs": [{"objective_id": "handoff", "target_origin": "file:///bad"}],
        "validation_results": [{"outcome": "confirmed", "candidate_id": "missing"}],
    }}))
    saved = json.loads(session.path.read_text())
    candidate = Candidate("xss").to_dict()
    item = AttackSurfaceInput("handoff", ORIGIN).to_dict()
    saved["workflow"]["candidates"].append({**candidate, "signals": "bad"})
    saved["workflow"]["attack_surface_inputs"].append({**item, "candidate_ids": "bad"})
    for invalid_id in (None, 42, ""):
        saved["workflow"]["candidates"].append({**candidate, "id": invalid_id})
        saved["workflow"]["attack_surface_inputs"].append({**item, "id": invalid_id})
    candidate.pop("id")
    item.pop("id")
    saved["workflow"]["candidates"].append(candidate)
    saved["workflow"]["attack_surface_inputs"].append(item)
    session.path.write_text(json.dumps(saved))
    restored = session.load().workflow
    assert restored.candidates == {} and restored.attack_surface_inputs == {} and restored.validation_results == []
    session.path.write_text(json.dumps({"workflow": {"objective": {
        "id": "handoff", "mode": "whole_target", "target_origin": ORIGIN, "requested_goals": "bad",
    }}}))
    with pytest.raises(SessionLoadError, match="malformed requested goals"):
        session.load()
    session.path.write_text("{invalid-json")
    with pytest.raises(SessionLoadError, match="failed to read"):
        session.load()
