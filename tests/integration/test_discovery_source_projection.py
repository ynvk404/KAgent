"""Synthetic lan-17-shaped discovery; production calls, no model/target I/O."""
from copy import deepcopy
from dataclasses import replace
import json
import re
import socket

import httpx
import pytest

from src.skills.artifacts import completion_artifact_path
from src.workflow.assessment import resolve_sources
from src.workflow.state import WorkflowObjective
from tests.helpers.burp_selection import make_runtime, ORIGIN
from tests.helpers.discovery_calls import execute, attribution
from tests.helpers.workflow import record_completed_phase


SPEC = {"openapi": "3.0.0", "servers": [{"url": "/b2b/v2"}], "paths": {
    "/orders": {"post": {"requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "properties": {"cid": {"type": "string"}}}}}}}}}}
BODIES = {
    "/api-docs": (301, "text/html", '<a href="/api-docs/">Redirecting</a>'),
    "/api-docs/": (200, "text/html", '<script src="./swagger-ui-init.js"></script>'),
    "/api-docs/swagger-ui-init.js": (200, "application/javascript", 'const options = {swaggerDoc: '
        + json.dumps(SPEC) + '}; SwaggerUIBundle(options);'),
    "/openapi.json": (200, "application/json", json.dumps(SPEC)),
    "/main.js": (200, "application/javascript", 'import "./chunk.js"; /* password=body-secret-canary */'),
    "/api-docs/swagger.json": (200, "text/html", '<script src="./swagger-ui-init.js"></script>'),
}


@pytest.fixture
async def discovery(tmp_path, monkeypatch):
    def deny(*_args, **_kwargs):
        raise AssertionError("real network forbidden")
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket.socket, "connect_ex", deny)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_kw: [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 0))])
    sent = []
    real_client = httpx.AsyncClient

    def respond(request):
        sent.append(str(request.url))
        status, media, body = BODIES[request.url.path]
        return httpx.Response(status, content=body.encode(), headers={
            "content-type": media + "; private=header-secret-canary",
            "set-cookie": "session=cookie-secret-canary",
            "location": "/api-docs/?token=redirect-secret-canary",
        }, request=request)

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real_client(
        transport=httpx.MockTransport(respond), **kw))
    rt = make_runtime(tmp_path)
    rt.workflow.objective = WorkflowObjective("source-projection", "whole_target", ORIGIN)
    rt.workflow.objective.add_requested_goal("sqli")
    recon = rt.skills.get("recon")
    ref = completion_artifact_path(recon.completion_artifact, ORIGIN)
    path = tmp_path / ref
    path.parent.mkdir(parents=True)
    path.write_text("Synthetic offline Recon prerequisite.")
    record_completed_phase(rt.workflow, "recon", objective_id="source-projection",
                           target_origin=ORIGIN, artifact_ref=ref)
    rt.workflow.completed_skills.add("recon")
    rt.workflow.completed_artifacts["recon"] = ref
    rt.workflow.current_phase = "enumeration"
    await execute(rt, "load_skill", {"name": "web-enumeration"})
    for url in BODIES:
        await execute(rt, "http", {"url": url, "phase": "recon", "max_response_bytes": 8192})
    return rt, sent


async def listing(rt, **args):
    return json.loads((await execute(rt, "workflow", {"action": "list", "view": "sources", **args})).result)


async def test_source_projection_distinguishes_redirect_ui_bundle_and_spec_without_reading(discovery):
    rt, sent = discovery
    before = deepcopy(rt.workflow.to_dict())
    rights = rt.engagement.http_permissions
    authority = deepcopy(rights.grants), rights.epoch
    observations = dict(rt.policy.observations._items)
    rows = (await listing(rt))["sources"]
    by_url = {row["document_url"]: row for row in rows}
    for url, (status, media, body) in BODIES.items():
        row = by_url[ORIGIN + url]
        assert row["method"] == "GET" and row["status"] == status and row["media_type"] == media
        assert row["retained_body_bytes"] == len(body.encode())
        assert row["response_complete"] and not row["response_truncated"]
        source = rt.workflow.discovery_sources[row["id"]]
        assert row["retained_ref"] == source.retained_ref
        assert not row["selected"] and row["disposition"] == "pending"
    assert by_url[ORIGIN + "/api-docs/swagger.json"]["media_type"] == "text/html"
    assert "canary" not in json.dumps(rows) and "swaggerDoc" not in json.dumps(rows)
    assert rt.workflow.to_dict() == before and rt.policy.observations._items == observations
    assert (rights.grants, rights.epoch) == authority and len(sent) == len(BODIES)
    assert not rt.workflow.candidates and not rt.workflow.evidence and not rt.workflow.attempts


async def test_reader_identifies_selected_body_and_recovers_wrong_offset(discovery):
    rt, sent = discovery
    source = next(s for s in rt.workflow.objective_sources() if s.document_url == ORIGIN + "/api-docs")
    before = deepcopy(rt.workflow.to_dict())
    args = {"discovery_source_id": source.id, "start_char": 1600, "max_chars": 1500}
    failed = await execute(rt, "read_discovery_source", args, success=False)
    assert failed.status == "error" and "offset exceeds" in failed.result
    assert f"source_chars={len(BODIES['/api-docs'][2])}" in failed.result
    assert "start_char=0" in failed.result and "next_start_char" in failed.result
    result = await execute(rt, "read_discovery_source", {**args, "start_char": 0})
    header, body = result.result.split("\n", 1)
    page = json.loads(header)
    assert page["document_url"] == source.document_url and page["method"] == "GET"
    assert page["media_type"] == "text/html" and page["status"] == 301
    assert page["source_chars"] == len(body) and page["next_start_char"] is None
    assert body == BODIES["/api-docs"][2] and len(result.result) <= 2000
    assert rt.workflow.to_dict() == before and len(sent) == len(BODIES)
    rt.policy.revoke("http")
    denied = await execute(rt, "read_discovery_source", args, success=False)
    assert denied.status == "error" and "source_chars=" not in denied.result


@pytest.mark.parametrize("fault", ["missing", "hash", "status", "body", "url", "producer"])
async def test_response_projection_requires_matching_authoritative_observation(discovery, fault):
    rt, _ = discovery
    source = next(iter(rt.workflow.objective_sources()))
    item = rt.policy.observations._items[source.retained_ref]
    if fault == "missing": rt.policy.observations._items.pop(item.id)
    else:
        changes = {"hash": {"retained_hash": "0" * 64}, "status": {"status": 999},
                   "body": {"body": b"tampered"}, "url": {"url": ORIGIN + "/other"},
                   "producer": {"producer": "foreign"}}[fault]
        rt.policy.observations._items[item.id] = replace(item, **changes)
    before = deepcopy(rt.workflow.to_dict())
    row = next(r for r in (await listing(rt))["sources"] if r["id"] == source.id)
    assert row["document_url"] == source.document_url and row["method"] == "GET"
    assert not {"status", "media_type", "retained_body_bytes", "response_complete", "response_truncated"} & row.keys()
    assert rt.workflow.to_dict() == before


async def test_cursor_and_source_validation_recover_without_changing_workflow(discovery):
    rt, _ = discovery
    first = await listing(rt, limit=1)
    guidance = rt.workflow_tool.schema()['properties']['discovery_cursor']['description']
    assert 'next_discovery_cursor' in guidance and 'never cursor' in guidance and 'restart' in guidance
    source = rt.workflow.discovery_sources[first["sources"][0]["id"]]
    before = deepcopy(rt.workflow.to_dict())
    bad = await execute(rt, "workflow", {"action": "list", "view": "sources",
        "cursor": first["next_discovery_cursor"]}, success=False)
    assert bad.status == "error" and "discovery_cursor" in bad.result
    second = await listing(rt, limit=1, discovery_cursor=first["next_discovery_cursor"])
    assert second["sources"][0]["id"] != source.id
    rt.policy.observations._items.clear()
    assert (await listing(rt, limit=1))["next_discovery_cursor"] == first["next_discovery_cursor"]
    for id_ in ("ds_dummy", "ds_" + "0" * 64):
        result = await execute(rt, "read_discovery_source", {
            "discovery_source_id": id_, "start_char": 0, "max_chars": 100}, success=False)
        assert result.status == "error"
    assert rt.workflow.to_dict() == before


async def test_enumeration_completes_only_after_real_inventory_review_and_coverage(discovery, tmp_path):
    rt, sent = discovery
    source = next(s for s in rt.workflow.objective_sources() if s.document_url.endswith("swagger-ui-init.js"))
    args = {"action": "complete_skill", "skill_name": "web-enumeration", "current_phase": "analysis"}
    before = deepcopy(rt.workflow.to_dict())
    missing = await execute(rt, "workflow", args, success=False)
    assert missing.status == "error" and "inventory.md" in missing.result
    assert rt.workflow.to_dict() == before
    # Review every retained character through the real bounded reader.
    start, chunks = 0, []
    while True:
        output = await execute(rt, "read_discovery_source", {"discovery_source_id": source.id,
            "start_char": start, "max_chars": 2000})
        header, content = output.result.split("\n", 1)
        page = json.loads(header)
        chunks.append(content)
        if page["next_start_char"] is None: break
        start = page["next_start_char"]
    assert "".join(chunks) == BODIES["/api-docs/swagger-ui-init.js"][2]
    recorded = json.loads((await execute(rt, "workflow", {"action": "record_input", "method": "POST",
        "endpoint": "/b2b/v2/orders", "parameter": "cid", "location": "json", "input_type": "string",
        "content_type": "application/json", "source_attribution": attribution(source,
            "options.swaggerDoc.paths./orders.post.requestBody")})).result)
    assert recorded["input"]["source_ref"] is None
    # The GET document is not POST request context, even for documented inputs.
    rejected = await execute(rt, "workflow", {"action": "record_input", "method": "POST",
        "endpoint": "/api-docs/swagger-ui-init.js", "parameter": "cid", "location": "json",
        "source_ref": source.retained_ref}, success=False)
    assert rejected.status == "error" and "method does not match" in rejected.result
    assert len(rt.workflow.objective_inputs()) == 1
    skill = rt.skills.get("web-enumeration")
    ref = completion_artifact_path(skill.completion_artifact, ORIGIN)
    await execute(rt, "file_write", {"path": str(tmp_path / ref), "content": "\n".join([
        "# Synthetic bounded inventory", "POST /b2b/v2/orders; JSON cid:string; documented only, reachability unknown.",
        f"Source: {source.document_url}; {source.id}; {source.retained_ref}",
        "Only the visible /orders operation was reviewed; other bundle content was not reviewed."])})
    missing_coverage = await execute(rt, "workflow", args, success=False)
    assert missing_coverage.status == "error" and "coverage" in missing_coverage.result
    loaded = (await execute(rt, "load_skill", {"name": "web-enumeration"})).result
    examples = [json.loads(block) for block in re.findall(r'```json\s*\n(.*?)\n```', loaded, re.S)]
    closing = next(e for e in examples if e['tool'] == 'workflow' and e['arguments'] == {'action': 'list'})
    status = json.loads((await execute(rt, closing['tool'], closing['arguments'])).result)
    coverage = status["phase_coverage"]["source-projection:enumeration"]
    assert set(coverage) == {"html_navigation"} and coverage["html_navigation"]["status"] == "performed"
    for dimension, state, reason in [
        ("standard_metadata", "skipped", "Metadata paths omitted in this synthetic bounded pass."),
        ("api_documentation", "observed", f"Reviewed literal /orders and cid in {source.id}; no extraction adapter."),
        ("javascript_endpoint_extraction", "observed", "Reviewed initializer literal; main module import only; no extraction attestation."),
        ("browser_burp_capture", "skipped", "No browser/capture review performed in this bounded pass."),
        ("active_content_discovery", "skipped", "Known documented operation is sufficient for this bounded pass; no path gap pursued."),
    ]:
        await execute(rt, "workflow", {"action": "record_phase_coverage", "phase": "enumeration",
            "coverage_dimension": dimension, "coverage_status": state, "coverage_reason": reason})
    await execute(rt, "workflow", {"action": "select_source", "discovery_source_id": source.id})
    selected = await execute(rt, "workflow", args, success=False)
    assert selected.status == "error" and "selected source" in selected.result
    await execute(rt, "workflow", {"action": "set_source_disposition", "discovery_source_id": source.id,
        "retained_ref": source.retained_ref, "source_disposition": "processed",
        "source_reason": "Complete synthetic initializer read; visible operation and field recorded."})
    assert rt.workflow_tool.phase_completion_readiness("web-enumeration")["ready"]
    assert json.loads((await execute(rt, "workflow", args)).result)["ok"]
    assert rt.workflow.completed_phases() == {"recon", "enumeration"}
    assert all(i.disposition == "pending" for i in rt.workflow.objective_inputs())
    assert any(s.disposition == "pending" for s in rt.workflow.objective_sources())
    assert rt.workflow.objective.requested_goals[0].status == "pending"
    assert len(sent) == len(BODIES) and not rt.workflow.candidates and not rt.workflow.evidence
    with pytest.raises(ValueError, match="ownership mismatch"):
        resolve_sources(rt.policy, rt.workflow, None, None, [source.retained_ref], terminal=True, negative=False)
