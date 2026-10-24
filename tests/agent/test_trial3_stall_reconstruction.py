"""Extend Trial 3's shape beyond its former stall through offline transports.

Synthetic response bodies and a scripted client reproduce the retained facts,
not a live experiment. No historical session, provider, or target is resumed.
Repeated discovery metadata reads use the supported Workflow API. Raw HTTP
readback remains attempt-owned; it has no discovery/search mode.
"""
from copy import deepcopy
import json

import httpx
import pytest

from src.agent.events import WorkflowProgressEvent
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.tools.common.permission_status import PermissionStatusTool
from src.tools.discovery.service import ServiceDiscoveryTool
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from tests.helpers.burp_selection import make_runtime


PROMPT = (
    "Perform a whole-target assessment of the authorized target. Discover endpoints and inputs, "
    "analyze them, then validate SQL Injection and XSS. Stay within the declared origin and "
    "existing permissions and budgets. Use minimal non-sensitive proof; do not extract credentials "
    "or bulk data.\n"
)
SUMMARY = "artifacts/recon/127-0-0-1-3000/summary.md"
ROOT = (b"<!doctype html><html><head><title>Offline fixture</title><style>"
        + b"/* retained CSS */" * 600
        + b'</style></head><body><script src="/main.js"></script></body></html>')


class Trial3Replay(FakeClient):
    def __init__(self, runtime, disposition):
        super().__init__([])
        self.runtime = runtime
        self.disposition = disposition

    async def chat(self, request, signal=None):
        self.requests.append(deepcopy(request))
        step = len(self.requests)
        if request.tools is None:
            assert step == 17
            return ChatResponse(Message("assistant", "Incomplete offline assessment."), "stop")
        assert step <= 16
        calls = {
            1: [("load_skill", {"name": "recon"}), ("permissions_status", {})],
            2: [("http", {"method": "GET", "url": "/", "phase": "recon", "max_response_bytes": 8192})],
            3: [("http", {"method": "GET", "url": "/rest/products/search?q=apple", "phase": "recon",
                           "max_response_bytes": 4096}),
                ("http", {"method": "GET", "url": "/robots.txt", "phase": "recon", "max_response_bytes": 2048})],
            4: [("file_write", {"path": SUMMARY, "content": "# Offline recon\nObserved HTTP service and TCP port.\n"})],
            5: [("service_discovery", {"target": self.runtime.target.base_url(), "timeout_seconds": 20})],
            6: [("workflow", {"action": "complete_skill", "skill_name": "recon", "artifact_ref": SUMMARY,
                               "current_phase": "enumeration"})],
            7: [("load_skill", {"name": "web-enumeration"})],
            8: [("workflow", {"action": "list", "view": "sources"}),
                ("workflow", {"action": "list", "view": "endpoints"})],
        }
        if step >= 9:
            source = next(s for s in self.runtime.workflow.discovery_sources.values()
                          if s.document_url.endswith("/"))
            if step == 9:
                calls[step] = [("workflow", {"action": "select_source", "discovery_source_id": source.id,
                                             "retained_ref": source.retained_ref})]
            elif step == 16 and self.disposition:
                calls[step] = [("workflow", {"action": "set_source_disposition", "discovery_source_id": source.id,
                    "retained_ref": source.retained_ref, "source_disposition": "partial",
                    "acknowledge_bounded_stop": True, "source_bounds": {"max_bytes": 8192},
                    "source_limitations": ["Only the retained prefix was inspected"],
                    "source_reason": "No script reference in the retained prefix"})]
            else:
                # get_source is read-only metadata. Repeating it cannot invent
                # extraction progress or turn this source into validation proof.
                calls[step] = [("workflow", {"action": "get_source", "discovery_source_id": source.id})]
        return ChatResponse(Message("assistant", "", tool_calls=[
            ToolCall(f"trial3-{step}-{i}", FunctionCall(name, json.dumps(args)))
            for i, (name, args) in enumerate(calls[step])
        ]), "tool_calls")


@pytest.mark.parametrize("disposition", [False, True], ids=["repeated-reads", "explicit-bounded-disposition"])
async def test_trial3_shape_continues_past_old_boundary_to_budget(tmp_path, monkeypatch, disposition):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KAGENT_PROJECT_ROOT", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    sent, sockets = [], []
    real_client = httpx.AsyncClient

    def respond(request):
        sent.append(str(request.url))
        body, media = {
            "/": (ROOT, "text/html"),
            "/robots.txt": (b"User-agent: *\nDisallow: /ftp\n", "text/plain"),
            "/rest/products/search": (b'{"status":"success","data":[]}', "application/json"),
        }[request.url.path]
        return httpx.Response(200, content=body, headers={"content-type": media}, request=request)

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real_client(transport=httpx.MockTransport(respond), **kw))

    class Writer:
        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def connect(host, port):
        sockets.append((host, port))
        return None, Writer()

    # Keep production socket_budget and Registry/permission checks; replace
    # only the actual TCP transport. No socket is opened.
    monkeypatch.setattr("src.tools.discovery.service.asyncio.open_connection", connect)
    runtime = make_runtime(tmp_path, max_steps=16)
    runtime.agent.tools.register(PermissionStatusTool())
    runtime.agent.tools.register(ServiceDiscoveryTool(runtime.target, runtime.engagement, workflow=runtime.workflow))
    for capability in ("shell", "bash", "web_search"):
        runtime.policy.revoke(capability)
    client = Trial3Replay(runtime, disposition)
    runtime.agent.set_client(client)
    events, evaluated, before, after, quotas = [], [], [], [], []

    def emit(event):
        events.append(event)
        if isinstance(event, WorkflowProgressEvent):
            if event.stage == "iteration_started":
                before.append(deepcopy(runtime.workflow.to_dict()))
            elif event.stage == "iteration_evaluated":
                evaluated.append(event.metrics.copy())
                after.append(deepcopy(runtime.workflow.to_dict()))
                quotas.append(sum(b.used for b in runtime.engagement.http_permissions._budgets.values()))

    await runtime.agent.run(PROMPT, FakeSignal(), emit)
    done = events[-1]
    assert done.stop_reason == "max_steps"
    assert (done.agent_loop_llm_calls, done.compaction_llm_calls, done.final_synthesis_llm_calls) == (16, 0, 1)
    assert len(sent) == 3 and sockets == [("127.0.0.1", 3000)]
    assert quotas == [0, 1, 3, 3] + [4] * 12
    assert [r["outer_iterations"] for r in evaluated] == list(range(1, 17))
    assert all(r["workflow_status"] == "actionable" for r in evaluated)
    for index in range(9, 15 if disposition else 16):
        assert before[index] == after[index]
    assert len(runtime.workflow.endpoints) == len(runtime.workflow.discovery_sources) == 3
    assert len(runtime.workflow.discovery_provenance) == 3
    assert not runtime.workflow.attack_surface_inputs and not runtime.workflow.candidates
    assert not runtime.workflow.attempts and not runtime.workflow.validation_results and not runtime.workflow.persisted_findings
    assert runtime.workflow.objective is not None
    assert [g.status for g in runtime.workflow.objective.requested_goals] == ["pending", "pending"]
    assert runtime.workflow.current_phase == "enumeration"
    root = next(s for s in runtime.workflow.discovery_sources.values() if s.document_url.endswith("/"))
    assert root.selected and root.disposition == ("partial" if disposition else "pending")

    # Inspect actual successful get_source receipts, not error strings parsed
    # as a nonexistent discovery readback envelope.
    read_ids = {f"trial3-{step}-0" for step in range(10, 16 if disposition else 17)}
    readers = [m for m in client.requests[-1].messages if m.tool_call_id in read_ids]
    assert len(readers) == (6 if disposition else 7)
    for message in readers:
        assert message.name == "workflow" and message.tool_status == "success"
        row = json.loads(message.content)
        assert row["ok"] and row["unresolved"]
        assert row["discovery_source"]["id"] == root.id
        assert row["discovery_source"]["retained_ref"] == root.retained_ref
        assert row["discovery_source"]["retained_hash"] == root.retained_hash
        assert row["discovery_source"]["selected"] and row["discovery_source"]["disposition"] == "pending"
        assert message.http_response_sources is None
    assert not [event for event in events if event.type == "tool-result" and event.status == "error"]
    retained = runtime.policy.observations._items[root.retained_ref]
    assert retained.body == ROOT[:8192] and retained.truncated and not retained.complete
    assert retained.candidate_id is None and retained.attempt_id is None
    assert runtime.store.load().workflow.to_dict() == runtime.workflow.to_dict()
