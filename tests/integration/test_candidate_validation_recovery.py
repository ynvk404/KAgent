"""Scripted model, native dispatch and MockTransport; no external services."""
import base64
from collections.abc import Generator
from copy import deepcopy
import json
from typing import Any
from urllib.parse import urlencode

import httpx
import pytest

from src.findings.store import Store, read_report
from src.llm.core.client import Client
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.tools.workflow.finding import ConfirmFindingTool
from src.workflow.assessment import accepted_result
from src.workflow.state import WorkflowState
from tests.helpers.agent_fakes import FakeSignal
from tests.helpers.burp_selection import ORIGIN, ingest, make_runtime

REAL_CLIENT = httpx.AsyncClient
ASSESSMENT = {"hypothesis": "category is evaluated in a SQL predicate",
              "criteria": "Two complete TRUE/FALSE pairs with stable distinct content",
              "limitations": "Offline fixture; no database extraction or live verification",
              "observed_impact": "Controlled predicates change the returned fixture products.",
              "severity": "medium", "completed_attempt": True}


class ScriptedClient(Client):
    def __init__(self):
        self.script: Generator[tuple[str, Any], str, None] | None = None
        self.started = False
        self.calls = 0
        self.finished = 0
        self.errors: list[Exception] = []

    def name(self):
        return "fake"

    def model(self):
        return "offline-workflow"

    def begin(self, script):
        self.script, self.started = script, False

    async def chat(self, request, signal=None):
        assert self.script is not None
        try:
            if self.started:
                last = next(m for m in reversed(request.messages) if m.role == "tool")
                name, args = self.script.send(last.content)
            else:
                self.started = True
                name, args = next(self.script)
        except StopIteration:
            self.finished += 1
            return ChatResponse(Message("assistant", "Bounded fixture workflow recorded."), "stop")
        except Exception as err:
            # Agent provider retry must not hide a failed scripted assertion.
            self.errors.append(err)
            raise
        self.calls += 1
        return ChatResponse(Message("assistant", "", tool_calls=[ToolCall(
            str(self.calls), FunctionCall(name, args if isinstance(args, str) else json.dumps(args))
        )]), "tool_calls")


def observation(output):
    line = next(line for line in output.splitlines() if line.startswith("Runtime HTTP evidence ("))
    envelope, _ = json.JSONDecoder().raw_decode(line.split(": ", 1)[1])
    assert envelope["complete"] and not envelope["truncated"]
    return envelope["observation_id"]


def product_script(runtime, capture):
    detail = json.loads((yield "browser_capture_get", {"id": capture["id"]}))
    refs = {"source_ref": detail["id"], "baseline_request_ref": detail["baseline_request_ref"]}
    args = {"action": "record_candidate", "candidate_class": "sqli", "method": "GET",
            "endpoint": "/product", "parameter": "productId", "location": "query", **refs}
    before = deepcopy(runtime.workflow.to_dict())
    rejected = yield "workflow", {**args, "endpoint": "/filter", "parameter": "category"}
    assert "binding is ambiguous or mismatched" in rejected
    assert runtime.workflow.to_dict() == before
    assert runtime.agent._turn_capture_selection() is not None
    rejected = yield "workflow", {**args, "status": "validating"}
    assert "validating is runtime-owned" in rejected
    assert runtime.workflow.to_dict() == before
    created = json.loads((yield "workflow", args))
    cid = created["candidate"]["id"]
    assert created["candidate"]["status"] == "queued" and not runtime.workflow.attempts
    before = deepcopy(runtime.workflow.to_dict())
    rejected = yield "workflow", {**args, "status": "validating", "signals": ["extra input context"]}
    assert "validating is runtime-owned" in rejected
    assert runtime.workflow.to_dict() == before and not runtime.workflow.attempts
    yield "load_skill", {"name": "sql-injection"}
    started = json.loads((yield "workflow", {"action": "start_validation", "candidate_id": cid}))
    aid = started["validation_context"]["attempt_id"]
    ids = []
    # Baseline, syntax probe, then two inconclusive numeric Boolean pairs.
    for payload in ("14", "14'", "14 AND 1=1", "14 AND 1=2", "14 AND 1=1", "14 AND 1=2"):
        ids.append(observation((yield "http", {"candidate_id": cid, "phase": "validation", "mutation_value": payload})))
    proof_text = f"# Product bounded test\n- candidate_id: {cid}\n- observation_ids: {', '.join(ids)}\n"
    for oid in ids:
        source = runtime.policy.observations._items[oid]
        proof_text += f"{source.method} {source.url}: {source.status} {source.body.decode()} ({oid})\n"
    proof_text += "Baseline, quote and both repeated numeric TRUE/FALSE pairs returned unchanged content. No confirmation; no general absence claim.\n"
    yield "file_write", {"path": str(runtime.policy.root / "product-proof.md"), "content": proof_text}
    proof = json.loads((yield "workflow", {"action": "record_evidence", "candidate_id": cid,
        "evidence_path": "product-proof.md", "observation_ids": ids}))
    result = json.loads((yield "workflow", {"action": "record_result", "candidate_id": cid,
        "skill_name": "sql-injection", "outcome": "not-confirmed", "attempt_id": aid,
        "mutation_performed": False,  # Controlled fixture only returns comparison responses.
        "observation_ids": ids, "evidence_refs": [proof["evidence"]["id"]],
        "techniques": ["syntax-sensitivity", "boolean-based"],
        "assessment": {**ASSESSMENT, "hypothesis": "productId quote may change SQL evaluation",
                       "criteria": "Compare baseline, quote and two repeated numeric TRUE/FALSE pairs",
                       "observed_impact": "Fixture unchanged in all six bounded observations."}}))
    assert result["ok"] and not result["eligible_for_confirm_finding"]


def filter_script(runtime, old_id):
    created = json.loads((yield "workflow", {"action": "record_candidate", "candidate_class": "sqli",
        "endpoint": "/filter", "method": "GET", "parameter": "category", "location": "query",
        "signals": ["Operator independently requested category validation at the active origin."]}))
    cid = created["candidate"]["id"]
    assert created["candidate"]["baseline_request_ref"] is None
    assert created["candidate"]["source_ref"] is None
    yield "load_skill", {"name": "sql-injection"}
    started = json.loads((yield "workflow", {"action": "start_validation", "candidate_id": cid}))
    aid = started["validation_context"]["attempt_id"]
    ids, pairs = [], []
    for repetition in (1, 2):
        pair: dict[str, Any] = {"repetition": repetition}
        for side, predicate in (("true", "1=1"), ("false", "1=2")):
            output = yield "http", {"url": "/filter?" + urlencode({"category": "Gifts' AND " + predicate + "--"}),
                                    "method": "GET", "phase": "validation"}
            oid = observation(output)
            ids.append(oid)
            source = runtime.policy.observations._items[oid]
            assert source.candidate_id == cid and source.attempt_id == aid
            pair[side] = {"status": source.status, "size": len(source.body), "marker": source.body.decode()}
        pairs.append(pair)
    registration = {"action": "record_evidence", "candidate_id": cid,
                    "evidence_path": "filter-proof.md", "observation_ids": ids}
    before = deepcopy(runtime.workflow.to_dict())
    malformed = yield "workflow", '{"action":"record_evidence","candidate_id":'
    assert "could not parse arguments" in malformed and runtime.workflow.to_dict() == before
    forbidden = yield "workflow", {**registration, "attempt_id": aid}
    assert "does not accept attempt_id" in forbidden and runtime.workflow.to_dict() == before
    proof_text = f"# Filter proof\n- candidate_id: {cid}\n- observation_ids: {', '.join(ids)}\n"
    for oid in ids:
        source = runtime.policy.observations._items[oid]
        proof_text += f"{source.method} {source.url}: {source.status} {source.body.decode()} ({oid})\n"
    yield "file_write", {"path": str(runtime.policy.root / "filter-proof.md"), "content": proof_text}
    before = deepcopy(runtime.workflow.to_dict())
    wrong_owner = yield "workflow", {**registration, "observation_ids": [old_id]}
    assert "ownership mismatch" in wrong_owner
    assert json.loads(wrong_owner.split('\n', 1)[1])['error']['code'] == 'SOURCE_OWNERSHIP_MISMATCH'
    after = runtime.workflow.to_dict()
    budget = after.pop('evidence_recovery')[aid]
    before.pop('evidence_recovery')
    assert after == before  # Rejection changes only attempt-scoped repair accounting.
    assert budget['candidate_id'] == cid and budget['rejections'] == 1 and budget['paused']
    registered = json.loads((yield "workflow", registration))
    assert registered["primary_parents"] == ids
    result = json.loads((yield "workflow", {"action": "record_result", "candidate_id": cid,
        "skill_name": "sql-injection", "outcome": "confirmed", "attempt_id": aid,
        "mutation_performed": False,
        "evidence_refs": [registered["evidence"]["id"]], "observation_ids": ids,
        "techniques": ["SQLI-2", "boolean-based"], "repeatable": True, "assessment": ASSESSMENT,
        "confirmation": {"kind": "boolean-differential", "request_template": ORIGIN + "/filter?category=Gifts' AND {predicate}--",
                         "true_predicate": "1=1", "false_predicate": "1=2", "pairs": pairs}}))
    assert result["eligible_for_confirm_finding"] and not runtime.workflow.finding_is_persisted(cid)
    finding = yield "confirm_finding", {"candidate_id": cid, "title": "Offline category fixture",
        "severity": "medium", "url": ORIGIN + "/filter", "method": "GET", "parameter": "category",
        "payload": "Gifts' AND 1=1--", "response_excerpt": "fixture products",
        "observed_impact": ASSESSMENT["observed_impact"], "potential_impact": "No additional impact assessed.",
        "curl": "curl '" + ORIGIN + "/filter?category=Gifts%27%20AND%201%3D1--'",
        "remediation": "Use parameterized queries for category.", "vuln_class": "sqli"}
    assert 'Finding "Offline category fixture" written to ' in finding
    assert runtime.workflow.finding_is_persisted(cid)


@pytest.mark.asyncio
async def test_selected_product_then_independent_filter_completes_real_evidence_gates(tmp_path, monkeypatch):
    client = ScriptedClient()
    runtime = make_runtime(tmp_path, client)
    sent = []

    def handler(request):
        sent.append(request)
        category = request.url.params.get("category", "")
        body = b"fixture products" if "1=1" in category else b"empty" if "1=2" in category else b"fixture unchanged"
        return httpx.Response(200, content=body, request=request)

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler), **kw))
    runtime.registry.register(ConfirmFindingTool(Store(project_directory=tmp_path), workflow=runtime.workflow))
    raw = b"GET /product?productId=14 HTTP/1.1\r\nHost: 127.0.0.1:3000\r\n\r\n"
    capture = ingest(runtime, path="/product?productId=14", rawRequestB64=base64.b64encode(raw).decode())
    runtime.agent.select_burp_captures(capture["id"])
    client.begin(product_script(runtime, capture))
    await runtime.agent.run("Validate SQLi only on the selected product request in this authorized lab.", FakeSignal(), lambda _: None)
    assert client.finished == 1
    assert not client.errors
    product = next(iter(runtime.workflow.candidates.values()))
    negative = runtime.workflow.latest_result(product.id)
    assert negative is not None and negative.outcome == "not-confirmed"
    assert accepted_result(runtime.workflow, product, negative, runtime.policy)
    assert runtime.workflow.attempts[negative.attempt_id]["status"] == "completed"
    assert not runtime.workflow.persisted_findings
    old_id = negative.evidence_manifest[0]["source"]["id"]
    client.begin(filter_script(runtime, old_id))
    await runtime.agent.run("Independently validate SQLi on GET /filter?category in the same authorized lab; use its own evidence.",
                            FakeSignal(), lambda _: None)
    assert client.finished == 2
    assert not client.errors
    candidate = next(c for c in runtime.workflow.candidates.values() if c.endpoint == "/filter")
    result = runtime.workflow.latest_result(candidate.id)
    assert result is not None and result.outcome == "confirmed"
    assert result.attempt_id != negative.attempt_id
    assert accepted_result(runtime.workflow, candidate, result, runtime.policy)
    assert runtime.workflow.finding_is_persisted(candidate.id)
    reports = list((tmp_path / "artifacts/findings").glob("*.md"))
    assert len(reports) == 1 and read_report(reports[0]).candidate_id == candidate.id
    assert len(sent) == 10  # completing the ledger requires no repair probes
    restored = WorkflowState.from_dict(json.loads(json.dumps(runtime.workflow.to_dict())))
    assert accepted_result(restored, restored.candidates[candidate.id], restored.latest_result(candidate.id))
    assert restored.finding_is_persisted(candidate.id)
    assert set(restored.evidence_sources[negative.evidence_refs[0]]).isdisjoint(
        restored.evidence_sources[result.evidence_refs[0]])
