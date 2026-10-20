"""Option B A01–A13/A17: native offline reads through actual Agent/Registry.

All HTTP uses MockTransport, session/artifact writes use tmp_path. The lifecycle
and cross-version acceptance cases live in the companion lifecycle module.
"""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace

import httpx
import pytest

from src.agent.scope import runtime_scope
from src.llm.core.types import ChatRequest, FunctionCall, Message, ToolCall
from src.permission.runtime.execution import ExecutionBlocked
from src.tools.workflow.source_processing import read_admitted_source
from src.workflow.assessment import digest, source_row
from src.workflow.state import WorkflowObjective
from tests.helpers.agent_fakes import FakeSignal
from tests.helpers.burp_selection import make_runtime, ORIGIN

JS = b' ' * 5993 + b'fetch("/api/products");'
JS += b' ' * (8000 - len(JS))
REAL_HTTP_CLIENT = httpx.AsyncClient


async def invoke(rt, name, args, *, signal=None):
    call = ToolCall(f"bounded-{len(rt.agent.history)}", FunctionCall(name, json.dumps(args)))
    parsed = rt.agent.parse_tool_call(call)
    rt.agent._tool_call_event(call, parsed)
    rt.agent.history.append(Message("assistant", "", tool_calls=[call]))
    output = await rt.agent.run_parsed_tool_call(call, parsed, signal or FakeSignal())
    rt.agent.record_tool_result(call, parsed, output, lambda _: None, [], defer_admission=True)
    return output


async def native(tmp_path, monkeypatch, body=JS, *, cap=8000, media="application/javascript"):
    sent = []
    def handler(request):
        sent.append(request)
        return httpx.Response(200, content=body, headers={"Content-Type": media}, request=request)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: REAL_HTTP_CLIENT(transport=httpx.MockTransport(handler), **kw))
    rt = make_runtime(tmp_path)
    rt.registry = rt.agent.tools  # Readers are scoped to the concrete Agent.
    rt.sent = sent
    rt.workflow.objective = WorkflowObjective("bounded-discovery", "whole_target", ORIGIN)
    result = await invoke(rt, "http", {"url": "/main.js", "phase": "recon", "max_response_bytes": cap})
    assert not result.err_str, result.result
    source = next(iter(rt.workflow.discovery_sources.values()))
    result = await invoke(rt, "workflow", {"action": "select_source", "discovery_source_id": source.id})
    assert not result.err_str
    rt.source = rt.workflow.discovery_sources[source.id]
    rt.args = {"observation_id": source.retained_ref, "start_char": 0, "max_chars": 2000,
               "mode": "discovery", "discovery_source_id": source.id}
    return rt


async def read(rt, **changes):
    return await invoke(rt, "read_http_observation", {**rt.args, **changes})


def unpack(result):
    assert not result.err_str, result.result
    header, body = result.result.split("\n", 1)
    return json.loads(header), body


def rebind(rt, **changes):
    """Test independent rights checks after internally consistent tampering."""
    item = replace(rt.policy.observations._items[rt.args["observation_id"]], **changes)
    item = replace(item, retained_hash=digest(source_row(item)))
    rt.policy.observations._items[item.id] = item
    old = rt.source
    rt.source = replace(old, retained_hash=item.retained_hash, id="")
    rt.workflow.discovery_sources.pop(old.id)
    rt.workflow.discovery_sources[rt.source.id] = rt.source
    rt.args["discovery_source_id"] = rt.source.id
    return item


async def test_a03_a07_a09_a10_js_first_hit_exact_source_and_read_only(tmp_path, monkeypatch):
    rt = await native(tmp_path, monkeypatch)
    rt.workflow.discovery_provenance.clear()  # A reader must not repair missing graph links.
    before = deepcopy(rt.workflow.to_dict())
    facts = rt.workflow.progress_facts()
    revision = rt.workflow.committed_revision
    rights = rt.engagement.http_permissions
    budgets = [*rights._budgets.values(), *rights._exact_budgets.values()]
    assert budgets and sum(b.used for b in budgets) == 1
    budget = [(id(b), b.used, b.active) for b in budgets]
    result = await read(rt, needle="/api/products", max_chars=500)
    row, body = unpack(result)
    assert row["search"] == {"needle": "/api/products", "start_char": 0,
                             "match_char": 6000, "searched_end_char": 6013}
    assert row["start_char"] == 5920 and row["end_char"] == 6420
    assert body == JS.decode()[5920:6420]
    item = rt.policy.observations._items[rt.args["observation_id"]]
    assert row["observation_id"] == item.id and row["discovery_source_id"] == rt.source.id
    assert row["retained_hash"] == digest(source_row(item)) == rt.source.retained_hash
    assert row["body_sha256"] == hashlib.sha256(JS).hexdigest() == item.response_hash
    assert row["scope"] == runtime_scope(rt.agent)
    assert row["retained_bytes"] == row["source_chars"] == 8000
    assert row["next_start_char"] == 6420 and not row["retained_eof"]
    assert result.result.http_sources == ((item.id, item.retained_hash),)
    assert rt.agent.history[-1].content == result.result
    # Even missing graph links must not cause observation_handoff on read.
    assert rt.workflow.to_dict() == before and rt.workflow.progress_facts() == facts
    assert rt.workflow.committed_revision == revision
    assert budget == [(id(b), b.used, b.active) for b in [*rights._budgets.values(), *rights._exact_budgets.values()]]
    assert len(rt.sent) == 1 and not rt.agent.result_retention.references


@pytest.mark.parametrize("body,media", [
    ('<html><a href="/help">Help</a></html>', "text/html"),
    ('{"paths":["/api/products"],"example":{"q":"sample"}}', "application/json"),
    ('<root>ordinary XML</root>', "application/xml"), ("plain text", "text/plain"),
])
async def test_a10_generic_utf8_formats(tmp_path, monkeypatch, body, media):
    rt = await native(tmp_path, monkeypatch, body.encode(), media=media)
    row, excerpt = unpack(await read(rt))
    assert excerpt == body and row["retained_eof"] and row["complete"]
    assert not rt.workflow.attack_surface_inputs and not rt.workflow.validation_results


@pytest.mark.parametrize("needle,start,match", [
    ("api", 0, 5), ("api", 6, 14), ("API", 0, None), ("a.i", 0, None),
    ("%2F", 0, 19), ("/", 0, 0), ("é", 0, None), ("e\u0301", 0, 23),
])
async def test_a10_literal_first_suffix_no_decoding_or_normalization(tmp_path, monkeypatch, needle, start, match):
    text = "/* x api */ \" api\" %2F e\u0301"
    rt = await native(tmp_path, monkeypatch, text.encode())
    row, body = unpack(await read(rt, start_char=start, needle=needle, max_chars=20))
    expected = text.find(needle, start)
    # The slash in a comment is ordinary literal text, with no semantic claim.
    assert (expected if expected >= 0 else None) == match
    assert row["search"]["match_char"] == (expected if expected >= 0 else None)
    assert body == text[row["start_char"]:row["end_char"]]
    if expected < 0:
        assert body == "" and row["search"]["searched_end_char"] == len(text)
        assert row["start_char"] == row["end_char"] == len(text)
        assert row["retained_eof"] and row["next_start_char"] is None
    else:
        assert needle in body and row["search"]["searched_end_char"] == expected + len(needle)


async def test_a11_a12_unicode_pagination_actual_offsets_and_eof(tmp_path, monkeypatch):
    text = "\ufeff" + 'é🙂e\u0301\n"\\' * 900
    rt = await native(tmp_path, monkeypatch, text.encode(), cap=65536)
    offset, chunks = 0, []
    while True:
        result = await read(rt, start_char=offset)
        row, body = unpack(result)
        assert len(result.result) <= 2000 and row["offset_unit"] == "unicode_characters"
        assert row["retained_bytes"] == len(text.encode()) and row["source_chars"] == len(text)
        assert body == text[row["start_char"]:row["end_char"]]
        chunks.append(body)
        if row["next_start_char"] is None:
            assert row["retained_eof"] and row["complete"]
            break
        assert row["next_start_char"] > offset
        offset = row["next_start_char"]
    assert "".join(chunks) == text and len(rt.sent) == 1
    row, body = unpack(await read(rt, start_char=len(text)))
    assert not body and row["next_start_char"] is None
    assert (await read(rt, start_char=len(text) + 1)).status == "error"


@pytest.mark.parametrize("body,cap", [(b"\xff", 10), ("🙂".encode(), 3)])
async def test_a12_invalid_or_cap_split_utf8_is_unavailable(tmp_path, monkeypatch, body, cap):
    rt = await native(tmp_path, monkeypatch, body, cap=cap)
    result = await read(rt)
    assert result.status == "error" and result.error_kind == "reference_unavailable"
    assert len(rt.sent) == 1


async def test_a11_envelope_must_fit_hit_and_never_return_nonadvancing_page(tmp_path, monkeypatch):
    rt = await native(tmp_path, monkeypatch, ("é" * 80 + "x" * 4000).encode())
    for maximum in (1, 80, 2000):
        row, body = unpack(await read(rt, max_chars=maximum))
        assert 0 < len(body) <= maximum and row["next_start_char"] == len(body)
    needle = "\u0080" * 80  # Printable by the audited C0/DEL contract; JSON escaping is bounded.
    rt = await native(tmp_path / "escaped", monkeypatch, needle.encode() + b"x" * 4000)
    result = await read(rt, needle=needle)
    row, body = unpack(result)
    assert needle in body and len(result.result) <= 2000
    # Exercise exhausted envelope capacity without expanding the output cap.
    monkeypatch.setattr("src.tools.common.tool_result.MAX_READ_CHARS", 100)
    result = await read(rt, max_chars=80, needle=needle)
    assert result.error_kind == "reference_unavailable"


async def test_a13_retained_eof_is_distinct_from_original_response_complete(tmp_path, monkeypatch):
    rt = await native(tmp_path, monkeypatch, JS + b"UNRETAINED", cap=8000)
    row, body = unpack(await read(rt, start_char=7900))
    assert body == JS.decode()[7900:] and row["retained_eof"]
    assert not row["complete"] and row["adapter_truncated"]
    row, body = unpack(await read(rt, needle="UNRETAINED"))
    assert row["search"]["match_char"] is None and row["search"]["searched_end_char"] == 8000
    assert body == "" and not row["complete"] and row["next_start_char"] is None
    assert len(rt.sent) == 1


@pytest.mark.parametrize("fault", ["unselected", "foreign-source", "pair", "hash", "ref", "locator", "url",
    "origin", "objective", "restore", "session", "epoch", "body", "headers", "evicted", "http-revoked",
    "reader-revoked", "all-revoked", "origin-revoked", "denied", "workflow-tool", "http-tool", "reader-tool",
    "no-policy", "skill", "generic"])
async def test_a03_a04_a05_a13_rights_fail_closed_no_refetch(tmp_path, monkeypatch, fault):
    rt = await native(tmp_path, monkeypatch)
    oid = rt.args["observation_id"]
    item = rt.policy.observations._items[oid]
    if fault == "unselected": rt.workflow.discovery_sources[rt.source.id] = replace(rt.source, selected=False)
    elif fault == "foreign-source": rt.args["discovery_source_id"] = "ds_" + "f" * 64
    elif fault == "pair": rt.args["observation_id"] = "obs_" + "f" * 32
    elif fault in {"hash", "ref", "locator", "url", "origin", "objective"}:
        key = {"hash": "retained_hash", "ref": "retained_ref", "url": "document_url",
               "origin": "target_origin", "objective": "objective_id"}.get(fault, str(fault))
        # B must validate even bypassed frozen-dataclass corruption.
        object.__setattr__(rt.source, key, "f" * 64 if fault == "hash" else "wrong")
    elif fault == "restore": rt.workflow.discovery_restore_invalid = True
    elif fault == "session": rt.policy.session_id = "foreign-session"
    elif fault == "epoch": rt.engagement.http_permissions.epoch = "foreign-epoch"
    elif fault == "body": rt.policy.observations._items[oid] = replace(item, body=b"corrupt")
    elif fault == "headers": rt.policy.observations._items[oid] = replace(item, response_headers=(("location", "evil"),))
    elif fault == "evicted": rt.policy.observations._items.clear()
    elif fault.endswith("-revoked") and fault != "origin-revoked":
        rt.policy.revoke({"http-revoked": "http", "reader-revoked": "read_http_observation", "all-revoked": "*"}[fault])
    elif fault == "origin-revoked": rt.engagement.http_permissions._revoked.add(rt.target.origin())
    elif fault == "denied": rt.engagement.http_permissions.denied = True
    elif fault in {"workflow-tool", "http-tool", "reader-tool"}:
        rt.registry.tools[{"workflow-tool": "workflow", "http-tool": "http", "reader-tool": "read_http_observation"}[fault]] = SimpleNamespace()
    elif fault == "no-policy": rt.prompter.execution_policy = None
    elif fault == "skill":
        rt.agent.is_tool_allowed = lambda *a: SimpleNamespace(ok=False, reason="skill unavailable")
    elif fault == "generic":
        assert rt.policy.generic_validation is not None
        rt.policy.generic_validation.in_flight["bounded-generic"] = 1
    result = await read(rt)
    assert result.status == "error", fault
    assert "fetch(\"/api/products\")" not in result.result and len(rt.sent) == 1


@pytest.mark.parametrize("field,value", [("candidate_id", "candidate"), ("attempt_id", "attempt"),
    ("probe_binding", "probe"), ("candidate_binding", "binding"), ("source_kind", "imported-capture"),
    ("source_kind", "tool-output"), ("producer", "mcp"), ("producer", "content_discovery"),
    ("session_id", "foreign-session"), ("objective_id", "foreign-objective"),
    ("response_hash", "f" * 64), ("url", "http://other.test/main.js"),
    ("source_details", {"analysis_session": "burp-selection"}),
    ("source_details", {"analysis_session": "foreign", "body_representation": "bounded-native-decoded-bytes"})])
async def test_a06_owned_or_foreign_producers_never_borrow_discovery(tmp_path, monkeypatch, field, value):
    rt = await native(tmp_path, monkeypatch)
    rebind(rt, **{field: value})
    result = await read(rt)
    assert result.status == "error" and len(rt.sent) == 1


async def test_a04_direct_and_no_objective_runtime_reject_discovery(tmp_path, monkeypatch):
    rt = await native(tmp_path, monkeypatch)
    for objective in (WorkflowObjective("direct", "direct", ORIGIN), None):
        rt.workflow.objective = objective
        assert (await read(rt)).status == "error"
    assert len(rt.sent) == 1


async def test_a05_receipt_default_and_controller_required(tmp_path, monkeypatch):
    rt = await native(tmp_path, monkeypatch)
    with pytest.raises(ExecutionBlocked, match="receipt"):
        read_admitted_source(rt.agent, rt.workflow_tool, rt.source, rt.prompter)
    assert read_admitted_source(rt.agent, rt.workflow_tool, rt.source, rt.prompter,
                                require_receipt=False).id == rt.args["observation_id"]
    reader = rt.registry.get("read_http_observation")
    with pytest.raises(ExecutionBlocked):
        await reader.run(rt.args, FakeSignal(), rt.prompter)
    rt.policy.revoke("http")
    with pytest.raises(ExecutionBlocked):
        read_admitted_source(rt.agent, rt.workflow_tool, rt.source, rt.prompter, require_receipt=False)


@pytest.mark.parametrize("changes,remove", [
    ({"mode": None}, ()), ({"mode": "owned"}, ()), ({"needle": None}, ()),
    ({"needle": ""}, ()), ({"needle": "a" * 81}, ()), ({"needle": "a\n"}, ()),
    ({"needle": "\x7f"}, ()), ({"needle": "\ud800"}, ()), ({"needle": True}, ()),
    ({"needle": "abc", "max_chars": 2}, ()), ({"needle": "abc"}, ("mode",)),
    ({}, ("mode",)), ({}, ("discovery_source_id",)), ({"discovery_source_id": None}, ()),
    ({"discovery_source_id": "tr_wrong"}, ()), ({"observation_id": "obs_bad"}, ()),
    ({"start_char": True}, ()), ({"start_char": None}, ()), ({"start_char": -1}, ()),
    ({"max_chars": True}, ()), ({"max_chars": None}, ()), ({"max_chars": 2001}, ()),
    ({"max_chars": 0}, ()), ({"extra": "ignored?"}, ()), ({}, ("start_char",)),
])
async def test_a02_invalid_args_before_review_or_receipt(tmp_path, monkeypatch, changes, remove):
    rt = await native(tmp_path, monkeypatch)
    rt.prompter.set_yolo(False)
    args = {**rt.args, **changes}
    for key in remove: args.pop(key)
    rt.operator.requests.clear()
    result = await invoke(rt, "read_http_observation", args)
    assert result.error_kind == "invalid_args", result.result
    assert not rt.operator.requests and rt.policy.active == 0 and len(rt.sent) == 1


@pytest.mark.parametrize("placement", ["outside", "split", "needle", "client-key"])
async def test_a17_secret_screening_precedes_slice_search_and_permission(tmp_path, monkeypatch, placement):
    secret = "controller-managed-internal-secret"
    text = "safe" + "x" * 3000 + (secret if placement != "needle" else "ordinary text")
    rt = await native(tmp_path, monkeypatch, text.encode())
    if placement == "client-key": rt.agent.client.api_key = secret
    else: rt.policy.internal_secret_values = lambda: (secret,)
    rt.prompter.set_yolo(False)
    for start in (0, 3004, 3012):
        result = await read(rt, start_char=start, max_chars=8 if placement != "needle" else 80,
                            **({"needle": secret} if placement == "needle" else {}))
        assert result.status == "error" and secret not in result.result
    assert not rt.operator.requests and len(rt.sent) == 1


@pytest.mark.parametrize("provider", ["openai", "deepseek", "anthropic", "gemini"])
async def test_a01_mode_schema_encoders_and_cache(tmp_path, monkeypatch, provider):
    from src.llm.providers import anthropic, gemini
    from src.llm.providers.openai import OpenAIClient
    rt = await native(tmp_path, monkeypatch)
    reader = rt.registry.get("read_http_observation")
    rt.agent.tools_token_estimate()
    discovery_key = rt.agent.tools_tokens_key
    schema = reader.schema()
    assert schema["required"] == ["observation_id", "start_char", "max_chars"]
    assert not schema["additionalProperties"] and not {"oneOf", "if", "then"} & schema.keys()
    specs = [spec for spec in rt.registry.as_llm_tools() if spec["function"]["name"] == reader.name()]
    before = deepcopy(specs)
    req = ChatRequest("fixture", [Message("user", "next")], tools=specs)
    if provider in {"openai", "deepseek"}:
        client = OpenAIClient("https://fixture.invalid", "synthetic", "fixture", provider_name=provider)
        encoded = client.encode_request(req, False)["tools"][0]["function"]["parameters"]
    elif provider == "anthropic": encoded = anthropic.encode_request(req, "fixture")["tools"][0]["input_schema"]
    else: encoded = gemini.encode_request(req)["tools"][0]["functionDeclarations"][0]["parameters"]
    assert specs == before
    assert encoded["properties"]["mode"]["enum"] == ["discovery"]
    for objective in (WorkflowObjective("direct", "direct", ORIGIN), None):
        rt.workflow.objective = objective
        rt.agent.tools_token_estimate()
        assert rt.agent.tools_tokens_key != discovery_key
        assert set(reader.schema()["properties"]) == {"observation_id", "start_char", "max_chars"}
        assert "mode=discovery" not in reader.description()
