"""Offline lan-04 regression: visible document fields precede more discovery.

Scripted calls verify guidance delivery and contracts, not model compliance.
"""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from src.llm.core.types import ChatRequest, ChatResponse, Message
from src.workflow.state import WorkflowObjective, WorkflowState
from tests.agent.test_workflow_request_preparation import SnapshotClient, block, setup
from tests.helpers.agent_fakes import FakeSignal
from tests.helpers.workflow import record_completed_phase


@pytest.mark.parametrize("restored", [False, True])
async def test_unselected_sources_do_not_suppress_incremental_handoff_advice(tmp_path, restored):
    # lan-04 had Recon complete, zero inputs, eight unselected sources. The
    # model had read the inline Order schema but the next advice stayed generic.
    from src.workflow.discovery.inventory import SourceRecord

    origin = "https://fixture.test"
    state = WorkflowState(objective=WorkflowObjective("lan04-offline", "whole_target", origin))
    recon = "artifacts/recon/fixture-test/summary.md"
    path = tmp_path / recon
    path.parent.mkdir(parents=True)
    path.write_text("# Offline recon fixture", encoding="utf-8")
    record_completed_phase(state, "recon", objective_id="lan04-offline", target_origin=origin,
                           artifact_ref=recon)
    for index in range(8):
        state.admit_discovery(SourceRecord("lan04-offline", origin, "http",
            f"obs_fixture_{index}", "a" * 64))
    if restored:
        state = WorkflowState.from_dict(state.to_dict())
    client = SnapshotClient([ChatResponse(Message("assistant", "offline"), "stop") for _ in range(2)])
    agent = setup(tmp_path, client, state)
    agent.active_skills = {"web-enumeration"}
    before = deepcopy(state.to_dict())
    # Content supplied by the offline test, as the successfully read lan-04
    # document did; no parser or automatic input inference is being tested.
    visible = Message("tool", 'OpenAPI: servers=/b2b/v2; POST /orders; '
                      'requestBody application/json -> Order; Order.cid:string required',
                      name="read_tool_result", tool_call_id="fixture-review")
    for text in ("Continue from this document.", "Continue."):
        req = ChatRequest(client.model(), [visible, Message("user", text)], tools=agent.tools.as_llm_tools())
        await agent._chat_for_turn(req, FakeSignal(), lambda event: None)
        advice = block(client.requests[-1], "Workflow action guidance:")
        assert 'workflow(action="record_input"' in advice
        assert "before fetching another resource" in advice
        assert "observed method, endpoint, parameter and location" in advice
        assert "document attribution" in advice and "not request context" in advice
        assert "partial inventory" in advice and "all JavaScript bundles" in advice
        assert "observed" in advice and "performed" in advice
        assert "complete_skill" in advice
        assert client.requests[-1].messages[-1].content == text
    assert state.to_dict() == before
    assert not state.attack_surface_inputs and not state.candidates
    assert not list(tmp_path.glob("artifacts/web-enumeration/**/inventory.md"))


async def test_document_inputs_inventory_and_honest_coverage_complete_after_continue(tmp_path):
    from tests.helpers.discovery_calls import captured, execute, attribution
    from tests.helpers.burp_selection import ORIGIN

    # Literal document from lan-04, supplied as an offline capture. This does
    # not claim that lan-04's shell observations were admitted HTTP sources.
    document = (Path(__file__).resolve().parents[1] / "fixtures/lan04-openapi.json").read_text()
    spec = json.loads(document)
    assert spec["servers"][0]["url"] == "/b2b/v2"
    assert "post" in spec["paths"]["/orders"]
    assert set(spec["components"]["schemas"]["Order"]["properties"]) == {
        "cid", "orderLines", "orderLinesData"}
    runtime, source = await captured(tmp_path, document)
    recon = "artifacts/recon/127-0-0-1-3000/summary.md"
    await execute(runtime, "file_write", {"path": str(tmp_path / recon), "content": "# Offline recon fixture"})
    record_completed_phase(runtime.workflow, "recon", objective_id="discovery", target_origin=ORIGIN,
                           artifact_ref=recon)
    await execute(runtime, "load_skill", {"name": "web-enumeration"})
    client = SnapshotClient([ChatResponse(Message("assistant", "offline"), "stop") for _ in range(2)])
    runtime.agent.set_client(client)

    async def request_advice():
        req = ChatRequest(client.model(), [Message("user", "Continue.")], tools=runtime.registry.as_llm_tools())
        await runtime.agent._chat_for_turn(req, FakeSignal(), lambda event: None)
        return block(client.requests[-1], "Workflow action guidance:")

    assert "before fetching another resource" in await request_advice()
    for name, kind in (("cid", "string"), ("orderLines", "array"), ("orderLinesData", "string")):
        accepted = json.loads((await execute(runtime, "workflow", {
            "action": "record_input", "method": "POST", "endpoint": "/b2b/v2/orders",
            "parameter": name, "location": "json", "input_type": kind, "content_type": "application/json",
            "source_attribution": attribution(source, f"/components/schemas/Order/properties/{name}"),
        })).result)
        assert accepted["attribution_kind"] == "manual_declaration"
        assert accepted["input"]["source_ref"] is accepted["input"]["baseline_request_ref"] is None
    # Persist/restore canonical state before the next request, with no discovery
    # rerun and no permission or bytes gained from historical metadata.
    await runtime.agent.save()
    runtime.workflow.replace_from(runtime.store.load().workflow)
    assert "partial inventory" in await request_advice()
    # Continue must re-admit the skill contract; persisted state grants no tools.
    await execute(runtime, "load_skill", {"name": "web-enumeration"})
    assert not runtime.workflow_tool.phase_completion_readiness("web-enumeration")["ready"]
    inventory = "artifacts/web-enumeration/127-0-0-1-3000/inventory.md"
    await execute(runtime, "file_write", {"path": str(tmp_path / inventory), "content": (
        "# Partial documented inventory\nPOST /b2b/v2/orders: JSON cid:string, orderLines:array, orderLinesData:string.\n"
        f"Document attribution: {source.id}; {source.retained_ref}.\n"
        "Documented only; endpoint reachability/authentication unknown. Nested orderLine fields not recorded in this fixture.\n"
        "SPA bundles not reviewed; broader endpoint coverage remains unknown.\n")})
    assert not runtime.workflow_tool.phase_completion_readiness("web-enumeration")["ready"]
    for dimension, status, reason in (
        ("api_documentation", "observed", "Manually reviewed captured OpenAPI Order schema; no machine attestation"),
        ("browser_burp_capture", "observed", "Reviewed offline captured document; no live browser navigation"),
        ("html_navigation", "skipped", "Only the supplied document reviewed; HTML navigation omitted"),
        ("standard_metadata", "skipped", "Metadata requests omitted in this bounded document review"),
        ("javascript_endpoint_extraction", "skipped", "SPA bundle review omitted; endpoints beyond supplied document unknown"),
        ("active_content_discovery", "skipped", "Bounded review of supplied document only; no active path discovery performed"),
    ):
        await execute(runtime, "workflow", {"action": "record_phase_coverage", "phase": "enumeration",
            "coverage_dimension": dimension, "coverage_status": status, "coverage_reason": reason})
    assert runtime.workflow_tool.phase_completion_readiness("web-enumeration")["ready"]
    assert all(row.status != "performed" for row in runtime.workflow.phase_coverage["discovery:enumeration"].values())
    await execute(runtime, "workflow", {"action": "complete_skill", "skill_name": "web-enumeration",
                                       "artifact_ref": inventory, "current_phase": "analysis"})
    assert "web-enumeration" in runtime.workflow.completed_skills
    assert runtime.agent._planner_context().structured_phase == "input_analysis"
    assert {item.parameter for item in runtime.workflow.objective_inputs()} == {"cid", "orderLines", "orderLinesData"}
    assert all(item.disposition == "pending" for item in runtime.workflow.objective_inputs())
    assert not runtime.workflow.candidates and not runtime.workflow.attempts and not runtime.workflow.evidence
    assert not runtime.workflow.discovery_sources[source.id].selected
