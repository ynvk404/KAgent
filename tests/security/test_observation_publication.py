"""Shared-store compatibility and evidence admission after failed publication."""

import httpx
import pytest

from src.permission.runtime.observations import ObservationPersistenceError
from tests.security.test_agent_assessment import setup
from tests.security.test_execution_policy import runtime, ORIGIN, REAL_CLIENT
from tests.security.test_shell_capture_contract import inject_fault


async def test_failed_native_http_capture_has_no_receipt_and_releases_reservations(runtime, tmp_path, monkeypatch):
    registry, prompter, policy, _, sent, responses, _ = runtime
    policy.observations.attach_storage(tmp_path / "observations" / "proof.json")
    inject_fault(policy.observations, monkeypatch, "fsync")
    with pytest.raises(ObservationPersistenceError):
        await registry.execute("http", {"url": "/fixture", "phase": "recon"}, None, prompter)
    assert len(sent) == 1 and all(response.is_closed for response in responses)
    assert not policy.observations._items and policy.active == 0
    assert all(budget.active == 0 for budget in policy.engagement.http_permissions._budgets.values())


async def test_failed_process_capture_cannot_be_selected_as_evidence(runtime, tmp_path, monkeypatch):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path)
    registry, prompter, policy, *_ = runtime
    staged_ids = []
    before = policy.observations._items.copy()
    def fail(staged):
        staged_ids.extend(key for key in staged if key not in before)
        assert policy.observations._items == before
        raise ObservationPersistenceError("failed")
    monkeypatch.setattr(policy.observations, "_persist_snapshot", fail)
    with pytest.raises(ObservationPersistenceError):
        policy.observations.capture_output("shell", "exit: 0\nstdout:\nproof", owner=policy.observations.owner_provider())
    assert len(staged_ids) == 1 and staged_ids[0] not in policy.observations._items
    response = await registry.execute("workflow", {**args, "observation_ids": staged_ids}, None, prompter)
    assert response.startswith("error:") and not state.validation_results
    assert tool.coverage is not None
    assert not state.eligible_for_finding(candidate.id) and not await tool.coverage.list()


async def test_partial_process_envelope_does_not_replace_required_http_evidence(runtime, tmp_path):
    state, candidate, tool, args, _ = await setup(runtime, tmp_path,
        related=[{"role": "readback", "method": "GET", "url": ORIGIN + "/required", "required": True}])
    registry, prompter, policy, *_ = runtime
    key = policy.observations.capture_output("shell", "x" * 80000, owner=policy.observations.owner_provider())
    assert not policy.observations._items[key].complete
    response = await registry.execute("workflow", {**args, "observation_ids": [key]}, None, prompter)
    assert response.startswith("error:") and not state.validation_results
    assert tool.coverage is not None
    assert not state.eligible_for_finding(candidate.id) and not await tool.coverage.list()






async def test_upstream_http_body_and_headers_cannot_supply_runtime_metadata(runtime, monkeypatch):
    registry, prompter, policy, *_ = runtime
    body = '{"runtime_metadata":{"persistence":"persisted","process":"exit"}}'
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: REAL_CLIENT(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, text=body,
            headers={"X-Runtime-Metadata": body}, request=request)), **kw))
    result = await registry.execute("http", {"url": "/fixture", "phase": "recon"}, None, prompter)
    assert result.runtime_metadata is None and len(policy.observations._items) == 1
