"""Explicit opt-in characterization; deterministic system tests remain the oracle.

KAGENT_SYSTEM_LIVE=1 permits the saved provider's API only. The Agent's only
network tool is native HTTP with exact lab-origin admission; no shell/web/MCP.
"""
import asyncio
import json
import os
from pathlib import Path

import pytest

from src.config.config import load
from src.llm.runtime.provider_runtime import build_startup_runtime
from src.permission.network.grants import HTTPLimits
from tests.helpers.agent_fakes import FakeSignal
from tests.helpers.local_lab import LocalLab
from tests.helpers.scenario_oracle import InvariantOracle, TraceRecorder
from tests.helpers.system_runtime import drain, lab_definition, prepare_lab


@pytest.mark.skipif(os.getenv("KAGENT_SYSTEM_LIVE") != "1", reason="live system validation requires explicit KAGENT_SYSTEM_LIVE=1")
async def test_saved_provider_against_disposable_local_target(tmp_path, monkeypatch, record_property):
    cfg = load()
    if not cfg.backend and not cfg.active_custom_provider_id:
        pytest.skip("no saved provider configured")
    provider = build_startup_runtime(cfg, custom_provider_id=cfg.active_custom_provider_id)
    lab = LocalLab()
    await lab.start()
    rt = None
    try:
        await lab.ready()
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("KAGENT_PROJECT_ROOT", str(tmp_path))
        scenario = lab_definition(lab)
        _, rt, _ = prepare_lab(tmp_path, monkeypatch, lab, scenario)
        rt.agent.set_client(provider.client)
        rt.agent.set_max_steps(60)
        rt.engagement.http_permissions.activate(lab.origin, HTTPLimits(requests=60, rate=5, burst=5, concurrency=1))
        rt.policy.internal_secret_values = lambda: tuple(value for value in (
            *provider.config.api_keys.values(), *cfg.custom_provider_api_keys.values()) if value)
        oracle = InvariantOracle(tmp_path)
        trace = TraceRecorder(rt, oracle)
        try:
            await asyncio.wait_for(rt.agent.run(scenario.user_input, FakeSignal(), trace.record), 180)
            await rt.agent.save()
            oracle.boundary(rt, "live-finished")
            assert not trace.errors
            assert not rt.agent.running and rt.policy.active == 0
            assert rt.target.base_url() == lab.origin
            assert {origin.as_url() for origin in rt.engagement.allowed_origins} == {lab.origin}
            for item in rt.policy.observations._items.values():
                assert any(row["url"] == item.url and row["status"] == item.status for row in lab.wire)
            for candidate_id in rt.workflow.persisted_findings:
                result = rt.workflow.latest_result(candidate_id)
                assert result is not None and result.outcome == "confirmed" and result.evidence_manifest
                for entry in result.evidence_manifest:
                    source = entry["source"]
                    assert source["complete"] and not source["truncated"]
                    assert any(row["url"] == source["url"] and row["status"] == source["status"]
                               and row["response"] == bytes.fromhex(source["body"]) for row in lab.wire)
            text = "\n".join(message.content for message in rt.agent.history if message.role == "assistant").lower()
            declined = any(marker in text for marker in ("cannot assist with penetration", "can't assist with penetration", "against my policy", "cannot help with hacking"))
            status = "model-policy-behavior" if declined else "completed" if oracle.independently_complete(rt) else "model-incomplete"
            result = {"status": status, "requests": len(lab.wire), "findings": len(rt.workflow.persisted_findings),
                      "runtime_errors": sum(event["type"] == "error" for event in trace.events)}
            (tmp_path / "live-result.json").write_text(json.dumps(result, indent=2))
            record_property("live_system_validation", json.dumps(result))
            assert not result["runtime_errors"], "provider/runtime error; inspect sanitized trace"
            if status != "completed":
                pytest.skip(status + "; runtime invariants checked, no claim of successful assessment")
            loaded = rt.store.load()
            assert loaded.workflow.to_dict() == rt.workflow.to_dict()
            assert len(list((tmp_path / "artifacts/findings").glob("*.md"))) == 1
        finally:
            trace.write(tmp_path / "live-trace.json")
    finally:
        if rt is not None:
            await drain(rt)
        await lab.close()
