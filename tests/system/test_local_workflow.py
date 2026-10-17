"""Real loopback HTTP -> Agent -> registry -> evidence -> finding -> TUI/resume."""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import replace
from pathlib import Path

import pytest
from textual import events

from tests.helpers.scenarios import FakeTransport
from tests.helpers.system_runtime import (
    assert_idle, assert_wire, drain, heartbeat, lab_definition, make_system_app, prepare_lab,
)


@pytest.mark.parametrize("mode", ["whole_target", "direct"])
async def test_local_pipeline_with_tui_and_fresh_resume(tmp_path, monkeypatch, local_lab, mode, record_property):
    scenario = lab_definition(local_lab, mode=mode)
    runner, runtime, traffic = prepare_lab(tmp_path, monkeypatch, local_lab, scenario)
    metrics = {}
    async def drive(rt, definition, trace):
        app = make_system_app(rt, trace)
        async with app.run_test(size=(100, 32)) as pilot:
            async def operator():
                while True:
                    if app.state.pending_perm is not None:
                        metrics["permission_reviews"] = metrics.get("permission_reviews", 0) + 1
                        began = time.monotonic()
                        await app._process_key(events.Key("y", "y"))
                        metrics["key_handler_max_ms"] = max(metrics.get("key_handler_max_ms", 0),
                                                            (time.monotonic() - began) * 1000)
                    await asyncio.sleep(0.002)
            controller = asyncio.create_task(operator(), name="lab-operator")
            try:
                async with heartbeat(metrics, label=mode):
                    app.submit(definition.user_input)
                    task = app.run_task
                    assert task is not None
                    await task
                assert_idle(app)
                assert not rt.bridge._busy and not rt.bridge._waiters and rt.bridge._visible is None
                assert any(entry.kind == "user" for entry in app.state.transcript)
                assert any(event["type"] == "tool-result" for event in trace.events)
                assert any(entry.kind in {"validation", "finding", "info"} for entry in app.state.transcript)
                await pilot.press("x")
                assert app.input.value.endswith("x")
                metrics["ui_recovered"] = True
            finally:
                controller.cancel()
                await asyncio.gather(controller, return_exceptions=True)
    try:
        run = await runner.run(scenario, runtime=runtime, transport=traffic, drive=drive)
        assert_wire(traffic, local_lab.origin)
        assert metrics["permission_reviews"] > 0
        fresh = await runner.resume(run)
        assert fresh.workflow is not runtime.workflow
        assert not fresh.engagement.http_permissions.grants
        assert len(list((tmp_path / "artifacts/findings").glob("*.md"))) == 1
        metrics.update(requests=len(traffic.sent), calls=len(run.model.calls), elapsed_ms=run.elapsed * 1000)
    finally:
        await drain(runtime)
    # Workflow/ownership, resumed state, real input recovery and owned cleanup
    # determine this system verdict. Raw heartbeat is diagnostic, not a budget.
    metrics["functional_lifecycle_verdict"] = "passed"
    record_property("system_metrics", json.dumps(metrics))
    (tmp_path / "system-metrics.json").write_text(json.dumps(metrics, indent=2))


async def test_twenty_independent_direct_runs_leave_no_tasks_or_cross_session_state(tmp_path, monkeypatch, local_lab, record_property):
    measurements = []
    initial_tasks = asyncio.all_tasks()
    try:
        for index in range(20):
            local_lab.wire.clear()
            root = tmp_path / str(index)
            root.mkdir()
            scenario = replace(lab_definition(local_lab, mode="direct"), id=f"repeat-{index}")
            runner, runtime, traffic = prepare_lab(root, monkeypatch, local_lab, scenario)
            metrics = {}
            try:
                async with heartbeat(metrics):
                    run = await runner.run(scenario, runtime=runtime, transport=traffic)
                assert_wire(traffic, local_lab.origin)
                await runner.resume(run)
                assert len(runtime.workflow.candidates) == 1
                assert not list(root.rglob("*.tmp.*"))
                measurements.append(metrics)
            finally:
                await drain(runtime)
            await asyncio.sleep(0)
            assert not local_lab.tasks and not local_lab.writers
            assert not [task for task in asyncio.all_tasks() - initial_tasks if not task.done()]
    finally:
        record_property("repeatability", json.dumps({"completed": len(measurements), "runs": measurements}))
