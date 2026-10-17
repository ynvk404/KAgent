"""System adapters over the existing scenario runner, runtime and oracles."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import replace
import logging
import time
from typing import Any

import httpx

from src.permission.permission import YoloPrompter
from src.ui.bridges.perm_bridge import BridgedPrompter
from src.ui.core.app import AppProps, KAgent
from src.ui.core.state import AgentEventAction, SetPerm
from src.ui.widgets.banner import BannerData
from tests.helpers.scenarios import FakeTransport, ScenarioRunner
from tests.helpers.ui_fakes import make_test_config_snapshot
from tests.scenarios.test_happy_paths import definition


def lab_definition(lab, *, mode="whole_target", outcome="confirmed", **kwargs):
    scenario = definition(id="lab-" + mode, mode=mode, origin=lab.origin, outcome=outcome, **kwargs)
    # End-to-end watchdog includes real TUI mounting and all durable checkpoints.
    # Heartbeat is a system diagnostic; dedicated responsiveness tests keep
    # their own strict limits, separate from this hang/lifecycle watchdog.
    return replace(scenario, timeout=60, user_input=scenario.user_input +
        " Research/system testing only. Scope is exactly this disposable loopback origin."
        " No external target, destructive action, persistence on target, stealth or real data.")


def prepare_lab(root, monkeypatch, lab, scenario):
    runner = ScenarioRunner(root, monkeypatch, defer_trace_redaction=True)
    traffic = FakeTransport(scenario)
    # This ledger is filled by the real server, never by MockTransport.
    assert not lab.wire
    traffic.sent = lab.wire
    if scenario.mode == "whole_target":
        for index in (0, 1):
            args, _ = traffic.expected[index]
            traffic.expected[index] = (args, (200, lab.render("/", {}, {})[1], "text/html"))
        traffic.expected[2] = ({"url": "/robots.txt", "method": "GET"},
                               (200, b"User-agent: *\nDisallow: /hidden\n", "text/plain"))
    runtime, _ = runner.prepare(scenario, transport=traffic, mock_transport=False)
    return runner, runtime, traffic


def assert_wire(traffic, origin):
    assert len(traffic.sent) == len(traffic.expected)
    for actual, (args, (status, body, _)) in zip(traffic.sent, traffic.expected):
        expected = httpx.Request(args["method"], origin + args["url"], content=args.get("body", ""))
        assert (actual["method"], actual["url"], actual["body"]) == (
            expected.method, str(expected.url), expected.content.decode())
        assert (actual["status"], actual["response"]) == (status, body)


def make_system_app(runtime, trace=None):
    async def apply_provider(change):
        raise AssertionError("system scenario must not switch to a real provider")

    app = KAgent(AppProps(
        agent=runtime.agent, banner_data=BannerData(provider="offline", model="deterministic", cwd=str(runtime.policy.root)),
        parent_signal=asyncio.Event(), read_config=lambda: make_test_config_snapshot(),
        apply_provider=apply_provider,
    ))
    bridge = BridgedPrompter(lambda request: app.dispatch(SetPerm(request)))
    prompter = YoloPrompter(bridge, False)
    prompter.bind_execution_policy(runtime.policy)
    runtime.prompter = runtime.agent.prompter = prompter
    runtime.bridge = bridge
    if trace is not None:
        original = app.dispatch
        def dispatch(action):
            if isinstance(action, AgentEventAction):
                trace.record(action.event)
            original(action)
        app.dispatch = dispatch
    return app


def assert_idle(app):
    assert not app.state.busy and not app.agent.is_running()
    assert app.run_abort_event is None and app.run_task is None
    assert app.state.pending_perm is None and app.state.pending_ask is None
    assert not app._elapsed_active and app._elapsed_timer is None
    assert not app.agent._background_tasks


async def wait_until(predicate, timeout=2):
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.002)


@asynccontextmanager
async def heartbeat(metrics: dict[str, Any], *, label: str = "system"):
    beats = [time.monotonic()]
    async def tick():
        while True:
            await asyncio.sleep(0.01)
            beats.append(time.monotonic())
    task = asyncio.create_task(tick(), name="system-heartbeat")
    try:
        yield
    finally:
        beats.append(time.monotonic())
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        metrics.update(heartbeat_ticks=len(beats) - 2,
                       heartbeat_gap_ms=max(b-a for a,b in zip(beats, beats[1:])) * 1000,
                       heartbeat_window=[beats[0], beats[-1]],
                       heartbeat_slow_gaps=[[a, b] for a, b in zip(beats, beats[1:]) if b-a >= 0.12])
        metrics.update(heartbeat_diagnostic_limit_ms=120,
                       heartbeat_warning=metrics["heartbeat_gap_ms"] >= 120)
        if metrics["heartbeat_warning"]:
            logging.getLogger(__name__).warning(
                "%s: diagnostic heartbeat gap %.1f ms exceeds 120 ms",
                label, metrics["heartbeat_gap_ms"],
            )


async def drain(runtime):
    # Mirror runtime ownership shutdown, including offloaded writes.
    from src.agent.ownership import join, retire
    task = retire(runtime.agent)
    if task is not None:
        await join(task)
    if runtime.agent._background_tasks:
        await asyncio.gather(*tuple(runtime.agent._background_tasks))
    if runtime.policy.scanner_runtime is not None:
        await runtime.policy.scanner_runtime.drain(close=True)
    assert not runtime.agent.running and not runtime.agent._background_tasks
    assert runtime.policy.active == 0 and not runtime.policy._active_receipts
