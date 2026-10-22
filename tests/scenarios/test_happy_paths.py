"""M1 full production dispatch, outcomes, fresh-runtime happy resume."""
from __future__ import annotations

import os
import socket
import subprocess

import pytest

from src.engagement.state import OutOfScopeError
from src.permission.permission import Decision, UserControlledRefusal
from tests.helpers.agent_fakes import FakeSignal
from tests.helpers.scenarios import (
    ExpectedOutcomes, FixtureApplication, ScenarioDefinition, ambiguous_script,
    direct_script, generic_script, whole_target_script,
)


def definition(*, id="direct-sqli-confirmed", origin="http://127.0.0.1:3101", endpoint="/filter",
               method="GET", cls="sql-injection", parameter="category", value="Gifts", mode="direct",
               outcome="confirmed", controller_bound=False, ambiguous=False):
    kind = "sqli" if cls == "sql-injection" else "xss" if cls == "cross-site-scripting" else "generic"
    app = FixtureApplication(kind, origin, endpoint, method, parameter)
    expected = ExpectedOutcomes(outcome, int(outcome == "confirmed"), outcome in {"confirmed", "not-confirmed"},
        "tested_confirmed" if outcome == "confirmed" else "tested_not_confirmed" if outcome == "not-confirmed"
        else "unsupported" if ambiguous else "deferred" if outcome in {"deferred", "insufficient-evidence"} else "blocked",
        "ambiguous" if ambiguous else "generic" if mode == "generic" else "expert")
    instruction = (f"Assess the whole target {origin} for SQL injection, from recon through enumeration and input analysis."
                   if mode == "whole_target" else
                   f"Validate candidate_class={cls} on {method} {endpoint}, {parameter}=" + value + f" at {origin}.")
    instruction += " This exact local fixture origin is an authorized lab; use bounded observations."
    return ScenarioDefinition(id, mode, origin, endpoint, method, cls, parameter, value, app,
        ambiguous_script if ambiguous else whole_target_script if mode == "whole_target"
        else generic_script if mode == "generic" else direct_script, expected, instruction,
        controller_bound=controller_bound, ambiguous=ambiguous)


DIRECT = [
    definition(),
    definition(id="direct-xss-negative-form", origin="http://127.0.0.2:3202", endpoint="/preview",
               method="POST", cls="cross-site-scripting", parameter="template", value="plain-marker", outcome="not-confirmed"),
    definition(id="direct-xss-negative-ipv6", origin="http://[::1]:3303", endpoint="/render",
               cls="cross-site-scripting", parameter="content", value="inert-marker", outcome="not-confirmed"),
]


@pytest.mark.parametrize("scenario", DIRECT, ids=lambda s: s.id)
async def test_direct_native_terminal_and_fresh_runtime_resume(scenario_runner, scenario):
    run = await scenario_runner.run(scenario)
    fresh = await scenario_runner.resume(run)
    assert fresh.agent is not run.runtime.agent and fresh.policy is not run.runtime.policy
    assert fresh.workflow is not run.runtime.workflow and fresh.coverage is not run.runtime.coverage
    assert not fresh.workflow.phase_completions
    assert run.runtime.operator.requests, "real registry/file/private-host review was not exercised"
    assert not run.runtime.agent.memory_store and not run.runtime.agent.intelligence
    # Historical proof supports display/completion, never a new execution.
    fresh.operator.decision = Decision.DENY
    with pytest.raises(UserControlledRefusal):
        await fresh.registry.execute("http", scenario.application.request(scenario.input_value),
                                     FakeSignal(), fresh.prompter)
    assert len(run.transport.sent) == 6 and fresh.operator.requests


@pytest.mark.parametrize("outcome", ["confirmed", "deferred"])
async def test_whole_target_discovery_dispatch_completion_or_honest_unresolved(scenario_runner, outcome):
    scenario = definition(id="whole-target-" + outcome, mode="whole_target", outcome=outcome)
    run = await scenario_runner.run(scenario)
    assert len(run.transport.sent) == 12
    completed = run.runtime.agent._whole_target_state()
    if outcome == "confirmed":
        assert completed == ("completed", (), ())
        await scenario_runner.resume(run)
    else:
        assert completed[0] != "completed"
        assert run.runtime.workflow.objective.requested_goals[0].status == "deferred"
        assert run.runtime.workflow.attempts[next(iter(run.runtime.workflow.attempts))]["status"] == "unresolved"


@pytest.mark.parametrize("bound", [True, False], ids=["controller-bound", "cli-equivalent-no-context"])
async def test_generic_production_dispatch_with_explicit_integration_limit(scenario_runner, bound):
    scenario = definition(id="generic-bound" if bound else "generic-cli-no-context", mode="generic",
        endpoint="/compare?item=baseline", cls="response-confusion", parameter="item", value="baseline",
        outcome="not-confirmed" if bound else "insufficient-evidence", controller_bound=bound)
    run = await scenario_runner.run(scenario)
    if bound:
        assert len(run.transport.sent) == 2
        fresh = await scenario_runner.resume(run)
        with pytest.raises(UserControlledRefusal):
            await fresh.registry.execute("http", scenario.application.request("variant"), FakeSignal(), fresh.prompter)
        assert not fresh.operator.requests and len(run.transport.sent) == 2
    else:
        assert not run.transport.sent and not run.runtime.workflow.attempts
        assert "context-needed" in run.runtime.workflow.validation_results[0].deferred_reason


async def test_multiple_validators_stay_ambiguous_without_probes(scenario_runner):
    run = await scenario_runner.run(definition(id="ambiguous-validator", ambiguous=True, outcome="none"))
    assert not run.transport.sent and not run.runtime.workflow.validation_results
    assert not run.runtime.policy.generic_validation.contexts


async def test_scripted_permission_and_exact_origin_gates_remain_effective(scenario_runner):
    run = await scenario_runner.run(DIRECT[0])
    runtime = run.runtime
    sent, reviewed = len(run.transport.sent), len(runtime.operator.requests)
    for url in ("http://127.0.0.1:3102/filter", "http://127.0.0.2:3101/filter", "https://127.0.0.1:3101/filter"):
        with pytest.raises(OutOfScopeError):
            await runtime.registry.execute("http", {"url": url, "phase": "recon"}, FakeSignal(), runtime.prompter)
    assert len(run.transport.sent) == sent and len(runtime.operator.requests) == reviewed
    runtime.operator.decision = Decision.DENY
    path = runtime.policy.root / "denied-write.txt"
    with pytest.raises(UserControlledRefusal):
        await runtime.registry.execute("file_write", {"path": str(path), "content": "should not persist"},
                                       FakeSignal(), runtime.prompter)
    assert not path.exists() and len(runtime.operator.requests) == reviewed + 1


@pytest.mark.parametrize("family,address", [(socket.AF_INET, ("127.0.0.1", 9)),
    (socket.AF_INET, ("198.51.100.1", 9)), (socket.AF_INET6, ("::1", 9)),
    (socket.AF_INET6, ("2001:db8::1", 9))])
def test_offline_guard_blocks_ipv4_ipv6_and_loopback(offline_scenario, family, address):
    with pytest.raises(RuntimeError, match="offline boundary"):
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.connect(address)
    assert offline_scenario.pop() == "IPv4/IPv6 socket"


def test_offline_guard_blocks_dns_process_and_user_data(offline_scenario, tmp_path):
    from tests.scenarios.conftest import REPO
    for operation in (lambda: socket.getaddrinfo("fixture.invalid", 80),
                      lambda: subprocess.Popen(["true"]), lambda: os.system("true"),
                      lambda: (REPO / ".kagent/old-session.json").read_text(),
                      lambda: (tmp_path.parent / "outside-scenario.txt").write_text("forbidden")):
        with pytest.raises(RuntimeError, match="offline boundary"):
            operation()
    assert len(offline_scenario) == 5
    offline_scenario.clear()
    left, right = socket.socketpair(socket.AF_UNIX)
    try:
        left.send(b"asyncio-compatible")
        assert right.recv(32) == b"asyncio-compatible"
    finally:
        left.close()
        right.close()


def test_trace_redacts_diagnostics(scenario_runner):
    from tests.helpers.scenario_oracle import TraceRecorder, InvariantOracle
    trace = TraceRecorder(None, InvariantOracle(scenario_runner.root))
    trace.record({"type": "diagnostic", "text": "Authorization: Bearer fixture-secret-token\nCookie: session=fixture-cookie"})
    trace.write(scenario_runner.root / "trace.json")
    saved = (scenario_runner.root / "trace.json").read_text()
    assert "fixture-secret-token" not in saved and "fixture-cookie" not in saved
    assert not trace.errors
