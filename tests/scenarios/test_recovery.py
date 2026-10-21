"""Exact filesystem faults and event-controlled awaits around native dispatch."""
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path

import pytest

from src.coverage.store import CoverageStore
from src.permission.network.grants import HTTPLimits
from src.workflow.validation.probe import ProbeProposal
from tests.helpers.agent_fakes import FakeSignal, ScriptedModel
from tests.helpers.scenario_oracle import InvariantOracle, TraceRecorder
from tests.helpers.scenarios import (
    SQLI_VALUES, SSTI_FINGERPRINTS, ScenarioRun, dedicated_validation, direct_script, finding_arguments, generic_script, receipt,
)
from src.workflow.validation.route import GENERIC_VALIDATOR
from tests.scenarios.test_safety import protected, rejected, safety_definition, safety_outcomes, unresolved_closures


@pytest.mark.parametrize("boundary", ["canonical", "export"])
async def test_s09_s10_filesystem_commit_and_explicit_retry(scenario_runner, monkeypatch, boundary):
    def script(runtime, scenario):
        original = direct_script(runtime, scenario)
        feedback = None
        hits = []
        while True:
            try:
                name, args = next(original) if feedback is None else original.send(feedback)
            except StopIteration:
                assert len(hits) == 1
                return
            selected = name == "confirm_finding"
            if not selected:
                feedback = yield name, args
                continue
            before = protected(runtime)
            with monkeypatch.context() as fault:
                real_open, real_replace = os.open, os.replace

                def fail_open(path, flags, *a, **kw):
                    destination = runtime.policy.root / "artifacts/findings/offline-controlled-product-filter.md"
                    if Path(path) == destination and not hits:
                        hits.append(str(path))
                        raise OSError("M2 canonical open failure")
                    return real_open(path, flags, *a, **kw)

                def fail_replace(source, destination, *a, **kw):
                    target = Path(destination)
                    expected = runtime.policy.root / "artifacts/reports/findings/offline-controlled-product-filter.md"
                    if target == expected and not hits:
                        hits.append(str(destination))
                        raise OSError("M2 " + boundary + " replace failure")
                    return real_replace(source, destination, *a, **kw)

                if boundary == "canonical":
                    fault.setattr(os, "open", fail_open)
                    feedback = yield from rejected(runtime, name, args, "M2 canonical open failure", kind="tool_exception")
                else:
                    fault.setattr(os, "replace", fail_replace)
                    feedback = yield name, args
                assert len(hits) == 1
                reports = list((runtime.policy.root / "artifacts/findings").glob("*.md"))
                cid = args["candidate_id"]
                result = runtime.workflow.latest_result(cid)
                assert result and result.outcome == "confirmed"
                if boundary == "canonical":
                    assert not reports and not runtime.workflow.finding_is_persisted(cid)
                    assert protected(runtime) == before
                    assert not InvariantOracle.independently_complete(runtime)
                elif boundary == "export":
                    assert "compact report export failed" in feedback
                    assert runtime.workflow.finding_is_persisted(cid) and len(reports) == 1
                    assert InvariantOracle.independently_complete(runtime)
                    report_bytes = reports[0].read_bytes()
                    assert not list((runtime.policy.root / "artifacts/reports/findings").glob("*.md"))
                runtime.scenario_snapshots.append(("immediate-" + boundary, protected(runtime)))
                runtime.scenario_trace.record({"type": "controller", "action": "immediate-" + boundary,
                    "canonical_count": len(reports), "finding_marker": runtime.workflow.finding_is_persisted(cid),
                    "result_id": result.result_id, "http_count": len(runtime.scenario_transport.sent)})
            # Explicit recovery action; never HTTP or result resubmission.
            feedback = yield name, args
            assert "written to " in feedback
            reports = list((runtime.policy.root / "artifacts/findings").glob("*.md"))
            assert len(reports) == 1
            if boundary == "export":
                assert reports[0].read_bytes() == report_bytes
                assert len(list((runtime.policy.root / "artifacts/reports/findings").glob("*.md"))) == 1
            assert len(runtime.scenario_transport.sent) == 6

    await scenario_runner.run(safety_definition("S09-S10-" + boundary, script))


async def test_s11_coverage_failure_snapshot_and_fresh_runtime_sync_without_http(scenario_runner, monkeypatch):
    finding_args = {}

    def failure_script(runtime, scenario):
        original = direct_script(runtime, scenario)
        feedback = None
        while True:
            try:
                name, args = next(original) if feedback is None else original.send(feedback)
            except StopIteration:
                return
            if name == "workflow" and args["action"] == "record_result":
                real_replace = Path.replace
                hits = []

                def fail(source, target):
                    if Path(target) == runtime.coverage.path and not hits:
                        hits.append(str(source))
                        raise OSError("M2 coverage replace failure")
                    return real_replace(source, target)

                with monkeypatch.context() as fault:
                    fault.setattr(Path, "replace", fail)
                    feedback = yield name, args
                    payload = receipt(feedback)
                    assert payload["coverage_sync"] == "pending" and "could not be persisted" in payload["coverage_error"]
                    assert payload["eligible_for_confirm_finding"] is False
                    assert len(hits) == 1 and isinstance(runtime.coverage.last_save_error, OSError)
                    assert runtime.workflow.validation_results[-1].coverage_synced is False
                    assert len(runtime.coverage.entries) == 1
                    assert not runtime.coverage.path.is_file()
                    assert not InvariantOracle.independently_complete(runtime)
                    runtime.scenario_snapshots.append(("coverage-failure", protected(runtime)))
                    runtime.scenario_trace.record({"type": "controller", "action": "coverage-failure",
                        "memory_rows": len(runtime.coverage.entries), "disk_rows": 0, "coverage_synced": False})
                result = runtime.workflow.validation_results[-1]
                finding_args.update(finding_arguments(scenario, result.candidate_id, result.assessment["observed_impact"]))
                runtime.scenario_agent_errors.append("hit max steps (13)")
                original.close()
                return
            else:
                feedback = yield name, args

    scenario = safety_definition("S11", failure_script)
    scenario = replace(scenario, max_steps=13, expected_stop=(13, "max_steps"),
                       expected=replace(scenario.expected, complete=False, findings=0))
    run = await scenario_runner.run(scenario)
    assert not await CoverageStore(str(run.runtime.coverage.path)).list()
    fresh = await scenario_runner.resume(run, unchanged=False)
    assert fresh.workflow.validation_results[-1].coverage_synced is False
    assert fresh.workflow.validation_results[-1].result_id == run.runtime.workflow.validation_results[-1].result_id
    assert not fresh.engagement.http_permissions.grants and not fresh.policy.generic_validation.contexts

    def recovery(runtime, _):
        cid = finding_args["candidate_id"]
        yield from rejected(runtime, "confirm_finding", finding_args, "candidate is not eligible", kind="tool_exception")
        for expected in ("synced", "not-pending"):
            value = receipt((yield "workflow", {"action": "sync_coverage", "candidate_id": cid}))
            assert value["coverage_sync"] == expected
        output = yield "confirm_finding", finding_args
        assert "written to " in output

    continuation = replace(scenario, script=recovery, user_input="Continue the current validation; repair coverage and persist the existing finding without retesting.",
        expected_stop=None, expected=replace(scenario.expected, complete=True, findings=1))
    await scenario_runner.run(continuation, runtime=fresh, transport=run.transport, oracle=run.oracle, prefix="recovery")
    assert len(run.transport.sent) == 6 and len(fresh.workflow.validation_results) == 1


async def test_s12_actual_session_replace_failure_live_commit_checkpoint_and_resume(scenario_runner, monkeypatch):
    scenario = safety_definition("S12", direct_script)
    runtime, transport = scenario_runner.prepare(scenario)
    oracle = InvariantOracle(scenario_runner.root)
    trace = TraceRecorder(runtime, oracle)
    model = ScriptedModel(scenario.script(runtime, scenario))
    runtime.scenario_model = model
    runtime.agent.set_client(model)
    hits = []
    real_replace = os.replace

    def fail(source, destination, *args, **kwargs):
        if Path(destination) == runtime.store.path and runtime.workflow.validation_results and len(hits) < 2:
            # Observe the exact commit boundary before the failed replacement.
            saved = json.loads(runtime.store.path.read_text())["workflow"]
            assert not saved["validation_results"]
            assert runtime.workflow.validation_results[-1].outcome == "confirmed"
            assert runtime.workflow.validation_results[-1].coverage_synced
            hits.append(deepcopy(saved))
            trace.record({"type": "controller", "action": "session-replace-failure",
                          "live_revision": runtime.workflow.committed_revision, "saved_results": 0})
            raise OSError("M2 session replace failure")
        return real_replace(source, destination, *args, **kwargs)

    try:
        with monkeypatch.context() as fault:
            fault.setattr(os, "replace", fail)
            with pytest.raises(OSError, match="M2 session replace failure"):
                await asyncio.wait_for(runtime.agent.run(scenario.user_input, FakeSignal(), trace.record), 30)
        # Occurrence 1 is admission; occurrence 2 is finalization. Both use
        # the same real Store.save -> os.replace boundary, with no mock save.
        assert len(hits) == 2 and not model.errors and not trace.errors
        assert not runtime.agent.running and not runtime.agent._background_tasks
        assert not runtime.workflow.mutation_lock.locked()
        assert not list(runtime.store.path.parent.glob(runtime.store.path.name + ".tmp.*"))
        assert runtime.agent._workflow_saved_revision < runtime.workflow.committed_revision
        oracle.boundary(runtime, "failed-session-joined")
        assert not json.loads(runtime.store.path.read_text())["workflow"]["validation_results"]
        assert len(runtime.workflow.validation_results) == 1 and not runtime.workflow.persisted_findings
        errors = [e for e in trace.events if e["type"] == "error"]
        assert len(errors) == 1 and "M2 session replace failure" in errors[0]["err"]
        trace.record({"type": "controller", "action": "explicit-checkpoint-retry"})
        await runtime.agent.save()
        assert runtime.agent._workflow_saved_revision == runtime.workflow.committed_revision
        assert len(json.loads(runtime.store.path.read_text())["workflow"]["validation_results"]) == 1
        run = ScenarioRun(scenario, runtime, transport, model, trace, oracle, 0)
        fresh = await scenario_runner.resume(run, unchanged=False)
        result = fresh.workflow.validation_results[-1]
        assert result.result_id == runtime.workflow.validation_results[-1].result_id

        def continue_script(rt, sc):
            args = finding_arguments(sc, result.candidate_id, result.assessment["observed_impact"])
            output = yield "confirm_finding", args
            assert "written to " in output

        continuation = replace(scenario, script=continue_script,
            user_input="Continue current validation; persist the already confirmed finding without more probes.")
        await scenario_runner.run(continuation, runtime=fresh, transport=transport, oracle=oracle, prefix="checkpoint-recovery")
        assert len(transport.sent) == 6
    finally:
        trace.write(scenario_runner.root / "session-failure-trace.json")


@pytest.mark.parametrize("bounded_stop", [False, True], ids=["repair", "budget-closure"])
async def test_s04_s16_native_truncation_immutable_repair_or_bounded_closure(scenario_runner, bounded_stop):
    def script(runtime, scenario):
        normal = replace(scenario, expected=replace(scenario.expected, outcome="confirmed"))
        original = direct_script(runtime, normal)
        feedback = None
        partial = None
        old_proof = None
        while True:
            try:
                name, args = next(original) if feedback is None else original.send(feedback)
            except StopIteration:
                return
            if name == "http" and partial is None:
                output = yield name, {**args, "max_response_bytes": 3}
                line = next(line for line in output.splitlines() if line.startswith("Runtime HTTP evidence ("))
                envelope, _ = json.JSONDecoder().raw_decode(line.split(": ", 1)[1])
                partial = envelope["observation_id"]
                assert envelope["truncated"] and not envelope["complete"]
                source = runtime.policy.observations._items[partial]
                assert source.body == b"fix" and len(runtime.scenario_transport.sent) == 1
                partial_hash = source.retained_hash
            if name == "workflow" and args["action"] == "record_evidence":
                # Register a real partial-source snapshot; registration is not
                # terminal admission. Later repair creates a distinct artifact.
                path = "artifacts/partial-proof.md"
                yield "file_write", {"path": str(runtime.policy.root / path),
                    "content": f"# Candidate proof\n- candidate_id: {args['candidate_id']}\n- observation_ids: {partial}\nPartial native response, not terminal proof.\n"}
                old = receipt((yield "workflow", {**args, "evidence_path": path, "observation_ids": [partial]}))["evidence"]
                old_proof = runtime.policy.root / old["path"]
                old_bytes = old_proof.read_bytes()
                old_ref = old["id"]
            if name == "workflow" and args["action"] == "record_result":
                assert old_proof is not None
                invalid = {**args, "observation_ids": [partial], "evidence_refs": [old_ref]}
                yield from rejected(runtime, name, invalid, "evidence-admissibility:")
                assert old_proof.read_bytes() == old_bytes
                assert runtime.policy.observations._items[partial].retained_hash == partial_hash
                assert len(runtime.scenario_transport.sent) == 7
                if bounded_stop:
                    runtime.scenario_model.runtime_stop = (len(runtime.scenario_model.calls) + 2, args["attempt_id"])
                    for _ in range(2):
                        call_id = f"{runtime.scenario_model.prefix}-{len(runtime.scenario_model.calls) + 1}"
                        runtime.scenario_errors[call_id] = (name, "evidence-admissibility:", "workflow_state")
                        yield name, invalid
                        assert old_proof.read_bytes() == old_bytes
                        assert runtime.policy.observations._items[partial].retained_hash == partial_hash
                        assert len(runtime.scenario_transport.sent) == 7
                    raise AssertionError("runtime repair budget did not stop after three submissions")
                repair_path = "artifacts/repaired-proof.md"
                complete_ids = args["observation_ids"]
                text = f"# Candidate proof\n- candidate_id: {args['candidate_id']}\n- observation_ids: {', '.join(complete_ids)}\n"
                for oid in complete_ids:
                    source = runtime.policy.observations._items[oid]
                    assert source.complete and not source.truncated
                    text += f"{oid}: HTTP {source.status}; {source.body.decode()}\n"
                text += args["assessment"]["observed_impact"] + "\n" + args["assessment"]["limitations"]
                yield "file_write", {"path": str(runtime.policy.root / repair_path), "content": text}
                repaired = receipt((yield "workflow", {"action": "record_evidence", "candidate_id": args["candidate_id"],
                    "evidence_path": repair_path, "observation_ids": complete_ids}))["evidence"]
                args = {**args, "evidence_refs": [repaired["id"]]}
                assert args["evidence_refs"] != [old_ref]
                assert old_proof.read_bytes() == old_bytes and len(runtime.scenario_transport.sent) == 7
            feedback = yield name, args
            if old_proof is not None:
                assert old_proof.read_bytes() == old_bytes

    scenario = safety_definition("S04-S16-" + str(bounded_stop), script)
    scenario = replace(scenario, http_values=(scenario.input_value, scenario.input_value, *SQLI_VALUES[1:]))
    if bounded_stop:
        scenario = replace(scenario, expected=replace(scenario.expected, outcome="insufficient-evidence", findings=0, complete=False))
    run = await scenario_runner.run(scenario)
    if bounded_stop:
        state = run.runtime.workflow
        result = state.validation_results[-1]
        assert result.outcome == "insufficient-evidence" and not result.evidence_manifest
        assert state.attempts[result.attempt_id]["status"] == "unresolved"
        assert len(state.validation_results) == 1
        unresolved_closures(run, result.attempt_id)
        rejected_boundaries = [b["workflow"] for b in run.oracle.boundaries
            if b["label"] == "record_result" and not b["workflow"]["validation_results"]]
        assert len(rejected_boundaries) == 3
        for key in ("attempts", "candidates", "evidence", "evidence_sources", "selected_sources", "persisted_findings"):
            assert all(boundary[key] == rejected_boundaries[0][key] for boundary in rejected_boundaries[1:])
        assert not state.persisted_findings and len(run.transport.sent) == 7


async def test_s14_missing_actual_proof_blocks_completion_and_restoration_repairs(scenario_runner):
    run = await scenario_runner.run(safety_definition("S14", direct_script))
    runtime = run.runtime
    result = runtime.workflow.validation_results[-1]
    proof = runtime.policy.root / runtime.workflow.evidence[result.evidence_refs[0]].path
    original = proof.read_bytes()
    ledger = deepcopy(result.to_dict())
    proof.unlink()
    ref = result.evidence_refs[0]
    run.oracle.expected_unavailable.add(ref)
    run.oracle.boundary(runtime, "proof-unavailable")
    assert runtime.workflow.finding_is_persisted(result.candidate_id)
    assert runtime.workflow.latest_result(result.candidate_id).to_dict() == ledger
    assert not run.oracle.independently_complete(runtime)
    assert runtime.agent._validation_completion_blockers()
    def recovery(rt, _):
        yield from rejected(rt, "workflow", {"action": "complete_skill", "skill_name": "sql-injection"},
                            "assigned work remains unresolved")
        assert not run.oracle.independently_complete(rt) and rt.workflow.latest_result(result.candidate_id).to_dict() == ledger
        rt.scenario_trace.record({"type": "controller", "action": "restore-exact-proof", "sha256": hashlib.sha256(original).hexdigest()})
        # Restore the exact fixture backup without changing source ownership,
        # assessment seals, canonical finding or probe history.
        proof.write_bytes(original)
        proof.chmod(0o400)
        run.oracle.expected_unavailable.remove(ref)
        value = receipt((yield "workflow", {"action": "complete_skill", "skill_name": "sql-injection"}))
        assert value["completion_source"] == "runtime"

    continuation = replace(run.definition, script=recovery, user_input="Continue current validation; repair the missing retained proof without retesting.")
    await scenario_runner.run(continuation, runtime=runtime, transport=run.transport, oracle=run.oracle, prefix="proof-recovery")
    fresh = await scenario_runner.resume(run)
    assert run.oracle.independently_complete(fresh) and len(run.transport.sent) == 6
    run.trace.write(scenario_runner.root / "proof-recovery-trace.json")


async def test_s08_terminal_history_readable_but_old_sources_cannot_own_retest(scenario_runner):
    scenario = safety_definition("S08-history", direct_script, cls="ssti", endpoint="/render",
                                 parameter="content", value="plain-marker", outcome="not-confirmed")
    run = await scenario_runner.run(scenario)
    old_result = deepcopy(run.runtime.workflow.validation_results[0].to_dict())
    old_id = old_result["evidence_manifest"][0]["source"]["id"]
    source_path = run.runtime.workflow.evidence[old_result["evidence_refs"][0]].source_path
    fresh = await scenario_runner.resume(run, unchanged=False)
    assert fresh.workflow.validation_results[0].to_dict() == old_result
    assert not fresh.policy.observations._items and old_id in fresh.workflow.selected_sources
    cid = old_result["candidate_id"]
    app = scenario.application
    run.transport.expected.extend((app.request(value), app.render(value))
                                 for value in (scenario.input_value, *SSTI_FINGERPRINTS))

    def script(rt, sc):
        original = dedicated_validation(rt, sc, cid)
        feedback = None
        while True:
            try:
                name, args = next(original) if feedback is None else original.send(feedback)
            except StopIteration:
                return
            feedback = yield name, args
            if name == "workflow" and args["action"] == "start_validation":
                aid = receipt(feedback)["validation_context"]["attempt_id"]
                assert aid != old_result["attempt_id"]
                yield from rejected(rt, "workflow", {"action": "record_evidence", "candidate_id": cid,
                    "evidence_path": str(Path(source_path).relative_to(rt.policy.root)), "observation_ids": [old_id]},
                    "ownership mismatch")

    fresh.engagement.http_permissions.activate(scenario.origin, HTTPLimits(requests=7, rate=1000, burst=100))
    continuation = replace(scenario, script=script, user_input=f"Continue the current objective; explicitly retest candidate {cid} with fresh evidence and the same bounded Phase 1 criteria.")
    await scenario_runner.run(continuation, runtime=fresh, transport=run.transport, oracle=run.oracle, prefix="retest")
    assert len(fresh.workflow.validation_results) == 2
    assert fresh.workflow.validation_results[0].to_dict() == old_result
    new = fresh.workflow.validation_results[-1]
    assert new.attempt_id != old_result["attempt_id"]
    assert set(fresh.workflow.evidence_sources[new.evidence_refs[0]]).isdisjoint(
        fresh.workflow.evidence_sources[old_result["evidence_refs"][0]])


async def test_s06_revoke_during_event_controlled_presend_then_recover(scenario_runner, monkeypatch):
    entered, release = asyncio.Event(), asyncio.Event()
    scenario = safety_definition("S06", direct_script)
    runtime, transport = scenario_runner.prepare(scenario)
    permissions = runtime.engagement.http_permissions
    original = permissions.reserve_when_ready
    held = False

    async def pause(*args, **kw):
        nonlocal held
        if not held:
            held = True
            entered.set()
            await asyncio.wait_for(release.wait(), 5)
        return await original(*args, **kw)

    def script(rt, sc):
        original_script = direct_script(rt, sc)
        feedback = None
        first = True
        while True:
            try:
                name, args = next(original_script) if feedback is None else original_script.send(feedback)
            except StopIteration:
                return
            if name == "http" and first:
                first = False
                yield from rejected(rt, name, args, "unknown/replayed receipt", kind="policy_block", presend_admission=True)
                rt.scenario_trace.record({"type": "controller", "action": "operator-retry", "origin": sc.origin})
                permissions.retry(sc.origin)
                permissions.activate(sc.origin, HTTPLimits(requests=7, rate=1000, burst=100))
            feedback = yield name, args

    scenario = replace(scenario, script=script)
    with monkeypatch.context() as fault:
        fault.setattr(permissions, "reserve_when_ready", pause)
        task = asyncio.create_task(scenario_runner.run(scenario, runtime=runtime, transport=transport))
        try:
            await asyncio.wait_for(entered.wait(), 10)
            assert not transport.sent
            # Capture the real registry receipt while the HTTP invocation is
            # waiting, before revocation invalidates its transport admission.
            active_receipts = list(runtime.policy._active_receipts)
            assert len(active_receipts) == 1
            runtime.scenario_presend_receipt_id = active_receipts[0]
            InvariantOracle(scenario_runner.root).boundary(runtime, "in-flight", quiescent=False)
            permissions.revoke(next(iter(permissions.grants.values())).id)
            release.set()
            await asyncio.wait_for(task, 30)
        finally:
            release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    assert not permissions._receipts and not permissions._review_locks and not permissions._inflight


@pytest.mark.parametrize("generic", [False, True], ids=["expert", "generic-controller"])
async def test_s07_s08_cancel_http_join_restore_and_fresh_continuation(scenario_runner, monkeypatch, generic):
    scenario = (safety_definition("S07-S08-generic", generic_script, mode="generic", cls="response-confusion",
        endpoint="/compare?item=baseline", parameter="item", value="baseline", outcome="not-confirmed", controller_bound=True)
        if generic else safety_definition("S07-S08-expert", direct_script))
    runtime, transport = scenario_runner.prepare(scenario)
    oracle = InvariantOracle(scenario_runner.root)
    trace = TraceRecorder(runtime, oracle)
    model = ScriptedModel(scenario.script(runtime, scenario))
    runtime.scenario_model = model
    runtime.agent.set_client(model)
    entered, release = asyncio.Event(), asyncio.Event()
    original = runtime.engagement.http_permissions.reserve_when_ready
    held = False

    async def pause(*args, **kw):
        nonlocal held
        if not held:
            held = True
            entered.set()
            await asyncio.wait_for(release.wait(), 5)
        return await original(*args, **kw)

    with monkeypatch.context() as fault:
        fault.setattr(runtime.engagement.http_permissions, "reserve_when_ready", pause)
        task = asyncio.create_task(runtime.agent.run(scenario.user_input, FakeSignal(), trace.record))
        try:
            await asyncio.wait_for(entered.wait(), 10)
            assert not transport.sent and not runtime.workflow.validation_results
            aid = next(a["id"] for a in runtime.workflow.attempts.values() if a["status"] == "active")
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 10)
        finally:
            release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            trace.write(scenario_runner.root / "interruption-trace.json")
    assert not model.errors and not trace.errors
    assert not [e for e in trace.events if e["type"] == "error"]
    done = [e for e in trace.events if e["type"] == "done"]
    assert len(done) == 1 and done[0]["stop_reason"] == "cancelled"
    # Task cancellation propagates out of run_parsed_tool_call before its
    # ToolCallResult/event exists. Permission-review cancellation has a
    # different (explicit cancelled result) contract.
    started_http = [e for e in trace.events if e["type"] == "tool-call" and e["name"] == "http"]
    assert len(started_http) == 1
    assert not [e for e in trace.events if e["type"] == "tool-result" and e["id"] == started_http[0]["id"]]
    oracle.boundary(runtime, "cancelled-joined")
    assert not runtime.agent.running and not runtime.agent._background_tasks
    assert not runtime.engagement.http_permissions._receipts and not runtime.engagement.http_permissions._review_locks
    assert not runtime.policy.generic_validation.in_flight
    saved = json.loads(runtime.store.path.read_text())["workflow"]
    assert not saved["validation_results"] and saved["attempts"][aid]["status"] == "active"
    run = ScenarioRun(scenario, runtime, transport, model, trace, oracle, 0)
    fresh = await scenario_runner.resume(run, unchanged=False)
    assert fresh.workflow.attempts[aid]["status"] == "interrupted"
    reconciled = [m for m in fresh.agent.history if m.role == "tool" and m.tool_call_id == started_http[0]["id"]]
    assert len(reconciled) == 1 and reconciled[0].tool_status == "cancelled"
    assert reconciled[0].tool_error_kind == "cancelled" and "tool call did not complete" in reconciled[0].content
    assert not fresh.engagement.http_permissions.grants and not fresh.policy._receipts
    assert fresh.policy.generic_validation.durable_attempt is None and not fresh.policy.generic_validation.contexts

    def continue_script(rt, sc):
        cid = next(iter(rt.workflow.candidates))
        if generic:
            probe = ProbeProposal(cid, rt.workflow.objective.id, sc.origin, sc.endpoint,
                                  "GET", "query", sc.parameter, ("variant",))
            yield from rejected(rt, "workflow", {"action": "start_validation", "candidate_id": cid,
                                "probe": probe.to_dict()}, "context-needed")
        # An old attempt cannot authorize a new result. Closure is honest,
        # and start/controller rebind remains explicit production behavior.
        yield from rejected(rt, "workflow", {"action": "record_result", "candidate_id": cid,
            "attempt_id": aid, "skill_name": GENERIC_VALIDATOR if generic else "sql-injection",
            "outcome": "not-confirmed", "assessment": {"completed_attempt": True}},
            "stale/wrong attempt identity")
        yield from (generic_script(rt, sc) if generic else dedicated_validation(rt, sc, cid))
        result = rt.workflow.validation_results[-1]
        assert result.attempt_id != aid and rt.workflow.attempts[aid]["status"] == "interrupted"
        assert all(e["source"]["attempt_id"] == result.attempt_id for e in result.evidence_manifest)

    fresh.engagement.http_permissions.activate(scenario.origin, HTTPLimits(requests=7, rate=1000, burst=100))
    continuation = replace(scenario, script=continue_script, user_input="Continue the interrupted validation using a fresh attempt and fresh rights.")
    await scenario_runner.run(continuation, runtime=fresh, transport=transport, oracle=oracle, prefix="continued")
