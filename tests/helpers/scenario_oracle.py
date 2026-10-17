"""Independent M1 expectations plus production completion diagnostics.

Checks run after committed tool results and save/resume, never mid-await.
Historical evidence integrity and current execution rights are separate.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, is_dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from src.coverage.store import CoverageStore
from src.findings.store import read_report
from src.redaction.redact import apply_evidence, redact_payload
from src.target.origin import HTTPOrigin
from src.workflow.validation_route import resolve_validation_route


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def binding(candidate) -> str:
    row = candidate.to_dict().copy()
    for key in ("status", "priority", "signals", "source_skill"):
        row.pop(key, None)
    return canonical_hash(row)


class InvariantOracle:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.proofs: dict[str, bytes] = {}
        self.sources: dict[str, str] = {}
        self.boundaries: list[dict[str, Any]] = []
        self.bindings: dict[str, dict[str, Any]] = {}
        self.expected_unavailable: set[str] = set()

    def boundary(self, runtime, label: str, *, restored: bool = False, quiescent: bool = True) -> None:
        state = runtime.workflow
        for candidate in state.candidates.values():
            self.bindings.setdefault(binding(candidate), candidate.to_dict())
        active = [a for a in state.attempts.values() if a["status"] == "active"]
        assert len(active) <= 1, "multiple active attempts"
        for attempt in state.attempts.values():
            candidate = state.candidates[attempt["candidate_id"]]
            assert attempt["session_id"] == runtime.store.id
            assert attempt["candidate_binding"] in self.bindings, "unknown captured binding"
            if attempt["status"] == "active":
                assert attempt["candidate_binding"] == binding(candidate), "active binding changed"
                assert state.objective and attempt["objective_id"] == state.objective.id
                assert candidate.status == "validating"
                assert attempt["epoch"] == runtime.engagement.http_permissions.epoch
                assert attempt["target_revision"] == runtime.target.revision
                assert attempt["result_position"] == sum(r.candidate_id == candidate.id for r in state.validation_results)
        for candidate in state.candidates.values():
            if candidate.status == "validating":
                matching = [a for a in state.attempts.values() if a["candidate_id"] == candidate.id
                            and a["status"] in {"active", "interrupted"}]
                assert matching, "validating without matching runtime attempt"
        for item in runtime.policy.observations._items.values():
            retained = asdict(item)
            retained["body"] = item.body.hex()
            retained.pop("retained_hash", None)
            assert canonical_hash(retained) == item.retained_hash
            assert self.sources.setdefault(item.id, item.retained_hash) == item.retained_hash
            if item.candidate_id is not None:
                attempt = state.attempts[item.attempt_id]
                for key in ("candidate_id", "candidate_binding", "session_id", "objective_id", "epoch"):
                    assert getattr(item, key) == attempt[key], f"native source ownership: {key}"
        for artifact in state.evidence.values():
            path = (self.root / artifact.path).resolve()
            assert path.is_relative_to(self.root)
            if artifact.id in self.expected_unavailable:
                assert not path.is_file() and artifact.id in self.proofs
                assert hashlib.sha256(self.proofs[artifact.id]).hexdigest() == artifact.sha256
                continue  # Availability is a separate current completion fact.
            assert path.is_file()
            raw = path.read_bytes()
            assert len(raw) == artifact.size and hashlib.sha256(raw).hexdigest() == artifact.sha256
            assert path.stat().st_mode & 0o222 == 0, "proof is writable"
            previous = self.proofs.setdefault(artifact.id, raw)
            assert previous == raw, "immutable snapshot bytes changed"
            assert artifact.candidate_id in state.candidates
        for result in state.validation_results:
            candidate = state.candidates[result.candidate_id]
            assert result.session_id == runtime.store.id
            if result.outcome not in {"confirmed", "not-confirmed"}:
                if state.latest_result(candidate.id) is result:
                    assert not state.finding_is_persisted(candidate.id), "unresolved finding"
                continue
            assert result.assessment_contract_version == 2
            assert result.assessment_source == "agent" and result.result_id and result.assessment_binding
            attempt = state.attempts[result.attempt_id]
            assert result.candidate_binding == attempt["candidate_binding"]
            captured = self.bindings[result.candidate_binding]
            assert result.objective_id == attempt["objective_id"]
            if state.latest_result(candidate.id) is result and result.candidate_binding == binding(candidate):
                assert candidate.status in {"validated", "validating"}
            assert attempt["status"] == "completed" and attempt["candidate_id"] == candidate.id
            assert result.assessment["attempt"] == {k: v for k, v in attempt.items() if k != "status"}
            result_row = result.to_dict().copy()
            for key in ("assessment_binding", "coverage_synced", "cleanup_state", "cleanup_status"):
                result_row.pop(key, None)
            assert canonical_hash(result_row) == result.assessment_binding
            assert result.evidence_refs and result.evidence_manifest
            usable_primary = []
            ids = set()
            for entry in result.evidence_manifest:
                source = entry["source"]
                ids.add(source["id"])
                for key in ("candidate_id", "candidate_binding", "session_id", "objective_id", "attempt_id"):
                    assert source[key] == getattr(result, key), f"wrong source owner: {key}"
                assert source["epoch"] == attempt["epoch"]
                hashed = source.copy()
                hashed.pop("role", None)
                hashed.pop("required", None)
                assert canonical_hash(hashed) == entry["hash"], "source snapshot hash changed"
                assert self.sources.setdefault(source["id"], entry["hash"]) == entry["hash"]
                if source.get("required", True):
                    assert source["complete"] and not source["truncated"]
                    assert source["execution_status"] == "completed"
                # Optional metadata/process outputs need not be complete; at
                # least one eligible HTTP primary remains mandatory.
                if (source["source_kind"] in {"native-http", "imported-capture"}
                        and source["complete"] and not source["truncated"]
                        and source["execution_status"] == "completed"):
                    assert HTTPOrigin.from_url(source["url"]) == HTTPOrigin.from_url(captured["target"])
                    usable_primary.append(source)
            assert usable_primary, "derived-only terminal evidence"
            for ref in result.evidence_refs:
                assert state.evidence[ref].candidate_id == candidate.id
                assert ref in self.proofs
                assert set(state.evidence_sources.get(ref, [])) <= ids
                assert result.assessment["artifact_sources"][ref] == state.evidence_sources[ref]
            if result.outcome == "not-confirmed":
                assert result.assessment["completed_attempt"] is True
                if state.latest_result(candidate.id) is result:
                    assert not state.finding_is_persisted(candidate.id), "negative finding"
            if (label == "record_result" and result.outcome == "confirmed"
                    and state.latest_result(candidate.id) is result and not state.finding_is_persisted(candidate.id)):
                assert not state.finding_is_persisted(candidate.id)
                if result.coverage_synced:
                    assert runtime.workflow_tool.validation_completion_error(candidate.id, runtime.policy) == "confirmed finding persistence pending"
        if quiescent:
            assert runtime.policy.active == 0 and not runtime.policy._active_receipts
            assert not runtime.engagement.http_permissions._inflight
            assert not runtime.engagement.http_permissions._receipts
            assert not runtime.engagement.http_permissions._review_locks
            assert not runtime.policy.generic_validation.in_flight
        self.boundaries.append({"label": label, "revision": state.committed_revision,
            "workflow": deepcopy(state.to_dict()), "unavailable_proofs": sorted(self.expected_unavailable)})

    @staticmethod
    def proof_available(runtime, artifact) -> bool:
        path = (runtime.policy.root / artifact.path).resolve()
        if not path.is_relative_to(runtime.policy.root.resolve()):
            return False
        try:
            raw = path.read_bytes()
        except OSError:
            return False
        return len(raw) == artifact.size and hashlib.sha256(raw).hexdigest() == artifact.sha256

    @staticmethod
    def independently_complete(runtime) -> bool:
        state, objective = runtime.workflow, runtime.workflow.objective
        if objective is None or not state.candidates:
            return False
        current = [c for c in state.candidates.values() if c.objective_id == objective.id]
        if not current:
            return False
        for candidate in current:
            result = state.latest_result(candidate.id)
            if (result is None or result.outcome not in {"confirmed", "not-confirmed"}
                    or candidate.status != "validated" or result.candidate_binding != binding(candidate)
                    or not result.evidence_refs or not result.coverage_synced
                    or result.cleanup_state not in {"not-required", "succeeded"}
                    or any(not InvariantOracle.proof_available(runtime, state.evidence[ref]) for ref in result.evidence_refs)
                    or (result.outcome == "confirmed" and not state.finding_is_persisted(candidate.id))):
                return False
        if any(goal.status not in {"tested_confirmed", "tested_not_confirmed"} for goal in objective.requested_goals):
            return False
        if objective.mode == "whole_target":
            if state.completed_phases() != {"recon", "enumeration", "input_analysis"}:
                return False
            if not state.attack_surface_inputs or any(i.disposition != "analyzed" for i in state.attack_surface_inputs.values()):
                return False
        return True

    async def outcomes(self, run) -> None:
        runtime, definition = run.runtime, run.definition
        state, expected = runtime.workflow, definition.expected
        assert run.model.consumed and not run.model.errors, repr(run.model.errors)
        assert not run.trace.errors, run.trace.errors
        assert not run.transport.errors, run.transport.errors
        assert len(run.transport.sent) == len(run.transport.expected), "script skipped expected HTTP"
        calls = run.model.calls
        plans = [e for e in run.trace.events if e["type"] == "decision" and e.get("recommended_skill")]
        loaded = [e["name"] for e in run.trace.events if e["type"] == "skill-active"]
        if definition.mode == "whole_target":
            recommendations = [e["recommended_skill"] for e in plans]
            expected_skills = ("recon", "web-enumeration", "web-input-analysis", "sql-injection")
            assert all(skill in recommendations and skill in loaded for skill in expected_skills)
            positions = [next(i for i, (name, args) in enumerate(calls) if name == "load_skill" and args["name"] == skill)
                         for skill in expected_skills]
            assert positions == sorted(positions)
        elif expected.route == "expert":
            skill = "sql-injection" if definition.application.kind == "sqli" else "ssti"
            assert plans and plans[0]["recommended_skill"] == skill
            assert skill in loaded
        results = [e for e in run.trace.events if e["type"] == "tool-result"]
        assert len(results) == len(calls), "undispatched scripted calls"
        assert [e["id"] for e in results] == [f"scenario-{i}" for i in range(1, len(calls) + 1)]
        assert not [e for e in run.trace.events if e["type"] == "error"], run.trace.events[-3:]
        expected_errors = 0
        for (name, args), event in zip(calls, results):
            assert event["name"] == name
            if name == "workflow" and args["action"] == "start_validation" and (
                    definition.ambiguous or (definition.application.kind == "generic" and not definition.controller_bound)):
                expected_errors += 1
                assert event["status"] == "error"
                assert ("ambiguous" if definition.ambiguous else "context-needed") in event["result"]
            else:
                assert not event["err"] and not event["error_kind"] and event["status"] in {"success", "observation"}, event
        assert sum(e["status"] == "error" for e in results) == expected_errors
        assert state.objective and state.objective.mode == ("direct" if definition.mode == "generic" else definition.mode)
        assert state.objective.target_origin == HTTPOrigin.from_url(definition.origin).as_url()
        assert len(state.candidates) == 1
        candidate = next(iter(state.candidates.values()))
        assert (candidate.endpoint, candidate.method, candidate.parameter, candidate.candidate_class) == (
            definition.endpoint, definition.method, definition.parameter, definition.candidate_class)
        assert resolve_validation_route(runtime.skills, candidate.candidate_class).kind == expected.route
        assert runtime.engagement.allowed_origins == {HTTPOrigin.from_url(definition.origin)}
        registered = next(b for b in self.boundaries if b["label"] == "record_candidate")
        assert registered["workflow"]["candidates"][0]["status"] in {"queued", "deferred"}
        assert not registered["workflow"]["attempts"], "registration claimed execution"
        if expected.outcome == "none":
            assert not state.validation_results and not state.attempts
        else:
            assert len(state.validation_results) == 1
            result = state.latest_result(candidate.id)
            assert result and result.outcome == expected.outcome
            if definition.mode == "generic" and not definition.controller_bound:
                # Failed start has no owned effect ledger or trusted context.
                # Zero fixture traffic is a boundary check, not a no-write proof.
                assert result.mutation_performed is None and result.cleanup_state == "unknown"
                assert not state.attempts and not run.transport.sent and not state.persisted_findings
            else:
                assert result.cleanup_state == "not-required" and result.mutation_performed is False
            if expected.outcome in {"confirmed", "not-confirmed"}:
                assert result.coverage_synced
                assert not runtime.workflow_tool.validation_completion_error(candidate.id, runtime.policy)
                assert len(result.evidence_manifest) == (2 if definition.mode == "generic" else 6)
                # Compare actual persisted response bytes to the independently
                # specified fixture ledger, not the model's interpretation.
                observed = [e["source"] for e in result.evidence_manifest]
                expected_http = run.transport.expected[-len(observed):]
                for source, (_, (status, body, _)) in zip(observed, expected_http):
                    assert (source["status"], bytes.fromhex(source["body"])) == (status, body)
                if expected.outcome == "confirmed":
                    committed = next(b for b in self.boundaries if b["label"] == "record_result")
                    assert not committed["workflow"]["persisted_findings"], "confirmed conflated with a finding"
                    assert "confirm_finding" in [name for name, _ in calls]
                else:
                    assert "confirm_finding" not in [name for name, _ in calls]
            else:
                assert not result.evidence_refs and not result.evidence_manifest
        if expected.goal_status is not None:
            assert len(state.objective.requested_goals) == 1
            goal = state.objective.requested_goals[0]
            assert goal.candidate_class == candidate.candidate_class and goal.status == expected.goal_status
            assert goal.candidate_ids == [candidate.id]
        if definition.mode == "whole_target":
            assert state.completed_phases() == {"recon", "enumeration", "input_analysis"}
            assert len(state.attack_surface_inputs) == 1
            item = next(iter(state.attack_surface_inputs.values()))
            assert item.disposition == "analyzed" and item.candidate_ids == [candidate.id]
            assert state.phase_coverage_record("recon", "reachability").status == "performed"
            assert state.phase_coverage_record("enumeration", "html_navigation").status == "performed"
            assert not runtime.workflow_tool.discovery_artifact_errors()
        else:
            assert not state.phase_completions and not state.attack_surface_inputs
        assert self.independently_complete(runtime) is expected.complete
        done = [e for e in run.trace.events if e["type"] == "done"]
        assert len(done) == 1
        if expected.complete:
            assert done[0]["stop_reason"] == ("workflow_completed" if definition.mode == "whole_target" else "final_response")
            assert not runtime.agent._validation_completion_blockers()
        else:
            assert done[0]["stop_reason"] in {"workflow_blocked", "workflow_stalled"}
        await self.persisted(run, runtime)

    async def persisted(self, run, runtime) -> None:
        definition = run.definition
        original, state = run.runtime.workflow, runtime.workflow
        assert runtime.store is not run.runtime.store or runtime is run.runtime
        saved = json.loads(runtime.store.path.read_text())
        assert saved["workflow"] == state.to_dict(), "canonical outcome was not saved"
        assert "grants" not in saved["engagement_state"]
        assert not {"permission_receipts", "execution_receipts"} & set(saved["workflow"])
        assert state.to_dict() == original.to_dict(), "fresh runtime canonical state differs"
        rows = await CoverageStore(str(runtime.coverage.path)).list()
        terminal = definition.expected.outcome in {"confirmed", "not-confirmed"}
        assert len(rows) == int(terminal)
        if rows:
            assert rows[0].status == ("failed" if definition.expected.outcome == "confirmed" else "passed")
            assert rows[0].vulnClass == definition.candidate_class and rows[0].param == definition.parameter
            assert rows[0].context is not None
            assert rows[0].count == 1 and rows[0].context.target_origin == definition.origin
            assert rows[0].context.method == definition.method
            assert rows[0].context.location == ("query" if definition.method == "GET" else "body")
            assert rows[0].context.objective_id == state.objective.id
        reports = list((self.root / "artifacts/findings").glob("*.md"))
        assert len(reports) == definition.expected.findings
        for path in reports:
            report = read_report(path)
            assert report.candidate_id in state.persisted_findings
            assert report.url == definition.origin + definition.endpoint
            assert report.observed_impact == state.latest_result(report.candidate_id).assessment["observed_impact"]
            assert state.finding_is_persisted(report.candidate_id)
        if runtime is not run.runtime:
            assert not runtime.engagement.http_permissions.grants
            assert not runtime.policy._receipts and not runtime.policy._active_receipts
            assert not runtime.policy.generic_validation.contexts
            assert not runtime.policy.observations._items
            assert runtime.policy.generic_validation.durable_attempt is None
            assert self.independently_complete(runtime) is definition.expected.complete
            for candidate in state.candidates.values():
                assert runtime.workflow_tool.validation_completion_error(candidate.id, runtime.policy) is None
            if definition.mode == "whole_target":
                assert runtime.agent._whole_target_state() == ("completed", (), ())


class TraceRecorder:
    def __init__(self, runtime, oracle: InvariantOracle, *, defer_redaction: bool = False):
        self.runtime, self.oracle = runtime, oracle
        self.defer_redaction = defer_redaction
        self._pending_redaction = 0
        self.events: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self.calls: dict[str, dict[str, Any]] = {}

    def record(self, event: dict[str, Any]) -> None:
        # Agent's safe emitter can swallow sink exceptions. Save any oracle
        # failure and assert it outside Agent.run, including script retries.
        try:
            if is_dataclass(event) and not isinstance(event, type):
                event = asdict(event)
            cleaned = {}
            for key, value in event.items():
                if is_dataclass(value) and not isinstance(value, type):
                    value = asdict(value)
                elif isinstance(value, BaseException):
                    value = str(value)
                cleaned[key] = value
            if self.defer_redaction:
                # Snapshot the exact event without running test-only redaction
                # inside a measured production callback. Runtime events already
                # cross its sanitizer; this transient copy is sanitized before
                # outcomes/export and is never written raw.
                self.events.append(deepcopy(cleaned))
            else:
                encoded = apply_evidence(json.dumps(redact_payload(cleaned), default=str))
                self.events.append(json.loads(encoded))
            if event["type"] == "tool-call":
                self.calls[event["id"]] = event["args"]
            elif event["type"] == "tool-result":
                args = self.calls.get(event["id"], {})
                label = args.get("action", event["name"]) if isinstance(args, dict) else event["name"]
                self.oracle.boundary(self.runtime, label)
        except Exception as error:
            self.errors.append(apply_evidence(str(error)))

    def sanitize_pending(self) -> None:
        if not self.defer_redaction:
            return
        while self._pending_redaction < len(self.events):
            index = self._pending_redaction
            encoded = apply_evidence(json.dumps(redact_payload(self.events[index]), default=str))
            self.events[index] = json.loads(encoded)
            self._pending_redaction += 1

    def write(self, path: Path) -> None:
        # Keep structural snapshots, hashes and minimal sanitized diagnostics;
        # full traffic stays only in the production evidence/session stores.
        self.sanitize_pending()
        events = [{k: (v[:1800] if isinstance(v, str) else v) for k, v in e.items()} for e in self.events]
        snapshots = [{"label": b["label"], "revision": b["revision"],
            "candidates": b["workflow"]["candidates"], "attempts": b["workflow"]["attempts"],
            "objective": b["workflow"]["objective"], "persisted_findings": b["workflow"]["persisted_findings"],
            "unavailable_proofs": b["unavailable_proofs"],
            "results": [{key: result.get(key) for key in ("result_id", "candidate_id", "attempt_id", "outcome",
                "coverage_synced", "cleanup_state", "evidence_refs", "assessment_binding")}
                for result in b["workflow"]["validation_results"]]}
            for b in self.oracle.boundaries]
        path.write_text(apply_evidence(json.dumps(redact_payload({"events": events, "snapshots": snapshots,
                            "errors": self.errors}), indent=2, default=str)), encoding="utf-8")
