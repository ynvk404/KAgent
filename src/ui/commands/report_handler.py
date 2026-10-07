"""Local report controller; capture before scheduling, publish on this loop."""
from __future__ import annotations

import asyncio
import contextvars
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.coverage.context import project_candidate_coverage
from src.report.builder import Sanitizer, build_report, endpoint_matches_origin, origin, owned_origin
from src.report.model import (
    MAX_COVERAGE, MAX_RECORDS, MAX_RESULTS, Record, ReportError, Resources,
    SourceSnapshot, freeze,
)
from src.report.output import StagedReport, default_filename, stage_report, validate_filename
from src.ui.core.state import Append, TranscriptEntry
from src.version import VERSION
from src.workflow.review import review_snapshot, confirmation_binding
from src.workflow.state import WorkflowState, validation_result_fingerprint
from src.workflow.assessment import accepted_result, assessment_provenance

_IN_FLIGHT: dict[int, asyncio.Task] = {}


def _record(obj: Any, names: tuple[str, ...], **extra: Any) -> Record:
    return freeze({**{name: getattr(obj, name, None) for name in names}, **extra})


def capture_workflow(state: WorkflowState, target: str, policy=None) -> dict[str, Any]:
    """Capture allowlisted primitives and opaque joins; never copy specimens."""
    if len(state.candidates) + len(state.attack_surface_inputs) > MAX_RECORDS or len(state.validation_results) > MAX_RESULTS:
        raise ReportError("Assessment snapshot exceeds report record limits; reduce recorded resources and retry.")
    obj = state.objective
    if obj and obj.target_origin and origin(obj.target_origin) != origin(target):
        raise ReportError("active objective and target do not match. Export cannot mix their assessment records.")
    selected = {
        cid: c for cid, c in state.candidates.items() if obj and owned_origin(c.target, c.endpoint, obj.target_origin) == origin(target) and
        (cid == obj.candidate_id if obj.mode == "candidate_validation" else c.objective_id == obj.id)
    }
    endpoint_conflicts = sum(not endpoint_matches_origin(c.endpoint, origin(target)) for c in selected.values())
    selected = {cid: c for cid, c in selected.items() if endpoint_matches_origin(c.endpoint, origin(target))}
    results = [r for r in state.validation_results if obj and r.objective_id == obj.id and r.candidate_id in selected]
    global_latest = {r.candidate_id: r for r in state.validation_results}
    bindings = {cid: confirmation_binding(state, cid) for cid in selected if cid in global_latest}
    projections = {}
    admissibility = {id(r): accepted_result(state, selected[r.candidate_id], r, policy)
                     for r in results if r.assessment_contract_version >= 2}
    for r in results:
        if admissibility.get(id(r)) is False:
            projections[id(r)] = None
            continue
        try:
            endpoint, parameter, context = project_candidate_coverage(state, selected[r.candidate_id], r)
            projections[id(r)] = {"endpoint": endpoint, "param": parameter,
                "vulnClass": selected[r.candidate_id].candidate_class, "context": asdict(context)}
        except ValueError:
            projections[id(r)] = None
    candidate_fields = ("id", "target", "objective_id", "candidate_class", "endpoint", "method", "parameter",
                        "location", "content_type", "auth_context_ref", "test_case", "status")
    result_fields = ("candidate_id", "objective_id", "outcome", "evidence_refs", "skill_name", "techniques",
                     "cleanup_state", "cleanup_status", "coverage_synced", "deferred_reason", "notes", "recorded_at", "session_id", "assessment_source", "assessment_contract_version", "result_id", "attempt_id", "assessment_binding")
    input_fields = ("id", "objective_id", "target_origin", "endpoint", "method", "parameter", "location", "content_type",
                    "auth_context_ref", "disposition", "disposition_reason", "candidate_ids")
    inputs = [i for i in state.attack_surface_inputs.values() if obj and i.objective_id == obj.id and origin(i.target_origin) == origin(target)]
    endpoint_conflicts += sum(not endpoint_matches_origin(i.endpoint, origin(target)) for i in inputs)
    inputs = [i for i in inputs if endpoint_matches_origin(i.endpoint, origin(target))]
    refs = {ref for r in results for ref in r.evidence_refs}
    phase_records = []
    if obj:
        for key, marker in state.phase_completions.items():
            if marker.objective_id == obj.id:
                phase_records.append(freeze(marker.to_dict()))
        recorded = {p.get("phase") for p in phase_records}
        for key, records in state.phase_coverage.items():
            if key.startswith(obj.id + ":") and key[len(obj.id) + 1:] not in recorded:
                phase_records.append(freeze({"objective_id": obj.id, "target_origin": obj.target_origin,
                    "phase": key[len(obj.id) + 1:], "artifact_ref": "", "coverage": {k: v.to_dict() for k, v in records.items()}}))
    return {
        "objective": _record(obj, ("id", "mode", "target_origin", "candidate_id"),
            requested_goals=[{k: getattr(g, k) for k in ("id", "candidate_class", "status", "candidate_ids", "reason")} for g in obj.requested_goals]) if obj else Record(),
        "candidates": tuple(_record(c, candidate_fields, persisted=state.persisted_findings.get(cid)) for cid, c in selected.items()),
        "results": tuple(_record(r, result_fields, fingerprint=validation_result_fingerprint(r),
            current_admissible=admissibility.get(id(r)),
            assessment_provenance=assessment_provenance(state, selected[r.candidate_id], r, policy),
            binding=bindings[r.candidate_id] if global_latest.get(r.candidate_id) is r else "", projection=projections[id(r)]) for r in results),
        "inputs": tuple(_record(i, input_fields) for i in inputs),
        "evidence": tuple(_record(e, ("id", "candidate_id", "path", "sha256", "size", "source_path"))
                          for ref, e in state.evidence.items() if ref in refs),
        "phases": tuple(phase_records),
        "foreign_records": len(selected) != len(state.candidates) or len(results) != len(state.validation_results) or len(inputs) != len(state.attack_surface_inputs),
        "endpoint_conflict_count": endpoint_conflicts,
    }


def assessment_identity(app: Any) -> tuple[Any, ...]:
    agent = app.agent
    obj = agent.workflow.objective
    return (agent.target.base_url(), getattr(agent.target, "revision", 0),
            obj.id if obj else None, obj.mode if obj else None,
            obj.target_origin if obj else None, obj.candidate_id if obj else None,
            getattr(agent.engagement_state, "revision", 0))


def capture(app: Any, exported_at: str) -> tuple[SourceSnapshot, Resources, tuple[Any, ...]]:
    agent = app.agent
    target = agent.target.base_url()
    if not origin(target):
        raise ReportError("no valid active target. Set /target <url> first.")
    identity = assessment_identity(app)
    finding_tool = agent.tools.get("confirm_finding")
    workflow_tool = agent.tools.get("workflow")
    store = getattr(finding_tool, "store", None)
    if store is None:
        raise ReportError("Finding resources unavailable. Start KAgent with its normal report stores.")
    from src.permission.runtime.execution import policy_for
    data = capture_workflow(agent.workflow, target, policy_for(getattr(agent, "prompter", None)))
    coverage_store = getattr(workflow_tool, "coverage", None)
    coverage = None
    coverage_paths = ()
    if coverage_store is not None:
        if len(coverage_store.entries) > MAX_COVERAGE:
            raise ReportError("Coverage snapshot exceeds report row limit.")
        if coverage_store.loaded:
            coverage = tuple(freeze(asdict(row)) for row in coverage_store.entries.values())
        coverage_paths = tuple(Path(p) for p in (coverage_store.path, coverage_store.legacy_path) if p)
    cfg = app.read_config()
    provider = cfg.get("active_provider_name") or ""
    backend = cfg.get("backend") or ""
    backend = getattr(backend, "value", backend)
    del cfg  # Secret-bearing container must not cross the async boundary.
    source = SourceSnapshot(target=target, target_name=agent.target.name(),
        scope=tuple(o.as_url() for o in sorted(agent.engagement_state.allowed_origins)),
        coverage=coverage, session=getattr(getattr(agent, "store", None), "id", ""),
        provider=provider, backend=backend, model=agent.client.model(), version=VERSION,
        exported_at=exported_at, running=bool(agent.running), restored=bool(getattr(app, "resume_summary", "")), **data)
    resources = Resources(Path(store.project_dir), tuple(dict.fromkeys((Path(store.dir), Path(store.project_dir) / "findings"))),
                          Path(getattr(workflow_tool, "evidence_root", store.project_dir)), coverage_paths)
    return source, resources, identity


def _notice(app: Any, text: str, *, error: bool = False) -> None:
    app.dispatch(Append(entry=TranscriptEntry(kind="error" if error else "system", text=text)))


def start_report(app: Any, args: list[str]) -> asyncio.Task | None:
    """Synchronous entry guarantees capture before the first async suspension."""
    key = id(app)
    if key in _IN_FLIGHT:
        _notice(app, "/report: a report export is already in progress.")
        return None
    try:
        if len(args) > 1:
            raise ReportError("Use /report [filename.pdf]; reports are saved under artifacts/reports/.")
        if args:
            validate_filename(args[0])
        now = datetime.now(timezone.utc).isoformat()
        source, resources, identity = capture(app, now)
        filename = args[0] if args else default_filename(source.session, source.objective.get("id", ""), now)
    except ReportError as exc:
        _notice(app, f"/report: {exc} No completed PDF was created.", error=True)
        return None
    except Exception:
        _notice(app, "/report: snapshot capture unavailable. Run /report again after restoring valid state. No completed PDF was created.", error=True)
        return None
    task = asyncio.create_task(_export(app, source, resources, identity, filename))
    _IN_FLIGHT[key] = task

    def finished(done: asyncio.Task) -> None:
        if _IN_FLIGHT.get(key) is done:
            _IN_FLIGHT.pop(key, None)
        if not done.cancelled():
            done.exception()  # Consume unexpected local failures without logging secrets.

    task.add_done_callback(finished)
    return task


def _prepare(source: SourceSnapshot, resources: Resources, filename: str):
    from src.report.pdf import render_pdf
    doc = build_report(source, resources)
    pdf = render_pdf(doc)
    stage = stage_report(resources.project, filename, pdf)
    return doc, stage


async def _export(app: Any, source: SourceSnapshot, resources: Resources, identity: tuple[Any, ...], filename: str) -> None:
    # Executor Futures are not Tasks cancelled by asyncio.run's shutdown sweep.
    # Shield this Future so every cancellation path can still receive and clean
    # the eventual stage. Preserve to_thread's context propagation.
    context = contextvars.copy_context()
    worker = asyncio.get_running_loop().run_in_executor(
        None, lambda: context.run(_prepare, source, resources, filename))
    stage: StagedReport | None = None
    cancelled = False
    try:
        _notice(app, "Generating report…")
        # A cancelled waiter cannot stop an offloaded writer. Drain it, even
        # under repeated cancellation, and clean its stage without publication.
        while True:
            try:
                doc, stage = await asyncio.shield(worker)
                break
            except asyncio.CancelledError:
                cancelled = True
                if worker.done():
                    doc, stage = worker.result()
                    break
        if cancelled:
            raise asyncio.CancelledError
        if assessment_identity(app) != identity:
            raise ReportError("Assessment changed during export; run /report again.")
        final = stage.publish()
        warning_count = doc.unavailable_count + doc.unfinalized_count + doc.omitted_count + len(doc.evidence)
        warning_count += sum("incomplete" in text.lower() or "unavailable" in text.lower() for text in doc.limitations)
        text = f"PDF report saved: {Sanitizer().text(str(final.relative_to(resources.project)))} — {doc.finding_count} findings; {doc.status}"
        if warning_count:
            text += f" {warning_count} data-gap/omission warnings; see report limitations."
        _notice(app, text)
    except asyncio.CancelledError:
        _notice(app, "/report: export cancelled. No completed PDF was created.")
        raise
    except ReportError as exc:
        _notice(app, f"/report: {exc} No completed PDF was created.", error=True)
    except Exception:
        _notice(app, "/report: local PDF generation/output failed. Check local fonts, dependencies and artifacts/reports/ access. No completed PDF was created.", error=True)
    finally:
        if stage is not None:
            stage.cleanup()
        _IN_FLIGHT.pop(id(app), None)
