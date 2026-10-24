"""Small action hints supplement the existing planner without routing work."""
from src.agent.decision_planner import PlannerContext
from src.tools.workflow.action_view import ActionView


def render_action_guidance(view: ActionView, context: PlannerContext, *, owned_active: bool = False) -> str:
    """Use current validation_handoff ownership, never Candidate status alone."""
    lines = [
        "Workflow action guidance:",
        "Available = exposed for consideration, not permission or guaranteed execution. "
        "Recommended = conditional on current runtime state. "
        "Excluded = incompatible with the verified objective contract.",
    ]
    if view.excluded:
        lines.append("Excluded: " + ", ".join(view.excluded) + ".")
    phase = context.structured_phase
    if owned_active or (
        any(c.status == "validating" for c in context.candidates) or context.repair_candidate_ids
    ):
        if context.objective_mode == "whole_target":
            lines.append("Recommended: finish current validation/recovery before discovery.")
        if owned_active:
            lines.append(
                "Recommended: list and reconcile the required request ledger, owned observations and effects. "
                "Use actual IDs/timing; obs_ is not a read_tool_result reference. "
                "Use record_attempt_state promptly for supported effects while ownership/action remains valid; "
                "do not wait for proof. GET or no write acknowledgement does not establish mutation=false; unknown stays unknown.")
            lines.append(
                "Reuse valid proof; otherwise save minimal proof and record_evidence with actual parents. "
                "Choose evidence_refs explicitly; registration does not replace record_result for the active attempt's honest outcome. "
                "With incomplete bounded testing/missing evidence, submit insufficient-evidence or the applicable unresolved outcome "
                "rather than wait for ineligible proof.")
            lines.append(
                "After probing_stopped use only runtime-permitted local actions within existing budgets. "
                "Check the record_result tool response and canonical state for commit; Markdown/summary is not a commit.")
        else:
            lines.append(
                "Recommended: no owned active attempt; inspect list and the runtime handoff for permitted evidence repair, "
                "exact retries or current admission. Preserve terminal results and recovery budgets; do not automatically reopen an attempt.")
    elif phase in {"recon", "enumeration", "input_analysis"}:
        if phase == "recon":
            lines.append("Recommended: gather sourced service/technology observations; inspect coverage gaps. Scanner hints are not vulnerabilities.")
        elif phase == "enumeration":
            lines.append(
                'Recommended: as soon as visible documentation, a form or a request call site establishes an input, '
                'call workflow(action="record_input", ...) before fetching another resource. '
                'Record only the observed method, endpoint, parameter and location; do not infer fields from route names. '
                'Prior knowledge is a verification hypothesis, never observed OpenAPI paths or fields. '
                'Use document attribution for documented fields, not request context or replay authority. '
                'This applies even when no source is selected. Defer hypotheses to input analysis.')
            lines.append(
                'Write the canonical partial inventory with known inputs and source limitations; '
                'reading all JavaScript bundles is not a prerequisite. Account for each coverage dimension honestly: '
                'unattested review is observed, never self-claimed performed; skipped/not_applicable need actual reasons. '
                'Resolve selected-source obligations or record supported bounded stops, then complete_skill only when ready.')
            lines.append(
                'Reconcile each retained discovery row before grouping routes: JSON, 401/403, handler errors and '
                'a calibrated SPA wildcard are different observations. A 500 proves neither method/body schema nor auth. '
                'Trace visible JS request methods/fields, not only path strings. Derive totals from reconciled entries. '
                'Keep quote/syntax probes for input analysis; phase=recon is only an annotation. '
                'record_phase_coverage accepts phase, coverage_dimension, coverage_status, coverage_reason; omit coverage_phase.')
        else:
            lines.append(
                'Recommended: analyze inputs; record disposition or record_candidate only with evidenced controllability '
                'and a class-specific hypothesis. Reflection, ordinary search differences and sibling endpoints do not establish SQLi. '
                'Keep exact baseline/status/size/content, including empty data and adverse evidence; a parser error leaves SQL shape unknown. '
                'Use input_id and get_input for canonical endpoint/source context; never drop identity after a binding error. '
                'Unstarted supported work is queued; deferred needs an actual deferred_reason, not merely unconfirmed status.')
            if context.blocked_input_count:
                lines.append(
                    'Blocked inputs prevent complete_skill and new validation admission. Finish other pending triage; '
                    'do not guess credentials or tokens to clear readiness. Use ask_user once for missing input or an '
                    'operator exclusion; only an actual exclusion justifies dropped for that dependency. '
                    'Otherwise keep blocked and report incomplete. Update the artifact before completion; '
                    'an exclusion is untested work, not a negative result or new authority.')
        if phase != "recon":
            lines.append(
                'Readers: get_source is metadata only. Use list(view="sources") then read_discovery_source with an exact ds_ ID '
                'for retained discovery bodies; read_http_observation needs Candidate/Attempt ownership. '
                'Use read_tool_result only for a published tr_ result_ref while its producer capability is allowed. '
                'Use bounded offsets/continuation; missing/truncated content is a limitation, not authority to refetch. '
                'Do not repeat failed reads unchanged or target requests to repair retrieval. Shell HTTP is not a truncation fallback; '
                'ordinary GET needs no Shell exception. Selected sources keep obligations/limitations; unselected sources are not a backlog.')
        if phase != "enumeration":
            lines.append('Reuse visible input IDs and list pages/cursors; record_input may include manual source_attribution. Scanner completion is not discovery completion.')
        lines.append("Check permissions_status; use native discovery only for actual gaps. complete_skill requires ready state and canonical artifacts; repair blockers or state bounded stops.")
    elif context.objective_mode == "whole_target" and context.workflow_status in {"completed", "blocked"}:
        lines.append("Recommended: list current status and blockers; report the bounded outcome or repair the stated dependency. Readiness grants no finding eligibility.")
    elif context.candidates:
        lines.append("Recommended: list to inspect current work; start_validation only with the resolved validator and current prerequisites. Generic restrictions still apply.")
        lines.append("Primary-only: prefer start_validation(candidate_id) when Candidate covers the request; related_requests is for unique method/URL associations, not payloads.")
    else:
        lines.append("Recommended: record_candidate for an observed hypothesis; list for canonical work.")
    if context.coverage_sync_candidate_ids or any(c.coverage_synced is False for c in context.candidates):
        lines.append("Recommended: sync_coverage when the accepted result and proof remain intact.")
    lines.append("Keep proof repair, exact retries/cleanup updates and explicit retests available; runtime rechecks every call.")
    return "\n".join(lines)
