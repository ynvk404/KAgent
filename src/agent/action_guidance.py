"""Small action hints supplement the existing planner without routing work."""
from src.agent.decision_planner import PlannerContext
from src.tools.workflow.action_view import ActionView


def render_action_guidance(view: ActionView, context: PlannerContext) -> str:
    lines = [
        "Workflow action guidance:",
        "Available = exposed for consideration, not permission or guaranteed execution. "
        "Recommended = conditional on current runtime state. "
        "Excluded = incompatible with the verified objective contract.",
    ]
    if view.excluded:
        lines.append("Excluded: " + ", ".join(view.excluded) + ".")
    phase = context.structured_phase
    if context.objective_mode == "whole_target" and (
        any(c.status == "validating" for c in context.candidates) or context.repair_candidate_ids
    ):
        lines.append("Recommended: finish owned Attempt/recovery before discovery; list sources, save proof, record_evidence then record_result. Respect probing_stopped and existing budgets.")
    elif phase in {"recon", "enumeration", "input_analysis"}:
        if phase == "recon":
            lines.append("Recommended: gather sourced service/technology observations; inspect coverage gaps. Scanner hints are not vulnerabilities.")
        elif phase == "enumeration":
            lines.append("Recommended: inventory endpoints/sources/inputs; inspect coverage gaps. Defer hypotheses to input analysis.")
        else:
            lines.append("Recommended: analyze inputs; record disposition or record_candidate only with evidenced controllability and compatible input bindings.")
        lines.append("Use bounded list pages/cursors and get_input/get_source; inspect pending/partial/blocked sources and limitations. Native discovery, scanner endpoints, triage and coverage differ; scanner completion is not discovery completion.")
        lines.append("Check permissions_status: ready scanner, native or no scanner depends on gaps. complete_skill requires ready state and canonical artifacts; repair blockers or state bounded stops.")
    elif context.objective_mode == "whole_target" and context.workflow_status in {"completed", "blocked"}:
        lines.append("Recommended: list current status and blockers; report the bounded outcome or repair the stated dependency. Readiness grants no finding eligibility.")
    elif any(c.status == "validating" for c in context.candidates):
        lines.append("Recommended: record_evidence for usable sources; record_result for the active attempt's honest outcome, including unresolved closure.")
        lines.append("Use list for actual owned observation IDs/timing; obs_ is not a read_tool_result reference. Record effects via record_attempt_state before ending; absence is unknown, not false.")
    elif context.candidates:
        lines.append("Recommended: list to inspect current work; start_validation only with the resolved validator and current prerequisites. Generic restrictions still apply.")
        lines.append("Primary-only: prefer start_validation(candidate_id) when Candidate covers the request; related_requests is for unique method/URL associations, not payloads.")
    else:
        lines.append("Recommended: record_candidate for an observed hypothesis; list for canonical work.")
    if context.coverage_sync_candidate_ids or any(c.coverage_synced is False for c in context.candidates):
        lines.append("Recommended: sync_coverage when the accepted result and proof remain intact.")
    lines.append("Keep proof repair, exact retries/cleanup updates and explicit retests available; runtime rechecks every call.")
    return "\n".join(lines)
