"""Short, transient continuation hints from the current runtime projection."""
from typing import Any

from src.workflow.validation.route import ValidationRoute


def expert_attempt_preparation(skill: str, candidate_id: str) -> str:
    """Shared ordering for a new expert attempt; no requests or authority."""
    return (
        f'After current prerequisites are complete, read the current playbook with load_skill(name="{skill}"). '
        'Before start_validation, prepare the primary request and any necessary supplementary method/URL '
        'associations and roles from the existing Candidate, inventory and context. Do not guess endpoints '
        'or send validation probes to prepare them. Prefer candidate_id alone when the Candidate covers '
        'the primary request and no supplementary associations are needed; otherwise declare each unique '
        'supplementary method/URL once in related_requests with a consistent role. Different methods on '
        'the same path are different request identities; payload variations are observations. '
        f'Then call workflow(action="start_validation", candidate_id="{candidate_id}", ...) successfully '
        'before probes → evidence → result. Association grants no execution permission. '
        'An owned active attempt follows resume/recovery with its immutable declaration and budget instead.'
    )


def render_validation_guidance(handoff: dict[str, Any], route: ValidationRoute | None,
                               active_skills: frozenset[str]) -> str:
    action = handoff['next_action']
    recovery = handoff['recovery']
    lines = [
        'Runtime validation continuation (current state, not authorization):',
        f"Candidate {handoff['candidate_id']}; attempt={handoff['attempt_id'] or 'none'} "
        f"status={handoff['attempt_status'] or 'none'}; owned_active={handoff['owned_active']}; "
        f"probing_stopped={handoff['probing_stopped']}. Recovery={recovery['status']} "
        f"rejections={recovery['rejections']}/{recovery['rejection_limit']} "
        f"repair_turns={recovery['repair_turns']}/{recovery['repair_turn_limit']}. "
        'Continue/compaction and reopening the same objective do not reset these counters.',
    ]
    if action == 'preserve_result':
        lines.append('Preserve the terminal result; finish accepted-result coverage/finding persistence if pending. '
                     'Fresh probing requires an explicit retest or the existing evidence-revalidation path through runtime gates.')
    elif action == 'stop_recovery':
        lines.append('Recovery exhausted: no new probes or budget reset. Close an owned active attempt with an honest '
                     'unresolved result if needed; otherwise leave it unresolved. Continue independent work, '
                     'or obtain an explicit operator-selected retest through existing gates.')
    elif action == 'repair_prerequisites':
        lines.append(f"Before validation: {handoff['prerequisite_error']}. "
                     'Use web-input-analysis: inspect list/get_input, record a compatible input if missing, '
                     'analyze it and link_input_candidate before start_validation. Repair required discovery artifacts first.')
    elif action == 'resolve_dependency':
        lines.append('Preserve the unresolved result and inspect list for its recorded dependency. '
                     'Resolve browser/authorization/blocking conditions and follow the validator stop conditions '
                     'before considering a new attempt through existing gates. Do not retry blocked probes or infer authority from Continue.')
    elif action == 'start_validation':
        start = (expert_attempt_preparation(route.skill_name, handoff['candidate_id'])
                 if route and route.kind == 'expert' and route.skill_name else
                 'resolve the current validator route and its admitted proposal, then call start_validation')
        lines.append('No owned active attempt: ' + start + ' before any validation probes. '
                     'A closed/interrupted attempt is not resumed by HTTP phase="validation"; a new attempt '
                     'must pass current admission and cannot adopt captures from before start.')
    elif action == 'finalize_owned':
        lines.append('Resume local finalization of the owned active attempt only: probing has stopped. '
                     'Reuse visible owned sources; list only missing metadata, save minimal proof, record_evidence then record_result; '
                     'without usable proof record an honest unresolved outcome. Stopped probing alone is not recovery exhaustion.')
    else:
        lines.append('Resume this owned active attempt; do not open a replacement. Reuse visible sources; list only missing metadata; '
                     'continue only an identified missing bounded validation step, or save proof, record_evidence and record_result.')
    skill = route.skill_name if route and route.kind == 'expert' else None
    if skill and action not in {'preserve_result', 'stop_recovery'}:
        if skill not in active_skills and action != 'start_validation':
            lines.append(f'Reload load_skill(name="{skill}") before validation probes/proof work; '
                         'skill activation expires per turn and grants no authority.')
        if skill == 'sql-injection':
            if action in {'start_validation', 'resume_owned'}:
                lines.append('Choose technique by context/oracle; control in active attempt. '
                             'Full query text is not required. '
                             'Observation → Hypothesis → Oracle → Expected Result → Falsifier → Next Decision: '
                             'competing shapes with the same prediction add no information. Keep bounds.')
            elif action == 'finalize_owned':
                lines.append('Reconcile used/remaining syntax allowance and the actual stop reason; never call it exhausted while unused. '
                             'Keep Candidate status, ValidationResult outcome, goal status and finding eligibility separate; '
                             'Phase 3 unmet prerequisites do not turn insufficient-evidence into not-confirmed.')
            lines.append('Boolean confirmation only: two complete TRUE/FALSE repetitions, four distinct owned observations '
                         'and structured confirmation. '
                         'Syntax shapes: at most three after the initial signal (Input Analysis included). '
                         'First confirmation change counts; phases/recapture never reset allowance. '
                         'Count executed requests, not proposals. No retrieval/ownership resends; '
                         'Reassess unusable TRUE before FALSE; bounded plans only, else unresolved.')
        elif skill == 'cross-site-scripting':
            lines.append('Raw HTML in JSON is an observation, not an XSS Candidate when rendering context or a compatible '
                         'source-to-sink path is unknown. Do not mutate to rescue an unsupported hypothesis. '
                         'Distinguish JSON readback, persistence, executable rendering and execution proof. '
                         'CAPTCHA issuance alone does not show CAPTCHA rejection or interception.')
    return '\n'.join(lines)
