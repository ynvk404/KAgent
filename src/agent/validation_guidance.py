"""Short, transient continuation hints from the current runtime projection."""
from typing import Any

from src.workflow.validation_route import ValidationRoute


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
        start = ('call workflow(action="start_validation", candidate_id="' + handoff['candidate_id'] + '")'
                 if route and route.kind == 'expert' else
                 'resolve the current validator route and its admitted proposal, then call start_validation')
        lines.append('No owned active attempt: ' + start + ' before any validation probes. '
                     'A closed/interrupted attempt is not resumed by HTTP phase="validation"; a new attempt '
                     'must pass current admission and cannot adopt captures from before start.')
    elif action == 'finalize_owned':
        lines.append('Resume local finalization of the owned active attempt only: probing has stopped. '
                     'Inspect list for usable owned sources, save minimal proof, record_evidence then record_result; '
                     'without usable proof record an honest unresolved outcome. Stopped probing alone is not recovery exhaustion.')
    else:
        lines.append('Resume this owned active attempt; do not open a replacement. Inspect list for its sources; '
                     'continue only an identified missing bounded validation step, or save proof, record_evidence and record_result.')
    skill = route.skill_name if route and route.kind == 'expert' else None
    if skill and action not in {'preserve_result', 'stop_recovery'}:
        if skill not in active_skills:
            order = 'After start_validation, reload' if action == 'start_validation' else 'Reload'
            lines.append(f'{order} load_skill(name="{skill}") before validation probes/proof work; '
                         'skill activation expires per turn and grants no authority.')
        if skill == 'sql-injection':
            lines.append('Boolean SQLi confirmation needs two complete TRUE/FALSE repetitions, at least four distinct owned '
                         'observations and structured confirmation under the SQLi skill. Syntax-shape adjustments: '
                         'at most three after the initial signal, guided by observed query shape; no punctuation walk.')
        elif skill == 'cross-site-scripting':
            lines.append('Raw HTML in JSON is not executable XSS proof; establish the actual compatible input/rendering sink. '
                         'CAPTCHA issuance alone does not show CAPTCHA rejection or interception.')
    return '\n'.join(lines)
