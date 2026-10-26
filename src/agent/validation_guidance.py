"""Short, transient continuation hints from the current runtime projection."""
from typing import Any

from src.workflow.validation.route import ValidationRoute


def expert_attempt_preparation(skill: str, candidate_id: str) -> str:
    """Shared ordering for a new expert attempt; no requests or authority."""
    return (
        f'After current prerequisites are complete, read the current playbook with load_skill(name="{skill}"). '
        'Before start_validation, prepare the primary request and supplementary method/URL '
        'associations/roles from the existing Candidate, inventory and context. Do not guess endpoints '
        'or probe to prepare them. Prefer candidate_id alone for the primary request with '
        'no supplementary associations; otherwise declare unique method/URL entries once in '
        'related_requests with a consistent role. Different methods on '
        'the same path are different request identities; payload variations are observations. '
        f'Then call workflow(action="start_validation", candidate_id="{candidate_id}", ...) successfully '
        'before probes → evidence → result. Association grants no execution permission. '
        'Owned active attempts keep their immutable declaration and recovery budget.'
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
    effects = handoff.get('effects', {})
    if action == 'retry_declined':
        lines.append(f"Further retry explicitly declined: {handoff.get('retry_decision')}. "
                     'Preserve the unresolved result; do not repeat the same retry decision. '
                     'If a useful revised strategy is identified, explicitly reconsider with record_retry_decision '
                     '(decision=retry and reason describing it), or explain the strategy and start_validation '
                     'through existing admission/permission gates. This is not a permanent retest prohibition.')
        return '\n'.join(lines)
    if handoff.get('retry_eligible'):
        lines.append(f"Previous outcome: insufficient-evidence; reason: {str(handoff.get('latest_reason') or 'not recorded')[:160]}; "
                     f"evidence_refs={handoff.get('evidence_refs', [])[:3]}; retry_decision={handoff.get('retry_decision')}. "
                     'Retry is optional, not running. Decide from existing observations: revised strategy → start_validation, '
                     'or record_retry_decision(retry_decision={decision: decline, reason: <grounded reason>}). '
                     'insufficient-evidence alone is neither retry nor decline.')
    if action == 'reconcile_discovery':
        lines.append(f"Investigation returned tool result {handoff.get('discovery_attempt_ref')}; "
                     'reconcile its outcome through record_candidate before further discovery. '
                     'The stored step is investigated, not fresh work. Do not replay it. '
                     'Replace it only with an evidence-based next question or meaningful hypothesis; '
                     're-recording the same step or omitting it preserves this reconciliation requirement. '
                     'Otherwise clear it explicitly with the resolved queued/deferred_reason=null decision '
                     'or a concrete deferred stop/dependency reason. This result grants no validation readiness. '
                     'Ready independent validation and finding persistence take precedence.')
        return '\n'.join(lines)
    if action == 'discover_request':
        lines.append('Request discovery remains open independently of completed input triage. '
                     'Load web-input-analysis; choose a useful authorized source review or request-hypothesis probe '
                     'for the recorded discovery_next_step. This plan is not observed request context or permission. '
                     'Keep inferred/observed provenance explicit. After execution reconcile the outcome before another '
                     'discovery request: clear the completed step or update it. Do not repeat unchanged discovery; update the step '
                     'from new evidence or a meaningful hypothesis. Resolve it explicitly, or close it with the actual '
                     'non-actionable/access dependency reason; missing schema alone is not operator-only. '
                     'Ready independent validation and finding persistence take precedence.')
        return '\n'.join(lines)
    if handoff['owned_active'] and effects.get('declaration_required'):
        lines.append('Effects declaration required after the latest target dispatch. A later request invalidates an earlier '
                     'no-mutation/cleanup declaration. Finish only necessary validation, then record_attempt_state from usable '
                     'owned observations before finalization. Unknown effects do not prove a write occurred.')
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
                     'Closed/interrupted attempts need current admission; prestart captures stay unowned.')
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
            if action == 'start_validation' and handoff.get('retry_eligible'):
                lines.append('Reassess SQL boundaries and the oracle for a meaningful revised hypothesis; '
                             'prefer harmless computed expressions where applicable; no automatic probe or required technique.')
            elif action in {'start_validation', 'resume_owned'}:
                lines.append('Choose technique by context/oracle; control in active attempt. Reuse suitable observations. Full query text is not required. '
                             'Observation → Hypothesis → Oracle → Expected Result → Falsifier → Next Decision: '
                             'competing SQL prefix/input/suffix shapes with same prediction add no information. '
                             'If syntax unresolved: TRUE preserves benign marker before FALSE; do not batch. '
                             'Inconclusive/failed TRUE: reassess context/oracle. '
                             'Continue useful discriminating tests within scope, permissions and runtime/operator limits; no numeric shape cap. '
                             'Failed probes leave other hypotheses open. Avoid equivalent probes; sufficient evidence needs no extra requests.')
            elif action == 'finalize_owned':
                lines.append('Describe actual observations, hypotheses tested, remaining uncertainty and the real stop reason. '
                             'Keep Candidate status, ValidationResult outcome, goal status and finding eligibility separate; '
                             'Phase 3 unmet prerequisites do not turn insufficient-evidence into not-confirmed.')
            lines.append('Boolean confirmation (conditional): two complete TRUE/FALSE repetitions, four distinct owned observations '
                         'and structured confirmation. No retrieval/ownership resends; bounded plans only, else unresolved.')
        elif skill == 'cross-site-scripting':
            if action in {'start_validation', 'resume_owned'}:
                lines.append('Identify input source, output/DOM sink, execution context and observed transformations. '
                             'Choose a minimal context-appropriate test for a discriminating prediction; reuse adequate observations. '
                             'Separate reflection, neutralization and execution evidence; necessary but unavailable browser proof stays browser-required. '
                             'New observations can justify further adaptation; avoid equivalent variants and finalize when evidence suffices.')
            lines.append('Raw HTML in JSON is an observation, not an XSS Candidate when rendering context or a compatible '
                         'source-to-sink path is unknown. Do not mutate to rescue an unsupported hypothesis. '
                         'Distinguish JSON readback, persistence, executable rendering and execution proof. '
                         'CAPTCHA issuance alone does not show CAPTCHA rejection or interception.')
    return '\n'.join(lines)
