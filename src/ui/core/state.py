from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Literal, Union, cast

from src.agent.events import (
    AgentEvent,
    AssistantTextEvent,
    AssistantDeltaEvent,
    ToolCallEvent,
    ToolResultEvent,
    ErrorEvent,
    CompactEvent,
    DecisionEvent,
    SkillActiveEvent,
    MemoryRecallEvent,
    DoneEvent,
)

if TYPE_CHECKING:
    from src.ui.bridges.ask_bridge import AskRequest
    from src.ui.bridges.perm_bridge import BridgedPermissionRequest
    from src.ui.widgets.banner import BannerData
else:
    AskRequest = Any
    BridgedPermissionRequest = Any
    BannerData = Any

from src.tools.common.tool_display import display_tool_name
from src.ui.core.admission import PendingCall, call_metadata, result_issues, issue_category
from src.ui.core.outcomes import OutcomeFacts, ProgressRecord, concise_text
from src.ui.render.sanitize import sanitize_text


TranscriptKind = Literal[
    "user",
    "assistant",
    "system",
    "error",
    "finding",
    "info",
    "warning",
    "validation",
]

UiPhase = Literal[
    "idle",
    "planning",
    "running-tool",
    "answering",
    "waiting-approval",
    "waiting-user",
    "skills",
]

@dataclass(frozen=True, slots=True, weakref_slot=True)
class TranscriptEntry:
    kind: TranscriptKind
    text: str
    streaming: bool = False
    details: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PresentedIssue:
    key: str
    operation: str
    index: int
    text: str
    count: int = 1
    recovered: bool = False
    category: str = "failure"
    recovery_identity: str = ""


@dataclass(frozen=True, slots=True)
class AppState:
    banner: str
    banner_data: BannerData
    transcript: tuple[TranscriptEntry, ...] = field(default_factory=tuple)
    transcript_revision: int = 0
    busy: bool = False
    clear_gen: int = 0
    clear_message: str | None = None
    api_ready: bool = True
    active_skill: str | None = None
    pending_perm: BridgedPermissionRequest  | None = None
    pending_ask: AskRequest | None = None
    pending_skills: bool = False
    yolo: bool = False
    phase: UiPhase = "idle"
    running_tool: str | None = None
    presentation_scope: str = ""
    issues: tuple[PresentedIssue, ...] = field(default=(), repr=False)
    milestones: tuple[str, ...] = field(default=(), repr=False)
    delivered_results: tuple[str, ...] = field(default=(), repr=False)
    outcome_written: bool = False
    deferred_outcome: str | None = None
    deferred_facts: OutcomeFacts | None = field(default=None, repr=False)
    pending_calls: tuple[PendingCall, ...] = field(default=(), repr=False)
    # Buffer incomplete credentials until a complete message/event boundary.
    stream_chunks: tuple[str, ...] = field(default=(), repr=False)
    baseline: OutcomeFacts | None = field(default=None, repr=False)
    latest_facts: OutcomeFacts | None = field(default=None, repr=False)
    progress_rows: tuple[tuple[str, int], ...] = field(default=(), repr=False)
    observed: tuple[ProgressRecord, ...] = field(default=(), repr=False)
    activated_skills: tuple[str, ...] = ()
    skill_receipts: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    running_skill: str | None = None
    planner_recommendation: tuple[str, str] | None = None


def initial_state(banner: str, banner_data: BannerData) -> AppState:
    return AppState(banner=banner, banner_data=banner_data)


@dataclass(frozen=True, slots=True)
class SetBanner:
    banner: str


@dataclass(frozen=True, slots=True)
class MergeBannerData:
    patch: dict[str, Any]


@dataclass(frozen=True, slots=True)
class Append:
    entry: TranscriptEntry


@dataclass(frozen=True, slots=True)
class AppendDelta:
    text: str


@dataclass(frozen=True, slots=True)
class SetBusy:
    busy: bool
    facts: OutcomeFacts | None = None


@dataclass(frozen=True, slots=True)
class SetApiReady:
    ready: bool


@dataclass(frozen=True, slots=True)
class SetActiveSkill:
    name: str | None


@dataclass(frozen=True, slots=True)
class SetYolo:
    on: bool


@dataclass(frozen=True, slots=True)
class SetPerm:
    req: BridgedPermissionRequest  | None


@dataclass(frozen=True, slots=True)
class SetAsk:
    req: AskRequest | None


@dataclass(frozen=True, slots=True)
class SetSkillsPicker:
    open: bool


@dataclass(frozen=True, slots=True)
class Clear:
    message: str | None = None


@dataclass(frozen=True, slots=True)
class FinalizeDeferredOutcome:
    pass


@dataclass(frozen=True, slots=True)
class AgentEventAction:
    event: AgentEvent
    facts: OutcomeFacts | None = None


Action = Union[
    SetBanner,
    MergeBannerData,
    Append,
    AppendDelta,
    SetBusy,
    SetApiReady,
    SetActiveSkill,
    SetYolo,
    SetPerm,
    SetAsk,
    SetSkillsPicker,
    Clear,
    AgentEventAction,
    FinalizeDeferredOutcome,
]


def reducer(state: AppState, action: Action) -> AppState:
    match action:
        case SetBanner(banner=banner):
            return replace(state, banner=banner)

        case MergeBannerData(patch=patch):
            merged = replace(
                state.banner_data,
                **patch,
            )
            return replace(state, banner_data=merged)

        case Append(entry=entry):
            state = _finish_stream(state)
            entry = replace(entry, text=sanitize_text(entry.text),
                            details=tuple(sanitize_text(detail) for detail in entry.details))
            return replace(state, transcript=(*state.transcript, entry))

        case AppendDelta(text=text):
            phase: UiPhase = "answering" if state.busy else state.phase
            last = state.transcript[-1] if state.transcript else None
            if last is not None and last.kind == "assistant" and last.streaming:
                return replace(state, phase=phase, stream_chunks=(*state.stream_chunks, text))
            return replace(
                state,
                phase=phase,
                stream_chunks=(text,),
                transcript=(*state.transcript, TranscriptEntry(kind="assistant", text="Assistant text streaming; awaiting sanitized message", streaming=True)),
            )

        case SetBusy(busy=busy, facts=facts):
            if busy and not state.busy:
                state = replace(state, issues=(), milestones=(), delivered_results=(), pending_calls=(), outcome_written=False,
                                deferred_outcome=None, deferred_facts=None,
                                baseline=replace(facts, records=tuple(row for row in facts.records if row.kind != "capture")) if facts else None,
                                latest_facts=facts,
                                progress_rows=(), observed=(), activated_skills=(), skill_receipts=(),
                                active_skill=None, running_tool=None, running_skill=None, planner_recommendation=None,
                                presentation_scope=facts.scope if facts else state.presentation_scope)
            return replace(state, busy=busy, phase="planning" if busy else "idle",
                           running_tool=state.running_tool if busy else None,
                           running_skill=state.running_skill if busy else None,
                           active_skill=state.active_skill if busy else None,
                           pending_calls=state.pending_calls if busy else ())

        case SetApiReady(ready=ready):
            return replace(state, api_ready=ready)

        case SetActiveSkill(name=name):
            return replace(state, active_skill=sanitize_text(name) if name is not None else None)

        case SetYolo(on=on):
            return replace(state, yolo=on)

        case SetPerm(req=req):
            return replace(
                state,
                pending_perm=req,
                phase="waiting-approval" if req else ("running-tool" if state.busy else "idle"),
            )

        case SetAsk(req=req):
            return replace(
                state,
                pending_ask=req,
                phase="waiting-user" if req else ("running-tool" if state.pending_calls
                                                  else "answering" if state.busy else "idle"),
            )

        case SetSkillsPicker(open=open_):
            return replace(state, pending_skills=open_, phase="skills" if open_ else "idle")

        case Clear(message=message):
            return replace(
                state,
                transcript=(),
                clear_gen=state.clear_gen + 1,
                transcript_revision=state.transcript_revision + 1,
                stream_chunks=(),
                pending_calls=(),
                issues=(), milestones=(), delivered_results=(), outcome_written=False,
                presentation_scope="", deferred_outcome=None, deferred_facts=None,
                baseline=None, latest_facts=None, progress_rows=(), observed=(),
                activated_skills=(), skill_receipts=(), running_skill=None, running_tool=None, planner_recommendation=None,
                clear_message=sanitize_text(message) if message is not None else None,
                active_skill=(
                    None
                    if message == "conversation reset"
                    else state.active_skill
                ),
            )

        case FinalizeDeferredOutcome():
            if state.deferred_outcome is None:
                return state
            return _finish_outcome(state, state.deferred_outcome, state.deferred_facts)

        case AgentEventAction(event=event, facts=facts):
            if state.outcome_written and isinstance(event, (DecisionEvent, SkillActiveEvent, ToolCallEvent,
                                                            AssistantDeltaEvent, AssistantTextEvent)):
                return state
            if facts and facts.stale_event:
                if facts.scope == state.presentation_scope:
                    return state
                return replace(state, pending_calls=(), running_tool=None, running_skill=None, active_skill=None,
                               phase="waiting-approval" if state.pending_perm else "waiting-user" if state.pending_ask
                               else "answering" if state.busy else "idle")
            if facts and facts.scope != state.presentation_scope:
                state = replace(state, presentation_scope=facts.scope, issues=(), milestones=(),
                                delivered_results=(), outcome_written=False, deferred_outcome=None, deferred_facts=None,
                                baseline=replace(facts, records=tuple(row for row in facts.records if row.kind != "capture")),
                                latest_facts=facts, progress_rows=(), observed=(), pending_calls=(),
                                active_skill=None, activated_skills=(), skill_receipts=(), running_tool=None,
                                running_skill=None, planner_recommendation=None)
            elif facts:
                state = replace(state, latest_facts=facts, baseline=state.baseline or facts)
            return _apply_agent_event(state, event, facts)

        case _:
            raise AssertionError(f"Unhandled action: {action!r}")


def _present_issue(state: AppState, operation: str, text: str, *, category: str = "failure",
                   root: str | None = None, recovery_identity: str = "") -> AppState:
    key = hashlib.sha256((operation + "\n" + category + "\n" + (root or text)).encode()).hexdigest()
    kind: TranscriptKind = ("system" if category == "diagnostic" else "warning"
                            if category in {"incomplete", "denial", "cancelled", "export", "pending"} else "error")
    previous = next((issue for issue in state.issues if issue.key == key), None)
    if previous:
        updated = replace(previous, count=previous.count + 1, recovered=False, recovery_identity=recovery_identity)
        transcript = list(state.transcript)
        transcript[previous.index] = TranscriptEntry(kind=kind, text=f"{text} (repeated {updated.count} times)")
        return replace(state, issues=tuple(updated if item is previous else item for item in state.issues),
                       transcript=tuple(transcript), transcript_revision=state.transcript_revision + 1)
    issue = PresentedIssue(key, operation, len(state.transcript), text, category=category, recovery_identity=recovery_identity)
    return replace(state, issues=(*state.issues[-255:], issue),
                   transcript=(*state.transcript, TranscriptEntry(kind=kind, text=text)))


def _recover_issues(state: AppState, operation: str, recovery_identity: str) -> AppState:
    transcript = list(state.transcript)
    issues = list(state.issues)
    changed = False
    for i, issue in enumerate(issues):
        if (issue.operation == operation and not issue.recovered
                and issue.category in {"failure", "denial", "export", "network", "pending"}
                and (issue.recovery_identity == recovery_identity or issue.category == "network")):
            issues[i] = replace(issue, recovered=True)
            transcript[issue.index] = TranscriptEntry(kind="info", text=
                f"{issue.text} (seen {issue.count} times; recovered by successful operation receipt)")
            changed = True
    return replace(state, issues=tuple(issues), transcript=tuple(transcript),
                   transcript_revision=state.transcript_revision + 1) if changed else state


def _finish_stream(state: AppState, text: str | None = None) -> AppState:
    last = state.transcript[-1] if state.transcript else None
    if last is None or last.kind != "assistant" or not last.streaming:
        return state
    safe = sanitize_text(text if text is not None else "".join(state.stream_chunks))
    return replace(state, stream_chunks=(),
                   transcript=(*state.transcript[:-1], replace(last, text=safe, streaming=False)))


def _activity_label(name: str) -> str:
    return "Saving finding" if name == "confirm_finding" else sanitize_text(display_tool_name(name))


def _new_records(state: AppState, kind: str) -> tuple[ProgressRecord, ...]:
    baseline = {(row.kind, row.key) for row in state.baseline.records} if state.baseline else set()
    current = state.latest_facts.records if state.latest_facts else ()
    return tuple({row.key: row for row in (*current, *state.observed)
                  if row.kind == kind and (row.kind, row.key) not in baseline}.values())


def _progress_row(state: AppState, key: str, text: str, kind: TranscriptKind = "system") -> AppState:
    rows = dict(state.progress_rows)
    entry = TranscriptEntry(kind=kind, text=sanitize_text(text))
    if key in rows:
        index = rows[key]
        if state.transcript[index] == entry:
            return state
        transcript = list(state.transcript)
        transcript[index] = entry
        return replace(state, transcript=tuple(transcript), transcript_revision=state.transcript_revision + 1)
    rows[key] = len(state.transcript)
    return replace(state, progress_rows=tuple(rows.items()), transcript=(*state.transcript, entry))


def _milestone(state: AppState, key: str, text: str, kind: TranscriptKind = "info") -> AppState:
    if key in state.milestones:
        return state
    primary, *details = text.splitlines()
    return replace(state, milestones=(*state.milestones, key),
                   transcript=(*state.transcript, TranscriptEntry(kind=kind, text=sanitize_text(primary),
                       details=tuple(sanitize_text(detail.strip()) for detail in details))))


def _quantity(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular if count == 1 else plural or singular + 's'}"


def _examples(records: tuple[ProgressRecord, ...]) -> str:
    labels = list(dict.fromkeys(row.label for row in records))
    return "; ".join(labels[:3]) + (f"; +{len(labels)-3} more" if len(labels) > 3 else "")


def _flush_selection(state: AppState) -> AppState:
    selected, captures = _new_records(state, "selection"), _new_records(state, "capture")
    if selected:
        text = f"Selected: {_examples(selected)} ({_quantity(len(selected), 'input')})"
        if captures:
            text += f"; {_quantity(len(captures), 'captured request')} selected"
    elif captures:
        text = f"Selected capture: {_examples(captures)} ({_quantity(len(captures), 'captured request')})"
    else:
        return state
    return _progress_row(state, "selection", text + ".", "info")


def _flush_progress(state: AppState) -> AppState:
    if state.latest_facts and state.latest_facts.overview:
        state = _progress_row(state, "workflow", state.latest_facts.overview)
    inputs, endpoints = _new_records(state, "input"), _new_records(state, "endpoint")
    if inputs or endpoints:
        dispositions = {value: sum(row.disposition == value for row in inputs)
                        for value in ("analyzed", "pending", "blocked", "dropped")}
        details = ", ".join(f"{count} {key}" for key, count in dispositions.items() if count)
        state = _progress_row(state, "inventory", f"Attack surface recorded: {_quantity(len(endpoints), 'endpoint')}, "
                              f"{_quantity(len(inputs), 'input')}" + (f" ({details})" if details else "") +
                              f"; {_examples(inputs or endpoints)}.")
    state = _flush_selection(state)
    candidates = _new_records(state, "candidate")
    if candidates:
        text = "Candidate recorded" if len(candidates) == 1 else f"Candidates recorded · {len(candidates)}"
        state = _progress_row(state, "candidates", f"{text} · {_examples(candidates)}.", "info")
    validations = _new_records(state, "validation")
    if validations:
        for row in sorted(validations, key=lambda row: row.order):
            text = f"Validation {row.disposition.replace('-', ' ')} · {row.label}"
            if row.detail:
                text += f"\n  Observed impact · {concise_text(row.detail)}"
            if row.evidence:
                text += f"\n  Evidence · {concise_text(row.evidence)}"
            state = _milestone(state, "validation:" + row.key, text,
                               "validation" if row.disposition == "confirmed" else "info")
    observations = _new_records(state, "observation")
    if observations:
        state = _progress_row(state, "observations", f"HTTP activity (observations only): "
                              f"{_quantity(len(observations), 'response')} · {_examples(observations)}.")
    return state


def _apply_agent_event(state: AppState, ev: AgentEvent, facts: OutcomeFacts | None = None) -> AppState:
    if not isinstance(ev, (AssistantDeltaEvent, AssistantTextEvent)):
        state = _finish_stream(state)
    match ev:
        case AssistantTextEvent(text=text):
            last = state.transcript[-1] if state.transcript else None
            if last is not None and last.kind == "assistant" and last.streaming:
                return replace(_flush_progress(_finish_stream(state, text)), phase="answering")
            state = _flush_progress(state)
            return replace(
                state,
                phase="answering",
                transcript=(*state.transcript, TranscriptEntry(kind="assistant", text=sanitize_text(text))),
            )

        case AssistantDeltaEvent(text=text):
            return reducer(state, AppendDelta(text=text))

        case ToolCallEvent():
            call = call_metadata(ev)
            if facts and facts.activity:
                call = replace(call, activity=facts.activity)
            call = replace(call, scope=state.presentation_scope,
                           identity=(facts.operation_owner if facts and facts.operation_owner else call.identity),
                           skill=(facts.activity_skill if facts and facts.activity_skill else call.skill),
                           recovery_identity=(facts.operation_owner if facts and facts.operation_owner else call.recovery_identity))
            if call.operation == "start_validation":
                state = _flush_progress(state)
            elif call.name == "http":
                state = _flush_selection(state)
            pending = tuple(item for item in state.pending_calls if item.id != ev.id)
            return replace(state, pending_calls=(*pending[-255:], call) if ev.id else pending,
                           phase="waiting-approval" if state.pending_perm else "waiting-user" if state.pending_ask else "running-tool",
                           running_skill=call.skill if call.skill in state.activated_skills else None,
                           running_tool=sanitize_text(_activity_label(ev.name) +
                           (": " + (facts.activity if facts and facts.activity else call.activity)
                            if (facts and facts.activity) or call.activity else "")))

        case ToolResultEvent():
            call = next((item for item in state.pending_calls if ev.id and item.id == ev.id and item.name == ev.name), None)
            pending = tuple(item for item in state.pending_calls if item is not call)
            state = replace(state, pending_calls=pending,
                            phase=("idle" if state.outcome_written else "waiting-approval" if state.pending_perm
                                   else "waiting-user" if state.pending_ask else "running-tool" if pending else "answering"),
                            running_skill=pending[-1].skill if pending and pending[-1].skill in state.activated_skills else None,
                            running_tool=(_activity_label(pending[-1].name) +
                                          (": " + pending[-1].activity if pending[-1].activity else "")) if pending else None)
            delivery = hashlib.sha256(repr((ev.id, ev.name, ev.result, ev.err, ev.status,
                                            ev.error_kind, ev.truncated)).encode()).hexdigest()
            if ev.id and delivery in state.delivered_results:
                return state
            if ev.id:
                state = replace(state, delivered_results=(*state.delivered_results[-255:], delivery))
            issues = result_issues(ev, call)
            operation = ev.name + ":" + (call.identity if call else "uncorrelated:" + ev.id)
            recovery_identity = call.recovery_identity if call else "uncorrelated:" + ev.id
            context = facts.activity if facts and facts.activity else call.activity if call else ""
            if issues:
                groups: dict[str, list[str]] = {}
                for issue in issues:
                    if issue.startswith("Validation ") and facts and any(
                            key.startswith("validation-pause:") for key, _, _ in facts.milestones):
                        continue
                    groups.setdefault(issue_category(issue, ev), []).append(issue)
                for category, notices in groups.items():
                    state = _present_issue(state, operation, sanitize_text(display_tool_name(ev.name)) +
                                           (" · " + context if context else "") + ": " + "; ".join(notices),
                                           category=category, recovery_identity=recovery_identity)
            completed = bool(call and ev.status in {"success", "observation"} and not ev.err
                             and all(issue_category(issue, ev) in {"diagnostic", "incomplete"} for issue in issues))
            if completed and ev.name == "workflow":
                try:
                    receipt = json.loads(ev.result)
                except (ValueError, TypeError):
                    receipt = None
                completed = isinstance(receipt, dict) and receipt.get("ok") is True
                if completed and call and call.operation in {"record_result", "start_validation"}:
                    completed = bool(facts and facts.accepted_call)
            if completed:
                state = _recover_issues(state, operation, recovery_identity)
                if call and call.name == "load_skill":
                    state = replace(state, skill_receipts=(*state.skill_receipts, (call.id, call.skill)))
                elif ev.name not in {"http", "workflow", "confirm_finding", "read_skill_file", "read_payloads", "browser_capture_status"}:
                    state = replace(state, observed=(*state.observed, ProgressRecord(
                        "operation", ev.id, sanitize_text(display_tool_name(ev.name)))))
            if ev.name == "http" and ev.status in {"success", "observation"} and not ev.err and ev.http_status is not None and call:
                state = replace(state, observed=(*state.observed, ProgressRecord("observation", ev.id,
                                context or _activity_label(ev.name), str(ev.http_status))))
            flush_progress = bool(call and (call.operation in {"start_validation", "complete_skill", "record_result"}
                                            or ev.name == "confirm_finding"))
            if flush_progress:
                state = _flush_progress(state)
            if facts:
                for key, kind, text in facts.milestones:
                    baseline = {row.key for row in state.baseline.records if row.kind == "finding"} if state.baseline else set()
                    if key not in baseline:
                        state = _milestone(state, key, text, cast(TranscriptKind, kind))
            if not flush_progress and facts and facts.overview:
                state = _progress_row(state, "workflow", facts.overview)
            return state

        case ErrorEvent(err=agent_err):
            state = replace(state, phase="waiting-approval" if state.pending_perm else "waiting-user" if state.pending_ask
                            else "running-tool" if state.pending_calls else "answering" if state.busy else state.phase)
            from src.llm.runtime.context_budget import ContextCapacityError
            return _present_issue(state, "runtime", sanitize_text(str(agent_err)),
                                  root="context capacity" if isinstance(agent_err, ContextCapacityError) else None,
                                  category="cancelled" if isinstance(agent_err, BaseException)
                                  and str(agent_err) == "turn cancelled" else "failure")

        case DecisionEvent(summary=summary):
            if not state.pending_calls and not state.pending_perm and not state.pending_ask:
                state = replace(state, phase="planning", running_tool=None, running_skill=None)
            if summary.startswith(("context guard:", "context pressure:")) and (
                    "unresolved pressure:" in summary or "fixed/non-compactable floor" in summary):
                root = "fixed context floor" if "fixed/non-compactable floor" in summary else "reducible capacity pressure"
                return _present_issue(state, "context", sanitize_text(summary), category="diagnostic", root=root)
            if ev.recommended_skill:
                event_key = "planner:" + ev.decision_id if ev.decision_id else ""
                if event_key and event_key in state.milestones:
                    return state
                if event_key:
                    state = replace(state, milestones=(*state.milestones, event_key))
                recommendation = (ev.recommended_skill, ev.candidate_id or "")
                if recommendation != state.planner_recommendation:
                    state = replace(state, planner_recommendation=recommendation,
                                    transcript=(*state.transcript, TranscriptEntry(kind="info",
                                        text="Planner recommended · " + concise_text(ev.recommended_skill, 100))))
            return state

        case CompactEvent():
            return state if state.pending_calls or state.pending_perm or state.pending_ask else replace(state, phase="planning")

        case SkillActiveEvent(name=name):
            if ev.call_id and (ev.call_id, name) not in state.skill_receipts:
                return state
            if ev.call_id:
                key = "activation:" + ev.call_id
                if key in state.milestones:
                    return state
                state = replace(state, milestones=(*state.milestones, key))
            state = _flush_progress(state)
            if name and name != state.active_skill:
                state = replace(state, transcript=(*state.transcript, TranscriptEntry(kind="info",
                    text="Skill activated · " + concise_text(name, 100))))
            return replace(state, active_skill=sanitize_text(name),
                           activated_skills=tuple(dict.fromkeys((*state.activated_skills, name))))

        case MemoryRecallEvent():
            return state

        case DoneEvent():
            state = replace(state, busy=False, phase="waiting-user" if state.pending_ask else "idle",
                            running_tool=None, running_skill=None, active_skill=None, pending_calls=())
            if ev.stop_reason == "max_steps" and state.pending_ask is not None:
                return replace(state, deferred_outcome=ev.stop_reason, deferred_facts=facts)
            if state.outcome_written:
                return state
            return _finish_outcome(state, ev.stop_reason, facts)

        case _:
            raise AssertionError(f"Unhandled AgentEvent: {ev!r}")


def _finish_outcome(state: AppState, reason: str | None, facts: OutcomeFacts | None) -> AppState:
    if state.outcome_written:
        return state
    label = {
        "final_response": "Turn finished", "workflow_completed": "Workflow completed",
        "workflow_blocked": "Blocked", "workflow_stalled": "Stalled", "cancelled": "Turn cancelled",
        "max_steps": "Stopped at max steps", "runtime_error": "Runtime failure",
        "context_capacity": "Context capacity failure", "client_error": "Provider failure",
        "all_tools_refused": "Blocked by tool refusals", "plan_only_blocked": "Plan-only tool request blocked",
        "invalid_response": "Invalid response",
    }.get(reason or "", f"Turn ended ({reason})" if reason else "Turn ended (runtime outcome unavailable)")
    pending = list(facts.pending if facts else ())
    state = _flush_progress(state)
    outstanding = [issue for issue in state.issues if not issue.recovered
                   and issue.category in {"failure", "denial", "network"}]
    displayed_cause = ''
    if reason in {"workflow_blocked", "workflow_stalled", "all_tools_refused"}:
        current_denial = next((issue.text for issue in reversed(outstanding) if issue.category == 'denial'), '')
        cause = (current_denial if reason == 'all_tools_refused' else
                 facts.blockers[0] if facts and facts.blockers else pending[0] if pending else '')
        if cause:
            label += " · " + concise_text(cause)
            displayed_cause = cause
    unresolved = sum(not issue.recovered and issue.category in {"failure", "denial", "network"} for issue in state.issues)
    exports = sum(not issue.recovered and issue.category == "export" for issue in state.issues)
    if unresolved:
        pending.append(_quantity(unresolved, "unrecovered operation issue"))
    permission_pending = sum(not issue.recovered and issue.category == 'pending' for issue in state.issues)
    if permission_pending:
        pending.append(_quantity(permission_pending, 'unresolved permission outcome'))
    if exports:
        pending.append(_quantity(exports, "optional export failure"))
    residual = bool(pending or (facts and (facts.incomplete or facts.goals or facts.blockers)))
    if facts and facts.scope:
        saved, unsaved = len(_new_records(state, "finding")), len(_new_records(state, "unsaved"))
        counts = [(saved, "saved finding"), (unsaved, "accepted-but-unsaved validation"),
                  (facts.incomplete, "incomplete validation"), (facts.goals, "incomplete goal")]
        pending[0:0] = [_quantity(count, noun) for count, noun in counts if count]
        negative = sum(row.disposition == "not-confirmed" for row in _new_records(state, "validation"))
        if negative:
            pending.insert(0, f"{_quantity(negative, 'validation')} not confirmed")
        if facts.blockers:
            pending.append(_quantity(len(facts.blockers), "active workflow blocker"))
    suffix_items = [item for item in pending if item != displayed_cause]
    suffix = "; " + "; ".join(suffix_items) if suffix_items else ""
    operations = _new_records(state, "operation")
    if operations:
        operation_counts: dict[str, int] = {}
        for row in operations:
            operation_counts[row.label] = operation_counts.get(row.label, 0) + 1
        suffix += "; Operations completed: " + "; ".join(
            f"{name} ({count})" for name, count in operation_counts.items())
    if reason == "workflow_completed" and (residual or not facts or not facts.completion_supported):
        label = "Turn finished · workflow work remains" if residual else "Turn finished · workflow completion unavailable"
    return replace(state, outcome_written=True, deferred_outcome=None, deferred_facts=None, transcript=(*state.transcript,
                   TranscriptEntry(kind="error" if reason in {"runtime_error", "context_capacity", "client_error", "invalid_response"}
                                   else "warning" if residual or reason in {"workflow_blocked", "workflow_stalled", "cancelled"}
                                   else "info", text=sanitize_text(label + suffix + "."))))
