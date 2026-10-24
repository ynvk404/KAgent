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
    WorkflowProgressEvent,
)

if TYPE_CHECKING:
    from src.ui.render.help import HelpDocument
    from src.ui.bridges.ask_bridge import AskRequest
    from src.ui.bridges.perm_bridge import BridgedPermissionRequest
    from src.ui.widgets.banner import BannerData
else:
    AskRequest = Any
    BridgedPermissionRequest = Any
    BannerData = Any

from src.tools.common.tool_display import display_tool_name
from src.tools.common.runtime_metadata import RuntimeMetadata
from src.ui.core.admission import PendingCall, call_metadata, invocation_call, result_issues, issue_category, http_activity
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
    help_document: HelpDocument | None = None


@dataclass(frozen=True, slots=True)
class TurnDetails:
    """Latest local UI outcome snapshot; never serialized into a session."""
    turn_number: int
    stop_reason: str | None
    outcome: str
    saved_findings: int
    unsaved_validations: int
    incomplete_validations: int
    incomplete_goals: int
    remaining: tuple[str, ...]
    completed_operations: tuple[tuple[str, int], ...]


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
    milestones: tuple[str, ...] = field(default=(), repr=False)
    delivered_results: tuple[str, ...] = field(default=(), repr=False)
    outcome_written: bool = False
    deferred_outcome: str | None = None
    deferred_facts: OutcomeFacts | None = field(default=None, repr=False)
    # One bounded correlation ledger, independent of visible activity. Keep
    # tombstones through Clear/Done/SetBusy/scope changes. Evicted or unknown
    # correlated results fail closed; they cannot acquire the current scope.
    call_history: tuple[PendingCall, ...] = field(default=(), repr=False)
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
    turn_number: int = 0
    latest_turn_details: TurnDetails | None = field(default=None, repr=False)


    @property
    def pending_calls(self) -> tuple[PendingCall, ...]:
        return tuple(call for call in self.call_history if not call.retired and not call.resolved
                     and call.scope == self.presentation_scope)


def _retire_calls(state: AppState) -> tuple[PendingCall, ...]:
    return tuple(replace(call, retired=True) if not call.retired else call for call in state.call_history)


def _remember_call(state: AppState, call: PendingCall) -> tuple[PendingCall, ...]:
    history = (*state.call_history, call)
    if len(history) <= 256:
        return history
    # Prefer retiring old tombstones over losing a live sibling. If all slots
    # are live, evict the oldest; its late result will fail closed as unknown.
    index = next((i for i, item in enumerate(history) if item.retired or item.resolved), 0)
    return history[:index] + history[index + 1:]


def initial_state(banner: str, banner_data: BannerData) -> AppState:
    return AppState(banner=banner, banner_data=banner_data)


def _phase_with_pending_request(state: AppState, fallback: UiPhase) -> UiPhase:
    """Keep the status phase aligned with the request currently shown by the app."""
    # _get_active_modal presents user questions before permission requests.
    if state.pending_ask is not None:
        return "waiting-user"
    if state.pending_perm is not None:
        return "waiting-approval"
    return fallback


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
            phase = _phase_with_pending_request(state, "answering" if state.busy else state.phase)
            last = state.transcript[-1] if state.transcript else None
            if last is not None and last.kind == "assistant" and last.streaming:
                return replace(state, phase=phase, stream_chunks=(*state.stream_chunks, text))
            return replace(
                state,
                phase=phase,
                stream_chunks=(text,),
                transcript=(*state.transcript, TranscriptEntry(kind="assistant", text="Receiving response…", streaming=True)),
            )

        case SetBusy(busy=busy, facts=facts):
            if busy and not state.busy:
                state = replace(state, milestones=(), delivered_results=(), call_history=_retire_calls(state), outcome_written=False,
                                turn_number=state.turn_number + 1,
                                deferred_outcome=None, deferred_facts=None,
                                baseline=replace(facts, records=tuple(row for row in facts.records if row.kind != "capture")) if facts else None,
                                latest_facts=facts,
                                progress_rows=(), observed=(), activated_skills=(), skill_receipts=(),
                                active_skill=None, running_tool=None, running_skill=None, planner_recommendation=None,
                                presentation_scope=facts.scope if facts else state.presentation_scope)
            return replace(state, busy=busy,
                           phase=_phase_with_pending_request(state, "planning" if busy else "idle"),
                           running_tool=state.running_tool if busy else None,
                           running_skill=state.running_skill if busy else None,
                           active_skill=state.active_skill if busy else None,
                           call_history=state.call_history if busy else _retire_calls(state))

        case SetApiReady(ready=ready):
            return replace(state, api_ready=ready)

        case SetActiveSkill(name=name):
            return replace(state, active_skill=sanitize_text(name) if name is not None else None)

        case SetYolo(on=on):
            return replace(state, yolo=on)

        case SetPerm(req=req):
            state = replace(state, pending_perm=req)
            fallback: UiPhase = "waiting-approval" if req else ("running-tool" if state.busy else "idle")
            return replace(state, phase=_phase_with_pending_request(state, fallback))

        case SetAsk(req=req):
            state = replace(state, pending_ask=req)
            fallback = ("waiting-user" if req else "running-tool" if state.pending_calls
                        else "answering" if state.busy else "idle")
            return replace(state, phase=_phase_with_pending_request(state, fallback))

        case SetSkillsPicker(open=open_):
            state = replace(state, pending_skills=open_)
            return replace(state, phase=_phase_with_pending_request(state, "skills" if open_ else "idle"))

        case Clear(message=message):
            return replace(
                state,
                transcript=(),
                clear_gen=state.clear_gen + 1,
                transcript_revision=state.transcript_revision + 1,
                stream_chunks=(),
                call_history=_retire_calls(state),
                milestones=(), delivered_results=(), outcome_written=False,
                presentation_scope="", deferred_outcome=None, deferred_facts=None,
                baseline=None, latest_facts=None, progress_rows=(), observed=(),
                activated_skills=(), skill_receipts=(), running_skill=None, running_tool=None, planner_recommendation=None,
                clear_message=sanitize_text(message) if message is not None else None,
                latest_turn_details=None,
                phase=_phase_with_pending_request(state, state.phase),
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
            if isinstance(event, WorkflowProgressEvent):
                return state  # Diagnostics must not flush streams or change presentation state.
            if isinstance(event, SkillActiveEvent) and event.call_id:
                known = invocation_call(state.call_history, event)
                if (known is not None and known.retired) or (known is None and event.invocation is not None):
                    return state
            if isinstance(event, (ToolCallEvent, ToolResultEvent)):
                known = invocation_call(state.call_history, event)
                if isinstance(event, ToolCallEvent) and known is not None:
                    return state
                if isinstance(event, ToolResultEvent) and (
                        (known is not None and (known.retired or known.resolved))
                        or (known is None and (event.invocation is not None or state.call_history))):
                    return state
            if state.outcome_written and isinstance(event, (DecisionEvent, SkillActiveEvent, ToolCallEvent,
                                                            AssistantDeltaEvent, AssistantTextEvent)):
                return state
            if facts and facts.stale_event:
                if facts.scope == state.presentation_scope:
                    if isinstance(event, ToolResultEvent):
                        known = invocation_call(state.call_history, event)
                        if known is not None:
                            return replace(state, call_history=tuple(
                                replace(call, retired=True) if call is known else call for call in state.call_history))
                    return state
                return replace(state, presentation_scope=facts.scope, call_history=_retire_calls(state),
                               milestones=(), delivered_results=(), outcome_written=False,
                               deferred_outcome=None, deferred_facts=None, baseline=None, latest_facts=facts,
                               progress_rows=(), observed=(), activated_skills=(), skill_receipts=(), planner_recommendation=None,
                               running_tool=None, running_skill=None, active_skill=None,
                               phase=_phase_with_pending_request(state, "answering" if state.busy else "idle"))
            if facts and facts.scope != state.presentation_scope:
                state = replace(state, presentation_scope=facts.scope, milestones=(),
                                delivered_results=(), outcome_written=False, deferred_outcome=None, deferred_facts=None,
                                baseline=replace(facts, records=tuple(row for row in facts.records if row.kind != "capture")),
                                latest_facts=facts, progress_rows=(), observed=(), call_history=_retire_calls(state),
                                active_skill=None, activated_skills=(), skill_receipts=(), running_tool=None,
                                running_skill=None, planner_recommendation=None)
            elif facts:
                state = replace(state, latest_facts=facts, baseline=state.baseline or facts)
            return _apply_agent_event(state, event, facts)

        case _:
            raise AssertionError(f"Unhandled action: {action!r}")


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
    return " · ".join(labels[:3]) + (f" · +{len(labels)-3} more" if len(labels) > 3 else "")


def _flush_selection(state: AppState) -> AppState:
    selected, captures = _new_records(state, "selection"), _new_records(state, "capture")
    if selected:
        text = f"Selected: {_examples(selected)} ({_quantity(len(selected), 'input')})"
        if captures:
            text += f" · {_quantity(len(captures), 'captured request')} selected"
    elif captures:
        text = f"Selected capture: {_examples(captures)} ({_quantity(len(captures), 'captured request')})"
    else:
        return state
    return _progress_row(state, "selection", text + ".", "info")


def _flush_progress(state: AppState) -> AppState:
    inputs, endpoints = _new_records(state, "input"), _new_records(state, "endpoint")
    if inputs or endpoints:
        dispositions = {value: sum(row.disposition == value for row in inputs)
                        for value in ("analyzed", "pending", "blocked", "dropped")}
        details = ", ".join(f"{count} {key}" for key, count in dispositions.items() if count)
        state = _progress_row(state, "inventory", f"Attack surface recorded: {_quantity(len(endpoints), 'endpoint')}, "
                              f"{_quantity(len(inputs), 'input')}" + (f" ({details})" if details else "") +
                              f"\n{_examples(inputs or endpoints)}.", "info")
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
                text += f"\n  Observed impact · {concise_text(row.detail, shortened_marker='… [shortened]')}"
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
    if isinstance(ev, WorkflowProgressEvent):
        return state
    if not isinstance(ev, (AssistantDeltaEvent, AssistantTextEvent)):
        state = _finish_stream(state)
    match ev:
        case AssistantTextEvent(text=text):
            last = state.transcript[-1] if state.transcript else None
            if last is not None and last.kind == "assistant" and last.streaming:
                state = _flush_progress(_finish_stream(state, text))
                return replace(state, phase=_phase_with_pending_request(state, "answering"))
            state = _flush_progress(state)
            return replace(
                state,
                phase=_phase_with_pending_request(state, "answering"),
                transcript=(*state.transcript, TranscriptEntry(kind="assistant", text=sanitize_text(text))),
            )

        case AssistantDeltaEvent(text=text):
            return reducer(state, AppendDelta(text=text))

        case ToolCallEvent():
            call = call_metadata(ev)
            if facts and facts.activity:
                call = replace(call, activity=facts.activity)
            call = replace(call, scope=state.presentation_scope,
                           skill=(facts.activity_skill if facts and facts.activity_skill else call.skill))
            if call.operation == "start_validation":
                state = _flush_progress(state)
            elif call.name == "http":
                state = _flush_selection(state)
            history = _remember_call(state, call) if ev.id else state.call_history
            return replace(state, call_history=history,
                           phase=_phase_with_pending_request(state, "running-tool"),
                           running_skill=call.skill if call.skill in state.activated_skills else None,
                           running_tool=sanitize_text(_activity_label(ev.name) +
                           (": " + (facts.activity if facts and facts.activity else call.activity)
                            if (facts and facts.activity) or call.activity else "")))

        case ToolResultEvent():
            call = invocation_call(state.call_history, ev)
            if call is not None:
                state = replace(state, call_history=tuple(
                    replace(item, resolved=True) if item is call else item for item in state.call_history))
            pending = state.pending_calls
            state = replace(state,
                            phase=_phase_with_pending_request(
                                state, "idle" if state.outcome_written else "running-tool" if pending else "answering"),
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
            context = facts.activity if facts and facts.activity else call.activity if call else ""
            # Feedback stays in the raw event/model history. Only current
            # intervention, session and preservation failures enter the view.
            exports = [notice for notice in issues if issue_category(notice, ev) == "export"]
            if ev.presentation_impact in {"intervention", "session", "persistence"}:
                notices = exports or issues or ["Result preservation unavailable" if ev.presentation_impact == "persistence"
                                               else "User intervention required" if ev.presentation_impact == "intervention"
                                               else "Session blocked"]
                state = replace(state, transcript=(*state.transcript, TranscriptEntry(
                    kind="warning", text=sanitize_text(display_tool_name(ev.name) + ": " + "; ".join(notices)))))
            metadata = ev.runtime_metadata
            if type(metadata) is RuntimeMetadata and metadata.persistence in {"failed", "memory-only"}:
                notice = ("Result persistence failed" if metadata.persistence == "failed" else
                          "Result retained in memory only; unavailable after resume")
                state = replace(state, transcript=(*state.transcript, TranscriptEntry(
                    kind="warning", text=sanitize_text(display_tool_name(ev.name) + ": " + notice))))
            completed = bool(call and ev.status in {"success", "observation"} and not ev.err and not ev.error_kind
                             and all(issue_category(issue, ev) in {"diagnostic", "incomplete"} for issue in issues))
            if completed and ev.name == "workflow":
                try:
                    receipt = json.loads(ev.result)
                except (ValueError, TypeError):
                    receipt = None
                completed = isinstance(receipt, dict) and receipt.get("ok") is True
            if completed and call:
                if call and call.name == "load_skill":
                    state = replace(state, skill_receipts=(*state.skill_receipts, (call.invocation.id if call.invocation else call.id, call.skill)))
                elif ev.name not in {"http", "workflow", "confirm_finding", "read_skill_file", "read_payloads", "browser_capture_status"}:
                    state = replace(state, observed=(*state.observed, ProgressRecord(
                        "operation", ev.id, sanitize_text(display_tool_name(ev.name)))))
            if ev.name == "http" and ev.status in {"success", "observation"} and not ev.err and ev.http_status is not None and call:
                state = replace(state, observed=(*state.observed, ProgressRecord("observation", ev.id,
                                http_activity(ev, call, context), str(ev.http_status))))
            flush_progress = bool(call and (call.operation in {"start_validation", "complete_skill", "record_result",
                                            "record_input", "set_input_disposition", "record_candidate", "link_input_candidate"}
                                            or ev.name == "confirm_finding"))
            if flush_progress:
                state = _flush_progress(state)
            if facts:
                for key, kind, text in facts.milestones:
                    baseline = {row.key for row in state.baseline.records if row.kind == "finding"} if state.baseline else set()
                    if key not in baseline:
                        state = _milestone(state, key, text, cast(TranscriptKind, kind))
            return state

        case ErrorEvent(err=agent_err):
            state = replace(state, phase=_phase_with_pending_request(
                state, "running-tool" if state.pending_calls else "answering" if state.busy else state.phase))
            if getattr(agent_err, "presentation_impact", None) == "operation":
                return state
            from src.agent.agent import IneffectiveCompactionError
            if isinstance(agent_err, IneffectiveCompactionError):
                return state
            return replace(state, transcript=(*state.transcript,
                TranscriptEntry(kind="error", text=sanitize_text(str(agent_err)))))

        case DecisionEvent(summary=summary):
            if not state.pending_calls and not state.pending_perm and not state.pending_ask:
                state = replace(state, phase="planning", running_tool=None, running_skill=None)
            if summary.startswith(("context guard:", "context pressure:")):
                return state
            if ev.recommended_skill:
                event_key = "planner:" + ev.decision_id if ev.decision_id else ""
                if event_key and event_key in state.milestones:
                    return state
                if event_key:
                    state = replace(state, milestones=(*state.milestones, event_key))
                recommendation = (ev.recommended_skill, ev.candidate_id or "")
                if recommendation != state.planner_recommendation:
                    context = next((row for row in facts.records
                                    if row.kind == "candidate" and row.key == ev.candidate_id), None) if facts else None
                    label = "Planner recommended · " + concise_text(ev.recommended_skill, 100)
                    if context:
                        context_label = concise_text(context.label, 180)
                        label += " · " + context_label
                        if facts and any(row.kind == "candidate" and row.key != context.key
                                         and concise_text(row.label, 180) == context_label for row in facts.records):
                            label += " · " + context.key[-8:]
                    state = replace(state, planner_recommendation=recommendation,
                                    transcript=(*state.transcript, TranscriptEntry(kind="info",
                                        text=label)))
            return state

        case CompactEvent():
            if not state.pending_calls and not state.pending_perm and not state.pending_ask:
                state = replace(state, phase="planning")
            # Current runtime supplies both estimates only after successful
            # compaction. Trigger/skip events never carry an after estimate.
            if (isinstance(ev.tokens_before, int) and not isinstance(ev.tokens_before, bool)
                    and isinstance(ev.tokens_after, int) and not isinstance(ev.tokens_after, bool)
                    and ev.tokens_before >= 0 and ev.tokens_after >= 0):
                def tokens(value: int) -> str:
                    return f"{value / 1000:.1f}k" if value >= 1000 else str(value)
                return _milestone(state, f"compact:{ev.tokens_before}:{ev.tokens_after}",
                    f"Context compacted · {tokens(ev.tokens_before)} → {tokens(ev.tokens_after)} tokens", "info")
            if ev.summary.startswith('auto-compacted history:'):
                return _milestone(state, 'compact:' + ev.summary, 'Context compacted', 'info')
            return state

        case SkillActiveEvent(name=name):
            receipt_id = ev.invocation.id if ev.invocation else ev.call_id
            if ev.call_id and (receipt_id, name) not in state.skill_receipts:
                return state
            if ev.call_id:
                key = "activation:" + receipt_id
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
            state = replace(state, busy=False, phase=_phase_with_pending_request(state, "idle"),
                            running_tool=None, running_skill=None, active_skill=None, call_history=_retire_calls(state))
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
        "final_response": "Turn completed", "workflow_completed": "Workflow completed",
        "workflow_blocked": "Blocked", "cancelled": "Turn cancelled",
        "max_steps": "Stopped at max steps", "runtime_error": "Runtime failure",
        "context_capacity": "Context capacity failure", "client_error": "Provider failure",
        "all_tools_refused": "Blocked by tool refusals", "plan_only_blocked": "Plan-only tool request blocked",
        "invalid_response": "Invalid response",
    }.get(reason or "", f"Turn ended ({reason})" if reason else "Turn ended (runtime outcome unavailable)")
    pending = list(facts.pending if facts else ())
    # Only authoritative workflow facts establish remaining assessment work.
    workflow_residual = bool(pending or (facts and (facts.incomplete or facts.goals or facts.blockers)))
    state = _flush_progress(state)
    displayed_cause = ''
    if reason == "workflow_blocked":
        cause = facts.blockers[0] if facts and facts.blockers else pending[0] if pending else ''
        if cause:
            label += " · " + concise_text(cause)
            displayed_cause = cause
    if state.pending_perm is not None:
        pending.append("permission review pending")
    if state.pending_ask is not None:
        pending.append("user input pending")
    residual = workflow_residual or state.pending_perm is not None or state.pending_ask is not None
    saved = unsaved = 0
    if facts and facts.scope:
        saved, unsaved = len(_new_records(state, "finding")), len(_new_records(state, "unsaved"))
        counts = [(unsaved, "accepted-but-unsaved validation"),
                  (facts.incomplete, "incomplete validation"), (facts.goals, "incomplete goal")]
        pending[0:0] = ([_quantity(saved, "finding saved", "findings saved")] if saved else []) + [
            _quantity(count, noun) for count, noun in counts if count]
        residual = residual or bool(unsaved)
        workflow_residual = workflow_residual or bool(unsaved)
        negative = sum(row.disposition == "not-confirmed" for row in _new_records(state, "validation"))
        if negative:
            pending.insert(0, f"{_quantity(negative, 'validation')} not confirmed")
        if facts.blockers:
            pending.append(_quantity(len(facts.blockers), "active workflow blocker"))
    suffix_items = [item for item in pending if item != displayed_cause]
    # Preserve the redactor's field boundary. A form-like password/token at
    # the end of a blocker must not consume the following outcome counters.
    suffix = "; " + "; ".join(suffix_items) if suffix_items else ""
    operations = _new_records(state, "operation")
    operation_counts: dict[str, int] = {}
    if operations:
        for row in operations:
            operation_counts[row.label] = operation_counts.get(row.label, 0) + 1
    if reason == "workflow_completed" and (workflow_residual or not facts or not facts.completion_supported):
        label = "Turn ended · workflow work remains" if workflow_residual else "Turn ended · workflow completion unavailable"
    elif reason == "final_response" and workflow_residual:
        label = "Turn ended · work remains"
    summary = sanitize_text(label + suffix + ".")
    details = TurnDetails(state.turn_number, reason, summary, saved, unsaved,
        facts.incomplete if facts else 0, facts.goals if facts else 0,
        tuple(sanitize_text(item) for item in pending),
        tuple((sanitize_text(name), count) for name, count in operation_counts.items()))
    return replace(state, outcome_written=True, deferred_outcome=None, deferred_facts=None,
                   latest_turn_details=details, transcript=(*state.transcript,
                   TranscriptEntry(kind="error" if reason in {"runtime_error", "context_capacity", "client_error", "invalid_response"}
                                   else "warning" if residual or reason in {"workflow_blocked", "all_tools_refused", "cancelled", "max_steps"}
                                   else "info", text=summary)))
