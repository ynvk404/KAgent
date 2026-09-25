import traceback
import asyncio
import json
import re
import time
import uuid
import ssl
import httpx
from copy import deepcopy
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import reveal_type
from typing import (
    Any,
    Awaitable,
    Callable,
    List,
    Literal,
    Optional,
    TypeVar,
    cast,
)

from .mentions import expand_file_mentions

from src.redact.redact import apply as redact

from src.llm.client import (
    Client,
    StreamingClient,
    is_streaming,
)

from src.llm.types import (
    ChatRequest,
    ChatResponse,
    Message,
    ToolCall,
    parsed_args,
)
from src.llm.reasoning import (
    ReasoningLevel,
    ReasoningPurpose,
    requested_level,
    resolve_level,
)
from src.llm.metrics import MetricsCollector, RequestMetrics

from src.logger.logger import debug as log_debug, error as log_error

from src.intelligence.store import (
    IntelligenceStore,
    format_intelligence_context,
)

from src.memory.store import (
    AddMemoryInput,
    MemoryFact,
    MemoryStore,
    format_memory_recall,
)

from src.permission.permission import Prompter, UserControlledRefusal
from src.engagement.state import EngagementState, OutOfScopeError

from src.session.store import (
    SessionMemory,
    Store,
)

from src.skills.registry import (
    Registry as SkillRegistry,
    materialize_skill_body,
)

from src.target.origin import HTTPOrigin
from src.target.target import Target
from src.workflow.state import WorkflowObjective, WorkflowState, candidate_origin

from src.tools.aliases import canonical_tool_name
from src.tools.registry import InvalidToolArguments, Registry as ToolRegistry
from src.tools.types import ActionPermissionTool
from src.tools.outcome import ErrorKind, ToolOutput, ToolStatus

from .decision_planner import (
    PlannerCandidate,
    PlannerContext,
    build_decision_plan,
    is_purely_informational,
    normalize,
)

from src.agent.events import (
    AgentEvent,
    AssistantTextEvent,
    AssistantDeltaEvent,
    ToolCallEvent,
    ToolResultEvent,
    ErrorEvent,
    DoneEvent,
    DecisionEvent,
    MemoryRecallEvent,
    SkillActiveEvent,
    CompactEvent,
    MaxStepsError,
    InvalidResponseError,
)

from .sanitize import (
    ThinkingStreamFilter,
    strip_thinking_tags,
)

from .system_prompt import (
    BuildOptions,
    PromptProfile,
    PromptToolingProfile,
    build_system_prompt,
)

T = TypeVar("T")
R = TypeVar("R")

EventSink = Callable[[AgentEvent], None]

DEFAULT_MAX_STEPS = 20
MAX_CONSECUTIVE_NO_PROGRESS = 4
REASONING_POLICY_ID = "reasoning-baseline-v1"

_EVENT_FACTORIES = {
    "assistant-text": AssistantTextEvent,
    "assistant-delta": AssistantDeltaEvent,
    "tool-call": ToolCallEvent,
    "tool-result": ToolResultEvent,
    "error": ErrorEvent,
    "compact": CompactEvent,
    "decision": DecisionEvent,
    "skill-active": SkillActiveEvent,
    "memory-recall": MemoryRecallEvent,
    "done": DoneEvent,
}

_KEY_ALIASES = {
    "argsJSON": "args_json",
    "tokensBefore": "tokens_before",
    "tokensAfter": "tokens_after",
    "memoryItems": "memory_items",
    "durationMs": "duration_ms",
}

MAX_CONSECUTIVE_AUTOCOMPACT_FAILURES = 3
COMPACTION_INPUT_CHAR_LIMIT = 22_000
COMPACTION_MIN_SAVINGS_TOKENS = 64
COMPACTION_MIN_REDUCTION_RATIO = 0.10
COMPACTION_RECENT_MESSAGE_CHAR_LIMIT = 2_000
SCOPE_CONTEXT_MARKER = "# Current engagement scope (authoritative)"
COMPACTION_MIN_HISTORY_TOKENS = 2_048
COMPACTION_MIN_HISTORY_RATIO = 1 / 3
MAX_PARALLEL_TOOL_CALLS = 4

_EXPLICIT_HTTP_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_OPERATIONAL_TARGET_TERMS = re.compile(
    r"\b(?:assess|assessment|audit|check|enumerate|exploit|inspect|investigate|"
    r"pentest|penetration test|probe|recon|reconnaissance|scan|test|validate|verify)\b",
    re.IGNORECASE,
)
_WHOLE_TARGET_INTENT = re.compile(
    r"\b(?:whole[- ]target|entire target|full target|full[- ]scope assessment|"
    r"full security assessment|security assessment of (?:the )?(?:target|application|website|site)|"
    r"comprehensive (?:pentest|penetration test|assessment)|"
    r"assess the entire|test the entire target|test (?:all|every) endpoints|"
    r"map (?:the )?entire application|end[- ]to[- ]end (?:pentest|assessment)|"
    r"complete penetration test|(?:run|perform|conduct) (?:a )?(?:pentest|penetration test)|"
    r"pentest (?:the )?(?:target|application|website|site)|"
    r"penetration test (?:the )?(?:target|application|website|site))\b",
    re.IGNORECASE,
)
_PENTEST_REQUEST_INTENT = re.compile(r"\b(?:pentest|penetration test)\b", re.IGNORECASE)
_NEW_OBJECTIVE_INTENT = re.compile(
    r"\b(?:new (?:task|assessment|objective)|start over|different task|"
    r"instead,? (?:test|check|validate)|stop testing|stop the assessment)\b",
    re.IGNORECASE,
)
_OBJECTIVE_CONTINUATION_INTENT = re.compile(
    r"^\s*(?:please\s+)?(?:continue|resume|retry|try again|pick up|keep going|go on)\b",
    re.IGNORECASE,
)
_OBJECTIVE_DEPENDENCY_REPLY = re.compile(
    r"\b(?:auth(?:orization)?|credentials?|browser|evidence)\b",
    re.IGNORECASE,
)
_OBJECTIVE_DEPENDENCY_PROVIDED = re.compile(
    r"\b(?:granted|provided|available|ready|attached|uploaded|provide|"
    r"here\s+(?:is|are))\b",
    re.IGNORECASE,
)
_CANDIDATE_VALIDATION_INTENT = re.compile(
    r"\b(?:validate|verify|test|retest)\b",
    re.IGNORECASE,
)

STATEFUL_TOOLS = {
    "load_skill",
    "workflow",
}

MIDTURN_ELISION_PREFIX = (
    "[tool output elided mid-turn to fit context"
)

MIDTURN_ELISION_KEEP_RECENT = 4
MIDTURN_RECENT_TOOL_RESULT_CHAR_FLOOR = COMPACTION_RECENT_MESSAGE_CHAR_LIMIT
MIDTURN_SAFETY_RATIO = 0.02
MIDTURN_MIN_SAFETY_TOKENS = 128
MIDTURN_WINDOW_WEIGHTS = (40, 15, 15, 15, 15)
MAX_MEMORY_LIST = 200
WORKFLOW_HISTORY_MARKER = (
    "[workflow tool result elided; current structured state is in the system prompt]"
)

_MALFORMED_TOOL_CALL_TAG_RE = re.compile(
    r"<\s*/?\s*(?:[^\w\s<>]*DSML[^\w\s<>]*\s*)?"
    r"(?P<name>tool_calls?|function_calls?|tool_use|calls|invoke|parameter|arguments)"
    r"\b[^>]*>",
    re.IGNORECASE,
)
_NAMED_TOOL_INVOCATION_RE = re.compile(
    r"<[^>]*\b(?:invoke|tool_calls?|function_calls?)\b[^>]*\bname\s*=",
    re.IGNORECASE,
)
_TOOL_CALL_CONTAINER_TAGS = frozenset(
    {
        "tool_call",
        "tool_calls",
        "function_call",
        "function_calls",
        "tool_use",
        "calls",
    }
)
_TOOL_CALL_DETAIL_TAGS = frozenset({"invoke", "parameter", "arguments"})


def _looks_like_malformed_tool_call(content: str) -> bool:
    """Identify tool-call markup leaked as text instead of structured calls.

    This is a safety net for malformed provider/model output. It deliberately
    requires multiple tool-protocol tags and a named invocation to avoid
    treating ordinary prose or a single markup example as an attempted call.
    """
    tags = [
        match.group("name").lower()
        for match in _MALFORMED_TOOL_CALL_TAG_RE.finditer(content)
    ]
    return bool(
        _TOOL_CALL_CONTAINER_TAGS.intersection(tags)
        and _TOOL_CALL_DETAIL_TAGS.intersection(tags)
        and _NAMED_TOOL_INVOCATION_RE.search(content)
    )

COMPACTION_SYSTEM_PROMPT = (
    "Create a compact continuation memory for the same "
    "pentesting/coding session. Use concise Markdown with "
    "exactly these headings: Current objective, Plan, "
    "Completed tasks, Target and scope, Decisions and assumptions, "
    "Tested surface, Findings and evidence, Files and commands, "
    "Credentials and placeholders, Open TODOs, Next best actions. "
    "Preserve exact endpoints, params, IDs, files, commands, "
    "tool results that matter, confirmed negatives, and "
    "reproduction evidence. Redact secrets but keep stable "
    "placeholders. Omit chatter and failed dead ends unless "
    "they prevent repeat work. Do not restate Candidate or "
    "ValidationResult records: authoritative WorkflowState is preserved "
    "separately. Keep only evidence references needed to continue."
)


class IneffectiveCompactionError(RuntimeError):
    pass


@dataclass
class SessionMemoryParsed:
    objectives: list[str] = field(default_factory=list)
    plan: list[str] = field(default_factory=list)
    completed: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    tested: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    credentials: list[str] = field(default_factory=list)
    todos: list[str] = field(default_factory=list)


class ParsedToolCall:
    def __init__(
        self,
        args: dict,
        args_json: str,
        parse_err: Exception | None = None,
    ):
        self.args = args
        self.args_json = args_json
        self.parse_err = parse_err


class ToolCallResult:
    def __init__(
        self,
        result: str,
        err_str: str,
        duration_ms: int,
        terminal_user_controlled_refusal: bool = False,
        status: ToolStatus = "success",
        error_kind: ErrorKind | None = None,
        http_status: int | None = None,
        truncated: bool = False,
    ):
        self.result = result
        self.err_str = err_str
        self.duration_ms = duration_ms
        self.terminal_user_controlled_refusal = (
            terminal_user_controlled_refusal
        )
        self.status = status
        self.error_kind = error_kind
        self.http_status = http_status
        self.truncated = truncated


def tool_error_kind(err: Exception, *, invalid_args: bool = False) -> ErrorKind:
    if invalid_args or isinstance(err, InvalidToolArguments):
        return "invalid_args"
    if isinstance(err, OutOfScopeError):
        return "scope_denied"
    if isinstance(err, UserControlledRefusal):
        return "permission_denied"
    if isinstance(err, (asyncio.TimeoutError, httpx.TimeoutException)):
        return "timeout"
    cause: BaseException | None = err
    while cause is not None:
        if isinstance(cause, ssl.SSLError):
            return "tls"
        cause = cause.__cause__ or cause.__context__
    if isinstance(err, (httpx.NetworkError, ConnectionError)):
        return "network"
    return "tool_exception"


def _weighted_window_lengths(total: int) -> list[int]:
    """Split a source budget deterministically across the five windows."""
    lengths = [total * weight // 100 for weight in MIDTURN_WINDOW_WEIGHTS]
    remainder = total - sum(lengths)
    for index in range(remainder):
        lengths[index % len(lengths)] += 1
    return lengths


def _distributed_window_ranges(source_length: int, budget: int) -> list[tuple[int, int]]:
    lengths = _weighted_window_lengths(min(source_length, max(0, budget)))
    anchors = (0.0, 0.25, 0.5, 0.75, 1.0)
    ranges: list[tuple[int, int]] = []

    for index, (anchor, length) in enumerate(zip(anchors, lengths)):
        if length <= 0:
            continue
        if index == 0:
            start = 0
        elif index == len(anchors) - 1:
            start = source_length - length
        else:
            center = round(source_length * anchor)
            start = center - length // 2
        start = min(max(0, start), source_length - length)
        end = start + length

        if ranges and start <= ranges[-1][1]:
            ranges[-1] = (ranges[-1][0], max(ranges[-1][1], end))
        else:
            ranges.append((start, end))

    return ranges


def _render_distributed_windows(content: str, source_budget: int) -> str:
    ranges = _distributed_window_ranges(len(content), source_budget)
    if not ranges:
        return ""

    parts: list[str] = []
    previous_end = 0
    for start, end in ranges:
        if start > previous_end:
            parts.append(
                "\n"
                f"{MIDTURN_ELISION_PREFIX}; characters "
                f"{previous_end}-{start} omitted; original length {len(content)}]"
                "\n"
            )
        parts.append(content[start:end])
        previous_end = end

    if previous_end < len(content):
        parts.append(
            "\n"
            f"{MIDTURN_ELISION_PREFIX}; characters "
            f"{previous_end}-{len(content)} omitted; original length {len(content)}]"
            "\n"
        )
    return "".join(parts)


def _render_distributed_omissions(content: str, omitted: int) -> str:
    """Render four ordered gaps between the five evidence anchor points."""
    source_length = len(content)
    anchors = [0, source_length // 4, source_length // 2, source_length * 3 // 4, source_length]
    capacities = [max(0, anchors[i + 1] - anchors[i] - 2) for i in range(4)]
    gap_lengths = _proportional_reductions(capacities, omitted)
    gaps: list[tuple[int, int]] = []
    for index, gap_length in enumerate(gap_lengths):
        if gap_length <= 0:
            continue
        segment_start = anchors[index] + 1
        segment_end = anchors[index + 1] - 1
        start = segment_start + (segment_end - segment_start - gap_length) // 2
        gaps.append((start, start + gap_length))

    parts: list[str] = []
    previous_end = 0
    for start, end in gaps:
        parts.append(content[previous_end:start])
        parts.append(
            "\n"
            f"{MIDTURN_ELISION_PREFIX}; characters "
            f"{start}-{end} omitted; original length {source_length}]"
            "\n"
        )
        previous_end = end
    parts.append(content[previous_end:])
    return "".join(parts)


def bound_recent_tool_result(content: str, target_length: int) -> str:
    """Bound one LLM-facing result with ordered windows including marker cost."""
    target_length = max(
        MIDTURN_RECENT_TOOL_RESULT_CHAR_FLOOR,
        min(len(content), target_length),
    )
    if len(content) <= target_length or MIDTURN_ELISION_PREFIX in content:
        return content

    low = 0
    high = len(content)
    best = ""
    while low <= high:
        source_budget = (low + high) // 2
        rendered = _render_distributed_windows(content, source_budget)
        if len(rendered) <= target_length:
            if len(rendered) > len(best):
                best = rendered
            low = source_budget + 1
        else:
            high = source_budget - 1

    # When weighted windows overlap under slight pressure, filling their gaps
    # can otherwise produce a large representational cliff. A complementary
    # four-gap search keeps almost all source while retaining the same five
    # distributed evidence regions.
    low = 1
    high = len(content)
    while low <= high:
        omitted = (low + high) // 2
        rendered = _render_distributed_omissions(content, omitted)
        if len(rendered) <= target_length:
            if len(rendered) > len(best):
                best = rendered
            high = omitted - 1
        else:
            low = omitted + 1

    if not best or len(best) >= len(content):
        return content
    return best


def _proportional_reductions(capacities: list[int], required: int) -> list[int]:
    """Allocate an integer reduction using stable largest remainders."""
    total_capacity = sum(capacities)
    amount = min(max(0, required), total_capacity)
    if amount == 0 or total_capacity == 0:
        return [0] * len(capacities)

    reductions = [amount * capacity // total_capacity for capacity in capacities]
    remainders = [amount * capacity % total_capacity for capacity in capacities]
    left = amount - sum(reductions)
    order = sorted(range(len(capacities)), key=lambda i: (-remainders[i], i))
    for index in order:
        if left == 0:
            break
        if reductions[index] < capacities[index]:
            reductions[index] += 1
            left -= 1
    return reductions


@dataclass(slots=True)
class ToolAllowedResult:
    ok: bool
    reason: str | None = None


@dataclass(slots=True)
class MemoryStats:
    compactions: int = 0
    items: int = 0
    last_compacted_at: Optional[str] = None

    def __getitem__(self, key: str):
        return getattr(self, key)

    def get(self, key: str, default=None):
        return getattr(self, key, default)


class AgentRunOptions:
    def __init__(
        self,
        tools: bool = True,
    ):
        self.tools = tools


class AgentOptions:
    def __init__(
        self,
        client: Client,
        tools: ToolRegistry,
        skills: SkillRegistry,
        prompter: Prompter,
        store: Optional[Store],
        target: Target,
        thinking_enabled: bool = False,
        max_steps: int = DEFAULT_MAX_STEPS,
        auto_compact_threshold: int = 16000,
        tooling_profile: Optional[PromptToolingProfile] = None,
        prompt_profile: Optional[PromptProfile] = None,
        streaming_enabled: bool = True,
        intelligence: Optional[IntelligenceStore] = None,
        memory_store: Optional[MemoryStore] = None,
        engagement: str = "",
        workflow: WorkflowState | None = None,
        engagement_state: EngagementState | None = None,
    ):
        self.client = client
        self.tools = tools
        self.skills = skills
        self.prompter = prompter
        self.store = store
        self.target = target

        self.thinking_enabled = thinking_enabled
        self.max_steps = max_steps
        self.auto_compact_threshold = auto_compact_threshold

        self.tooling_profile: PromptToolingProfile = (
            tooling_profile
            if tooling_profile is not None
            else "minimal"
        )
        self.prompt_profile: PromptProfile = (
            prompt_profile
            if prompt_profile is not None
            else "full"
        )
        self.streaming_enabled = streaming_enabled
        self.intelligence = intelligence
        self.memory_store = memory_store
        self.engagement = engagement
        self.workflow = workflow
        self.engagement_state = engagement_state


class Agent:

    def __init__(
        self,
        opts: AgentOptions,
    ):
        self.client = opts.client

        self.tools = opts.tools
        self.skills = opts.skills
        self.prompter = opts.prompter

        self.store = opts.store
        self.target = opts.target

        self.intelligence = opts.intelligence
        self.memory_store = opts.memory_store

        self._background_tasks: set[asyncio.Task] = set()
        self.request_metrics = MetricsCollector()
        self._llm_call_counts = {
            "agent_loop_llm_calls": 0,
            "compaction_llm_calls": 0,
            "final_synthesis_llm_calls": 0,
        }

        self.thinking = (
            opts.thinking_enabled
            if opts.thinking_enabled is not None
            else False
        )

        self.max_steps = (
            opts.max_steps
            if opts.max_steps > 0
            else DEFAULT_MAX_STEPS
        )

        self.memory: Optional[SessionMemory] = None
        self.workflow = opts.workflow or WorkflowState()
        self.engagement_state = opts.engagement_state or EngagementState()
        if not self.target.empty():
            self.engagement_state.add_origin(self.target.base_url())

        self.auto_compact_threshold = (
            opts.auto_compact_threshold
            if opts.auto_compact_threshold is not None
            else 16000
        )

        self.consecutive_compact_failures = 0

        self.tooling_profile: PromptToolingProfile = (
            opts.tooling_profile
            if opts.tooling_profile is not None
            else "minimal"
        )
        self.prompt_profile: PromptProfile = (
            opts.prompt_profile
            if opts.prompt_profile is not None
            else "full"
        )

        self.streaming_enabled = (
            opts.streaming_enabled
            if opts.streaming_enabled is not None
            else True
        )

        self.engagement = (
            opts.engagement
            if opts.engagement is not None
            else ""
        )

        self.running = False

        self.active_skills: set[str] = set()
        self.pending_skills: set[str] = set()

        self.tools_tokens_cache: int = 0
        self.tools_tokens_key: tuple[str, ...] | None = None

        self.turn_executed_tool = False

        self.sys_prompt = build_system_prompt(
            BuildOptions(
                skills=self.skills,
                thinking_enabled=self.thinking,
                target=self.target,
                tooling_profile=self.tooling_profile,
                prompt_profile=self.prompt_profile,
                memory=self.memory,
                engagement=self.engagement,
                curated_memory=(
                    self.memory_store.index()
                    if self.memory_store
                    else ""
                ),
                workflow=self.workflow,
                engagement_state=self.engagement_state,
            )
        )

        self.history = [
            Message(
                role="system",
                content=self.sys_prompt,
            )
        ]

    def _spawn_background(self, coro, label: str) -> asyncio.Task:
        """Run a coroutine detached, keeping a reference so it is not garbage
        collected mid-flight and its failure is reported instead of dropped."""
        task = asyncio.create_task(coro)
        self._background_tasks.add(task)

        def done(finished: asyncio.Task) -> None:
            self._background_tasks.discard(finished)

            if finished.cancelled():
                return

            err = finished.exception()
            if err is not None:
                log_error(
                    f"agent: background task {label} failed",
                    {"err": err_message(err)},
                )

        task.add_done_callback(done)
        return task

    def get_history(self) -> list[Message]:
        return [replace(m) for m in self.history]

    def get_max_steps(self) -> int:
        return self.max_steps

    def set_max_steps(self, n: int) -> None:
        if n >= 1:
            self.max_steps = n

    def get_auto_compact_threshold(self) -> int:
        return self.auto_compact_threshold

    def set_auto_compact_threshold(self, n: int) -> None:
        self.auto_compact_threshold = max(0, int(n))

    def get_memory_stats(self) -> MemoryStats:
        return MemoryStats(
            compactions=(
                self.memory.compactions
                if self.memory
                else 0
            ),
            items=(
                count_memory_items(self.memory)
                if self.memory
                else 0
            ),
            last_compacted_at=(
                self.memory.last_compacted_at
                if self.memory
                else None
            ),
        )

    def is_running(self) -> bool:
        return self.running

    def thinking_is_enabled(self) -> bool:
        return self.thinking

    def reasoning_status(self, enabled: bool | None = None) -> str:
        preference = self.thinking if enabled is None else enabled
        requested = requested_level(ReasoningPurpose.AGENT_TURN, preference)
        has_tools = bool(self.tools.as_llm_tools())
        resolution = resolve_level(
            requested,
            self.client.reasoning_capabilities(has_tools=has_tools),
        )
        if resolution.effective is None:
            return (
                f"thinking {'on' if preference else 'off'} requested; provider behavior unverified. "
                "System prompt guidance follows this setting."
            )
        if resolution.effective is not requested:
            status = (
                f"thinking {'on' if preference else 'off'} requested; "
                f"model uses {resolution.effective.value} ({resolution.relation})"
            )
            if resolution.relation == "fallback":
                return f"{status}. System prompt guidance follows this setting."
            return status
        return f"thinking {'on' if preference else 'off'}; model uses {resolution.effective.value}"

    async def set_thinking_enabled(self, enabled: bool) -> None:
        self.thinking = enabled
        self.rebuild_system_prompt()
        await self.save()

    def set_client(self, client: Client) -> None:
        if self.running:
            raise RuntimeError(
                "cannot switch model/provider while a turn is in flight "
                "- cancel first with Esc"
            )

        self.client = client

    def set_prompt_profile(self, profile: PromptProfile) -> None:
        if self.prompt_profile == profile:
            return

        self.prompt_profile = profile
        self.rebuild_system_prompt()
        self.history = ensure_system_prompt(
            self.history,
            self.sys_prompt,
        )

    def format_memory(
        self,
    ) -> str:
        if (
            self.memory is None
            or count_memory_items(self.memory) == 0
        ):
            return (
                "session memory is empty — "
                "run /compact after useful work accumulates."
            )

        m = self.memory
        out = []

        out.append(
            f"Session memory · "
            f"{m.compactions} compaction"
            f"{'' if m.compactions == 1 else 's'}"
        )

        if m.last_compacted_at:
            out.append(
                f"Last compacted: {m.last_compacted_at}"
            )

        for title, items in [
            ("Objectives", m.objectives),
            ("Plan", m.plan),
            ("Completed", m.completed),
            ("Findings", m.findings),
            ("Tested surface", m.tested),
            ("Files", m.files),
            ("Commands", m.commands),
            ("Credentials / placeholders", m.credentials),
            ("TODOs", m.todos),
        ]:
            append_memory_section(
                out,
                title,
                items,
            )

        return "\n".join(out)

    async def clear_memory(self) -> None:
        if (
            self.memory is None
            or count_memory_items(self.memory) == 0
        ):
            return

        self.memory = None
        self.rebuild_system_prompt()
        self.history = ensure_system_prompt(
            self.history,
            self.sys_prompt,
        )
        await self.save()

    async def forget_memory(
        self,
        query: str,
    ) -> list[str]:
        needle = query.strip().lower()

        if not needle:
            return []

        removed: list[str] = []

        if self.memory_store:
            removed.extend(
                self.memory_store.forget(query)
            )

        if self.memory:

            def prune(items: list[str]) -> list[str]:
                result = []

                for item in items:
                    if needle in item.lower():
                        removed.append(item)
                    else:
                        result.append(item)

                return result

            self.memory = replace(
                self.memory,
                objectives=prune(self.memory.objectives),
                plan=prune(self.memory.plan),
                completed=prune(self.memory.completed),
                findings=prune(self.memory.findings),
                tested=prune(self.memory.tested),
                files=prune(self.memory.files),
                commands=prune(self.memory.commands),
                credentials=prune(self.memory.credentials),
                todos=prune(self.memory.todos),
            )

        if not removed:
            return []

        self.rebuild_system_prompt()
        self.history = ensure_system_prompt(
            self.history,
            self.sys_prompt,
        )
        await self.save()

        return removed

    async def add_memory(
        self,
        input: AddMemoryInput,
    ) -> MemoryFact | None:
        if self.memory_store is None:
            return None

        if isinstance(input, dict):
            input = AddMemoryInput(**input)

        fact = self.memory_store.add(input)

        if fact is None:
            return None

        self.rebuild_system_prompt()
        self.history = ensure_system_prompt(
            self.history,
            self.sys_prompt,
        )
        await self.save()

        return fact

    def list_curated_memory(self) -> list[MemoryFact]:
        if self.memory_store is None:
            return []

        return self.memory_store.list()

    def recall_curated_memory(
        self,
        user_msg: str,
        emit,
    ) -> str:
        if self.memory_store is None:
            return ""

        query = "\n".join(
            [
                user_msg,
                self.target.base_url(),
                self.target.name(),
            ]
        )

        facts = self.memory_store.search(
            query,
            5,
        )

        if len(facts) == 0:
            return ""

        emit(
            {
                "type": "memory-recall",
                "names": [fact.name for fact in facts],
            }
        )

        return format_memory_recall(facts)

    async def clear_intelligence(
        self,
        scope: Literal["project", "personal", "all"] = "all",
    ) -> None:
        if self.intelligence:
            await self.intelligence.clear(scope)

    def get_intelligence_stats(
        self,
    ) -> dict:
        if self.intelligence:
            return self.intelligence.get_stats()

        return {
            "project": 0,
            "personal": 0,
        }

    def build_intelligence_context(
        self,
        user_msg: str,
    ) -> str:
        if self.intelligence is None:
            return ""

        query = "\n".join(
            x
            for x in [
                user_msg,
                self.target.base_url(),
                self.target.name(),
                self.memory.last_summary if self.memory else "",
                *(self.memory.objectives if self.memory else []),
                *(self.memory.tested if self.memory else []),
                *(self.memory.files if self.memory else []),
                *(self.memory.todos if self.memory else []),
            ]
            if x is not None
        )
        results = [
            r
            for r in self.intelligence.search(query, 5)
            if r["score"] >= 6
        ]

        return format_intelligence_context(results)

    async def learn_intelligence(
        self,
        summary: str,
    ) -> None:
        if self.intelligence is None:
            return

        source_session_id = (
            self.store.id
            if self.store is not None
            else None
        )

        try:
            await self.intelligence.learn_from_text(
                summary,
                source_session_id,
            )

        except Exception as err:
            log_error(
                "agent: intelligence learning failed",
                {
                    "err": err_message(err),
                },
            )

    async def set_skill_enabled(self, name: str, enabled: bool) -> bool:
        if not self.skills.has(name):
            return False

        changed = self.skills.set_disabled(name, not enabled)

        if not changed:
            return False

        if not enabled:
            self.active_skills.discard(name)
            self.pending_skills.discard(name)

        self.rebuild_system_prompt()
        self.history = ensure_system_prompt(
            self.history,
            self.sys_prompt,
        )
        await self.save()

        return True

    def rebuild_from_skills(self) -> None:
        self.rebuild_system_prompt()
        self.history = ensure_system_prompt(
            self.history,
            self.sys_prompt,
        )

    async def inject_skill(self, name: str) -> str:
        if self.running:
            raise RuntimeError(
                "cannot load a skill while a turn is in flight "
                "- cancel first with Esc"
            )

        skill = self.skills.get(name)

        if skill is None:
            raise RuntimeError(f'unknown skill "{name}"')

        if self.skills.is_disabled(name):
            raise RuntimeError(
                f'skill "{name}" is disabled '
                "- enable it from /skills first"
            )

        body = materialize_skill_body(skill)

        self.history.append(
            Message(
                role="system",
                content=(
                    f"The user invoked /{name}. "
                    f"Apply this skill to the next request:\n\n{body}"
                ),
            )
        )

        self.pending_skills.add(name)
        await self.save()

        return name

    def is_tool_allowed(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
    ) -> ToolAllowedResult:
        if len(self.active_skills) == 0:
            return ToolAllowedResult(
                ok=True,
            )

        tool = self.tools.get(tool_name)

        if tool is None:
            return ToolAllowedResult(
                ok=True,
            )

        requires_permission = (
            tool.requires_permission_for(args or {})
            if isinstance(tool, ActionPermissionTool)
            else tool.requires_permission()
        )

        if not requires_permission:
            return ToolAllowedResult(
                ok=True,
            )

        active_skills = []

        for name in self.active_skills:
            skill = self.skills.get(name)

            if skill is not None:
                active_skills.append(skill)

        if len(active_skills) == 0:
            return ToolAllowedResult(
                ok=True,
            )

        for skill in active_skills:
            if len(skill.tools) == 0:
                return ToolAllowedResult(
                    ok=True,
                )

        wanted = canonical_tool_name(tool_name)

        allowed_by = []

        for skill in active_skills:

            allowed_tools = [
                canonical_tool_name(t)
                for t in skill.tools
            ]

            if wanted in allowed_tools:
                allowed_by.append(skill)

        if len(allowed_by) > 0:
            return ToolAllowedResult(
                ok=True,
            )

        summary = []

        for name in self.active_skills:

            skill = self.skills.get(name)

            if skill and len(skill.tools) > 0:
                tools = ", ".join(skill.tools)
            else:
                tools = "(none)"

            summary.append(
                f"{name} (allows: {tools})"
            )

        return ToolAllowedResult(
            ok=False,
            reason=(
                f'tool "{tool_name}" is not in any active skill allowed-tools list. '
                f'Active skills: {"; ".join(summary)}. '
                'Load a skill that allows this tool or choose another approach.'
            ),
        )

    def approx_tokens(self) -> int:
        return approximate_message_tokens(self.history)

    def tools_token_estimate(self) -> int:
        tools_key = tuple(self.tools.names())

        if tools_key != self.tools_tokens_key:

            tools_json = json.dumps(
                self.tools.as_llm_tools(),
                ensure_ascii=False,
            )

            self.tools_tokens_cache = len(tools_json) // 4
            self.tools_tokens_key = tools_key

        return self.tools_tokens_cache

    async def reset(self) -> None:
        self.memory = None
        self.workflow.clear()
        self._clear_permission_cache()
        self.rebuild_system_prompt()

        self.history = [
            Message(
                role="system",
                content=self.sys_prompt,
            )
        ]

        self.active_skills.clear()
        self.pending_skills.clear()

        self.consecutive_compact_failures = 0

        if self.store is not None:
            await self.store.clear()

    def has_saved_session(self) -> bool:

        if self.store is None:
            return False

        try:
            loaded = self.store.load()

            return (
                len(loaded.messages) > 1
                or bool(loaded.workflow.candidates)
                or bool(loaded.workflow.validation_results)
            )

        except Exception as err:
            log_error(
                "agent: saved session is unreadable; starting fresh",
                {"err": err_message(err)},
            )
            return False

    def resume_saved(self) -> None:
        if self.store is None:
            return

        loaded = self.store.load()
        self._clear_permission_cache()

        if loaded.target is not None:
            self.target.copy_from(loaded.target)

        self.memory = loaded.memory
        self.workflow.replace_from(loaded.workflow)
        self.engagement_state.replace_from(loaded.engagement_state)
        if not self.target.empty():
            self.engagement_state.add_origin(self.target.base_url())

        self.rebuild_system_prompt()

        if len(loaded.messages) == 0:

            self.history = [
                Message(
                    role="system",
                    content=self.sys_prompt,
                )
            ]
            return

        self.history = reconcile_tool_calls(
            ensure_system_prompt(
                loaded.messages,
                self.sys_prompt,
            )
        )

    async def save(
        self,
    ) -> None:
        if self.store is None:
            return

        await self.store.save(
            self.history,
            self.target,
            self.memory,
            self.workflow,
            self.engagement_state,
        )

    async def save_context_snapshot(self, reason: str = "periodic") -> str:
        if self.store is None:
            return ""

        out = []

        out.append("# KAgent Session Context")
        out.append("")

        out.append(f"Updated: {datetime.now(timezone.utc).isoformat()}")
        out.append(f"Reason: {reason}")
        out.append(f"Provider: {self.client.name()}")
        out.append(f"Model: {self.client.model()}")
        out.append(
            f"Target: {self.target.base_url() or self.target.name() or '(none)'}"
        )
        out.append(f"Approx tokens: {self.approx_tokens()}")

        out.append("")

        out.append("## Persistent Memory")
        out.append("")
        out.append(self.format_memory())

        out.append("")

        out.append("## Redacted Conversation Context")
        out.append("")
        out.append(
            format_history_for_compaction(self.history[1:])
        )

        content = "\n".join(out)

        return await self.store.save_context_snapshot(content)

    def rebuild_system_prompt(
        self,
    ) -> None:
        self.sys_prompt = build_system_prompt(
            BuildOptions(
                skills=self.skills,
                thinking_enabled=self.thinking,
                target=self.target,
                tooling_profile=self.tooling_profile,
                prompt_profile=self.prompt_profile,
                memory=self.memory,
                engagement=self.engagement,
                curated_memory=(
                    self.memory_store.index()
                    if self.memory_store
                    else ""
                ),
                workflow=self.workflow,
                engagement_state=self.engagement_state,
            )
        )

    async def set_target_base_url(self, url: str) -> None:
        self.apply_target_base_url(url)
        await self.save()

    async def clear_target(self) -> None:
        self.apply_target_clear()
        await self.save()

    def apply_target_base_url(self, url: str) -> None:
        new_origin = HTTPOrigin.from_url(url)
        current_origin = self.target.origin()
        origin_changed = current_origin != new_origin

        if origin_changed:
            _, scope_changed = self.engagement_state.reset_to_origin(url)
        else:
            _, scope_changed = self.engagement_state.add_origin(url)

        self.target.set_base_url(url)
        if origin_changed:
            self.workflow.clear()
            self._clear_permission_cache()
        elif scope_changed:
            self._clear_permission_cache()
        self.refresh_scope_context()

    def apply_target_clear(self) -> None:
        scope_changed = self.engagement_state.clear()
        target_changed = not self.target.empty()
        self.target.clear()
        if scope_changed or target_changed:
            self.workflow.clear()
        self._clear_permission_cache()
        self.refresh_scope_context()

    def _clear_permission_cache(self) -> None:
        clear = getattr(self.prompter, "clear_session_cache", None)
        if callable(clear):
            clear()

    def initialize_target_from_user_request(self, user_msg: str) -> bool:
        if not _OPERATIONAL_TARGET_TERMS.search(user_msg):
            return False

        origins: list[HTTPOrigin] = []
        for match in _EXPLICIT_HTTP_URL_RE.finditer(user_msg):
            candidate = match.group(0).rstrip(".,;!?)]}")
            try:
                origins.append(HTTPOrigin.from_url(candidate))
            except ValueError:
                continue

        if len(origins) != 1:
            return False

        current_origin = self.target.origin()
        if current_origin == origins[0]:
            return False
        if current_origin is None and self.target.empty() and self.engagement_state.allowed_origins:
            return False

        self.apply_target_base_url(origins[0].as_url())
        return True

    def _available_workflow_phases(self) -> frozenset[str]:
        enabled = {
            skill.name for skill in self.skills.list_enabled()
            if not skill.disable_model_invocation
        }
        phases = set()
        if "recon" in enabled:
            phases.add("recon")
        if "web-enumeration" in enabled:
            phases.add("enumeration")
        if "web-input-analysis" in enabled:
            phases.add("input_analysis")
        return frozenset(phases)

    def _workflow_validator_classes(self) -> frozenset[str]:
        return frozenset(
            candidate_class
            for skill in self.skills.list_enabled()
            if skill.stage == "validation" and not skill.disable_model_invocation
            for candidate_class in skill.candidate_classes
        )

    def _whole_target_state(self) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
        objective = self.workflow.objective
        if objective is None or objective.mode != "whole_target":
            return "not_applicable", (), ()
        target_origin = self.target.origin()
        origin = target_origin.as_url() if target_origin is not None else None
        workflow_tool = self.tools.get("workflow")
        coverage_sync_available = bool(
            workflow_tool is not None
            and getattr(workflow_tool, "coverage", None) is not None
        )
        return self.workflow.whole_target_status(
            target_origin=origin,
            available_phases=self._available_workflow_phases(),
            validator_classes=self._workflow_validator_classes(),
            coverage_sync_available=coverage_sync_available,
        )

    def _initialize_request_objective(self, user_msg: str, tools_enabled: bool) -> None:
        if not tools_enabled:
            return
        target_origin = self.target.origin()
        origin = target_origin.as_url() if target_origin is not None else None
        current = self.workflow.objective
        candidate_id = next(
            (item_id for item_id in sorted(self.workflow.candidates) if item_id in user_msg),
            None,
        )
        candidate_request = bool(
            candidate_id and _CANDIDATE_VALIDATION_INTENT.search(user_msg)
        )
        whole_request = bool(
            not is_purely_informational(normalize(user_msg))
            and (
                _WHOLE_TARGET_INTENT.search(user_msg)
                or (
                    _PENTEST_REQUEST_INTENT.search(user_msg)
                    and not candidate_request
                )
            )
        )

        if current is not None and not _NEW_OBJECTIVE_INTENT.search(user_msg):
            different_candidate = (
                current.mode == "candidate_validation"
                and candidate_request
                and candidate_id != current.candidate_id
            )
            if not different_candidate and self._is_objective_continuation(
                user_msg, current
            ):
                return

        if whole_request and origin:
            mode = "whole_target"
            selected_candidate = None
        elif candidate_request:
            mode = "candidate_validation"
            selected_candidate = candidate_id
        else:
            mode = "direct"
            selected_candidate = None
        self.workflow.objective = WorkflowObjective(
            id=uuid.uuid4().hex,
            mode=mode,  # type: ignore[arg-type]
            target_origin=origin,
            candidate_id=selected_candidate,
        )

    def _is_objective_continuation(self, user_msg: str, current: WorkflowObjective) -> bool:
        if current.mode == "whole_target":
            status, _, _ = self._whole_target_state()
            if status == "completed":
                return False
        elif current.mode == "candidate_validation":
            candidate = self.workflow.candidates.get(current.candidate_id or "")
            if candidate is None:
                return False
            candidate_target = candidate_origin(candidate.target)
            active_target = self.target.origin()
            active_origin = active_target.as_url() if active_target is not None else None
            if (
                current.target_origin is not None
                and candidate_target != current.target_origin
            ) or (active_origin is not None and candidate_target != active_origin):
                return False

        if _OBJECTIVE_CONTINUATION_INTENT.search(user_msg):
            return True
        if is_purely_informational(normalize(user_msg)):
            return False
        if self._previous_turn_asked_user():
            return True
        dependency_reply = _OBJECTIVE_DEPENDENCY_REPLY.search(user_msg)
        dependency_provided = _OBJECTIVE_DEPENDENCY_PROVIDED.search(user_msg)
        return bool(
            dependency_reply
            and (self._objective_has_blocker(current) or dependency_provided)
        )

    def _previous_turn_asked_user(self) -> bool:
        for message in reversed(self.history):
            if message.role != "assistant":
                continue
            return bool(
                message.tool_calls
                and any(call.function.name == "ask_user" for call in message.tool_calls)
            )
        return False

    def _objective_has_blocker(self, objective: WorkflowObjective) -> bool:
        if objective.mode == "whole_target":
            _, _, blockers = self._whole_target_state()
            return bool(blockers)
        if objective.mode == "candidate_validation" and objective.candidate_id:
            candidate = self.workflow.candidates.get(objective.candidate_id)
            result = self.workflow.latest_result(objective.candidate_id)
            return bool(
                (candidate is not None and candidate.status == "deferred")
                or (
                    result is not None
                    and result.outcome in {
                        "blocked", "insufficient-evidence", "deferred",
                        "browser-required", "authorization-required",
                    }
                )
            )
        return False

    def _planner_context(self) -> PlannerContext:
        objective = self.workflow.objective
        whole_target = objective is not None and objective.mode == "whole_target"
        status, actionable_work, blockers = (
            self._whole_target_state()
            if whole_target else ("not_applicable", (), ())
        )
        candidates = (
            self.workflow.objective_candidates()
            if whole_target
            else tuple(sorted(self.workflow.candidates.values(), key=lambda item: item.id))
        )
        pending_inputs = sum(
            item.disposition == "pending" for item in self.workflow.objective_inputs()
        ) if whole_target else 0
        blocked_inputs = sum(
            item.disposition == "blocked" for item in self.workflow.objective_inputs()
        ) if whole_target else 0
        sync_candidates = tuple(
            candidate.id
            for candidate in candidates
            if (result := self.workflow.latest_result(candidate.id)) is not None
            and result.coverage_synced is False
            and f"coverage-sync:{candidate.id}" in actionable_work
        ) if whole_target else ()
        return PlannerContext(
            active_skills=frozenset(self.active_skills),
            candidate_classes=(
                frozenset(item.candidate_class for item in candidates if item.status in {"new", "queued", "validating"})
                if whole_target else self.workflow.relevant_candidate_classes()
            ),
            completed_skills=frozenset(self.workflow.completed_skills),
            candidates=tuple(
                PlannerCandidate(
                    id=candidate.id,
                    candidate_class=candidate.candidate_class,
                    status=candidate.status,
                    endpoint=candidate.endpoint,
                    priority=candidate.priority,
                    latest_outcome=(result.outcome if result else None),
                    deferred_reason=(result.deferred_reason if result else None),
                    evidence_count=(len(result.evidence_refs) if result else 0),
                    coverage_synced=(result.coverage_synced if result else None),
                )
                for candidate in candidates
                for result in [self.workflow.latest_result(candidate.id)]
            ),
            objective_mode=objective.mode if objective else None,
            objective_id=objective.id if objective else None,
            target_origin=objective.target_origin if objective else None,
            completed_phases=(
                self.workflow.completed_phases(objective) if whole_target else frozenset()
            ),
            pending_input_count=pending_inputs,
            blocked_input_count=blocked_inputs,
            coverage_sync_candidate_ids=sync_candidates,
            workflow_status=status,
            workflow_blockers=blockers,
        )

    def _refresh_whole_target_guidance(self, working: list[Message], user_msg: str) -> None:
        objective = self.workflow.objective
        if objective is None or objective.mode != "whole_target":
            return
        working[:] = [
            message for message in working
            if not (
                message.role == "system"
                and message.content.startswith("Decision planner guidance for this turn:")
            )
        ]
        decision = build_decision_plan(
            user_msg,
            self.skills.list_enabled(),
            self.target,
            self._planner_context(),
        )
        if decision is not None:
            working.append(Message(role="system", content=decision.guidance))

    def add_scope_origin(self, url: str) -> tuple[HTTPOrigin, bool]:
        if self.target.empty():
            raise ValueError("no active engagement")
        origin, changed = self.engagement_state.add_origin(url)
        if changed:
            self._clear_permission_cache()
            self.refresh_scope_context()
        return origin, changed

    def remove_scope_origin(self, url: str) -> tuple[HTTPOrigin, bool]:
        if self.target.empty():
            raise ValueError("no active engagement")
        origin = HTTPOrigin.from_url(url)
        if origin == self.target.origin():
            raise ValueError("cannot remove the active target origin")
        removed_origin, changed = self.engagement_state.remove_origin(url)
        if changed:
            self._clear_permission_cache()
            self.refresh_scope_context()
        return removed_origin, changed

    def reset_scope_to_target(self) -> tuple[HTTPOrigin, bool]:
        if self.target.empty():
            raise ValueError("no active engagement")
        origin, changed = self.engagement_state.reset_to_origin(
            self.target.base_url()
        )
        if changed:
            self._clear_permission_cache()
            self.refresh_scope_context()
        return origin, changed

    def refresh_scope_context(self) -> None:
        """Refresh the current scope instructions after a real mutation."""
        self.rebuild_system_prompt()
        self.history = ensure_system_prompt(self.history, self.sys_prompt)
        self.history = [
            message
            for message in self.history
            if not (
                message.role == "system"
                and message.content.startswith(SCOPE_CONTEXT_MARKER)
            )
        ]
        origins = "\n".join(
            f"- {origin.as_url()}"
            for origin in sorted(self.engagement_state.allowed_origins)
        ) or "- (none)"
        self.history.append(
            Message(
                role="system",
                content=(
                    f"{SCOPE_CONTEXT_MARKER}\n"
                    f"Revision: {self.engagement_state.revision}\n"
                    "This is the complete, current allowed HTTP-origin list. "
                    "Every listed origin is in scope for http and web_fetch; "
                    "do not treat one as out of scope because of an earlier "
                    "conversation message. Runtime tool validation remains "
                    "authoritative.\n"
                    f"{origins}"
                ),
            )
        )

    async def coverage_context(self, signal) -> str:
        if self.tools.get("coverage") is None:
            return "Coverage tool is not available in this session."

        try:
            summary = await self.tools.execute(
                "coverage",
                {"action": "summary"},
                signal,
                self.prompter,
            )
        except Exception as err:
            summary = f"error: {err_message(err)}"

        try:
            entries = await self.tools.execute(
                "coverage",
                {"action": "list"},
                signal,
                self.prompter,
            )
        except Exception as err:
            entries = f"error: {err_message(err)}"

        return "\n".join(
            [
                "Coverage summary:",
                str(summary),
                "",
                "Coverage entries:",
                str(entries),
                "",
                "Workflow candidates:",
                *[
                    (
                        f"- {candidate.id} {candidate.candidate_class} "
                        f"{candidate.status} {candidate.method or ''} "
                        f"{candidate.endpoint or ''}; latest="
                        f"{(result.outcome if result else 'none')}; "
                        f"reason={(result.deferred_reason if result else None) or 'none'}; "
                        f"coverage_sync={(result.coverage_synced if result else None)}"
                    )
                    for candidate in sorted(
                        self.workflow.candidates.values(), key=lambda item: item.id
                    )[:25]
                    for result in [self.workflow.latest_result(candidate.id)]
                ],
                "",
                (
                    "Coverage collection results are paginated. "
                    "complete=false means the displayed page is not the full "
                    "matching set; has_more/next_cursor describe continuation."
                ),
                (
                    "Use this coverage state to choose next tests. "
                    "Prefer untested endpoint/parameter/vulnerability-class "
                    "combinations. Do not repeat entries already marked "
                    "passed or failed unless the objective explicitly asks for retesting. "
                    "A blocked/deferred candidate may be revisited only when its blocker changes."
                ),
            ]
        )

    def _reset_llm_call_counts(self) -> None:
        for name in self._llm_call_counts:
            self._llm_call_counts[name] = 0

    def _count_llm_call(self, name: str) -> None:
        self._llm_call_counts[name] += 1

    def _done_event(self, stop_reason: str | None) -> dict[str, Any]:
        return {
            "type": "done",
            "stop_reason": stop_reason,
            **self._llm_call_counts,
            "total_llm_calls": sum(self._llm_call_counts.values()),
        }

    async def run(
        self,
        user_msg: str,
        signal,
        emit,
        opts: AgentRunOptions | None = None,
    ) -> None:
        safe_emit = make_safe_emit(signal, emit)

        self.running = True
        self._reset_llm_call_counts()
        self._turn_client_error = False
        stop_reason = "runtime_error"

        try:
            stop_reason = await self.run_inner(
                user_msg,
                signal,
                safe_emit,
                opts,
            )

        except asyncio.CancelledError:
            stop_reason = "cancelled"
            raise
        except Exception as err:
            if signal.aborted or is_abort_like_error(err):
                stop_reason = "cancelled"

                safe_emit(
                    {
                        "type": "error",
                        "err": AgentRuntimeError("turn cancelled"),
                    }
                )
                return
            if self._turn_client_error:
                stop_reason = "client_error"
            traceback.print_exc()

            log_error(
                "agent: panic in Run",
                {
                    "err": err_message(err),
                },
            )

            safe_emit(
                {
                    "type": "error",
                    "err": err,
                }
            )

        finally:

            self.running = False

            safe_emit(self._done_event(stop_reason))

    async def run_inner(
        self,
        user_msg: str,
        signal,
        emit,
        opts=None,
    ) -> str:
        if isinstance(opts, dict):
            opts = AgentRunOptions(**opts)

        tools_enabled = opts is None or getattr(opts, "tools", True)
        turn_thinking = self.thinking
        turn_requested_level = requested_level(
            ReasoningPurpose.AGENT_TURN, turn_thinking
        )
        turn_resolution = resolve_level(
            turn_requested_level,
            self.client.reasoning_capabilities(
                has_tools=tools_enabled and bool(self.tools.as_llm_tools())
            ),
        )
        turn_reasoning_level = turn_resolution.effective or turn_requested_level
        turn_request_thinking = (
            turn_reasoning_level is not ReasoningLevel.OFF
            if turn_resolution.effective is not None
            else turn_thinking
        )
        if tools_enabled:
            self.initialize_target_from_user_request(user_msg)
            self._initialize_request_objective(user_msg, tools_enabled)

        self.active_skills = set(self.pending_skills)
        self.pending_skills.clear()
        for name in sorted(self.active_skills):
            emit(
                {
                    "type": "skill-active",
                    "name": name,
                }
            )

        self.turn_executed_tool = False

        self.history = reconcile_tool_calls(
            self.history
        )
        elide_persisted_workflow_results(self.history)
        self.rebuild_system_prompt()
        self.history = ensure_system_prompt(
            self.history,
            self.sys_prompt,
        )

        expanded_user_msg = expand_file_mentions(
            user_msg
        )

        incoming_tokens = len(expanded_user_msg) // 4

        if opts is not None and getattr(opts, "tools", True) is False:
            tools_tokens = 0
        else:
            tools_tokens = self.tools_token_estimate()

        history_tokens = self.approx_tokens()
        trigger_tokens = history_tokens + incoming_tokens + tools_tokens
        compactable_history_tokens = approximate_message_tokens(self.history[1:])

        if (
            self.auto_compact_threshold > 0
            and self.consecutive_compact_failures
            < MAX_CONSECUTIVE_AUTOCOMPACT_FAILURES
            and trigger_tokens >= self.auto_compact_threshold
            and compactable_history_tokens
            >= minimum_compactable_history_tokens(self.auto_compact_threshold)
        ):
            await self.auto_compact(
                signal,
                emit,
                trigger_tokens=trigger_tokens,
                history_tokens=history_tokens,
                incoming_tokens=incoming_tokens,
                tools_tokens=tools_tokens,
            )

        if opts is not None and getattr(opts, "tools", True) is False:
            decision = None
        else:
            decision = build_decision_plan(
                user_msg,
                self.skills.list_enabled(),
                self.target,
                self._planner_context(),
            )

        if decision and decision.recommended_skill:
            matched_prefix = f"matched {decision.recommended_skill} signals:"
            matched_signals = decision.reason.removeprefix(matched_prefix).strip()
            summary = (
                f"Planner · {decision.recommended_skill} · "
                f"risk: {decision.risk}"
            )
            if matched_signals:
                summary += f"\nmatched: {matched_signals}"
            emit(
                {
                    "type": "decision",
                    "summary": summary,
                }
            )

        self.history.append(
            Message(
                role="user",
                content=user_msg,
            )
        )

        working = deepcopy(self.history)

        try:
            await self.save()
        except Exception as err:
            emit(
                {
                    "type": "error",
                    "err": Exception(
                        f"save session: {err}"
                    ),
                }
            )

        last = working[-1] if working else None

        if decision and last:
            working.insert(
                len(working) - 1,
                Message(
                    role="system",
                    content=decision.guidance,
                ),
            )

        intelligence_context = self.build_intelligence_context(
            user_msg
        )

        if intelligence_context and last:
            working.insert(
                len(working) - 1,
                Message(
                    role="system",
                    content=intelligence_context,
                ),
            )

        recall = self.recall_curated_memory(
            user_msg,
            emit,
        )

        if recall and last:
            working.insert(
                len(working) - 1,
                Message(
                    role="system",
                    content=recall,
                ),
            )

        if last:
            last.content = expanded_user_msg

        max_steps = self.max_steps
        objective = self.workflow.objective
        whole_target = bool(
            tools_enabled and objective is not None and objective.mode == "whole_target"
        )
        consecutive_no_progress = 0

        for step in range(max_steps):

            if signal.aborted:
                raise Exception("aborted")

            if self.auto_compact_threshold > 0:
                self.guard_working_context(
                    working,
                    emit,
                    opts,
                )

            if whole_target:
                self._refresh_whole_target_guidance(working, expanded_user_msg)
            before_facts = self.workflow.progress_facts() if whole_target else frozenset()
            response_chunks: list[str] | None = [] if whole_target else None

            req = ChatRequest(
                model=self.client.model(),
                messages=working,
                thinking_enabled=turn_request_thinking,
                reasoning_level=turn_reasoning_level,
                requested_reasoning_level=turn_requested_level,
            )

            if opts is None or getattr(opts, "tools", True):
                req.tools = self.tools.as_llm_tools()

            self._count_llm_call("agent_loop_llm_calls")
            if response_chunks is None:
                resp, streamed = await self._chat_for_turn(req, signal, emit)
            else:
                resp, streamed = await self._chat_for_turn(
                    req, signal, emit, stream_buffer=response_chunks
                )
            self._sanitize_response(resp)
            if streamed and response_chunks and not resp.message.content:
                resp.message.content = "".join(response_chunks)

            tool_calls = resp.message.tool_calls or []

            has_tool_calls = len(tool_calls) > 0

            if (
                opts is not None
                and getattr(opts, "tools", True) is False
                and has_tool_calls
            ):

                if resp.message.content and not streamed:
                    emit(
                        {
                            "type": "assistant-text",
                            "text": resp.message.content,
                        }
                    )

                emit(
                    {
                        "type": "error",
                        "err": Exception(
                            "plan-only mode blocked tool calls"
                        ),
                    }
                )

                return "plan_only_blocked"

            if not has_tool_calls and not resp.message.content.strip():
                emit({"type": "error", "err": InvalidResponseError()})
                return "invalid_response"

            malformed_tool_text = (
                not has_tool_calls
                and tools_enabled
                and _looks_like_malformed_tool_call(resp.message.content)
            )
            if not malformed_tool_text:
                await self._record_assistant_response(
                    resp, streamed, working, emit, emit_text=not whole_target
                )

            if malformed_tool_text:
                emit({
                    "type": "error",
                    "err": RuntimeError(
                        "model emitted malformed tool-call text instead of a "
                        "structured tool call; the intended action was not executed. "
                        "Retrying once with structured tool calling."
                    ),
                })
                retry_instruction = Message(
                    role="user",
                    content=(
                        "The previous assistant message contained text that looks "
                        "like a tool invocation, but it was not returned as a "
                        "structured tool call and no tool was executed. If that "
                        "action is still needed, call the appropriate available "
                        "tool using structured function calling only; do not print "
                        "tool-call syntax as text. Otherwise, explain that no tool "
                        "action is needed."
                    ),
                )
                working.append(retry_instruction)
                self.history.append(retry_instruction)
                try:
                    await self.save()
                except Exception as err:
                    emit({"type": "error", "err": Exception(f"save session: {err}")})

                if self.auto_compact_threshold > 0:
                    self.guard_working_context(working, emit, opts)
                retry_req = ChatRequest(
                    model=self.client.model(),
                    messages=working,
                    thinking_enabled=turn_request_thinking,
                    reasoning_level=turn_reasoning_level,
                    requested_reasoning_level=turn_requested_level,
                )
                if opts is None or getattr(opts, "tools", True):
                    retry_req.tools = self.tools.as_llm_tools()
                self._count_llm_call("agent_loop_llm_calls")
                retry_chunks: list[str] | None = [] if whole_target else None
                if retry_chunks is None:
                    resp, streamed = await self._chat_for_turn(retry_req, signal, emit)
                else:
                    resp, streamed = await self._chat_for_turn(
                        retry_req, signal, emit, stream_buffer=retry_chunks
                    )
                self._sanitize_response(resp)
                if streamed and retry_chunks and not resp.message.content:
                    resp.message.content = "".join(retry_chunks)
                tool_calls = resp.message.tool_calls or []
                has_tool_calls = len(tool_calls) > 0

                if not has_tool_calls:
                    warning = (
                        "Warning: the model did not return a structured tool call "
                        "after one retry; the intended action was not executed."
                    )
                    emit({"type": "error", "err": RuntimeError(warning)})
                    resp.message.content = (
                        f"{resp.message.content.rstrip()}\n\n{warning}"
                        if resp.message.content.strip()
                        else warning
                    )
                    if streamed and not whole_target:
                        emit({"type": "assistant-text", "text": warning})

                await self._record_assistant_response(
                    resp, streamed, working, emit, emit_text=not whole_target
                )
                response_chunks = retry_chunks

            if not has_tool_calls:

                if whole_target:
                    status, actionable, blockers = self._whole_target_state()
                    after_facts = self.workflow.progress_facts()
                    if after_facts - before_facts:
                        consecutive_no_progress = 0
                    else:
                        consecutive_no_progress += 1
                    if status == "completed":
                        return await self._whole_target_synthesis(
                            working, signal, emit,
                            thinking_enabled=turn_request_thinking,
                            reasoning_level=turn_reasoning_level,
                            requested_reasoning_level=turn_requested_level,
                            stop_reason="workflow_completed",
                            instruction=(
                                "The runtime completion contract is satisfied for the current whole-target "
                                "objective. Give a concise final assessment based on recorded evidence, "
                                "including confirmed and not-confirmed results, and do not overstate coverage."
                            ),
                            max_steps=max_steps,
                        )
                    if not actionable and blockers:
                        return await self._whole_target_synthesis(
                            working, signal, emit,
                            thinking_enabled=turn_request_thinking,
                            reasoning_level=turn_reasoning_level,
                            requested_reasoning_level=turn_requested_level,
                            stop_reason="workflow_blocked",
                            instruction=(
                                "The whole-target objective is blocked by structured runtime state. "
                                "Give a concise status summary, state that assessment is incomplete, "
                                "and explain these blockers without claiming completion: "
                                + "; ".join(blockers)
                            ),
                            max_steps=max_steps,
                        )
                    if consecutive_no_progress >= MAX_CONSECUTIVE_NO_PROGRESS:
                        return await self._whole_target_synthesis(
                            working, signal, emit,
                            thinking_enabled=turn_request_thinking,
                            reasoning_level=turn_reasoning_level,
                            requested_reasoning_level=turn_requested_level,
                            stop_reason="workflow_stalled",
                            instruction=(
                                "The whole-target workflow has made no new structured progress for "
                                f"{MAX_CONSECUTIVE_NO_PROGRESS} consecutive iterations. The objective "
                                "is incomplete. Summarize what was established and identify the "
                                "remaining structured work: " + "; ".join(actionable)
                            ),
                            max_steps=max_steps,
                        )
                    if step == max_steps - 1:
                        return await self._whole_target_synthesis(
                            working, signal, emit,
                            thinking_enabled=turn_request_thinking,
                            reasoning_level=turn_reasoning_level,
                            requested_reasoning_level=turn_requested_level,
                            stop_reason="max_steps",
                            instruction=(
                                f"The hard limit of {max_steps} outer agent iterations was reached. "
                                "The whole-target objective is incomplete. Summarize the evidence "
                                "recorded so far and identify remaining work: "
                                + "; ".join(actionable)
                            ),
                            max_steps=max_steps,
                        )
                    working.append(Message(
                        role="system",
                        content=(
                            "The preceding assistant text is an intermediate response. Do not end "
                            "the whole-target objective while runtime-known actionable work remains. "
                            "Continue from the current structured state and follow the latest planner guidance."
                        ),
                    ))
                    continue

                if self.turn_executed_tool:
                    self._spawn_background(
                        self.learn_intelligence(
                            build_turn_learning_text(
                                user_msg,
                                resp.message.content,
                            )
                        ),
                        "learn_intelligence",
                    )

                return "final_response"

            if whole_target:
                # Tool-call responses are known to be intermediate once the
                # complete provider response has been parsed, so flush their
                # buffered text before executing the calls.
                self._emit_buffered_response_text(
                    resp, streamed, response_chunks or [], emit
                )

            all_refused = await self.execute_tool_calls(
                tool_calls,
                signal,
                emit,
                working,
            )

            if all_refused:
                return "all_tools_refused"

            if whole_target:
                status, actionable, blockers = self._whole_target_state()
                after_facts = self.workflow.progress_facts()
                if after_facts - before_facts:
                    consecutive_no_progress = 0
                else:
                    consecutive_no_progress += 1
                if status == "completed":
                    return await self._whole_target_synthesis(
                        working, signal, emit,
                        thinking_enabled=turn_request_thinking,
                        reasoning_level=turn_reasoning_level,
                        requested_reasoning_level=turn_requested_level,
                        stop_reason="workflow_completed",
                        instruction=(
                            "The runtime completion contract is satisfied for the current whole-target "
                            "objective. Give a concise final assessment based on recorded evidence, "
                            "including confirmed and not-confirmed results, and do not overstate coverage."
                        ),
                        max_steps=max_steps,
                    )
                if not actionable and blockers:
                    return await self._whole_target_synthesis(
                        working, signal, emit,
                        thinking_enabled=turn_request_thinking,
                        reasoning_level=turn_reasoning_level,
                        requested_reasoning_level=turn_requested_level,
                        stop_reason="workflow_blocked",
                        instruction=(
                            "The whole-target objective is blocked by structured runtime state. "
                            "Give a concise status summary, say the assessment is incomplete, "
                            "and explain these blockers without claiming completion: "
                            + "; ".join(blockers)
                        ),
                        max_steps=max_steps,
                    )
                if consecutive_no_progress >= MAX_CONSECUTIVE_NO_PROGRESS:
                    return await self._whole_target_synthesis(
                        working, signal, emit,
                        thinking_enabled=turn_request_thinking,
                        reasoning_level=turn_reasoning_level,
                        requested_reasoning_level=turn_requested_level,
                        stop_reason="workflow_stalled",
                        instruction=(
                            "The whole-target workflow has made no new structured progress for "
                            f"{MAX_CONSECUTIVE_NO_PROGRESS} consecutive iterations. The objective "
                            "is incomplete. Summarize current evidence and remaining work: "
                            + "; ".join(actionable)
                        ),
                        max_steps=max_steps,
                    )
                if step == max_steps - 1:
                    return await self._whole_target_synthesis(
                        working, signal, emit,
                        thinking_enabled=turn_request_thinking,
                        reasoning_level=turn_reasoning_level,
                        requested_reasoning_level=turn_requested_level,
                        stop_reason="max_steps",
                        instruction=(
                            f"The hard limit of {max_steps} outer agent iterations was reached. "
                            "The whole-target objective is incomplete. Summarize the evidence "
                            "recorded so far and remaining work: " + "; ".join(actionable)
                        ),
                        max_steps=max_steps,
                    )

            if step == max_steps - 1:
                if self.auto_compact_threshold > 0:
                    self.guard_working_context(working, emit, opts)
                synthesis_req = ChatRequest(
                    model=self.client.model(),
                    messages=working,
                    thinking_enabled=turn_request_thinking,
                    reasoning_level=turn_reasoning_level,
                    requested_reasoning_level=turn_requested_level,
                )
                self._count_llm_call("final_synthesis_llm_calls")
                synthesis, synthesis_streamed = await self._chat_for_turn(
                    synthesis_req, signal, emit, purpose="final_synthesis"
                )
                self._sanitize_response(synthesis)
                if synthesis.message.tool_calls or not synthesis.message.content.strip():
                    emit({
                        "type": "error",
                        "err": InvalidResponseError(
                            "final synthesis returned tools or no visible text"
                        ),
                    })
                    return "invalid_response"
                await self._record_assistant_response(
                    synthesis, synthesis_streamed, working, emit
                )
                return "final_response"

        emit(
            {
                "type": "error",
                "err": MaxStepsError(max_steps),
            }
        )
        return "max_steps"

    @staticmethod
    def _sanitize_response(resp: ChatResponse) -> None:
        resp.message.content = strip_thinking_tags(resp.message.content)

    async def _record_assistant_response(
        self,
        resp: ChatResponse,
        streamed: bool,
        working: list[Message],
        emit,
        *,
        emit_text: bool = True,
    ) -> None:
        self.history.append(resp.message)
        working.append(resp.message)
        try:
            await self.save()
        except Exception as err:
            emit({"type": "error", "err": Exception(f"save session: {err}")})
        if emit_text and resp.message.content and not streamed:
            emit({"type": "assistant-text", "text": resp.message.content})

    @staticmethod
    def _emit_buffered_response_text(
        resp: ChatResponse, streamed: bool, chunks: list[str], emit
    ) -> None:
        if streamed and chunks:
            for chunk in chunks:
                emit({"type": "assistant-delta", "text": chunk})
        elif resp.message.content:
            emit({"type": "assistant-text", "text": resp.message.content})

    async def _whole_target_synthesis(
        self,
        working: list[Message],
        signal,
        emit,
        *,
        thinking_enabled: bool,
        reasoning_level: ReasoningLevel,
        requested_reasoning_level: ReasoningLevel,
        stop_reason: Literal[
            "workflow_completed", "workflow_blocked", "workflow_stalled", "max_steps"
        ],
        instruction: str,
        max_steps: int,
    ) -> str:
        working.append(Message(role="system", content=instruction))
        if self.auto_compact_threshold > 0:
            self.guard_working_context(working, emit, None)
        request = ChatRequest(
            model=self.client.model(),
            messages=working,
            thinking_enabled=thinking_enabled,
            reasoning_level=reasoning_level,
            requested_reasoning_level=requested_reasoning_level,
        )
        self._count_llm_call("final_synthesis_llm_calls")
        chunks: list[str] = []
        response, streamed = await self._chat_for_turn(
            request, signal, emit, purpose="final_synthesis", stream_buffer=chunks
        )
        self._sanitize_response(response)
        if streamed and chunks and not response.message.content:
            response.message.content = "".join(chunks)
        if response.message.tool_calls or not response.message.content.strip():
            emit({
                "type": "error",
                "err": InvalidResponseError(
                    "whole-target synthesis returned tools or no visible text"
                ),
            })
            return "invalid_response"
        await self._record_assistant_response(
            response, streamed, working, emit, emit_text=False
        )
        self._emit_buffered_response_text(response, streamed, chunks, emit)
        if stop_reason == "max_steps":
            emit({"type": "error", "err": MaxStepsError(max_steps)})
        return stop_reason

    async def _chat_for_turn(
        self, req, signal, emit, purpose: str = "agent_turn",
        stream_buffer: list[str] | None = None,
    ) -> tuple[ChatResponse, bool]:
        started = time.perf_counter()
        started_at = datetime.now(timezone.utc).isoformat()
        response: ChatResponse | None = None
        status: Literal["success", "error", "cancelled"] = "success"
        try:
            if stream_buffer is None:
                response, streamed = await self.chat(req, signal, emit)
            else:
                response, streamed = await self.chat(
                    req, signal, emit, stream_buffer=stream_buffer
                )
            return response, streamed
        except BaseException as err:
            status = "cancelled" if isinstance(err, asyncio.CancelledError) or getattr(signal, "aborted", False) else "error"
            self._turn_client_error = True
            raise
        finally:
            self._record_request_metrics(req, purpose, started_at, started, status, response)

    def _record_request_metrics(
        self, req: ChatRequest, purpose: str, started_at: str,
        started: float, status: Literal["success", "error", "cancelled"],
        response: ChatResponse | None,
    ) -> None:
        self.request_metrics.add(RequestMetrics(
            request_id=uuid.uuid4().hex,
            started_at=started_at,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            provider=self.client.name(), model=self.client.model(),
            purpose=purpose, policy_id=REASONING_POLICY_ID,
            requested_reasoning_level=(
                req.requested_reasoning_level.value
                if req.requested_reasoning_level is not None else None
            ),
            effective_reasoning_level=self._known_effective_reasoning_level(req),
            status=status,
            usage=response.usage if response else None,
            tool_call_count=len(response.message.tool_calls or []) if response else None,
            retry_count=response.retry_count if response else None,
            retry_wait_ms=response.retry_wait_ms if response else None,
        ))

    def _known_effective_reasoning_level(self, req: ChatRequest) -> str | None:
        if req.reasoning_level is None:
            return None
        resolution = resolve_level(
            req.reasoning_level,
            self.client.reasoning_capabilities(has_tools=bool(req.tools)),
        )
        return resolution.effective.value if resolution.effective is not None else None

    def _compaction_reasoning_settings(self) -> tuple[ReasoningLevel, bool]:
        requested = requested_level(ReasoningPurpose.COMPACTION, self.thinking)
        resolution = resolve_level(
            requested, self.client.reasoning_capabilities(has_tools=False)
        )
        level = resolution.effective or requested
        return level, level is not ReasoningLevel.OFF if resolution.effective else False

    def guard_working_context(
        self,
        working: list[Message],
        emit,
        opts=None,
    ) -> None:
        if opts is not None and getattr(opts, "tools", True) is False:
            tools_tokens = 0
        else:
            tools_tokens = self.tools_token_estimate()

        def size() -> int:
            return tools_tokens + approximate_message_tokens(working)

        threshold = self.auto_compact_threshold
        if threshold <= 0 or size() < threshold:
            return

        safety_tokens = max(
            MIDTURN_MIN_SAFETY_TOKENS,
            round(threshold * MIDTURN_SAFETY_RATIO),
        )
        target_tokens = max(0, threshold - safety_tokens)

        tool_indexes: list[int] = []

        for i, msg in enumerate(working):

            if msg.role == "tool":
                tool_indexes.append(i)

        def is_adaptive_tool_result(index: int) -> bool:
            return (
                self.tools.context_reduction_policy(working[index].name)
                == "adaptive"
            )

        elidable = tool_indexes[
            : max(
                0,
                len(tool_indexes)
                - MIDTURN_ELISION_KEEP_RECENT,
            )
        ]

        dropped = 0

        for i in elidable:

            if size() <= target_tokens:
                break

            if not is_adaptive_tool_result(i):
                continue

            msg = working[i]

            if msg.content.startswith(
                MIDTURN_ELISION_PREFIX
            ):
                continue

            original_length = len(msg.content)
            marker = (
                f"{MIDTURN_ELISION_PREFIX}"
                f" — {original_length} bytes dropped]"
            )

            working[i] = Message(
                role=msg.role,
                content=marker,
                tool_calls=msg.tool_calls,
                tool_call_id=msg.tool_call_id,
                name=msg.name,
            )

            dropped += original_length - len(marker)

        current_tokens = size()
        if current_tokens > target_tokens:
            candidates = [
                i
                for i in tool_indexes
                if is_adaptive_tool_result(i)
                and len(working[i].content) > MIDTURN_RECENT_TOOL_RESULT_CHAR_FLOOR
                and MIDTURN_ELISION_PREFIX not in working[i].content
            ]

            # Token estimates round each message independently. Keep the
            # proportional plan, but let each rendered replacement own the
            # stopping condition before touching a later result.
            if candidates:
                capacities = [
                    len(working[i].content) - MIDTURN_RECENT_TOOL_RESULT_CHAR_FLOOR
                    for i in candidates
                ]
                required_chars = (current_tokens - target_tokens) * 4
                reductions = _proportional_reductions(capacities, required_chars)

                for i, reduction in zip(candidates, reductions):
                    if reduction <= 0:
                        continue
                    msg = working[i]
                    bounded = bound_recent_tool_result(
                        msg.content,
                        len(msg.content) - reduction,
                    )
                    if bounded == msg.content:
                        continue
                    dropped += len(msg.content) - len(bounded)
                    working[i] = Message(
                        role=msg.role,
                        content=bounded,
                        tool_calls=msg.tool_calls,
                        tool_call_id=msg.tool_call_id,
                        name=msg.name,
                    )
                    if size() <= target_tokens:
                        break

        residual_tokens = max(0, size() - target_tokens)
        if dropped > 0:

            emit(
                {
                    "type": "decision",
                    "summary": (
                        "context guard: "
                        f"reduced {dropped} characters "
                        "of tool output "
                        "mid-turn to fit the context window"
                        + (
                            f"; unresolved pressure: {residual_tokens} tokens"
                            if residual_tokens > 0
                            else ""
                        )
                    ),
                }
            )

    async def execute_tool_calls(
        self,
        tool_calls: list[ToolCall],
        signal,
        emit,
        working: list[Message],
    ) -> bool:
        sequential = (
            len(tool_calls) <= 1
            or any(
                tc.function.name in STATEFUL_TOOLS
                for tc in tool_calls
            )
        )

        if sequential:

            results: list[ToolCallResult] = []

            for tc in tool_calls:

                if signal.aborted:
                    raise Exception("aborted")

                parsed = self.parse_tool_call(tc)

                emit(
                    {
                        "type": "tool-call",
                        "id": tc.id,
                        "name": tc.function.name,
                        "args": parsed.args,
                        "argsJSON": parsed.args_json,
                    }
                )
                result = await self.run_parsed_tool_call(
                    tc,
                    parsed,
                    signal,
                )
                self.record_tool_result(
                    tc,
                    parsed,
                    result,
                    emit,
                    working,
                )
                results.append(result)

            try:
                await self.save()
            except Exception as err:
                emit(
                    {
                        "type": "error",
                        "err": Exception(
                            f"save session: {err}"
                        ),
                    }
                )

            return all(
                result.terminal_user_controlled_refusal
                for result in results
            )
        parsed_all = [
            self.parse_tool_call(tc)
            for tc in tool_calls
        ]

        for tc, parsed in zip(tool_calls, parsed_all):

            emit(
                {
                    "type": "tool-call",
                    "id": tc.id,
                    "name": tc.function.name,
                    "args": parsed.args,
                    "argsJSON": parsed.args_json,
                }
            )

        results = await map_with_concurrency(
            tool_calls,
            MAX_PARALLEL_TOOL_CALLS,
            lambda tc, i: self.run_parsed_tool_call(
                tc,
                parsed_all[i],
                signal,
            ),
        )

        for tc, parsed, result in zip(
            tool_calls,
            parsed_all,
            results,
        ):

            self.record_tool_result(
                tc,
                parsed,
                result,
                emit,
                working,
            )

        try:
            await self.save()
        except Exception as err:
            emit(
                {
                    "type": "error",
                    "err": Exception(
                        f"save session: {err}"
                    ),
                }
            )

        if signal.aborted:
            raise Exception("aborted")

        return all(
            result.terminal_user_controlled_refusal
            for result in results
        )

    def parse_tool_call(
        self,
        tc: ToolCall,
    ) -> ParsedToolCall:
        args: dict[str, Any] = {}
        parse_err: Exception | None = None

        try:
            args = parsed_args(tc.function)
        except Exception as err:
            parse_err = err

        return ParsedToolCall(
            args=args,
            args_json=tc.function.arguments,
            parse_err=parse_err,
        )

    async def run_parsed_tool_call(
        self,
        tc: ToolCall,
        parsed: ParsedToolCall,
        signal,
    ) -> ToolCallResult:
        if signal.aborted:
            return ToolCallResult(
                result="ERROR: aborted",
                err_str="aborted",
                duration_ms=0,
                status="cancelled",
                error_kind="cancelled",
            )

        start = time.monotonic()

        result = ""
        run_err: Exception | None = None

        if parsed.parse_err is not None:
            run_err = Exception(
                f"could not parse arguments: "
                f"{parsed.parse_err} "
                f"(raw: {parsed.args_json})"
            )

        else:

            allowed = self.is_tool_allowed(
                tc.function.name,
                parsed.args,
            )

            if not allowed.ok:
                run_err = Exception(
                    allowed.reason
                    or "tool blocked by active skills"
                )

            else:
                try:
                    result = await self.tools.execute(
                        tc.function.name,
                        parsed.args,
                        signal,
                        self.prompter,
                    )
                except Exception as err:
                    run_err = err

        duration_ms = int(
            (time.monotonic() - start) * 1000
        )

        err_str = ""
        status: ToolStatus = "success"
        error_kind: ErrorKind | None = None
        http_status: int | None = None
        truncated = False

        if run_err is not None:

            err_str = str(run_err)

            result = f"ERROR: {err_str}"
            status = "cancelled" if signal.aborted else "error"
            error_kind = (
                "cancelled" if signal.aborted else tool_error_kind(
                    run_err, invalid_args=parsed.parse_err is not None,
                )
            )

            log_error(
                "agent: tool failed",
                {
                    "tool": tc.function.name,
                    "duration_ms": duration_ms,
                    "err": err_str,
                },
            )

        elif isinstance(result, ToolOutput):
            status = result.status
            error_kind = result.error_kind
            http_status = result.http_status
            truncated = result.truncated
            if status == "error":
                err_str = (
                    "fetch failed"
                    if tc.function.name in ("web_fetch", "web_search")
                    else (error_kind or "tool failed")
                )
            elif status == "cancelled":
                err_str = "cancelled"

        return ToolCallResult(
            result=result,
            err_str=err_str,
            duration_ms=duration_ms,
            terminal_user_controlled_refusal=isinstance(
                run_err,
                UserControlledRefusal,
            ),
            status=status,
            error_kind=error_kind,
            http_status=http_status,
            truncated=truncated,
        )

    def record_tool_result(
        self,
        tc: ToolCall,
        parsed: ParsedToolCall,
        res: ToolCallResult,
        emit,
        working: list[Message],
    ) -> None:
        emit(
            {
                "type": "tool-result",
                "id": tc.id,
                "name": tc.function.name,
                "result": res.result,
                "err": res.err_str,
                "duration_ms": res.duration_ms,
                "status": res.status,
                "error_kind": res.error_kind,
                "http_status": res.http_status,
                "truncated": res.truncated,
            }
        )

        if not res.err_str:
            self.turn_executed_tool = True

        if (
            tc.function.name == "load_skill"
            and not res.err_str
        ):
            name = (
                parsed.args.get("name", "")
                if isinstance(parsed.args, dict)
                else ""
            )

            if isinstance(name, str) and name:
                self.active_skills.add(name)

                emit(
                    {
                        "type": "skill-active",
                        "name": name,
                    }
                )

        tool_msg = Message(
            role="tool",
            content=res.result,
            tool_call_id=tc.id,
            name=tc.function.name,
            tool_status=res.status,
            tool_error_kind=res.error_kind,
            tool_http_status=res.http_status,
            tool_truncated=res.truncated,
        )

        self.history.append(tool_msg)
        working.append(tool_msg)

    async def chat(
        self,
        req: ChatRequest,
        signal,
        emit,
        stream_buffer: list[str] | None = None,
    ) -> tuple[ChatResponse, bool]:
        if (
            self.streaming_enabled
            and is_streaming(self.client)
        ):
            c: StreamingClient = cast(
                StreamingClient,
                self.client,
            )
            filter = ThinkingStreamFilter()

            def on_delta(delta: str):
                visible = filter.push(delta)
                if visible:
                    if stream_buffer is not None:
                        stream_buffer.append(visible)
                    else:
                        emit({"type": "assistant-delta", "text": visible})
            resp = await c.chat_stream(
                ChatRequest(
                    model=req.model,
                    messages=req.messages,
                    tools=req.tools,
                    stream=True,
                    thinking_enabled=req.thinking_enabled,
                    reasoning_level=req.reasoning_level,
                    requested_reasoning_level=req.requested_reasoning_level,
                ),
                on_delta,
                signal,
            )

            tail = filter.flush()
            if tail:
                if stream_buffer is not None:
                    stream_buffer.append(tail)
                else:
                    emit({"type": "assistant-delta", "text": tail})

            return resp, True

        resp = await self.client.chat(
            req,
            signal,
        )

        return resp, False

    async def compact(
        self,
        signal,
        emit,
    ) -> None:
        safe_emit = make_safe_emit(signal, emit)
        compact_started = time.monotonic()
        previous_request_id = (
            self.request_metrics.records[-1].request_id
            if self.request_metrics.records else None
        )

        self.running = True
        self._reset_llm_call_counts()

        try:
            history_snap = self.get_history()
            elide_persisted_workflow_results(history_snap)

            if len(history_snap) <= 1:
                safe_emit(
                    {
                        "type": "compact",
                        "summary": "nothing to compact",
                    }
                )
                return

            compact_level, compact_thinking = self._compaction_reasoning_settings()
            req = ChatRequest(
                model=self.client.model(),
                messages=[
                    Message(
                        role="system",
                        content=COMPACTION_SYSTEM_PROMPT,
                    ),
                    Message(
                        role="user",
                        content=bounded_history_for_compaction(
                            history_snap[1:]
                        ),
                    ),
                ],
                thinking_enabled=compact_thinking,
                reasoning_level=compact_level,
                requested_reasoning_level=ReasoningLevel.OFF,
            )

            self._count_llm_call("compaction_llm_calls")
            resp = await self._chat_for_compaction(req, signal, "manual")
            summary = strip_thinking_tags(
                resp.message.content
            )

            if not summary:
                safe_emit(
                    {
                        "type": "error",
                        "err": RuntimeError(
                            "compact returned empty summary"
                        ),
                    }
                )
                return

            tokens_before, tokens_after = await self.apply_compaction_summary(
                summary,
                history_snap,
                "manual compact",
            )

            self.consecutive_compact_failures = 0

            safe_emit(
                {
                    "type": "compact",
                    "summary": summary,
                    "tokensBefore": tokens_before,
                    "tokensAfter": tokens_after,
                    "memoryItems": count_memory_items(
                        self.memory
                    ),
                }
            )

        except Exception as err:

            log_error(
                "agent: panic in Compact",
                {
                    "err": err_message(err),
                },
            )

            safe_emit(
                {
                    "type": "error",
                    "err": err,
                }
            )

        finally:
            self.request_metrics.set_latest_compaction_total(
                (time.monotonic() - compact_started) * 1000,
                after_request_id=previous_request_id,
            )
            log_debug(
                "agent: compaction total timing",
                {
                    "kind": "manual",
                    "duration_ms": round((time.monotonic() - compact_started) * 1000, 2),
                },
            )

            self.running = False

            safe_emit(self._done_event(None))

    async def auto_compact(
        self,
        signal,
        emit,
        trigger_tokens: int | None = None,
        history_tokens: int | None = None,
        incoming_tokens: int = 0,
        tools_tokens: int = 0,
    ) -> None:
        compact_started = time.monotonic()
        previous_request_id = (
            self.request_metrics.records[-1].request_id
            if self.request_metrics.records else None
        )
        tokens_before = self.approx_tokens()
        displayed_tokens = trigger_tokens if trigger_tokens is not None else tokens_before
        displayed_history_tokens = (
            history_tokens if history_tokens is not None else tokens_before
        )

        emit(
            {
                "type": "compact",
                "summary": (
                    f"auto-compact triggered "
                    f"(~{displayed_tokens} tokens >= "
                    f"threshold {self.auto_compact_threshold}; "
                    f"history: {displayed_history_tokens} + "
                    f"input: {incoming_tokens} + "
                    f"tools: {tools_tokens})..."
                ),
                "tokensBefore": tokens_before,
            }
        )

        compaction_succeeded = False
        compaction_error: Exception | None = None

        try:
            compaction_succeeded = await self.compact_in_place(signal)

        except Exception as err:

            compaction_error = err
            self.consecutive_compact_failures += 1

            log_error(
                "agent: auto-compact failed",
                {
                    "err": err_message(err),
                    "consecutive": self.consecutive_compact_failures,
                },
            )

            emit(
                {
                    "type": "error",
                    "err": RuntimeError(
                        f"auto-compact failed "
                        f"({self.consecutive_compact_failures}/"
                        f"{MAX_CONSECUTIVE_AUTOCOMPACT_FAILURES}): "
                        f"{err_message(err)}"
                    ),
                }
            )

        if compaction_succeeded:

            self.consecutive_compact_failures = 0

            tokens_after = self.approx_tokens()

            emit(
                {
                    "type": "compact",
                    "summary": (
                        f"auto-compacted: "
                        f"~{tokens_before} -> "
                        f"~{tokens_after} tokens"
                    ),
                    "tokensBefore": tokens_before,
                    "tokensAfter": tokens_after,
                    "memoryItems": count_memory_items(
                        self.memory
                    ),
                }
            )

        elif compaction_error is None:

            emit(
                {
                    "type": "compact",
                    "summary": "auto-compact skipped: nothing to compact",
                    "tokensBefore": tokens_before,
                }
            )

        self.request_metrics.set_latest_compaction_total(
            (time.monotonic() - compact_started) * 1000,
            after_request_id=previous_request_id,
        )
        log_debug(
            "agent: compaction total timing",
            {
                "kind": "auto",
                "duration_ms": round((time.monotonic() - compact_started) * 1000, 2),
            },
        )

    async def _chat_for_compaction(
        self,
        req: ChatRequest,
        signal,
        kind: str,
    ) -> ChatResponse:
        llm_started = time.perf_counter()
        started_at = datetime.now(timezone.utc).isoformat()
        response: ChatResponse | None = None
        status: Literal["success", "error", "cancelled"] = "success"
        try:
            response = await self.client.chat(req, signal)
            return response
        except BaseException as err:
            status = "cancelled" if isinstance(err, asyncio.CancelledError) or getattr(signal, "aborted", False) else "error"
            raise
        finally:
            self._record_request_metrics(req, "compaction", started_at, llm_started, status, response)
            log_debug(
                "agent: compaction LLM timing",
                {
                    "kind": kind,
                    "duration_ms": round((time.perf_counter() - llm_started) * 1000, 2),
                },
            )

    async def compact_in_place(
        self,
        signal,
    ) -> bool:
        history_snap = self.get_history()
        elide_persisted_workflow_results(history_snap)

        if len(history_snap) <= 1:
            return False

        compact_level, compact_thinking = self._compaction_reasoning_settings()
        req = ChatRequest(
            model=self.client.model(),
            messages=[
                Message(
                    role="system",
                    content=COMPACTION_SYSTEM_PROMPT,
                ),
                Message(
                    role="user",
                    content=bounded_history_for_compaction(
                        history_snap[1:]
                    ),
                ),
            ],
            thinking_enabled=compact_thinking,
            reasoning_level=compact_level,
            requested_reasoning_level=ReasoningLevel.OFF,
        )

        self._count_llm_call("compaction_llm_calls")
        resp = await self._chat_for_compaction(req, signal, "auto")

        summary = strip_thinking_tags(
            resp.message.content
        )

        if not summary:
            raise RuntimeError(
                "compact returned empty summary"
            )

        await self.apply_compaction_summary(
            summary,
            history_snap,
            "auto compact",
        )

        return True

    async def apply_compaction_summary(
        self,
        summary: str,
        history_snap: list[Message],
        snapshot_reason: str,
    ) -> tuple[int, int]:
        next_memory = remove_workflow_duplicates(
            merge_memory(self.memory, summary),
            self.workflow,
        )
        parsed = parse_compaction_summary(summary)
        structured = any(
            (
                parsed.objectives,
                parsed.plan,
                parsed.completed,
                parsed.findings,
                parsed.tested,
                parsed.files,
                parsed.commands,
                parsed.credentials,
                parsed.todos,
            )
        )
        next_prompt = self.build_system_prompt_with_memory(next_memory)
        recent = recent_useful_turn(history_snap[1:])
        if structured:
            next_history = [Message(role="system", content=next_prompt), *recent]
        else:
            next_history = [
                Message(role="system", content=next_prompt),
                Message(
                    role="user",
                    content=(
                        "Session context was compacted. Continue from this "
                        f"summary:\n\n{summary}"
                    ),
                ),
                *recent,
            ]

        if len(next_history) == 1:
            next_history.append(
                Message(
                    role="user",
                    content="Session context was compacted. Continue from carried session state.",
                )
            )

        tokens_before = approximate_message_tokens(history_snap)
        tokens_after = approximate_message_tokens(next_history)
        required_savings = max(
            COMPACTION_MIN_SAVINGS_TOKENS,
            int(tokens_before * COMPACTION_MIN_REDUCTION_RATIO),
        )
        if tokens_before - tokens_after < required_savings:
            raise IneffectiveCompactionError(
                "compact result rejected: context would not shrink meaningfully "
                f"(~{tokens_before} -> ~{tokens_after} tokens; "
                f"requires at least {required_savings} tokens saved)"
            )

        self.memory = next_memory
        self.sys_prompt = next_prompt
        self.history = next_history
        await self.learn_intelligence(summary)
        await self.save()
        await self.save_context_snapshot(snapshot_reason)
        return tokens_before, tokens_after

    def build_system_prompt_with_memory(
        self,
        memory: SessionMemory | None,
    ) -> str:
        return build_system_prompt(
            BuildOptions(
                skills=self.skills,
                thinking_enabled=self.thinking,
                target=self.target,
                tooling_profile=self.tooling_profile,
                prompt_profile=self.prompt_profile,
                memory=memory,
                engagement=self.engagement,
                curated_memory=(self.memory_store.index() if self.memory_store else ""),
                workflow=self.workflow,
                engagement_state=self.engagement_state,
            )
        )


def count_memory_items(
    memory: Optional[SessionMemory]
) -> int:
    if memory is None:
        return 0

    return (
        len(memory.objectives)
        + len(memory.plan)
        + len(memory.completed)
        + len(memory.findings)
        + len(memory.tested)
        + len(memory.files)
        + len(memory.commands)
        + len(memory.credentials)
        + len(memory.todos)
    )


def approximate_message_tokens(messages: list[Message]) -> int:
    total = 0
    for message in messages:
        if message.content:
            total += len(message.content) // 4
        if message.reasoning_content:
            total += len(message.reasoning_content) // 4
        for call in message.tool_calls or []:
            total += (len(call.function.name) + len(call.function.arguments)) // 4
    return total


def minimum_compactable_history_tokens(auto_compact_threshold: int) -> int:
    return max(
        COMPACTION_MIN_HISTORY_TOKENS,
        int(auto_compact_threshold * COMPACTION_MIN_HISTORY_RATIO),
    )


def recent_useful_turn(messages: list[Message]) -> list[Message]:
    """Keep the latest raw user request and final answer, not bulky tool payloads."""
    user_index = next(
        (index for index in range(len(messages) - 1, -1, -1) if messages[index].role == "user"),
        None,
    )
    if user_index is None:
        return []

    recent = [compact_recent_message(messages[user_index])]
    final_answer = next(
        (
            message
            for message in reversed(messages[user_index + 1 :])
            if message.role == "assistant" and message.content and not message.tool_calls
        ),
        None,
    )
    if final_answer is not None:
        # A clipped assistant answer cannot safely replay its original
        # provider-private continuation state. The summary already carries
        # the answer; omit this history step rather than send altered content
        # without the state required by DeepSeek or Gemini.
        has_provider_state = (
            final_answer.reasoning_content is not None
            or final_answer.gemini_parts is not None
        )
        if not (has_provider_state and len(final_answer.content) > COMPACTION_RECENT_MESSAGE_CHAR_LIMIT):
            recent.append(compact_recent_message(final_answer))
    return recent


def compact_recent_message(message: Message) -> Message:
    content = message.content or ""
    if len(content) <= COMPACTION_RECENT_MESSAGE_CHAR_LIMIT:
        return replace(message)
    marker_template = "\n[... {omitted} characters summarized during compaction ...]\n"
    retained = COMPACTION_RECENT_MESSAGE_CHAR_LIMIT
    for _ in range(10):
        marker = marker_template.format(omitted=len(content) - retained)
        next_retained = max(0, COMPACTION_RECENT_MESSAGE_CHAR_LIMIT - len(marker))
        if next_retained >= retained:
            break
        retained = next_retained
    marker = marker_template.format(omitted=len(content) - retained)
    head = retained // 2
    tail = retained - head
    bounded = (
        content[:head]
        + marker
        + content[-tail:]
    )
    return replace(
        message, content=bounded, reasoning_content=None, tool_calls=None,
        gemini_parts=None, provider_state_provider=None, provider_state_model=None,
    )


def remove_workflow_duplicates(
    memory: SessionMemory,
    workflow: WorkflowState,
) -> SessionMemory:
    """Do not mirror Candidate-linked facts into prose session memory."""
    candidate_ids = tuple(workflow.candidates)
    if not candidate_ids:
        return memory

    def keep(items: list[str]) -> list[str]:
        return [item for item in items if not any(value in item for value in candidate_ids)]

    return replace(
        memory,
        objectives=keep(memory.objectives),
        plan=keep(memory.plan),
        completed=keep(memory.completed),
        findings=keep(memory.findings),
        tested=keep(memory.tested),
        files=keep(memory.files),
        commands=keep(memory.commands),
        credentials=keep(memory.credentials),
        todos=keep(memory.todos),
    )


def elide_persisted_workflow_results(messages: list[Message]) -> None:
    """Drop successful prior-turn workflow payloads once state is injected."""
    for message in messages:
        if message.role != "tool" or message.name != "workflow":
            continue
        try:
            payload = json.loads(message.content)
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict) and payload.get("ok") is True:
            message.content = WORKFLOW_HISTORY_MARKER


def append_memory_section(
    out: list[str],
    title: str,
    items: list[str]
) -> None:
    if not items:
        return

    out.append("")
    out.append(title)

    for item in items[-8:]:
        out.append(f"- {item}")


def ensure_system_prompt(
    messages: list[Message],
    prompt: str
) -> list[Message]:
    if not messages or messages[0].role != "system":
        return [
            Message(role="system", content=prompt),
            *messages
        ]

    if messages[0].content == prompt:
        return messages

    return [
        Message(role="system", content=prompt),
        *messages[1:]
    ]


def format_history_for_compaction(messages: list[Message]) -> str:
    lines: list[str] = []

    for m in messages:
        if not m.content and (not m.tool_calls or len(m.tool_calls) == 0):
            continue

        if m.name:
            lines.append(f"\n[{m.role}:{m.name}]")
        else:
            lines.append(f"\n[{m.role}]")

        if m.content:
            lines.append(redact(m.content))

        if m.tool_calls:
            for tc in m.tool_calls:
                lines.append(
                    f"tool_call {tc.id} "
                    f"{tc.function.name} "
                    f"{redact(tc.function.arguments)}"
                )

    return "\n".join(lines)


def err_message(err) -> str:
    if isinstance(err, Exception):
        return str(err)
    return str(err)


def reconcile_tool_calls(messages: list[Message]) -> list[Message]:
    out: list[Message] = []

    i = 0

    while i < len(messages):

        message = messages[i]

        if message is None:
            i += 1
            continue

        out.append(message)

        tool_calls = message.tool_calls

        if (
            message.role != "assistant"
            or not tool_calls
        ):
            i += 1
            continue

        answered: set[str] = set()

        j = i + 1

        while j < len(messages):

            next_message = messages[j]

            if (
                next_message is None
                or next_message.role != "tool"
            ):
                break

            if next_message.tool_call_id:
                answered.add(next_message.tool_call_id)

            out.append(next_message)

            j += 1

        for tool_call in tool_calls:

            if (
                tool_call.id
                and tool_call.id not in answered
            ):

                out.append(
                    Message(
                        role="tool",
                        content=(
                            "ERROR: tool call did not complete "
                            "(the turn was interrupted before "
                            "this tool produced a result)."
                        ),
                        tool_call_id=tool_call.id,
                        name=(
                            tool_call.function.name
                            if tool_call.function
                            else None
                        ),
                        tool_status="cancelled",
                        tool_error_kind="cancelled",
                    )
                )

        i = j

    return out


def _to_agent_event(event: Any):
    if not isinstance(event, dict):
        return event

    event = cast(dict[str, Any], event)

    event_type = event.get("type")
    if not isinstance(event_type, str):
        return event

    cls = _EVENT_FACTORIES.get(event_type)
    if cls is None:
        return event

    kwargs: dict[str, Any] = {
        _KEY_ALIASES.get(str(key), str(key)): value
        for key, value in event.items()
        if key != "type"
    }

    return cls(**kwargs)


def make_safe_emit(signal, emit):
    def safe_emit(event):

        event = _to_agent_event(event)

        if (
            signal.aborted
            and event["type"] not in ("done", "error")
        ):
            return

        try:
            emit(event)

        except Exception as err:
            log_error(
                "agent: event listener raised; event dropped",
                {
                    "event": event["type"],
                    "err": err_message(err),
                },
            )

    return safe_emit


def is_abort_like_error(err: object) -> bool:
    if not isinstance(err, Exception):
        return False

    msg = str(err).lower()

    return (
        err.__class__.__name__ == "AbortError"
        or msg == "aborted"
        or "operation was aborted" in msg
    )


class AgentRuntimeError(RuntimeError):
    @property
    def message(self) -> str:
        return str(self)


def bounded_history_for_compaction(
    messages: list[Message],
) -> str:
    full = format_history_for_compaction(messages)

    if len(full) <= COMPACTION_INPUT_CHAR_LIMIT:
        return full

    tail = full[-COMPACTION_INPUT_CHAR_LIMIT:]

    boundary = tail.find("\n[")

    if boundary > 0:
        trimmed = tail[boundary:]
    else:
        trimmed = tail

    return "\n".join(
        [
            (
                "[system]\n"
                "Older conversation text was omitted because "
                f"the compaction input exceeded "
                f"{COMPACTION_INPUT_CHAR_LIMIT} characters. "
                "Preserve continuity from persistent memory "
                "and the newest visible context below."
            ),
            trimmed,
        ]
    )


def merge_memory(
    prev: SessionMemory | None,
    summary: str,
) -> SessionMemory:
    now = datetime.now(timezone.utc).isoformat()

    parsed = parse_compaction_summary(summary)

    base = prev if prev is not None else empty_memory()

    return SessionMemory(
        updated_at=now,
        last_compacted_at=now,
        last_summary=summary,
        compactions=(prev.compactions if prev else 0) + 1,

        objectives=merge_list(
            base.objectives,
            parsed.objectives,
        ),

        plan=merge_list(
            base.plan,
            parsed.plan,
        ),

        completed=merge_list(
            base.completed,
            parsed.completed,
        ),

        findings=merge_list(
            base.findings,
            parsed.findings,
            MAX_MEMORY_LIST,
        ),

        tested=merge_list(
            base.tested,
            parsed.tested,
        ),

        files=merge_list(
            base.files,
            parsed.files,
        ),

        commands=merge_list(
            base.commands,
            parsed.commands,
        ),

        credentials=merge_list(
            base.credentials,
            parsed.credentials,
            MAX_MEMORY_LIST,
        ),

        todos=merge_list(
            base.todos,
            parsed.todos,
        ),
    )


def merge_list(
    prev: Optional[list[str]],
    next_items: list[str],
    cap: int = 24,
) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []

    for item in (prev or []) + next_items:

        clean = " ".join(item.split()).strip()

        if not clean:
            continue

        key = clean.lower()

        if key in seen:
            continue

        seen.add(key)

        if len(clean) > 240:
            clean = clean[:239] + "…"

        out.append(clean)

    if cap is not None:
        return out[-cap:]

    return out


def empty_memory() -> SessionMemory:
    now = datetime.now(timezone.utc).isoformat()

    return SessionMemory(
        version=1,
        updated_at=now,
        compactions=0,

        objectives=[],
        plan=[],
        completed=[],
        findings=[],
        tested=[],
        files=[],
        commands=[],
        credentials=[],
        todos=[],
    )


def parse_compaction_summary(
    summary: str,
) -> SessionMemoryParsed:
    sections = split_markdown_sections(summary)

    files_and_commands = section_items(
        sections,
        [
            "files and commands",
        ],
    )

    return SessionMemoryParsed(
        objectives=section_items(
            sections,
            [
                "current objective",
                "target and scope",
            ],
        ),

        plan=section_items(
            sections,
            [
                "plan",
            ],
        ),

        completed=section_items(
            sections,
            [
                "completed tasks",
            ],
        ),

        findings=section_items(
            sections,
            [
                "findings and evidence",
            ],
        ),

        tested=section_items(
            sections,
            [
                "tested surface",
                "decisions and assumptions",
            ],
        ),

        files=[
            s
            for s in files_and_commands
            if re.search(
                r"(?:^|[\s/])[\w.-]+\.\w+|/|\\",
                s,
            )
        ],

        commands=[
            s
            for s in files_and_commands
            if re.search(
                r"`[^`]+`|\b(?:curl|npm|git|rg|python|node|ffuf|nuclei|sqlmap|httpx)\b",
                s,
            )
        ],

        credentials=section_items(
            sections,
            [
                "credentials and placeholders",
            ],
        ),

        todos=section_items(
            sections,
            [
                "open todos",
                "next best actions",
            ],
        ),
    )


def section_items(
    sections: dict[str, list[str]],
    names: list[str],
) -> list[str]:
    out: list[str] = []

    for name in map(normalize_heading, names):

        for line in sections.get(name, []):

            item = re.sub(
                r"^\s*(?:[-*]|\d+[.)])\s+",
                "",
                line,
            ).strip()

            if not item:
                continue

            if re.match(
                r"^none\b|^n/a$",
                item,
                re.IGNORECASE,
            ):
                continue

            out.append(item)

    return out


def normalize_heading(s: str) -> str:
    return re.sub(
        r"[:#]",
        "",
        s.lower(),
    ).strip()


def split_markdown_sections(text: str) -> dict[str, list[str]]:
    sections = {}
    current = "summary"

    for raw in text.replace("\r\n", "\n").split("\n"):

        heading = re.match(
            r"^#{1,3}\s+(.+?)\s*$",
            raw
        )

        if heading and heading.group(1):
            current = normalize_heading(
                heading.group(1)
            )

            if current not in sections:
                sections[current] = []

            continue

        if current not in sections:
            sections[current] = []

        sections[current].append(raw)

    return sections


def build_turn_learning_text(
    user_msg: str,
    assistant_msg: str,
) -> str:
    return "\n".join(
        [
            "## User request",
            user_msg,
            "",
            "## Task outcome",
            assistant_msg,
        ]
    )


async def map_with_concurrency(
    items: list[T],
    limit: int,
    fn: Callable[[T, int], Awaitable[R]],
) -> list[R]:
    results = cast(
        list[R],
        [None] * len(items)
    )

    next_index = 0
    lock = asyncio.Lock()

    async def worker():
        nonlocal next_index

        while True:
            async with lock:
                index = next_index
                next_index += 1

            if index >= len(items):
                return

            results[index] = await fn(
                items[index],
                index
            )

    workers = [
        asyncio.create_task(worker())
        for _ in range(
            min(limit, len(items))
        )
    ]

    try:
        await asyncio.gather(*workers)
    except BaseException:
        for task in workers:
            if not task.done():
                task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        raise

    return results


def tools_enabled(opts) -> bool:
    if opts is None:
        return True

    if isinstance(opts, dict):
        return opts.get("tools", True)

    return getattr(opts, "tools", True)
