import traceback
import asyncio
import json
import re
import time
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

from src.logger.logger import error as log_error

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

from src.permission.permission import Prompter

from src.session.store import (
    SessionMemory,
    Store,
)

from src.skills.registry import (
    Registry as SkillRegistry,
    materialize_skill_body,
)

from src.target.target import Target

from src.tools.aliases import canonical_tool_name
from src.tools.registry import Registry as ToolRegistry
from src.tools.types import ActionPermissionTool

from .decision_planner import build_decision_plan

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
MAX_PARALLEL_TOOL_CALLS = 4

STATEFUL_TOOLS = {
    "load_skill",
}

MIDTURN_ELISION_PREFIX = (
    "[tool output elided mid-turn to fit context"
)

MIDTURN_ELISION_KEEP_RECENT = 4
MAX_MEMORY_LIST = 200

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
    "they prevent repeat work."
)


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
    ):
        self.result = result
        self.err_str = err_str
        self.duration_ms = duration_ms


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
                )
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
        total = 0

        for message in self.history:

            if message.content:
                total += len(message.content) // 4

            if message.reasoning_content:
                total += len(message.reasoning_content) // 4

            for tc in (getattr(message, "tool_calls", None) or []):

                function = tc.function

                total += (
                    len(function.name)
                    +
                    len(function.arguments)
                ) // 4

        return total

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

            return len(loaded.messages) > 1

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

        if loaded.target is not None:
            self.target.copy_from(loaded.target)

        self.memory = loaded.memory

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
            )
        )

    async def set_target_base_url(self, url: str) -> None:
        self.target.set_base_url(url)
        self.rebuild_system_prompt()
        self.history = ensure_system_prompt(
            self.history,
            self.sys_prompt,
        )
        await self.save()

    async def clear_target(self) -> None:
        self.target.clear()
        self.rebuild_system_prompt()
        self.history = ensure_system_prompt(
            self.history,
            self.sys_prompt,
        )
        await self.save()

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
                (
                    "Use this coverage state to choose next tests. "
                    "Prefer untested endpoint/parameter/vulnerability-class "
                    "combinations. Do not repeat entries already marked "
                    "passed, failed, skipped, waf-blocked, or tried unless "
                    "the objective explicitly asks for retesting."
                ),
            ]
        )

    async def run(
        self,
        user_msg: str,
        signal,
        emit,
        opts: AgentRunOptions | None = None,
    ) -> None:
        safe_emit = make_safe_emit(signal, emit)

        self.running = True

        try:
            await self.run_inner(
                user_msg,
                signal,
                safe_emit,
                opts,
            )

        except Exception as err:
            if signal.aborted or is_abort_like_error(err):

                safe_emit(
                    {
                        "type": "error",
                        "err": AgentRuntimeError("turn cancelled"),
                    }
                )
                return
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

            safe_emit(
                {
                    "type": "done",
                }
            )

    async def run_inner(
        self,
        user_msg: str,
        signal,
        emit,
        opts=None,
    ) -> None:
        if isinstance(opts, dict):
            opts = AgentRunOptions(**opts)

        self.active_skills = set(self.pending_skills)
        self.pending_skills.clear()

        self.turn_executed_tool = False

        self.history = reconcile_tool_calls(
            self.history
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

        if (
            self.auto_compact_threshold > 0
            and self.consecutive_compact_failures
            < MAX_CONSECUTIVE_AUTOCOMPACT_FAILURES
            and trigger_tokens >= self.auto_compact_threshold
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
            )

        if decision and decision.recommended_skill:
            emit(
                {
                    "type": "decision",
                    "summary": (
                        f"decision planner: selected skill: "
                        f"{decision.recommended_skill} · "
                        f"risk: {decision.risk} · "
                        f"{decision.reason}"
                    ),
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

        for step in range(max_steps):

            if signal.aborted:
                raise Exception("aborted")

            if self.auto_compact_threshold > 0:
                self.guard_working_context(
                    working,
                    emit,
                    opts,
                )

            req = ChatRequest(
                model=self.client.model(),
                messages=working,
                thinking_enabled=self.thinking,
            )

            if opts is None or getattr(opts, "tools", True):
                req.tools = self.tools.as_llm_tools()

            resp, streamed = await self.chat(
                req,
                signal,
                emit,
            )
            resp.message.content = strip_thinking_tags(
                resp.message.content
            )

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

                return

            self.history.append(resp.message)

            working.append(resp.message)

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

            if resp.message.content and not streamed:
                emit(
                    {
                        "type": "assistant-text",
                        "text": resp.message.content,
                    }
                )

            if not has_tool_calls:

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

                return

            await self.execute_tool_calls(
                tool_calls,
                signal,
                emit,
                working,
            )

        emit(
            {
                "type": "error",
                "err": MaxStepsError(max_steps),
            }
        )

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

            total = tools_tokens

            for msg in working:

                total += len(msg.content) // 4

                if msg.reasoning_content:
                    total += len(msg.reasoning_content) // 4

                if msg.tool_calls:

                    for tc in msg.tool_calls:

                        total += (
                            len(tc.function.name)
                            + len(tc.function.arguments)
                        ) // 4

            return total

        if size() < self.auto_compact_threshold:
            return

        tool_indexes: list[int] = []

        for i, msg in enumerate(working):

            if msg.role == "tool":
                tool_indexes.append(i)

        elidable = tool_indexes[
            : max(
                0,
                len(tool_indexes)
                - MIDTURN_ELISION_KEEP_RECENT,
            )
        ]

        dropped = 0

        for i in elidable:

            if size() < self.auto_compact_threshold:
                break

            msg = working[i]

            if msg.content.startswith(
                MIDTURN_ELISION_PREFIX
            ):
                continue

            bytes_dropped = len(msg.content)

            working[i] = Message(
                role=msg.role,
                content=(
                    f"{MIDTURN_ELISION_PREFIX}"
                    f" — {bytes_dropped} bytes dropped]"
                ),
                tool_calls=msg.tool_calls,
                tool_call_id=msg.tool_call_id,
                name=msg.name,
            )

            dropped += bytes_dropped

        if dropped > 0:

            emit(
                {
                    "type": "decision",
                    "summary": (
                        "context guard: "
                        f"elided {dropped} bytes "
                        "of older tool output "
                        "mid-turn to fit the context window"
                    ),
                }
            )

    async def execute_tool_calls(
        self,
        tool_calls: list[ToolCall],
        signal,
        emit,
        working: list[Message],
    ) -> None:
        sequential = (
            len(tool_calls) <= 1
            or any(
                tc.function.name in STATEFUL_TOOLS
                for tc in tool_calls
            )
        )

        if sequential:

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

            return

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

        if run_err is not None:

            err_str = str(run_err)

            result = f"ERROR: {err_str}"

            log_error(
                "agent: tool failed",
                {
                    "tool": tc.function.name,
                    "duration_ms": duration_ms,
                    "err": err_str,
                },
            )

        return ToolCallResult(
            result=result,
            err_str=err_str,
            duration_ms=duration_ms,
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
        )

        self.history.append(tool_msg)
        working.append(tool_msg)

    async def chat(
        self,
        req: ChatRequest,
        signal,
        emit,
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
                    emit(
                        {
                            "type": "assistant-delta",
                            "text": visible,
                        }
                    )
            resp = await c.chat_stream(
                ChatRequest(
                    model=req.model,
                    messages=req.messages,
                    tools=req.tools,
                    stream=True,
                    thinking_enabled=req.thinking_enabled,
                ),
                on_delta,
                signal,
            )

            tail = filter.flush()
            if tail:
                emit(
                    {
                        "type": "assistant-delta",
                        "text": tail,
                    }
                )

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

        self.running = True

        try:
            history_snap = self.history.copy()

            if len(history_snap) <= 1:
                safe_emit(
                    {
                        "type": "compact",
                        "summary": "nothing to compact",
                    }
                )
                return

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
            )

            resp = await self.client.chat(req, signal)
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

            self.memory = merge_memory(
                self.memory,
                summary,
            )

            self.rebuild_system_prompt()

            self.consecutive_compact_failures = 0

            await self.learn_intelligence(summary)

            self.history = [
                Message(
                    role="system",
                    content=self.sys_prompt,
                ),
                Message(
                    role="user",
                    content=(
                        "Session context was compacted. "
                        "Continue from this summary:\n\n"
                        f"{summary}"
                    ),
                ),
            ]

            try:
                await self.save()

            except Exception as err:
                safe_emit(
                    {
                        "type": "error",
                        "err": RuntimeError(
                            f"save compacted session: "
                            f"{err_message(err)}"
                        ),
                    }
                )

            try:
                await self.save_context_snapshot(
                    "manual compact"
                )

            except Exception as err:
                safe_emit(
                    {
                        "type": "error",
                        "err": RuntimeError(
                            f"save context snapshot: "
                            f"{err_message(err)}"
                        ),
                    }
                )

            safe_emit(
                {
                    "type": "compact",
                    "summary": summary,
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

            self.running = False

            safe_emit(
                {
                    "type": "done",
                }
            )

    async def auto_compact(
        self,
        signal,
        emit,
        trigger_tokens: int | None = None,
        history_tokens: int | None = None,
        incoming_tokens: int = 0,
        tools_tokens: int = 0,
    ) -> None:
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

    async def compact_in_place(
        self,
        signal,
    ) -> bool:
        history_snap = self.history.copy()

        if len(history_snap) <= 1:
            return False

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
        )

        resp = await self.client.chat(
            req,
            signal,
        )

        summary = strip_thinking_tags(
            resp.message.content
        )

        if not summary:
            raise RuntimeError(
                "compact returned empty summary"
            )

        self.memory = merge_memory(
            self.memory,
            summary,
        )

        self.rebuild_system_prompt()

        await self.learn_intelligence(
            summary
        )

        self.history = [
            Message(
                role="system",
                content=self.sys_prompt,
            ),
            Message(
                role="user",
                content=(
                    "Session context was compacted. "
                    "Continue from this summary:\n\n"
                    f"{summary}"
                ),
            ),
        ]

        await self.save()

        await self.save_context_snapshot(
            "auto compact"
        )

        return True


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
            "## User preferences and working style",
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
        worker()
        for _ in range(
            min(limit, len(items))
        )
    ]

    await asyncio.gather(*workers)

    return results


def tools_enabled(opts) -> bool:
    if opts is None:
        return True

    if isinstance(opts, dict):
        return opts.get("tools", True)

    return getattr(opts, "tools", True)
