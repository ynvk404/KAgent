# ==========================================================
# Imports
# ==========================================================
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
#from src.config.config import ToolingProfile

from .mentions import expand_file_mentions

from ..redact.redact import redact

from ..llm.client import (
    Client,
    StreamingClient,
    is_streaming,
)

from ..llm.types import (
    ChatRequest,
    ChatResponse,
    Message,
    ToolCall,
    parsed_args,
)

from ..logger.logger import error as log_error

from ..intelligence.store import (
    IntelligenceStore,
    format_intelligence_context,
)

from ..memory.store import (
    AddMemoryInput,
    MemoryFact,
    MemoryStore,
    format_memory_recall,
)

from ..permission.permission import Prompter

from ..session.store import (
    SessionMemory,
    Store,
)

from ..skills.registry import (
    Registry as SkillRegistry,
    materialize_skill_body,
)

from ..target.target import Target

from ..tools.aliases import canonical_tool_name
from ..tools.registry import Registry as ToolRegistry

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

# ==========================================================
# Type Aliases
# ==========================================================

T = TypeVar("T")
R = TypeVar("R")

EventSink = Callable[[AgentEvent], None]


# ==========================================================
# Constants
# ==========================================================

DEFAULT_MAX_STEPS = 20


# Map "type" -> event dataclass tương ứng.
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

# Một số emit() dùng key kiểu TypeScript (camelCase) cho các field
# chỉ có @property read-only trên dataclass -> cần đổi tên khi khởi tạo.
_KEY_ALIASES = {
    "argsJSON": "args_json",
    "tokensBefore": "tokens_before",
    "tokensAfter": "tokens_after",
    "memoryItems": "memory_items",
    "durationMs": "duration_ms",
}

# Số lần auto-compaction lỗi liên tiếp tối đa.
MAX_CONSECUTIVE_AUTOCOMPACT_FAILURES = 3

# Số ký tự tối đa đưa vào compact context.
COMPACTION_INPUT_CHAR_LIMIT = 22_000

# Số tool tối đa chạy song song trong một bước.
MAX_PARALLEL_TOOL_CALLS = 4

# Tool làm thay đổi trạng thái agent.
STATEFUL_TOOLS = {
    "load_skill",
}

# Marker đánh dấu tool output đã bị cắt.
MIDTURN_ELISION_PREFIX = (
    "[tool output elided mid-turn to fit context"
)

# Số tool result mới nhất được giữ lại.
MIDTURN_ELISION_KEEP_RECENT = 4

# Giới hạn số item trong memory list
MAX_MEMORY_LIST = 200

# Prompt dùng khi compact context
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


# ==========================================================
# Data Models
# ==========================================================


# ==========================================================
# Data Models
# ==========================================================

# Lưu thông tin memory đã được parse của một session.
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


# Lưu thông tin một tool call được sinh ra từ LLM.
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


# Lưu kết quả sau khi Agent thực thi một tool.
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

# Lưu kết quả kiểm tra quyền sử dụng tool.
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

# ==========================================================
# Agent Options
# ==========================================================

class AgentRunOptions:
    """
    Option khi chạy một lượt Agent.
    """

    def __init__(
        self,
        tools: bool = True,
    ):
        self.tools = tools


class AgentOptions:
    """
    Cấu hình khởi tạo Agent.
    """

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


# ==========================================================
# Agent
# ==========================================================

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

        # Session memory
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

        # Runtime state
        self.running = False

        # Skill state
        self.active_skills: set[str] = set()
        self.pending_skills: set[str] = set()

        # Tool token cache
        self.tools_tokens_cache = 0
        self.tools_tokens_key = -1

        # Đánh dấu turn hiện tại có chạy tool hay chưa
        self.turn_executed_tool = False

        # Build system prompt
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
                    format_memory_recall(
                        self.memory_store.list()
                    )
                    if self.memory_store
                    else ""
                ),
            )
        )

        self.history = [
            Message(
                role="system",
                content=self.sys_prompt,
            )
        ]

    # ==========================================================
    # Accessors & Configuration
    # ==========================================================

    def get_history(self) -> list[Message]:
            """
            Lấy lịch sử hội thoại.
            Trả về bản copy để tránh sửa trực tiếp history gốc.
            """
            return [replace(m) for m in self.history]


    def get_max_steps(self) -> int:
        """
        Lấy số bước tối đa Agent được chạy.
        """
        return self.max_steps


    def set_max_steps(self, n: int) -> None:
        """
        Cập nhật số bước tối đa.
        Chỉ nhận giá trị >= 1.
        """
        if n >= 1:
            self.max_steps = n


    def get_auto_compact_threshold(self) -> int:
        """
        Lấy ngưỡng tự động compact memory.
        """
        return self.auto_compact_threshold


    def set_auto_compact_threshold(self, n: int) -> None:
        """
        Thiết lập ngưỡng tự động compact (đơn vị: approx tokens).
        Giá trị 0 sẽ tắt tính năng auto-compact.
        """
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
        """
        Trả về True nếu Agent đang thực thi run() hoặc compact().
        """
        return self.running


    def thinking_is_enabled(self) -> bool:
        """
        Kiểm tra chế độ Thinking có đang được bật hay không.
        """
        return self.thinking


    async def set_thinking_enabled(self, enabled: bool) -> None:
        """
        Bật/Tắt chế độ Thinking của Agent.
        """

        # Cập nhật trạng thái Thinking
        self.thinking = enabled

        # Tạo lại System Prompt để phản ánh cấu hình mới
        self.rebuild_system_prompt()

        # Lưu session
        await self.save()


    def set_client(self, client: Client) -> None:
        """
        Thay đổi LLM Client (provider/model) đang sử dụng.

        Không cho phép đổi khi Agent đang thực thi một lượt (turn),
        tránh việc cùng một phiên làm việc sử dụng hai client khác nhau.
        """
        if self.running:
            raise RuntimeError(
                "cannot switch model/provider while a turn is in flight "
                "- cancel first with Esc"
            )

        self.client = client


    def set_prompt_profile(self, profile: PromptProfile) -> None:
        """
        Thiết lập Prompt Profile mới.
        Nếu profile không thay đổi thì bỏ qua.
        """

        if self.prompt_profile == profile:
            return

        self.prompt_profile = profile

        # Xây dựng lại System Prompt
        self.rebuild_system_prompt()

        # Đảm bảo history luôn chứa System Prompt mới
        self.history = ensure_system_prompt(
            self.history,
            self.sys_prompt,
        )


    # ==========================================================
    # Session Memory Management
    # ==========================================================

    # Format session memory thành text hiển thị
    def format_memory(
        self,
    ) -> str:

        # Memory rỗng
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

        # Thông tin compact
        out.append(
            f"Session memory · "
            f"{m.compactions} compaction"
            f"{'' if m.compactions == 1 else 's'}"
        )

        if m.last_compacted_at:
            out.append(
                f"Last compacted: {m.last_compacted_at}"
            )

        # Các nhóm dữ liệu memory
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
        """
        Xóa session memory do Agent tạo.
        Không ảnh hưởng engagement memory.
        """

        # Không có memory thì bỏ qua
        if (
            self.memory is None
            or count_memory_items(self.memory) == 0
        ):
            return

        # Xóa session memory
        self.memory = None

        # Tạo lại system prompt sau khi mất memory
        self.rebuild_system_prompt()

        # Đảm bảo system prompt mới được cập nhật vào history
        self.history = ensure_system_prompt(
            self.history,
            self.sys_prompt,
        )

        # Lưu session
        await self.save()


    async def forget_memory(
        self,
        query: str,
    ) -> list[str]:
        """
        Xóa memory chứa từ khóa.
        Bao gồm long memory và session memory.
        """

        needle = query.strip().lower()

        if not needle:
            return []

        removed: list[str] = []

        # Xóa long-term memory
        if self.memory_store:
            removed.extend(
                self.memory_store.forget(query)
            )

        # Xóa session memory
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

        # Không có memory bị xóa
        if not removed:
            return []

        # Cập nhật lại prompt
        self.rebuild_system_prompt()

        self.history = ensure_system_prompt(
            self.history,
            self.sys_prompt,
        )

        # Lưu session
        await self.save()

        return removed


    async def add_memory(
        self,
        input: AddMemoryInput,
    ) -> MemoryFact | None:
        """
        Thêm một Memory Fact vào Curated Memory.
        Sau khi thêm sẽ rebuild System Prompt,
        cập nhật history rồi lưu session.
        """

        if self.memory_store is None:
            return None

        if isinstance(input, dict):
            input = AddMemoryInput(**input)

        fact = self.memory_store.add(input)

        if fact is None:
            return None

        # Rebuild System Prompt
        self.rebuild_system_prompt()

        # Cập nhật message system đầu tiên trong history
        self.history = ensure_system_prompt(
            self.history,
            self.sys_prompt,
        )

        # Lưu session
        await self.save()

        return fact

    def list_curated_memory(self) -> list[MemoryFact]:
        """
        Liệt kê toàn bộ Curated Memory.
        """
        if self.memory_store is None:
            return []

        return self.memory_store.list()

    def recall_curated_memory(
        self,
        user_msg: str,
        emit,
    ) -> str:
        """
        Truy xuất các Curated Memory liên quan đến yêu cầu hiện tại.
        """

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


    # ==========================================================
    # Intelligence Management
    # ==========================================================

    async def clear_intelligence(
        self,
        scope: str = "all",
    ) -> None:
        if self.intelligence:
            await self.intelligence.clear(scope)


    # Lấy thống kê intelligence
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
        """
        Truy xuất tri thức (Intelligence) liên quan đến yêu cầu hiện tại.
        """

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
        """
        Học tri thức mới từ kết quả của phiên pentest hiện tại.
        """

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


    # ==========================================================
    # Skill Management
    # ==========================================================

    async def set_skill_enabled(self, name: str, enabled: bool) -> bool:
        """
        Bật/Tắt một skill trong Skill Registry.
        Trả về True nếu trạng thái thay đổi.
        """

        # Skill không tồn tại
        if not self.skills.has(name):
            return False

        # set_disabled(disabled=True/False)
        changed = self.skills.set_disabled(name, not enabled)

        if not changed:
            return False

        if not enabled:
            self.active_skills.discard(name)
            self.pending_skills.discard(name)

        # Cập nhật System Prompt
        self.rebuild_system_prompt()

        self.history = ensure_system_prompt(
            self.history,
            self.sys_prompt,
        )

        # Lưu session
        await self.save()

        return True


    def rebuild_from_skills(self) -> None:
        """
        Xây dựng lại System Prompt từ Skill Registry hiện tại.
        Được gọi khi skill được reload hoặc thay đổi.
        """

        self.rebuild_system_prompt()

        self.history = ensure_system_prompt(
            self.history,
            self.sys_prompt,
        )


    async def inject_skill(self, name: str) -> str:
        """
        Nạp trực tiếp một skill vào history dưới dạng System Message.
        Skill sẽ được áp dụng cho yêu cầu kế tiếp.
        """

        # Không cho phép nạp skill khi agent đang chạy
        if self.running:
            raise RuntimeError(
                "cannot load a skill while a turn is in flight "
                "- cancel first with Esc"
            )

        # Lấy skill
        skill = self.skills.get(name)

        if skill is None:
            raise RuntimeError(f'unknown skill "{name}"')

        # Skill bị disable
        if self.skills.is_disabled(name):
            raise RuntimeError(
                f'skill "{name}" is disabled '
                "- enable it from /skills first"
            )

        # Sinh nội dung skill
        body = materialize_skill_body(skill)

        # Chèn vào history như một System Message
        self.history.append(
            Message(
                role="system",
                content=(
                    f"The user invoked /{name}. "
                    f"Apply this skill to the next request:\n\n{body}"
                ),
            )
        )

        # Đánh dấu skill đang được kích hoạt
        self.pending_skills.add(name)

        # Lưu session
        await self.save()

        return name

    def is_tool_allowed(
        self,
        tool_name: str,
    ) -> ToolAllowedResult:
        """
        Kiểm tra tool có được phép sử dụng dựa trên skill đang active.

        Rule:
        1. Không có active skill -> không giới hạn.
        2. Tool không yêu cầu permission -> luôn cho phép.
        3. Skill không khai báo allowed-tools -> cho phép tất cả.
        4. Tool nằm trong allowed-tools của skill -> cho phép.
        5. Ngược lại -> block.
        """

        # Không có skill đang active
        if len(self.active_skills) == 0:
            return ToolAllowedResult(
                ok=True,
            )

        # Lấy tool
        tool = self.tools.get(tool_name)

        # Tool không tồn tại
        # để tầng execute xử lý lỗi rõ hơn
        if tool is None:
            return ToolAllowedResult(
                ok=True,
            )

        # Tool dạng workflow primitive
        if not tool.requires_permission():
            return ToolAllowedResult(
                ok=True,
            )

        # Lấy danh sách skill đang active
        active_skills = []

        for name in self.active_skills:
            skill = self.skills.get(name)

            if skill is not None:
                active_skills.append(skill)

        # Không có skill hợp lệ
        if len(active_skills) == 0:
            return ToolAllowedResult(
                ok=True,
            )

        # Skill không khai báo allowed-tools
        # nghĩa là inherit tất cả tool
        for skill in active_skills:
            if len(skill.tools) == 0:
                return ToolAllowedResult(
                    ok=True,
                )

        # Chuẩn hóa tên tool
        wanted = canonical_tool_name(tool_name)

        # Kiểm tra tool có nằm trong allowed-tools không
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

        # Tạo message lỗi
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

    # ==========================================================
    # Token & Context Estimation
    # ==========================================================

    def approx_tokens(self) -> int:
        """
        Ước lượng số token trong history.

        Quy ước:
        ~4 ký tự = 1 token
        """

        total = 0

        for message in self.history:

            # Nội dung message
            if message.content:
                total += len(message.content) // 4


            # Tool calls
            for tc in (getattr(message, "tool_calls", None) or []):

                function = tc.function

                total += (
                    len(function.name)
                    +
                    len(function.arguments)
                ) // 4


        return total


    def tools_token_estimate(self) -> int:
        """
        Ước lượng số token của JSON Schema các tool được gửi kèm
        trong mỗi request tới LLM.

        Kết quả được cache và chỉ tính lại khi số lượng tool thay đổi.
        """

        # Số lượng tool hiện tại
        count = len(self.tools.names())

        # Nếu số tool thay đổi thì tính lại
        if count != self.tools_tokens_key:

            # Chuyển toàn bộ Tool Schema thành JSON
            tools_json = json.dumps(
                self.tools.as_llm_tools(),
                ensure_ascii=False,
            )

            # Ước lượng token (~4 ký tự ≈ 1 token)
            self.tools_tokens_cache = len(tools_json) // 4

            # Cập nhật cache key
            self.tools_tokens_key = count

        return self.tools_tokens_cache


    # ==========================================================
    # Session Lifecycle
    # ==========================================================

    async def reset(self) -> None:
        """
        Khởi tạo lại session về trạng thái ban đầu.
        Xóa history, memory, skill đang active và dữ liệu session.
        """

        # Chỉ giữ lại System Prompt
        self.history = [
            Message(
                role="system",
                content=self.sys_prompt,
            )
        ]

        # Xóa bộ nhớ dài hạn
        self.memory = None

        # Xóa các skill đang active
        self.active_skills.clear()
        self.pending_skills.clear()

        # Reset bộ đếm lỗi auto compact
        self.consecutive_compact_failures = 0

        # Xóa session trong Store
        if self.store is not None:
            await self.store.clear()


    def has_saved_session(self) -> bool:

        if self.store is None:
            return False

        try:
            loaded = self.store.load()

            return len(loaded.messages) > 1

        except Exception:
            return False

    def resume_saved(self) -> None:
        """
        Khôi phục session đã lưu.
        """

        if self.store is None:
            return

        loaded = self.store.load()

        # Khôi phục target
        if loaded.target is not None:
            self.target.copy_from(loaded.target)

        # Khôi phục memory
        self.memory = loaded.memory

        # Xây dựng lại System Prompt
        self.rebuild_system_prompt()

        # Không có history
        if len(loaded.messages) == 0:

            self.history = [
                Message(
                    role="system",
                    content=self.sys_prompt,
                )
            ]
            return

        # Sửa các Tool Call còn dang dở
        self.history = reconcile_tool_calls(
            ensure_system_prompt(
                loaded.messages,
                self.sys_prompt,
            )
        )


    async def save(
        self,
    ) -> None:
        """
        Lưu session hiện tại xuống Session Store.
        """

        if self.store is None:
            return

        await self.store.save(
            self.history,
            self.target,
            self.memory,
        )


    async def save_context_snapshot(self, reason: str = "periodic") -> str:
        """
        Lưu snapshot của toàn bộ session vào Store.
        Trả về đường dẫn hoặc ID của file snapshot.
        """

        # Nếu chưa cấu hình Store thì không làm gì
        if self.store is None:
            return ""

        out = []

        # Tiêu đề
        out.append("# Pentestagent Session Context")
        out.append("")

        # Thông tin phiên làm việc
        out.append(f"Updated: {datetime.now(timezone.utc).isoformat()}")
        out.append(f"Reason: {reason}")
        out.append(f"Provider: {self.client.name()}")
        out.append(f"Model: {self.client.model()}")
        out.append(
            f"Target: {self.target.base_url() or self.target.name() or '(none)'}"
        )
        out.append(f"Approx tokens: {self.approx_tokens()}")

        out.append("")

        # Bộ nhớ dài hạn
        out.append("## Persistent Memory")
        out.append("")
        out.append(self.format_memory())

        out.append("")

        # Lịch sử hội thoại (đã rút gọn)
        out.append("## Redacted Conversation Context")
        out.append("")
        out.append(
            format_history_for_compaction(self.history[1:])
        )

        # Ghép thành chuỗi Markdown
        content = "\n".join(out)

        # Lưu xuống Store
        return await self.store.save_context_snapshot(content)


    def rebuild_system_prompt(
        self,
    ) -> None:
        """
        Xây dựng lại System Prompt dựa trên trạng thái hiện tại của Agent.
        """

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


    # ==========================================================
    # Target Management
    # ==========================================================

    async def set_target_base_url(self, url: str) -> None:
        """
        Thiết lập URL mục tiêu.
        """

        self.target.set_base_url(url)

        self.rebuild_system_prompt()

        self.history = ensure_system_prompt(
            self.history,
            self.sys_prompt,
        )

        await self.save()


    async def clear_target(self) -> None:
        """
        Xóa Target hiện tại.
        """

        self.target.clear()

        self.rebuild_system_prompt()

        self.history = ensure_system_prompt(
            self.history,
            self.sys_prompt,
        )

        await self.save()


    # ==========================================================
    # Context Builders
    # ==========================================================

    async def coverage_context(self, signal) -> str:
        """
        Tạo context về trạng thái coverage hiện tại để cung cấp cho LLM.
        """

        # Kiểm tra Coverage Tool có tồn tại không
        if self.tools.get("coverage") is None:
            return "Coverage tool is not available in this session."

        # Lấy thông tin tổng quan (summary)
        try:
            summary = await self.tools.execute(
                "coverage",
                {"action": "summary"},
                signal,
                self.prompter,
            )
        except Exception as err:
            summary = f"error: {err_message(err)}"

        # Lấy danh sách coverage
        try:
            entries = await self.tools.execute(
                "coverage",
                {"action": "list"},
                signal,
                self.prompter,
            )
        except Exception as err:
            entries = f"error: {err_message(err)}"

        # Ghép thành chuỗi context gửi cho LLM
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


    # ==========================================================
    # Agent Execution (Run Loop)
    # ==========================================================

    # Run Loop
    async def run(
        self,
        user_msg: str,
        signal,
        emit,
        opts: AgentRunOptions | None = None,
    ) -> None:
        """
        Hàm bao ngoài điều khiển toàn bộ một lượt chạy (turn) của Agent.
        """

        # Tạo hàm emit an toàn (không phát event nếu đã bị hủy)
        safe_emit = make_safe_emit(signal, emit)

        # Đánh dấu agent đang chạy
        self.running = True

        try:
            # Thực thi vòng lặp chính của Agent
            await self.run_inner(
                user_msg,
                signal,
                safe_emit,
                opts,
            )

        except Exception as err:
            # Người dùng hủy (Ctrl+C / Esc)
            if signal.aborted or is_abort_like_error(err):

                safe_emit(
                    {
                        "type": "error",
                        "err": AgentRuntimeError("turn cancelled"),
                    }
                )
                return
            traceback.print_exc()

            # Các lỗi khác
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

            # Đánh dấu đã kết thúc
            self.running = False

            # Thông báo hoàn thành
            safe_emit(
                {
                    "type": "done",
                }
            )


    # Main Agent Loop
    async def run_inner(
        self,
        user_msg: str,
        signal,
        emit,
        opts=None,
    ) -> None:
        """
        Vòng xử lý chính của Agent cho một lượt tương tác.
        """
        # Hỗ trợ caller truyền dict thay vì AgentRunOptions
        if isinstance(opts, dict):
            opts = AgentRunOptions(**opts)

        # Kích hoạt các skill đang chờ
        self.active_skills = set(self.pending_skills)
        self.pending_skills.clear()

        # Đánh dấu chưa thực thi tool trong turn này
        self.turn_executed_tool = False

        # Sửa các tool call còn dang dở từ turn trước
        self.history = reconcile_tool_calls(
            self.history
        )

        # Mở rộng các @file thành nội dung thực tế
        expanded_user_msg = expand_file_mentions(
            user_msg
        )

        # Ước lượng số token của input mới
        incoming_tokens = len(expanded_user_msg) // 4

        # Token của Tool Schema
        if opts is not None and getattr(opts, "tools", True) is False:
            tools_tokens = 0
        else:
            tools_tokens = self.tools_token_estimate()

        history_tokens = self.approx_tokens()
        trigger_tokens = history_tokens + incoming_tokens + tools_tokens

        # Kiểm tra có cần Auto Compact không
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


       # Decision Planning
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

        # Conversation History
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

        # Context Injection

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

        # Agent Reasoning Loop

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

            # Build Chat Request
            req = ChatRequest(
                model=self.client.model(),
                messages=working,
            )

            if opts is None or getattr(opts, "tools", True):
                req.tools = self.tools.as_llm_tools()

            # LLM Response
            print("RUN_INNER BEFORE CHAT")
            resp, streamed = await self.chat(
                req,
                signal,
                emit,
            )
            print("RUN_INNER AFTER CHAT")
            resp.message.content = strip_thinking_tags(
                resp.message.content
            )

            tool_calls = resp.message.tool_calls or []

            has_tool_calls = len(tool_calls) > 0

            # Plan-only Mode
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

            # Store Assistant Message

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

            # Assistant Output

            if resp.message.content and not streamed:
                emit(
                    {
                        "type": "assistant-text",
                        "text": resp.message.content,
                    }
                )

            # Finish Turn

            if not has_tool_calls:

                if self.turn_executed_tool:
                    asyncio.create_task(
                        self.learn_intelligence(
                            build_turn_learning_text(
                                user_msg,
                                resp.message.content,
                            )
                        )
                    )

                return

            # Tool Execution

            await self.execute_tool_calls(
                tool_calls,
                signal,
                emit,
                working,
            )

        # Max Steps Error

        emit(
            {
                "type": "error",
                "err": MaxStepsError(max_steps),
            }
        )


    # Context Guard
    def guard_working_context(
        self,
        working: list[Message],
        emit,
        opts=None,
    ) -> None:
        """
        Mid-turn context guard.

        Nếu working context quá lớn thì chỉ lược bỏ (elide)
        các Tool Output cũ trong working copy để tránh vượt
        context window.

        Không làm thay đổi self.history.
        """

        # Tool Schema Tokens
        if opts is not None and getattr(opts, "tools", True) is False:
            tools_tokens = 0
        else:
            tools_tokens = self.tools_token_estimate()

        # Context Size Estimation

        def size() -> int:

            total = tools_tokens

            for msg in working:

                total += len(msg.content) // 4

                if msg.tool_calls:

                    for tc in msg.tool_calls:

                        total += (
                            len(tc.function.name)
                            + len(tc.function.arguments)
                        ) // 4

            return total

        if size() < self.auto_compact_threshold:
            return

        # Tool Output Elision

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

            # Replace Tool Output
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

        # Emit Context Event

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


    # Tool Execution
    async def execute_tool_calls(
        self,
        tool_calls: list[ToolCall],
        signal,
        emit,
        working: list[Message],
    ) -> None:
        """
        Thực thi các Tool Call của một bước.

        - Nếu chỉ có một tool hoặc có tool thay đổi trạng thái
          (ví dụ load_skill) thì chạy tuần tự.

        - Nếu các tool độc lập thì chạy song song với số lượng
          giới hạn để tăng tốc.
        """

        sequential = (
            len(tool_calls) <= 1
            or any(
                tc.function.name in STATEFUL_TOOLS
                for tc in tool_calls
            )
        )

        # Sequential Execution

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
                print(">>> BEFORE run_parsed_tool_call")
                result = await self.run_parsed_tool_call(
                    tc,
                    parsed,
                    signal,
                )
                print(">>> AFTER run_parsed_tool_call")
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

        # Parallel Execution

        parsed_all = [
            self.parse_tool_call(tc)
            for tc in tool_calls
        ]

        # Emit Tool Calls

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


    # Tool Running
    def parse_tool_call(
        self,
        tc: ToolCall,
    ) -> ParsedToolCall:
        """
        Parse JSON arguments của Tool Call.

        Nếu parse lỗi thì không raise exception ngay,
        mà lưu lỗi lại để Agent trả về cho LLM tự sửa.
        """

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
        """
        Thực thi một tool call đã được parse.
        Không raise exception, mọi lỗi sẽ được trả về dưới dạng ToolCallResult
        để Agent tiếp tục xử lý các tool khác.
        """

        if signal.aborted:
            return ToolCallResult(
                result="ERROR: aborted",
                err_str="aborted",
                duration_ms=0,
            )

        start = time.monotonic()

        result = ""
        run_err: Exception | None = None

        # JSON arguments parse lỗi
        if parsed.parse_err is not None:
            run_err = Exception(
                f"could not parse arguments: "
                f"{parsed.parse_err} "
                f"(raw: {parsed.args_json})"
            )

        else:

            # Kiểm tra tool có được phép chạy không
            allowed = self.is_tool_allowed(
                tc.function.name
            )

            if not allowed.ok:
                run_err = Exception(
                    allowed.reason
                    or "tool blocked by active skills"
                )

            else:
                try:
                    print(">>> BEFORE execute")
                    result = await self.tools.execute(
                        tc.function.name,
                        parsed.args,
                        signal,
                        self.prompter,
                    )
                    print(">>> AFTER execute")
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


    # Tool Result Handling
    def record_tool_result(
        self,
        tc: ToolCall,
        parsed: ParsedToolCall,
        res: ToolCallResult,
        emit,
        working: list[Message],
    ) -> None:
        """
        Gửi kết quả tool, kích hoạt skill nếu cần,
        và thêm tool message vào history + working.
        """

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

        # Đánh dấu turn này đã thực thi tool thành công
        if not res.err_str:
            self.turn_executed_tool = True

        # Nếu load_skill thành công thì kích hoạt skill
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
        """
        Gửi request tới LLM.

        Returns:
            (response, streamed)
        """

        # Streaming
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
            print("CHAT_STREAM RETURNED")
            resp = await c.chat_stream(
                ChatRequest(
                    model=req.model,
                    messages=req.messages,
                    tools=req.tools,
                    stream=True,
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

        # Non-streaming
        resp = await self.client.chat(
            req,
            signal,
        )

        return resp, False


    # ==========================================================
    # Context Compaction
    # ==========================================================

    # Compact Context
    async def compact(
        self,
        signal,
        emit,
    ) -> None:
        """
        Nén (compact) lịch sử hội thoại thành một bản tóm tắt
        để giảm số token sử dụng.
        """

        safe_emit = make_safe_emit(signal, emit)

        self.running = True

        try:
            # Snapshot history
            history_snap = self.history.copy()

            if len(history_snap) <= 1:
                safe_emit(
                    {
                        "type": "compact",
                        "summary": "nothing to compact",
                    }
                )
                return

            # Tạo ChatRequest
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

            # Gọi LLM
            resp = await self.client.chat(req, signal)
            print("CHAT RETURNED")
            # Lấy summary
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

            # Merge Memory
            self.memory = merge_memory(
                self.memory,
                summary,
            )

            # Rebuild System Prompt
            self.rebuild_system_prompt()

            # Reset bộ đếm compact lỗi
            self.consecutive_compact_failures = 0

            # Học từ summary
            await self.learn_intelligence(summary)

            # Reset History
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

            # Lưu Session
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

            # Lưu Snapshot
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

            # Thông báo compact thành công
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
        """
        Tự động compact lịch sử hội thoại khi vượt ngưỡng token.
        """

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

        try:
            await self.compact_in_place(signal)
            compaction_succeeded = True

        except Exception as err:

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


    async def compact_in_place(
        self,
        signal,
    ) -> None:
        """
        Thực hiện compact history tại chỗ.

        Không emit event.
        Không bắt exception.
        Mọi lỗi sẽ throw ra ngoài để auto_compact()
        hoặc caller xử lý.
        """

        history_snap = self.history.copy()

        if len(history_snap) <= 1:
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

        # Gọi LLM
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

        # Merge memory
        self.memory = merge_memory(
            self.memory,
            summary,
        )

        # Cập nhật lại System Prompt
        self.rebuild_system_prompt()

        # Học thêm từ summary
        await self.learn_intelligence(
            summary
        )

        # Reset history
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

        # Lưu session
        await self.save()

        # Lưu snapshot
        await self.save_context_snapshot(
            "auto compact"
        )

# ==========================================================
# Module-level Helper Functions
# ==========================================================

def count_memory_items(
    memory: Optional[SessionMemory]
) -> int:
    """
    Đếm tổng số item trong SessionMemory.
    Port 1:1 từ TypeScript.
    """

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
    # Thêm một nhóm memory vào output
    if not items:
        return

    out.append("")
    out.append(title)

    # Chỉ hiển thị 8 memory mới nhất
    for item in items[-8:]:
        out.append(f"- {item}")


def ensure_system_prompt(
    messages: list[Message],
    prompt: str
) -> list[Message]:
    """
    Đảm bảo system prompt luôn ở đầu history.
    """

    # Chưa có system message -> thêm mới
    if not messages or messages[0].role != "system":
        return [
            Message(role="system", content=prompt),
            *messages
        ]

    # Prompt không đổi -> giữ nguyên
    if messages[0].content == prompt:
        return messages

    # Prompt thay đổi -> cập nhật system message
    return [
        Message(role="system", content=prompt),
        *messages[1:]
    ]


def format_history_for_compaction(messages: list[Message]) -> str:
    """
    Chuyển lịch sử hội thoại thành chuỗi văn bản để phục vụ
    context compaction hoặc lưu snapshot.

    Đồng thời che (redact) các thông tin nhạy cảm như:
    - Bearer Token
    - API Key
    - Password
    - JWT
    """

    lines: list[str] = []

    for m in messages:
        # Bỏ qua message không có nội dung và cũng không có tool call
        if not m.content and (not m.tool_calls or len(m.tool_calls) == 0):
            continue

        # Hiển thị role và tên (nếu có)
        if m.name:
            lines.append(f"\n[{m.role}:{m.name}]")
        else:
            lines.append(f"\n[{m.role}]")

        # Nội dung hội thoại
        if m.content:
            lines.append(redact.apply(m.content))

        # Thông tin tool call
        if m.tool_calls:
            for tc in m.tool_calls:
                lines.append(
                    f"tool_call {tc.id} "
                    f"{tc.function.name} "
                    f"{redact.apply(tc.function.arguments)}"
                )

    return "\n".join(lines)


def err_message(err) -> str:
    """
    Chuyển Exception hoặc đối tượng bất kỳ thành chuỗi lỗi.
    """
    if isinstance(err, Exception):
        return str(err)
    return str(err)


def reconcile_tool_calls(messages: list[Message]) -> list[Message]:
    """
    Sửa các Tool Call còn dang dở trong history.

    Mỗi Assistant Tool Call phải có một Tool Message tương ứng.
    Nếu session bị dừng giữa chừng khiến Tool Result chưa được ghi,
    hàm sẽ tự sinh một Tool Message báo lỗi để history hợp lệ.
    """

    out: list[Message] = []

    i = 0

    while i < len(messages):

        message = messages[i]

        if message is None:
            i += 1
            continue

        # Giữ nguyên message hiện tại
        out.append(message)

        # Lấy danh sách tool call
        tool_calls = message.tool_calls

        # Không phải Assistant hoặc không có Tool Call
        if (
            message.role != "assistant"
            or not tool_calls
        ):
            i += 1
            continue

        # Các Tool Call đã có Tool Result
        answered: set[str] = set()

        j = i + 1

        # Thu thập các Tool Message ngay sau Assistant
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

        # Sinh Tool Message cho các Tool Call chưa có kết quả
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
    """
    Tạo một Event Emitter an toàn.

    Nếu Agent đã bị hủy (Abort), chỉ cho phép gửi
    event "done" và "error".
    """

    def safe_emit(event):

        event = _to_agent_event(event)

        # Đã hủy thì chỉ cho phép done và error
        if (
            signal.aborted
            and event["type"] not in ("done", "error")
        ):
            return

        try:
            emit(event)

        except Exception:
            # UI lỗi không được làm Agent dừng
            pass

    return safe_emit

def is_abort_like_error(err: object) -> bool:
    """
    Kiểm tra xem exception có phải lỗi do hủy (Abort) hay không.
    """

    if not isinstance(err, Exception):
        return False

    msg = str(err).lower()

    return (
        err.__class__.__name__ == "AbortError"
        or msg == "aborted"
        or "operation was aborted" in msg
    )

class AgentRuntimeError(RuntimeError):
    """
    RuntimeError tương thích với TypeScript Error.message.
    """

    @property
    def message(self) -> str:
        return str(self)

def bounded_history_for_compaction(
    messages: list[Message],
) -> str:
    """
    Giới hạn kích thước history khi gửi cho LLM để compact.
    Nếu history vượt quá COMPACTION_INPUT_CHAR_LIMIT ký tự,
    chỉ giữ phần cuối và thêm một system note.
    """

    # Chuyển history thành chuỗi
    full = format_history_for_compaction(messages)

    # Nếu chưa vượt giới hạn thì trả về luôn
    if len(full) <= COMPACTION_INPUT_CHAR_LIMIT:
        return full

    # Lấy COMPACTION_INPUT_CHAR_LIMIT ký tự cuối
    tail = full[-COMPACTION_INPUT_CHAR_LIMIT:]

    # Tìm vị trí bắt đầu của một message mới
    boundary = tail.find("\n[")

    # Nếu tìm thấy thì cắt từ đầu message
    if boundary > 0:
        trimmed = tail[boundary:]
    else:
        trimmed = tail

    # Ghép thêm system note
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
    """
    Gộp Memory hiện tại với Summary vừa sinh ra sau khi compact.
    """

    # Thời gian hiện tại (ISO 8601 UTC)
    now = datetime.now(timezone.utc).isoformat()

    # Phân tích summary thành các trường có cấu trúc
    parsed = parse_compaction_summary(summary)

    # Nếu chưa có memory thì tạo memory rỗng
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
    """
    Gộp hai danh sách, loại bỏ phần tử trùng lặp (không phân biệt hoa/thường),
    chuẩn hóa khoảng trắng, giới hạn độ dài mỗi phần tử và số lượng phần tử.
    """

    seen: set[str] = set()
    out: list[str] = []

    # Ghép danh sách cũ và mới
    for item in (prev or []) + next_items:

        # Chuẩn hóa khoảng trắng
        clean = " ".join(item.split()).strip()

        # Bỏ chuỗi rỗng
        if not clean:
            continue

        # So sánh không phân biệt hoa/thường
        key = clean.lower()

        # Đã tồn tại thì bỏ qua
        if key in seen:
            continue

        seen.add(key)

        # Giới hạn chiều dài mỗi mục (240 ký tự)
        if len(clean) > 240:
            clean = clean[:239] + "…"

        out.append(clean)

    # Giới hạn số lượng phần tử (giữ các phần tử mới nhất)
    if cap is not None:
        return out[-cap:]

    return out


def empty_memory() -> SessionMemory:
    """
    Khởi tạo một SessionMemory rỗng.
    """

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
    """
    Parse summary sau compact thành dữ liệu SessionMemory.

    Tương đương:
    Omit<
        SessionMemory,
        'version',
        'updatedAt',
        'compactions',
        'lastCompactedAt',
        'lastSummary'
    >
    """

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
    """
    Lấy các item trong các section Markdown cụ thể.

    - Chuẩn hóa tên heading.
    - Loại bỏ ký tự bullet (-, *, 1., 2)).
    - Bỏ dòng rỗng.
    - Bỏ các giá trị như "none", "n/a".
    """

    out: list[str] = []

    # normalize heading trước khi tìm section
    for name in map(normalize_heading, names):

        # Lấy các dòng trong section
        for line in sections.get(name, []):

            # Xóa bullet markdown:
            # "- item"
            # "* item"
            # "1. item"
            item = re.sub(
                r"^\s*(?:[-*]|\d+[.)])\s+",
                "",
                line,
            ).strip()

            # Bỏ dòng rỗng
            if not item:
                continue

            # Bỏ "none" hoặc "n/a"
            if re.match(
                r"^none\b|^n/a$",
                item,
                re.IGNORECASE,
            ):
                continue

            out.append(item)

    return out


def normalize_heading(s: str) -> str:
    """
    Chuẩn hóa heading:
    - Chuyển thành chữ thường
    - Xóa ký tự ':' và '#'
    - Xóa khoảng trắng thừa đầu cuối
    """

    return re.sub(
        r"[:#]",
        "",
        s.lower(),
    ).strip()


def split_markdown_sections(text: str) -> dict[str, list[str]]:
    """
    Tách nội dung Markdown thành các section.
    """

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
    """
    Tạo văn bản đầu vào cho learn_intelligence().
    """

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
    """
    Chạy tối đa limit task cùng lúc.
    Kết quả giữ nguyên thứ tự input.
    """

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
