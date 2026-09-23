from __future__ import annotations

import dataclasses
import json
import os
import random
import string
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from src.llm.types import (
    FunctionCall,
    GeminiProvider,
    Message,
    Role,
    ToolCall,
    ToolProvider,
)
from src.logger.logger import get_logger
from src.paths import user_data_root
from src.engagement.state import EngagementState
from src.target.target import Target
from src.workflow.state import WorkflowState

log = get_logger("session.store")


@dataclass
class SessionMemory:
    version: int = 1
    updated_at: str = ""
    compactions: int = 0
    last_compacted_at: str | None = None
    last_summary: str | None = None
    objectives: list[str] = field(default_factory=list)
    plan: list[str] = field(default_factory=list)
    completed: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    tested: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    credentials: list[str] = field(default_factory=list)
    todos: list[str] = field(default_factory=list)


@dataclass
class SessionFile:
    updated_at: str
    messages: list[Message]
    id: str | None = None
    target: Target | None = None
    memory: SessionMemory | None = None
    workflow: WorkflowState = field(default_factory=WorkflowState)
    engagement_state: EngagementState = field(default_factory=EngagementState)


@dataclass
class Summary:
    id: str
    path: str
    updated_at: datetime
    preview: str


def new_id() -> str:
    return str(uuid.uuid4())


def validate_id(session_id: str) -> None:
    if not session_id:
        raise ValueError("session id is required")

    if "/" in session_id or "\\" in session_id or ".." in session_id:
        raise ValueError(f"invalid session id: {session_id}")


def dir_from_path(path=None):
    if not path:
        return user_data_root() / "sessions"
    return Path(path).parent


FSYNC_EVERY = 5


def random_tmp_id():
    return "".join(random.choice(string.hexdigits.lower()) for _ in range(6))


def cleanup_stale_temps(directory: Path, max_age_seconds: int = 60):
    if not directory.exists():
        return

    now = datetime.now().timestamp()

    for file in directory.iterdir():
        if ".tmp." not in file.name and not file.name.endswith(".tmp"):
            continue

        try:
            age = now - file.stat().st_mtime
            if age > max_age_seconds:
                file.unlink(missing_ok=True)
        except OSError:
            log.warning("session: could not remove stale temp %s", file, exc_info=True)


def _tool_call_from_dict(d: Any) -> ToolCall | None:
    if not isinstance(d, dict):
        return None

    fn_data = d.get("function")
    if not isinstance(fn_data, dict):
        return None

    name = fn_data.get("name", "")
    arguments = fn_data.get("arguments", "")
    call_id = d.get("id", "")
    call_type = d.get("type", "function")
    if (
        not all(
            isinstance(value, str) for value in (name, arguments, call_id, call_type)
        )
        or call_type != "function"
    ):
        return None

    function = FunctionCall(
        name=name,
        arguments=arguments,
    )

    provider = None
    provider_data = d.get("provider")
    if isinstance(provider_data, dict):
        gemini_data = provider_data.get("gemini")
        gemini = None
        if isinstance(gemini_data, dict):
            thought_signature = gemini_data.get("thought_signature")
            if thought_signature is None or isinstance(thought_signature, str):
                gemini = GeminiProvider(thought_signature=thought_signature)
        provider = ToolProvider(gemini=gemini)

    return ToolCall(
        id=call_id,
        function=function,
        type=call_type,
        provider=provider,
    )


def _tool_calls_from_list(raw: Any) -> list[ToolCall] | None:
    if not isinstance(raw, list) or not raw:
        return None

    result = [
        tc for tc in (_tool_call_from_dict(item) for item in raw) if tc is not None
    ]
    return result or None


_MEMORY_KEY_ALIASES = {
    "updatedAt": "updated_at",
    "lastCompactedAt": "last_compacted_at",
    "lastSummary": "last_summary",
}

_MEMORY_FIELDS = {f.name for f in dataclasses.fields(SessionMemory)}


def _memory_from_dict(data: dict) -> SessionMemory | None:
    normalized: dict[str, Any] = {}
    for key, value in data.items():
        canonical = _MEMORY_KEY_ALIASES.get(key, key)
        if canonical in _MEMORY_FIELDS:
            normalized[canonical] = value

    list_fields = {
        "objectives",
        "plan",
        "completed",
        "findings",
        "tested",
        "files",
        "commands",
        "credentials",
        "todos",
    }
    optional_string_fields = {"last_compacted_at", "last_summary"}

    if (
        not isinstance(normalized.get("version", 1), int)
        or isinstance(normalized.get("version", 1), bool)
        or not isinstance(normalized.get("updated_at", ""), str)
        or not isinstance(normalized.get("compactions", 0), int)
        or isinstance(normalized.get("compactions", 0), bool)
        or any(
            value is not None and not isinstance(value, str)
            for key, value in normalized.items()
            if key in optional_string_fields
        )
        or any(
            not isinstance(value, list)
            or not all(isinstance(item, str) for item in value)
            for key, value in normalized.items()
            if key in list_fields
        )
    ):
        log.warning("session: dropping malformed session memory")
        return None

    return SessionMemory(**normalized)


_MESSAGE_ROLES = {"system", "user", "assistant", "tool"}


def _message_from_dict(data: Any) -> Message | None:
    if not isinstance(data, dict):
        return None

    role = data.get("role", "user")
    content = data.get("content", "")
    if (
        not isinstance(role, str)
        or role not in _MESSAGE_ROLES
        or not isinstance(content, str)
    ):
        return None

    reasoning_content = data.get("reasoning_content")
    if reasoning_content is not None and not isinstance(reasoning_content, str):
        reasoning_content = None

    tool_call_id = data.get("tool_call_id")
    if tool_call_id is not None and not isinstance(tool_call_id, str):
        tool_call_id = None

    name = data.get("name")
    if name is not None and not isinstance(name, str):
        name = None

    tool_status = data.get("tool_status")
    if tool_status not in ("success", "observation", "error", "cancelled"):
        tool_status = None
    tool_error_kind = data.get("tool_error_kind")
    if tool_error_kind not in (
        "permission_denied", "scope_denied", "timeout", "network", "tls",
        "invalid_args", "cancelled", "tool_exception",
    ):
        tool_error_kind = None
    tool_http_status = data.get("tool_http_status")
    if isinstance(tool_http_status, bool) or not isinstance(tool_http_status, int):
        tool_http_status = None
    tool_truncated = data.get("tool_truncated") is True

    return Message(
        role=cast(Role, role),
        content=content,
        reasoning_content=reasoning_content,
        tool_calls=_tool_calls_from_list(data.get("tool_calls")),
        tool_call_id=tool_call_id,
        name=name,
        tool_status=tool_status,
        tool_error_kind=tool_error_kind,
        tool_http_status=tool_http_status,
        tool_truncated=tool_truncated,
    )


class SessionLoadError(RuntimeError):
    """A session file exists but could not be read back."""


def _restrict_permissions(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        log.warning(
            "session: could not restrict permissions on %s; it may be "
            "readable by other users",
            path,
            exc_info=True,
        )


class Store:
    def __init__(self, path, session_id: str = ""):
        self.path = Path(path)
        self.id = session_id
        self.save_count = 0

    @staticmethod
    def new_with_id(directory, session_id):
        return Store(Path(directory) / f"{session_id}.json", session_id)

    def context_snapshot_path(self):
        session_id = self.id or self.path.stem or "session"
        return self.path.parent.parent / "context" / f"{session_id}.md"

    def load(self) -> SessionFile:
        if not self.path.exists():
            return SessionFile(
                updated_at="",
                messages=[],
                id=self.id,
                target=None,
                memory=None,
                workflow=WorkflowState(),
                engagement_state=EngagementState(),
            )

        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as err:
            raise SessionLoadError(
                f"session: failed to read {self.path}: {err}"
            ) from err

        if not isinstance(raw, dict):
            raise SessionLoadError(f"session: {self.path}: not a JSON object")

        raw_messages = raw.get("messages", [])
        messages: list[Message] = []
        for item in raw_messages if isinstance(raw_messages, list) else []:
            message = _message_from_dict(item)
            if message is not None:
                messages.append(message)

        memory = None
        memory_data = raw.get("memory")
        if isinstance(memory_data, dict):
            memory = _memory_from_dict(memory_data)

        target = None
        target_data = raw.get("target")
        if isinstance(target_data, dict):
            target = Target.from_dict(target_data)

        workflow_data = raw.get("workflow")
        if workflow_data is not None and not isinstance(workflow_data, dict):
            log.warning("session: ignoring malformed workflow state")
        workflow = WorkflowState.from_dict(workflow_data)

        engagement_data = raw.get("engagement_state")
        if engagement_data is not None and not isinstance(engagement_data, dict):
            log.warning("session: ignoring malformed engagement state")
        engagement_state = EngagementState.from_dict(engagement_data)
        if not engagement_state.allowed_origins and target is not None:
            target_url = target.base_url()
            if target_url:
                try:
                    engagement_state.initialize_target(target_url)
                except ValueError:
                    log.warning("session: could not derive engagement scope from target")

        return SessionFile(
            updated_at=raw.get("updated_at", ""),
            id=raw.get("id", self.id),
            messages=messages,
            target=target,
            memory=memory,
            workflow=workflow,
            engagement_state=engagement_state,
        )

    async def save(
        self,
        messages: list[Message],
        target: Target | None = None,
        memory: SessionMemory | None = None,
        workflow: WorkflowState | None = None,
        engagement_state: EngagementState | None = None,
    ) -> None:
        if not self.path or str(self.path) in ("", "."):
            return

        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        serialized_messages = []
        for msg in messages:
            serialized: dict[str, Any] = {
                "role": msg.role,
                "content": msg.content,
                "reasoning_content": msg.reasoning_content,
                "tool_calls": (
                    [dataclasses.asdict(tc) for tc in msg.tool_calls]
                    if msg.tool_calls
                    else None
                ),
                "tool_call_id": msg.tool_call_id,
                "name": msg.name,
            }
            if msg.role == "tool":
                if msg.tool_status is not None:
                    serialized["tool_status"] = msg.tool_status
                if msg.tool_error_kind is not None:
                    serialized["tool_error_kind"] = msg.tool_error_kind
                if msg.tool_http_status is not None:
                    serialized["tool_http_status"] = msg.tool_http_status
                if msg.tool_truncated:
                    serialized["tool_truncated"] = True
            serialized_messages.append(serialized)

        data = {
            "updated_at": datetime.now().isoformat(),
            "id": self.id if self.id else None,
            "target": target.to_dict() if target and not target.is_empty() else None,
            "memory": dataclasses.asdict(memory) if memory else None,
            "workflow": workflow.to_dict() if workflow else None,
            "engagement_state": (
                engagement_state.to_dict() if engagement_state else None
            ),
            "messages": serialized_messages,
        }

        body = json.dumps(data, ensure_ascii=False) + "\n"

        self.save_count += 1
        need_fsync = self.save_count == 1 or self.save_count % FSYNC_EVERY == 0

        tmp = Path(str(self.path) + ".tmp." + random_tmp_id())
        created_tmp = False

        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created_tmp = True
            with os.fdopen(fd, "w", encoding="utf8") as f:
                f.write(body)
                f.flush()
                if need_fsync:
                    os.fsync(f.fileno())

            os.replace(tmp, self.path)

            _restrict_permissions(self.path)

        except Exception:
            if created_tmp:
                tmp.unlink(missing_ok=True)
            raise

    async def clear(self) -> None:
        if not self.path or str(self.path) in ("", "."):
            return
        self.path.unlink(missing_ok=True)

    async def save_context_snapshot(self, markdown: str) -> str:
        if not self.path or str(self.path) in ("", "."):
            return ""

        out = self.context_snapshot_path()
        out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        if not markdown.endswith("\n"):
            markdown += "\n"

        tmp = Path(str(out) + ".tmp." + random_tmp_id())
        created_tmp = False

        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created_tmp = True
            with os.fdopen(fd, "w", encoding="utf8") as f:
                f.write(markdown)
                f.flush()
                os.fsync(f.fileno())

            os.replace(tmp, out)

            _restrict_permissions(out)

        except Exception:
            if created_tmp:
                tmp.unlink(missing_ok=True)
            raise

        return str(out)


_PREVIEW_MARKER = "\n\n# Referenced files\n\n"


def _first_user_preview(messages: list, max_len: int) -> str:
    for m in messages:
        role = m.get("role") if isinstance(m, dict) else getattr(m, "role", None)
        if role != "user":
            continue

        content = m.get("content") if isinstance(m, dict) else getattr(m, "content", "")
        content = content or ""

        idx = content.find(_PREVIEW_MARKER)
        if idx >= 0:
            content = content[:idx]

        first_line = content.split("\n", 1)[0].strip()

        chars = list(first_line)
        if len(chars) > max_len:
            return "".join(chars[: max_len - 1]) + "…"
        return first_line

    return "(no user messages)"


def list_dir(directory) -> list[Summary]:
    directory = Path(directory)
    if not directory.exists():
        return []

    try:
        entries = list(directory.iterdir())
    except OSError:
        log.warning("session: could not list %s", directory, exc_info=True)
        return []

    out: list[Summary] = []
    for entry in entries:
        if not entry.name.endswith(".json"):
            continue

        try:
            raw = json.loads(entry.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            log.warning("session: skipping unreadable session %s", entry, exc_info=True)
            continue

        if not isinstance(raw, dict):
            continue

        session_id = raw.get("id") or entry.stem

        updated_at_raw = raw.get("updated_at")
        try:
            updated_at = (
                datetime.fromisoformat(updated_at_raw)
                if updated_at_raw
                else datetime.fromtimestamp(0)
            )
        except (TypeError, ValueError):
            updated_at = datetime.fromtimestamp(0)

        out.append(
            Summary(
                id=session_id,
                path=str(entry),
                updated_at=updated_at,
                preview=_first_user_preview(raw.get("messages") or [], 80),
            )
        )

    out.sort(key=lambda s: s.updated_at, reverse=True)
    return out
