from __future__ import annotations

import codecs
import os
import time
from pathlib import Path
from typing import Any

from src.permission.permission import (
    Decision,
    PermissionRequest,
    UserControlledRefusal,
    PermissionReviewStale,
    PermissionPolicyBlocked,
)
from src.paths import project_artifact_root, project_root

from src.tools.common.types import (
    PermissionHints,
    Tool,
    arg_bool,
    arg_string,
)
from src.tools.execution.sensitive import is_sensitive_path
from src.permission.runtime.execution import policy_for, file_resource_identity
from src.permission.runtime.invocations import capture_review, REVIEW_TIMEOUT_SECONDS
from src.permission.network.grants import check_cancelled
from src.tools.common.arguments import string_fields
from src.tools.common.outcome import ToolOutput

READ_BYTE_CAP = 200 * 1024

WRITE_FILE_MODE = 0o644
WRITE_DIR_MODE = 0o755


def _artifact_permission_hints(path: str, verb: str) -> PermissionHints:
    """Keep broad trust limited to generated output inside this project."""
    resolved = Path(real_resolve(str(Path(path).expanduser().resolve())))
    artifact_root = project_artifact_root().resolve()
    canonical_project = project_root().resolve()
    if (
        artifact_root.is_relative_to(canonical_project)
        and resolved.is_relative_to(artifact_root)
    ):
        return {
            "riskTier": "routine",
            "yoloAutoApprove": True,
            "cacheKey": str(artifact_root),
            "sessionScopeDisplay": f"{verb} under {artifact_root}",
        }
    return {
        "noSessionCache": True,
        "riskTier": "high-impact",
        "cacheKey": str(resolved),
        "sessionScopeDisplay": f"{verb} to {resolved}",
    }

def decode_utf8_capped(
    data: bytes,
    cap: int,
) -> str:
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    return decoder.decode(data[:cap], False)

def real_resolve(
    abs_path: str,
) -> str:
    path = Path(abs_path)
    try:
        return str(
            path.resolve(
                strict=True
            )
        )
    except Exception:
        try:
            parent = path.parent.resolve()
            return str(
                parent / path.name
            )
        except Exception:
            return abs_path

async def gate_sensitive_path(
    p,
    abs_path: str,
    verb: str,
    signal,
):
    real = real_resolve(
        abs_path
    )
    policy = policy_for(p)
    check_cancelled(signal)
    version = file_resource_identity(abs_path)
    active_check = policy.active_review_check() if policy is not None else lambda: True
    guard = capture_review(signal=signal, clock=policy.clock if policy else time.monotonic,
                           timeout=policy.review_timeout if policy else REVIEW_TIMEOUT_SECONDS,
                           condition=lambda: active_check() and file_resource_identity(abs_path) == version)
    if policy is not None:
        policy.require_path(real, write=verb in {"write to", "edit"})
        if not policy.nested_allowed():
            raise PermissionPolicyBlocked("blocked: file-executor-without-valid-receipt")
        if policy.yolo:
            return real
    if (
        not is_sensitive_path(abs_path)
        and not is_sensitive_path(real)
    ):
        return real

    shown = (
        f"{abs_path}\nresolves to: {real}"
        if real != abs_path
        else abs_path
    )

    decision = await p.ask(
        PermissionRequest(
            tool="file",
            summary=f"{verb} sensitive file: {real}",
            detail=(
                f"path: {shown}\n\n"
                "This path is on the sensitive-path list "
                "(private keys, cloud credentials, shell history, "
                "config dirs, etc.). Approve only if you intend to "
                f"{verb} it."
            ),
            no_session_cache=True,
            risk_tier="high-impact",
            is_current=guard.is_current,
        ),
        signal,
    )

    check_cancelled(signal)
    if not guard.is_current():
        raise PermissionReviewStale('blocked: stale sensitive-file review')
    if decision not in {Decision.ALLOW_ONCE, Decision.ALLOW_SESSION}:
        raise UserControlledRefusal(
            f"{verb} of sensitive path denied: {real}"
        )

    if policy is not None:
        if not policy.nested_allowed():
            raise PermissionReviewStale("blocked: policy-changed-during-sensitive-read-review")
        if str(policy.require_path(abs_path, write=verb in {"write to", "edit"})) != real:
            raise PermissionReviewStale("blocked: file-resource-changed-during-review")

    return real

def count_occurrences(
    text: str,
    needle: str,
) -> int:
    if not needle:
        return 0

    count = 0
    pos = 0

    while True:
        idx = text.find(
            needle,
            pos
        )

        if idx < 0:
            return count

        count += 1
        pos = idx + len(needle)

def _preview(content: str, limit: int = 400) -> str:
    return content if len(content) <= limit else f"{content[:limit]}..."

class FileReadTool(Tool):
    def __init__(
        self,
        tool_name="file_read"
    ):
        self.tool_name = tool_name

    def name(self):
        return self.tool_name

    def description(self):
        return (
            "Read UTF-8 file from disk. "
            "Returns up to 200KB. Reads of paths under ~/.ssh, ~/.aws, "
            "shell history files, etc. require explicit user approval."
        )

    def schema(self):
        return {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string"
                }
            },
            "required": [
                "path"
            ]
        }

    def requires_permission(self):
        return False

    async def run(
        self,
        args,
        signal,
        prompter,
    ) -> str:
        path = arg_string(
            args,
            "path"
        )

        if not path:
            raise ValueError(
                "path is required"
            )

        abs_path = str(
            Path(path).resolve()
        )

        real = await gate_sensitive_path(
            prompter,
            abs_path,
            "read",
            signal
        )

        policy = policy_for(prompter)
        if policy is not None:
            policy.revalidate_active(self, args, signal)

        size = os.path.getsize(
            real
        )

        with open(
            real,
            "rb"
        ) as f:
            data = f.read(
                READ_BYTE_CAP
            )

        content = decode_utf8_capped(
            data,
            READ_BYTE_CAP
        )

        if size > READ_BYTE_CAP:
            return ToolOutput(
                content
                + f"\n[... truncated {size-READ_BYTE_CAP} bytes ...]",
                truncated=True,
            )

        return content

class FileWriteTool(Tool):
    def __init__(
        self,
        tool_name="file_write"
    ):
        self.tool_name = tool_name

    def name(self):
        return self.tool_name

    def description(self):
        return (
            "Write content to a file, creating or overwriting it. "
            "User confirmation required."
        )

    def schema(self):
        return {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string"
                },
                "content": {
                    "type": "string"
                }
            },
            "required": [
                "path",
                "content"
            ]
        }

    def requires_permission(self):
        return True

    def validate_args(self, args: dict[str, Any]) -> None:
        string_fields(args, required=("path", "content"), nonempty=("path",))

    def permission_hints(
        self,
        args
    ) -> PermissionHints:
        return _artifact_permission_hints(arg_string(args, "path"), "writes")

    def summarize(
        self,
        args,
    ):
        path = arg_string(args, "path")
        content = arg_string(args, "content")

        return {
            "summary": f"write file: {path}",
            "detail": (
                f"path: {path}\n--- content ---\n{content}"
            ),
        }

    async def run(
        self,
        args,
        signal,
        prompter,
    ) -> str:
        self.validate_args(args)
        path = arg_string(
            args,
            "path"
        )

        content = arg_string(
            args,
            "content"
        )

        if not path:
            raise ValueError(
                "path is required"
            )

        abs_path = str(
            Path(path).resolve()
        )

        real = await gate_sensitive_path(
            prompter,
            abs_path,
            "write to",
            signal
        )

        policy = policy_for(prompter)
        if policy is not None:
            policy.revalidate_active(self, args, signal)

        parent = Path(real).parent
        file_existed = Path(real).exists()

        parent.mkdir(
            parents=True,
            exist_ok=True,
            mode=WRITE_DIR_MODE,
        )

        if policy is not None:
            policy.revalidate_active(self, args, signal)

        Path(real).write_text(
            content,
            encoding="utf-8"
        )

        if not file_existed:
            try:
                os.chmod(real, WRITE_FILE_MODE)
            except OSError:
                pass

        return (
            f"wrote "
            f"{len(content.encode('utf-8'))} bytes "
            f"to {real}"
        )

class FileEditTool(Tool):
    def __init__(
        self,
        tool_name="file_edit"
    ):
        self.tool_name = tool_name

    def name(self):
        return self.tool_name

    def description(self):
        return (
            "Replace an exact string in a file. old_string must appear "
            "exactly once unless replace_all=true. Use for patching "
            "scripts or notes without rewriting the whole file."
        )

    def requires_permission(self):
        return True

    def validate_args(self, args: dict[str, Any]) -> None:
        string_fields(args, required=("path", "old_string", "new_string"),
                      nonempty=("path", "old_string"))
        if "replace_all" in args and not isinstance(args["replace_all"], bool):
            raise ValueError("replace_all must be a boolean")

    def schema(self):
        return {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string"
                },
                "old_string": {
                    "type": "string"
                },
                "new_string": {
                    "type": "string"
                },
                "replace_all": {
                    "type": "boolean"
                }
            },
            "required": [
                "path",
                "old_string",
                "new_string"
            ]
        }

    def permission_hints(
        self,
        args
    ) -> PermissionHints:
        return _artifact_permission_hints(arg_string(args, "path"), "edits")

    def summarize(
        self,
        args,
    ):
        path = arg_string(args, "path")

        return {
            "summary": f"edit file: {path}",
            "detail": (
                f"path: {path}\n"
                f"replace_all: {arg_bool(args, 'replace_all')}\n"
                f"- {arg_string(args, 'old_string')}\n"
                f"+ {arg_string(args, 'new_string')}"
            ),
        }

    async def run(
        self,
        args,
        signal,
        prompter,
    ) -> str:
        self.validate_args(args)
        path = arg_string(
            args,
            "path"
        )

        old = arg_string(
            args,
            "old_string"
        )

        new = arg_string(
            args,
            "new_string"
        )

        replace_all = arg_bool(
            args,
            "replace_all"
        )

        if not path or not old:
            raise ValueError(
                "path and old_string are required"
            )

        abs_path = str(
            Path(path).resolve()
        )

        real = await gate_sensitive_path(
            prompter,
            abs_path,
            "edit",
            signal
        )

        policy = policy_for(prompter)
        if policy is not None:
            policy.revalidate_active(self, args, signal)

        content = Path(real).read_text(
            encoding="utf-8"
        )

        count = count_occurrences(
            content,
            old
        )

        if count == 0:
            raise ValueError(
                f"old_string not found in {real}"
            )

        if count > 1 and not replace_all:
            raise ValueError(
                f"old_string appears {count} times in {real}; pass "
                "replace_all=true or use a longer unique snippet"
            )

        updated = content.replace(
            old,
            new
        )

        if policy is not None:
            policy.revalidate_active(self, args, signal)

        Path(real).write_text(
            updated,
            encoding="utf-8"
        )

        return (
            f"edited {real} "
            f"({count} replacement(s))"
        )

class FileReadToolAlias(FileReadTool):
    def __init__(self):
        super().__init__(
            "FileReadTool"
        )

class FileWriteToolAlias(FileWriteTool):
    def __init__(self):
        super().__init__(
            "FileWriteTool"
        )

class FileEditToolAlias(FileEditTool):
    def __init__(self):
        super().__init__(
            "FileEditTool"
        )
