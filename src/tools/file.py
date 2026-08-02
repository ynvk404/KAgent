# tools/file.py

from __future__ import annotations

import codecs
import os
from pathlib import Path
from typing import Any

from .types import (
    Tool,
    arg_bool,
    arg_string,
)

from .sensitive import is_sensitive_path


READ_BYTE_CAP = 200 * 1024

WRITE_FILE_MODE = 0o644
WRITE_DIR_MODE = 0o755


# ==========================================================
# Helpers
# ==========================================================


def decode_utf8_capped(
    data: bytes,
    cap: int,
) -> str:
    """
    Decode up to `cap` bytes of UTF-8 without emitting a trailing
    replacement character when the cap falls mid-codepoint.

    Mirrors the TS implementation (Node's StringDecoder.write): an
    incremental decoder buffers an incomplete trailing multi-byte
    sequence instead of emitting a replacement char for it, while
    invalid bytes *inside* the decoded range are still replaced with
    U+FFFD rather than silently dropped (unlike errors="ignore", which
    would delete them with no trace).
    """

    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    # final=False: do not flush/replace a dangling incomplete sequence
    # at the very end of the capped slice.
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
        {
            "tool": "file",
            "summary":
                f"{verb} sensitive file: {real}",
            "detail":
                (
                    f"path: {shown}\n\n"
                    "This path is on the sensitive-path list "
                    "(private keys, cloud credentials, shell history, "
                    "config dirs, etc.). Approve only if you intend to "
                    f"{verb} it."
                ),
            "noSessionCache": True,
        },
        signal,
    )

    if decision == "deny":
        raise PermissionError(
            f"{verb} of sensitive path denied: {real}"
        )

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


# ==========================================================
# File Read
# ==========================================================


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
        p,
    ):

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
            p,
            abs_path,
            "read",
            signal
        )

        # Read from the gate-resolved real path, not the lexical one,
        # so a symlink swapped in between the gate check and the I/O
        # can't smuggle a sensitive file past the prompt (TOCTOU).
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
            return (
                content
                + f"\n[... truncated {size-READ_BYTE_CAP} bytes ...]"
            )

        return content


# ==========================================================
# File Write
# ==========================================================


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

    def permission_hints(
        self,
        args
    ):
        # Scope an "allow session" approval to the destination path so
        # it can't silently authorize writes to other files later on.
        return {
            "cacheKey":
                str(
                    Path(
                        arg_string(
                            args,
                            "path"
                        )
                    ).resolve()
                )
        }

    def summarize(
        self,
        args,
    ):
        path = arg_string(args, "path")
        content = arg_string(args, "content")

        return {
            "summary": f"write file: {path}",
            "detail": (
                f"path: {path}\n--- content ---\n{_preview(content)}"
            ),
        }

    async def run(
        self,
        args,
        signal,
        p,
    ):

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
            p,
            abs_path,
            "write to",
            signal
        )

        parent = Path(real).parent

        parent.mkdir(
            parents=True,
            exist_ok=True
        )

        # mkdir(exist_ok=True) leaves the mode of an already-existing
        # dir untouched, which matches Node's mkdir({recursive:true});
        # only chmod the leaf dir when we're the ones creating it fresh
        # is unnecessary here since Python's mkdir already applies mode
        # to newly-created components. Set explicitly for parity.
        try:
            os.chmod(parent, WRITE_DIR_MODE)
        except OSError:
            pass

        Path(real).write_text(
            content,
            encoding="utf-8"
        )

        try:
            os.chmod(real, WRITE_FILE_MODE)
        except OSError:
            pass

        return (
            f"wrote "
            f"{len(content.encode('utf-8'))} bytes "
            f"to {real}"
        )


# ==========================================================
# File Edit
# ==========================================================


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
    ):
        # Scope an "allow session" approval to the edited path.
        return {
            "cacheKey":
                str(
                    Path(
                        arg_string(
                            args,
                            "path"
                        )
                    ).resolve()
                )
        }

    def summarize(
        self,
        args,
    ):
        path = arg_string(args, "path")

        return {
            "summary": f"edit file: {path}",
            "detail": (
                f"path: {path}\n"
                f"- {arg_string(args, 'old_string')}\n"
                f"+ {arg_string(args, 'new_string')}"
            ),
        }

    async def run(
        self,
        args,
        signal,
        p,
    ):

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
            p,
            abs_path,
            "edit",
            signal
        )

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

        # Literal split/join replacement (not re.sub / str.format), so
        # nothing in new_string is ever interpreted as a backreference
        # or template token.
        updated = content.replace(
            old,
            new
        )

        Path(real).write_text(
            updated,
            encoding="utf-8"
        )

        try:
            os.chmod(real, WRITE_FILE_MODE)
        except OSError:
            pass

        return (
            f"edited {real} "
            f"({count} replacement(s))"
        )


# ==========================================================
# Aliases
# ==========================================================


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