"""Bounded operator-provided user input, never configuration or authority."""
from __future__ import annotations

import os
from pathlib import Path
import stat

MAX_PROMPT_BYTES = 64 * 1024


class PromptFileError(ValueError):
    pass


def read_prompt_file(value: str | Path) -> str:
    path = Path(value).expanduser().absolute()
    try:
        if str(value) == "-" or any(p.is_symlink() for p in (path, *path.parents)):
            raise PromptFileError("prompt file must be a regular file without symlinks")
        if not stat.S_ISREG(path.lstat().st_mode):
            raise PromptFileError("prompt file is not a regular file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise PromptFileError("prompt file must be a regular file with one link")
            raw = stream.read(MAX_PROMPT_BYTES + 1)
    except FileNotFoundError:
        raise PromptFileError("prompt file does not exist") from None
    except PermissionError:
        raise PromptFileError("prompt file is not readable") from None
    except OSError:
        raise PromptFileError("prompt file could not be opened safely") from None
    if len(raw) > MAX_PROMPT_BYTES:
        raise PromptFileError("prompt file exceeds 64 KiB")
    try:
        text = raw.decode("utf-8-sig").replace("\r\n", "\n")
    except UnicodeDecodeError:
        raise PromptFileError("prompt file is not valid UTF-8") from None
    if not text.strip():
        raise PromptFileError("prompt file is empty")
    if any((ord(c) < 32 and c not in "\n\t") or ord(c) == 127 for c in text):
        raise PromptFileError("prompt file contains unsupported control characters")
    return text
