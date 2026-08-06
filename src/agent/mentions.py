import os
import re
import time
from pathlib import Path
from dataclasses import dataclass

from src.logger.logger import get_logger

log = get_logger("agent.mentions")

INLINE_BYTE_CAP = 64 * 1024
MENTION_RE = re.compile(r'(^|[\s("\'`])@(\S+)')

index_cwd: str = ""
index_built_at: float = 0
mention_index: dict[str, list[str]] | None = None
REBUILD_COOLDOWN_MS = 2000
INDEX_FILE_CAP = 5000
INDEX_DIR_CAP = 1000
INDEX_DEPTH_CAP = 12
SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    ".next",
    "dist",
    "build",
    ".cache",
}


def is_sensitive_path(path: str) -> bool:
    return False


def extract_mentions(input_text: str) -> list[str]:
    out: list[str] = []
    for match in MENTION_RE.finditer(input_text):
        raw = clean_mention_path(match.group(2) or "")
        if raw and not raw.lower().startswith(("http://", "https://")):
            out.append(raw)
    return out


def clean_mention_path(raw: str) -> str:
    p = raw.strip()
    p = re.sub(r'^["\']|["\']$', "", p)
    p = re.sub(r'["\'.,;:)\]]+$', "", p)
    if p.startswith("~/"):
        p = str(Path.home() / p[2:])
    return p


def real_resolve_sync(path: str) -> str:
    try:
        return str(Path(path).resolve(strict=True))
    except Exception:
        try:
            parent = Path(path).parent.resolve(strict=True)
            return str(parent / Path(path).name)
        except Exception:
            return path


def walk(
    directory: str,
    idx: dict[str, list[str]],
    state: dict,
    depth: int,
) -> None:
    if (
        state["files"] >= INDEX_FILE_CAP
        or state["dirs"] >= INDEX_DIR_CAP
        or depth > INDEX_DEPTH_CAP
    ):
        return

    try:
        entries = os.scandir(directory)
    except OSError:
        log.debug("mentions: skipping unreadable directory %s", directory, exc_info=True)
        return

    for entry in entries:
        if (
            state["files"] >= INDEX_FILE_CAP
            or state["dirs"] >= INDEX_DIR_CAP
        ):
            return

        if entry.is_dir(follow_symlinks=False):
            if entry.name in SKIP_DIRS:
                continue
            state["dirs"] += 1
            walk(
                entry.path,
                idx,
                state,
                depth + 1,
            )
            continue

        if not entry.is_file(follow_symlinks=False):
            continue

        idx.setdefault(entry.name, []).append(entry.path)
        state["files"] += 1


def build_index(cwd: str) -> dict[str, list[str]]:
    idx: dict[str, list[str]] = {}
    state = {
        "files": 0,
        "dirs": 0,
    }
    walk(cwd, idx, state, depth=0)
    return idx


def find_by_basename(name: str, limit: int = 6) -> list[str]:
    global mention_index
    global index_cwd
    global index_built_at

    cwd = os.getcwd()

    if mention_index is None or index_cwd != cwd:
        mention_index = build_index(cwd)
        index_cwd = cwd
        index_built_at = time.time()

    matches = mention_index.get(name, [])

    if (
        not matches
        and (time.time() - index_built_at) * 1000 > REBUILD_COOLDOWN_MS
    ):
        mention_index = build_index(cwd)
        index_built_at = time.time()
        matches = mention_index.get(name, [])

    return sorted(matches)[:limit]


def resolve_mention(raw: str) -> tuple[str, str]:
    if os.path.isabs(raw):
        candidate = raw
    else:
        candidate = str(Path(raw).resolve())

    if os.path.isfile(candidate):
        return candidate, ""

    if "/" in raw or "\\" in raw:
        return "", f"File not found: {raw}"

    matches = find_by_basename(raw, 6)

    if len(matches) == 0:
        return "", f"File not found: {raw}"

    if len(matches) == 1:
        return matches[0], ""

    return (
        "",
        "Ambiguous file mention. Matches:\n" + "\n".join(matches),
    )


def expand_file_mentions(input_text: str) -> str:
    mentions = extract_mentions(input_text)

    if not mentions:
        return input_text

    seen = set()
    blocks = []

    for raw in mentions:
        resolved, note = resolve_mention(raw)

        if note:
            blocks.append(f"### @{raw}\n[{note}]")
            continue

        if not resolved:
            continue

        if resolved in seen:
            continue

        seen.add(resolved)
        real = real_resolve_sync(resolved)

        if is_sensitive_path(resolved) or is_sensitive_path(real):
            blocks.append(
                f"### @{raw}\n[Refusing to inline sensitive path {real}. Read it with file_read instead.]"
            )
            continue

        if not os.path.exists(real) or os.path.isdir(real):
            blocks.append(f"### @{raw}\n[File not found: {raw}]")
            continue

        try:
            with open(real, "rb") as f:
                buf = f.read()
        except Exception as err:
            blocks.append(f"### @{raw}\n[Could not read file: {err}]")
            continue

        body = buf.decode("utf-8", errors="replace")
        truncated = ""

        if len(buf) > INLINE_BYTE_CAP:
            body = body.encode("utf-8")[:INLINE_BYTE_CAP].decode(
                "utf-8", errors="ignore"
            )
            truncated = f"\n[... truncated {len(buf)-INLINE_BYTE_CAP} bytes ...]"

        blocks.append(
            f"### @{raw}\nPath: {real}\n\n```text\n{body}\n```\n{truncated}"
        )

    if not blocks:
        return input_text

    return input_text + "\n\n# Referenced files\n\n" + "\n\n".join(blocks)


@dataclass
class MentionCandidate:
    display: str
    insert: str
    is_dir: bool


PICKER_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".next",
    "dist",
    "build",
    ".cache",
}


def ensure_index() -> None:
    global mention_index
    global index_cwd
    global index_built_at

    cwd = os.getcwd()

    if mention_index is None or cwd != index_cwd:
        mention_index = build_index(cwd)
        index_cwd = cwd
        index_built_at = time.time()


def relativize(path: str, cwd: str) -> str:
    try:
        return os.path.relpath(path, cwd)
    except Exception:
        return path


def mention_candidates(
    partial: str,
    limit: int = 8,
) -> list[str]:
    if not partial:
        return []

    ensure_index()

    needle = partial.lower()
    cwd = os.getcwd()

    starts = []
    contains = []

    if mention_index is None:
        return []

    for name, paths in mention_index.items():
        lower = name.lower()

        if lower == needle or lower.startswith(needle):
            for p in paths:
                starts.append((name, p))

        elif needle in lower:
            for p in paths:
                contains.append((name, p))

    starts.sort(key=lambda x: (x[0], x[1]))
    contains.sort(key=lambda x: (x[0], x[1]))

    combined = (starts + contains)[:limit]

    return [
        relativize(path, cwd)
        for _, path in combined
    ]


def parse_mention_path(
    partial: str,
) -> tuple[str, str]:
    last = partial.rfind("/")

    if last < 0:
        return "", partial

    return (
        partial[: last + 1],
        partial[last + 1 :],
    )


def has_parent(
    abs_dir: str,
) -> bool:
    parent = str(Path(abs_dir).resolve().parent)
    return parent != str(Path(abs_dir).resolve())


def list_mention_dir(
    dir: str,
    base: str,
    limit: int = 12,
) -> list[MentionCandidate]:
    if not dir:
        abs_dir = os.getcwd()

    elif dir.startswith("~/"):
        abs_dir = str(Path.home() / dir[2:])

    else:
        abs_dir = str(Path(dir).resolve())

    try:
        entries = list(os.scandir(abs_dir))
    except OSError:
        log.debug("mentions: skipping unreadable directory %s", abs_dir, exc_info=True)
        return []

    needle = base.lower()
    show_hidden = base.startswith(".")

    starts: list[MentionCandidate] = []
    contains: list[MentionCandidate] = []

    if has_parent(abs_dir):
        insert = f"{dir}../"

        if (
            not needle
            or "..".startswith(needle)
            or "../".startswith(needle)
        ):
            starts.append(
                MentionCandidate(
                    display="../",
                    insert=insert,
                    is_dir=True,
                )
            )

    for entry in entries:

        if entry.name in PICKER_SKIP_DIRS:
            continue

        if entry.name.startswith(".") and not show_hidden:
            continue

        lower = entry.name.lower()

        if needle and needle not in lower:
            continue

        is_dir = entry.is_dir()

        display = entry.name + ("/" if is_dir else "")

        insert = (
            dir
            + entry.name
            + ("/" if is_dir else "")
        )

        cand = MentionCandidate(
            display=display,
            insert=insert,
            is_dir=is_dir,
        )

        if not needle or lower.startswith(needle):
            starts.append(cand)
        else:
            contains.append(cand)

    def sort_key(c: MentionCandidate):
        if c.display == "../":
            return (0, "", "")

        return (
            1,
            0 if c.is_dir else 1,
            c.display,
        )

    starts.sort(key=sort_key)
    contains.sort(key=sort_key)

    return (starts + contains)[:limit]


def find_active_mention(
    text: str,
):
    i = len(text) - 1

    while i >= 0:
        ch = text[i]

        if ch in (" ", "\t", "\n"):
            return None

        if ch == "@":
            prev = text[i - 1] if i > 0 else ""

            if i == 0 or re.match(r'[\s("\'`]', prev):
                partial = text[i + 1 :]

                if partial.lower().startswith(
                    ("http:", "https:")
                ):
                    return None

                return {
                    "at": i,
                    "partial": partial,
                }

            return None

        i -= 1

    return None