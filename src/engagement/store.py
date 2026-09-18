from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from src.logger.logger import get_logger

log = get_logger("engagement.store")

ENGAGEMENT_CHAR_LIMIT = 6000
_TRUNCATION_MARKER = (
    f"[engagement notes truncated at {ENGAGEMENT_CHAR_LIMIT} characters "
    "— keep them concise]"
)

@dataclass(slots=True)
class EngagementStore:
    cwd: str | Path |None = None
    home: str | Path | None = None

    project_path: Path = field(init=False)
    personal_path: Path = field(init=False)

    def __post_init__(self) -> None:
        cwd = Path(self.cwd).resolve() if self.cwd else Path.cwd().resolve()
        home = Path(self.home).expanduser() if self.home else Path.home()

        self.project_path = cwd / ".kagent" / "engagement.md"
        self.personal_path = home / ".kagent" / "engagement.md"

    def load(self) -> str:
        parts: list[str] = []

        personal = _read_text(self.personal_path)
        if personal:
            parts.append(personal)

        project = ""
        if not _same_file(self.personal_path, self.project_path):
            project = _read_text(self.project_path)
        if project:
            parts.append(project)

        combined = "\n\n".join(parts).strip()

        if len(combined) <= ENGAGEMENT_CHAR_LIMIT:
            return combined

        return _truncate(personal, project)


def _same_file(first: Path, second: Path) -> bool:
    if first == second:
        return True

    try:
        return first.samefile(second)
    except OSError:
        return False


def _truncate(personal: str, project: str) -> str:
    """Keep authoritative project rules available within the fixed budget."""
    if not project:
        return _with_marker(
            personal,
            ENGAGEMENT_CHAR_LIMIT - len(_TRUNCATION_MARKER) - 2,
        )

    project_budget = ENGAGEMENT_CHAR_LIMIT - len(_TRUNCATION_MARKER) - 2
    if len(project) > project_budget:
        return _with_marker(project, project_budget)

    personal_budget = (
        ENGAGEMENT_CHAR_LIMIT - len(project) - len(_TRUNCATION_MARKER) - 4
    )
    if personal_budget <= 0:
        return _with_marker(project, project_budget)

    return f"{personal[:personal_budget]}\n\n{project}\n\n{_TRUNCATION_MARKER}"


def _with_marker(text: str, budget: int) -> str:
    return f"{text[:budget]}\n\n{_TRUNCATION_MARKER}"


def _read_text(path: Path) -> str:
    if not path.exists():
        return ""

    try:
        return path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        log.warning(
            "engagement: could not read %s; its notes are missing from this session",
            path,
            exc_info=True,
        )
        return ""
