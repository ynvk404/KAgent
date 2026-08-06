from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from src.logger.logger import get_logger

log = get_logger("engagement.store")

ENGAGEMENT_CHAR_LIMIT = 6000

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

        project = _read_text(self.project_path)
        if project:
            parts.append(project)

        combined = "\n\n".join(parts).strip()

        if len(combined) <= ENGAGEMENT_CHAR_LIMIT:
            return combined

        return (
            combined[:ENGAGEMENT_CHAR_LIMIT]
            + f"\n\n[engagement notes truncated at "
            f"{ENGAGEMENT_CHAR_LIMIT} characters — keep them concise]"
        )


def _read_text(path: Path) -> str:
    if not path.exists():
        return ""

    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        log.warning(
            "engagement: could not read %s; its notes are missing from this session",
            path,
            exc_info=True,
        )
        return ""
