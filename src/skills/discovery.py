import os
from pathlib import Path

from src.paths import (
    legacy_project_data_root,
    project_data_root,
    project_root,
    user_data_root,
)


def _lexical_resolve(*parts: str) -> str:
    joined = os.path.join(*parts)
    if not os.path.isabs(joined):
        joined = os.path.join(os.getcwd(), joined)
    return os.path.normpath(joined)


def builtin_skills_dir() -> str:
    return str(project_root() / "skills")


def skill_search_dirs(
    configured: list[str],
    cwd: str | None = None,
    home: str | None = None,
) -> list[str]:
    supplied_cwd = cwd
    if cwd is None:
        cwd = os.getcwd()

    if home is None:
        home = str(Path.home())

    root = project_root() if supplied_cwd is None else project_root(cwd)
    dirs = [
        str(root / "skills"),
        str(
            project_data_root() / "skills"
            if supplied_cwd is None
            else project_data_root(cwd) / "skills"
        ),
        str(user_data_root(home) / "builtin-skills"),
        str(user_data_root(home) / "skills"),
    ]

    legacy_root = legacy_project_data_root() if supplied_cwd is None else None
    if legacy_root is not None:
        dirs.append(str(legacy_root / "skills"))

    dirs.extend(_lexical_resolve(cwd, d) for d in configured)

    return dirs
