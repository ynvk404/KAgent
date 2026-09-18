import os
from pathlib import Path


def _lexical_resolve(*parts: str) -> str:
    joined = os.path.join(*parts)
    if not os.path.isabs(joined):
        joined = os.path.join(os.getcwd(), joined)
    return os.path.normpath(joined)


def builtin_skills_dir() -> str:
    return _lexical_resolve(os.getcwd(), "skills")


def skill_search_dirs(
    configured: list[str],
    cwd: str | None = None,
    home: str | None = None,
) -> list[str]:
    if cwd is None:
        cwd = os.getcwd()

    if home is None:
        home = str(Path.home())

    dirs = [
        _lexical_resolve(cwd, "skills"),
        _lexical_resolve(cwd, ".kagent", "skills"),
        _lexical_resolve(home, ".kagent", "builtin-skills"),
        _lexical_resolve(home, ".kagent", "skills"),
    ]

    dirs.extend(_lexical_resolve(cwd, d) for d in configured)

    return dirs
