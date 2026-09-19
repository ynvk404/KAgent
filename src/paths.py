"""Central runtime path policy for KAgent.

User-global state remains under ``~/.kagent``.  Project-local state is rooted
at the nearest containing project marker, rather than whichever subdirectory
happened to be the process working directory.
"""

from __future__ import annotations

import os
from pathlib import Path

APP_DIR_NAME = ".kagent"
PROJECT_MARKERS = (".git", "pyproject.toml")


def user_data_root(home: str | Path | None = None) -> Path:
    """Return the user-global KAgent data directory."""
    base = Path(home).expanduser() if home is not None else Path.home()
    return base / APP_DIR_NAME


def project_root(start: str | Path | None = None) -> Path:
    """Find the containing project root, falling back to the supplied CWD.

    ``KAGENT_PROJECT_ROOT`` is useful for marker-less projects and embedding.
    An explicit ``start`` still wins so tests and callers can be deterministic.
    """
    if start is None:
        override = os.getenv("KAGENT_PROJECT_ROOT")
        if override:
            return Path(override).expanduser().resolve()
        candidate = Path.cwd()
    else:
        # Explicit paths historically represented the project directory, and
        # keeping that contract also makes embedding and tests deterministic.
        return Path(start).expanduser().resolve()

    candidate = candidate.resolve()
    if candidate.is_file():
        candidate = candidate.parent

    for directory in (candidate, *candidate.parents):
        if any((directory / marker).exists() for marker in PROJECT_MARKERS):
            return directory
    return candidate


def project_data_root(start: str | Path | None = None) -> Path:
    return project_root(start) / APP_DIR_NAME


def legacy_project_data_root(start: str | Path | None = None) -> Path | None:
    """Return the old CWD-relative root when it differs from the project root.

    Callers may read this location for compatibility, but all new writes should
    use :func:`project_data_root`.
    """
    if start is not None:
        return None
    candidate = Path.cwd()
    candidate = candidate.resolve()
    if candidate.is_file():
        candidate = candidate.parent
    legacy = candidate / APP_DIR_NAME
    canonical = project_root() / APP_DIR_NAME
    return legacy if legacy != canonical else None
