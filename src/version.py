"""Project version lookup shared by the CLI and runtime components."""
from __future__ import annotations

from importlib import metadata
from pathlib import Path
import tomllib


def get_version() -> str:
    """Return the installed distribution version, or the source project version."""
    try:
        return metadata.version("kagent")
    except metadata.PackageNotFoundError:
        pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
        try:
            with pyproject.open("rb") as project_file:
                version = tomllib.load(project_file)["project"]["version"]
        except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError):
            return "unknown"
        return version if isinstance(version, str) and version else "unknown"


VERSION = get_version()


def describe() -> str:
    return f"kagent {VERSION}"
