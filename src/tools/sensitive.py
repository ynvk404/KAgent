# tools/sensitive.py

from __future__ import annotations

import os
from pathlib import Path


# ==========================================================
# Sensitive system paths
# ==========================================================

SYSTEM_PATHS = [
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/master.passwd",

    # macOS realpath variants
    "/private/etc/shadow",
    "/private/etc/sudoers",
    "/private/etc/master.passwd",
]


# ==========================================================
# Sensitive home-relative paths
# ==========================================================

HOME_RELATIVE = [
    ".ssh",
    ".aws",
    ".gnupg",
    ".gcloud",
    ".kube",
    ".docker",
    ".config/gcloud",
    ".config/op",
    ".kagent",
    ".netrc",
    ".pgpass",
    ".npmrc",
    ".pypirc",
    ".bash_history",
    ".zsh_history",
    ".python_history",
    ".mysql_history",
    ".psql_history",
]


# ==========================================================
# Public API
# ==========================================================


def is_sensitive_path(
    abs_path: str,
) -> bool:
    """
    Return True if abs_path matches a known-sensitive path.

    Lexical check only:
    - normalize path separators
    - normalize case
    - do not follow symlinks
    """

    # Normalize separators first.
    # Important on Windows:
    # Path("/etc/shadow") -> "\\etc\\shadow"
    cleaned = abs_path.replace("\\", "/")

    # Only resolve normal relative paths.
    # Do not call abspath() on Linux-style absolute paths.
    if not cleaned.startswith("/"):
        cleaned = os.path.abspath(cleaned).replace("\\", "/")

    for target in SYSTEM_PATHS:
        if matches_path(
            cleaned,
            target,
        ):
            return True

    try:
        home = Path.home()
    except RuntimeError:
        return False

    if not home:
        return False

    for rel in HOME_RELATIVE:
        target = os.path.abspath(
            os.path.join(
                home,
                *rel.split("/"),
            )
        ).replace("\\", "/")

        if matches_path(
            cleaned,
            target,
        ):
            return True

    return False


# ==========================================================
# Internal helper
# ==========================================================


def matches_path(
    candidate: str,
    target: str,
) -> bool:
    """
    Exact match or directory prefix match.

    Examples:
        ~/.ssh/id_rsa  -> True
        ~/.ssh         -> True
        ~/.ssh_other   -> False
    """

    c = (
        os.path.normpath(candidate)
        .replace("\\", "/")
        .lower()
    )

    t = (
        os.path.normpath(target)
        .replace("\\", "/")
        .lower()
    )

    return (
        c == t
        or c.startswith(
            t + "/"
        )
    )