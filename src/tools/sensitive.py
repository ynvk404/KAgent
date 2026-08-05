from __future__ import annotations

import os
from pathlib import Path

SYSTEM_PATHS = [
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/master.passwd",
    "/private/etc/shadow",
    "/private/etc/sudoers",
    "/private/etc/master.passwd",
]

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

def is_sensitive_path(
    abs_path: str,
) -> bool:
    cleaned = abs_path.replace("\\", "/")

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

def matches_path(
    candidate: str,
    target: str,
) -> bool:
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