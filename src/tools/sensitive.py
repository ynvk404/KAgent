from __future__ import annotations

import os
import re
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
    ".azure",
    ".gnupg",
    ".gcloud",
    ".kube",
    ".docker",
    ".config/gcloud",
    ".config/gh",
    ".config/op",
    ".config/git/credentials",
    ".kagent",
    ".netrc",
    ".pgpass",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".terraform.d",
    ".terraformrc",
    ".gem/credentials",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".composer/auth.json",
    ".m2/settings.xml",
    ".bash_history",
    ".zsh_history",
    ".python_history",
    ".mysql_history",
    ".psql_history",
]

#: Basenames that hold secrets wherever they appear on disk.
SENSITIVE_BASENAMES = {
    "credentials.json",
    "service-account.json",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
}

#: Dotenv variants: .env, .env.local, .env.production, ...
DOTENV_RE = re.compile(r"^\.env(\..+)?$")

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

    basename = os.path.basename(
        os.path.normpath(cleaned)
    ).lower()

    if basename in SENSITIVE_BASENAMES:
        return True

    if DOTENV_RE.match(basename):
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