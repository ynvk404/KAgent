from __future__ import annotations

import re
from pathlib import Path, PurePosixPath


_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)
_UNSAFE_IDENTIFIER_RE = re.compile(r"[^a-z0-9]+")
_SUPPORTED_FIELDS = {"target"}


def target_identifier(target: str) -> str:
    """Return the stable artifact identifier defined by the skill contract."""
    value = _SCHEME_RE.sub("", target.strip()).lower()
    value = _UNSAFE_IDENTIFIER_RE.sub("-", value).strip("-")[:64]
    if not value:
        raise ValueError("artifact target is required")
    return value


def validate_completion_artifact_template(template: str) -> str:
    """Validate a project-relative completion artifact template."""
    if not isinstance(template, str) or not template.strip():
        raise ValueError("completion artifact must be a non-empty string")
    normalized = template.strip().replace("\\", "/")
    fields = set(re.findall(r"{([^{}]+)}", normalized))
    if fields - _SUPPORTED_FIELDS or "target" not in fields:
        raise ValueError("completion artifact must contain only the {target} field")
    try:
        rendered = normalized.format(target="target")
    except (KeyError, ValueError) as exc:
        raise ValueError("invalid completion artifact template") from exc
    path = PurePosixPath(rendered)
    if path.is_absolute() or ".." in path.parts or path.name in {"", "."}:
        raise ValueError("completion artifact must stay inside the project")
    return normalized


def completion_artifact_path(template: str, target: str) -> str:
    normalized = validate_completion_artifact_template(template)
    return normalized.format(target=target_identifier(target))


def resolve_project_artifact(root: Path, relative_path: str) -> Path:
    base = root.resolve()
    artifact = (base / relative_path).resolve()
    try:
        artifact.relative_to(base)
    except ValueError as exc:
        raise ValueError("artifact path must stay inside the project") from exc
    return artifact
