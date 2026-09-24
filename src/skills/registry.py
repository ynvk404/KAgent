from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Literal

import yaml

from src.logger.logger import get_logger

log = get_logger("skills.registry")


SkillStage = Literal[
    "reconnaissance",
    "enumeration",
    "analysis",
    "validation",
    "reporting",
]

VALID_STAGES: frozenset[str] = frozenset(
    {
        "reconnaissance",
        "enumeration",
        "analysis",
        "validation",
        "reporting",
    }
)

CANDIDATE_CLASS_ALIASES: dict[str, str] = {
    "sqli": "sql-injection",
    "sql-injection": "sql-injection",
    "xss": "cross-site-scripting",
    "cross-site-scripting": "cross-site-scripting",
    "idor": "access-control",
    "bola": "access-control",
    "access-control": "access-control",
    "auth": "authentication",
    "authentication": "authentication",
    "csrf": "csrf",
    "ssrf": "ssrf",
    "ssti": "ssti",
}

OPTIONAL_TOOL_PREFIXES = (
    "mcp_",
    "plugin_",
)


class SkillMetadataError(ValueError):
    pass


@dataclass(slots=True)
class SkillTriggers:
    strong: list[str] = field(default_factory=list)
    weak: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Skill:
    name: str
    description: str
    tools: list[str]
    disable_model_invocation: bool
    path: str
    body: str
    stage: SkillStage | None = None
    triggers: SkillTriggers = field(default_factory=SkillTriggers)
    candidate_classes: list[str] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)


class Registry:

    def __init__(self):
        self.skills: dict[str, Skill] = {}
        self.disabled: set[str] = set()

    def add(self, skill: Skill):
        self.skills[skill.name] = skill

    def get(self, name: str) -> Skill | None:
        return self.skills.get(name)

    def has(self, name: str) -> bool:
        return name in self.skills

    def list(self) -> list[Skill]:
        return sorted(
            self.skills.values(),
            key=lambda x: x.name
        )

    def list_enabled(self) -> list[Skill]:
        return [
            skill
            for skill in self.list()
            if skill.name not in self.disabled
        ]

    def validators_for_class(self, candidate_class: str) -> list[Skill]:
        """Return enabled validation playbooks that explicitly handle a class."""
        canonical = normalize_candidate_class(candidate_class)
        return [
            skill for skill in self.list_enabled()
            if skill.stage == "validation"
            and not skill.disable_model_invocation
            and canonical in skill.candidate_classes
        ]

    def set_disabled_names(self, names: Iterable[str]):
        self.disabled = set(names)

    def disabled_names(self) -> list[str]:
        return sorted(self.disabled)

    def is_disabled(self, name: str) -> bool:
        return name in self.disabled

    def clear(self):
        self.skills.clear()

    def validation_errors(
        self,
        known_tools: set[str] | None = None,
    ) -> dict[str, list[str]]:
        known_skills = set(self.skills)
        return {
            skill.name: errors
            for skill in self.list()
            if (
                errors := validate_skill(
                    skill,
                    known_tools=known_tools,
                    known_skills=known_skills,
                )
            )
        }

    def set_disabled(self, name: str, on: bool) -> bool:
        old = name in self.disabled

        if on and not old:
            self.disabled.add(name)
            return True

        if not on and old:
            self.disabled.remove(name)
            return True

        return False

    def load_dir(self, directory: str | Path):
        directory = Path(directory)

        if not directory.exists():
            return

        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError:
            log.warning(
                "skills: could not list %s; no skills loaded from it",
                directory,
                exc_info=True,
            )
            return

        for item in entries:
            if item.name.startswith("."):
                continue

            if item.name.startswith("_"):
                continue

            if not item.is_dir():
                continue

            skill_file = item / "SKILL.md"

            if not skill_file.exists():
                continue

            try:
                skill = parse_skill(skill_file)
                self.add(skill)
            except Exception:
                log.warning("skills: skipping %s", skill_file, exc_info=True)


_FRONTMATTER_RE = re.compile(
    r"\A---[ \t]*\r?\n(?P<yaml>.*?)\r?\n---[ \t]*\r?\n?",
    re.DOTALL,
)

_LEADING_BLANK_LINES_RE = re.compile(r"\A(?:\r?\n)+")

MAX_DESCRIPTION = 1024
NAME_RE = re.compile(r"^[a-z0-9-]+$")


def parse_skill(path: str | Path) -> Skill:
    path = Path(path)
    raw = path.read_text(encoding="utf-8")

    metadata: dict = {}
    body = raw

    match = _FRONTMATTER_RE.match(raw)

    if match:
        parsed = yaml.safe_load(match.group("yaml"))
        if parsed is None:
            metadata = {}
        elif isinstance(parsed, dict):
            metadata = parsed
        else:
            raise SkillMetadataError("frontmatter must be a mapping")
        body = raw[match.end():]

    name_value = metadata.get("name")
    if name_value is None:
        name = path.parent.name
    elif not isinstance(name_value, str) or not name_value.strip():
        raise SkillMetadataError("`name` must be a non-empty string")
    else:
        name = name_value.strip()

    description_value = metadata.get("description")
    if description_value is None:
        description = ""
    elif not isinstance(description_value, str):
        raise SkillMetadataError("`description` must be a string")
    else:
        description = description_value.strip()

    stage_value = metadata.get("stage")
    stage: SkillStage | None = None
    if stage_value is not None:
        if not isinstance(stage_value, str):
            raise SkillMetadataError("`stage` must be a string")
        normalized_stage = normalize_metadata_name(stage_value)
        if normalized_stage not in VALID_STAGES:
            raise SkillMetadataError(
                f'unknown `stage` "{stage_value}"; expected one of: '
                + ", ".join(sorted(VALID_STAGES))
            )
        stage = normalized_stage  # type: ignore[assignment]

    triggers = parse_triggers(metadata.get("triggers"))
    candidate_classes = parse_string_list(
        metadata.get("candidate-classes"),
        "candidate-classes",
        normalize_candidate_class,
    )
    requires = parse_string_list(
        metadata.get("requires"),
        "requires",
        normalize_metadata_name,
    )

    tool_keys = ("allowed-tools", "allowedTools", "tools")
    if not any(key in metadata for key in tool_keys):
        raise SkillMetadataError("missing required `allowed-tools` metadata")

    tools_value = first_metadata_value(
        metadata,
        *tool_keys,
    )
    tools = parse_string_list(tools_value, "allowed-tools", str.strip)

    disable_value = first_metadata_value(
        metadata,
        "disable-model-invocation",
        "disableModelInvocation",
    )
    if disable_value is None:
        disable = False
    elif isinstance(disable_value, bool):
        disable = disable_value
    else:
        raise SkillMetadataError(
            "`disable-model-invocation` must be a boolean"
        )

    return Skill(
        name=name,
        description=description,
        tools=tools,
        disable_model_invocation=disable,
        path=str(path),
        body=_LEADING_BLANK_LINES_RE.sub("", body),
        stage=stage,
        triggers=triggers,
        candidate_classes=candidate_classes,
        requires=requires,
    )


def first_metadata_value(metadata: dict, *keys: str):
    for key in keys:
        if key in metadata:
            return metadata[key]
    return None


def normalize_metadata_name(value: str) -> str:
    return re.sub(
        r"-+",
        "-",
        re.sub(r"[\s_]+", "-", value.strip().lower()),
    ).strip("-")


def normalize_candidate_class(value: str) -> str:
    normalized = normalize_metadata_name(value)
    return CANDIDATE_CLASS_ALIASES.get(normalized, normalized)


def normalize_trigger(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower()).replace("_", " ")


def parse_string_list(
    value,
    field_name: str,
    normalizer,
) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise SkillMetadataError(f"`{field_name}` must be a list of strings")

    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise SkillMetadataError(
                f"`{field_name}` must contain only non-empty strings"
            )
        normalized = normalizer(item)
        if normalized not in result:
            result.append(normalized)
    return result


def parse_triggers(value) -> SkillTriggers:
    if value is None:
        return SkillTriggers()
    if not isinstance(value, dict):
        raise SkillMetadataError("`triggers` must be a mapping")

    unknown = set(value) - {"strong", "weak"}
    if unknown:
        raise SkillMetadataError(
            "`triggers` contains unknown keys: " + ", ".join(sorted(unknown))
        )

    return SkillTriggers(
        strong=parse_string_list(value.get("strong"), "triggers.strong", normalize_trigger),
        weak=parse_string_list(value.get("weak"), "triggers.weak", normalize_trigger),
    )


def is_optional_external_tool(name: str) -> bool:
    return name.startswith(OPTIONAL_TOOL_PREFIXES)


def validate_skill(
    skill: Skill,
    known_tools: set[str] | None = None,
    known_skills: set[str] | None = None,
) -> list[str]:
    errors: list[str] = []
    directory = Path(skill.path).parent.name

    if not skill.name:
        errors.append("missing `name`")
    elif not NAME_RE.match(skill.name):
        errors.append(
            f'name "{skill.name}" must be lowercase-kebab ([a-z0-9-])'
        )
    elif skill.name != directory:
        errors.append(
            f'name "{skill.name}" does not match its directory "{directory}"'
        )

    if not skill.description:
        errors.append("missing `description`")
    elif len(skill.description) > MAX_DESCRIPTION:
        errors.append(
            f"description is {len(skill.description)} chars "
            f"(max {MAX_DESCRIPTION})"
        )

    if skill.stage is not None and skill.stage not in VALID_STAGES:
        errors.append(
            f'unknown stage "{skill.stage}"; expected one of: '
            + ", ".join(sorted(VALID_STAGES))
        )

    if not isinstance(skill.disable_model_invocation, bool):
        errors.append("`disable-model-invocation` must be a boolean")

    for candidate_class in skill.candidate_classes:
        if not NAME_RE.match(candidate_class):
            errors.append(
                f'candidate class "{candidate_class}" must be lowercase-kebab'
            )

    for requirement in skill.requires:
        if not NAME_RE.match(requirement):
            errors.append(
                f'requires entry "{requirement}" must be lowercase-kebab'
            )
        elif known_skills is not None and requirement not in known_skills:
            errors.append(
                f'requires entry "{requirement}" is not a loaded skill'
            )

    for tool in skill.tools:
        if (
            known_tools is not None
            and tool not in known_tools
            and not is_optional_external_tool(tool)
        ):
            errors.append(
                f'allowed-tools entry "{tool}" is not a known tool'
            )

    return errors


def materialize_skill_body(skill: Skill) -> str:
    directory = str(Path(skill.path).parent)
    body = skill.body.replace("${SKILL_DIR}", directory)

    return f"# Skill: {skill.name}\n\n" + body


def new_registry():
    return Registry()
