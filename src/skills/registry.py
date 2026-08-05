from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml


@dataclass(slots=True)
class Skill:
    name: str
    description: str
    tools: list[str]
    disable_model_invocation: bool
    path: str
    body: str


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

    def set_disabled_names(self, names: Iterable[str]):
        self.disabled = set(names)

    def disabled_names(self) -> list[str]:
        return sorted(self.disabled)

    def is_disabled(self, name: str) -> bool:
        return name in self.disabled

    def clear(self):
        self.skills.clear()

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
            entries = directory.iterdir()
        except Exception:
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
            except Exception as e:
                print(f"[skills] skip {skill_file}: {e}")


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
        metadata = parsed if isinstance(parsed, dict) else {}
        body = raw[match.end():]

    name = metadata.get("name")
    if not isinstance(name, str) or not name:
        name = path.parent.name

    description = metadata.get("description")
    if not isinstance(description, str):
        description = ""

    tools = metadata.get("allowed-tools")
    if tools is None:
        tools = metadata.get("allowedTools")
    if tools is None:
        tools = metadata.get("tools")
    if tools is None:
        tools = []

    if not isinstance(tools, list):
        tools = []

    tools = [x for x in tools if isinstance(x, str)]

    disable = (
        metadata.get("disable-model-invocation") is True
        or metadata.get("disableModelInvocation") is True
    )

    return Skill(
        name=name,
        description=description,
        tools=tools,
        disable_model_invocation=disable,
        path=str(path),
        body=_LEADING_BLANK_LINES_RE.sub("", body),
    )


def validate_skill(skill: Skill, known_tools: set[str]) -> list[str]:
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

    for tool in skill.tools:
        if tool not in known_tools:
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