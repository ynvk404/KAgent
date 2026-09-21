from __future__ import annotations

import re
from pathlib import Path

import pytest

from src.findings.store import Store
from src.permission.permission import AlwaysAllow
from src.agent.decision_planner import GENERIC_TRIGGER_TERMS, normalize
from src.skills.registry import (
    VALID_STAGES,
    Registry,
    normalize_candidate_class,
    validate_skill,
)
from src.tools.finding import ConfirmFindingTool
from src.tools.payloads import ReadPayloadsTool
from src.tools.skill_file import ReadSkillFileTool


REPO_ROOT = Path(__file__).resolve().parents[2]
SKILLS_ROOT = REPO_ROOT / "skills"
REMOVED_SKILL_NAMES = {"finding-validation", "ssrf-impact", "takeover"}
HANDOFF_REFERENCE_RE = re.compile(
    r"(?:transition to|hand(?:ed)? off to|routed? to|belongs to)\s+"
    r"`([a-z0-9-]+)`",
    re.IGNORECASE,
)
PAYLOAD_CALL_RE = re.compile(
    r'read_payloads\(skill="([a-z0-9-]+)",\s*file="([^"\n]+)"'
)
TOOL_SKILL_EXAMPLE_RE = re.compile(r'skill="([a-z0-9-]+)"')


@pytest.fixture(scope="module")
def shipped_registry() -> Registry:
    registry = Registry()
    registry.load_dir(SKILLS_ROOT)
    return registry


def test_shipped_skills_have_valid_selection_metadata(shipped_registry):
    known_tools = {
        "ask_user",
        "confirm_finding",
        "file_write",
        "http",
        "read_payloads",
        "shell",
        "workflow",
    }
    known_skills = {skill.name for skill in shipped_registry.list()}

    for skill in shipped_registry.list():
        assert skill.stage in VALID_STAGES
        assert skill.triggers.strong
        assert validate_skill(skill, known_tools, known_skills) == []
        assert all(
            normalize(trigger) not in GENERIC_TRIGGER_TERMS
            for trigger in skill.triggers.strong
        )
        assert skill.candidate_classes == [
            normalize_candidate_class(candidate_class)
            for candidate_class in skill.candidate_classes
        ]


def test_explicit_skill_handoffs_resolve_to_shipped_skills(shipped_registry):
    known = {skill.name for skill in shipped_registry.list()}
    references: set[str] = set()

    for skill in shipped_registry.list():
        references.update(HANDOFF_REFERENCE_RE.findall(skill.body))

    assert references, "expected shipped skills to contain explicit handoffs"
    assert references <= known, (
        "skill handoffs reference unavailable skills: "
        f"{sorted(references - known)}"
    )


def test_removed_skill_names_are_absent_from_skill_contracts(shipped_registry):
    referenced = {
        name
        for skill in shipped_registry.list()
        for name in re.findall(
            r"`([a-z0-9-]+)`",
            f"{skill.description}\n{skill.body}",
        )
    }

    assert REMOVED_SKILL_NAMES.isdisjoint(referenced)


def test_user_facing_tool_examples_name_loaded_skills(shipped_registry):
    help_text = "\n".join(
        [
            ReadPayloadsTool(shipped_registry).description(),
            ReadSkillFileTool(shipped_registry).description(),
        ]
    )
    examples = set(TOOL_SKILL_EXAMPLE_RE.findall(help_text))
    known = {skill.name for skill in shipped_registry.list()}

    assert examples
    assert examples <= known, (
        "user-facing examples reference unavailable skills: "
        f"{sorted(examples - known)}"
    )


@pytest.mark.asyncio
async def test_shipped_payload_calls_resolve_through_production_tool(
    shipped_registry,
):
    references: set[tuple[str, str]] = set()

    for skill in shipped_registry.list():
        references.update(PAYLOAD_CALL_RE.findall(skill.body))

    assert references
    tool = ReadPayloadsTool(shipped_registry)

    for skill_name, filename in sorted(references):
        output = await tool.run(
            {
                "skill": skill_name,
                "file": filename,
            },
            None,
            AlwaysAllow(),
        )
        assert not output.startswith("error:"), (
            f"unresolvable payload reference {skill_name}/{filename}: "
            f"{output}"
        )
        assert not output.startswith(f'skill "{skill_name}" has no payload')


def test_payloads_txt_mentions_have_a_real_shipped_file(shipped_registry):
    referencing = {
        skill.name
        for skill in shipped_registry.list()
        if "payloads.txt" in skill.body
    }

    assert referencing
    missing = {
        skill_name
        for skill_name in referencing
        if not (SKILLS_ROOT / skill_name / "payloads.txt").is_file()
    }
    assert not missing, f"skills reference missing payloads.txt files: {missing}"


def test_finding_skills_document_required_production_arguments(
    shipped_registry,
    tmp_path,
):
    required = ConfirmFindingTool(
        Store(str(tmp_path / "findings"))
    ).schema()["required"]

    finding_skills = [
        skill
        for skill in shipped_registry.list()
        if "confirm_finding" in skill.tools
    ]
    assert finding_skills

    for skill in finding_skills:
        section = skill.body.split("Confirm an evidence-backed finding", 1)[1]
        missing = {
            field
            for field in required
            if re.search(rf"\b{re.escape(field)}\b", section) is None
        }
        assert not missing, (
            f"{skill.name} omits required confirm_finding arguments: "
            f"{sorted(missing)}"
        )


def test_documented_conformance_test_path_exists():
    readme = (SKILLS_ROOT / "README.md").read_text(encoding="utf-8")
    matches = re.findall(r"`(tests/skills/[^`]*conformance[^`]*)`", readme)

    assert matches
    for relative_path in matches:
        assert (REPO_ROOT / relative_path).is_file()
