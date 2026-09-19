import logging
import re
from pathlib import Path

import pytest

from src.skills.registry import (
    Registry,
    Skill,
    SkillMetadataError,
    SkillTriggers,
    normalize_candidate_class,
    parse_skill,
    validate_skill,
    materialize_skill_body,
)

def write_skill(tmp_path: Path, dirname: str, content: str) -> Path:
    d = tmp_path / dirname
    d.mkdir(parents=True, exist_ok=True)
    f = d / "SKILL.md"
    f.write_text(content, encoding="utf-8", newline="")
    return f

def test_frontmatter_with_triple_dash_in_value(tmp_path):
    content = (
        "---\n"
        'name: mytool\n'
        'description: "A---B workflow"\n'
        "allowed-tools: []\n"
        "---\n"
        "\n"
        "# Body\n"
        "Some content here that is long enough to be meaningful.\n"
    )
    f = write_skill(tmp_path, "mytool", content)

    skill = parse_skill(f)

    assert skill.name == "mytool"
    assert skill.description == "A---B workflow"
    assert "name: mytool" not in skill.body
    assert skill.body.startswith("# Body")

def test_frontmatter_crlf_line_endings(tmp_path):
    content = (
        "---\r\n"
        "name: crlf-tool\r\n"
        "description: uses CRLF\r\n"
        "allowed-tools: []\r\n"
        "---\r\n"
        "\r\n"
        "# Body\r\n"
        "content\r\n"
    )
    f = write_skill(tmp_path, "crlf-tool", content)

    skill = parse_skill(f)

    assert skill.name == "crlf-tool"
    assert skill.description == "uses CRLF"
    assert skill.body.startswith("# Body")

def test_missing_allowed_tools_is_rejected(tmp_path):
    content = "---\nname: plain-dir\ndescription: missing tools\n---\nBody\n"
    f = write_skill(tmp_path, "plain-dir", content)

    with pytest.raises(SkillMetadataError, match="missing required `allowed-tools`"):
        parse_skill(f)

def test_frontmatter_non_dict_is_rejected(tmp_path):
    content = (
        "---\n"
        "- item1\n"
        "- item2\n"
        "---\n"
        "\n"
        "# Body\n"
    )
    f = write_skill(tmp_path, "non-dict-fm", content)

    with pytest.raises(SkillMetadataError, match="frontmatter must be a mapping"):
        parse_skill(f)

@pytest.mark.parametrize(
    "key",
    ["allowed-tools", "allowedTools", "tools"],
)
def test_tools_key_variants(tmp_path, key):
    content = (
        "---\n"
        "name: tool-variant\n"
        "description: test\n"
        f"{key}:\n"
        "  - bash\n"
        "  - web_search\n"
        "---\n"
        "\n"
        "Body\n"
    )
    f = write_skill(tmp_path, f"variant-{key}", content)

    skill = parse_skill(f)

    assert skill.tools == ["bash", "web_search"]

def test_tools_key_priority_order(tmp_path):
    content = (
        "---\n"
        "name: priority-tool\n"
        "description: test\n"
        "allowed-tools:\n"
        "  - preferred\n"
        "allowedTools:\n"
        "  - second\n"
        "tools:\n"
        "  - third\n"
        "---\n"
        "\n"
        "Body\n"
    )
    f = write_skill(tmp_path, "priority-tool", content)

    skill = parse_skill(f)

    assert skill.tools == ["preferred"]

def test_explicit_empty_tools_list_is_respected(tmp_path):
    content = (
        "---\n"
        "name: empty-tools\n"
        "description: test\n"
        "allowed-tools: []\n"
        "allowedTools:\n"
        "  - should-not-be-used\n"
        "---\n"
        "\n"
        "Body\n"
    )
    f = write_skill(tmp_path, "empty-tools", content)

    skill = parse_skill(f)

    assert skill.tools == []

def test_tools_not_a_list_is_rejected(tmp_path):
    content = (
        "---\n"
        "name: bad-tools\n"
        "description: test\n"
        "allowed-tools: bash\n"
        "---\n"
        "\n"
        "Body\n"
    )
    f = write_skill(tmp_path, "bad-tools", content)

    with pytest.raises(SkillMetadataError, match="must be a list"):
        parse_skill(f)

def test_tools_rejects_non_string_entries(tmp_path):
    content = (
        "---\n"
        "name: mixed-tools\n"
        "description: test\n"
        "allowed-tools:\n"
        "  - bash\n"
        "  - 42\n"
        "  - true\n"
        "  - web_search\n"
        "---\n"
        "\n"
        "Body\n"
    )
    f = write_skill(tmp_path, "mixed-tools", content)

    with pytest.raises(SkillMetadataError, match="non-empty strings"):
        parse_skill(f)

@pytest.mark.parametrize("key", ["disable-model-invocation", "disableModelInvocation"])
def test_disable_model_invocation_true(tmp_path, key):
    content = (
        "---\n"
        "name: disabled-tool\n"
        "description: test\n"
        "allowed-tools: []\n"
        f"{key}: true\n"
        "---\n"
        "\n"
        "Body\n"
    )
    f = write_skill(tmp_path, f"disabled-{key}", content)

    skill = parse_skill(f)

    assert skill.disable_model_invocation is True

def test_disable_model_invocation_default_false(tmp_path):
    content = (
        "---\n"
        "name: normal-tool\n"
        "description: test\n"
        "allowed-tools: []\n"
        "---\n"
        "\n"
        "Body\n"
    )
    f = write_skill(tmp_path, "normal-tool", content)

    skill = parse_skill(f)

    assert skill.disable_model_invocation is False

def test_disable_model_invocation_non_bool_is_rejected(tmp_path):
    content = (
        "---\n"
        "name: stringy-flag\n"
        "description: test\n"
        "allowed-tools: []\n"
        'disable-model-invocation: "true"\n'
        "---\n"
        "\n"
        "Body\n"
    )
    f = write_skill(tmp_path, "stringy-flag", content)

    with pytest.raises(SkillMetadataError, match="must be a boolean"):
        parse_skill(f)

def test_load_dir_skips_hidden_and_template_dirs(tmp_path):
    write_skill(tmp_path, "visible", "---\nname: visible\ndescription: d\nallowed-tools: []\n---\nBody\n")
    write_skill(tmp_path, ".hidden", "---\nname: hidden\ndescription: d\nallowed-tools: []\n---\nBody\n")
    write_skill(tmp_path, "_template", "---\nname: template\ndescription: d\nallowed-tools: []\n---\nBody\n")

    r = Registry()
    r.load_dir(tmp_path)

    names = [x.name for x in r.list()]

    assert "visible" in names
    assert "hidden" not in names
    assert "template" not in names

def test_load_dir_skips_non_directory_items(tmp_path):
    (tmp_path / "stray.txt").write_text("not a skill dir", encoding="utf-8")
    write_skill(tmp_path, "real-skill", "---\nname: real-skill\ndescription: d\nallowed-tools: []\n---\nBody\n")

    r = Registry()
    r.load_dir(tmp_path)

    names = [x.name for x in r.list()]

    assert names == ["real-skill"]

def test_load_dir_skips_dir_without_skill_md(tmp_path):
    empty_dir = tmp_path / "no-skill-here"
    empty_dir.mkdir()
    write_skill(tmp_path, "has-skill", "---\nname: has-skill\ndescription: d\nallowed-tools: []\n---\nBody\n")

    r = Registry()
    r.load_dir(tmp_path)

    names = [x.name for x in r.list()]

    assert names == ["has-skill"]

def test_load_dir_skips_broken_skill_but_loads_rest(tmp_path, monkeypatch):
    write_skill(tmp_path, "good-skill", "---\nname: good-skill\ndescription: d\nallowed-tools: []\n---\nBody\n")
    write_skill(tmp_path, "broken-skill", "---\nname: broken-skill\ndescription: d\nallowed-tools: []\n---\nBody\n")

    import src.skills.registry as registry_mod

    original_parse = registry_mod.parse_skill

    def flaky_parse(path):
        if "broken-skill" in str(path):
            raise ValueError("boom")
        return original_parse(path)

    monkeypatch.setattr(registry_mod, "parse_skill", flaky_parse)

    r = Registry()
    r.load_dir(tmp_path)

    names = [x.name for x in r.list()]

    assert "good-skill" in names
    assert "broken-skill" not in names


def test_load_dir_duplicate_metadata_names_have_stable_precedence(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    write_skill(first, "duplicate", "---\nname: duplicate\ndescription: first\nallowed-tools: []\n---\nBody\n")
    write_skill(second, "duplicate", "---\nname: duplicate\ndescription: last\nallowed-tools: []\n---\nBody\n")

    registry = Registry()
    registry.load_dir(first)
    registry.load_dir(second)

    skill = registry.get("duplicate")
    assert skill is not None
    assert skill.description == "last"

def test_get_has_clear(tmp_path):
    write_skill(tmp_path, "alpha", "---\nname: alpha\ndescription: d\nallowed-tools: []\n---\nBody\n")

    r = Registry()
    r.load_dir(tmp_path)

    assert r.has("alpha") is True
    assert r.has("missing") is False

    skill = r.get("alpha")
    assert skill is not None
    assert skill.name == "alpha"

    assert r.get("missing") is None

    r.clear()

    assert r.list() == []
    assert r.has("alpha") is False

def test_clear_does_not_touch_disabled_set(tmp_path):
    write_skill(tmp_path, "alpha", "---\nname: alpha\ndescription: d\nallowed-tools: []\n---\nBody\n")

    r = Registry()
    r.load_dir(tmp_path)
    r.set_disabled("alpha", True)

    r.clear()

    assert r.list() == []
    assert r.is_disabled("alpha") is True

def make_skill(
    name: str = "valid-skill",
    description: str = "A valid description",
    tools: list[str] | None = None,
    disable_model_invocation: bool = False,
    path: str = "/skills/valid-skill/SKILL.md",
    body: str = "body",
    stage: str | None = None,
    triggers: SkillTriggers | None = None,
    candidate_classes: list[str] | None = None,
    requires: list[str] | None = None,
) -> Skill:
    return Skill(
        name=name,
        description=description,
        tools=tools if tools is not None else ["bash"],
        disable_model_invocation=disable_model_invocation,
        path=path,
        body=body,
        stage=stage,  # type: ignore[arg-type]
        triggers=triggers or SkillTriggers(),
        candidate_classes=candidate_classes or [],
        requires=requires or [],
    )

def test_validate_skill_valid_case():
    skill = make_skill()
    errors = validate_skill(skill, known_tools={"bash", "web_search"})
    assert errors == []

def test_validate_skill_missing_name():
    skill = make_skill(name="")
    errors = validate_skill(skill, known_tools=set())
    assert any("missing `name`" in e for e in errors)

def test_validate_skill_name_not_kebab_case():
    skill = make_skill(name="Invalid_Name", path="/skills/Invalid_Name/SKILL.md")
    errors = validate_skill(skill, known_tools=set())
    assert any("lowercase-kebab" in e for e in errors)

def test_validate_skill_name_does_not_match_directory():
    skill = make_skill(name="foo", path="/skills/bar/SKILL.md")
    errors = validate_skill(skill, known_tools=set())
    assert any("does not match its directory" in e for e in errors)

def test_validate_skill_missing_description():
    skill = make_skill(description="")
    errors = validate_skill(skill, known_tools=set())
    assert any("missing `description`" in e for e in errors)

def test_validate_skill_description_too_long():
    skill = make_skill(description="x" * 1025)
    errors = validate_skill(skill, known_tools=set())
    assert any("max 1024" in e for e in errors)

def test_validate_skill_unknown_tool():
    skill = make_skill(tools=["bash", "made-up-tool"])
    errors = validate_skill(skill, known_tools={"bash"})
    assert any('"made-up-tool" is not a known tool' in e for e in errors)


def test_parse_complete_selection_metadata(tmp_path):
    skill_file = write_skill(
        tmp_path,
        "xxe",
        """---
name: xxe
description: Validate XML external entity candidates.
stage: validation
triggers:
  strong:
    - XML external entity
    - XXE
  weak:
    - XML parser
candidate-classes:
  - xxe
requires:
  - web_input_analysis
allowed-tools:
  - http
disable-model-invocation: false
---
Body
""",
    )

    skill = parse_skill(skill_file)

    assert skill.stage == "validation"
    assert skill.triggers.strong == ["xml external entity", "xxe"]
    assert skill.triggers.weak == ["xml parser"]
    assert skill.candidate_classes == ["xxe"]
    assert skill.requires == ["web-input-analysis"]
    assert skill.disable_model_invocation is False


def test_absent_optional_selection_metadata_has_safe_defaults(tmp_path):
    skill_file = write_skill(
        tmp_path,
        "simple",
        "---\nname: simple\ndescription: Legacy simple skill\nallowed-tools: []\n---\nBody\n",
    )

    skill = parse_skill(skill_file)

    assert skill.stage is None
    assert skill.triggers == SkillTriggers()
    assert skill.candidate_classes == []
    assert skill.requires == []


@pytest.mark.parametrize(
    ("metadata", "message"),
    [
        ("stage: exploitation", "unknown `stage`"),
        ("triggers: [xxe]", "`triggers` must be a mapping"),
        ("triggers:\n  strong: xxe", "`triggers.strong` must be a list"),
        ("triggers:\n  other: [xxe]", "unknown keys"),
        ("candidate-classes: xxe", "`candidate-classes` must be a list"),
        ("requires: web-input-analysis", "`requires` must be a list"),
    ],
)
def test_malformed_selection_metadata_is_rejected(tmp_path, metadata, message):
    skill_file = write_skill(
        tmp_path,
        "broken",
        "---\nname: broken\ndescription: Broken metadata\n"
        "allowed-tools: []\n"
        f"{metadata}\n---\nBody\n",
    )

    with pytest.raises(SkillMetadataError, match=re.escape(message)):
        parse_skill(skill_file)


def test_candidate_class_alias_normalization():
    assert normalize_candidate_class("SQLI") == "sql-injection"
    assert normalize_candidate_class("xss") == "cross-site-scripting"
    assert normalize_candidate_class("IDOR") == "access-control"
    assert normalize_candidate_class("bola") == "access-control"
    assert normalize_candidate_class("XXE") == "xxe"


def test_validate_skill_accepts_optional_external_tool_prefixes():
    skill = make_skill(tools=["bash", "mcp_burp_repeater", "plugin_custom"])
    errors = validate_skill(skill, known_tools={"bash"})

    assert errors == []


def test_validate_skill_reports_missing_prerequisite():
    skill = make_skill(requires=["missing-skill"])
    errors = validate_skill(
        skill,
        known_tools={"bash"},
        known_skills={"valid-skill"},
    )

    assert any('"missing-skill" is not a loaded skill' in error for error in errors)


def test_registry_validation_uses_loaded_skill_and_tool_sets():
    registry = Registry()
    registry.add(make_skill(requires=["missing"], tools=["ghost"]))

    errors = registry.validation_errors(known_tools={"bash"})

    assert "valid-skill" in errors
    assert any("not a known tool" in error for error in errors["valid-skill"])
    assert any("not a loaded skill" in error for error in errors["valid-skill"])

def test_validate_skill_multiple_errors_accumulate():
    skill = make_skill(name="", description="", tools=["ghost"])
    errors = validate_skill(skill, known_tools=set())
    assert len(errors) >= 3

def test_materialize_skill_body_replaces_skill_dir():
    skill = make_skill(
        name="tool-x",
        path="/opt/skills/tool-x/SKILL.md",
        body="Run ${SKILL_DIR}/scripts/run.sh for setup.",
    )

    materialized = materialize_skill_body(skill)

    assert materialized.startswith("# Skill: tool-x\n\n")
    assert "/opt/skills/tool-x/scripts/run.sh" in materialized
    assert "${SKILL_DIR}" not in materialized

def test_materialize_skill_body_no_placeholder_still_adds_header():
    skill = make_skill(name="tool-y", body="No placeholder here.")

    materialized = materialize_skill_body(skill)

    assert materialized == "# Skill: tool-y\n\nNo placeholder here."

def test_load_dir_reports_bad_skill_instead_of_printing(tmp_path, caplog, capsys):
    skill_dir = tmp_path / "broken"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: \"unterminated\nfoo: [\n---\n\nbody\n", encoding="utf-8"
    )

    registry = Registry()
    with caplog.at_level(logging.WARNING, logger="kagent.skills.registry"):
        registry.load_dir(tmp_path)

    assert registry.list() == []
    assert capsys.readouterr().out == ""
    assert any("broken/SKILL.md" in r.getMessage() for r in caplog.records)
