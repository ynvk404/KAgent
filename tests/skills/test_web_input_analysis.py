"""
Contract tests for the web-input-analysis SKILL.md.

These tests validate the skill as a prompt/playbook contract rather than
executing curl, invoking an LLM, or probing a target. They are intentionally
stable against runtime/tool implementation changes.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml


def find_web_input_analysis_skill() -> Path:
    """Locate web-input-analysis/SKILL.md from the test file location."""
    here = Path(__file__).resolve()

    candidates = [
        here.parent / "web-input-analysis" / "SKILL.md",
        here.parent / "skills" / "web-input-analysis" / "SKILL.md",
        here.parent.parent / "skills" / "web-input-analysis" / "SKILL.md",
        here.parent.parent / "web-input-analysis" / "SKILL.md",
        here.parent.parent.parent / "skills" / "web-input-analysis" / "SKILL.md",
    ]

    for path in candidates:
        if path.is_file():
            return path

    for root in [here.parent, here.parent.parent, here.parent.parent.parent]:
        matches = list(root.rglob("web-input-analysis/SKILL.md"))
        if matches:
            return matches[0]

    raise FileNotFoundError(
        "Could not locate web-input-analysis/SKILL.md"
    )


@pytest.fixture(scope="module")
def skill_path() -> Path:
    return find_web_input_analysis_skill()


@pytest.fixture(scope="module")
def skill_text(skill_path: Path) -> str:
    return skill_path.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def flat_lower(skill_text: str) -> str:
    """
    skill_text lowercased with all whitespace (including the markdown
    hard-wrap line breaks the playbook uses at ~80 columns) collapsed to
    single spaces.

    Multi-word phrase assertions must match against this, not against
    ``skill_text.lower()`` directly — a phrase that happens to straddle a
    wrap point (e.g. "target\\nidentifier") will never match the
    single-line literal otherwise, which is a false failure, not a real
    contract break.
    """
    return re.sub(r"\s+", " ", skill_text.lower())


@pytest.fixture(scope="module")
def skill_frontmatter_and_body(
    skill_text: str,
) -> tuple[dict, str]:
    if not skill_text.startswith("---"):
        pytest.fail("SKILL.md must start with YAML frontmatter")

    parts = skill_text.split("---", 2)

    if len(parts) != 3:
        pytest.fail(
            "SKILL.md must contain YAML frontmatter delimited by ---"
        )

    raw_frontmatter = parts[1]
    body = parts[2].strip()

    frontmatter = yaml.safe_load(raw_frontmatter)

    if not isinstance(frontmatter, dict):
        pytest.fail("SKILL.md frontmatter must parse to a mapping")

    return frontmatter, body


# ---------------------------------------------------------------------------
# Frontmatter
# ---------------------------------------------------------------------------


def test_frontmatter_name(
    skill_frontmatter_and_body: tuple[dict, str],
) -> None:
    frontmatter, _ = skill_frontmatter_and_body

    assert frontmatter["name"] == "web-input-analysis"


def test_frontmatter_has_description(
    skill_frontmatter_and_body: tuple[dict, str],
) -> None:
    frontmatter, _ = skill_frontmatter_and_body

    description = frontmatter.get("description")

    assert isinstance(description, str)
    assert description.strip()


def test_frontmatter_allowed_tools(
    skill_frontmatter_and_body: tuple[dict, str],
) -> None:
    frontmatter, _ = skill_frontmatter_and_body

    assert frontmatter.get("allowed-tools") == [
        "shell",
        "http",
        "file_write",
        "workflow",
    ]


# ---------------------------------------------------------------------------
# Scope / phase contract
# ---------------------------------------------------------------------------


def test_skill_is_analysis_not_exploitation(
    flat_lower: str,
) -> None:
    assert "does not exploit anything" in flat_lower
    assert "does not produce findings" in flat_lower
    assert "not exploitation" in flat_lower

    assert "do not develop it further here" in flat_lower
    assert "do not decide a finding exists here" in flat_lower


def test_skill_requires_enumeration_inventory(
    skill_text: str,
    flat_lower: str,
) -> None:
    lower = skill_text.lower()

    assert "web-enumeration" in lower
    assert "inventory" in lower
    assert "inventory.md" in lower
    assert "a direct concrete validation request may bypass this analysis step" in flat_lower


def test_skill_has_explicit_preconditions(
    skill_text: str,
) -> None:
    assert "## Preconditions" in skill_text

    lower = skill_text.lower()

    assert "inventory doesn't exist or looks stale" in lower
    assert "go back to `web-enumeration`" in lower


# ---------------------------------------------------------------------------
# Candidate triage / context classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "marker",
    [
        "Reflected in HTML/JS output",
        "Object/resource identifier",
        "Query/filter-like",
        "Redirect/URL-like",
        "File/path-like",
        "State-changing action",
        "Structural/serialization-heavy",
    ],
)
def test_required_context_categories(
    skill_text: str,
    marker: str,
) -> None:
    assert marker in skill_text


def test_passive_analysis_is_preferred(
    flat_lower: str,
) -> None:
    assert "passive, no new requests" in flat_lower
    assert "most candidates should be classifiable from this alone" in flat_lower
    assert "prefer stopping at tier 1 or 2" in flat_lower


# ---------------------------------------------------------------------------
# Probe safety contract
# ---------------------------------------------------------------------------


def test_tiered_signal_gathering_exists(
    skill_text: str,
) -> None:
    assert "## 3. Light signal-gathering" in skill_text
    assert "Tier 1" in skill_text
    assert "Tier 2" in skill_text
    assert "Tier 3" in skill_text


def test_tier2_is_once_per_candidate(
    skill_text: str,
) -> None:
    lower = skill_text.lower()

    assert "at most once per candidate" in lower
    assert "unique, inert marker" in lower


def test_tier3_is_limited_and_not_confirmation(
    flat_lower: str,
) -> None:
    assert "at most one probe per parameter" in flat_lower
    assert "never a way to \"weakly confirm\"" in flat_lower
    # the playbook says "SQLi", not the spelled-out "SQL injection" — match
    # the actual term rather than a paraphrase of it
    assert "does not tell you sqli is present" in flat_lower
    assert "it is never a way to" in flat_lower


def test_no_exploit_escalation(
    flat_lower: str,
) -> None:
    forbidden_escalation_markers = [
        "union building",
        "payload escalation",
        "session hijacking",
        "data extraction",
        "sleep-based timing hit",
    ]

    for marker in forbidden_escalation_markers:
        assert marker in flat_lower

    assert "stop, do not develop it further here" in flat_lower


def test_sensitive_data_is_not_recorded(
    flat_lower: str,
) -> None:
    assert "do not copy pii/secrets into the candidate file" in flat_lower
    assert "returned data" in flat_lower
    assert "did not" in flat_lower


# ---------------------------------------------------------------------------
# Vulnerability-class routing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "context, suspected_class",
    [
        ("Reflected value, no/partial encoding", "cross-site-scripting"),
        (
            "Query/filter param + syntax-sensitive response",
            "sql-injection",
        ),
        (
            "Object identifier + no visible ownership check",
            "access-control",
        ),
        (
            "State-changing action referencing another user/object's ID",
            "access-control",
        ),
    ],
)
def test_active_class_mappings(
    skill_text: str,
    context: str,
    suspected_class: str,
) -> None:
    assert context in skill_text
    assert suspected_class in skill_text


def test_handoff_uses_enabled_skill_metadata(
    flat_lower: str,
) -> None:
    assert "loaded skill registry is the source of truth" in flat_lower
    assert "recommended_skills" in flat_lower
    assert "only `sql-injection`, `cross-site-scripting`, and `access-control`" not in flat_lower


@pytest.mark.parametrize(
    "deferred_context",
    [
        "Redirect-only behavior",
        "File/path-like",
        "Structural/serialization-heavy",
    ],
)
def test_unsupported_classes_are_deferred(
    skill_text: str,
    deferred_context: str,
) -> None:
    assert deferred_context in skill_text

    lower = skill_text.lower()
    assert "deferred" in lower
    assert "no validator handles a suspected class" in lower


def test_no_workflow_is_invented_for_inactive_classes(
    flat_lower: str,
) -> None:
    assert (
        "do not invent a workflow for a vulnerability class that doesn't "
        "have a skill yet"
    ) in flat_lower


# ---------------------------------------------------------------------------
# Prioritization contract
# ---------------------------------------------------------------------------


def test_prioritization_order_is_explicit(
    skill_text: str,
) -> None:
    assert "## 5. Prioritize" in skill_text

    lower = skill_text.lower()

    assert "confidence" in lower
    assert "reachability/auth" in lower
    assert "likely impact" in lower


@pytest.mark.parametrize(
    "level",
    ["High", "Medium", "Low"],
)
def test_priority_levels_are_defined(
    skill_text: str,
    level: str,
) -> None:
    assert level in skill_text


# ---------------------------------------------------------------------------
# Candidate output contract
# ---------------------------------------------------------------------------


def test_candidate_output_path(
    skill_text: str,
) -> None:
    assert "artifacts/web-input-analysis/<target>/candidates.md" in skill_text


@pytest.mark.parametrize(
    "field",
    [
        "endpoint:",
        "parameter:",
        "location:",
        "context:",
        "signal:",
        "suspected_class:",
        "confidence:",
        "rationale:",
        "recommended_next_skill:",
    ],
)
def test_candidate_schema_contains_required_fields(
    skill_text: str,
    field: str,
) -> None:
    assert field in skill_text


def test_candidate_output_does_not_include_poc_or_exploit(
    skill_text: str,
) -> None:
    lower = skill_text.lower()

    assert "do not include a `poc` or `exploit` field" in lower


def test_handoff_is_explicit(
    skill_text: str,
) -> None:
    assert "## 7. Handoff" in skill_text

    lower = skill_text.lower()

    assert "hand off only the candidates relevant to each skill" in lower
    assert "sql-injection" in lower
    assert "cross-site-scripting" in lower
    assert "access-control" in lower


# ---------------------------------------------------------------------------
# Target / file consistency
# ---------------------------------------------------------------------------


def test_target_identifier_reuses_recon_convention(
    flat_lower: str,
) -> None:
    assert "recon/skill.md" in flat_lower
    assert "target identifier convention" in flat_lower
    assert "reuse that identifier exactly" in flat_lower
    assert "do not re-derive it differently here" in flat_lower


def test_real_values_required(
    flat_lower: str,
) -> None:
    assert "substitute real values before running commands" in flat_lower
    assert "never write literal placeholders to files" in flat_lower


def test_no_scanner_or_exploitation_frameworks(
    flat_lower: str,
) -> None:
    assert "does not need scanners" in flat_lower
    assert "does not need exploitation frameworks" in flat_lower
    assert "sqlmap" in flat_lower
    assert "nuclei" in flat_lower


# ---------------------------------------------------------------------------
# Stop conditions
# ---------------------------------------------------------------------------


def test_stop_conditions_exist(
    skill_text: str,
) -> None:
    assert "## Stop conditions" in skill_text

    lower = skill_text.lower()

    assert "every inventory entry has been triaged" in lower
    assert "no probe has escalated into an actual exploit or proof" in lower
    assert "do not decide a finding exists here" in lower


def test_skill_has_no_finding_confirmation_workflow(
    skill_text: str,
) -> None:
    lower = skill_text.lower()

    assert "does not produce findings" in lower
    assert "confirmation and poc" in lower
    assert "vulnerability-specific skill" in lower


# ---------------------------------------------------------------------------
# Structural section order
# ---------------------------------------------------------------------------


def test_major_sections_appear_in_order(
    skill_text: str,
) -> None:
    expected = [
        "## Preconditions",
        "## 1. Load and triage the inventory",
        "## 2. Classify context for each candidate",
        "## 3. Light signal-gathering",
        "## 4. Map signals to a suspected vulnerability class",
        "## 5. Prioritize",
        "## 6. Build the candidate list",
        "## 7. Handoff",
        "## Stop conditions",
    ]

    positions = []

    for section in expected:
        pos = skill_text.find(section)
        assert pos != -1, f"Missing section: {section}"
        positions.append(pos)

    assert positions == sorted(positions)


# ---------------------------------------------------------------------------
# Placeholder / template hygiene
# ---------------------------------------------------------------------------


def test_examples_do_not_become_runtime_defaults(
    flat_lower: str,
) -> None:
    """
    The SKILL may contain example URLs, but it must explicitly say they are
    examples/replacements rather than literal runtime values.
    """
    assert "replace with the real target" in flat_lower
    assert "substitute real values before running commands" in flat_lower


def test_target_placeholder_is_only_used_as_identifier_in_output_paths(
    flat_lower: str,
) -> None:
    """
    Keep the convention that <target> means the derived identifier, not the
    raw URL. This protects downstream file consistency.
    """
    assert "below always refers to the identifier" in flat_lower
    assert "same target identifier as `recon`" in flat_lower
    assert "same target identifier as `recon` and `web-enumeration`" in flat_lower


# ---------------------------------------------------------------------------
# Basic quality guard against accidental prompt truncation
# ---------------------------------------------------------------------------


def test_skill_is_nontrivial_length(
    skill_text: str,
) -> None:
    # This is intentionally a loose lower bound: a large playbook should not
    # silently collapse into a tiny prompt during future refactoring.
    assert len(skill_text) >= 7000


def test_no_unclosed_fenced_code_blocks(
    skill_text: str,
) -> None:
    fences = re.findall(r"^```", skill_text, flags=re.MULTILINE)
    assert len(fences) % 2 == 0


def test_no_placeholder_angle_tokens(
    skill_text: str,
) -> None:
    """
    Real templates such as <target> are allowed by the contract, but raw
    angle placeholders inside shell examples should not accidentally become
    executable literals.
    """
    for line in skill_text.splitlines():
        stripped = line.strip()

        if not stripped.startswith(("curl ", "TARGET=", "APEX=")):
            continue

        assert "<TARGET>" not in stripped
        assert "<HOST>" not in stripped
        assert "<APEX>" not in stripped
