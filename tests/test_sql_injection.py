from __future__ import annotations

import asyncio
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml


# ============================================================================
# Paths
# ============================================================================

ROOT = Path(__file__).resolve().parents[1]

SKILLS_DIR = ROOT / "skills"
SQLI_DIR = SKILLS_DIR / "sql-injection"
SQLI_FILE = SQLI_DIR / "SKILL.md"

EXPECTED_ALLOWED_TOOLS = {
    "shell",
    "http",
    "file_write",
}

VALID_OUTCOMES = {
    "confirmed",
    "not confirmed",
    "blocked",
    "deferred (nosql, out of scope)",
}


# ============================================================================
# Helpers
# ============================================================================

def read_skill_text() -> str:
    """
    Raw file bytes, preserving line breaks. Use this only when line
    structure matters (frontmatter parsing, code-block scoping). For
    prose/substring checks, use normalized_text() instead — SKILL.md is
    hard-wrapped at ~79 cols, so a phrase that reads as one sentence can
    still contain a literal newline between two of its words.
    """
    assert SQLI_FILE.is_file(), f"Missing skill file: {SQLI_FILE}"
    return SQLI_FILE.read_text(encoding="utf-8")


def normalized_text() -> str:
    """
    Same content as read_skill_text(), with every run of whitespace
    (including newlines from hard-wrapping) collapsed to a single space.
    Use this for substring assertions against prose spanning a wrapped
    line, so line-wrap position isn't part of the test.
    """
    return re.sub(r"\s+", " ", read_skill_text())


def parse_frontmatter(raw: str) -> dict:
    assert raw.startswith("---"), "SKILL.md must start with frontmatter"

    match = re.match(
        r"\A---[ \t]*\r?\n(?P<yaml>.*?)\r?\n---[ \t]*\r?\n?",
        raw,
        re.DOTALL,
    )

    assert match is not None, "Invalid SKILL.md frontmatter"

    metadata = yaml.safe_load(match.group("yaml"))
    assert isinstance(metadata, dict)

    return metadata


def skill_body(raw: str) -> str:
    match = re.match(
        r"\A---[ \t]*\r?\n(?P<yaml>.*?)\r?\n---[ \t]*\r?\n?",
        raw,
        re.DOTALL,
    )

    assert match is not None

    body = raw[match.end():]
    return re.sub(r"\A(?:\r?\n)+", "", body)


def load_registry():
    """
    Uses the real Registry implementation from the project.
    """
    from src.skills.registry import Registry

    registry = Registry()
    registry.load_dir(SKILLS_DIR)
    return registry


def sql_injection_skill():
    registry = load_registry()

    skill = registry.get("sql-injection")

    assert skill is not None, (
        "sql-injection was not loaded into the Registry"
    )

    return skill


def extract_allowed_tools(skill) -> set[str]:
    return set(skill.tools)


# ============================================================================
# Layer 1 - Static
# ============================================================================

def test_sql_injection_skill_file_exists():
    assert SQLI_FILE.is_file()


def test_sql_injection_frontmatter_is_valid():
    metadata = parse_frontmatter(read_skill_text())

    assert metadata["name"] == "sql-injection"
    assert isinstance(metadata["description"], str)
    assert metadata["description"].strip()


def test_sql_injection_name_matches_directory():
    skill = sql_injection_skill()

    assert skill.name == "sql-injection"
    assert Path(skill.path).parent.name == "sql-injection"


def test_sql_injection_allowed_tools_are_exact():
    skill = sql_injection_skill()

    assert extract_allowed_tools(skill) == EXPECTED_ALLOWED_TOOLS


def test_sql_injection_allowed_tools_are_known():
    """
    Uses the exact KNOWN_TOOL_NAMES from the project's current policy.
    """
    known_tools = {
        "shell",
        "bash",
        "BashTool",
        "file_read",
        "FileReadTool",
        "file_write",
        "FileWriteTool",
        "file_edit",
        "FileEditTool",
        "glob",
        "GlobTool",
        "grep",
        "GrepTool",
        "http",
        "web_fetch",
        "web_search",
        "ask",
        "ask_user",
        "confirm_finding",
        "load_skill",
        "read_payloads",
        "read_skill_file",
        "coverage",
    }

    skill = sql_injection_skill()

    assert set(skill.tools) <= known_tools


def test_sql_injection_passes_registry_validation():
    from src.skills.registry import validate_skill

    skill = sql_injection_skill()

    known_tools = {
        "shell",
        "bash",
        "BashTool",
        "file_read",
        "FileReadTool",
        "file_write",
        "FileWriteTool",
        "file_edit",
        "FileEditTool",
        "glob",
        "GlobTool",
        "grep",
        "GrepTool",
        "http",
        "web_fetch",
        "web_search",
        "ask",
        "ask_user",
        "confirm_finding",
        "load_skill",
        "read_payloads",
        "read_skill_file",
        "coverage",
    }

    errors = validate_skill(skill, known_tools)

    assert errors == []


def test_sql_injection_description_is_within_registry_limit():
    from src.skills.registry import MAX_DESCRIPTION

    skill = sql_injection_skill()

    assert len(skill.description) <= MAX_DESCRIPTION


def test_sql_injection_has_no_unresolved_placeholders():
    """
    Guards against literal, un-substituted placeholders being written to
    files or commands (the thing the skill's own "Execution rule"
    prohibits) — e.g. a stray `<TARGET>` left in a curl command instead of
    the real host.

    This is deliberately narrower than "no angle-bracket token anywhere":
    the lowercase `<target>` token is this skill's (and recon's,
    web-enumeration's, web-input-analysis's) documented convention for
    referring to the *derived identifier* in prose and output paths, e.g.
    `sql-injection/<target>/results.md`. That usage is intentional and
    shared across the whole skill pipeline, so it is excluded here rather
    than flagged.
    """
    text = read_skill_text()

    forbidden = [
        "<TARGET>",
        "<PARAM>",
        "<VALUE>",
        "<HOST>",
        "<APEX>",
        "<endpoint>",
        "<parameter>",
        "<param>",
        "<value>",
    ]

    for marker in forbidden:
        assert marker not in text, f"unresolved placeholder found: {marker}"


def test_sql_injection_target_placeholder_only_used_as_documented_identifier():
    """
    Every occurrence of the lowercase `<target>` convention token should
    sit next to path- or identifier-like context (a slash, a backtick, or
    the word "identifier") rather than appearing as a stray unresolved
    value inside a runnable command.
    """
    text = read_skill_text()

    for match in re.finditer(r"<target>", text):
        start, end = match.span()
        window = text[max(0, start - 40): end + 40]
        assert (
            "/" in window
            or "identifier" in window.lower()
            or "`" in window
        ), f"unexpected bare <target> usage: {window!r}"


def test_sql_injection_scope_is_sql_only():
    text = normalized_text().lower()

    assert "sql injection only" in text
    assert "nosql/operator injection" in text
    assert "out of scope" in text


# ============================================================================
# Layer 2 - Explicit skill load
# ============================================================================

def test_sql_injection_is_discoverable_without_decision_planner():
    registry = load_registry()

    assert registry.has("sql-injection")
    assert registry.get("sql-injection") is not None


def test_sql_injection_can_be_loaded_explicitly():
    """
    Tests the actual LoadSkillTool path without decision_planner.
    """
    from src.skills.load_skill import LoadSkillTool

    registry = load_registry()
    tool = LoadSkillTool(registry)

    body = asyncio.run(
        tool.run({"name": "sql-injection"})
    )

    assert isinstance(body, str)
    assert body.startswith("# Skill: sql-injection")
    assert "SQL injection playbook" in body


def test_sql_injection_is_model_invocable():
    skill = sql_injection_skill()

    assert skill.disable_model_invocation is False


# ============================================================================
# Layer 3 - Behavioral contract
# ============================================================================

def test_error_based_path_is_defined():
    text = normalized_text().lower()

    assert "error-based" in text
    assert "single quote" in text
    assert "clear db error string" in text


def test_boolean_based_path_is_defined():
    text = normalized_text().lower()

    assert "boolean-based differential check" in text
    assert "1=1" in text
    assert "1=2" in text
    assert "repeat once" in text


def test_time_based_path_is_defined():
    text = normalized_text().lower()

    assert "time-based check" in text
    assert "sleep(5)" in text
    assert "repeatability" in text


def test_waf_and_rate_limit_are_blocked():
    text = normalized_text().lower()

    assert "403" in text
    assert "429" in text
    assert "blocked" in text
    assert "filter-bypass" in text


def test_nosql_is_deferred():
    text = normalized_text().lower()

    assert "deferred (nosql, out of scope)" in text


def test_authentication_context_is_preserved():
    text = normalized_text().lower()

    assert "session cookie" in text
    assert "authorization" in text
    assert "csrf token" in text
    assert "preserve the original request structure" in text


def test_post_json_context_is_supported():
    text = normalized_text().lower()

    assert "post/json" in text
    assert "application/json" in text
    assert "json body" in text


def test_second_order_is_recorded_not_automatically_chased():
    text = normalized_text().lower()

    assert "second-order-suspected" in text
    assert (
        "do not automatically build or run a multi-request confirmation "
        "flow" in text
    )


# ============================================================================
# Layer 4 - Output contract
# ============================================================================

def test_results_file_path_is_defined():
    text = normalized_text()

    expected = "sql-injection/<target>/results.md"

    assert expected in text


def test_results_file_uses_same_target_identifier():
    text = normalized_text().lower()

    assert (
        "same target identifier as `recon`, `web-enumeration`, and" in text
    )
    assert "web-input-analysis" in text


def test_results_require_exactly_one_outcome():
    text = normalized_text().lower()

    assert "every candidate gets exactly one outcome" in text

    for outcome in VALID_OUTCOMES:
        assert outcome in text


def test_results_record_every_candidate():
    text = normalized_text().lower()

    assert "every candidate, regardless of outcome" in text
    assert "confirmed, not confirmed, blocked, or deferred" in text


def test_results_do_not_store_full_response_bodies():
    text = normalized_text().lower()

    assert "not full response bodies" in text
    assert "never response bodies containing real user data" in text


def test_results_record_evidence():
    text = normalized_text().lower()

    required = [
        "technique(s) tried",
        "status/size/timing deltas",
        "apparent db engine",
        "injection context",
        "scope of proof obtained",
    ]

    for item in required:
        assert item in text


# ============================================================================
# Layer 5 - Guardrails
# ============================================================================

def test_confirm_finding_is_not_allowed():
    skill = sql_injection_skill()

    assert "confirm_finding" not in skill.tools


def test_sqlmap_is_not_allowed_as_default():
    text = normalized_text().lower()

    assert "sqlmap" in text
    assert "do not reach for `sqlmap`" in text


def test_ghauri_is_not_allowed_as_default():
    text = normalized_text().lower()

    assert "ghauri" in text


def test_union_select_extraction_is_forbidden():
    text = normalized_text().lower()

    assert "union select" in text
    assert "do not" in text


def test_real_data_extraction_is_forbidden():
    text = normalized_text().lower()

    forbidden_concepts = [
        "credentials",
        "session tokens",
        "real row data",
        "dump table",
    ]

    for concept in forbidden_concepts:
        assert concept in text


def test_file_write_is_allowed_for_results():
    skill = sql_injection_skill()

    assert "file_write" in skill.tools


def test_http_is_allowed():
    skill = sql_injection_skill()

    assert "http" in skill.tools


def test_shell_is_allowed():
    skill = sql_injection_skill()

    assert "shell" in skill.tools


def test_skill_stops_after_sufficient_proof():
    text = normalized_text().lower()

    assert "stop probing that candidate" in text
    assert "clear, repeatable positive signal" in text
    assert "stop the skill entirely" in text


def test_skill_does_not_create_final_finding():
    text = normalized_text().lower()

    assert "does not create a final finding itself" in text
    assert "finding-validation" in text


def test_blocked_candidate_is_not_treated_as_negative():
    text = normalized_text().lower()

    assert "a `blocked` result is distinct from `not confirmed`" in text


def test_skill_does_not_retry_waf_with_bypass():
    text = normalized_text().lower()

    assert (
        "don't retry with encoding tricks or filter-bypass variants"
        in text
    )


# ============================================================================
# Layer 6 - Decision planner
# ============================================================================

def _load_decision_planner():
    try:
        from src.agent import decision_planner
    except ImportError:
        pytest.skip("decision_planner module is unavailable")

    return decision_planner


def test_sql_injection_planner_registration():
    planner = _load_decision_planner()

    intent_to_skill = getattr(planner, "INTENT_TO_SKILL", None)

    if intent_to_skill is None:
        pytest.skip("INTENT_TO_SKILL is not exposed")

    # Before rollout this should skip, not fail: sql_injection is
    # deliberately not registered in decision_planner.py yet (see the
    # NOTE above INTENT_TO_SKILL in that module). Registering it early
    # is a separate, later step gated on completing the skill's own
    # rollout checklist, not on this test suite passing.
    if "sql_injection" not in intent_to_skill:
        pytest.skip(
            "sql_injection has not been rolled out into decision_planner.py"
        )

    assert intent_to_skill["sql_injection"] == "sql-injection"


def test_sql_injection_planner_keywords():
    planner = _load_decision_planner()

    intent_keywords = getattr(planner, "INTENT_KEYWORDS", None)

    if intent_keywords is None:
        pytest.skip("INTENT_KEYWORDS is not exposed")

    if "sql_injection" not in intent_keywords:
        pytest.skip(
            "sql_injection has not been rolled out into decision_planner.py"
        )

    keywords = intent_keywords["sql_injection"]

    assert isinstance(keywords, dict)
    assert "strong" in keywords
    assert "weak" in keywords

    strong = {str(x).lower() for x in keywords["strong"]}

    assert "sql injection" in strong
    assert "sqli" in strong


def _make_stub_skills(names):
    """
    A minimal stand-in for src.skills.registry.Skill.

    recommend_skill()/detect_intent() only ever read `skill.name` off each
    entry in the `skills` list (to build `available_skill_names`), so a
    duck-typed object with just a `.name` attribute is sufficient — this
    deliberately avoids importing the real Skill class, whose constructor
    signature/module path isn't guaranteed by anything this test suite has
    confirmed (see the src.skills.tool import mixup earlier in this file's
    history).
    """
    return [SimpleNamespace(name=name) for name in names]


@pytest.mark.parametrize(
    "text",
    [
        "check this parameter for sql injection",
        "test this endpoint for sqli",
        "is this parameter injectable with SQL injection",
    ],
)
def test_sql_injection_recommendation(text):
    planner = _load_decision_planner()

    intent_to_skill = getattr(planner, "INTENT_TO_SKILL", None)
    intent_keywords = getattr(planner, "INTENT_KEYWORDS", None)

    if (
        not isinstance(intent_to_skill, dict)
        or "sql_injection" not in intent_to_skill
        or not isinstance(intent_keywords, dict)
        or "sql_injection" not in intent_keywords
    ):
        pytest.skip(
            "sql_injection intent is not rolled out yet"
        )

    recommend_skill = getattr(planner, "recommend_skill", None)
    normalize = getattr(planner, "normalize", None)

    # Deliberately not using callable() here: pyright/Pylance narrows a
    # callable()-checked value's type to Callable[..., object], which
    # erases the return type to plain `object` and breaks result["name"]
    # below with "__getitem__ not defined on object" — even though the
    # actual runtime value (via getattr) is a real function. An identity
    # check against None avoids that erasure while still catching the
    # "attribute doesn't exist" case (getattr's default).
    if recommend_skill is None or normalize is None:
        pytest.skip(
            "recommend_skill/normalize are not exposed by decision_planner"
        )

    skills = _make_stub_skills(
        set(intent_to_skill.values()) | {"sql-injection"}
    )

    normalized = normalize(text)
    result = recommend_skill(normalized, skills)

    assert result is not None, (
        f"planner returned no recommendation for SQLi intent: {text!r}"
    )

    assert result["name"] == "sql-injection", (
        f"expected sql-injection for {text!r}, got {result!r}"
    )


def test_sql_injection_does_not_replace_web_input_analysis():
    planner = _load_decision_planner()

    intent_to_skill = getattr(planner, "INTENT_TO_SKILL", None)

    if not isinstance(intent_to_skill, dict):
        pytest.skip("INTENT_TO_SKILL is not exposed")

    if "sql_injection" not in intent_to_skill:
        pytest.skip(
            "sql_injection has not been rolled out into decision_planner.py"
        )

    assert intent_to_skill.get("web_input_analysis") == (
        "web-input-analysis"
    )
    assert intent_to_skill["sql_injection"] == "sql-injection"


# ============================================================================
# End-to-end consistency checks
# ============================================================================

def test_sql_injection_pipeline_contract():
    text = normalized_text().lower()

    pipeline = [
        "web-input-analysis",
        "candidates.md",
        "results.md",
        "finding-validation",
    ]

    for item in pipeline:
        assert item in text


def test_sql_injection_is_candidate_driven():
    text = normalized_text().lower()

    assert "does not discover new ones" in text
    assert "does not re-triage the whole inventory" in text


def test_sql_injection_is_single_candidate_at_a_time():
    text = normalized_text().lower()

    assert "work one candidate at a time" in text
    assert "finish, record, then move to the next" in text