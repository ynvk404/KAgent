"""
Skill contract tests for skills/ssrf/SKILL.md.

These tests do not exercise any live HTTP/agent behavior — they pin down
the *contract* of the skill file itself: frontmatter shape, and the
architectural boundaries agreed for the validation-only rollout (no
exploit-oriented framing, ask_user present, conditional escalation,
bounded impact levels, no literal placeholders, and correct handling of
inconclusive results).

Behavior/decision-level tests (routing via the Decision Planner) belong
in a later test file once ssrf is registered in INTENT_TO_SKILL /
INTENT_KEYWORDS — that registration is explicitly deferred, so this file
only covers the skill contract.
"""

import re
from pathlib import Path

import pytest
import yaml

SKILL_PATH = Path(__file__).parent.parent / "skills" / "ssrf" / "SKILL.md"


def load_skill():
    raw = SKILL_PATH.read_text(encoding="utf-8")

    assert raw.startswith("---\n"), "SKILL.md must start with a frontmatter block"

    _, frontmatter_raw, body = raw.split("---\n", 2)
    frontmatter = yaml.safe_load(frontmatter_raw)

    return frontmatter, body


def normalize_ws(text: str) -> str:
    # Markdown prose wraps at ~80 chars, so a multi-word phrase can be
    # split across a line break in the source file even though it reads
    # as one phrase. Collapse all whitespace runs (including newlines)
    # to a single space before doing phrase-level substring checks.
    return re.sub(r"\s+", " ", text)


def has_word(text: str, word: str) -> bool:
    return re.search(r"(?<!\w)" + re.escape(word) + r"(?!\w)", text) is not None


@pytest.fixture(scope="module")
def skill():
    frontmatter, body = load_skill()
    return {
        "frontmatter": frontmatter,
        "body": body,
        "body_flat": normalize_ws(body),
    }


# ---------------------------------------------------------------------------
# Frontmatter contract
# ---------------------------------------------------------------------------


def test_skill_name_is_ssrf(skill):
    assert skill["frontmatter"]["name"] == "ssrf"


def test_allowed_tools_includes_ask_user(skill):
    # ask_user must ship in allowed-tools from the start, not be added
    # later — the scope checkpoint depends on it being available.
    assert "ask_user" in skill["frontmatter"]["allowed-tools"]


def test_allowed_tools_does_not_include_unexpected_tools(skill):
    # Validation-only scope: http/shell/file_write/ask_user is the
    # expected toolset. Anything else is a signal the skill has grown
    # beyond validation without a corresponding architecture review.
    allowed = set(skill["frontmatter"]["allowed-tools"])
    assert allowed == {"http", "shell", "file_write", "ask_user"}


def test_description_does_not_advertise_exploit_chaining(skill):
    description = normalize_ws(skill["frontmatter"]["description"]).lower()

    exploit_terms = [
        "rce",
        "credential disclosure",
        "credential theft",
        "chain to",
        "bypass filters",
    ]

    for term in exploit_terms:
        # word-boundary match: a naive `in` check false-positives on
        # substrings like "reso-URCE" containing "rce".
        assert not has_word(description, term), (
            f"description should not advertise exploit-chain behavior: {term!r} "
            "found — this is what routes the Decision Planner to the wrong "
            "expectation of what the skill does"
        )


def test_description_mentions_validation_scope(skill):
    description = skill["frontmatter"]["description"].lower()

    assert "validate" in description or "confirm" in description


# ---------------------------------------------------------------------------
# Preconditions / scope checkpoint
# ---------------------------------------------------------------------------


def test_has_preconditions_section(skill):
    assert "## Preconditions" in skill["body"]


def test_preconditions_require_canary_only_when_blind(skill):
    body = skill["body"]

    assert "only** if" in body or "only if" in body.lower()
    assert "blind" in body.lower()


def test_does_not_instruct_inventing_canary(skill):
    body = skill["body"].lower()

    assert "do not invent" in body or "not invent or reuse" in body


def test_has_scope_checkpoint_before_internal_or_metadata_access(skill):
    body = skill["body"]

    assert "Scope checkpoint" in body
    assert "ask_user" in body

    # The checkpoint must explicitly cover internal ranges and metadata,
    # not just say "be careful."
    checkpoint_idx = body.index("Scope checkpoint")
    checkpoint_section = body[checkpoint_idx: checkpoint_idx + 800].lower()

    assert "internal" in checkpoint_section
    assert "metadata" in checkpoint_section
    assert "localhost" in checkpoint_section


def test_scope_checkpoint_precedes_sensitive_requests(skill):
    body = skill["body"]

    checkpoint = body.index("## Scope checkpoint")
    phase_a = body.index("## 2. Phase A")
    internal = body.index("## 4. Minimal internal-access validation")
    metadata = body.index("## 5. Minimal metadata validation")

    # A future edit could reorder sections while every individual
    # keyword test above still passes. Pin the actual ordering so the
    # checkpoint can never end up after the requests it's meant to gate.
    assert checkpoint < phase_a
    assert checkpoint < internal
    assert checkpoint < metadata


def test_skill_sections_are_in_safe_order(skill):
    body = skill["body"]

    preconditions = body.index("## Preconditions")
    checkpoint = body.index("## Scope checkpoint")
    confirm = body.index("## 1. Confirm the primitive")

    # Preconditions must be established before the scope checkpoint is
    # even reachable, and the checkpoint must gate the first actual
    # confirmation request.
    assert preconditions < checkpoint < confirm


# ---------------------------------------------------------------------------
# Inconclusive-result handling (the fix from this round)
# ---------------------------------------------------------------------------


def test_does_not_conclude_absence_from_missing_evidence(skill):
    body = skill["body"].lower()

    # The skill must never assert "this is not SSRF" purely because the
    # canary didn't fire / response didn't differ. Absence of observed
    # evidence is not evidence of absence.
    assert "this is not ssrf" not in body
    assert "stop \u2014 this is not ssrf" not in body


def test_reports_inconclusive_result_explicitly(skill):
    body = skill["body_flat"].lower()

    assert "could not be confirmed" in body
    assert "available evidence" in body


def test_lists_plausible_causes_for_null_result(skill):
    body = skill["body"].lower()

    # At least a couple of the known causes of a false negative should be
    # named, so the model doesn't collapse "no signal" into "no vuln."
    causes = ["blind", "filtering", "timeout"]
    hits = [cause for cause in causes if cause in body]

    assert len(hits) >= 2, (
        "expected the skill to name multiple plausible causes for an "
        f"inconclusive result, found: {hits}"
    )


def test_validation_contract_is_present(skill):
    body = skill["body_flat"].lower()

    # Guards against a future "make it safer" edit that strips the
    # actual confirmation mechanics rather than just bounding them —
    # a skill with no positive validation contract is not a weaker
    # version of this skill, it's a different, useless one.
    assert "confirm the primitive" in body
    assert "compare against a baseline request" in body
    assert "ssrf-1" in body


def test_requires_baseline_comparison(skill):
    body = skill["body_flat"].lower()

    assert "compare against a baseline request" in body


# ---------------------------------------------------------------------------
# Conditional escalation (Phase A / Phase B)
# ---------------------------------------------------------------------------


def test_has_phase_a_and_phase_b(skill):
    body = skill["body"]

    assert "Phase A" in body
    assert "Phase B" in body


def test_phase_b_is_conditional_on_evidence(skill):
    body = skill["body"]

    phase_b_idx = body.index("Phase B")
    phase_b_section = body[phase_b_idx: phase_b_idx + 600].lower()

    # Phase B must be gated on both conditions being true, not run by
    # default alongside Phase A.
    assert "only" in phase_b_section
    assert "both" in phase_b_section
    assert "server-side fetch" in phase_b_section
    assert "filtering" in phase_b_section


def test_phase_b_rejects_default_full_bypass_corpus(skill):
    body = skill["body_flat"].lower()

    # The permitted phrasing is "not the full bypass corpus by default".
    # Assert that phrasing is present, and that the bare, unqualified
    # phrase never appears on its own — a weaker either/or check here
    # would pass even if the "not" got dropped in a future edit.
    assert "not the full bypass corpus by default" in body
    assert "full bypass corpus by default" not in body.replace(
        "not the full bypass corpus by default", ""
    )


# ---------------------------------------------------------------------------
# Internal access / metadata are bounded
# ---------------------------------------------------------------------------


def test_forbids_broad_internal_network_scans(skill):
    body = skill["body"].lower()

    assert "do not perform broad internal network scans" in body


def test_internal_validation_requires_explicit_evidence(skill):
    body = skill["body"].lower()

    idx = body.index("minimal internal-access validation")
    section = body[idx: idx + 500]

    assert "explicit evidence" in section or "explicitly identified" in section


def test_metadata_validation_stops_short_of_credentials(skill):
    body = skill["body_flat"].lower()

    idx = body.index("minimal metadata validation")
    section = body[idx: idx + 600]

    assert "do not enumerate iam roles" in section
    assert "separately scoped authorization" in section


# ---------------------------------------------------------------------------
# Bounded impact ladder — SSRF-1..4, nothing beyond
# ---------------------------------------------------------------------------


def test_impact_ladder_covers_ssrf_1_through_4(skill):
    body = skill["body"]

    for level in ["SSRF-1", "SSRF-2", "SSRF-3", "SSRF-4"]:
        assert level in body


def test_impact_ladder_does_not_include_ssrf_5(skill):
    body = skill["body"]

    # SSRF-5 (credential material disclosed) is separately scoped impact
    # work. Its presence here would signal scope creep.
    assert "SSRF-5" not in body


def test_stops_before_credential_use_or_rce(skill):
    body = skill["body"].lower()

    idx = body.index("stop when impact is proven")
    section = body[idx: idx + 700]

    assert "do not continue toward" in section
    assert "credential" in section
    assert "rce" in section


def test_defers_deeper_impact_to_separately_authorized_followup(skill):
    body = skill["body"]

    assert "separately scoped follow-up" in body
    assert "explicit authorization" in body.lower()


# ---------------------------------------------------------------------------
# Reporting / filename hygiene
# ---------------------------------------------------------------------------


def test_execution_rule_names_placeholders_as_forbidden(skill):
    # The skill is allowed to *mention* `<endpoint>`/`<role>` as examples
    # of what not to write — that's the instruction itself. What it must
    # never do is use one of those literal placeholders as the actual
    # reporting filename (that was the inconsistency in the old draft).
    body = skill["body_flat"]

    assert "never write literal" in body.lower()
    assert "<endpoint>" in body
    assert "<role>" in body


def test_does_not_use_angle_bracket_placeholder_as_actual_filename(skill):
    body = skill["body"]

    # This is the literal regression from the old draft:
    # `findings/ssrf-<endpoint>.md` used as the real reporting path.
    assert "ssrf-<endpoint>.md" not in body
    assert "ssrf-<role>.md" not in body


def test_reporting_section_does_not_contain_angle_bracket_placeholders(skill):
    body = skill["body"]

    idx = body.index("## Reporting")
    section = body[idx:]

    assert "<endpoint>" not in section
    assert "<role>" not in section


def test_filename_pattern_is_sanitized_placeholder(skill):
    body = skill["body"]

    assert "findings/ssrf-{sanitized-parameter-or-path}.md" in body


def test_documents_sanitization_rule(skill):
    body = skill["body_flat"].lower()

    assert "sanitized for filesystem safety" in body
