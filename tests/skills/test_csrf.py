"""
Skill contract tests for skills/csrf/SKILL.md.

These tests do not exercise any live HTTP/agent behavior — they pin down
the *contract* of the skill file itself: frontmatter shape, and the
architectural boundaries agreed for the validation-only rollout (no
account-takeover/destructive framing, ask_user present, behavioral
evidence required before confirming, bounded impact levels, no literal
placeholders, and correct handling of inconclusive results).

CSRF intentionally differs from ssrf's contract in one structural way: it
has no Phase A / Phase B bypass-corpus escalation. Its core loop is
baseline -> defense analysis -> minimal probe -> cross-site validation,
so this file has no phase-ordering tests analogous to ssrf's Phase A/B
ones — instead it pins the CSRF-specific epistemic guards (token absent
!= confirmed, HTTP 200 != confirmed, HTTP replay != browser execution).

Behavior/decision-level tests (routing via the Decision Planner) belong
in the planner tests using the skill's frontmatter selection metadata, so this file
only covers the skill contract.
"""

import re
from pathlib import Path

import pytest
import yaml

SKILL_PATH = Path(__file__).resolve().parents[2] / "skills" / "csrf" / "SKILL.md"


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


def test_skill_name_is_csrf(skill):
    assert skill["frontmatter"]["name"] == "csrf"


def test_allowed_tools_includes_ask_user(skill):
    # ask_user must ship in allowed-tools from the start, not be added
    # later — the scope checkpoint depends on it being available.
    assert "ask_user" in skill["frontmatter"]["allowed-tools"]


def test_allowed_tools_does_not_include_unexpected_tools(skill):
    # Phase 3 adds only structured state and evidence-gated finding handoff.
    allowed = set(skill["frontmatter"]["allowed-tools"])
    assert allowed == {
        "http",
        "shell",
        "file_write",
        "ask_user",
        "confirm_finding",
        "workflow",
    }


def test_description_does_not_advertise_impact_chaining(skill):
    description = normalize_ws(skill["frontmatter"]["description"]).lower()

    impact_terms = [
        "account takeover",
        "password change",
        "chain to",
        "exploit",
    ]

    for term in impact_terms:
        # word-boundary match to avoid substring false positives, same
        # pattern as test_ssrf.py's exploit-term check.
        assert not has_word(description, term), (
            f"description should not advertise impact-chain behavior: {term!r} "
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


def test_preconditions_require_authenticated_context_and_safe_action(skill):
    body = skill["body_flat"].lower()

    assert "authenticated context" in body
    assert "safe" in body and "test action" in body


def test_does_not_instruct_inventing_origin_or_credentials(skill):
    body = skill["body"].lower()

    assert "do not invent" in body
    assert "credentials, tokens, origins" in body or "an external domain" in body


def test_has_scope_checkpoint_gated_by_ask_user(skill):
    body = skill["body"]

    assert "## Scope checkpoint" in body

    checkpoint_idx = body.index("## Scope checkpoint")
    checkpoint_section = body[checkpoint_idx: checkpoint_idx + 900].lower()

    assert "ask_user" in checkpoint_section
    assert "modify persistent state" in checkpoint_section
    assert "do not infer authorization" in checkpoint_section


def test_scope_checkpoint_requires_known_result_before_firing(skill):
    # This is the small ask_user reinforcement added on top of the
    # original draft: the agent must not send a state-changing
    # validation request before it knows what a successful result would
    # even look like.
    body = skill["body_flat"].lower()

    assert (
        "do not proceed with a state-changing validation request until "
        "the safe test action and its expected observable result are known"
        in body
    )


def test_skill_sections_are_in_safe_order(skill):
    body = skill["body"]

    preconditions = body.index("## Preconditions")
    checkpoint = body.index("## Scope checkpoint")
    identify = body.index("## 1. Identify the state-changing request")

    # Preconditions must be established before the scope checkpoint is
    # even reachable, and the checkpoint must gate the first step that
    # starts recording/testing a real request.
    assert preconditions < checkpoint < identify


def test_scope_checkpoint_precedes_state_changing_probes(skill):
    body = skill["body"]

    checkpoint = body.index("## Scope checkpoint")
    minimal_validation = body.index("## 3. Minimal validation")
    cross_site_validation = body.index("## 4. Cross-site request validation")

    # A future edit could reorder sections while every individual
    # keyword test above still passes. Pin the actual ordering so the
    # checkpoint can never end up after the steps that actually send a
    # state-changing probe — mirrors the equivalent guard in
    # test_ssrf.py's test_scope_checkpoint_precedes_sensitive_requests.
    assert checkpoint < minimal_validation
    assert checkpoint < cross_site_validation


# ---------------------------------------------------------------------------
# Validation contract — baseline, defense analysis, minimal probe
# ---------------------------------------------------------------------------


def test_requires_identifying_state_changing_request_first(skill):
    body = skill["body"]

    assert "## 1. Identify the state-changing request" in body


def test_validation_contract_is_present(skill):
    body = skill["body"]

    # Guards against a future "make it safer" edit that strips the
    # actual validation mechanics rather than just bounding them — a
    # skill missing one of these core steps is not a weaker version of
    # this skill, it's a broken one. Mirrors test_ssrf.py's
    # test_validation_contract_is_present.
    assert "## 1. Identify the state-changing request" in body
    assert "## 2. Evaluate CSRF defenses" in body
    assert "## 3. Minimal validation" in body
    assert "## 4. Cross-site request validation" in body


def test_does_not_continue_on_non_state_changing_requests(skill):
    body = skill["body_flat"].lower()

    assert "do not continue with csrf testing against requests that have no meaningful state change" in body


def test_evaluates_defenses_before_probing(skill):
    body = skill["body"]

    evaluate_idx = body.index("## 2. Evaluate CSRF defenses")
    minimal_idx = body.index("## 3. Minimal validation")

    assert evaluate_idx < minimal_idx

    defenses_section = body[evaluate_idx:minimal_idx].lower()
    for defense in [
        "synchronizer csrf token",
        "double-submit cookie",
        "origin validation",
        "referer validation",
        "samesite",
    ]:
        assert defense in defenses_section


def test_requires_baseline_comparison(skill):
    body = skill["body_flat"].lower()

    assert "compare each probe with the known-good baseline" in body


def test_does_not_attempt_token_theft_or_auth_bypass(skill):
    body = skill["body_flat"].lower()

    assert "do not attempt token theft or authentication bypass" in body


# ---------------------------------------------------------------------------
# SameSite caveat (fix from this round)
# ---------------------------------------------------------------------------


def test_samesite_is_not_treated_as_sufficient_protection_alone(skill):
    body = skill["body_flat"].lower()

    assert "do not mark a request as protected solely because a samesite attribute is present" in body


# ---------------------------------------------------------------------------
# Epistemic guards — the three "X != confirmed" invariants
# ---------------------------------------------------------------------------


def test_token_absence_alone_does_not_confirm_csrf(skill):
    body = skill["body_flat"].lower()

    assert "do not report csrf-3 solely because a token field appears absent" in body
    assert "require" in body and "behavioral evidence" in body


def test_http_200_alone_does_not_confirm_csrf(skill):
    body = skill["body_flat"].lower()

    assert "do not treat a successful http status alone as evidence of csrf" in body
    assert "confirm that the intended state-changing operation was actually accepted" in body


def test_http_replay_is_not_equated_with_browser_execution(skill):
    body = skill["body_flat"].lower()

    idx = body.index("cross-site request validation")
    section = body[idx: idx + 1200]

    assert "do not claim full browser-level exploitability" in section
    assert "browser-mediated cross-site execution" in section
    assert "not equivalent to a real browser" in section


def test_does_not_conclude_absence_from_inconclusive_evidence(skill):
    body = skill["body"].lower()

    # Mirrors ssrf's epistemic guard: a null/ambiguous result must never
    # be reported as "this is not CSRF."
    assert "this is not csrf" not in body


def test_reports_inconclusive_result_explicitly(skill):
    body = skill["body_flat"].lower()

    assert "csrf could not be confirmed with the available evidence" in body


# ---------------------------------------------------------------------------
# Bounded impact ladder — CSRF-1..3, correct semantics, nothing beyond
# ---------------------------------------------------------------------------


def test_impact_ladder_covers_csrf_1_through_3(skill):
    body = skill["body"]

    for level in ["CSRF-1", "CSRF-2", "CSRF-3"]:
        assert level in body


def test_impact_ladder_does_not_include_csrf_4(skill):
    body = skill["body"]

    # Nothing beyond confirmed cross-site execution belongs in this
    # skill's ladder — deeper impact is a separate, authorized workflow.
    assert "CSRF-4" not in body


def test_csrf_1_means_candidate_not_defense_held(skill):
    # Regression guard for the semantics fix: CSRF-1 must describe
    # "endpoint identified / relevant", not "tested defense remains in
    # place" (which was the original, incorrect draft).
    body = skill["body_flat"]

    idx = body.index("**CSRF-1**")
    line = body[idx: idx + 200].lower()

    assert "identified" in line
    assert "relevant to csrf testing" in line
    assert "defense remains in place" not in line


def test_csrf_3_requires_safe_state_change_accepted_cross_site(skill):
    body = skill["body_flat"]

    idx = body.index("**CSRF-3**")
    line = body[idx: idx + 250].lower()

    assert "safe state-changing action" in line
    assert "cross-site" in line
    assert "without an effective csrf defense" in line


def test_stops_at_csrf_3_without_further_account_actions(skill):
    body = skill["body_flat"].lower()

    idx = body.index("stop when csrf is confirmed")
    section = body[idx: idx + 700]

    assert "do not perform additional account actions" in section
    assert "do not chain into account takeover" in section
    assert "do not test destructive endpoints" in section
    assert "do not attempt privilege escalation" in section


def test_hands_off_deeper_impact_to_separate_authorized_workflow(skill):
    body = skill["body_flat"].lower()

    assert "deeper impact validation belongs to a separate, explicitly authorized workflow" in body


# ---------------------------------------------------------------------------
# Destructive-action blocklist for the default PoC
# ---------------------------------------------------------------------------


def test_forbids_high_impact_actions_as_default_poc(skill):
    body = skill["body_flat"].lower()

    idx = body.index("do not use:")
    section = body[idx: idx + 400]

    for action in [
        "password reset",
        "email change",
        "account deletion",
        "fund transfer",
        "privilege modification",
        "destructive administration actions",
    ]:
        assert action in section


# ---------------------------------------------------------------------------
# Reporting / filename hygiene
# ---------------------------------------------------------------------------


def test_execution_rule_names_forbidden_inventions(skill):
    body = skill["body_flat"].lower()

    assert "do not invent credentials, tokens, origins, or target endpoints" in body


def test_does_not_use_angle_bracket_placeholder_as_actual_filename(skill):
    body = skill["body"]

    assert "csrf-<endpoint>.md" not in body
    assert "csrf-<parameter>.md" not in body


def test_reporting_section_does_not_contain_angle_bracket_placeholders(skill):
    body = skill["body"]

    idx = body.index("## Reporting")
    section = body[idx:]

    assert "<endpoint>" not in section
    assert "<parameter>" not in section


def test_validation_artifact_is_separate_from_official_finding(skill):
    body = skill["body"]

    assert "csrf/<target>/results.md" in body
    assert "`confirm_finding` alone creates the report under `findings/`" in body
    assert "findings/csrf-{sanitized-parameter-or-path}.md" not in body


def test_documents_evidence_redaction(skill):
    body = skill["body_flat"].lower()

    assert "redacted supporting evidence" in body


def test_never_writes_literal_placeholder_as_finding_filename(skill):
    body = skill["body_flat"].lower()

    assert "not an official finding" in body
