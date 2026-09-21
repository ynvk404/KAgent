"""
Contract tests for skills/ssti/SKILL.md and skills/ssti/payloads.txt.

These tests do not execute live HTTP requests or invoke the agent.
They pin down the agreed SSTI architecture:

- one vulnerability skill with one payload corpus
- Phase 1: safe fingerprinting
- Phase 2: non-destructive validation
- Phase 3: optional impact validation
- ask_user required before deeper phases
- Phase 2 must not contain execution-oriented probes
- Phase 3 requires explicit authorization
- SSTI-1 / SSTI-2 / SSTI-3 semantics
- inconclusive results are not treated as absence
- reporting and filename hygiene

Behavior/decision-level tests belong in a later test file once SSTI is
selected through its frontmatter metadata.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml


SKILL_DIR = Path(__file__).resolve().parents[2] / "skills" / "ssti"
SKILL_PATH = SKILL_DIR / "SKILL.md"
PAYLOADS_PATH = SKILL_DIR / "payloads.txt"


def load_skill():
    raw = SKILL_PATH.read_text(encoding="utf-8")

    assert raw.startswith("---\n"), (
        "SKILL.md must start with a frontmatter block"
    )

    _, frontmatter_raw, body = raw.split("---\n", 2)
    frontmatter = yaml.safe_load(frontmatter_raw)

    return frontmatter, body


def load_payloads() -> str:
    assert PAYLOADS_PATH.exists(), (
        "skills/ssti/payloads.txt must exist"
    )

    return PAYLOADS_PATH.read_text(encoding="utf-8")


def normalize_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def section_between(
    text: str,
    start_marker: str,
    end_marker: str,
) -> str:
    start = text.index(start_marker)
    end = text.index(end_marker, start + len(start_marker))
    return text[start:end]


def section_after(text: str, start_marker: str) -> str:
    start = text.index(start_marker)
    return text[start:]


@pytest.fixture(scope="module")
def skill():
    frontmatter, body = load_skill()

    return {
        "frontmatter": frontmatter,
        "body": body,
        "body_flat": normalize_ws(body),
    }


@pytest.fixture(scope="module")
def payloads():
    raw = load_payloads()

    phase1 = section_between(
        raw,
        "PHASE 1",
        "PHASE 2",
    )

    phase2 = section_between(
        raw,
        "PHASE 2",
        "PHASE 3",
    )

    phase3 = section_after(
        raw,
        "PHASE 3",
    )

    return {
        "raw": raw,
        "phase1": phase1,
        "phase2": phase2,
        "phase3": phase3,
    }


# ---------------------------------------------------------------------------
# File / structure contract
# ---------------------------------------------------------------------------


def test_skill_directory_exists():
    assert SKILL_DIR.is_dir()


def test_skill_file_exists():
    assert SKILL_PATH.is_file()


def test_payload_file_exists():
    assert PAYLOADS_PATH.is_file()


# ---------------------------------------------------------------------------
# Frontmatter contract
# ---------------------------------------------------------------------------


def test_skill_name_is_ssti(skill):
    assert skill["frontmatter"]["name"] == "ssti"


def test_allowed_tools_include_required_tools(skill):
    allowed = set(skill["frontmatter"]["allowed-tools"])

    assert {
        "http",
        "shell",
        "read_payloads",
        "file_write",
        "ask_user",
    }.issubset(allowed)


def test_allowed_tools_do_not_include_unexpected_impact_tools(skill):
    allowed = set(skill["frontmatter"]["allowed-tools"])

    assert allowed == {
        "http",
        "shell",
        "read_payloads",
        "file_write",
        "ask_user",
        "confirm_finding",
        "workflow",
    }


def test_description_mentions_ssti_validation(skill):
    description = normalize_ws(
        skill["frontmatter"]["description"]
    ).lower()

    assert "server-side template injection" in description
    assert "fingerprinting" in description
    assert "expression evaluation" in description


def test_description_mentions_explicit_impact_authorization(skill):
    description = normalize_ws(
        skill["frontmatter"]["description"]
    ).lower()

    assert "explicit user authorization" in description
    assert "validating impact" in description


# ---------------------------------------------------------------------------
# One-skill / three-phase architecture
# ---------------------------------------------------------------------------


def test_skill_declares_three_phases(skill):
    body = skill["body"]

    assert "Phase 1: Detection / Fingerprint" in body
    assert "Phase 2: Validation" in body
    assert "Phase 3: Impact validation (optional)" in body


def test_phase_order_is_safe(skill):
    body = skill["body"]

    phase1 = body.index("## Phase 1: Detection / fingerprint")
    phase2 = body.index("## Phase 2: Validation")
    phase3 = body.index("## Phase 3: Impact validation (optional)")

    assert phase1 < phase2 < phase3


def test_phase_3_is_explicitly_optional(skill):
    body = skill["body_flat"].lower()

    assert "phase 3 (impact) is optional" in body
    assert "does not run automatically" in body


# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------


def test_has_preconditions_section(skill):
    assert "## Preconditions" in skill["body"]


def test_preconditions_require_core_context(skill):
    body = skill["body_flat"].lower()

    required = [
        "target url",
        "actual parameter",
        "http method",
        "context in which the input appears",
        "user-authorized canary",
    ]

    for term in required:
        assert term in body, f"missing SSTI precondition: {term!r}"


def test_blind_canary_requires_ask_user(skill):
    body = skill["body_flat"].lower()

    assert "blind confirmation" in body
    assert "ask_user once" in body
    assert "do not invent or reuse a canary domain" in body


def test_preconditions_do_not_allow_literal_placeholders(skill):
    body = skill["body"].lower()

    assert "never write literal placeholder values" in body


# ---------------------------------------------------------------------------
# Scope checkpoint / authorization
# ---------------------------------------------------------------------------


def test_has_scope_checkpoint(skill):
    body = skill["body"]

    assert "## Scope checkpoint (entering Phase 2)" in body


def test_scope_checkpoint_mentions_ask_user(skill):
    body = skill["body"]

    idx = body.index("## Scope checkpoint")
    section = body[idx: idx + 1200].lower()

    assert "ask_user" in section
    assert "confirm authorization" in section


def test_scope_checkpoint_precedes_phase_2(skill):
    body = skill["body"]

    checkpoint = body.index("## Scope checkpoint")
    phase2 = body.index("## Phase 2: Validation")

    assert checkpoint < phase2


def test_scope_checkpoint_covers_deeper_probe_types(skill):
    body = skill["body"].lower()

    for term in [
        "object introspection",
        "filter/attribute chains",
        "read files",
        "execute commands",
        "environment state",
    ]:
        assert term in body


def test_phase_3_requires_explicit_authorization(skill):
    body = skill["body_flat"].lower()

    assert "only proceed when" in body
    assert "ssti has already been confirmed (ssti-2)" in body
    assert (
        "the user explicitly authorizes deeper impact validation via ask_user"
        in body
    )


def test_phase_3_requires_authorization_after_ssti2(skill):
    body = skill["body_flat"].lower()

    condition_idx = body.index(
        "the user explicitly authorizes deeper impact validation via ask_user"
    )
    ssti2_idx = body.index("ssti-2")

    assert ssti2_idx < condition_idx


# ---------------------------------------------------------------------------
# Phase 1 validation contract
# ---------------------------------------------------------------------------


def test_phase_1_is_safe_and_arithmetic_only(skill):
    body = skill["body_flat"].lower()

    assert "safe and non-destructive" in body
    assert "arithmetic" in body
    assert "without a scope-checkpoint confirmation" in body


def test_phase_1_uses_single_payload_corpus(skill):
    body = skill["body_flat"]

    assert 'read_payloads(skill="ssti", file="payloads.txt")' in body


def test_phase_1_requires_only_phase1_payload_section(skill):
    body = skill["body_flat"].lower()

    assert "use only the `phase 1 — fingerprint` section" in body


def test_phase_1_does_not_use_introspection(skill):
    phase1 = section_between(
        skill["body"],
        "## Phase 1: Detection / fingerprint",
        "## Phase 2: Validation",
    ).lower()

    assert "do not use introspection" in phase1


def test_phase_1_null_result_is_inconclusive_not_absence(skill):
    body = skill["body_flat"].lower()

    assert "do not conclude that ssti is absent" in body
    assert "could not be confirmed with the available evidence" in body


# ---------------------------------------------------------------------------
# Phase 2 validation contract
# ---------------------------------------------------------------------------


def test_phase_2_is_non_destructive(skill):
    body = skill["body_flat"].lower()

    phase2 = section_between(
        body,
        "## phase 2: validation",
        "### blind ssti validation",
    )

    assert "minimal, non-destructive confirmation" in phase2
    assert "not to reach execution" in phase2


def test_phase_2_allows_type_introspection(skill):
    body = skill["body_flat"].lower()

    assert "object/class introspection" in body
    assert "type information only" in body


def test_phase_2_forbids_gadget_enumeration(skill):
    body = skill["body_flat"].lower()

    assert "do not attempt to enumerate or walk toward an exec-capable gadget" in body
    assert "subprocess.popen" in body


def test_phase_2_forbids_rce_payloads(skill):
    body = skill["body_flat"].lower()

    forbidden = [
        "runtime.exec",
        "system",
        "popen",
        "execsync",
        "php `exec` filters",
    ]

    for term in forbidden:
        assert term in body


def test_phase_2_uses_same_payload_file_but_scopes_section(skill):
    body = skill["body_flat"].lower()

    assert (
        'read_payloads(skill="ssti", file="payloads.txt") provides '
        "introspection-only probes"
        in body
    )
    assert "use only the `phase 2 — validation` section" in body


# ---------------------------------------------------------------------------
# Phase 2 blind validation
# ---------------------------------------------------------------------------


def test_blind_validation_has_controlled_side_channel(skill):
    body = skill["body_flat"].lower()

    assert "user-authorized dns or http callback" in body
    assert "timing analysis only as a last resort" in body
    assert "baseline comparison" in body


def test_blind_validation_forbids_os_command_callback(skill):
    body = skill["body_flat"].lower()

    assert "do not perform an os command execution to trigger the callback" in body


def test_blind_validation_can_stop_at_ssti2(skill):
    body = skill["body_flat"].lower()

    assert "treat this as ssti-2 at most and stop" in body


# ---------------------------------------------------------------------------
# Result ladder
# ---------------------------------------------------------------------------


def test_result_ladder_covers_ssti_1_to_3(skill):
    body = skill["body"]

    for level in ["SSTI-1", "SSTI-2", "SSTI-3"]:
        assert level in body


def test_ssti1_is_signal_not_confirmed_finding(skill):
    body = skill["body_flat"].lower()

    idx = body.index("**ssti-1**")
    section = body[idx: idx + 450]

    assert "likely engine identified" in section
    assert "additional validation is required" in section


def test_ssti2_is_confirmed_non_destructive_finding(skill):
    body = skill["body_flat"].lower()

    idx = body.index("**ssti-2**")
    section = body[idx: idx + 300]

    assert "ssti conclusively confirmed" in section
    assert "non-destructive expression evaluation" in section


def test_ssti3_is_phase3_only(skill):
    body = skill["body_flat"].lower()

    idx = body.index("**ssti-3**")
    section = body[idx: idx + 300]

    assert "phase 3" in section


def test_ssti2_is_reportable_on_its_own(skill):
    body = skill["body_flat"].lower()

    assert "ssti-2 is a complete, reportable finding on its own" in body


def test_ssti3_requires_direct_evidence(skill):
    body = skill["body_flat"].lower()

    assert "do not report ssti-3 without direct evidence" in body
    assert "command output" in body
    assert "sensitive file/data content" in body


# ---------------------------------------------------------------------------
# Phase 3 impact boundary
# ---------------------------------------------------------------------------


def test_phase_3_is_not_automatic(skill):
    body = skill["body_flat"].lower()

    phase3 = body[
        body.index("## phase 3: impact validation (optional)") :
    ]

    assert "do not enter this phase automatically" in phase3


def test_phase_3_uses_payload_corpus_only_after_authorization(skill):
    body = skill["body_flat"].lower()

    phase3 = body[
        body.index("## phase 3: impact validation (optional)") :
    ]

    assert "payloads.txt" in phase3
    assert "phase 3 — impact" in phase3
    assert "explicitly" in phase3 or "explicit" in phase3


def test_phase_3_requires_minimal_impact(skill):
    body = skill["body_flat"].lower()

    assert "minimum non-sensitive or minimally sensitive artifact" in body
    assert "single file explicitly relevant to the finding" in body


def test_phase_3_forbids_broad_context_dumps(skill):
    body = skill["body_flat"].lower()

    for term in [
        "do not dump environment",
        "configuration",
        "request context",
        "broad dump",
    ]:
        assert term in body


def test_phase_3_forbids_post_exploitation_chaining(skill):
    body = skill["body_flat"].lower()

    forbidden = [
        "credential harvesting",
        "lateral movement",
        "further exploitation",
        "forging a session",
    ]

    for term in forbidden:
        assert term in body


# ---------------------------------------------------------------------------
# Payload corpus structure
# ---------------------------------------------------------------------------


def test_payload_corpus_has_all_three_phase_banners(payloads):
    raw = payloads["raw"]

    assert "PHASE 1" in raw
    assert "PHASE 2" in raw
    assert "PHASE 3" in raw


def test_payload_corpus_has_phase_order(payloads):
    raw = payloads["raw"]

    phase1 = raw.index("PHASE 1")
    phase2 = raw.index("PHASE 2")
    phase3 = raw.index("PHASE 3")

    assert phase1 < phase2 < phase3


def test_phase1_payloads_do_not_contain_known_execution_primitives(payloads):
    phase1 = payloads["phase1"].lower()

    forbidden = [
        "popen(",
        "execsync",
        "runtime.exec",
        "os.popen",
        "subprocess",
        "open('/etc/",
        'open("/etc/',
        "__globals__",
        "__subclasses__",
        "request.environ",
    ]

    for term in forbidden:
        assert term not in phase1, (
            f"Phase 1 payload corpus must remain arithmetic/parse-only: "
            f"found {term!r}"
        )


def test_phase2_payloads_do_not_walk_toward_execution(payloads):
    phase2 = payloads["phase2"].lower()

    forbidden = [
        "__subclasses__",
        "popen(",
        "os.popen",
        "subprocess.popen",
        "runtime.exec",
        "execsync",
        "open('/etc/",
        'open("/etc/',
        "__globals__",
    ]

    for term in forbidden:
        assert term not in phase2, (
            f"Phase 2 must remain introspection-only: found {term!r}"
        )


def test_phase2_contains_benign_introspection(payloads):
    phase2 = payloads["phase2"].lower()

    assert "__class__" in phase2
    assert "getclass()" in phase2


def test_phase3_contains_only_impact_after_banner(payloads):
    phase3 = payloads["phase3"].lower()

    assert "popen(" in phase3 or "subprocess" in phase3
    assert "phase 3" in phase3


def test_phase3_corpus_does_not_include_broad_default_dumps(payloads):
    phase3 = payloads["phase3"].lower()

    forbidden_broad_dumps = [
        "{{config}}",
        "{{config.items()}}",
        "{{self}}",
        "{{request.environ}}",
    ]

    for payload in forbidden_broad_dumps:
        assert payload not in phase3


def test_payload_corpus_documents_phase_authorization(payloads):
    raw = payloads["raw"].lower()

    assert "phase 2" in raw
    assert "phase 3" in raw
    assert "ask_user" in raw
    assert "does not grant permission" in raw


# ---------------------------------------------------------------------------
# Reporting / filename hygiene
# ---------------------------------------------------------------------------


def test_reporting_section_exists(skill):
    assert "## Reporting" in skill["body"]


def test_reporting_filename_is_sanitized(skill):
    body = skill["body"]

    assert "findings/ssti-{sanitized-parameter-or-path}.md" in body
    assert "sanitized for filesystem safety" in body


def test_reporting_forbids_literal_placeholders(skill):
    body = skill["body"]

    assert "never write a literal placeholder as the filename" in body
    assert "findings/ssti-<endpoint>.md" not in body


def test_reporting_requires_phase_and_evidence(skill):
    body = skill["body_flat"].lower()

    reporting = body[body.index("## reporting") :]

    required = [
        "exact input field",
        "fingerprint output",
        "inferred engine",
        "ssti level reached",
        "exact probe/response evidence",
        "note when evidence is inconclusive",
        "deeper impact validation",
        "explicit authorization",
    ]

    for term in required:
        assert term in reporting, (
            f"reporting section missing required term: {term!r}"
        )


# ---------------------------------------------------------------------------
# Architecture invariants
# ---------------------------------------------------------------------------


def test_no_separate_impact_skill_is_referenced_as_required(skill):
    body = skill["body"].lower()

    # Current architecture is one skill with internal phases.
    assert "ssti-impact" not in body


def test_single_payload_file_is_the_documented_corpus(skill):
    body = skill["body"]

    assert 'file="payloads.txt"' in body


def test_skill_does_not_require_multiple_payload_files(skill):
    body = skill["body"].lower()

    assert "fingerprint-polyglot.txt" not in body
    assert "jinja2-confirm.txt" not in body
