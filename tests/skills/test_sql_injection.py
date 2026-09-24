"""
tests/test_sqlinjection.py

Contract tests for skills/sql-injection/{SKILL.md,payloads.txt}.

These tests do NOT execute any SQL injection technique, do NOT make any
network or shell calls, and do NOT exercise a live agent. They check two
things:

1. Static content contract — SKILL.md and payloads.txt contain the
   invariants this skill was designed around (no dns_callback dependency,
   Phase 2d capability-gating, Phase 3 separate authorization, scope
   bounds on extraction, etc.), so a future edit to either file can't
   silently drift from the agreed design without a test failing.

2. Reference gate logic — a small, pure-Python re-implementation of the
   Phase 2d / Phase 3 authorization gates described in SKILL.md, tested
   as an executable spec. This models the *decision policy* the skill
   text instructs an agent to follow; it is not the agent itself and
   contains no payloads, no request logic, and no exploitation code.

Run with: pytest tests/test_sqlinjection.py -v
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pytest
import yaml

# ---------------------------------------------------------------------------
# Locating the skill files
# ---------------------------------------------------------------------------

def _find_skill_dir() -> Path:
    """Walk up from this test file looking for skills/sql-injection/."""
    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        candidate = parent / "skills" / "sql-injection"
        if (candidate / "SKILL.md").exists():
            return candidate
    raise FileNotFoundError(
        "Could not locate skills/sql-injection/SKILL.md relative to "
        f"{here}. Expected repo layout: <root>/skills/sql-injection/SKILL.md"
    )


SKILL_DIR = _find_skill_dir()
SKILL_MD_PATH = SKILL_DIR / "SKILL.md"
PAYLOADS_PATH = SKILL_DIR / "payloads.txt"


@pytest.fixture(scope="session")
def skill_text() -> str:
    return SKILL_MD_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def payloads_text() -> str:
    return PAYLOADS_PATH.read_text(encoding="utf-8")


def _norm(text: str) -> str:
    """
    Collapse whitespace/newlines so phrase checks survive line-wrapping,
    and strip leading '#' comment markers (payloads.txt banners wrap
    across multiple '#'-prefixed lines) so a wrapped comment reads as one
    continuous phrase.
    """
    lines = [re.sub(r"^\s*#+\s?", "", line) for line in text.splitlines()]
    return re.sub(r"\s+", " ", " ".join(lines))


@pytest.fixture(scope="session")
def skill_frontmatter(skill_text: str) -> dict:
    """Parse the YAML frontmatter block at the top of SKILL.md."""
    match = re.match(r"^---\n(.*?)\n---\n", skill_text, re.DOTALL)
    assert match, "SKILL.md must start with a YAML frontmatter block delimited by '---'"
    data = yaml.safe_load(match.group(1))
    assert isinstance(data, dict)
    return data


# ---------------------------------------------------------------------------
# 1. Frontmatter / allowed-tools contract
# ---------------------------------------------------------------------------

class TestFrontmatter:
    def test_name_and_description_present(self, skill_frontmatter: dict):
        assert skill_frontmatter.get("name") == "sql-injection"
        assert skill_frontmatter.get("description")

    def test_canonical_completion_artifact_declared(self, skill_frontmatter: dict):
        assert skill_frontmatter.get("completion-artifact") == (
            "sql-injection/{target}/results.md"
        )

    def test_allowed_tools_present(self, skill_frontmatter: dict):
        tools = skill_frontmatter.get("allowed-tools")
        assert isinstance(tools, list) and tools, "allowed-tools must be a non-empty list"

    def test_dns_callback_not_declared(self, skill_frontmatter: dict):
        """
        Core regression this whole exercise was about: the skill must not
        declare a dependency on a tool (dns_callback) that doesn't exist
        in the current runtime.
        """
        tools = skill_frontmatter["allowed-tools"]
        assert "dns_callback" not in tools
        # Also guard against re-adding it under a near-alias.
        for t in tools:
            assert "callback" not in t.lower() and "oob" not in t.lower(), (
                f"allowed-tools contains a suspicious OOB-flavored tool "
                f"entry {t!r} — if a real OOB tool has been added, update "
                f"the capability-gating tests below rather than silently "
                f"allowing it."
            )

    def test_core_tools_present(self, skill_frontmatter: dict):
        tools = set(skill_frontmatter["allowed-tools"])
        for expected in {"shell", "http", "read_payloads", "file_write", "ask_user"}:
            assert expected in tools, f"expected tool {expected!r} missing from allowed-tools"

    def test_no_automated_exploitation_tools(self, skill_frontmatter: dict):
        tools = " ".join(skill_frontmatter["allowed-tools"]).lower()
        for banned in ("sqlmap", "ghauri", "exploit"):
            assert banned not in tools


# ---------------------------------------------------------------------------
# 2. Phase 2d capability-gating contract (SKILL.md text)
# ---------------------------------------------------------------------------

class TestPhase2dCapabilityGateText:
    def test_capability_check_section_exists(self, skill_text: str):
        assert "Phase 2d capability check" in skill_text

    def test_capability_checked_before_authorization(self, skill_text: str):
        """
        The gate order matters: capability presence must be checked before
        the skill ever asks the user to authorize something that cannot
        run. Assert the capability-present item appears before the
        explicit-authorization item in the numbered list.
        """
        section = skill_text.split("### Phase 2d capability check", 1)[1]
        section = section.split("### 2d. Out-of-band", 1)[0]
        cap_idx = section.find("Capability present")
        auth_idx = section.find("Explicit authorization")
        assert cap_idx != -1 and auth_idx != -1
        assert cap_idx < auth_idx, (
            "Capability presence must be checked before explicit "
            "authorization in the Phase 2d gate."
        )

    def test_current_capability_absence_is_stated(self, skill_text: str):
        assert "contains no such tool" in skill_text
        assert "check fails by default" in skill_text

    def test_no_workaround_via_shell(self, skill_text: str):
        """
        The skill must explicitly forbid simulating/faking an OOB
        callback via shell or any other substitute mechanism.
        """
        assert re.search(
            r"never be used to simulate, fake, or locally stand in for an OOB",
            _norm(skill_text),
        )
        assert "fake a listener or a callback" in _norm(skill_text)

    def test_failed_capability_check_short_circuits(self, skill_text: str):
        """
        If capability check 1 fails, the skill must stop there — not
        proceed to ask_user for authorization of something unexecutable.
        """
        normalized = _norm(skill_text)
        assert "do not proceed to checks 2 or 3" in normalized
        assert "do not ask" in normalized
        assert "not simulate the technique" in normalized

    def test_failed_capability_check_records_result(self, skill_text: str):
        assert "phase_2d_used: no" in skill_text
        assert "OOB unavailable" in skill_text

    def test_phase3_authorization_is_independent_of_phase2d(self, skill_text: str):
        assert "Do not infer Phase 3 authorization merely because Phase 2d" in skill_text


# ---------------------------------------------------------------------------
# 3. Result recording / outcome contract
# ---------------------------------------------------------------------------

EXPECTED_OUTCOMES = {
    "confirmed (SQLI-2)",
    "confirmed (SQLI-3)",
    "not confirmed",
    "blocked",
    "deferred (nosql, out of scope)",
}


class TestOutcomeContract:
    def test_all_five_outcomes_documented(self, skill_text: str):
        for outcome in EXPECTED_OUTCOMES:
            assert outcome in skill_text, f"missing outcome definition: {outcome!r}"

    def test_not_confirmed_does_not_require_every_technique(self, skill_text: str):
        """
        Regression for the earlier over-strict wording: `not confirmed`
        must not be defined as requiring literally every technique to
        have been run — the "stop at first clear signal" rule means a
        candidate can validly reach `not confirmed` without exhausting
        every phase-2 technique.
        """
        # Find the bullet defining not confirmed in "Recording the result"
        section = skill_text.split("## Recording the result", 1)[1]
        section = section.split("### Standard result entry template", 1)[0]
        not_confirmed_line = [
            line for line in section.splitlines() if line.strip().startswith("- `not confirmed`")
        ]
        assert not_confirmed_line, "could not find the `not confirmed` definition bullet"
        line = not_confirmed_line[0]
        assert "does not mean every technique must be run" in line or "stop at the first clear signal" in line
        assert "every technique actually available" not in line

    def test_blocked_distinct_from_not_confirmed(self, skill_text: str):
        assert "distinct from `not confirmed`" in skill_text

    def test_2c_treated_as_guard_not_confirmation_technique(self, skill_text: str):
        """
        2c (WAF/rate-limit check) should be described as a guard condition
        (absence of blocking), not as a technique that itself must
        produce a positive/negative confirmation signal.
        """
        assert "condition was observed under 2c" in _norm(skill_text)


# ---------------------------------------------------------------------------
# 4. Scope-bound contract ("Bound the proof" / Phase 3 minimalism)
# ---------------------------------------------------------------------------

class TestScopeBounds:
    def test_bound_the_proof_section_exists(self, skill_text: str):
        assert "### Bound the proof" in skill_text

    def test_forbids_union_extraction(self, skill_text: str):
        assert "UNION SELECT" in skill_text
        assert "build or run a `UNION SELECT` chain" in skill_text

    def test_forbids_credential_and_row_dumping(self, skill_text: str):
        assert "dump table/column names, credentials, session tokens, or any real row data" in skill_text

    def test_forbids_automated_tooling_escalation(self, skill_text: str):
        assert '"see how bad it is"' in skill_text or "see how bad it is" in skill_text

    def test_login_boolean_token_is_evidence_not_a_followup_target(
        self, skill_text: str
    ):
        assert "token is incidental evidence" in skill_text
        assert "do not replay it, decode it, request it again" in skill_text
        assert "[REDACTED_TOKEN]" in skill_text
        assert "without sending another request" in skill_text

    def test_missing_jq_never_causes_another_target_request(self, skill_text: str):
        normalized = _norm(skill_text)
        assert "`jq` may be used when available" in normalized
        assert "workflow behavior must not depend on it being installed" in normalized
        assert "Never repeat a target request" in normalized

    def test_sqli2_stops_escalation_but_preserves_authorized_phase3(
        self, skill_text: str
    ):
        section = skill_text.split("### Bound the proof", 1)[1]
        section = section.split("## Phase 3: Minimal Impact Validation", 1)[0]
        normalized = _norm(section)
        assert "stop further confirmation probes and payload escalation" in normalized
        assert "Phase 3 remains available only when its separate authorization" in normalized
        assert "never an automatic next step" in normalized

    def test_phase2a_can_confirm_a_clear_phase1_signal(self, skill_text: str):
        section = skill_text.split("### 2a. Boolean-based differential check", 1)[1]
        section = section.split("### 2b. Time-based check", 1)[0]
        normalized = _norm(section)
        assert "including a clear error-based SQLI-1 signal" in normalized
        assert "Phase 1 alone does not establish SQLI-2" in normalized

    def test_direct_candidate_enters_workflow_before_active_probes(
        self, skill_text: str
    ):
        contract = skill_text.split("## Structured workflow contract", 1)[1]
        contract = contract.split("## Authorization matrix", 1)[0]
        assert "call `start_validation` **before** sending active SQL probes" in _norm(contract)

    def test_finding_impact_does_not_overclaim_admin_access(self, skill_text: str):
        assert "Do not claim full administrative access or account takeover" in _norm(skill_text)

    def test_audit_metadata_must_come_from_runtime(self, skill_text: str):
        normalized = _norm(skill_text)
        assert "Populate them only from runtime-supplied values" in normalized
        assert "never invent a plausible value" in normalized

    def test_phase3_requires_separate_authorization(self, skill_text: str):
        section = skill_text.split("## Phase 3: Minimal Impact Validation", 1)[1]
        section = section.split("## Recording the result", 1)[0]
        assert "explicitly authorizes deeper impact validation via `ask_user`" in section


    def test_phase3_limited_to_fingerprint(self, skill_text: str):
        section = skill_text.split("## Phase 3: Minimal Impact Validation", 1)[1]
        section = section.split("## Recording the result", 1)[0]
        assert "minimal, non-sensitive fingerprint reads" in section
        assert "not user data" in section
        assert "not credentials" in section

    def test_existing_login_impact_evidence_does_not_trigger_another_request(
        self, skill_text: str
    ):
        section = skill_text.split("## Phase 3: Minimal Impact Validation", 1)[1]
        section = section.split("## Recording the result", 1)[0]
        normalized = _norm(section)
        assert "confirming response already contains minimum sufficient impact evidence" in normalized
        assert "without sending another request" in normalized
        assert "does not by itself make the result SQLI-3" in normalized

    def test_column_enumeration_forbidden_in_payloads_and_skill(
        self, skill_text: str, payloads_text: str
    ):
        assert "Do not probe column counts broadly" in payloads_text
        assert "do not iterate" in payloads_text

    def test_nosql_deferred_not_handled_here(self, skill_text: str):
        assert "deferred (nosql, out of scope)" in skill_text
        assert "do not apply SQL syntax to it here" in _norm(skill_text)


# ---------------------------------------------------------------------------
# 5. Finding contract (only confirmed findings reach confirm_finding)
# ---------------------------------------------------------------------------

class TestFindingContract:
    def test_confirm_finding_schema_present(self, skill_text: str):
        assert "confirm_finding:" in skill_text
        for field_name in (
            "title:", "severity:", "url:", "method:", "parameter:",
            "payload:", "response_excerpt:", "impact:", "curl:",
            "remediation:", "vuln_class:",
        ):
            assert field_name in skill_text

    def test_only_confirmed_outcomes_are_persisted(self, skill_text: str):
        assert "Do not call `confirm_finding` for `not confirmed`, `blocked`, or `deferred`" in skill_text

    def test_no_concrete_query_rewrite_in_handoff(self, skill_text: str):
        assert "Do not fill in a rewritten, drop-in query fix" in _norm(skill_text)

    def test_proof_scope_remains_in_durable_evidence(self, skill_text: str):
        assert "proof scope" in skill_text
        assert "results.md" in skill_text

    def test_results_artifact_is_reused_as_evidence(self, skill_text: str):
        normalized = _norm(skill_text)
        assert "register this same file" in normalized
        assert "instead of creating a duplicate evidence Markdown file" in normalized


# ---------------------------------------------------------------------------
# 6. payloads.txt contract
# ---------------------------------------------------------------------------

class TestPayloadsFile:
    def test_phase2d_banner_states_oob_unavailable(self, payloads_text: str):
        normalized = _norm(payloads_text)
        section_markers = [
            "KAgent currently does not expose an OOB callback/listener tool",
            "MUST NOT be executed in the current runtime",
        ]
        for marker in section_markers:
            assert marker in normalized

        # The standalone NOTE banner directly under the PHASE 2D header.
        assert "# NOTE:" in payloads_text
        assert "KAgent currently has no OOB callback/listener tool." in normalized
        assert "must not be executed in the current environment" in normalized
        assert "Never execute them through shell or another substitute mechanism." in normalized

    def test_phase1_comment_does_not_claim_no_logic_change(self, payloads_text: str):
        """
        Regression: Phase 1's old comment claimed none of the probes
        change query logic, which is technically inaccurate for `;` and
        `--`. The corrected comment should describe them as parser/syntax
        boundary probes instead.
        """
        phase1 = payloads_text.split("PHASE 1 — DETECTION", 1)[1]
        phase1 = phase1.split("PHASE 2 — VALIDATION", 1)[0]
        assert "test parser" in phase1 or "syntax boundaries" in phase1
        assert "None of these attempt to change query" not in phase1

    def test_stacked_query_warning_present(self, payloads_text: str):
        phase2 = payloads_text.split("PHASE 2 — VALIDATION", 1)[1]
        phase2 = phase2.split("PHASE 2D", 1)[0]
        assert "stacked" in phase2.lower()
        assert "not evidence against sql injection" in phase2.lower() or "NOT evidence against" in phase2

    def test_oracle_dbms_lock_fallback_present(self, payloads_text: str):
        normalized = _norm(payloads_text)
        assert "DBMS_LOCK is unavailable or unauthorized" in normalized
        assert "Fall back to boolean-based validation" in normalized
        assert "do not substitute an" in normalized.lower() or "expensive recursive/heavy query" in normalized

    def test_phase3_fingerprint_caveat_present(self, payloads_text: str):
        phase3 = payloads_text.split("PHASE 3 — IMPACT", 1)[1]
        assert "without exploratory column/table" in phase3
        assert "Do not probe column counts broadly" in phase3

    def test_no_credential_or_table_dump_payloads(self, payloads_text: str):
        lowered = payloads_text.lower()
        for banned in ("information_schema.tables", "pg_shadow", "sys.user_password", "load credentials"):
            assert banned not in lowered

    def test_tokens_are_placeholders_not_fixed_values(self, payloads_text: str):
        assert "{TOKEN}" in payloads_text
        assert "{CALLBACK_DOMAIN}" in payloads_text

    def test_sections_present_in_order(self, payloads_text: str):
        markers = [
            "PHASE 1 — DETECTION",
            "PHASE 2 — VALIDATION",
            "PHASE 2D — OUT-OF-BAND",
            "PHASE 3 — IMPACT",
        ]
        positions = [payloads_text.index(m) for m in markers]
        assert positions == sorted(positions), "phase sections must appear in order in payloads.txt"


# ---------------------------------------------------------------------------
# 7. Reference gate logic — executable spec (no payloads, no requests)
# ---------------------------------------------------------------------------
#
# This is a small, independent re-implementation of the *decision policy*
# SKILL.md describes for Phase 2d and Phase 3 gating. It exists so the
# policy itself (not just prose) has an automated, falsifiable check. It
# deliberately contains no SQL, no HTTP calls, and no engine-specific
# logic — it only tracks booleans/enums representing "has this
# precondition been met".

Outcome = str  # one of EXPECTED_OUTCOMES


@dataclass
class Phase2State:
    """What's known about a single candidate's Phase 2 progress."""
    technique_2a_tried: bool = False
    technique_2a_signal: bool = False
    technique_2b_tried: bool = False
    technique_2b_signal: bool = False
    blocked_at_2c: bool = False


@dataclass
class Phase2dGate:
    """
    Reference model of the "Phase 2d capability check" in SKILL.md.

    capability_present: whether a real OOB callback/listener tool exists
        in the current runtime's allowed-tools (today: always False).
    """
    capability_present: bool = False
    phase2_state: Phase2State = field(default_factory=Phase2State)
    user_authorized: bool = False
    callback_domain_confirmed: bool = False

    def techniques_exhausted(self) -> bool:
        s = self.phase2_state
        if s.blocked_at_2c:
            return False  # blocked candidates don't proceed to 2d at all
        if s.technique_2a_signal or s.technique_2b_signal:
            return False  # already confirmed via 2a/2b — no need for 2d
        return s.technique_2a_tried and s.technique_2b_tried

    def may_run(self) -> tuple[bool, str]:
        """
        Returns (allowed, reason). Mirrors the three ordered checks in
        SKILL.md: capability -> techniques exhausted -> authorization.
        """
        if not self.capability_present:
            return False, "capability_absent"
        if not self.techniques_exhausted():
            return False, "techniques_not_exhausted"
        if not (self.user_authorized and self.callback_domain_confirmed):
            return False, "not_authorized"
        return True, "ok"


@dataclass
class Phase3Gate:
    sqli_confirmed_level2: bool = False
    user_authorized: bool = False
    impact_probe_succeeded: bool = False
    impact_evidence_already_sufficient: bool = False

    def may_run(self) -> tuple[bool, str]:
        if not self.sqli_confirmed_level2:
            return False, "sqli_not_confirmed"
        if not self.user_authorized:
            return False, "not_authorized"
        return True, "ok"

    def should_send_probe(self) -> tuple[bool, str]:
        allowed, reason = self.may_run()
        if not allowed:
            return False, reason
        if self.impact_evidence_already_sufficient:
            return False, "evidence_already_sufficient"
        return True, "ok"


def resolve_outcome(
    phase1_signal: bool,
    phase2: Phase2State,
    phase2d_gate: Optional[Phase2dGate],
    phase3_gate: Optional[Phase3Gate],
) -> Outcome:
    """
    Reference resolution of the five documented outcomes, following
    "stop at the first clear signal" — this does not require every
    technique to have run.
    """
    if phase2.blocked_at_2c:
        return "blocked"

    sqli2 = phase2.technique_2a_signal or phase2.technique_2b_signal
    if not sqli2 and phase2d_gate is not None:
        allowed, _ = phase2d_gate.may_run()
        if allowed:
            sqli2 = True  # a real OOB callback would be checked by the caller

    if sqli2 and phase3_gate is not None:
        allowed, _ = phase3_gate.may_run()
        if allowed and phase3_gate.impact_probe_succeeded:
            return "confirmed (SQLI-3)"

    if sqli2:
        return "confirmed (SQLI-2)"

    return "not confirmed"


class TestPhase2dGateLogic:
    def test_capability_absent_blocks_regardless_of_other_state(self):
        gate = Phase2dGate(
            capability_present=False,
            phase2_state=Phase2State(technique_2a_tried=True, technique_2b_tried=True),
            user_authorized=True,
            callback_domain_confirmed=True,
        )
        allowed, reason = gate.may_run()
        assert not allowed
        assert reason == "capability_absent"

    def test_capability_present_but_techniques_not_exhausted_blocks(self):
        gate = Phase2dGate(
            capability_present=True,
            phase2_state=Phase2State(technique_2a_tried=True, technique_2b_tried=False),
            user_authorized=True,
            callback_domain_confirmed=True,
        )
        allowed, reason = gate.may_run()
        assert not allowed
        assert reason == "techniques_not_exhausted"

    def test_already_confirmed_by_2a_skips_need_for_2d(self):
        gate = Phase2dGate(
            capability_present=True,
            phase2_state=Phase2State(
                technique_2a_tried=True, technique_2a_signal=True,
                technique_2b_tried=False,
            ),
        )
        # 2d isn't "needed" — techniques_exhausted() is False here because
        # 2a already gave a signal, meaning 2d shouldn't be reached at all.
        assert gate.techniques_exhausted() is False

    def test_capability_and_techniques_ok_but_no_authorization_blocks(self):
        gate = Phase2dGate(
            capability_present=True,
            phase2_state=Phase2State(technique_2a_tried=True, technique_2b_tried=True),
            user_authorized=False,
        )
        allowed, reason = gate.may_run()
        assert not allowed
        assert reason == "not_authorized"

    def test_authorization_without_callback_domain_blocks(self):
        gate = Phase2dGate(
            capability_present=True,
            phase2_state=Phase2State(technique_2a_tried=True, technique_2b_tried=True),
            user_authorized=True,
            callback_domain_confirmed=False,
        )
        allowed, reason = gate.may_run()
        assert not allowed
        assert reason == "not_authorized"

    def test_all_conditions_met_allows(self):
        gate = Phase2dGate(
            capability_present=True,
            phase2_state=Phase2State(technique_2a_tried=True, technique_2b_tried=True),
            user_authorized=True,
            callback_domain_confirmed=True,
        )
        allowed, reason = gate.may_run()
        assert allowed
        assert reason == "ok"

    def test_blocked_at_2c_never_reaches_2d(self):
        gate = Phase2dGate(
            capability_present=True,
            phase2_state=Phase2State(blocked_at_2c=True),
            user_authorized=True,
            callback_domain_confirmed=True,
        )
        allowed, reason = gate.may_run()
        assert not allowed
        assert reason == "techniques_not_exhausted"

    def test_current_environment_default_is_always_blocked(self):
        """
        Mirrors the real repo state today: capability_present defaults to
        False, so Phase2dGate() with no arguments must never allow a run,
        no matter what else is true.
        """
        gate = Phase2dGate(
            phase2_state=Phase2State(technique_2a_tried=True, technique_2b_tried=True),
            user_authorized=True,
            callback_domain_confirmed=True,
        )
        allowed, reason = gate.may_run()
        assert not allowed
        assert reason == "capability_absent"


class TestPhase3GateLogic:
    def test_requires_sqli2_confirmed_first(self):
        gate = Phase3Gate(sqli_confirmed_level2=False, user_authorized=True)
        allowed, reason = gate.may_run()
        assert not allowed
        assert reason == "sqli_not_confirmed"

    def test_requires_its_own_authorization(self):
        gate = Phase3Gate(sqli_confirmed_level2=True, user_authorized=False)
        allowed, reason = gate.may_run()
        assert not allowed
        assert reason == "not_authorized"

    def test_phase2d_authorization_does_not_imply_phase3(self):
        """
        Phase 2d and Phase 3 authorizations are independent — granting one
        must never be interpreted as granting the other.
        """
        phase2d = Phase2dGate(
            capability_present=True,
            phase2_state=Phase2State(technique_2a_tried=True, technique_2b_tried=True),
            user_authorized=True,
            callback_domain_confirmed=True,
        )
        phase2d_allowed, _ = phase2d.may_run()
        assert phase2d_allowed

        # A fresh Phase3Gate has its own, separate user_authorized flag —
        # it must start false regardless of phase2d's state.
        phase3 = Phase3Gate(sqli_confirmed_level2=True)
        allowed, reason = phase3.may_run()
        assert not allowed
        assert reason == "not_authorized"

    def test_all_conditions_met_allows(self):
        gate = Phase3Gate(sqli_confirmed_level2=True, user_authorized=True)
        allowed, reason = gate.may_run()
        assert allowed

    def test_sufficient_existing_evidence_stops_an_authorized_phase3_probe(self):
        gate = Phase3Gate(
            sqli_confirmed_level2=True,
            user_authorized=True,
            impact_evidence_already_sufficient=True,
        )
        should_probe, reason = gate.should_send_probe()
        assert not should_probe
        assert reason == "evidence_already_sufficient"

    def test_phase3_probe_is_optional_even_when_authorized(self):
        gate = Phase3Gate(sqli_confirmed_level2=True, user_authorized=True)
        should_probe, reason = gate.should_send_probe()
        assert should_probe
        assert reason == "ok"


class TestOutcomeResolution:
    def test_blocked_takes_precedence(self):
        outcome = resolve_outcome(
            phase1_signal=True,
            phase2=Phase2State(blocked_at_2c=True),
            phase2d_gate=None,
            phase3_gate=None,
        )
        assert outcome == "blocked"

    def test_not_confirmed_without_exhausting_every_technique(self):
        """
        Regression for the earlier over-strict `not confirmed` wording:
        a candidate with only 2a tried (and no signal), where context
        makes 2b inapplicable, can still validly resolve to
        `not confirmed` — it is not required to have run 2b.
        """
        outcome = resolve_outcome(
            phase1_signal=True,
            phase2=Phase2State(technique_2a_tried=True, technique_2a_signal=False),
            phase2d_gate=None,
            phase3_gate=None,
        )
        assert outcome == "not confirmed"

    def test_confirmed_sqli2_via_2a(self):
        outcome = resolve_outcome(
            phase1_signal=True,
            phase2=Phase2State(technique_2a_tried=True, technique_2a_signal=True),
            phase2d_gate=None,
            phase3_gate=None,
        )
        assert outcome == "confirmed (SQLI-2)"

    def test_confirmed_sqli3_requires_phase3_gate_allowed(self):
        phase3 = Phase3Gate(
            sqli_confirmed_level2=True,
            user_authorized=True,
            impact_probe_succeeded=True,
        )
        outcome = resolve_outcome(
            phase1_signal=True,
            phase2=Phase2State(technique_2a_tried=True, technique_2a_signal=True),
            phase2d_gate=None,
            phase3_gate=phase3,
        )
        assert outcome == "confirmed (SQLI-3)"

    def test_phase3_authorization_alone_does_not_upgrade_sqli2(self):
        phase3 = Phase3Gate(sqli_confirmed_level2=True, user_authorized=True)
        outcome = resolve_outcome(
            phase1_signal=True,
            phase2=Phase2State(technique_2a_tried=True, technique_2a_signal=True),
            phase2d_gate=None,
            phase3_gate=phase3,
        )
        assert outcome == "confirmed (SQLI-2)"

    def test_sqli2_without_phase3_authorization_stays_sqli2(self):
        phase3 = Phase3Gate(sqli_confirmed_level2=True, user_authorized=False)
        outcome = resolve_outcome(
            phase1_signal=True,
            phase2=Phase2State(technique_2a_tried=True, technique_2a_signal=True),
            phase2d_gate=None,
            phase3_gate=phase3,
        )
        assert outcome == "confirmed (SQLI-2)"

    def test_2d_unreachable_in_current_environment_never_yields_sqli2(self):
        """
        End-to-end regression: with capability_present defaulted False
        (today's real state), a candidate that only 2a/2b were
        inconclusive on must resolve to `not confirmed`, never quietly
        "confirm" via an unreachable Phase 2d.
        """
        gate = Phase2dGate(
            phase2_state=Phase2State(technique_2a_tried=True, technique_2b_tried=True),
            user_authorized=True,
            callback_domain_confirmed=True,
        )
        outcome = resolve_outcome(
            phase1_signal=True,
            phase2=Phase2State(technique_2a_tried=True, technique_2b_tried=True),
            phase2d_gate=gate,
            phase3_gate=None,
        )
        assert outcome == "not confirmed"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
