"""
Tests for authentication/SKILL.md.

Three classes, mirroring test_access_control.py:

- `TestSkillFileStructure` — checks the raw frontmatter + markdown body
  directly (regex split + PyYAML for the frontmatter block). Makes no
  assumption about how KAgent's real skill loader works, so it keeps
  working even if `src/skills/load_skill.py`'s internal API changes later.

- `TestSkillDecisionContract` — protects the behavioral invariants of the
  authentication playbook: identity/credential safety, scope boundaries
  (including the SSO/OAuth carve-out), tier ordering, 401/403 handling,
  write-authorization safety, expired-artifact handling, shared-state
  isolation across candidates, the overall-vs-sub-check outcome model, and
  handoff semantics.

- `TestRegistryIntegration` — checks that every string in `allowed-tools`
  actually resolves to a registered `Tool.name()`, using the real
  `Registry` and real `Tool` classes, constructed the same way
  `src/cli/main.py` constructs them at startup.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml


SKILL_PATH = (
    Path(__file__).resolve().parents[2]
    / "skills"
    / "authentication"
    / "SKILL.md"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def skill_text() -> str:
    assert SKILL_PATH.exists(), (
        f"expected skill file at {SKILL_PATH} — adjust SKILL_PATH if the "
        f"real skills directory layout differs"
    )
    return SKILL_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def frontmatter(skill_text: str) -> dict:
    m = re.match(r"^---\n(.*?)\n---\n", skill_text, re.DOTALL)
    assert m, "SKILL.md must open with a --- delimited YAML frontmatter block"
    fm = yaml.safe_load(m.group(1))
    assert isinstance(fm, dict)
    return fm


@pytest.fixture(scope="module")
def body(skill_text: str) -> str:
    m = re.match(r"^---\n.*?\n---\n(.*)$", skill_text, re.DOTALL)
    assert m
    return m.group(1)


# ---------------------------------------------------------------------------
# Tier 1 — structural checks on the raw file (no loader dependency)
# ---------------------------------------------------------------------------

class TestSkillFileStructure:

    def test_name_field(self, frontmatter):
        assert frontmatter.get("name") == "authentication"

    def test_description_present_and_substantial(self, frontmatter):
        desc = frontmatter.get("description")
        assert isinstance(desc, str)
        assert len(desc.strip()) > 150

    def test_description_references_upstream_skill(self, frontmatter):
        assert "web-input-analysis" in frontmatter["description"]

    def test_description_references_finding_tool(self, frontmatter):
        assert "confirm_finding" in frontmatter["description"]

    def test_description_disclaims_self_provisioning(self, frontmatter):
        desc = frontmatter["description"]
        assert "fabricated" in desc
        assert "self-provisioned" in desc

    def test_allowed_tools_exact_set(self, frontmatter):
        assert frontmatter.get("allowed-tools") == [
            "shell",
            "http",
            "file_write",
            "ask_user",
            "confirm_finding",
            "workflow",
        ]

    REQUIRED_HEADERS_IN_ORDER = [
        "# Authentication playbook",
        "## Scope",
        "## Target identifier",
        "## Preconditions",
        "## Credential and session material: use only what you're given",
        "## 1. Select and restate the candidate",
        "## 2. Establish a clean baseline",
        "## 3. Test the relevant property, least intrusive first",
        "## 4. Bound the proof — do not escalate into impact demonstration",
        "## 5. Record the result",
        "## 6. Confirm an evidence-backed finding",
        "## Stop conditions",
    ]

    def test_all_required_sections_present(self, body):
        missing = [h for h in self.REQUIRED_HEADERS_IN_ORDER if h not in body]
        assert not missing, f"missing sections: {missing}"

    def test_sections_appear_in_documented_order(self, body):
        positions = [body.index(h) for h in self.REQUIRED_HEADERS_IN_ORDER]
        assert positions == sorted(positions), (
            "section headers exist but are out of order relative to "
            "REQUIRED_HEADERS_IN_ORDER"
        )

    def _section(self, body: str, start_header: str, end_header: str) -> str:
        start = body.index(start_header)
        end = body.index(end_header)
        assert start < end
        return body[start:end]

    def test_step5_defines_all_six_outcomes(self, body):
        section = self._section(
            body,
            "## 5. Record the result",
            "## 6. Confirm an evidence-backed finding",
        )
        outcomes = [
            "`confirmed`",
            "`not confirmed`",
            "`blocked`",
            "`insufficient-identity`",
            "`requires-authorization-for-write`",
            "`deferred (out of scope)`",
        ]
        for outcome in outcomes:
            assert outcome in section, (
                f"outcome {outcome} not defined in step 5"
            )

    def test_target_identifier_convention_is_reused_not_redefined(self, body):
        section = self._section(
            body,
            "## Target identifier",
            "## Preconditions",
        )
        assert "recon/SKILL.md" in section
        assert "Reuse that" in section
        assert "identifier exactly" in section

    def test_http_tool_operational_notes_present(self, body):
        assert "Three operational notes" in body
        assert "Content-Type" in body
        assert "stateless" in body
        assert "cookie jar" in body

    def test_permission_prompt_cache_invariant_present(self, body):
        """
        Ported from access-control: swapping session/credential material
        against the same target host does not itself trigger a new
        permission prompt, so tooling silence must never be read as
        confirmation that the session/account under test actually
        changed.
        """
        section = re.sub(
            r"\s+",
            " ",
            self._section_for_module(
                body,
                "Three operational notes",
                "## Scope",
            ),
        )
        assert "cached per target host" in section
        assert "not\n  per credential/session" in body or "not per credential/session" in section
        assert "not itself trigger a new prompt" in section
        assert "must be verified from the response/evidence" in section

    @staticmethod
    def _section_for_module(body: str, start: str, end: str) -> str:
        s = body.index(start)
        e = body.index(end)
        assert s < e
        return body[s:e]

    def test_no_unresolved_placeholders(self, body):
        for banned in ["<TARGET>", "<HOST>", "<PAYLOAD>", "<endpoint>"]:
            assert banned not in body, (
                f"found unresolved placeholder {banned}"
            )

    def test_declares_correct_results_path(self, body):
        assert "artifacts/authentication/<target>/results.md" in body

    def test_curl_post_auth_examples_use_explicit_cookie_jar(self, body):
        """
        HTTPTool/curl are stateless and don't inherit cookies between
        invocations. Unlike access-control (which attaches an explicit
        Cookie header per identity), this skill's baseline explicitly
        manages a cookie jar file (`-c` to write, `-b` to read) so the
        pre-/post-auth session distinction stays visible across calls.
        Any example that reuses a post-auth session must read it back
        from an explicit jar file via `-b`, not rely on implicit state.
        """
        code_blocks = re.findall(r"```sh\n(.*?)```", body, re.DOTALL)
        jar_write_blocks = [b for b in code_blocks if " -c " in b or b.strip().startswith("curl -c")]
        jar_read_blocks = [b for b in code_blocks if " -b " in b or b.strip().startswith("curl -b")]

        assert jar_write_blocks, (
            "expected at least one example that establishes a cookie jar "
            "with -c (the baseline capture)"
        )
        assert jar_read_blocks, (
            "expected at least one example that reuses session state via "
            "-b (e.g. the logout-replay or MFA-bypass checks)"
        )

        for blk in jar_read_blocks:
            jar_paths = re.findall(r"-b\s+(\S+)", blk)
            assert jar_paths, f"block uses -b but no jar path found:\n{blk}"
            for path in jar_paths:
                assert path.startswith("/tmp/cookies_") or path.startswith("$"), (
                    f"cookie jar path {path!r} is not an explicit, "
                    f"skill-managed jar file:\n{blk}"
                )

    def test_secret_material_never_written_literally_to_results(self, body):
        section = self._section(
            body,
            "## 4. Bound the proof — do not escalate into impact demonstration",
            "## 5. Record the result",
        )
        assert "results.md" in section
        assert "raw secret values" in re.sub(r"\s+", " ", section)

    def test_five_attempt_cap_is_a_literal_loop_bound(self, body):
        section = self._section(
            body,
            "## 3. Test the relevant property, least intrusive first",
            "## 4. Bound the proof",
        )
        assert "for i in 1 2 3 4 5; do" in section
        assert "cap at 5 attempts" in section
        assert "Stop at 5 regardless of outcome" in section


# ---------------------------------------------------------------------------
# Tier 1b — behavioral / decision contract
# ---------------------------------------------------------------------------

class TestSkillDecisionContract:

    def _section(self, body: str, start_header: str, end_header: str) -> str:
        start = body.index(start_header)
        end = body.index(end_header)
        assert start < end
        return body[start:end]

    @staticmethod
    def _norm(s: str) -> str:
        """
        Collapse whitespace so markdown line wrapping does not affect
        semantic substring checks.
        """
        return re.sub(r"\s+", " ", s)

    def test_identity_section_explicitly_forbids_self_provisioning(self, body):
        section = self._norm(
            self._section(
                body,
                "## Credential and session material: use only what you're given",
                "## 1. Select and restate the candidate",
            )
        )

        assert "Do not:" in section
        assert "register new accounts" in section
        assert "explicitly authorized" in section
        assert "proceed with a test" in section
        assert "insufficient-identity" in section

    def test_identity_section_forbids_guessing_or_brute_forcing(self, body):
        section = self._norm(
            self._section(
                body,
                "## Credential and session material: use only what you're given",
                "## 1. Select and restate the candidate",
            )
        )
        assert "guess, brute-force, spray" in section
        assert "real user's password, OTP, or reset token" in section

    def test_identity_section_treats_unavailable_reset_channel_as_insufficient(self, body):
        section = self._norm(
            self._section(
                body,
                "## Credential and session material: use only what you're given",
                "## 1. Select and restate the candidate",
            )
        )
        assert "reset or OTP delivery channel" in section
        assert "insufficient-identity" in section
        assert "not `not confirmed`" in section

    def test_scope_forbids_scope_expansion(self, body):
        scope = self._norm(
            self._section(
                body,
                "## Scope",
                "## Target identifier",
            )
        )

        assert "Do not:" in scope
        assert "expand scope" in scope
        assert "web-input-analysis" in scope

        for excluded in ["CSRF", "JWT", "OAuth"]:
            assert excluded in scope

        assert "out of scope" in scope

    def test_scope_carves_out_third_party_sso_oauth(self, body):
        """
        Patch point 1: the authentication decision made by an external
        identity provider is out of this skill's testable surface — only
        the target application's own local session boundary is in scope.
        """
        scope = self._norm(
            self._section(
                body,
                "## Scope",
                "## Target identifier",
            )
        )
        assert "SSO/OAuth identity" in scope
        assert "outside the" in scope
        assert "target application's control" in scope
        assert "deferred (out of scope)" in scope

    def test_boundary_tiers_present_and_ordered(self, body):
        headers = [
            "Tier 1 — session fixation",
            "Tier 2 — session invalidation",
            "Tier 3 — MFA step enforcement",
            "Tier 4 — password-reset flow integrity",
            "Tier 5 — lockout / rate-limiting presence",
        ]

        positions = [body.index(h) for h in headers]
        assert positions == sorted(positions)

    def test_testing_is_least_intrusive_and_can_stop_early(self, body):
        section = self._norm(
            self._section(
                body,
                "## 3. Test the relevant property, least intrusive first",
                "## 4. Bound the proof",
            )
        )

        assert "Stop as soon as" in section
        assert "don't need every tier" in section

    def test_401_403_is_not_automatically_classified_as_blocked(self, body):
        """
        Application-level 401/403 denial is a meaningful not-confirmed
        result, while upstream WAF/challenge interception is blocked.
        This is patch point 7, ported from the access-control invariant
        but matched to authentication's actual wording (which frames the
        rule as "not by itself evidence of blocked" rather than
        access-control's "not... from the status code alone" phrasing).
        """
        section = self._norm(
            self._section(
                body,
                "## 3. Test the relevant property, least intrusive first",
                "## 4. Bound the proof",
            )
        )

        assert "401" in section
        assert "403" in section
        assert "not by itself evidence" in section
        assert "application-level" in section
        assert "not confirmed" in section
        assert "WAF" in section
        assert "upstream interception" in section

    def test_tier5_requires_established_expected_control_for_confirmed(self, body):
        section = self._norm(
            self._section(
                body,
                "Tier 5 — lockout / rate-limiting presence",
                "Rules across all tiers",
            )
        )
        assert "Only record" in section
        assert "confirmed" in section
        assert "specifically identified an" in section
        assert "expected" in section
        assert "control" in section

    def test_tier5_preserves_bounded_observation_even_when_not_confirmed(self, body):
        """
        Review fix: absence of an established expected control must not
        cause the raw 5-attempt observation to be discarded.
        """
        section = self._norm(
            self._section(
                body,
                "Tier 5 — lockout / rate-limiting presence",
                "Rules across all tiers",
            )
        )
        assert "Record this bounded" in section
        assert "do not discard the" in section

    def test_expired_or_stale_artifact_is_not_treated_as_secure(self, body):
        """
        Patch point 3: a token/OTP that expires mid-test must not be
        misread as evidence the property under test is secure.
        """
        section = self._norm(
            self._section(
                body,
                "## 3. Test the relevant property, least intrusive first",
                "## 4. Bound the proof",
            )
        )
        assert "expired/stale" in section
        assert "do not treat the" in section
        assert "resulting rejection as evidence that the underlying property is secure" in section
        assert "fresh" in section

    def test_isolation_across_candidates_sharing_state_is_defined(self, body):
        """
        Patch point 4: candidates that share a test account, session, or
        reset/MFA artifact must not let one candidate's testing consume
        or invalidate material another candidate still needs.
        """
        section = self._norm(
            self._section(
                body,
                "## 3. Test the relevant property, least intrusive first",
                "## 4. Bound the proof",
            )
        )
        assert "Isolation across candidates sharing state" in section
        assert "do not let testing one candidate consume or invalidate" in section
        assert "sequence state-destroying checks last" in section

    def test_step1_points_to_isolation_rule_for_shared_candidates(self, body):
        section = self._norm(
            self._section(
                body,
                "## 1. Select and restate the candidate",
                "## 2. Establish a clean baseline",
            )
        )
        assert "Isolation across candidates sharing state" in section

    def test_step1_prioritizes_least_dependent_check_first(self, body):
        """
        Parity fix ported from access-control's "always attempt that one
        first" guidance for the anonymous-vs-required-auth tier.
        """
        section = self._norm(
            self._section(
                body,
                "## 1. Select and restate the candidate",
                "## 2. Establish a clean baseline",
            )
        )
        assert "least-dependent check" in section
        assert "before tests that require additional credential" in section

    def test_write_testing_requires_explicit_authorization(self, body):
        section = self._norm(
            self._section(
                body,
                "## 4. Bound the proof",
                "## 5. Record the result",
            )
        )

        assert "requires-authorization-for-write" in section
        assert "explicit authorization" in section

    def test_requires_authorization_for_write_is_scoped_to_auth_state_changes(self, body):
        """
        Patch point 5: the outcome name is shared with access-control's
        taxonomy for a consistent downstream contract, but its meaning
        here must be pinned to authentication-specific state changes
        (reset trigger, MFA enrollment/reset, lockout/unlock, forced
        logout) rather than left to read as the access-control notion of
        a state-changing write against another user's resource.
        """
        section = self._norm(
            self._section(
                body,
                "## 5. Record the result",
                "## 6. Confirm an evidence-backed finding",
            )
        )
        assert "In this skill, this outcome specifically" in section
        assert "authentication state-changing actions" in section
        for action in [
            "triggering a password",
            "MFA enrollment/reset",
            "account lockout/unlock",
            "forced logout",
        ]:
            assert action in section

    def test_outcome_model_distinguishes_overall_from_sub_check(self, body):
        """
        Patch point 6: a candidate has exactly one overall outcome for
        hand-off purposes, but tiers with genuinely independent
        sub-checks (Tier 4) may record their own outcomes individually.
        """
        raw_section = self._section(
            body,
            "## 5. Record the result",
            "## 6. Confirm an evidence-backed finding",
        )
        section = self._norm(raw_section)
        assert "one **overall** outcome" in raw_section
        assert "sub-check" in section
        assert "derive the candidate's overall outcome" in section
        assert (
            "confirmed` if any sub-check reached" in section
            or "is `confirmed` if any sub-check" in section
        )

    def test_tier4_binding_subcheck_requires_second_account(self, body):
        section = self._norm(
            self._section(
                body,
                "Tier 4 — password-reset flow integrity",
                "Tier 5 — lockout / rate-limiting presence",
            )
        )
        assert "second, distinct test" in section
        assert "insufficient-identity" in section
        assert "do not infer binding behavior from the single-use/expiry checks" in section

    def test_observed_and_potential_impact_are_separated(self, body):
        """
        Patch point 2: impact described before calling `confirm_finding`
        observed impact must be evidence-backed, with untested consequences
        kept conditional in potential impact.
        """
        section = self._norm(
            self._section(
                body,
                "## 6. Confirm an evidence-backed finding",
                "## Stop conditions",
            )
        )
        assert "`observed_impact`: only what the authentication evidence demonstrates" in section
        assert "`potential_impact`: possible consequences" in section
        assert "stated conditionally" in section

    def test_deferred_candidates_are_not_handed_off(self, body):
        section = self._norm(
            self._section(
                body,
                "## 6. Confirm an evidence-backed finding",
                "## Stop conditions",
            )
        )

        assert "Do not call `confirm_finding`" in section
        assert "deferred (out of scope)" in section

    def test_only_confirmed_is_handed_off(self, body):
        section = self._norm(
            self._section(
                body,
                "## 6. Confirm an evidence-backed finding",
                "## Stop conditions",
            )
        )

        assert "Do not call `confirm_finding`" in section

        for non_handoff in [
            "not confirmed",
            "blocked",
            "insufficient-identity",
            "requires-authorization-for-write",
            "deferred (out of scope)",
        ]:
            assert non_handoff in section

    def test_stop_conditions_restate_core_guardrails(self, body):
        section = self._norm(body[body.index("## Stop conditions"):])

        for guardrail in [
            "guess or",
            "brute-force real credentials/OTPs/reset tokens",
            "exceed the Tier 5 five-attempt cap",
            "fabricate or self-provision test accounts",
            "account-takeover demonstrations",
            "run automated credential-testing tools by default",
            "retry blocked probes with bypass tricks",
        ]:
            assert guardrail in section


# ---------------------------------------------------------------------------
# Tier 2 — real Registry / real Tool integration
# ---------------------------------------------------------------------------

class TestRegistryIntegration:

    @pytest.fixture
    def registry(self, tmp_path):
        from src.tools.registry import Registry
        from src.tools.shell import ShellTool
        from src.tools.file import FileWriteTool
        from src.tools.http import HTTPTool
        from src.tools.ask import AskUserTool
        from src.tools.finding import ConfirmFindingTool
        from src.findings.store import Store
        from src.target.target import Target
        from src.tools.workflow import WorkflowTool
        from src.workflow.state import WorkflowState

        reg = Registry()
        target = Target()

        class StubPrompter:
            async def ask(self, q, signal=None) -> str:
                return ""

        reg.register(ShellTool())
        reg.register(FileWriteTool())
        from src.engagement.state import EngagementState
        reg.register(HTTPTool(target, EngagementState()))
        reg.register(AskUserTool(StubPrompter()))
        reg.register(ConfirmFindingTool(Store(str(tmp_path / "findings"))))
        reg.register(WorkflowTool(WorkflowState()))

        return reg

    def test_every_allowed_tool_is_registered(self, frontmatter, registry):
        for tool_name in frontmatter["allowed-tools"]:
            assert registry.get(tool_name) is not None, (
                f"allowed-tools entry {tool_name!r} does not resolve to a "
                f"registered tool"
            )

    def test_allowed_tools_are_subset_of_registered_tools(
        self,
        frontmatter,
        registry,
    ):
        allowed = set(frontmatter["allowed-tools"])
        registered = set(registry.names())

        assert allowed.issubset(registered), (
            "allowed-tools contains names not in the registry: "
            f"{allowed - registered}"
        )

    def test_no_registered_tool_used_outside_allowed_tools(
        self,
        frontmatter,
        body,
        registry,
    ):
        """
        Heuristic: flag any other registered tool name that appears as an
        inline-code token in the skill body but isn't declared in
        allowed-tools.

        False positives are possible if prose mentions a tool name in
        passing without intending to invoke it. Treat a failure here as
        a review signal, not automatic proof of a bug.
        """
        allowed = set(frontmatter["allowed-tools"])
        undeclared_registered = set(registry.names()) - allowed

        mentioned_as_code = set(re.findall(r"`([a-z_]+)`", body))
        suspicious = undeclared_registered & mentioned_as_code

        assert not suspicious, (
            "skill body references registered tool(s) "
            f"{suspicious} as inline code without declaring them in "
            "allowed-tools"
        )
