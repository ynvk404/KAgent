"""
Tests for access-control/SKILL.md.

Three classes:

- `TestSkillFileStructure` — checks the raw frontmatter + markdown body
  directly (regex split + PyYAML for the frontmatter block). Makes no
  assumption about how KAgent's real skill loader works, so it keeps
  working even if `src/skills/load_skill.py`'s internal API changes later.

- `TestSkillDecisionContract` — protects the behavioral invariants of the
  access-control playbook, such as identity safety, scope boundaries,
  tier ordering, 401/403 handling, write safety, and handoff semantics.
  Includes the normalized `deferred (out of scope)` taxonomy (this skill
  used to emit `deferred (authentication, out of scope)`, which didn't
  cover the CSRF/JWT/session-management out-of-scope cases also listed in
  Scope; it's now generic-outcome-string + free-text-reason, matching
  `authentication`'s taxonomy so `finding-validation` can parse one enum
  across skills), and the permission-prompt-cache operational note.

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
    Path(__file__).resolve().parent.parent
    / "skills"
    / "access-control"
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
        assert frontmatter.get("name") == "access-control"

    def test_description_present_and_substantial(self, frontmatter):
        desc = frontmatter.get("description")
        assert isinstance(desc, str)
        assert len(desc.strip()) > 150

    def test_description_references_upstream_skill(self, frontmatter):
        assert "web-input-analysis" in frontmatter["description"]

    def test_description_references_downstream_skill(self, frontmatter):
        assert "finding-validation" in frontmatter["description"]

    def test_allowed_tools_exact_set(self, frontmatter):
        assert frontmatter.get("allowed-tools") == [
            "shell",
            "http",
            "file_write",
            "ask_user",
        ]

    REQUIRED_HEADERS_IN_ORDER = [
        "# Access control playbook",
        "## Scope",
        "## Target identifier",
        "## Preconditions",
        "## Identity material: use only what you're given",
        "## 1. Select and restate the candidate",
        "## 2. Establish a clean baseline",
        "## 3. Test the relevant boundary, least intrusive first",
        "## 4. Bound the proof — do not escalate into impact demonstration",
        "## 5. Record the result",
        "## 6. Hand off to finding-validation",
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
            "## 6. Hand off to finding-validation",
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

    def test_no_stale_authentication_scoped_deferred_string(self, body):
        """
        Regression guard: this skill used to emit
        `deferred (authentication, out of scope)`, which only covered one
        of the four out-of-scope categories listed in Scope (auth, CSRF,
        JWT/OAuth, session-management). That string must not reappear —
        the outcome is now the generic `deferred (out of scope)` with a
        free-text reason instead.
        """
        assert "deferred (authentication, out of scope)" not in body

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
        assert "cached per target host" in body

    def test_no_unresolved_placeholders(self, body):
        for banned in ["<TARGET>", "<HOST>", "<PAYLOAD>", "<endpoint>"]:
            assert banned not in body, (
                f"found unresolved placeholder {banned}"
            )

    def test_declares_correct_results_path(self, body):
        assert "access-control/<target>/results.md" in body

    def test_curl_identity_examples_show_explicit_cookie_header(self, body):
        """
        HTTPTool/curl are stateless — every example that references a
        SESSION_* variable must explicitly interpolate that identity into
        a Cookie header in the same command block.
        """
        code_blocks = re.findall(r"```sh\n(.*?)```", body, re.DOTALL)
        session_blocks = [b for b in code_blocks if "SESSION_" in b]

        assert session_blocks, (
            "expected at least one example using SESSION_*"
        )

        for blk in session_blocks:
            session_vars = set(
                re.findall(r"\bSESSION_[A-Z0-9_]+\b", blk)
            )
            assert session_vars, (
                f"block mentions SESSION_ but no var found:\n{blk}"
            )

            for var in session_vars:
                pattern = rf'Cookie:\s*\$\{{?{re.escape(var)}\}}?'
                assert re.search(pattern, blk), (
                    f"{var} is referenced but not interpolated into a "
                    f"Cookie header in the same block:\n{blk}"
                )


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
                "## Identity material: use only what you're given",
                "## 1. Select and restate the candidate",
            )
        )

        assert "Do not:" in section
        assert "register new accounts" in section
        assert "explicitly authorized" in section
        assert "proceed with a test" in section
        assert "insufficient-identity" in section

    def test_permission_prompt_cache_invariant_present(self, body):
        """
        Permission prompts (where applicable) are cached per target host,
        not per identity — swapping SESSION_A for SESSION_B must not be
        read as proof the identity actually changed; that must come from
        response evidence.
        """
        section = self._norm(body)
        assert "cached per target host" in section
        assert "not per identity" in section
        assert "will not itself trigger a new prompt" in section
        assert "must be verified from the response/evidence" in section

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

    def test_scope_lists_four_out_of_scope_categories_and_taxonomy_covers_all(self, body):
        """
        Scope excludes four categories (authentication, CSRF, JWT/OAuth,
        session-management). The single `deferred (out of scope)` outcome
        string must be generic enough to cover all four via its free-text
        reason, rather than being pinned to just one of them.
        """
        scope = self._norm(
            self._section(
                body,
                "## Scope",
                "## Target identifier",
            )
        )
        for category in [
            "authentication mechanics",
            "CSRF",
            "JWT/OAuth token vulnerabilities",
            "session-management bugs",
        ]:
            assert category in scope

        step5 = self._norm(
            self._section(
                body,
                "## 5. Record the result",
                "## 6. Hand off to finding-validation",
            )
        )
        assert "`deferred (out of scope)`" in step5
        assert "Record" in step5
        assert "specific reason" in step5

    def test_boundary_tiers_present_and_ordered(self, body):
        headers = [
            "Tier 1 — anonymous vs. required auth",
            "Tier 2 — horizontal:",
            "Tier 3 — vertical:",
            "Tier 4 — parameter/role tampering",
            "Tier 5 — WAF / rate-limiting / upstream interception check",
        ]

        positions = [body.index(h) for h in headers]
        assert positions == sorted(positions)

    def test_testing_is_least_intrusive_and_can_stop_early(self, body):
        section = self._norm(
            self._section(
                body,
                "## 3. Test the relevant boundary, least intrusive first",
                "## 4. Bound the proof",
            )
        )

        assert "Stop as soon as" in section
        assert "don't need every tier" in section

    def test_403_is_not_automatically_classified_as_blocked(self, body):
        """
        Application-level 401/403 denial is a meaningful not-confirmed
        result, while upstream WAF/challenge interception is blocked.
        """
        section = self._norm(
            self._section(
                body,
                "## 3. Test the relevant boundary, least intrusive first",
                "## 4. Bound the proof",
            )
        )

        assert "403" in section
        assert "status code alone" in section
        assert "application-level" in section
        assert "not confirmed" in section
        assert "WAF" in section
        assert "upstream" in section

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
        assert "state-changing" in section

    def test_deferred_candidates_are_not_handed_off(self, body):
        section = self._norm(
            self._section(
                body,
                "## 6. Hand off to finding-validation",
                "## Stop conditions",
            )
        )

        assert "Do not hand off" in section
        assert "deferred (out of scope)" in section

    def test_only_confirmed_is_handed_off(self, body):
        section = self._norm(
            self._section(
                body,
                "## 6. Hand off to finding-validation",
                "## Stop conditions",
            )
        )

        assert "Do not hand off" in section

        for non_handoff in [
            "not confirmed",
            "blocked",
            "insufficient-identity",
            "requires-authorization-for-write",
            "deferred (out of scope)",
        ]:
            assert non_handoff in section

    def test_step5_capture_list_records_deferred_reason(self, body):
        """
        Since the outcome string is now generic, step 5's per-candidate
        capture list must explicitly call out recording the specific
        deferred reason (mirroring authentication's equivalent bullet),
        or the free-text reason has nowhere defined to live.
        """
        section = self._norm(
            self._section(
                body,
                "## 5. Record the result",
                "## 6. Hand off to finding-validation",
            )
        )
        assert "the specific reason for a `deferred` outcome" in section


# ---------------------------------------------------------------------------
# Tier 2 — real Registry / real Tool integration
# ---------------------------------------------------------------------------

class TestRegistryIntegration:

    @pytest.fixture
    def registry(self):
        from src.tools.registry import Registry
        from src.tools.shell import ShellTool
        from src.tools.file import FileWriteTool
        from src.tools.http import HTTPTool
        from src.tools.ask import AskUserTool
        from src.target.target import Target

        reg = Registry()
        target = Target()

        class StubPrompter:
            async def ask(self, q, signal=None) -> str:
                return ""

        reg.register(ShellTool())
        reg.register(FileWriteTool())
        reg.register(HTTPTool(target))
        reg.register(AskUserTool(StubPrompter()))

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