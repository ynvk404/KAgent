"""Tests for the recon SKILL.md contract.

These tests intentionally validate the skill as a prompt/playbook rather than
trying to execute curl or invoke the LLM.  They are therefore stable even when
KAgent's runtime/tool implementations change.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml


def find_recon_skill() -> Path:
    """Locate recon/SKILL.md from the test file or its parent directories."""
    roots = [Path(__file__).resolve().parent, *Path(__file__).resolve().parents]
    candidates: list[Path] = []
    for root in roots:
        candidates.extend(
            [
                root / "skills" / "recon" / "SKILL.md",
                root / "src" / "skills" / "recon" / "SKILL.md",
                root / ".agents" / "skills" / "recon" / "SKILL.md",
                root / ".claude" / "skills" / "recon" / "SKILL.md",
            ]
        )
    for path in candidates:
        if path.is_file():
            return path
    pytest.fail(
        "Could not find recon/SKILL.md. Checked:\n"
        + "\n".join(f"- {path}" for path in candidates)
    )


def read_skill() -> tuple[dict, str, Path]:
    path = find_recon_skill()
    text = path.read_text(encoding="utf-8")

    match = re.match(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", text, re.DOTALL)
    assert match, "SKILL.md must contain YAML frontmatter delimited by ---"

    frontmatter = yaml.safe_load(match.group(1)) or {}
    body = match.group(2)
    assert isinstance(frontmatter, dict), "Frontmatter must parse to a mapping"
    return frontmatter, body, path


def collapse_ws(s: str) -> str:
    """
    Collapse every run of whitespace (including hard-wrap newlines) to a
    single space.

    SKILL.md is hard-wrapped at ~79 cols, so a phrase that reads as one
    sentence in the source prose can still contain a literal newline
    between two of its words (e.g. "...so validate\nthe response before
    parsing..."). Prose/phrase assertions should compare against this
    collapsed form so the assertion doesn't depend on where a line
    happened to wrap. Structural checks (headings, frontmatter, fenced
    code blocks where exact formatting matters) should keep using the
    raw string instead.
    """
    return re.sub(r"\s+", " ", s)


def test_recon_frontmatter_contract():
    frontmatter, _, path = read_skill()

    assert frontmatter["name"] == "recon", path
    assert isinstance(frontmatter.get("description"), str)
    assert frontmatter["description"].strip()
    assert frontmatter["allowed-tools"] == ["shell", "http", "file_write"]


def test_recon_body_has_all_phase_boundaries():
    _, body, _ = read_skill()

    required_headings = [
        "## Target identifier convention",
        "## 1. Confirm the target and its shape",
        "## 1b. Passive subdomain discovery for a root domain",
        "## 2. Establish reachability",
        "## 3. Fingerprint the technology",
        "## 4. Record initial attack-surface clues",
        "## 5. Record reconnaissance results",
        "## 6. Transition to the next phase",
        "## Stop conditions",
    ]

    for heading in required_headings:
        assert heading in body, f"Missing required section: {heading}"


def test_recon_target_identifier_is_deterministic_and_bounded():
    _, body, _ = read_skill()

    text = collapse_ws(body).lower()

    required_rules = [
        "agent.target.base_url()",
        "agent.target.name()",
        "strip the scheme",
        "lowercase everything",
        "[a-z0-9]",
        "truncate to 64 characters",
        "app-example-com-8443",
    ]

    for rule in required_rules:
        assert rule in text, f"Target identifier rule missing/incomplete: {rule}"


def test_recon_only_allows_low_noise_tools():
    frontmatter, body, _ = read_skill()

    allowed = set(frontmatter["allowed-tools"])
    assert allowed == {"shell", "http", "file_write"}

    # The body may mention specialized scanners as things that are forbidden,
    # but they must not appear in the actual allow-list or be promoted as the
    # default reconnaissance mechanism.
    #
    # This boundary is defined across the intro *and* step 1b — 1b is where
    # `amass`/`assetfinder` get their explicit "don't auto-escalate to this"
    # treatment, alongside the intro's `nmap`/`subfinder`/`httpx`/`ffuf`/
    # `gobuster` list. Both sections precede any actual probing step, so the
    # boundary is scoped to everything before step 2 (reachability), not
    # just before step 1.
    forbidden_default_tools = [
        "nmap",
        "subfinder",
        "httpx",
        "ffuf",
        "gobuster",
        "amass",
        "assetfinder",
    ]

    pre_probing_section = body.split("## 2. Establish reachability", 1)[0]
    for tool in forbidden_default_tools:
        assert f"`{tool}`" in pre_probing_section, (
            f"Recon should explicitly define the boundary for specialized "
            f"tool: {tool}"
        )


def test_recon_explicitly_excludes_endpoint_and_parameter_enumeration():
    _, body, _ = read_skill()

    text = collapse_ws(body).lower()

    exclusion_phrases = [
        "it does not map endpoints, parameters, or forms",
        "do not perform broad content discovery",
        "do not run wordlist-based endpoint discovery",
        "directory brute-forcing",
        "parameter enumeration",
        "belongs to `web-enumeration`",
    ]

    for phrase in exclusion_phrases:
        assert phrase in text, f"Missing reconnaissance boundary: {phrase}"


def test_recon_local_targets_do_not_trigger_subdomain_discovery():
    _, body, _ = read_skill()

    text = collapse_ws(body).lower()

    required_constraints = [
        "do not perform external-domain reconnaissance against a target "
        "that is clearly",
        "single local url",
        "localhost service",
        "standalone ip",
        "skip this step entirely for single urls, localhost targets, "
        "and ip addresses.",
    ]

    for phrase in required_constraints:
        assert phrase in text, f"Missing local-target safety boundary: {phrase}"


def test_recon_crtsh_handling_is_resilient():
    _, body, _ = read_skill()

    text = collapse_ws(body).lower()

    for phrase in [
        "crt.sh",
        "validate the response before parsing",
        "retry with backoff",
        'type == "array"',
        "[ -s subs.txt ]",
        "recon/<target>/subs.txt",
    ]:
        assert phrase in text, f"Missing passive subdomain robustness rule: {phrase}"


def test_recon_reachability_collects_required_observations():
    _, body, _ = read_skill()

    text = collapse_ws(body).lower()

    for phrase in [
        "http status",
        "final url",
        "response headers",
        "server response headers",
        "x-powered-by",
        "basic page metadata",
    ]:
        assert phrase in text, f"Reachability/fingerprinting requirement missing: {phrase}"


def test_recon_fingerprint_results_are_not_overclaimed():
    _, body, _ = read_skill()

    text = collapse_ws(body)

    assert (
        "Treat fingerprint results as hypotheses until supported by "
        "concrete evidence." in text
    )
    assert (
        "Do not state that a technology is confirmed without an "
        "observable indicator." in text
    )


def test_recon_requires_summary_without_creating_findings():
    _, body, _ = read_skill()

    text = collapse_ws(body).lower()

    assert "recon/<target>/summary.md" in text
    assert "target and target type" in text
    assert "reachable service and observed status" in text
    assert "observed technologies" in text
    assert "initial attack-surface clues" in text
    assert "relevant uncertainties" in text
    assert "recommended next phase" in text
    assert (
        "do not create a security finding from reconnaissance observations "
        "alone" in text
    )


def test_recon_transition_is_linear():
    _, body, _ = read_skill()

    flow = body[body.index("## 6. Transition to the next phase"):]

    # The pipeline ordering claim is about the fenced ```text``` diagram
    # specifically, not about which of these words happens to appear first
    # anywhere in the surrounding prose (the prose bullets above the diagram
    # already mention web-enumeration/web-input-analysis/vulnerability-
    # specific skill before the diagram's own "recon" line, which isn't a
    # linearity violation — it's just prose explaining the transition before
    # showing the diagram).
    diagram_match = re.search(r"```text\n(.*?)```", flow, re.DOTALL)
    assert diagram_match, (
        "Expected a fenced ```text``` transition diagram under "
        "'## 6. Transition to the next phase'"
    )
    diagram = diagram_match.group(1)

    recon_index = diagram.index("recon")
    enumeration_index = diagram.index("web-enumeration")
    input_index = diagram.index("web-input-analysis")
    vuln_index = diagram.index("vulnerability-specific skill")

    assert recon_index < enumeration_index < input_index < vuln_index

    assert (
        "do not jump directly to a vulnerability-specific skill"
        in collapse_ws(flow)
    )


def test_recon_stop_conditions_prevent_scope_creep():
    _, body, _ = read_skill()

    stop_block = collapse_ws(body[body.index("## Stop conditions"):]).lower()

    for phrase in [
        "target has been classified",
        "reachability has been established or the failure is clearly recorded",
        "major technology indicators have been identified or explicitly "
        "marked unknown",
        "initial attack-surface clues have been recorded",
        "the next phase can be determined",
        "do not escalate reconnaissance into high-volume scanning",
        "full subdomain brute-forcing",
        "deep content discovery",
    ]:
        assert phrase in stop_block, f"Missing stop/scope rule: {phrase}"


def test_recon_does_not_use_findings_for_plain_recon_output():
    _, body, _ = read_skill()

    finding_section = collapse_ws(
        body[
            body.index("## 5. Record reconnaissance results"):
            body.index("## 6. Transition")
        ]
    ).lower()

    assert "confirm_finding" in finding_section
    assert (
        "do not reuse the target identifier for a finding file name"
        in finding_section
    )


def test_recon_examples_use_real_target_substitution_language():
    _, body, _ = read_skill()

    text = collapse_ws(body)

    assert "substitute the real target into commands before running them" in text
    assert "Never write literal placeholders" in text
    assert "`<TARGET>`" in text
    assert "`<HOST>`" in text
    assert "`<APEX>`" in text
