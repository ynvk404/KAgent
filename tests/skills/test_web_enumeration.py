"""Tests for the web-enumeration SKILL.md contract.

These tests intentionally validate the skill as a prompt/playbook rather than
trying to execute curl or invoke the LLM. They are therefore stable even when
KAgent's runtime/tool implementations change.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml


def find_web_enumeration_skill() -> Path:
    """Locate web-enumeration/SKILL.md from the test file or its parents."""
    roots = [Path(__file__).resolve().parent, *Path(__file__).resolve().parents]
    candidates: list[Path] = []
    for root in roots:
        candidates.extend(
            [
                root / "skills" / "web-enumeration" / "SKILL.md",
                root / "src" / "skills" / "web-enumeration" / "SKILL.md",
                root / ".agents" / "skills" / "web-enumeration" / "SKILL.md",
                root / ".claude" / "skills" / "web-enumeration" / "SKILL.md",
            ]
        )
    for path in candidates:
        if path.is_file():
            return path
    pytest.fail(
        "Could not find web-enumeration/SKILL.md. Checked:\n"
        + "\n".join(f"- {path}" for path in candidates)
    )


def read_skill() -> tuple[dict, str, Path]:
    path = find_web_enumeration_skill()
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
    between two of its words. Prose/phrase assertions should compare
    against this collapsed form so the assertion doesn't depend on where a
    line happened to wrap. Structural checks (headings, frontmatter, fenced
    code blocks where exact formatting matters) should keep using the raw
    string instead.
    """
    return re.sub(r"\s+", " ", s)


# ============================================================================
# Frontmatter / structure
# ============================================================================

def test_web_enumeration_frontmatter_contract():
    frontmatter, _, path = read_skill()

    assert frontmatter["name"] == "web-enumeration", path
    assert isinstance(frontmatter.get("description"), str)
    assert frontmatter["description"].strip()
    assert frontmatter["allowed-tools"] == ["shell", "http", "file_write", "workflow"]


def test_web_enumeration_body_has_all_phase_boundaries():
    _, body, _ = read_skill()

    required_headings = [
        "## Target identifier",
        "## Preconditions",
        "## 1. Build the target baseline",
        "## 2. Enumerate routes and endpoints from known sources",
        "## 3. Enumerate parameters and forms",
        "## 4. Enumerate API surfaces",
        "## 5. Enumerate static resources and JavaScript",
        "## 6. Focused content discovery (optional, bounded)",
        "## 7. Build the normalized inventory",
        "## 8. Handoff to web-input-analysis",
        # Note: unlike recon's "## Stop conditions" (H2), this skill uses
        # an H3 heading here — verify the exact level, not just the text.
        "### Stop conditions",
    ]

    for heading in required_headings:
        assert heading in body, f"Missing required section: {heading}"


# ============================================================================
# Target identifier reuse (must not re-derive its own convention)
# ============================================================================

def test_web_enumeration_reuses_recon_target_identifier():
    _, body, _ = read_skill()

    text = collapse_ws(body)

    assert (
        "the identifier derived by the convention defined in "
        "`recon/SKILL.md`" in text
    )
    assert '"Target identifier convention"' in text
    assert "do not re-derive it differently here" in text
    assert "do not invent a different naming scheme for this skill's output paths" in text


# ============================================================================
# Preconditions / handoff-back-to-recon boundary
# ============================================================================

def test_web_enumeration_preconditions_require_recon_context():
    _, body, _ = read_skill()

    text = collapse_ws(body)

    for phrase in [
        "a confirmed, reachable target (URL, host, or set of hosts);",
        "observed technology signals;",
        "confirmation that the target is in scope.",
        "If the target itself is unknown or scope is unclear, return to "
        "`recon` first.",
        "perform only the single lightweight request in step 1 to recover "
        "the minimum baseline",
        "Do not repeat full reconnaissance or technology fingerprinting "
        "here.",
    ]:
        assert phrase in text, f"Missing precondition rule: {phrase}"


def test_web_enumeration_reuses_recon_summary_before_reprobing():
    _, body, _ = read_skill()

    text = collapse_ws(body)

    for phrase in [
        "artifacts/recon/<target>/summary.md",
        "do not repeat reachability or fingerprinting work `recon` "
        "already did",
        "only re-probe if that result was inconclusive or missing",
    ]:
        assert phrase in text, f"Missing reuse-recon-output rule: {phrase}"


# ============================================================================
# Tool boundary (default to curl/http; scanners are the explicit exception)
# ============================================================================

def test_web_enumeration_only_allows_low_noise_tools():
    frontmatter, body, _ = read_skill()

    allowed = set(frontmatter["allowed-tools"])
    assert allowed == {"shell", "http", "file_write", "workflow"}

    # Same shape as recon's tool-boundary test: specialized scanners may be
    # *mentioned* as the explicitly-gated exception, but must not be the
    # allowed-tools default. Scope the search to before step 1 (where the
    # scanner boundary is actually defined), not the whole body, since step
    # 6 later reuses "ffuf"/"gobuster" as bare words without backticks in a
    # "do not escalate" sentence — that's a different, valid usage, not a
    # second definition of the boundary.
    intro_section = body.split("## Target identifier", 1)[0]

    for tool in ["ffuf", "gobuster", "dirsearch"]:
        assert f"`{tool}`" in intro_section, (
            f"web-enumeration should explicitly define the boundary for "
            f"specialized tool: {tool}"
        )

    text = collapse_ws(body)
    assert (
        "unless the user explicitly asks for them, or focused discovery "
        "in step 6 has already been tried and clearly justifies broader "
        "coverage." in text
    )


def test_web_enumeration_execution_rule_uses_real_substitution():
    _, body, _ = read_skill()

    text = collapse_ws(body)

    assert (
        "substitute the real target into commands before running them"
        in text
    )
    assert "Never write literal placeholders" in text
    assert "`<TARGET>`" in body
    assert "`<HOST>`" in body
    assert "`<endpoint>`" in body


# ============================================================================
# Step 2: passive-first route/endpoint discovery
# ============================================================================

def test_web_enumeration_prefers_passive_discovery_before_probing():
    _, body, _ = read_skill()

    text = collapse_ws(body)

    for phrase in [
        "Prefer routes the application already exposes before guessing "
        "paths.",
        "$TARGET/robots.txt",
        "$TARGET/sitemap.xml",
        "$TARGET/.well-known/security.txt",
        "Follow same-origin links one level deep when necessary to "
        "collect additional application routes.",
        "Do not recursively crawl the entire application here.",
        "Skip clearly external origins unless they are explicitly in "
        "scope.",
    ]:
        assert phrase in text, f"Missing passive-discovery rule: {phrase}"


# ============================================================================
# Step 3: forms/parameters are structure only, never submitted
# ============================================================================

def test_web_enumeration_forms_and_parameters_are_structure_only():
    _, body, _ = read_skill()

    text = collapse_ws(body)

    for phrase in [
        "HTTP method;",
        "action URL;",
        "field name;",
        "field type;",
        "hidden/required state when observable;",
        "presence of CSRF or similar hidden fields.",
        "query;",
        "form body;",
        "JSON body;",
        "Do not submit forms or inject test values at this stage. "
        "Enumeration records structure only.",
    ]:
        assert phrase in text, f"Missing form/parameter enumeration rule: {phrase}"


# ============================================================================
# Step 4: API surface enumeration stays bounded (no full introspection)
# ============================================================================

def test_web_enumeration_api_surface_enumeration_is_bounded():
    _, body, _ = read_skill()

    text = collapse_ws(body)

    for phrase in [
        "/swagger.json",
        "/swagger/v1/swagger.json",
        "/openapi.json",
        "/api-docs",
        "/.well-known/openapi.json",
        "A minimal check may be used only to determine whether "
        "introspection is enabled:",
        "Recording that introspection succeeded or is disabled is still "
        "enumeration.",
        "Do not retrieve the full schema, walk the complete type graph, "
        "fuzz queries, or attempt exploitation here.",
        "Those tasks belong to web-input-analysis or a "
        "vulnerability-specific skill when justified.",
    ]:
        assert phrase in text, f"Missing API-surface boundary rule: {phrase}"


# ============================================================================
# Step 5: static/JS resources — extraction only, no reverse engineering
# ============================================================================

def test_web_enumeration_static_and_js_enumeration_does_not_deobfuscate():
    _, body, _ = read_skill()

    text = collapse_ws(body)

    for phrase in [
        "Skip JavaScript or other resources that resolve to clearly "
        "unauthorized cross-origin domains.",
        "This step extracts route and endpoint strings already known by "
        "the frontend.",
        "Do not deobfuscate or reverse-engineer bundles.",
        '"/(api|rest)/[A-Za-z0-9/_-]+"',
    ]:
        assert phrase in text, f"Missing static/JS enumeration rule: {phrase}"


# ============================================================================
# Step 6: focused content discovery is optional, gated, and bounded
# ============================================================================

def test_web_enumeration_focused_discovery_is_optional_and_bounded():
    _, body, _ = read_skill()

    text = collapse_ws(body)

    for phrase in [
        "leave clear discovery gaps",
        "This is still enumeration, not vulnerability testing.",
        "Requests must remain plain GET requests against paths.",
        "Escalate gradually and stay on one host at a time.",
        "Only if the user has explicitly confirmed that broader "
        "discovery is wanted, use a small wordlist against a single "
        "scoped host:",
        "Do not escalate to ffuf, gobuster, larger wordlists, or "
        "multiple hosts without explicit authorization.",
        "If enumeration begins to resemble testing for a particular "
        "vulnerability class rather than discovering paths or "
        "resources, stop and hand off to the next phase.",
    ]:
        assert phrase in text, f"Missing focused-discovery boundary: {phrase}"


# ============================================================================
# Step 7: inventory format has no vulnerability-classification fields
# ============================================================================

def test_web_enumeration_inventory_excludes_vulnerability_fields():
    _, body, _ = read_skill()

    inventory_section = body[
        body.index("## 7. Build the normalized inventory"):
        body.index("## 8. Handoff to web-input-analysis")
    ]
    text = collapse_ws(inventory_section)

    assert "artifacts/web-enumeration/<target>/inventory.md" in text
    assert "### GET /search" in inventory_section
    assert "### POST /api/orders" in inventory_section

    for field in ["method;", "path;", "parameter;", "parameter location;",
                  "content type;", "authentication state;", "source;",
                  "observed response;", "notes."]:
        assert field in text, f"Missing required inventory field: {field}"

    assert "Do not add fields such as:" in text
    for forbidden_field in [
        "suspected_vulnerability;",
        "vulnerability_class;",
        "exploitability;",
        "severity.",
    ]:
        assert forbidden_field in text, (
            f"Missing explicitly-forbidden inventory field: {forbidden_field}"
        )

    assert (
        "Classification and vulnerability assessment are outside this "
        "skill." in text
    )


# ============================================================================
# Step 8: handoff summarizes but never pre-classifies
# ============================================================================

def test_web_enumeration_handoff_does_not_preclassify_vulnerabilities():
    _, body, _ = read_skill()

    handoff_section = body[
        body.index("## 8. Handoff to web-input-analysis"):
        body.index("### Stop conditions")
    ]
    text = collapse_ws(handoff_section)

    for phrase in [
        "total routes/endpoints found;",
        "sources used (application links, forms, JS, API docs, crawl, "
        "focused discovery);",
        "notable API surfaces such as Swagger/OpenAPI or GraphQL;",
        "endpoints referenced but not currently reachable;",
        "recommendation to proceed to web-input-analysis.",
        'Do not select the "most interesting" parameters yourself and '
        "do not recommend a vulnerability class for a specific endpoint.",
        "web-input-analysis must perform that classification from the "
        "inventory.",
    ]:
        assert phrase in text, f"Missing handoff rule: {phrase}"


def test_web_enumeration_transition_pipeline_is_linear():
    _, body, _ = read_skill()

    handoff_section = body[body.index("## 8. Handoff to web-input-analysis"):]

    # Unlike recon's ```text fenced diagram, this skill's diagram uses a
    # bare ``` fence with no language tag — match that exactly rather than
    # assuming the same fence style across skills.
    diagram_match = re.search(r"```\n(.*?)```", handoff_section, re.DOTALL)
    assert diagram_match, (
        "Expected a bare fenced ``` transition diagram under "
        "'## 8. Handoff to web-input-analysis'"
    )
    diagram = diagram_match.group(1)

    recon_index = diagram.index("recon")
    enumeration_index = diagram.index("web-enumeration")
    input_index = diagram.index("web-input-analysis")
    vuln_index = diagram.index("vulnerability-specific skill")

    assert recon_index < enumeration_index < input_index < vuln_index


# ============================================================================
# Stop conditions prevent scope creep
# ============================================================================

def test_web_enumeration_stop_conditions_prevent_scope_creep():
    _, body, _ = read_skill()

    stop_block = collapse_ws(body[body.index("### Stop conditions"):])

    for phrase in [
        "known routes and resources from application links, "
        "documentation, and JS have been collected;",
        "forms and parameter-bearing endpoints are inventoried;",
        "API entry points are identified;",
        "focused content discovery no longer produces useful new "
        "routes;",
        "further enumeration would become high-volume without a clear "
        "objective.",
        "Do not escalate into full crawling, large wordlist sweeps "
        "across multiple hosts, GraphQL schema fuzzing, or "
        "payload-based probing.",
        "Those activities belong to web-input-analysis or a "
        "vulnerability-specific skill and should only be performed when "
        "justified by the testing plan and authorized scope.",
    ]:
        assert phrase in stop_block, f"Missing stop/scope rule: {phrase}"
