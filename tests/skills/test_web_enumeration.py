"""Tests for the web-enumeration SKILL.md contract.

These tests intentionally validate the skill as a prompt/playbook rather than
trying to execute curl or invoke the LLM. They are therefore stable even when
KAgent's runtime/tool implementations change. They do not establish that an
LLM will follow the instructions in an experiment.
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
    assert frontmatter["allowed-tools"] == [
        "shell", "http", "content_discovery", "file_write", "workflow"
    ]
    assert frontmatter.get("completion-artifact") == (
        "artifacts/web-enumeration/{target}/inventory.md"
    )


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


def test_inventory_closure_accounts_for_observed_clues_without_full_ingestion():
    _, body, _ = read_skill()
    closing = collapse_ws(body.split('## 7.', 1)[1].split('## 8.', 1)[0]).replace('`', '').lower()
    assert re.search(r'sqli-only.{0,140}(?:class|classes).{0,140}discovery', closing)
    for clue in ('initializer', 'definition reference', 'robots', 'script/module', 'network call', 'api base'):
        assert clue in closing
    assert re.search(r'follow.{0,200}omission reason.{0,160}limitation', closing)
    assert re.search(r'guessed.{0,120}html.{0,170}(?:not|never).{0,140}(?:close|absen)', closing)
    assert re.search(r'relative references.{0,100}document url', closing)
    # Existing bounded-pass and provenance protections remain part of closure.
    assert 'unselected' in body.lower() and 'mandatory backlog' in body.lower()
    assert 'documented' in closing and 'referenced-only' in closing and 'tested' in closing


def test_enumeration_preserves_route_provenance_and_request_shape():
    _, body, _ = read_skill()
    text = collapse_ws(body).lower()

    assert "client_route`, `backend_endpoint`, or `unknown_route_reference" in text
    assert "a string alone does not establish a backend endpoint" in text
    assert "observed from the specification" in text
    assert "do not say they are reachable until requested" in text
    assert "normalized body hash or length" in text
    assert "does not make a backend endpoint valid" in text
    assert "same method, surrounding route shape, and response/source pattern" in text
    assert "requestbody.content` media type/schema" in text
    assert "sample_payload" in text and "content_type" in text


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
# Tool boundary (native scoped HTTP first; scanners are the explicit exception)
# ============================================================================

def test_web_enumeration_only_allows_low_noise_tools():
    frontmatter, body, _ = read_skill()

    allowed = set(frontmatter["allowed-tools"])
    assert allowed == {
        "shell", "http", "content_discovery", "file_write", "workflow"
    }

    # The semantic wrapper is the allowed tool. Direct scanner invocation
    # remains outside this skill's default tool contract.
    intro_section = body.split("## Target identifier", 1)[0]

    for tool in ["ffuf", "gobuster", "dirsearch"]:
        assert f"`{tool}`" in intro_section, (
            f"web-enumeration should explicitly define the boundary for "
            f"specialized tool: {tool}"
        )

    text = collapse_ws(body)
    assert "Use `content_discovery` only when steps 2–5 leave a concrete path-coverage gap." in text
    assert "`content_discovery` uses native HTTP through the runtime permission gate." in text


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
        "Do not deobfuscate or reverse-engineer bundles",
        'Resolve relative sources against the referencing page URL',
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
        "Requests remain GET-only and target paths on the active origin.",
        "Call `content_discovery` with `mode=\"auto\"` when a bounded discovery pass is justified.",
        "checks two independent random nonexistent paths and compares modest normalized response fingerprints",
        "`content_discovery` uses native HTTP.",
        "External scanner integration is unavailable; do not substitute shell scan loops.",
        "If coverage is already sufficient, record a `skipped` or `not_applicable` reason",
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
        "useful request fields from the selected sources are inventoried;",
        "valuable observed clues are followed within bounds or have a specific omission reason;",
        "API entry points and unresolved API-base/auth limitations are distinguished;",
        "further work has low expected information gain or would exceed existing bounds;",
        "canonical input records, inventory, source obligations and coverage agree.",
        "Optional content discovery need not run",
        "Do not escalate into full crawling, large wordlist sweeps "
        "across multiple hosts, GraphQL schema fuzzing, or "
        "payload-based probing.",
        "Those activities belong to web-input-analysis or a "
        "vulnerability-specific skill and should only be performed when "
        "justified by the testing plan and authorized scope.",
    ]:
        assert phrase in stop_block, f"Missing stop/scope rule: {phrase}"


def test_input_recording_is_incremental_and_keeps_analysis_boundary():
    _, body, _ = read_skill()
    early = collapse_ws(body[:body.index('## 1. Build the target baseline')])
    assert 'record_input' in early
    for requirement in ('relevant endpoint, request body', 'reachable schema definitions',
                        'before declaring an input type', 'reasonable bounded reading',
                        'omit `input_type`', 'required request attributes are grounded',
                        'an unresolved `$ref` alone does not mean object', 'promptly'):
        assert requirement.lower() in early.lower()
    assert 'immediately, before fetching another resource' not in early
    assert 'Do not wait for the final inventory' in early
    assert 'Record each newly established input once' in early
    assert 'Do not call `record_candidate`' in early
    assert 'Keep these inputs pending for `web-input-analysis`' in early


def test_large_response_strategy_preserves_read_boundaries_without_refetch():
    _, body, _ = read_skill()
    strategy = collapse_ws(body.split('## Large responses:', 1)[1].split('## 1.', 1)[0])
    for requirement in (
        'Do not repeatedly fetch the same large resource',
        'Do not fetch again, increase caps or cache-bust',
        'raw ObservationStore bytes are not a general discovery reader',
        'unowned discovery observation', 'gain read rights',
        'unavailable, evicted, outside limits or unreadable',
        'Do not raise the bound or restart retrieval',
        'retaining unresolved source limitations',
    ):
        assert requirement in strategy


def test_default_flow_uses_manual_fields_without_source_management_backlog():
    _, body, _ = read_skill()
    text = collapse_ws(body).lower()
    for contract in ('unselected pending source is not a mandatory backlog',
                     'there is no required select_source', 'get_source` only when',
                     'recording an input never selects or dispositions',
                     'caller declaration', 'not a machine extraction receipt',
                     'selected unresolved sources still block completion',
                     'do not drop a reference to bypass an admission error',
                     'fields nested in a sample do not replace separate records',
                     'not semantic completeness', 'in direct mode, discover only'):
        assert contract in text
    assert 'process_source' not in text


@pytest.fixture
def request_contract_checkpoint():
    """Inspect the closing decision rules together, independent of line wraps."""
    _, body, _ = read_skill()
    inventory = body.split('## 7. Build the normalized inventory', 1)[1].split(
        '## 8. Handoff to web-input-analysis', 1)[0]
    heading = '### Request-contract discovery before completion'
    assert heading in inventory, 'Request-contract review belongs in Enumeration closure'
    assert inventory.index(heading) < inventory.index('workflow(action="complete_skill"')
    checkpoint = inventory.split(heading, 1)[1].split('Inspect the overall workflow state', 1)[0]
    return collapse_ws(checkpoint.replace('`', '')).lower()


def test_get_500_keeps_unverified_request_contract_unknown(request_contract_checkpoint):
    text = request_contract_checkpoint
    assert re.search(r'separate.{0,60}observed endpoint/path.{0,70}verified request contract', text)
    assert re.search(r'get 500.{0,50}neither.{0,50}absence.{0,60}post support', text)
    assert re.search(
        r'keep unverified methods, body schemas and input fields.{0,30}unknown'
        r'.{0,40}never absent or unsupported', text)
    assert re.search(r'do not invent inputs or candidates.{0,50}close the phase', text)


def test_relevant_unknown_contract_requires_considering_a_next_step(request_contract_checkpoint):
    text = request_contract_checkpoint
    assert re.search(
        r'endpoint relevant to the testing objective.{0,80}unknown.{0,60}'
        r'consider at least one evidence-grounded next step.{0,40}before leaving', text)
    # Sources must provide request structure, rather than merely route names.
    for source in (
        r'inspect html form method/action and controls',
        r'javascript call sites/request construction',
        r'api schema/openapi',
        r'hypothesis-driven bounded http probe only when justified and permitted',
    ):
        assert re.search(source, text)
    assert re.search(r'reuse available evidence before new requests', text)


def test_record_input_method_conflict_requires_evidence_review(request_contract_checkpoint):
    text = request_contract_checkpoint
    assert re.search(
        r'if record_input is rejected for endpoint/method metadata conflict.{0,40}'
        r'review the proposal, request evidence and provenance', text)
    assert re.search(r'distinguish observed methods from hypotheses', text)
    assert re.search(r'correct arguments or retry only with valid support', text)
    assert re.search(
        r'do not treat validation rejection alone as a stopping reason', text)
    assert re.search(r'do not bypass or weaken runtime validation', text)


def test_contract_stop_requires_specific_reason_and_coverage_gap(request_contract_checkpoint):
    text = request_contract_checkpoint
    assert re.search(
        r'if further investigation is not possible or appropriate.{0,50}'
        r'record a concrete reason and corresponding coverage gap in the inventory', text)
    for reason in ('evidence unavailable', 'permission denied', 'budget exhausted'):
        assert reason in text
    assert re.search(
        r'not enough evidence to register an input.{0,30}alone is not a stopping reason', text)


def test_contract_discovery_preserves_existing_bounds_and_phase(request_contract_checkpoint):
    text = request_contract_checkpoint
    assert re.search(
        r'apply existing scope, permissions, resource budgets, rate limits, '
        r'bounded-reading rules and enumeration phase boundaries', text)
    assert re.search(r'do not automatically try all http methods, bulk post', text)
    assert re.search(r'(?:do not|or) perform unauthorized or high-impact operations', text)
    assert re.search(
        r'form submission and payload-based testing remain outside this phase', text)


def test_irrelevant_or_exhausted_endpoints_can_stop_without_extra_requests(request_contract_checkpoint):
    text = request_contract_checkpoint
    assert re.search(
        r'concrete reason.{0,230}endpoint irrelevant to the objective, or '
        r'no reasonable investigative lead remains', text)
    assert re.search(
        r'checkpoint requires a continue/stop assessment, not extra http requests, '
        r'resolution of every endpoint or indefinite discovery retries', text)


async def test_loaded_enumeration_includes_the_closing_contract_checkpoint():
    from src.skills.load_skill import LoadSkillTool
    from src.skills.registry import Registry

    _, _, path = read_skill()
    registry = Registry()
    registry.load_dir(path.parent.parent)
    loaded = await LoadSkillTool(registry).run({'name': 'web-enumeration'})
    # Verify delivery and phase order without a model, target, or simulated
    # decision engine claiming to interpret the prose.
    assert (
        loaded.index('## 7. Build the normalized inventory')
        < loaded.index('### Request-contract discovery before completion')
        < loaded.index('workflow(action="complete_skill"')
        < loaded.index('## 8. Handoff to web-input-analysis')
    )
    assert '/rest/user/login' not in loaded
