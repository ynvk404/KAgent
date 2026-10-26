"""
test_cross_site_scripting.py

This test suite does NOT invoke an LLM. It encodes the decision rules
described in cross-site-scripting/SKILL.md (steps 2, 3, 3a, and 5) as a
small reference classifier, and checks that classifier against the
scenarios the skill explicitly calls out. The goal is to catch logic bugs
or ambiguity in the skill's decision boundaries *before* they reach an
agent following the prose instructions — if the reference implementation
can't satisfy these cases unambiguously, the skill text likely can't
either.

If you change the outcome rules in SKILL.md, update `classify_xss_outcome`
to match, then rerun this file. A failing test here is a signal that the
skill's prose and its actual decision boundary have drifted apart.

Run with:
    pytest test_cross_site_scripting.py -v
"""

from dataclasses import dataclass
from enum import Enum
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
import asyncio
import re
import shutil
import subprocess
from urllib.parse import urlsplit

import pytest

from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry


@pytest.fixture(scope="module")
def skill_text():
    return (Path(__file__).resolve().parents[2] / "skills" /
            "cross-site-scripting" / "SKILL.md").read_text(encoding="utf-8")


def test_payload_resource_guidance_respects_available_tools_and_refusals(skill_text):
    section = " ".join(skill_text.split("## Relationship to `payloads.txt`", 1)[1]
                       .split("## Target identifier", 1)[0].split()).lower()
    for requirement in (
        "prefer `read_payloads`", "when available", "`read_skill_file` only if exposed",
        "permitted by its tool/skill contract", "do not guess nonexistent workspace skill paths",
        "unrelated runner filesystem paths", "refused or blocked", "existing refusal/stop behavior",
        "do not switch tools or paths to bypass",
    ):
        assert requirement in section
    # Mentioning the optional resource tool must not expand the allowed-tools contract.
    import yaml
    metadata = yaml.safe_load(skill_text.split("---", 2)[1])
    assert metadata["allowed-tools"] == [
        "shell", "http", "read_payloads", "file_write", "ask_user", "confirm_finding", "workflow",
    ]


def test_reflection_analysis_prioritizes_target_observations_over_marker_presence(skill_text):
    section = " ".join(skill_text.split("## 2. Determine the reflection context precisely", 1)[1]
                       .split("## 3. Confirm", 1)[0].split()).lower()
    for requirement in (
        "captured http observations from the target", "reflection context and encoding",
        "actual response before choosing further probes", "alphanumeric marker",
        "input propagation only", "does not confirm executable xss",
        "browser/dom execution evidence is unavailable", "limitation explicitly",
        "`browser-required`", "http-only evidence cannot prove every browser-dependent case",
    ):
        assert requirement in section


class Outcome(str, Enum):
    CONFIRMED = "confirmed"
    NOT_CONFIRMED = "not-confirmed"
    BLOCKED = "blocked"
    BROWSER_REQUIRED = "browser-required"


class ReflectionContext(str, Enum):
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    JS_STRING = "js_string"
    URL_HREF = "url_href"
    DOM_BASED = "dom_based"
    ENCODED = "encoded"


@dataclass
class Probe:
    """Evidence gathered during steps 2-3 of the skill for one candidate."""

    context: ReflectionContext

    # step 3a: was the probe intercepted by an upstream control (WAF, rate
    # limiter, CAPTCHA) before it ever reached application logic?
    upstream_blocked: bool = False

    # ordinary application-level status code (401/403/etc.) with NO
    # evidence of an upstream control — must never alone imply `blocked`
    ordinary_status_code: int | None = None

    # for html_body / html_attribute: did the payload come back unescaped
    # in a position the browser will parse as executable?
    payload_reflected_unescaped: bool = False
    payload_complete: bool = True

    # for js_string: does the response evidence deterministically show the
    # break-out landing in an executable position (not just "the marker
    # text appears somewhere in the response")?
    js_breakout_deterministic: bool = False

    # For URL contexts, retain the attribute representation separately from
    # actual execution evidence; HTML encoding does not establish a safe URL.
    url_attribute_source: str | None = None
    url_execution_observed: bool = False

    # for dom_based: was execution actually observed (vs. only a plausible
    # source -> sink path read from client-side source)?
    dom_execution_observed: bool = False
    dom_sink_path_plausible: bool = False


def classify_xss_outcome(probe: Probe) -> Outcome:
    """Reference implementation of SKILL.md steps 2, 3, 3a, and 5.

    Decision order matters and mirrors the skill's stated precedence:
    1. an upstream block always wins — the application was never tested.
    2. fully encoded/neutralized reflection is a clean negative.
    3. context determines whether HTTP-level evidence alone can support
       `confirmed`, or whether it can only ever support
       `browser-required`.
    """
    # 3a — blocked takes priority over everything else, for every context
    # including `encoded`; the skill is explicit that an ordinary 401/403
    # must NOT be treated the same way.
    if probe.upstream_blocked:
        return Outcome.BLOCKED

    if probe.context == ReflectionContext.ENCODED:
        return Outcome.NOT_CONFIRMED

    if probe.context in (
        ReflectionContext.HTML_BODY,
        ReflectionContext.HTML_ATTRIBUTE,
    ):
        # deterministic browser parsing context: HTTP-level evidence of
        # unescaped reflection is sufficient for `confirmed`.
        if probe.payload_reflected_unescaped and probe.payload_complete:
            return Outcome.CONFIRMED
        return Outcome.NOT_CONFIRMED

    if probe.context == ReflectionContext.JS_STRING:
        if not probe.payload_reflected_unescaped:
            return Outcome.NOT_CONFIRMED
        if probe.js_breakout_deterministic and probe.payload_complete:
            return Outcome.CONFIRMED
        # reflected, but whether the break-out actually lands in an
        # executable position can't be established from HTTP evidence
        # alone
        return Outcome.BROWSER_REQUIRED

    if probe.context == ReflectionContext.URL_HREF:
        # An observed execution marker is stronger than URL reflection;
        # an executable scheme alone never proves that execution occurred.
        if probe.url_execution_observed:
            return Outcome.CONFIRMED
        if probe.url_attribute_source is not None:
            # HTML character references are decoded before URL interpretation.
            try:
                scheme = urlsplit(unescape(probe.url_attribute_source)).scheme.lower()
            except ValueError:
                return Outcome.BROWSER_REQUIRED  # Unknown handling is unresolved.
            if scheme in {"http", "https"}:
                return Outcome.NOT_CONFIRMED  # This bounded scheme vector is neutralized.
            return Outcome.BROWSER_REQUIRED
        # Preserve existing cases that supply only a reflection observation.
        if probe.payload_reflected_unescaped:
            return Outcome.BROWSER_REQUIRED
        return Outcome.NOT_CONFIRMED

    if probe.context == ReflectionContext.DOM_BASED:
        # observed execution alone is sufficient — it doesn't need
        # dom_sink_path_plausible to also be set, since actually observing
        # execution is strictly stronger evidence than a plausible-but-
        # unconfirmed source->sink path.
        if probe.dom_execution_observed:
            return Outcome.CONFIRMED
        if probe.dom_sink_path_plausible:
            return Outcome.BROWSER_REQUIRED
        return Outcome.NOT_CONFIRMED

    raise ValueError(f"unhandled context: {probe.context}")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestConfirmedRequiresDeterministicContext:
    """Step 5: `confirmed` is only reachable where browser parsing of the
    HTTP-level evidence is deterministic."""

    def test_html_body_unescaped_script_is_confirmed(self):
        probe = Probe(
            context=ReflectionContext.HTML_BODY,
            payload_reflected_unescaped=True,
        )
        assert classify_xss_outcome(probe) == Outcome.CONFIRMED

    def test_html_attribute_unescaped_breakout_is_confirmed(self):
        probe = Probe(
            context=ReflectionContext.HTML_ATTRIBUTE,
            payload_reflected_unescaped=True,
        )
        assert classify_xss_outcome(probe) == Outcome.CONFIRMED

    def test_html_body_escaped_is_not_confirmed(self):
        probe = Probe(
            context=ReflectionContext.HTML_BODY,
            payload_reflected_unescaped=False,
        )
        assert classify_xss_outcome(probe) == Outcome.NOT_CONFIRMED

    def test_html_attribute_escaped_is_not_confirmed(self):
        # Symmetric to the html_body case above — both contexts share the
        # same "deterministic parsing" branch in the classifier, so both
        # need their own negative case, not just the positive one.
        probe = Probe(
            context=ReflectionContext.HTML_ATTRIBUTE,
            payload_reflected_unescaped=False,
        )
        assert classify_xss_outcome(probe) == Outcome.NOT_CONFIRMED


class TestNonDeterministicContextsNeverConfirmFromHttpAlone:
    """Step 3's interpretation rule: JS-string breakout, href/src context,
    and DOM sinks must never resolve straight to `confirmed` on the sole
    basis of the marker appearing in the response."""

    def test_js_string_reflected_but_breakout_not_deterministic(self):
        probe = Probe(
            context=ReflectionContext.JS_STRING,
            payload_reflected_unescaped=True,
            js_breakout_deterministic=False,
        )
        assert (
            classify_xss_outcome(probe)
            == Outcome.BROWSER_REQUIRED
        )

    def test_js_string_reflected_and_breakout_deterministic_is_confirmed(self):
        probe = Probe(
            context=ReflectionContext.JS_STRING,
            payload_reflected_unescaped=True,
            js_breakout_deterministic=True,
        )
        assert classify_xss_outcome(probe) == Outcome.CONFIRMED

    def test_js_string_not_reflected_is_not_confirmed(self):
        probe = Probe(
            context=ReflectionContext.JS_STRING,
            payload_reflected_unescaped=False,
        )
        assert classify_xss_outcome(probe) == Outcome.NOT_CONFIRMED

    def test_url_href_reflected_requires_browser_confirmation(self):
        probe = Probe(
            context=ReflectionContext.URL_HREF,
            payload_reflected_unescaped=True,
        )
        assert (
            classify_xss_outcome(probe)
            == Outcome.BROWSER_REQUIRED
        )

    def test_url_href_not_reflected_is_not_confirmed(self):
        # Explicit negative counterpart — previously only covered
        # incidentally by the totality sweep, which checks the result is
        # *a* valid Outcome but not *which* one.
        probe = Probe(
            context=ReflectionContext.URL_HREF,
            payload_reflected_unescaped=False,
        )
        assert classify_xss_outcome(probe) == Outcome.NOT_CONFIRMED

    def test_dom_based_plausible_path_without_observed_execution(self):
        probe = Probe(
            context=ReflectionContext.DOM_BASED,
            dom_sink_path_plausible=True,
            dom_execution_observed=False,
        )
        assert (
            classify_xss_outcome(probe)
            == Outcome.BROWSER_REQUIRED
        )

    def test_dom_based_observed_execution_is_confirmed(self):
        probe = Probe(
            context=ReflectionContext.DOM_BASED,
            dom_sink_path_plausible=True,
            dom_execution_observed=True,
        )
        assert classify_xss_outcome(probe) == Outcome.CONFIRMED

    def test_dom_based_observed_execution_alone_is_sufficient(self):
        # dom_execution_observed=True must be sufficient by itself,
        # independent of dom_sink_path_plausible — actually observing
        # execution is strictly stronger evidence than a merely plausible
        # source->sink path, and the two flags shouldn't need to agree.
        probe = Probe(
            context=ReflectionContext.DOM_BASED,
            dom_sink_path_plausible=False,
            dom_execution_observed=True,
        )
        assert classify_xss_outcome(probe) == Outcome.CONFIRMED

    def test_dom_based_no_plausible_path_is_not_confirmed(self):
        probe = Probe(
            context=ReflectionContext.DOM_BASED,
            dom_sink_path_plausible=False,
            dom_execution_observed=False,
        )
        assert classify_xss_outcome(probe) == Outcome.NOT_CONFIRMED


class TestUrlAttributeDecoding:
    @pytest.mark.parametrize("raw_unescaped", [False, True])
    @pytest.mark.parametrize(
        ("attribute_source", "decoded_value", "expected"),
        [
            pytest.param(
                "javascript:document.title=&#x27;synthetic-marker&#x27;",
                "javascript:document.title='synthetic-marker'",
                Outcome.BROWSER_REQUIRED,
                id="encoded-script-quotes",
            ),
            pytest.param(
                "java&#x73;cript&#58;document.title=&#39;synthetic-marker&#39;",
                "javascript:document.title='synthetic-marker'",
                Outcome.BROWSER_REQUIRED,
                id="encoded-script-scheme",
            ),
            pytest.param(
                "https&#58;//fixture.invalid/view?marker=synthetic&amp;mode=preview",
                "https://fixture.invalid/view?marker=synthetic&mode=preview",
                Outcome.NOT_CONFIRMED,
                id="encoded-https-control",
            ),
            pytest.param(
                "http&#58;//fixture.invalid/view?marker=synthetic&amp;mode=preview",
                "http://fixture.invalid/view?marker=synthetic&mode=preview",
                Outcome.NOT_CONFIRMED,
                id="encoded-http-control",
            ),
        ],
    )
    def test_decoded_url_controls_outcome(
        self, attribute_source, decoded_value, expected, raw_unescaped
    ):
        # Parse synthetic HTML locally; no browser, navigation or JS runs.
        class AnchorParser(HTMLParser):
            href: str | None = None

            def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
                if tag == "a":
                    self.href = dict(attrs).get("href")

        parser = AnchorParser()
        parser.feed(f'<a href="{attribute_source}">synthetic link</a>')
        assert attribute_source != decoded_value
        assert parser.href == decoded_value
        probe = Probe(
            context=ReflectionContext.URL_HREF,
            payload_reflected_unescaped=raw_unescaped,
            url_attribute_source=attribute_source,
        )
        assert classify_xss_outcome(probe) == expected

    @pytest.mark.parametrize(
        ("execution_observed", "upstream_blocked", "expected"),
        [
            (False, False, Outcome.BROWSER_REQUIRED),
            (True, False, Outcome.CONFIRMED),
            (True, True, Outcome.BLOCKED),
        ],
    )
    def test_url_confirmation_needs_execution_proof(
        self, execution_observed, upstream_blocked, expected
    ):
        # These are evidence states, not a claim that this fixture executes JS.
        probe = Probe(
            context=ReflectionContext.URL_HREF,
            url_attribute_source="javascript:document.title=&#39;synthetic-marker&#39;",
            url_execution_observed=execution_observed,
            upstream_blocked=upstream_blocked,
        )
        assert classify_xss_outcome(probe) == expected


class TestEncodedContextIsAlwaysNotConfirmed:
    """Step 2: fully encoded/neutralized reflection is a clean negative,
    regardless of any other flags — forcing a payload isn't valid."""

    def test_encoded_is_not_confirmed(self):
        probe = Probe(
            context=ReflectionContext.ENCODED,
            payload_reflected_unescaped=True,  # should be irrelevant
        )
        assert classify_xss_outcome(probe) == Outcome.NOT_CONFIRMED


class TestBlockedTakesPriorityOverEverything:
    """Step 3a: an upstream block means the application was never actually
    tested, so it must override any other evidence and must be reachable
    from every context — including `encoded`, since the interception
    happens before the application (and therefore before its encoding
    behavior) is ever reached."""

    @pytest.mark.parametrize("context", list(ReflectionContext))
    def test_upstream_block_wins_regardless_of_other_evidence(self, context):
        probe = Probe(
            context=context,
            upstream_blocked=True,
            payload_reflected_unescaped=True,
            js_breakout_deterministic=True,
            dom_execution_observed=True,
            dom_sink_path_plausible=True,
        )
        assert classify_xss_outcome(probe) == Outcome.BLOCKED


class TestOrdinaryStatusCodesNeverAutoBlockClassify:
    """Step 3a (the fix): a plain 401/403 with no upstream-control
    evidence must NOT be classified as `blocked` — that was the exact
    false-positive the skill was corrected to avoid. `upstream_blocked`
    must be driven by evidence of interception, never inferred from the
    status code alone."""

    @pytest.mark.parametrize("status_code", [401, 403, 429])
    def test_ordinary_status_without_block_evidence_is_not_blocked(
        self, status_code
    ):
        probe = Probe(
            context=ReflectionContext.HTML_BODY,
            ordinary_status_code=status_code,
            upstream_blocked=False,  # no evidence of interception
            payload_reflected_unescaped=False,
        )
        result = classify_xss_outcome(probe)
        assert result != Outcome.BLOCKED
        assert result == Outcome.NOT_CONFIRMED


class TestOutcomeIsAlwaysExactlyOneOfFour:
    """Step 5: 'every candidate gets exactly one outcome.' Sweep a broad
    grid of plausible evidence combinations and assert the classifier
    always resolves to a single valid Outcome member — i.e. it's a total
    function over the documented input space, never silently falling
    through."""

    @pytest.mark.parametrize("context", list(ReflectionContext))
    @pytest.mark.parametrize("upstream_blocked", [True, False])
    @pytest.mark.parametrize("reflected", [True, False])
    def test_classifier_is_total_and_valid(
        self, context, upstream_blocked, reflected
    ):
        probe = Probe(
            context=context,
            upstream_blocked=upstream_blocked,
            payload_reflected_unescaped=reflected,
            js_breakout_deterministic=reflected,
            dom_execution_observed=reflected,
            dom_sink_path_plausible=reflected,
        )
        result = classify_xss_outcome(probe)
        assert isinstance(result, Outcome)


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))


def test_fragment_transformation_requires_complete_same_context_variant():
    # Executable specification of the prose playbook; no browser/LLM is simulated.
    from pathlib import Path
    import asyncio
    from src.skills.registry import Registry
    from src.skills.load_skill import LoadSkillTool
    from src.tools.skills.payloads import ReadPayloadsTool
    from src.permission.permission import AlwaysAllow

    skills = Registry()
    skills.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    loaded = asyncio.run(LoadSkillTool(skills).run({'name': 'cross-site-scripting'}))
    prose = ' '.join(loaded.split())
    for rule in ('neither `<html>` nor `<body>` wrappers are required',
                 'An incomplete executable payload must not be confirmed',
                 'a prior close variant is not a stopping rule',
                 'existing or new observations support a different meaningful prediction'):
        assert rule in prose
    corpus = asyncio.run(ReadPayloadsTool(skills).run(
        {'skill': 'cross-site-scripting', 'file': 'payloads.txt'}, None, AlwaysAllow()))
    assert 'append one inert trailing character' in ' '.join(corpus.split())
    assert 'BenchmarkTest' not in loaded + corpus

    payload = "<script>document.title='marker'</script>"
    response = payload[:-1]  # text/html with raw reflection and no wrappers
    assert '<html>' not in response and '<body>' not in response
    assert classify_xss_outcome(Probe(ReflectionContext.HTML_BODY,
        payload_reflected_unescaped=True, payload_complete=False)) != Outcome.CONFIRMED
    variant_response = (payload + 'x')[:-1]
    assert variant_response == payload
    assert classify_xss_outcome(Probe(ReflectionContext.HTML_BODY,
        payload_reflected_unescaped=True, payload_complete=True)) == Outcome.CONFIRMED


def test_returned_syntax_checkpoint_uses_captured_bytes_before_confirmation(skill_text):
    # Static instruction contract only; this does not prove live LLM adherence.
    section = ' '.join(skill_text.split('## 5. Record the validation evidence', 1)[1]
                       .split('Every candidate gets exactly one outcome:', 1)[0].split())
    for requirement in (
        'Immediately before recording', 'actual captured response bytes',
        'every delimiter', 'intended payload', 'LLM-reconstructed HTML',
        "<script>document.title='proof'</script", 'lacks the final `>`',
        'a bounded same-context compensating adaptation', 'inspect its actual response',
        'another permitted confirmation condition', 'do not claim confirmed execution',
        'Deterministic HTTP-based confirmation remains sufficient',
    ):
        assert requirement in section


def test_encoding_is_assessed_in_the_actual_parser_context(skill_text):
    prose = ' '.join(skill_text.split()).lower()
    corpus = ' '.join((Path(__file__).resolve().parents[2] / 'skills' /
                       'cross-site-scripting' / 'payloads.txt').read_text().split()).lower()
    for rule in (
        'html-decoded value', 'encoding alone does not establish a safe scheme',
        'event handlers or urls', 'enclosing parser and any later decoding',
        'encoding presence/absence alone proves neither safety nor exploitability',
    ):
        assert rule in prose
    assert '(a) not' not in corpus
    assert 'encoded attribute is not automatically safe' in corpus
    assert 'unknown handling remains unresolved' in corpus
    assert 'establishes propagation only, not encoding or execution' in corpus


def test_stored_and_dom_guidance_keeps_capability_effects_and_proof_distinct(skill_text):
    prose = ' '.join(skill_text.split()).lower()
    corpus = ' '.join((Path(__file__).resolve().parents[2] / 'skills' /
                       'cross-site-scripting' / 'payloads.txt').read_text().split()).lower()
    for rule in (
        'interpolation escapes text', '`[innerhtml]` bindings sanitize html',
        'direct dom writes', '`bypasssecuritytrust*`', 'fragment insertion',
        'before a stateful execution probe', 'if the proof path needs browser execution',
        'record reported effects promptly', 'do not wait for execution proof',
        'rendering response may also serve as readback',
        'acceptance, stored markup and json readback are not execution evidence',
        'cleanup only with separate authority', 'honest limitations',
        'browser capability is not required for deterministic http proof',
        'an unobserved effect is not a tested negative',
    ):
        assert rule in prose
    assert 'without observed execution supports browser-required, not confirmed' in corpus
    assert 'unambiguous enough, confirmed' not in corpus
    assert 'missing browser execution stays browser-required' in corpus


@pytest.fixture(scope="module")
def payloads_text():
    text = (Path(__file__).resolve().parents[2] / 'skills' /
            'cross-site-scripting' / 'payloads.txt').read_text(encoding='utf-8')
    # Prose contract assertions tolerate wrapping, not missing concepts.
    return ' '.join(line.lstrip('# ').strip() for line in text.splitlines())


def test_marker_substitution_distinguishes_candidate_suffix_from_full_marker(payloads_text):
    for concept in (
        'Substitution is manual', 'preserves placeholders and annotations',
        'Do not fabricate timestamps/session metadata', "candidate's chosen marker",
        'Illustrative substitution only, not a recorded timestamp',
        'full detection marker xsspocdemo7', '{MARKER}=demo7', 'xsspoc-demo7',
        'suffix is demo7, not the full xsspocdemo7',
        'same suffix used for {TIMESTAMP}', 'record exact input/title strings',
    ):
        assert concept in payloads_text


def test_corpus_context_and_transformations_do_not_infer_execution(payloads_text):
    for concept in (
        'css-style-attribute | css-style-block | fully-encoded | unknown',
        'Unknown remains unresolved', 'encoding, escaping, sanitization and truncation',
        'propagation', 'neutralized output', 'potentially executable syntax and observed execution',
        'absence of HTML encoding is not confirmed execution',
        'unobserved title change does not establish execution failure',
        'Deterministic HTTP proof remains sufficient', 'complete returned syntax',
        'Intended request syntax cannot replace captured response bytes',
        'textarea/title', 'inert/incompatible context', 'actual value',
        'incomplete returned tag does not establish breakout',
        'captured source specifically shows script-tag stripping',
        'src=x must actually fail image loading', 'anchor href may require a click/navigation',
        'img src does not execute a javascript: URL as script',
    ):
        assert concept in payloads_text
    assert 'failed to execute' not in payloads_text


def test_corpus_stored_and_dom_notes_respect_existing_capability_checkpoint(payloads_text):
    for concept in (
        "SKILL.md step 3's Stored/SPA checkpoint", 'authority, isolation',
        'readback and cleanup feasibility', 'Do not submit an executable mutation',
        'required browser proof gap cannot be closed',
        'Acceptance, persistence/readback and execution are different facts',
        'stored markup or JSON readback is not execution evidence',
        'cleanup needs separate authority and verification or honest limitations',
        'cite the exact sink and taint path', 'browser-required, not confirmed',
        'Ordinary innerHTML script insertion is not execution',
        'adds no DOM variants or substitute execution',
    ):
        assert concept in payloads_text


@pytest.fixture(scope='module')
def loaded_xss():
    registry = Registry()
    registry.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    return asyncio.run(LoadSkillTool(registry).run({'name': 'cross-site-scripting'}))


class SourceTokens(HTMLParser):
    """Local attribute/text fixtures only, not an HTML5 browser or XSS oracle."""

    def __init__(self, source):
        super().__init__()
        self.tags = []
        self.data = []
        self.comments = []
        self.feed(source)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def handle_data(self, data):
        self.data.append(data)

    def handle_comment(self, data):
        self.comments.append(data)


@pytest.mark.parametrize('row', range(4), ids=['double', 'single', 'unquoted', 'entity-quote'])
def test_loaded_attribute_examples_match_full_assembly_and_attribute_decoding(loaded_xss, row):
    lines = [line for line in loaded_xss.splitlines() if line.startswith('| `<input value=')]
    assert len(lines) == 4
    template, submitted, returned = re.findall(r'`([^`]+)`', lines[row])[:3]
    assert template.replace('{input}', submitted) == returned
    tokens = SourceTokens(returned)
    assert len(tokens.tags) == 1
    tag, attrs = tokens.tags[0]
    assert tag == 'input' and attrs['data-tail'] == 't'
    if row == 3:
        assert 'data-probe' not in attrs
        assert attrs['value'] == 'm" data-probe="yes'
    else:
        assert attrs['value'] == 'm' and attrs['data-probe'] == 'yes'
    # All four are attribute/data observations; this fixture claims no execution.
    assert all(tag != 'script' for tag, _ in tokens.tags)


def test_html_backslash_does_not_escape_a_delimiter_and_wrong_quote_can_stay_data():
    tokens = SourceTokens('<input value="m\\" data-probe="yes" data-tail="t">')
    assert tokens.tags == [('input', {'value': 'm\\', 'data-probe': 'yes', 'data-tail': 't'})]
    tokens = SourceTokens("<input value='m\" data-probe=\"yes' data-tail='t'>")
    assert 'data-probe' not in tokens.tags[0][1]


def test_loaded_nested_html_js_and_url_examples_decode_one_layer(loaded_xss):
    handler_match = re.search(r'`(<button onclick="[^`]+</button>)`', loaded_xss)
    assert handler_match is not None
    source = handler_match[1]
    tokens = SourceTokens(source)
    handler = tokens.tags[0][1]['onclick']
    assert handler == "show('x');document.title='xsspoc-demo7';//')"
    assert '&#39;' in source and '&#39;' not in handler
    anchor_match = re.search(r'`(<a href="javascript:[^`]+</a>)`', loaded_xss)
    assert anchor_match is not None
    anchor = anchor_match[1]
    href = SourceTokens(anchor).tags[0][1]['href']
    assert href == "javascript:document.title='xsspoc-demo7'"
    assert urlsplit(href).scheme == 'javascript'
    encoded = SourceTokens('<a href="javascript%3Adocument.title=1">go</a>').tags[0][1]['href']
    assert urlsplit(encoded).scheme == ''  # HTML attribute decoding adds no percent decode.


def test_loaded_transformations_are_source_changes_not_execution_events(loaded_xss):
    section = loaded_xss.split('**Transformations:', 1)[1].split('## 3. Confirm', 1)[0]
    rows = [re.findall(r'`([^`]+)`', line)[:2] for line in section.splitlines()
            if line.startswith('| `')]
    encoded, escaped, stripped, attributes, clipped, url = rows
    assert encoded == ['<b>m</b>', '&lt;b&gt;m&lt;/b&gt;']
    tokens = SourceTokens(encoded[1])
    assert tokens.tags == [] and tokens.data == ['<b>m</b>']
    assert escaped == ["'", "\\'"]
    assert [tag for tag, _ in SourceTokens(stripped[0]).tags] == ['script', 'b']
    assert SourceTokens(stripped[1]).tags == [('b', {})]
    assert 'onerror' in SourceTokens(attributes[0]).tags[0][1]
    assert SourceTokens(attributes[1]).tags == [('img', {'src': 'x'})]
    assert clipped[0][:-1] == clipped[1]
    assert url[0] == 'javascript%3Adocument.title=1'
    prose = ' '.join(section.lower().split())
    assert 'if capture is truncated, the missing bytes are unknown' in prose
    assert 'never reconstruct it or use an inadmissible capture as terminal proof' in prose


@pytest.fixture(scope='module')
def js_sources(loaded_xss):
    match = re.search(r'```javascript\s*\n(.*?)```', loaded_xss, re.S)
    assert match is not None
    block = match[1]
    return dict(re.findall(r'const (\w+)=(.*);', block))


def check_js_syntax(source):
    # Parse only: no vm.run*, DOM, browser, document stub or execution event.
    node = shutil.which('node')
    if node is None:
        pytest.skip('Optional syntax-only JavaScript checks require an existing node binary')
    return subprocess.run([node, '--check', '--input-type=commonjs'], input=source,
                          text=True, capture_output=True, timeout=5, check=False)


@pytest.mark.parametrize('name', ['single', 'double', 'escaped', 'template', 'interpolation'])
def test_loaded_javascript_assemblies_parse_without_executing(js_sources, name):
    result = check_js_syntax('const ' + name + '=' + js_sources[name] + ';')
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(('replacement', 'valid'), [('first\nsecond', False),
                                                    (r'first\nsecond', True),
                                                    ('first\\\nsecond', True)])
def test_javascript_physical_newline_escape_and_continuation_differ(js_sources, replacement, valid):
    source = 'const single=' + js_sources['single'].replace('xsspoc-demo7', replacement) + ';'
    assert (check_js_syntax(source).returncode == 0) is valid


def test_javascript_line_comment_does_not_consume_a_next_line_suffix(js_sources):
    source = 'const single=' + js_sources['single'] + ';'
    # A physical newline exposes the application's otherwise commented quote.
    source = source.replace("//';", "//\n';")
    assert check_js_syntax(source).returncode != 0
    template = 'const template=' + js_sources['template'].replace('xsspoc-demo7', 'first\nsecond') + ';'
    assert check_js_syntax(template).returncode == 0


def test_loaded_dom_stored_and_policy_traces_keep_the_missing_proof_explicit(loaded_xss):
    text = ' '.join(loaded_xss.split()).lower()
    dom = text.split('**dom trace', 1)[1].split('**stored trace', 1)[0]
    for concept in ('source', 'transformation', 'sink', 'fragment insertion/dom mutation',
                    'execution evidence still missing', 'does not prove the branch ran',
                    'innerhtml', 'textcontent', 'browser-required'):
        assert concept in dom
    stored = text.split('**stored trace', 1)[1].split('**response policy', 1)[0]
    assert stored.index('acceptance') < stored.index('readback') < stored.index('rendering')
    for concept in ('reported write, not persistence', 'declared rendering response',
                    'separately authorized cleanup and verification', 'ownership',
                    'browser-required', 'cleanup cannot be verified'):
        assert concept in stored
    policy = text.split('**response policy', 1)[1].split('**3a.', 1)[0]
    for concept in ('application/json', 'text/plain', 'text/html', "script-src 'none'",
                    'report-only', 'does not enforce blocking', 'embedding/sandbox',
                    'needs its interaction', 'do not simulate an event'):
        assert concept in policy
