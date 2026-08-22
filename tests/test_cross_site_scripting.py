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

import pytest


class Outcome(str, Enum):
    CONFIRMED = "confirmed"
    NOT_CONFIRMED = "not confirmed"
    BLOCKED = "blocked"
    REQUIRES_BROWSER_CONFIRMATION = "requires-browser-confirmation"


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

    # for js_string: does the response evidence deterministically show the
    # break-out landing in an executable position (not just "the marker
    # text appears somewhere in the response")?
    js_breakout_deterministic: bool = False

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
       `requires-browser-confirmation`.
    """
    # 3a — blocked takes priority over everything else; the skill is
    # explicit that an ordinary 401/403 must NOT be treated the same way.
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
        if probe.payload_reflected_unescaped:
            return Outcome.CONFIRMED
        return Outcome.NOT_CONFIRMED

    if probe.context == ReflectionContext.JS_STRING:
        if not probe.payload_reflected_unescaped:
            return Outcome.NOT_CONFIRMED
        if probe.js_breakout_deterministic:
            return Outcome.CONFIRMED
        # reflected, but whether the break-out actually lands in an
        # executable position can't be established from HTTP evidence
        # alone
        return Outcome.REQUIRES_BROWSER_CONFIRMATION

    if probe.context == ReflectionContext.URL_HREF:
        # href/src contexts are inherently non-deterministic from HTTP
        # evidence alone (depends on user interaction, scheme handling,
        # CSP, etc.) — never `confirmed` from curl-level evidence.
        if probe.payload_reflected_unescaped:
            return Outcome.REQUIRES_BROWSER_CONFIRMATION
        return Outcome.NOT_CONFIRMED

    if probe.context == ReflectionContext.DOM_BASED:
        if probe.dom_execution_observed:
            return Outcome.CONFIRMED
        if probe.dom_sink_path_plausible:
            return Outcome.REQUIRES_BROWSER_CONFIRMATION
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
            == Outcome.REQUIRES_BROWSER_CONFIRMATION
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
            == Outcome.REQUIRES_BROWSER_CONFIRMATION
        )

    def test_dom_based_plausible_path_without_observed_execution(self):
        probe = Probe(
            context=ReflectionContext.DOM_BASED,
            dom_sink_path_plausible=True,
            dom_execution_observed=False,
        )
        assert (
            classify_xss_outcome(probe)
            == Outcome.REQUIRES_BROWSER_CONFIRMATION
        )

    def test_dom_based_observed_execution_is_confirmed(self):
        probe = Probe(
            context=ReflectionContext.DOM_BASED,
            dom_sink_path_plausible=True,
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
    from every context."""

    @pytest.mark.parametrize(
        "context",
        [
            ReflectionContext.HTML_BODY,
            ReflectionContext.HTML_ATTRIBUTE,
            ReflectionContext.JS_STRING,
            ReflectionContext.URL_HREF,
            ReflectionContext.DOM_BASED,
        ],
    )
    def test_upstream_block_wins_regardless_of_other_evidence(self, context):
        probe = Probe(
            context=context,
            upstream_blocked=True,
            payload_reflected_unescaped=True,
            js_breakout_deterministic=True,
            dom_execution_observed=True,
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