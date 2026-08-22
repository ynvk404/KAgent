---
name: cross-site-scripting
description: >
  Validate reflected, stored, or DOM-based cross-site scripting for a
  specific candidate that `web-input-analysis` flagged as
  `suspected_class: cross-site-scripting`, using the minimum non-destructive
  testing needed to establish evidence. Produces tested evidence
  (request/response, impact, remediation direction) for `finding-validation`
  to turn into a finding. Does not create findings itself. Use only after
  `web-input-analysis` has handed off a specific XSS candidate — never as a
  first step, and never against a parameter it didn't flag.
allowed-tools:
  - shell
  - http
  - file_write
---

# Cross-site scripting playbook

You are handed a specific candidate that `web-input-analysis` already
flagged `suspected_class: cross-site-scripting`, with a reasoned context
(reflected in HTML/JS output) and a light signal. This phase answers "is
this parameter actually exploitable for script execution, and what's the
concrete impact?" It does not re-triage the whole inventory and does not
test parameters this skill wasn't handed. It does not decide on its own
what becomes a tracked finding — `finding-validation` owns that decision
(see step 6).

**Objective:** for each candidate routed here, either establish clear
evidence that the payload is exploitable in the observed context, using the
minimum payload needed — not to explore every possible bypass or build a
persistent exploit chain — or record a clear negative, blocked, or
unconfirmable result. Then record the result and stop. This skill produces
evidence, not a final finding.

Default to `curl` and the built-in `http` tool. Do not pull in browser
automation frameworks, XSS scanners (XSStrike, dalfox), or payload
generators — this skill works from one candidate at a time with a small,
targeted payload set, not brute-force fuzzing.

Execution rule: substitute the real target and real parameter values before
running commands. Never write literal placeholder payloads such as
`<PAYLOAD>` to files — write the exact payload used. If the candidate or its
context is unclear, ask once before proceeding.

## Target identifier

`<target>` below always refers to the identifier derived by the convention
defined in `recon/SKILL.md` ("Target identifier convention"). Reuse that
identifier exactly — do not re-derive it differently here.

## Scope

Only test candidates explicitly handed off from
`web-input-analysis/<target>/candidates.md` with
`suspected_class: cross-site-scripting` (or a class list that includes it).
Do not:

- test candidates suspected of a different class (`sql-injection`,
  `access-control`) — those route to their own skill instead;
- expand scope to parameters or endpoints not present in the hand-off;
- run this skill directly from an inventory or from `recon` without
  `web-input-analysis` having produced a candidate first.

## Preconditions

Before starting, you should have:

- `web-input-analysis/<target>/candidates.md` containing at least one
  candidate with `suspected_class: cross-site-scripting`;
- confirmation the target is still in scope.

If no such candidate exists, or the candidate file is missing or stale, go
back to `web-input-analysis` rather than guessing at a parameter here.

## 1. Load the candidate and its context

For each XSS candidate handed off, note:

- endpoint, method, parameter, and location (query, body, path, header,
  cookie);
- the reflection context already observed by `web-input-analysis` (HTML
  body, HTML attribute, JS string, URL, or unknown — re-derive it in step 2
  if it wasn't captured);
- the confidence and rationale already recorded, so you don't repeat the
  Tier 1/2 signal-gathering `web-input-analysis` already did.

Work one candidate at a time. Don't run confirmation probes against every
`cross-site-scripting`-tagged candidate in a batch before recording results
for the first — finish, record, then move to the next.

## 2. Determine the reflection context precisely

The correct proof payload depends entirely on where the value lands. Send
one request with a distinctive, non-executing marker and inspect exactly
how it is embedded in the response before choosing a payload:

```sh
TARGET="http://localhost:3000"  # replace with the real target
MARKER="xsspoc$(date +%s)"

curl -ksS "$TARGET/search?q=${MARKER}\"'<>" \
  | grep -o ".\{20\}${MARKER}.\{20\}"
```

Classify what you see around the marker:

- **HTML body context** — the marker sits between tags and is not
  HTML-encoded.
- **HTML attribute context** — the marker sits inside a quoted attribute
  value.
- **JS string context** — the marker sits inside a JavaScript string
  literal.
- **URL/href context** — the marker lands in an `href`, `src`, or similar
  URL-bearing attribute.
- **Fully encoded/neutralized** — special characters are encoded or
  otherwise neutralized. This candidate is very likely not exploitable as
  reflected XSS; note this and mark it `not confirmed` rather than forcing
  a payload.

For reflected XSS, the HTTP response establishes the reflection context.
Whether that evidence is sufficient for `confirmed` depends on the context:
an unescaped executable `<script>` payload in an ordinary HTML body or
attribute context can be sufficient when browser parsing of that context is
deterministic. More context-sensitive cases (JS string break-out, DOM
sinks) may require browser-level confirmation — see step 3's interpretation
guidance and the outcome definitions in step 5.

## 3. Confirm with the minimum payload for that context

Use the smallest payload needed to establish exploitability in the observed
context. Do not use a maximal bypass chain — one clear result per candidate
is enough.

```sh
# HTML body context
curl -ksS "$TARGET/search?q=<script>document.title='xsspoc-${MARKER}'</script>"

# HTML attribute context — break out of the attribute first
curl -ksS "$TARGET/search?q=\"><script>document.title='xsspoc-${MARKER}'</script>"

# JS string context — break out of the string literal
curl -ksS "$TARGET/search?q='-document.title='xsspoc-${MARKER}'-'"
```

Interpret the result according to the observed context:

- For a normal HTML body or attribute context where an unescaped executable
  `<script>` payload is deterministically parsed as script, HTTP-level
  response evidence may be sufficient for `confirmed`.
- For a JavaScript string context where execution depends on correctly
  breaking out of the surrounding source syntax, use
  `requires-browser-confirmation` unless the response provides sufficiently
  deterministic evidence that the break-out succeeded and lands in an
  executable position.
- For DOM-based XSS where the source → sink path is established in client
  code but actual execution is not observed, use
  `requires-browser-confirmation`.
- Never claim browser execution solely because a payload string appears in
  an HTTP response when the observed context does not make execution
  deterministic from that response alone.

Keep the proof non-destructive and scoped to your own session:

- Do not exfiltrate cookies, tokens, or page content to an external
  listener — `document.title` (or an equally inert, self-contained
  indicator) is sufficient proof of script execution.
- Do not chain the payload into session hijacking, credential capture, or
  redirection to an external site.
- For a candidate that appears to require stored XSS (the value is
  persisted and rendered back on a later request, e.g. a comment or profile
  field), only submit the payload to a resource you own or a designated
  test account, and remove or clean up the stored payload afterward when
  the application supports it.
- For a candidate that appears to be DOM-based (the sink is client-side,
  e.g. `innerHTML`, `document.write`, `eval` on a URL fragment or a
  `postMessage` handler observed in JS during `web-enumeration`), confirm
  from the JS source itself where possible rather than guessing a payload —
  cite the exact sink and how tainted input reaches it.

**3a. WAF / rate-limiting check.** If a probe is clearly intercepted by an
upstream WAF, rate limiter, CAPTCHA, or equivalent challenge before reaching
application logic, record the candidate as `blocked`.

Do not classify an ordinary application response such as a normal `401` or
`403` as `blocked` merely from the status code. There must be evidence that
an upstream control intercepted the request before application handling —
otherwise it is an application-level response and should be evaluated as
such (e.g. `not confirmed`, or worth noting separately if it suggests an
access-control issue outside this skill's scope).

Do not retry blocked probes with encoding tricks, alternate payloads, or
filter-bypass techniques. That is outside this skill's scope.

If the first payload for the observed context doesn't execute, try at most
one or two close variants for that same context (e.g. a different quote
style). If none work, mark the candidate as `not confirmed` rather than
escalating into a broader payload sweep or filter-bypass exploration — that
shift is out of scope for this skill.

## 4. Bound the proof — do not escalate into impact demonstration

Once step 3 gives a clear result for a candidate, stop probing it. In
particular, do not:

- exfiltrate cookies, tokens, or session data, even to a listener you
  control;
- perform an actual session hijack, account takeover, or credential
  capture;
- chain the injection into further attacks (CSRF, redirect to a phishing
  page, etc.);
- run automated XSS scanners or fuzzers to "see how bad it is."

If step 3 never produces a clear signal, that's a valid outcome — record it
as `not confirmed` rather than continuing to escalate technique or payload
variety to force a result.

## 5. Record the validation evidence

Every candidate gets exactly one outcome:

- `confirmed` — sufficient evidence establishes XSS exploitability in the
  observed context. For ordinary HTML body or attribute contexts, an
  unescaped executable payload can be sufficient when browser parsing is
  deterministic from the response. Contexts that cannot be determined
  reliably from HTTP-level evidence alone (e.g. JS string context, DOM-based
  sinks) must be recorded as `requires-browser-confirmation` instead, not
  as `confirmed`.
- `not confirmed` — the candidate was actually tested and the observed
  application behavior did not establish XSS, or the input was fully
  encoded/neutralized.
- `blocked` — an upstream WAF, rate limiter, CAPTCHA, or equivalent control
  intercepted the probe before application logic could be evaluated (step
  3a); the application itself was never actually tested.
- `requires-browser-confirmation` — the response or source/sink analysis is
  consistent with XSS, but actual execution depends on browser behavior
  that cannot be established reliably with the available HTTP-level
  evidence.

For every candidate, regardless of outcome, capture:

- endpoint, method, parameter, location;
- outcome (one of the four above);
- reflection type: reflected, stored, or DOM-based;
- exact payload(s) used;
- the exact request(s) and response evidence showing the outcome (the
  relevant excerpt around the marker/payload — not full response bodies,
  and never response bodies containing real user data);
- authentication context: does triggering it require the victim to be
  logged in, and does the payload execute in their authenticated session;
- realistic impact when there's enough evidence to describe it (e.g.
  session-adjacent action, content spoofing, credential-phishing surface)
  — describe plausible impact without actually performing session hijacking
  or credential theft;
- any mitigating factors observed (e.g. CSP headers, HttpOnly cookies) even
  if they don't fully block this specific payload;
- for DOM-based candidates: the sink and the taint path observed in source,
  if apparent.

Write every candidate's result — confirmed, not confirmed, blocked, or
requires-browser-confirmation — to:

`cross-site-scripting/<target>/results.md`

using the same target identifier as `recon`, `web-enumeration`, and
`web-input-analysis`. This is the durable record of what was actually
tested and what was found, independent of whether anything gets turned into
a finding. One entry per candidate, in the same style as
`web-input-analysis/candidates.md`.

A `confirmed` result here is evidence ready for `finding-validation`; it is
not yet a tracked finding until that phase accepts it.

## 6. Hand off to finding-validation

`cross-site-scripting` does not create a final finding itself — it produces
tested evidence in `results.md`. Whether that evidence becomes a tracked
finding, and in what format, is `finding-validation`'s decision:

```
cross-site-scripting → results.md → finding-validation → final finding
```

For each candidate marked `confirmed` in `results.md`, hand off to
`finding-validation` with:

- affected endpoint/parameter/method;
- reflection type and authentication context;
- the exact request and payload that triggers execution, and the response
  or source/sink evidence;
- concrete impact in one or two sentences — not a hypothetical worst case;
- suggested remediation direction: context-appropriate output encoding, a
  templating engine that auto-escapes by default, and/or a
  Content-Security-Policy as defense-in-depth. Do not recommend
  blacklist-based input filtering as the primary fix.

Do not hand off `not confirmed`, `blocked`, or `requires-browser-
confirmation` candidates to `finding-validation` as findings — they stay
recorded in `results.md` only. For `requires-browser-confirmation`
candidates specifically, flag in the summary that browser-level
confirmation is needed before `finding-validation` (or the user) decides
whether to pursue it further.

Also summarize, across all candidates processed:

- how many were confirmed vs. not confirmed vs. blocked vs.
  requires-browser-confirmation;
- for not-confirmed candidates, a one-line reason;
- whether any confirmed result suggests a systemic issue (e.g. the same
  unescaped-output pattern recurring across multiple endpoints) worth
  flagging back to `web-input-analysis` for a broader look at similar
  parameters.

Findings follow their own naming convention, defined in
`finding-validation` — do not reuse the recon target identifier as the
finding file name, and do not hand-roll a different finding format here.

Do not re-run `web-input-analysis` or `web-enumeration` from here — flag it
in the summary and let the user or a fresh phase decide whether to expand
scope.

## Stop conditions

Stop working a candidate when it has reached one of the four outcomes in
step 5 and been written to `results.md`.

Stop the skill entirely when every `cross-site-scripting`-tagged candidate
handed to you has been worked to an outcome and `results.md` is complete.

Do not: test candidates this skill was not explicitly handed, run automated
payload fuzzing or XSS scanners by default, exfiltrate cookies/tokens/
credentials, chain into session hijacking or other vulnerability classes,
retry blocked probes with filter-bypass or encoding tricks, leave stored-
XSS payloads on shared application state without cleanup, or keep
escalating payload complexity on a candidate that already gave a clear
negative result.