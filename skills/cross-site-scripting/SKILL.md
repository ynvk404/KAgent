---
name: cross-site-scripting
description: >
  Validate reflected, stored, or DOM-based cross-site scripting for a
  specific candidate that `web-input-analysis` flagged as
  `suspected_class: cross-site-scripting`, using the minimum non-destructive
  testing needed to establish evidence. Produces tested evidence
  (request/response, impact, remediation direction) and calls
  `confirm_finding` only when that evidence meets the confirmed threshold.
  Use after `web-input-analysis` has handed off a specific XSS candidate, or
  when the user directly supplies a concrete endpoint, input, and reflection
  context to validate. Never expand beyond the provided candidate.
stage: validation
triggers:
  strong:
    - cross site scripting
    - xss
    - script injection
    - reflected xss
    - stored xss
    - dom xss
    - html injection
  weak:
    - script tag
    - innerhtml
    - document.write
    - postmessage
    - escape output
    - content security policy
candidate-classes:
  - cross-site-scripting
requires:
  - web-input-analysis
allowed-tools:
  - shell
  - http
  - read_payloads
  - file_write
  - ask_user
  - confirm_finding
  - workflow
---

# Cross-site scripting playbook

## Structured workflow contract

Before recording a `confirmed` result, save a minimal redacted proof artifact,
call `workflow(action="record_evidence", candidate_id="...",
evidence_path="...")`, and use the returned `ev_...` ID in `evidence_refs`.
Keep the artifact available through finding creation and session resume.
If coverage sync is `pending`, retry `workflow(action="sync_coverage",
candidate_id="...")` before `confirm_finding`.

Consume a matching Candidate with `workflow(action="start_validation",
candidate_id="...")`. For a concrete direct user request, validation may begin
immediately; record its supplied details as a Candidate for the result handoff,
without requiring prior recon/analysis. Finish every meaningful attempt
with `workflow(action="record_result", ...)`, mapping browser-only proof to
`browser-required` and keeping evidence as references. Use `force=true` only
for an explicit retest or materially changed input. Call `confirm_finding`
with the Candidate ID only after the structured outcome is `confirmed`.

You have a specific candidate that `web-input-analysis` flagged
`suspected_class: cross-site-scripting`, or that the user directly supplied
with an endpoint, input, and observed reflection context. This phase answers "is
this parameter actually exploitable for script execution, and what's the
concrete impact?" It does not re-triage the whole inventory and does not
test parameters outside the provided candidate. It may persist a tracked finding
only after the evidence meets step 5's confirmed threshold (see step 6).

**Objective:** for each candidate routed here, either establish clear
evidence that the payload is exploitable in the observed context, using the
minimum payload needed — not to explore every possible bypass or build a
persistent exploit chain — or record a clear negative, blocked, or
unconfirmable result. Then record the result and stop. This skill produces
evidence, not a final finding.

## Workflow at a glance

This skill has exactly two payload-bearing stages, matching the two
sections in `payloads.txt` — it deliberately does not mirror
`sql-injection`'s phase count, because the two vulnerability classes have
different workflows. What's shared between the two skills is the design
*contract* (candidate in → scope check → minimum evidence → stop → record),
not the number of phases:

```
Context detection    — inert text marker, establishes where/how input lands
        ↓
Context-specific
confirmation          — one execution marker matched to the observed context
        ↓
(if HTTP/source evidence is not deterministic)
requires-browser-confirmation — recorded and stopped, not escalated
```

**There is no optional "impact" phase analogous to `sql-injection`'s Phase
3, and this is a deliberate design choice, not an omission.** For XSS, the
minimum proof of exploitability (a harmless execution marker landing in an
executable position) *is* the impact ceiling — there is no smaller,
separately-authorized "confirm impact" step below it the way there is for
SQL injection (where confirming the vulnerability and reading a fingerprint
value are two meaningfully different levels of access). If a future version
of this skill ever needs a deeper, separately-gated impact phase, it should
get its own `ask_user` checkpoint here first — `payloads.txt` should never
grow a new phase section before `SKILL.md` defines the gate for it.

Default to `curl` and the built-in `http` tool. Do not pull in browser
automation frameworks, XSS scanners (XSStrike, dalfox), or payload
generators — this skill works from one candidate at a time with a small,
targeted payload set, not brute-force fuzzing.

**No browser-execution capability is available in the current runtime.**
When a candidate's evidence depends on actual browser execution (see
`requires-browser-confirmation` below), record that outcome and stop — do
not attempt to simulate or infer browser execution using `shell`, `http`,
or any other substitute. This mirrors how `sql-injection` treats its
OOB-confirmation capability gate: an unavailable capability is a reason to
record the honest limits of what was tested, not a reason to improvise a
workaround.

Execution rule: substitute the real target and real parameter values before
running commands. Never write literal placeholder payloads such as
`<PAYLOAD>` to files — write the exact payload used. If the candidate or its
context is unclear, use `ask_user` once before proceeding.

## Relationship to `payloads.txt`

`SKILL.md` and `payloads.txt` have different jobs, same as in
`sql-injection`:

- **`SKILL.md` decides what you're allowed to do** — which section of
  `payloads.txt` applies to the candidate's context, what evidence bar a
  result needs to meet, and when to stop.
- **`payloads.txt` provides the technical how** — the actual marker and
  execution-probe strings, once `SKILL.md` says a given section applies.

Reading a section of `payloads.txt` is not by itself authorization to use
it against a context it doesn't match. In particular:

- Use `read_payloads(skill="cross-site-scripting", file="payloads.txt")`
  and select only the `PHASE 1 — CONTEXT DETECTION` block for step 2
  below, and only the `PHASE 2 — CONTEXT-SPECIFIC CONFIRMATION` entry that
  matches the context you actually observed for step 3.
- Do not read the whole file and try every context's payload against a
  candidate "to see what sticks" — that is the fuzzing behavior this skill
  explicitly avoids.
- `payloads.txt` has no impact/exploitation section, by design (see
  "Workflow at a glance" above) — there is nothing further to read once
  Phase 2 gives you a result.

## Target identifier

`<target>` below always refers to the identifier derived by the convention
defined in `recon/SKILL.md` ("Target identifier convention"). Reuse that
identifier exactly — do not re-derive it differently here.

## Scope

Only test concrete candidates from `artifacts/web-input-analysis/<target>/candidates.md`
with `suspected_class: cross-site-scripting` (or a class list that includes
it), or candidates directly supplied by the user with equivalent endpoint,
input, and context details.
Do not:

- test candidates suspected of a different class (`sql-injection`,
  `access-control`) — those route to their own skill instead;
- expand scope to parameters or endpoints outside the provided candidate;
- invent endpoint, input, or context details from a generic "test XSS"
  request.

## Preconditions

Before starting, you should have:

- a `web-input-analysis` candidate, or equivalent endpoint/input/context
  details supplied directly by the user;
- confirmation the target is still in scope.

If no concrete candidate exists, use `web-input-analysis` rather than guessing
at an endpoint or parameter here.

## Session / authentication consistency

If the candidate's endpoint requires authentication or a session (check
`auth:` on the candidate entry), use one fixed, valid session/credential
for the entire candidate's test run — the context-detection request in
step 2 and the confirmation request(s) in step 3 must carry the same
session cookie, `Authorization` header, and CSRF token. If the session
expires mid-sequence, refresh it and re-run context detection before
continuing — don't compare a step-3 probe made with a stale session
against a step-2 observation made with a fresh one; that difference is
session state, not a change in how the input is handled.

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
one request with the **detection marker** from `payloads.txt`'s
`PHASE 1 — CONTEXT DETECTION` section — a plain, non-executing text string
— and inspect exactly how it is embedded in the response before choosing a
confirmation payload:

```sh
TARGET="http://localhost:3000"  # replace with the real target
MARKER="xsspoc$(date +%s)"      # from payloads.txt Phase 1

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
  URL-bearing attribute. Before selecting a Phase 2 payload for this
  context, observe — don't assume — three things: whether the value is
  HTML-encoded, whether the scheme is validated or allow-listed (e.g. the
  app only accepts `http(s)://`), and whether the URL is canonicalized
  before being written into the attribute. Only pick a probe from
  `payloads.txt`'s URL-context entry once you know which of these apply;
  do not default to a `javascript:`-scheme payload without that
  observation, since many apps validate or strip the scheme before an
  executable URL payload would ever matter.
- **HTML comment context** — the marker lands inside an HTML comment
  (`<!-- ... -->`).
- **CSS context** — the marker lands inside CSS. This has two mechanically
  different sub-cases, and `payloads.txt` has a separate entry for each —
  identify which one you're looking at before picking a Phase 2 payload:
  - *style attribute*, e.g. `<div style="color: MARKER">` — breakout
    mechanics are the same as HTML attribute context (close the quote and
    the tag).
  - *`<style>` block*, e.g. `<style>body{color:MARKER}</style>` — breakout
    mechanics are the same as HTML comment context (close and reopen the
    enclosing construct).
  Modern browsers no longer support `expression()`-style CSS execution, so
  this context rarely yields a working execution marker either way —
  classify it accurately when observed, but expect the Phase 2 entry for
  it to often end in `not confirmed` rather than force a result. Do not
  spend more than one probe per sub-case confirming this context is
  genuinely inert before moving on.
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

Use the **execution marker** from `payloads.txt`'s
`PHASE 2 — CONTEXT-SPECIFIC CONFIRMATION` section that matches the context
observed in step 2 — and only that section's entry for that context. Do
not use a maximal bypass chain — one clear result per candidate is enough.
Call it what it is: this payload does execute JavaScript (unlike the
step-2 detection marker, which is inert text); the safety property it has
is that the *action* it performs is harmless and self-contained
(`document.title`), not that it avoids executing code.

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
  the application supports it. Stored XSS reuses the same Phase 2 payload
  matched to the observed context — it is a difference in *where and when*
  the payload executes (store now, render later, possibly to a different
  user), not a different payload corpus. Record the trigger path — which
  endpoint stores the value and which endpoint/action renders it back —
  in the result's `order` field (see step 5).
- For a candidate that appears to be DOM-based (the sink is client-side,
  e.g. `innerHTML`, `document.write`, `eval` on a URL fragment or a
  `postMessage` handler observed in JS during `web-enumeration`), confirm
  from the JS source itself where possible rather than guessing a payload —
  cite the exact sink and how tainted input reaches it. This is
  source/sink analysis, not a separate payload category: if a live probe
  is still needed to confirm, it uses the same context-matched Phase 2
  entry as any other candidate.

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
style, or — for HTML body/attribute contexts specifically — an
event-handler-based marker if the `<script>` variant specifically appears
stripped while other tags/attributes pass through unescaped). Both are
listed under that context's entry in `payloads.txt`. This is different
from filter-bypass: a close variant tests whether the *same context* is
exploitable through an equivalent vector, which is squarely part of
assessing sanitization coverage; it does not use encoding tricks, case
obfuscation, or payload fragmentation aimed at evading a filter or WAF —
those remain out of scope per step 3a. If no close variant works, mark the
candidate as `not confirmed` rather than escalating further.

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
  evidence, and no browser-execution capability is available in this
  runtime to close that gap (see "Workflow at a glance").

### Standard result entry template

Write every candidate's result — confirmed, not confirmed, blocked, or
requires-browser-confirmation — to:

`artifacts/cross-site-scripting/<target>/results.md`

using the same target identifier as `recon`, `web-enumeration`, and
`web-input-analysis`, and this exact template, one entry per candidate,
appended in the order tested:

```markdown
## Candidate: <endpoint> [<method>] — param: <parameter> (<location>)

- **timestamp:** <ISO 8601 UTC timestamp when this entry was recorded, e.g. 2026-08-27T09:14:32Z>
- **agent_session_id:** <identifier for the current agent run/session, for audit-trail correlation with logs elsewhere>
- **outcome:** <confirmed | not confirmed | blocked | requires-browser-confirmation>
- **reflection_type:** <reflected | stored | dom-based>
- **context:** <html-body | html-attribute | js-string | url | html-comment | css-style-attribute | css-style-block | fully-encoded | unknown>
- **payload(s) used:** <exact detection marker and/or execution marker used, verbatim>
- **evidence:** <the exact request(s) and response excerpt around the marker/payload — not full response bodies, and never response bodies containing real user data>
- **auth_context:** <does triggering it require the victim to be logged in, and does the payload execute in their authenticated session>
- **order:** <first-order (reflected same request) | second-order-suspected (stored) — if stored/second-order, describe the trigger path: which endpoint stores the value, which endpoint/action renders it back, and to whom (e.g. "stored via POST /api/tickets, rendered to support agents at GET /admin/tickets/{id}")>
- **cleanup_performed:** <yes | no — not applicable (reflected, nothing stored) | app does not support deletion — required whenever a payload was stored per step 3>
- **mitigating_factors:** <e.g. CSP headers, HttpOnly cookies observed, even if they didn't fully block this payload>
- **dom_sink_evidence:** <for dom-based candidates: the exact sink and the taint path observed in source; n/a otherwise>
- **realistic_impact:** <plausible impact described in one or two sentences, without having actually performed session hijacking or credential theft>
- **notes:** <anything else relevant — WAF behavior, session issues, ambiguous signals>
```

This is the durable record of what was actually tested and what was found,
independent of whether anything gets turned into a finding. The
`timestamp` and `agent_session_id` fields exist purely for audit
traceability — they don't affect gating or outcome logic. `cleanup_performed`
exists so the stored-payload cleanup requirement in step 3 is independently
auditable rather than trusted to have happened silently.

A `confirmed` result here is evidence ready for `confirm_finding`; it is not
yet a tracked finding until that tool persists it.

## 6. Confirm an evidence-backed finding

`cross-site-scripting` first produces tested evidence in `results.md`. For
each candidate marked `confirmed`, call `confirm_finding` to persist the
canonical finding:

```
cross-site-scripting → results.md → confirm_finding → final finding
```

Populate the tool call from the recorded evidence. Supply the required
`candidate_id` of the confirmed Candidate, `title`, `severity`, exact `url`,
`parameter`, `payload`, `method`, a short proving `response_excerpt`,
`observed_impact`, `potential_impact`, a copy-pasteable `curl`, remediation,
and `vuln_class: xss`. The latest result and its registered evidence must be
valid. Include:

- affected endpoint/parameter/method;
- reflection type and authentication context;
- the exact request and payload that triggers execution, and the response
  or source/sink evidence;
- `observed_impact`: only what the execution and linked evidence demonstrate;
- `potential_impact`: untested consequences stated as conditional possibilities,
  never as facts;
- suggested remediation direction: context-appropriate output encoding, a
  templating engine that auto-escapes by default, and/or a
  Content-Security-Policy as defense-in-depth. Do not recommend
  blacklist-based input filtering as the primary fix.

Do not call `confirm_finding` for `not confirmed`, `blocked`, or
`requires-browser-confirmation` candidates — they stay recorded in
`results.md` only. For `requires-browser-confirmation`
candidates specifically, flag in the summary that browser-level
confirmation is needed before the user decides whether to pursue it further.

Also summarize, across all candidates processed:

- how many were confirmed vs. not confirmed vs. blocked vs.
  requires-browser-confirmation;
- for not-confirmed candidates, a one-line reason;
- whether any confirmed result suggests a systemic issue (e.g. the same
  unescaped-output pattern recurring across multiple endpoints) worth
  flagging back to `web-input-analysis` for a broader look at similar
  parameters.

Do not reuse the recon target identifier as the finding file name or
hand-roll a different finding format; `confirm_finding` owns canonical
finding persistence and naming.

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
XSS payloads on shared application state without cleanup, simulate browser
execution with `shell` or any other workaround when
`requires-browser-confirmation` applies, add a new payload phase to
`payloads.txt` without a corresponding gate defined here first, or keep
escalating payload complexity on a candidate that already gave a clear
negative result.
