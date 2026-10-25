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

A requested XSS goal does not itself establish a Candidate. Controllable input
or markup in JSON without rendering context/source-to-sink evidence remains an
observation. An API negative applies only to the tested sink and cannot exclude
DOM or stored XSS. Base `browser-required` on actual exposed and allowed browser
capabilities; do not invent execution or infer capability from application type.

Before proof/result submission, inspect the current candidate/attempt inventory.
Prefer completed, complete, non-truncated sources with the correct request
association; reuse an existing complete control instead of recapturing after
choosing a truncated duplicate. Metadata usability does not prove XSS impact.
Keep adverse evidence. If parents change, correct the source proof and dependent
claims and register a new immutable snapshot; never edit or rebind an old one.
Registration alone does not make a terminal result eligible. Reserve remaining
budget for finalization after probing stops; Continue resets no allowance.

## Runtime completion contract

The runtime derives validation completion from the current objective and target,
assigned Candidates, accepted terminal ValidationResults, immutable proof integrity,
coverage synchronization, cleanup, and required finding persistence. A `confirmed`
result resolves its assigned work only after `confirm_finding` persists it; a valid
`not-confirmed` result needs no finding. Pending, validating, blocked, deferred,
browser-required, authorization-required and insufficient-evidence work remains
outstanding. Stop unsafe or exhausted probes and record the unresolved outcome;
do not describe it as completed validation.

Do not issue a skill-completion tool call. The runtime tracks each requested goal
and other assigned work independently; one finding cannot complete unrelated work.
`results.md` is an optional report/export of persisted results, findings and evidence,
not a completion gate. If exported, use the documented canonical target path and
report write failures explicitly; never substitute an arbitrary alternate path.
Minimal redacted proof artifacts and primary source references remain mandatory for
both terminal outcomes, even when no results report is exported.

## Structured workflow contract

Attempt effects are durable bookkeeping, separate from evidence-repair retries.
Record observed writes or uncertainty before result submission using
`workflow(action="record_attempt_state", candidate_id=..., mutation_state=...,
effect_basis=..., observation_ids=[...], cleanup_state=..., cleanup_status=...)`.
Mutation states are `unknown`, `possible`, `reported-write`, `verified-write`,
and `no-mutation-established`. Unknown uses `mutation_performed: null`, never
false by default. A stored payload acknowledgement does not prove persistence;
cleanup unknown/not-attempted is not completed cleanup. Cleanup success needs
owned declared cleanup action/verification evidence and separate authority.
Explicit mutation/cleanup fields remain accepted on `record_result`; omitted
fields use attempt bookkeeping and otherwise remain unknown.

Copy current owned `obs_` IDs from `workflow(action="list", candidate_id=...)`;
page metadata using `next_observation_offset`. HTTP/readback metadata includes
adapter `elapsed_ms`. `read_http_observation` reads `obs_` bodies; `read_tool_result`
reads `tr_` retained outputs; `ev_` IDs identify registered immutable proof.
Do not invent IDs or resend HTTP to repair retrieval. Once probing stops,
use remaining existing budget for local evidence/result finalization, retaining
this playbook's reflected/stored/DOM and browser-proof requirements. A headless
input failure grants no authority; record unresolved when operator input is needed.

`start_validation` returns the Candidate plus a transient `validation_context`:
linked canonical input samples in whole-target mode, Candidate context in
direct mode, and explicit baseline/auth availability and limitations. Keep
`sample_payload` separate from an explicit `request_template`; a sanitized
sample is not a captured replay baseline or executable mutation instruction.
Do not infer missing method/body or fabricate injection markers. Resolve
ambiguity before exact requests; unavailable baseline/auth needs recapture or
live session repair through the existing gates. Availability grants no scope,
permission or proof. Workflow list/prompt rows are summaries; use
`workflow(action="get_input", input_id="...")` for a selected full canonical
sanitized input, including after resume or compaction.

For a new expert attempt: complete current prerequisites → read the current
skill → prepare primary/supplementary requests and roles → successfully call
`start_validation` → probe → evidence → result. Whole-target work requires
Workflow completion of Recon and Enumeration, a canonical analysis handoff and
a compatible linked analyzed input. Independent blocked inputs keep the global
phase/objective incomplete; they do not block an admitted Candidate. Direct and
candidate-validation retain their own admission contracts.

Prepare associations from the existing Candidate, inventory and context before
opening the attempt. Prefer candidate ID alone when it covers the primary
request and no supplementary request is needed. For example, a Candidate for
`POST /comments` may need known `GET /comments` as a supplementary request with
role `readback`. The same path with a different method is a different request
identity. Declare each supplementary method/URL once with a consistent role;
payload variations are observations. Declare only known endpoints actually
needed for this bounded hypothesis; do not guess rendering or cleanup routes
or send validation probes before admission. Association grants no permission
to execute a request and does not establish XSS.

An owned active attempt keeps its immutable declaration and recovery budget.
If its declaration lacks an association, do not amend it retrospectively or
repeat HTTP just to repair association. Continue if the current declaration
can still complete the work; otherwise record an honest unresolved outcome
and follow the explicit retest contract for a changed declaration.

Record the concrete Candidate before opening its attempt.
Keep its returned `attempt_id`; it is a controller identity, not one to invent.
The HTTP evidence envelope supplies real `observation_ids` for captured requests.
Both `confirmed` and `not-confirmed` require usable primary observations with
current candidate/attempt ownership and registered immutable evidence. A tested
negative is bounded to the actual API/sink and completed attempt; absence of
usable primary evidence is `insufficient-evidence`, not a negative result.

Save a minimal redacted proof artifact, then register it with
`workflow(action="record_evidence", candidate_id="...", evidence_path="...",
observation_ids=[...])` using its actual supporting captures. `record_evidence`
accepts only `action`, `candidate_id`, `evidence_path`, and `observation_ids`;
omit `attempt_id`. Use the returned `ev_...` ID in `evidence_refs`.
`record_result` accepts the returned `attempt_id` as an equality check and the
actual `observation_ids`, plus `assessment` containing `hypothesis`, `criteria`,
`limitations`, `observed_impact`, and `severity`. For `not-confirmed`, include
`completed_attempt: true` only when the bounded test actually completed.
Keep the artifact available through finding creation and session resume.
If coverage sync is `pending`, retry `workflow(action="sync_coverage",
candidate_id="...")` before `confirm_finding`.

After the preparation above, consume a matching Candidate with
`workflow(action="start_validation", candidate_id="...")`, including necessary
known supplementary associations. For a concrete direct user request, record its supplied
details as a Candidate and start its attempt before active probes,
without requiring prior recon/analysis. Finish every meaningful attempt
with `workflow(action="record_result", ...)`, mapping browser-only proof to
`browser-required` and keeping evidence as references. Use `force=true` only
for an explicit retest or materially changed input. Call `confirm_finding`
with the Candidate ID only after the structured outcome is `confirmed`.

Submission examples below use variables returned by production tools, never
literal placeholder IDs. `sources` contains only real observations supporting
the proof, and `evidence_id` is the returned registration handle:

```python
# Registration after the scoped HTTP capture(s) and redacted proof write.
{"action": "record_evidence", "candidate_id": candidate_id,
 "evidence_path": proof_path, "observation_ids": sources}
# Tested API negative; confirmed uses the same primary/evidence contract.
{"action": "record_result", "candidate_id": candidate_id,
 "attempt_id": attempt_id, "skill_name": "cross-site-scripting",
 "outcome": "not-confirmed", "observation_ids": sources,
 "evidence_refs": [evidence_id], "assessment": {
     "hypothesis": "The API input reflects into an executable context",
     "criteria": "Inspect the captured response type, encoding and surrounding syntax",
     "limitations": "Only this API candidate was tested; DOM execution was not observed",
     "observed_impact": "Completed probes did not establish executable API reflection",
     "severity": "info", "completed_attempt": True}}
# No usable primary evidence: references may be omitted, without fabricating IDs.
{"action": "record_result", "candidate_id": candidate_id,
 "skill_name": "cross-site-scripting", "outcome": "insufficient-evidence",
 "deferred_reason": "The response capture was unavailable or incomplete"}
```

Every supplied reference is checked, including for unresolved outcomes. Do not
attach another candidate/attempt's observation or proof to `insufficient-evidence`
to release the attempt; omit unavailable references and state the limitation.
Continuation retains the current recovery budget. A valid explicit retest starts
a separate attempt through the existing controller flow; `force=true` alone does
not create one or grant new authority.

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
browser-required — recorded and stopped, not escalated
```

**The current XSS validator has no optional impact phase analogous to
SQL injection's Phase 3.** The minimum proof here is a harmless execution
marker; deeper effects are a separate risk tier, not an automatic continuation
or a requirement for confirming XSS. This is a limit of this default flow,
not a blanket prohibition on every authorized controlled-impact demonstration.
If an engagement objective requires one, first record the current result and
ask ask_user to name the Candidate, exact lab target/context, synthetic
subject and single action, data/state bound, and risk tier. Proceed only with
that specific approval and an exact-action runtime permission gate that
/yolo cannot bypass; request fresh approval for a higher tier. The current
runtime has no browser-execution capability, so if the check depends on
browser behavior, record browser-required and stop rather than simulate it.

Prefer the built-in `http` tool with `phase: validation` for harmless marker
probes. Use `curl` only when the native tool cannot express a necessary
request detail; shell requests do not enforce target-origin scope. Do not pull in browser
automation frameworks, XSS scanners (XSStrike, dalfox), or payload
generators — this skill works from one candidate at a time with a small,
targeted payload set, not brute-force fuzzing.

**No browser-execution capability is available in the current runtime.**
When a candidate's evidence depends on actual browser execution (see
`browser-required` below), record that outcome and stop — do
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

- Prefer `read_payloads` for bundled payload resources when available. Use
  `read_skill_file` only if exposed by the current runtime and permitted by
  its tool/skill contract. Do not guess nonexistent workspace skill paths or
  access unrelated runner filesystem paths to compensate for missing tools.
  If a resource request is refused or blocked, respect that result and the
  existing refusal/stop behavior; do not switch tools or paths to bypass it.
- Use `read_payloads(skill="cross-site-scripting", file="payloads.txt")`
  and select only the `PHASE 1 — CONTEXT DETECTION` block for step 2
  below, and only the `PHASE 2 — CONTEXT-SPECIFIC CONFIRMATION` entry that
  matches the context you actually observed for step 3.
- Do not read the whole file and try every context's payload against a
  candidate "to see what sticks" — that is the fuzzing behavior this skill
  explicitly avoids.
- `payloads.txt` has no impact/exploitation section; a separate controlled
  impact path would need its own gate and runtime capability before any such
  vectors were added. There is nothing further to read after Phase 2.

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

- test candidates suspected of a different class — route SQL injection to
  `sql-injection`; for other classes, inspect the enabled registry and defer
  when no matching validator is available;
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

Prioritize captured HTTP observations from the target over payload examples
or local resource contents. Identify the reflection context and encoding from
the actual response before choosing further probes. Reflection of an
alphanumeric marker establishes input propagation only; it does not confirm
executable XSS. If browser/DOM execution evidence is unavailable, describe that
limitation explicitly and use `browser-required` when the existing outcome
rules require it; HTTP-only evidence cannot prove every browser-dependent case.

Follow the shared `http` tool contract and current Candidate validation context
for mode choice and replay/recapture rules. This Direct HTTP example applies
only to an established GET `/search` Candidate with query input `q` and no bound
capture, or an independent request allowed by the current workflow, scope and
permissions. For a bound capture use its replay recipe; an unavailable bound
capture is a blocker, not permission to reconstruct this example. Otherwise
use the Candidate's actual baseline and input binding.
Choose a fresh inert marker and inspect its context in the retained response.
Do not add syntax-breaking characters during plain-marker detection.

```json
{
  "tool": "http",
  "arguments": {
    "method": "GET",
    "url": "/search?q=xsspoc2026",
    "phase": "validation",
    "max_response_bytes": 8192
  }
}
```

Classify what you see around the marker:

Check the response Content-Type as well as the surrounding syntax. A
`Content-Type: text/html` response may be an HTML fragment: neither `<html>`
nor `<body>` wrappers are required for HTML parsing. Raw, unencoded reflection
in such a fragment is HTML context, not context=none just because wrappers
are absent. Distinguish raw HTML reflection from a complete executable payload
and from execution that still requires browser proof. Inspect enclosing
comments, attributes, inert elements and CSP before choosing the proof.

- **HTML body context** — the marker sits between tags and is not
  HTML-encoded.
- **HTML attribute context** — the marker sits inside a quoted attribute
  value.
- **JS string context** — the marker sits inside a JavaScript string
  literal.
- **URL/href context** — the marker lands in a URL-bearing attribute. Inspect
  the actual attribute, HTML-decoded value, scheme validation/allow-list and
  canonicalization before selecting a URL probe. HTML attribute encoding alone
  does not establish a safe scheme; different `href`/`src` elements also have
  different execution/interaction behavior. Unknown handling is a limitation,
  not permission to spray scheme variants or a reason to declare a negative.
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
  it to often end in `not-confirmed` rather than force a result. Do not
  spend more than one probe per sub-case confirming this context is
  genuinely inert before moving on.
- **Fully encoded/neutralized in the observed context** — a completed bounded
  test shows the input remains data there, permitting `not-confirmed` for that
  sink. HTML text encoding does not establish safety in JavaScript strings,
  event handlers or URLs: account for the enclosing parser and any later decoding.
  Encoding presence/absence alone proves neither safety nor exploitability.

For Angular clients, interpolation escapes text and `[innerHTML]` bindings
sanitize HTML by default; direct DOM writes and `bypassSecurityTrust*` calls have different
trust boundaries. Verify the actual binding/source-to-sink path rather than
assuming the framework is safe or vulnerable. Scripts inserted through ordinary
`innerHTML` fragment insertion do not execute merely because they appear in DOM;
HTML document parsing and fragment insertion are different proof contexts.

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
  `browser-required` unless the response provides sufficiently
  deterministic evidence that the break-out succeeded and lands in an
  executable position.
- For DOM-based XSS where the source → sink path is established in client
  code but actual execution is not observed, use
  `browser-required`.
- Never claim browser execution solely because a payload string appears in
  an HTTP response when the observed context does not make execution
  deterministic from that response alone.

Keep the proof non-destructive and scoped to your own session:

- Do not exfiltrate cookies, tokens, or page content to an external
  listener — `document.title` (or an equally inert, self-contained
  indicator) is sufficient proof of script execution.
- Do not chain the payload into session hijacking, credential capture, or
  redirection to an external site.
- **Stored/SPA checkpoint:** before a stateful execution probe, establish authority and
  the evidenced rendering context, and only submit the payload to a resource
  you own or a designated test account. Check isolation, readback and cleanup
  feasibility; missing cleanup authority never permits automatic deletion.
  If the proof path needs browser execution, check the actually permitted,
  integrated capability first. When it is unavailable, record `browser-required`
  if applicable rather than add executable mutations that cannot close the gap.
  Browser capability is not required for deterministic HTTP proof under step 3.
  After a write acknowledgement, record reported effects promptly under the
  structured contract; do not wait for execution proof or claim verified storage.
  Independent readback establishes persistence at that time; a rendering response
  may also serve as readback, without an extra request solely to satisfy a list.
  Acceptance, stored markup and JSON readback are not execution evidence. Follow
  the evidenced rendering sink to its executable context and applicable proof,
  then perform cleanup only with separate authority and record verification or
  honest limitations. Record store-to-render endpoints/audience in `order` and
  declare differing related request identities before starting the attempt.
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
such (e.g. `not-confirmed`, or worth noting separately if it suggests an
access-control issue outside this skill's scope).

Do not retry blocked probes with encoding tricks, alternate payloads, or
filter-bypass techniques. That is outside this skill's scope.

If the response shows a clear deterministic transformation, such as removing
exactly one trailing character, allow at most one bounded same-context close
variant compensating for that observed transformation. For trailing-character
removal, append one inert trailing character to the same execution marker and
inspect whether the returned payload is now complete. This consumes the close
variant allowance; do not also spray alternate vectors. It is not a new fuzzing
or filter-bypass phase. Confirm only if the returned complete executable syntax
and context meet the existing deterministic HTTP proof threshold; otherwise
retain browser-required when execution remains browser-dependent.

If the first payload for the observed context doesn't execute, try at most
one close variant for that same context (e.g. a different quote
style, or — for HTML body/attribute contexts specifically — an
event-handler-based marker if the `<script>` variant specifically appears
stripped while other tags/attributes pass through unescaped). Both are
listed under that context's entry in `payloads.txt`. This is different
from filter-bypass: a close variant tests whether the *same context* is
exploitable through an equivalent vector, which is squarely part of
assessing sanitization coverage; it does not use encoding tricks, case
obfuscation, or payload fragmentation aimed at evading a filter or WAF —
those remain out of scope per step 3a. If no close variant works, stop and use
step 5: `not-confirmed` needs a completed bounded test and usable proof; missing
browser execution remains `browser-required`, and missing sources/proof remains
`insufficient-evidence`. An unobserved effect is not a tested negative.

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

If step 3 never produces a clear signal, stop payload escalation and use step 5's
outcome rules. Distinguish a completed bounded negative from missing browser
execution, incomplete testing or unavailable proof.

## 5. Record the validation evidence

Immediately before recording any terminal XSS assessment, verify the actual
captured response bytes and surrounding context, including every delimiter
needed by the claimed executable syntax. Compare the returned syntax with the
request; do not substitute the intended payload or an LLM-reconstructed HTML
element for the captured response. An incomplete executable payload must not
be confirmed merely from raw reflection in text/html.

For example, a complete, untruncated response ending in
`<script>document.title='proof'</script` lacks the final `>`. Do not call it a
complete executable element because the intended request contained that
character. Use the one bounded same-context compensating variant permitted in
step 3 when deterministic trailing-character removal is observed, then inspect
its actual response. If complete executable syntax or another permitted
confirmation condition is not established, do not claim confirmed execution.
Deterministic HTTP-based confirmation remains sufficient when step 3's context
and proof conditions hold; a browser is not universally required.

Keep a compact observation ledger linking detection marker, execution marker
and the one permitted close variant to their effective requests, observation
IDs, HTTP statuses, body excerpts and capture flags. The runtime HTTP evidence
envelope supplies a redacted effective request preview; if
`request_preview_complete: false`, unseen request text remains unknown. Compare
distinct captured requests before calling a transformation deterministic or
claiming repetition. Inspect the actual Content-Type, surrounding syntax,
encoding, inert context and CSP for each response. Neither raw reflection nor
HTML fragment parsing alone establishes execution; deterministic HTTP proof
establishes exploitability under step 3, not observed browser execution.

Select primary sources with current candidate/attempt ownership, completed
execution and complete, untruncated captures that support the cited claims.
Metadata-only capture cannot prove response content. When required bytes were
omitted, use an available evidence-reading API only with a real reference and
its existing gates; if retrieval is unavailable, state the limitation rather
than reconstructing the response from the intended payload or conversation.
After admissibility rejection, inspect usable observations already captured.
Changing the primary parent set requires correcting the source proof and
dependent claims/excerpts, then `record_evidence` with the correct
`observation_ids` for a new immutable snapshot and replacing `evidence_refs`
before resubmitting. Removing an observation ID alone leaves derived proof
stale. Never edit registered snapshots in place or borrow another attempt's
sources. Following the loader preface, retry at most once with usable existing
evidence within the remaining recovery budget; this does not change the runtime
retry ceiling. Do not send new HTTP probes solely for manifest repair or reset
the budget.
If valid repair is unavailable, record `insufficient-evidence` and stop;
retain `browser-required` when the missing proof is browser execution.

Every candidate gets exactly one outcome:

- `confirmed` — sufficient evidence establishes XSS exploitability in the
  observed context. For ordinary HTML body or attribute contexts, an
  unescaped executable payload can be sufficient when browser parsing is
  deterministic from the response. Contexts that cannot be determined
  reliably from HTTP-level evidence alone (e.g. JS string context, DOM-based
  sinks) must be recorded as `browser-required` instead, not
  as `confirmed`.
- `not-confirmed` — the candidate was actually tested and the observed
  application behavior did not establish XSS, or the input was fully
  encoded/neutralized.
- `blocked` — an upstream WAF, rate limiter, CAPTCHA, or equivalent control
  intercepted the probe before application logic could be evaluated (step
  3a); the application itself was never actually tested.
- `browser-required` — the response or source/sink analysis is
  consistent with XSS, but actual execution depends on browser behavior
  that cannot be established reliably with the available HTTP-level
  evidence, and no browser-execution capability is available in this
  runtime to close that gap (see "Workflow at a glance").
- `insufficient-evidence` — no usable primary observations or required proof
  are available to support a terminal assessment. Omit unavailable references,
  explain the limitation, and stop without claiming a negative or completion.
- `deferred` / `authorization-required` — validation is postponed or blocked by
  missing authority; record the reason and keep the work outstanding.

An API response candidate and a client-side SPA route are separate sinks. A
negative JSON reflection test applies only to that API candidate. If a route
such as `#/search?q=...` has an evidenced source-to-sink path in client code,
record a separate DOM candidate and use `browser-required` when browser
execution cannot be checked. A route name, parameter name, application type,
or raw JSON/HTML markup alone does not establish that hypothesis.
Do not transfer the API result to the route. When no marker was reflected, set
`reflection_type` to `none`; never call that observation `reflected`.
JSON API reflection alone does not establish an executable HTML/DOM sink.
For stored XSS, distinguish the write capture from the later rendering/readback
capture and its observed context; declare related requests before execution
when their identity differs. Preserve mutation/cleanup bookkeeping and report
`browser-required` when the later execution still depends on a browser.

Use the existing Candidate `test_case` field before starting validation to
distinguish genuinely different API, DOM and stored hypotheses that share an
endpoint/input. Choose a stable description of the evidenced source/sink path,
such as `dom:location-search-to-innerhtml` or `stored:comment-to-review`, and
keep its source references and observed signals on that record. Reuse that
identity for the same hypothesis; payload variants are not new hypotheses.
Do not change an active attempt's declaration or Candidate identity to attach
another sink. Close its honest outcome and register the separately evidenced
hypothesis instead. A `browser-required` sibling remains unresolved even after
an API sibling reaches an accepted terminal result. This records identified
surfaces; it does not attest exhaustive browser or stored-XSS coverage.

### Standard result entry template

Optionally export every persisted candidate result — confirmed, not-confirmed,
blocked, browser-required, or another honest unresolved outcome — to:

`artifacts/cross-site-scripting/<target>/results.md`

using the same target identifier as `recon`, `web-enumeration`, and
`web-input-analysis`, and this exact template, one entry per candidate,
appended in the order tested:

```markdown
## Candidate: <endpoint> [<method>] — param: <parameter> (<location>)

- **candidate_id:** <structured Workflow Candidate ID>
- **timestamp:** <ISO 8601 UTC timestamp when this entry was recorded, e.g. 2026-08-27T09:14:32Z>
- **agent_session_id:** <identifier for the current agent run/session, for audit-trail correlation with logs elsewhere>
- **outcome:** <confirmed | not-confirmed | blocked | browser-required | insufficient-evidence | deferred | authorization-required>
- **reflection_type:** <none | reflected | stored | dom-based>
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
traceability — they don't affect gating or outcome logic. Populate them only
from runtime-supplied values; if timestamp/session identity is unavailable,
write `unavailable`, never invent a value. `cleanup_performed`
exists so the stored-payload cleanup requirement in step 3 is independently
auditable rather than trusted to have happened silently.

A `confirmed` result here is evidence ready for `confirm_finding`; it is not
yet a tracked finding until that tool persists it.

## 6. Confirm an evidence-backed finding

`cross-site-scripting` records accepted results with immutable evidence references. For
each candidate marked `confirmed`, call `confirm_finding` to persist the
canonical finding:

```
cross-site-scripting → accepted ValidationResult + immutable proof → confirm_finding → final finding
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

Do not call `confirm_finding` for `not-confirmed`, `blocked`, or
`browser-required` candidates — they remain recorded as
ValidationResults. For `browser-required`
candidates specifically, flag in the summary that browser-level
confirmation is needed before the user decides whether to pursue it further.

Also summarize, across all candidates processed:

- how many were confirmed vs. not-confirmed vs. blocked vs.
  browser-required;
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

Stop probing a candidate when its bounded testing reaches a recorded outcome.
Accepted terminal work is resolved by the runtime contract above; unresolved
outcomes stop probing but remain outstanding. Persist required confirmed findings
and resolve cleanup and coverage before describing validation as complete.

Do not: test candidates this skill was not explicitly handed, run automated
payload fuzzing or XSS scanners by default, exfiltrate cookies/tokens/
credentials, chain into session hijacking or other vulnerability classes,
retry blocked probes with filter-bypass or encoding tricks, leave stored-
XSS payloads on shared application state without cleanup, simulate browser
execution with `shell` or any other workaround when
`browser-required` applies, add a new payload phase to
`payloads.txt` without a corresponding gate defined here first, or keep
escalating payload complexity on a candidate that already gave a clear
negative result.
