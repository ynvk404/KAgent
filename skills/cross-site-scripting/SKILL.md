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
budget for finalization after probing stops; Continue does not reset declaration
or recovery allowances.

## Decision checkpoint — before a probe and after its response

**Observe → Model Context → Form Hypotheses → Predict → Probe → Interpret → Adapt → Reassess → Decide.**
Model the input source, output/DOM sink, execution context and observed
transformations. Separate reflection, neutralization and execution evidence.
After each response and before `record_result`, apply step 3's returned-code and
hypothesis checkpoints. Preserve effective code and decisions in assessment/proof.
Reuse adequate observations. A harmless context-appropriate test needs a
discriminating prediction; metacharacter detection helps only with unresolved
encoding or transformation uncertainty.

Use ambiguous existing observations to form competing hypotheses; no new HTTP
observation is needed merely to reconsider them. Compare results with predictions.
Continue a justified adaptation, even after a prior close variant. There is no numeric variant cap;
avoid redundant equivalent variants and payload spraying. A failed technique does
not close its Candidate while an essential supported alternative has a useful
permitted test within scope, permissions and runtime/operator limits. Continue
without asking to repeat the goal; no corpus exhaustion or minimum variants are
required. Stop when evidence is sufficient, the bounded hypothesis is adequately
ruled out, no useful authorized test remains, or execution is blocked. State the
actual stop reason; unresolved work needs its honest outcome. Missing necessary
browser proof remains `browser-required`; browser absence alone does not settle
a useful HTTP question. See step 3 before deciding to end validation.

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
unconfirmable result. Then record the result and stop. Only `confirm_finding`
turns an accepted confirmed assessment into a tracked finding.

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
confirmation          — harmless execution marker matched to the observed context
        ↓
(if HTTP/source evidence is not deterministic)
Reassess whether a useful HTTP discriminator remains; otherwise record
browser-required when the missing fact requires unavailable browser execution.
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
runtime has no browser-execution capability; apply the capability and proof
rules below.

Prefer the built-in `http` tool with `phase: validation` for harmless marker
probes. Use `curl` only when the native tool cannot express a necessary
request detail; shell requests do not enforce target-origin scope. Do not pull in browser
automation frameworks, XSS scanners (XSStrike, dalfox), or payload
generators — this skill works from one candidate at a time with a small,
targeted payload set, not brute-force fuzzing.

**No browser-execution capability is available in the current runtime.**
When the remaining necessary fact requires browser execution, record
`browser-required` and stop; do not attempt to simulate or infer browser execution
using `shell`, `http`, or any substitute. This does not prevent useful HTTP context
tests or step 3's deterministic HTTP proof of exploitability.

Execution rule: substitute the real target and real parameter values before
running commands. Never write literal placeholder payloads such as
`<PAYLOAD>` to files — write the exact payload used. If candidate/input identity
or authorization is unclear, use `ask_user` once before proceeding.
Uncertain parser context calls for hypotheses and discriminating tests under the
checkpoint, not an automatic stop or an invented surrounding source.

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
  below. For step 3, select or adapt `PHASE 2 — CONTEXT-SPECIFIC CONFIRMATION`
  examples for the observed context and any evidenced parser transition.
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

**Locate reflection → Identify context → Identify parser boundaries → Analyze
transformations → Select probe → Compare responses → Evaluate evidence.**
For each relevant occurrence of this candidate's input, retain the response type,
surrounding prefix/suffix and enclosing element/attribute or script type/loading
mode. One input can reach several contexts; a neutralized occurrence does not
settle another. Separate the outer response parser from the inner language context.

Model only evidenced layers: submitted value → encoded request → server/template
transformations → returned representation → relevant parser/DOM consumer. Request
URL/form decoding, HTML entities, JS escapes and later client decoding are different
operations; do not assume a second decode or a sanitizer's implementation from one
output. Mark uncertain layers as hypotheses. Add layers only when observations
make them relevant, rather than performing every encoding check for every Candidate.
Verify method, input binding, session and response identity before treating a missing
reflection as neutralization; a redirect/login page or wrong source is an invalid
comparison, not a negative XSS test.

The correct proof payload depends entirely on where the value lands. Reuse
adequate existing observations. If propagation or context remains unresolved,
send a request with the **detection marker** from `payloads.txt`'s
`PHASE 1 — CONTEXT DETECTION` section — a plain, non-executing text string
— and inspect exactly how it is embedded in the response before choosing a
confirmation payload. Use a metacharacter probe only for unresolved encoding or
transformation uncertainty; adequate existing evidence needs no extra detection
request:

Prioritize captured HTTP observations from the target over payload examples
or local resource contents. Identify the reflection context and encoding from
the actual response before choosing further probes; partial context may support
competing hypotheses without identifying the entire HTML/JavaScript source. Reflection of an
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
- **HTML attribute context** — the marker sits inside a double-quoted,
  single-quoted or unquoted attribute value; their delimiters differ.
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
  Modern browsers no longer support `expression()`-style CSS execution. Do not
  repeatedly test that unsupported path or an execution path already discredited
  by the observations. A distinct HTML breakout through the enclosing attribute
  or `</style>` boundary may still be supported by the captured syntax and
  transformations; assess that hypothesis with a context-appropriate test rather
  than infer it is inert from CSS placement alone. Interpret the returned HTML
  under step 3's execution-evidence requirements and stop when no useful test
  remains, without forcing a negative result.
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

**Parser boundaries — outer to inner.** Derive this path from captured source;
the label `js-string` alone does not identify the enclosing parser:

| Observed placement | Parser path and boundary to assess | Limit / falsifier |
|---|---|---|
| HTML text / attribute | HTML tokenization; an attribute's delimiter precedes any decoded value or URL interpretation. | Character references become data, not new markup or attribute delimiters in that same pass. Inspect any evidenced later consumer separately. |
| Inline script, including a JS string or template literal | HTML script-data tokenization → JS lexing for an executable script type; distinguish quote, backtick/interpolation and enclosing element boundaries. | JS quote/backslash escaping can block a literal breakout without neutralizing the enclosing HTML boundary. A non-executable script type is not execution proof. |
| External JavaScript loaded as script | JS lexing of the fetched resource, without an enclosing HTML script-data parser for its body. | An HTML end tag inside its JS string does not close the loading page's script element. Verify loading/consumer evidence; do not invent a loader. |
| Event-handler attribute | HTML attribute tokenization → character-reference decoding → JS handler parsing. | Decoded quotes can affect JS without closing the HTML attribute; execution still needs its actual trigger and policy. |
| JSON response / embedded data block | Standalone JSON is data without an evidenced execution sink. A data block in an HTML script element still has an outer HTML boundary. | JSON parsing/readback is not execution. Trace any observed later consumer; do not transfer a JSON API assessment to a separate sink. |
| DOM sink | Observed source → transformations → insertion/evaluation API → that API's parser. | `textContent`, HTML fragment insertion and JS evaluation differ; a source path or inserted script tag alone is not observed execution. |

For a `text/html` inline script, an appropriate literal `</script>` end tag can
terminate the element even inside a JS string, template literal or comment.
Inspect the actual opening element, script type, surrounding tokenizer state and
suffix: HTML script escaped/double-escaped states can change that interpretation.
Do not infer a boundary from a substring alone. In script data, `&lt;` is not
HTML-decoded into `<`; JS source `\u003C` or `<\/script>` likewise is not a literal
HTML end tag. Decoding JS string values yourself must not invent an earlier HTML
delimiter. A later evidenced reparse is a separate source-to-sink question.

Choose a probe only for a remaining boundary/transform hypothesis. Compare a
benign control with a minimal change to the uncertain delimiter or escape character
(including backslash), predicting returned structure before sending. An inert
structural marker can distinguish parsers without attempting execution. Compare
complete responses under the same request/session conditions; rule out only the
hypothesis whose required boundary is neutralized there. Filtering, a syntax error
or one escaped payload does not rule out other supported boundaries. Unresolved
transformations/consumer context remain `insufficient-evidence`; valid injection
with a necessary unobserved browser step remains `browser-required` under step 3.

### Context traces — synthetic source and responses, not session evidence

Optional worked contrasts are available through
`read_payloads(skill="cross-site-scripting", file="context-reasoning.md")`.
Consult the relevant contrast only when it helps resolve the current parser or
transformation question; no extra resource read or example sequence is required.
Use only captured bytes for incomplete observations; name missing context, never
reconstruct it or use an inadmissible capture as terminal proof. Earlier phases'
observations can guide planning but do not become owned proof for this attempt.

## 3. Confirm with the minimum payload for that context

Select or adapt a harmless **execution marker** from `payloads.txt`'s
`PHASE 2 — CONTEXT-SPECIFIC CONFIRMATION` examples for the observed context and
supported parser transition. These are examples, not a fixed selection algorithm;
compose only boundaries justified by captured syntax and transformations. Inspect
the marker expression too: quote escaping can invalidate a newly introduced script.
An equivalent quote-free marker may use a fresh decimal integer as `document.title`;
record the exact expected title string. Do not use a maximal bypass chain; one
result supported by sufficient evidence is enough for the Candidate.
This is an attempt to execute JavaScript, unlike the inert step-2 detection
marker. Its safety property is the harmless, self-contained action
(`document.title`); whether it can execute depends on the returned code/context.

For each chosen probe, state the hypothesis, expected observation if true, expected
observation if false, and why that difference resolves a current uncertainty. A
compact prediction in existing notes/proof suffices; no new workflow object is
needed. Prefer an existing observation or a small inert structural test when it
answers the question. If the alternatives predict the same visible result, choose
a better discriminator or state the observation limit instead of sending variants.

**Returned-code checkpoint — after a response, before a result.**

**Submitted input → Actual returned bytes → Parser context → Effective code → Syntax/trigger assessment → Evidence decision.**

1. Read the retained HTTP observation, including Content-Type, capture flags and
   the relevant prefix/suffix. Compare the submitted input with actual returned
   bytes for escaping, encoding, sanitization and filtering. Missing bytes remain
   unknown; the intended payload cannot replace the response.
2. Follow the evidenced parser path to the effective code the JavaScript parser
   receives. HTML script-data parsing and JavaScript parsing are separate steps;
   event-handler attributes undergo HTML character-reference decoding first.
   Preserve backslashes that survive those steps. Do not manually unescape JS
   source or invent another decoding pass. Include the complete script/handler
   and relevant surrounding syntax, not just the marker expression.
   Assess each resulting executable unit separately: a syntax error in the
   terminated original script does not establish an error in a new script/handler.
   Once a boundary is actually crossed, rebuild the context model for the new unit.
   Carry forward transformations visible in its bytes, but do not carry the old
   delimiter requirement into the new context. Before repairing the old literal or
   abandoning the path, consider whether a simpler harmless expression avoids the
   transformed syntax in that new context. This applies to any evidenced boundary,
   not a particular delimiter or payload.
3. Assess effective-code syntax, executable placement, trigger requirements and
   enforced CSP/embedding restrictions separately. A new HTML element can exist
   while its JavaScript is invalid. Invalid returned code cannot support
   `confirmed`, even when the original boundary was crossed. An optional offline
   syntax check establishes syntax only, never browser execution; no mandatory
   checker or substitute browser capability is introduced by this checkpoint.
4. Record a compact trace in the existing proof and assessment/notes: submitted
   input, observation ID and returned excerpt, parser path, effective code,
   syntax/trigger/policy assessment, and evidence decision. Distinguish structural
   breakout, valid JavaScript, evidence of exploitability under this playbook,
   and actually observed browser execution. Reconcile these same facts before
   `record_result` and `confirm_finding`; do not replace transformed code with
   its intended form in the report.

**Before ending validation**, summarize in existing assessment/notes the tested
hypothesis, predicted versus observed result with observation IDs, what was ruled
out, and any essential distinct hypothesis still supported by observations. A
failed payload or neutralized technique does not alone refute its whole Candidate.
For a remaining hypothesis, identify a minimal non-destructive discriminating test
and check scope, permission and remaining resources. If such a useful test is
available, continue the owned attempt without asking the user to repeat the same
goal; existing denials and operator limits still apply. If continuation is not
possible or useful, record the actual stop reason and the matching unresolved or
bounded negative outcome, not a negative merely to finish the turn.

Distinct hypotheses predict different observable outcomes from evidenced context;
equivalent variants add no information. Do not enumerate every payload or parser
boundary. Minimum testing means minimal evidence, not minimal reasoning. Sufficient
positive evidence needs no extra probes. A negative may close its bounded
Candidate/sink/hypothesis only after the essential supported alternatives within
that scope are resolved; it does not exclude other separately evidenced sinks.
Keep the assigned scope fixed: do not narrow the original Candidate hypothesis
after a failed technique just to declare `completed_attempt: true`.
Follow the existing Candidate identity/association rules for a different sink.

Synthetic returned-code contrasts (not target or browser-execution evidence):

| Returned context | Effective code / decision |
|---|---|
| New inline script containing `document.title=\'proof\'` | The backslashes remain outside a JS string; invalid syntax, despite the new script element. |
| Double-quoted handler attribute containing `document.title=\'proof\'` | HTML does not remove those backslashes; the handler has invalid JS syntax. |
| Handler attribute containing `document.title=&#39;proof&#39;` | Attribute decoding yields `document.title='proof'`; valid syntax still needs its actual trigger and applicable policy. |
| Returned marker expression `document.title=731942` | A possible quote-free adaptation when observed quote escaping justifies it; syntax alone does not establish execution. |

After any non-confirming probe, including invalid syntax, valid but inert code,
neutralized output or an inconclusive response, compare observation with prediction
and reassess the supported hypotheses under the decision checkpoint. Classify the
failure only as far as the observation supports; HTTP silence is not a diagnosis:

| Observation / failure mechanism | What remains to resolve before deciding |
|---|---|
| Input absent or sink not reached | Check effective request, source/sink and response identity; distinguish an invalid comparison from a tested propagation failure. |
| Encoded, escaped, sanitized or removed | Identify changed bytes at the relevant parser; rule out only the tested boundary/technique. |
| Valid but inert data/code | Identify the containing literal, inert element, uncalled function or unreachable branch; syntax validity does not establish a runnable path. |
| Boundary crossed, new code invalid | Preserve structural success; reassess the new context and simplify/adapt its expression before abandoning that hypothesis. |
| Runnable structure, trigger unobserved | Name the event, call, navigation or client branch needed; missing browser-only proof may require `browser-required`. |
| Enforced CSP or embedding restriction | Establish that it applies to this unit; report-only is not enforcement. Do not infer an upstream block or bypass it. |
| HTTP cannot distinguish the possibilities | State the missing fact and whether another permitted HTTP observation can resolve it; otherwise select the applicable unresolved outcome. |

Identify any changed bytes and why the effective code or execution mechanism fails.
When a useful in-scope hypothesis remains within permissions and budget, adapt the
harmless marker to that evidence,
predict the returned structure/effective code and confirmation conditions before
sending, then apply this entire checkpoint to the new observation. Changing tags
alone does not repair an expression broken by the same transformation. Preserve
failed variants as adverse evidence. Do not demand another probe when evidence
already suffices or no useful authorized test remains; do not spray variants or
bypass an upstream control. An invalid variant alone is neither `confirmed` nor
`not-confirmed`: unresolved syntax/interpretation or absent usable proof is
`insufficient-evidence`; a viable path with necessary unavailable browser proof is
`browser-required`. A negative still needs a completed bounded test and evidence
adequately ruling out its relevant hypothesis, not one failed payload.

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

For `browser-required`, name the specific missing browser-only fact (such as a
trigger or client-side branch). A `js-string` label or browser absence alone does
not settle a question that an available permitted HTTP test can discriminate.
Use such a test when useful; do not require extra HTTP when only unavailable
browser behavior remains or sufficient evidence already exists.

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

**DOM trace (synthetic source).** Source `location.search` → transformation
`new URLSearchParams(location.search).get('q')` → sink `panel.innerHTML = value`
→ fragment insertion/DOM mutation → execution evidence still missing. Captured
source does not prove the branch ran. Ordinary innerHTML script insertion is not
execution; document parsing differs. `textContent` keeps markup data at that sink,
without settling other paths. Reassess the insertion API/transformations; a remaining
browser-execution question requires `browser-required`.

**Stored trace (simulated responses).** Acceptance `200 {"saved":true}` → reported
write, not persistence → independent readback returns the marker → persistence
at that time, still no rendering from JSON → authorized, declared rendering response
→ step 3 execution evidence → separately authorized cleanup and verification.
Eligible rendering can supply readback plus deterministic HTTP proof; a SPA/trigger
gap stays `browser-required`. Keep isolation, audience, ownership and mutation
bookkeeping; if cleanup cannot be verified, report the limitation.

**Response policy and triggers (synthetic contrasts).** A script string in an
`application/json` or `text/plain` response is not HTML proof; a downstream renderer
is a separate sink. An ordinary `text/html` fragment can meet step 3's deterministic
HTTP proof conditions. Effective enforced `Content-Security-Policy: script-src 'none'`
blocks the inline marker; `Content-Security-Policy-Report-Only` does not enforce
blocking. Inspect applicable policies and embedding/sandbox context without bypasses.
An image handler needs its error event; a button needs its interaction. HTTP handler
reflection or a missing title change proves neither trigger success nor failure.
Missing browser proof stays `browser-required`; do not simulate an event.
Reference: [CSP enforcement and reporting](https://www.w3.org/TR/CSP3/#framework-policy).

**3a. WAF / rate-limiting check.** If a probe is clearly intercepted by an
upstream WAF, rate limiter, CAPTCHA, or equivalent challenge before reaching
application logic, record the candidate as `blocked`.

Do not classify an ordinary application response such as a normal `401` or
`403` as `blocked` merely from the status code. There must be evidence that
an upstream control intercepted the request before application handling —
otherwise evaluate the application response under the context and bounded-negative
rules. Missing required authentication or a login page does not test the claimed
rendering path; report that limitation rather than close the XSS hypothesis.

Do not retry blocked probes with encoding tricks, alternate payloads, or
filter-bypass techniques. That is outside this skill's scope.

If the response shows a clear deterministic transformation, such as removing
exactly one trailing character, a bounded same-context adaptation can test that
specific hypothesis. For trailing-character removal, append one inert trailing
character to the same execution marker and inspect whether the returned payload
is now complete. Further adaptation is appropriate when existing or new observations
support a different meaningful prediction; a prior close variant is not a stopping rule.
Confirm only if the returned complete executable syntax and context meet the
existing deterministic HTTP proof threshold; otherwise retain browser-required
when execution remains browser-dependent.

Choose adaptations from the observed context and transformation, such as matching
the actual quote style, or an event-handler-based marker for HTML body/attribute
contexts when `<script>` specifically appears stripped while other tags/attributes
pass through unescaped. Use `payloads.txt` as examples, not a sequence to exhaust.
Avoid redundant equivalent variants; each adaptation must test a meaningful
remaining hypothesis. This remains context-specific validation, not a fuzzing or
filter-bypass phase: encoding tricks, case obfuscation or payload fragmentation
aimed at evading a filter or WAF remain out of scope per step 3a.
When evidence suffices or no useful authorized test remains, use step 5:
`not-confirmed` needs a completed bounded test and usable proof; missing browser
execution remains `browser-required`, and incomplete testing or missing
sources/proof remains `insufficient-evidence`. An unobserved effect is not a
tested negative.

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

If step 3 remains inconclusive, reassess under the decision checkpoint. Stop
when no useful authorized test remains or execution is blocked, and use step 5's
outcome rules. Distinguish a completed bounded negative from missing browser
execution, incomplete testing or unavailable proof.

## 5. Record the validation evidence

Immediately before recording any terminal XSS assessment, verify the actual
captured response bytes and surrounding context, including every delimiter
needed by the claimed executable syntax. Compare the returned syntax with the
request; do not substitute the intended payload or an LLM-reconstructed HTML
element for the captured response. An incomplete executable payload must not
be confirmed merely from raw reflection in text/html.
Revisit step 3's returned-code trace here: a complete element with invalid
effective JavaScript is also inadmissible as confirmation proof. Evidence
registration checks provenance/integrity, not the correctness of this XSS
assessment; the Agent must reconcile syntax, trigger and policy before submission.
Raw response excerpts must preserve the retained observation representation,
including HTML entities, backslashes and existing redaction. Copy from the owned
observation; do not silently replace entities with decoded characters or reconstruct
source from the intended payload. Label any decoded/effective-code representation
separately as analysis, alongside its raw excerpt and observation ID.

For example, a complete, untruncated response ending in
`<script>document.title='proof'</script` lacks the final `>`. Do not call it a
complete executable element because the intended request contained that
character. Use a bounded same-context compensating adaptation under step 3
when deterministic trailing-character removal supports that test, then inspect
its actual response. If complete executable syntax or another permitted
confirmation condition is not established, do not claim confirmed execution.
Deterministic HTTP-based confirmation remains sufficient when step 3's context
and proof conditions hold; a browser is not universally required.

Keep a compact observation ledger linking detection marker, execution marker
and adaptations actually tested to their effective requests, observation
IDs, HTTP statuses, body excerpts and capture flags. In existing assessment/notes,
record the original sink, parser path, transformations and which hypotheses were
ruled out or remain unresolved; structural injection is not observed execution.
The runtime HTTP evidence envelope supplies a redacted effective request preview; if
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
  reliably from HTTP-level evidence alone must be recorded as `browser-required`.
  A JS-string origin is not itself a veto: apply step 3 to the actual resulting
  executable unit. Invalid code, inert placement, an unestablished required trigger
  or an applicable blocking policy cannot satisfy the deterministic HTTP exception.
- `not-confirmed` — an applicable bounded test completed with usable proof
  adequately ruling out the relevant execution hypothesis in the observed sink,
  including input fully encoded/neutralized there. Inconclusive observations
  alone do not complete a negative test. State the tested scope and why no essential
  supported hypothesis within it remains unresolved; one failed technique, several
  equivalent variants, an unobserved execution or a wish to stop is insufficient.
  Do not require disproving every imaginable XSS vector. Budget/permission limits
  with essential questions still open require the applicable unresolved outcome.
- `blocked` — an upstream WAF, rate limiter, CAPTCHA, or equivalent control
  intercepted the probe before application logic could be evaluated (step
  3a); the application itself was never actually tested.
- `browser-required` — the response or source/sink analysis is
  consistent with XSS, but actual execution depends on browser behavior
  that cannot be established reliably with the available HTTP-level
  evidence, and no browser-execution capability is available in this
  runtime to close that gap (see "Workflow at a glance").
- `insufficient-evidence` — necessary context, transformations or test
  interpretation remain unresolved, or no usable primary observations or required
  proof are available to support a terminal assessment. Omit unavailable references,
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

Choose the stop reason from the evidence and remaining useful tests before
recording the outcome; recording a result is not itself a reason to stop probing.
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
