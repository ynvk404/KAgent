---
name: web-input-analysis
description: >
  Analyze a web-enumeration inventory to identify which endpoints/parameters
  are worth testing and for what likely vulnerability class, using context and
  passive evidence first, with minimal non-destructive behavioral signals only
  when context is insufficient — not exploitation. Produces a prioritized
  candidate list for enabled validation skills or an explicit unsupported
  class. Use when an endpoint inventory is available; a direct concrete
  validation request may bypass this analysis step.
stage: analysis
triggers:
  strong:
    - input analysis
    - web input analysis
    - triage input candidates
    - suspected vulnerability class
    - prioritize testing candidates
  weak:
    - candidate
    - context
    - signal
    - reflected input
    - object identifier
    - which parameter
candidate-classes: []
completion-artifact: artifacts/web-input-analysis/{target}/candidates.md
requires:
  - web-enumeration
allowed-tools:
  - shell
  - http
  - file_write
  - workflow
---

# Web input analysis playbook

You have been handed an inventory that `web-enumeration` built. This phase
answers "of everything found, what's actually worth testing, and for which
bug class?" It does not exploit anything and does not produce findings.
That belongs to `sql-injection`, `cross-site-scripting`, `access-control`,
or (for classes without an active skill yet) is deferred entirely.

**Objective:** turn an endpoint/parameter inventory into a small, prioritized
list of candidate inputs, each with a reasoned suspected vulnerability class,
using context and minimal non-destructive signal-gathering — not proof.

Prefer the built-in `http` tool with `phase: validation` for bounded signal
probes. Use `curl` only when the native tool cannot express a necessary
request detail; shell requests do not enforce target-origin scope. This skill does not need
scanners, and it does not need exploitation frameworks (`sqlmap`, `nuclei`,
etc.) — if you find yourself reaching for one, you've drifted into a
vulnerability-specific skill's territory.

Execution rule: substitute real values before running commands. Never write
literal placeholders to files. If the inventory or target is unclear, ask
once before proceeding.

## Target identifier

`<target>` below always refers to the identifier derived by the convention
defined in `recon/SKILL.md` ("Target identifier convention"). Reuse that
identifier exactly — do not re-derive it differently here.

## Preconditions

Before starting, you should have:

- `artifacts/web-enumeration/<target>/inventory.md` (same target identifier as `recon`
  and `web-enumeration`);
- confirmation the target is still in scope.

If the inventory doesn't exist or looks stale, go back to `web-enumeration`
rather than re-deriving endpoints here.

## 1. Load and triage the inventory

Read every entry. Drop entries that are clearly not worth analyzing:

- static assets with no parameters (images, fonts, plain CSS/JS with no
  route clues);
- endpoints with no input surface at all (no query, body, header, cookie,
  or path parameter).

Everything else becomes an input to triage, not automatically a candidate.
Parameter names and HTTP methods are context hints only. Do not create a
Candidate until the inventory or a bounded observation shows that the server
reads or uses that specific input.

## 2. Classify context for each candidate

For each parameter, determine where and how it may be used, based on what
`web-enumeration` observed (request schema, route source, auth state, and
response context). Treat names and locations as hypotheses, not evidence that
the server consumes a value:

- **Reflected in HTML/JS output** — parameter value appears to influence
  rendered content (search boxes, error messages, "welcome back {name}").
- **Object/resource identifier** — numeric ID, UUID, slug, or filename that
  selects a specific record or file (`/api/orders/123`, `/files/report.pdf`).
- **Query/filter-like** — parameter name/shape suggests it feeds a backend
  query or filter (`sort`, `search`, `q`, `filter`, `category`).
- **Redirect/URL-like** — parameter takes a URL, path, or hostname
  (`redirect_uri`, `next`, `callback`, `url`).
- **File/path-like** — parameter looks like a filename or path
  (`file`, `path`, `template`, `page`).
- **State-changing action** — POST/PUT/DELETE that creates, modifies, or
  removes something, especially referencing another user's or another
  object's identifier.
- **Structural/serialization-heavy** — JSON/XML bodies, GraphQL queries,
  file uploads.
- **Document-query/operator-like** — a JSON value changes from a scalar to an
  object/operator shape, or an observed filter is passed directly to a
  document database.
- **Command/argument-like** — a value is plausibly used as a server-side
  program argument, process option, hostname, archive/conversion input, or
  diagnostic command parameter.
- **Token/policy-like** — JWT-bearing authorization input, CORS request/response
  policy, or another security-control input whose enforcement can be tested
  independently of business data.

Record the context alongside each input. A parameter can have more than one
context (for example, an identifier that also appears in an error response).
Before creating a Candidate, establish controllability from existing evidence
or one safe, single-value baseline comparison. Keep all other request fields
unchanged. If the response does not show a repeatable input-related difference,
record `control not observed` or the remaining ambiguity and do not infer use
from the parameter name. This check does not need to identify a code sink.

For a reflection hypothesis, record where the value appears: HTML text,
attribute, script, URL, JSON, or a non-rendered response. A marker in raw JSON
or a response the browser does not render is not an XSS candidate by itself.
If client-side rendering is unknown, record that ambiguity and stop short of
an XSS Candidate.

## 3. Light signal-gathering, in order of intrusiveness (non-destructive)

Try to classify each candidate from context alone first (step 2 + inventory
notes). Only reach for the steps below when context isn't enough to decide
whether — and how — a candidate is worth prioritizing. Each step below is
more intrusive than the last; stop as soon as you have enough signal.

**Tier 1 — passive, no new requests.** Re-read what `web-enumeration` already
recorded: observed response, whether the value appeared in the body, auth
state, sibling endpoints. Most candidates should be classifiable from this
alone.

**Tier 2 — harmless marker, at most once per input.** If context alone
doesn't tell you whether a value is reflected, send one request with a
unique, inert marker using the scoped `http` tool and its permission gate.
Check whether it comes back and, if so, whether it is in HTML text, an
attribute, script, URL, JSON, or a non-rendered response. Keep the method,
endpoint, content type, and all other values at the known-good baseline. Do not
send shell-based HTTP requests that bypass the runtime scope and permission
checks.

This tells you *whether reflection happens*, not whether it's exploitable.

**Tier 3 — minimal value-change probe, only if tiers 1–2 leave the input
unclassifiable, and at most one probe per parameter.** Tier 3 exists solely to
help you classify and prioritize a candidate — it is never a way to "weakly
confirm" that a vulnerability exists. A different response shape tells you a
parameter is worth handing to `sql-injection` with higher confidence; it does
not tell you SQLi is present, and it must not be written up or treated as
partial evidence of a finding. Use this tier only to resolve genuine
ambiguity, compare with a known-good baseline, and use the scoped `http` tool
with its current permission decision. A minimal syntax perturbation may be
used for a query/filter input when the exact request is permitted. Do not use
boolean bypasses, time delays, UNION payloads, NoSQL operators to bypass
authentication, another user's session or object, SSRF impact checks, command
execution, or an XSS execution payload here. Never probe a state-changing
request unless the single change is known to be non-mutating and permitted.

Rules across all tiers:

- Prefer stopping at Tier 1 or 2. Reaching Tier 3 should be the exception,
  not the routine — if you're using it on most candidates, you're probably
  under-using the context already in the inventory.
- One value change at a time, always against a baseline, never chained into
  a working exploit (no SQL boolean bypass, payload escalation, session
  swapping, SSRF impact validation, command execution, XSS execution, or data
  extraction).
- A permission prompt approves only the proposed request. It does not supply
  missing intent, authorize another origin, or turn a state-changing probe
  into a non-destructive one.
- Never record response bodies containing another user's real data beyond
  noting "returned data" vs "did not" — do not copy PII/secrets into the
  candidate file.
- If a bounded request unexpectedly exposes sensitive data or an unanticipated
  effect, stop. Do not fetch or copy additional data. Keep only the minimum
  redacted observation, leave confirmation to the dedicated validator, and do
  not claim a finding here.

If context already supports a useful hypothesis, skip probing — do not probe
just to probe. A numeric ID, a reflected string, a status code, or an error
message alone is not that evidence.

## 4. Map signals to a suspected vulnerability class

For each candidate, form a reasoned suspicion, not a conclusion:

| Context / signal | Suspected class |
|---|---|
| Controllable value appears in an HTML rendering context with encoding or DOM handling that remains unclear | `cross-site-scripting`; raw JSON reflection alone is not a candidate |
| Query/filter param + syntax-sensitive response (error/size/timing shift) | `sql-injection` |
| Object identifier on an authenticated object route, with observed evidence that the input selects an in-scope object and the ownership boundary remains unobserved | `access-control`; an ID/name or absent client-side check alone is insufficient |
| State-changing action whose documented request lets the caller select an object while its authorization boundary remains unclear | `access-control`; an HTTP method or identifier name alone is insufficient, and do not submit or swap cross-user IDs here |
| URL-fetch, image-import, webhook, or callback parameter with server-side fetch evidence | `ssrf`; an ordinary browser redirect alone is not SSRF |
| Reflected template expression evaluated by the server | `ssti` |
| Login, reset, MFA, logout, or session-lifecycle property | `authentication` |
| State-changing request using ambient browser credentials with a suspected missing defense | `csrf` |
| JSON query/filter input accepts an object/operator shape where a scalar is expected, or shows a repeatable type-sensitive query difference | `nosql-injection`; **input:** a concrete query/filter parameter or JSON/form-body field. Create a Candidate only for that field plus an observed query/operator signal, not merely because the endpoint uses JSON or MongoDB |
| Input plausibly reaches a server-side process/argument boundary and syntax or output behavior changes with a harmless marker | `command-injection`; **input:** the concrete query, body, header, or path field plausibly passed to a process/argument boundary. Create a Candidate only with that signal; do not infer command execution from a generic server error |
| XML body/document field is parsed with DTD or entity-processing signals | `xxe`; **input:** a concrete XML request body or uploaded XML document field. Create a Candidate for that input, but do not infer external-entity resolution from XML parsing or a `DOCTYPE` alone |
| File/path/filename input appears to select a server-side file and normalization or relative-path handling is relevant | `path-traversal`; **input:** a path-bearing route parameter, query parameter, or body field. Create a Candidate when a server-side file-selection/path-resolution signal exists; a filename parameter alone is not enough |
| Multipart/file field reaches an upload handler with a concrete validation, storage, naming, or retrieval concern | `file-upload`; **input:** the multipart file field and, when relevant, its filename/metadata. Create a Candidate for an observed policy concern; do not infer execution or public access merely because upload exists |
| JWT-bearing input shows a concrete signature, algorithm, expiry, issuer, audience, or claim-enforcement concern | `jwt-misconfiguration`; **input:** an Authorization header, cookie, or token parameter/body field known to carry a JWT. Do not create this class for opaque sessions or generic login failures, and never copy raw token material into signals |
| Read-only endpoint returns a concrete unsafe CORS policy signal such as untrusted Origin reflection or a credentialed cross-origin header combination | `cors-misconfiguration`; **input:** compare the request `Origin` header with response `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` headers. Do not infer browser-readable protected data from a permissive header alone |
| Redirect parameter produces redirect-only behavior without evidence of a server-side fetch | `open-redirect`; **input:** a concrete URL/return-destination field such as `next`, `return_url`, or `redirect_uri`, with observed off-origin `Location` behavior. Do not confuse it with `ssrf` |

These are signal examples, not a frozen list of available validators. The
loaded skill registry is the source of truth: `workflow(record_candidate)`
returns `supported` and `recommended_skills` from enabled validation skill
metadata. If no validator handles a suspected class, retain the observation
with `status: deferred` and explain the missing capability. Do not call a
validator from this analysis skill. Do not invent a workflow for a
vulnerability class that doesn't have a skill yet.

A candidate can map to more than one suspected class; list all of them with
independent confidence.

This phase gathers only bounded signals. Stop and hand off once the input is
controllable and a plausible class hypothesis has evidence. Do not run a
dedicated validator's payload set or try to prove exploitability here.

## 5. Prioritize

Rank candidates using, roughly:

1. **Confidence** — how strong is the signal (context-only < single
   behavioral signal < multiple corroborating signals).
2. **Reachability/auth** — unauthenticated and low-friction endpoints first.
3. **Likely impact** — data exposure, account takeover, or state changes
   outrank cosmetic issues.

Don't over-engineer scoring — a simple High/Medium/Low per candidate is
enough for the next skill to decide where to spend effort.

## 6. Build the candidate list

In a whole-target objective, account for every structured input discovered by
enumeration. For each input call `workflow(action="set_input_disposition",
input_id=..., disposition=...)`: use `analyzed` after triage, `dropped` with a
short reason when it is out of scope for this analysis, or `blocked` with the
current dependency when analysis cannot proceed. A blocked input remains an
objective blocker and must not be reported as complete. If a blocker is later
resolved, set the same input back to `pending` and analyze it in this objective.

For every candidate strong enough to include in the list, also call
`workflow(action="record_candidate", source_skill="web-input-analysis", ...)`
with its canonical `candidate_class`, method, endpoint, parameter/location,
short signals, and references to the baseline request or auth context when
available. When known, also pass `content_type` and a compact
`request_template` with `{INJECTION_POINT}` in the tested field. Reuse the
inventory's method, endpoint, parameter, and content type through `input_id`
when they are omitted. Store references and sanitized request skeletons, not
raw request/response bodies or credentials. The returned
Candidate ID is the handoff key for the validation skill. The workflow tool
deduplicates the same semantic target/method/endpoint/input/class tuple, so do
not manufacture alternate IDs. When an input record exists, pass its
`input_id` to link the candidate to that input. Weak/noisy observations that do
not meet the candidate-list bar must not be recorded. Inspect `supported` and
`recommended_skills` in the tool result before naming the next skill. For
multiple independent suspected classes, record one Candidate per class and
retain each returned ID; do not collapse them into one result.

Candidate `signals` must describe the observations exactly. If paired probes
produce identical status, size, and content markers, record them as
`no differential observed`; never summarize them as TRUE returning rows and
FALSE returning none. Signal gathering here is not confirmation, and a later
validator must not inherit a contradicted conclusion from free-form prose.

Write `artifacts/web-input-analysis/<target>/candidates.md`, using the same target
identifier as `recon` and `web-enumeration`. One entry per candidate:

```
- endpoint: GET /product
  parameter: id
  location: query
  context: object identifier
  signal: syntax punctuation changed the response shape against the baseline
  suspected_class: sql-injection
  confidence: medium
  rationale: syntax-sensitive request behavior observed once; context supports
    a server-side query hypothesis, not yet confirmed
  recommended_next_skill: sql-injection

- endpoint: GET /api/orders/{id}
  parameter: id
  location: path
  context: object identifier, state-changing sibling endpoints exist (PUT/DELETE)
  signal: authenticated inventory documents an object lookup; owner scoping was
    not observable during passive analysis
  suspected_class: access-control
  confidence: low
  rationale: object ownership behavior remains unknown; no IDs or sessions were
    swapped during analysis
  recommended_next_skill: access-control

- endpoint: GET /redirect
  parameter: next
  location: query
  context: redirect/URL-like
  signal: baseline behavior indicates a redirect and the destination parameter
    controls the returned Location
  suspected_class: open-redirect
  confidence: medium
  rationale: redirect-only sink with no server-side fetch evidence
  recommended_next_skill: open-redirect
```

Include `content_type`, `request_template`, `baseline_request_ref`, and
`auth_context_ref` when available. Do not invent a request template for path,
header, cookie, multipart, or nested JSON inputs when the representation is
ambiguous; carry the known content type and references and state the
limitation.

Do not include a `poc` or `exploit` field — that's the vulnerability
skill's output, not this one's.

## 7. Handoff

Summarize at the top of the candidate file:

- total candidates, grouped by suspected class;
- how many are high/medium/low confidence;
- how many were deferred (no active skill);
- recommended order to hand off supported candidates by their returned
  `recommended_skills`; list unsupported candidates separately.

Hand off only the candidates relevant to each skill — don't hand a whole
inventory back to a vulnerability skill and let it re-triage from scratch.
The structured Candidate is the authoritative handoff; `candidates.md` remains
the operator-readable analysis artifact.

## Stop conditions

Stop analysis when:

- every inventory entry has been triaged (classified or explicitly dropped);
- candidates worth testing have context and, where useful, one light signal;
- no probe has escalated into an actual exploit or proof;
- the candidate list is prioritized and ready to route to the enabled
  matching validators, with unsupported classes clearly flagged.

Then call `workflow(action="complete_skill",
skill_name="web-input-analysis",
artifact_ref="artifacts/web-input-analysis/<target>/candidates.md",
current_phase="validation")`. This records
workflow progress independently of the conversational summary.

If a whole-target input remains `blocked`, leave the phase incomplete, explain
the dependency, and let the runtime report the objective as blocked. Resume the
same input in the same objective after the dependency is resolved.

Do not turn signal-gathering into confirmation. Do not chain probes into a
working payload. Do not decide a finding exists here — that determination,
with PoC and impact, belongs entirely to the vulnerability-specific skill.
