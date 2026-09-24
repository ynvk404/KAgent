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

Default to `curl` and the built-in `http` tool. This skill does not need
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

- `web-enumeration/<target>/inventory.md` (same target identifier as `recon`
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

Everything else becomes a candidate to classify.

## 2. Classify context for each candidate

For each parameter, determine where and how it's likely used, based on what
`web-enumeration` already observed (naming, location, response, source) —
not new probing yet:

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

Record the context alongside each candidate. A parameter can have more than
one context (e.g. an ID that's also reflected in an error message).

## 3. Light signal-gathering, in order of intrusiveness (non-destructive)

Try to classify each candidate from context alone first (step 2 + inventory
notes). Only reach for the steps below when context isn't enough to decide
whether — and how — a candidate is worth prioritizing. Each step below is
more intrusive than the last; stop as soon as you have enough signal.

**Tier 1 — passive, no new requests.** Re-read what `web-enumeration` already
recorded: observed response, whether the value appeared in the body, auth
state, sibling endpoints. Most candidates should be classifiable from this
alone.

**Tier 2 — harmless marker, at most once per candidate.** If context alone
doesn't tell you whether a value is reflected, send one request with a
unique, inert marker and check if/how it comes back (unmodified, HTML-encoded,
stripped, absent):

```sh
TARGET="http://localhost:3000"  # replace with the real target

curl -ksS "$TARGET/search?q=pf_marker_$(date +%s)" | grep -o 'pf_marker_[0-9]*'
```

This tells you *whether reflection happens*, not whether it's exploitable.

**Tier 3 — minimal value-change probe, only if tiers 1–2 leave the candidate
unclassifiable, and at most one probe per parameter.** Tier 3 exists solely to
help you classify and prioritize a candidate — it is never a way to "weakly
confirm" that a vulnerability exists. A different response shape tells you a
parameter is worth handing to `sql-injection` with higher confidence; it does
not tell you SQLi is present, and it must not be written up or treated as
partial evidence of a finding. Use this tier only to resolve genuine
ambiguity — e.g. context suggests a query/filter parameter but you can't tell
if it's syntax-sensitive at all, or an identifier's ownership scoping is
genuinely unclear from the inventory. Compare against a known-good baseline
in the same request pair:

```sh
TARGET="http://localhost:3000"

# Baseline vs. one syntax-sensitivity probe — only if still needed after
# tiers 1-2:
curl -ksS -o /dev/null -w '%{http_code} %{size_download}\n' \
  --max-time 5 "$TARGET/product?id=1"
curl -ksS -o /dev/null -w '%{http_code} %{size_download}\n' \
  --max-time 5 "$TARGET/product?id=1'"

# Ownership check — only if inventory genuinely doesn't show whether the
# endpoint scopes by session, and only when you have two distinct sessions
# to compare (your own resource vs. a resource you don't own). A single
# unauthenticated request to one ID is not a swap and should be recorded as
# "not probed" rather than as an ownership signal:
curl -ksS -o /dev/null -w '%{http_code}\n' --max-time 5 \
  -H "Cookie: $SESSION_OWN" "$TARGET/api/orders/1"
curl -ksS -o /dev/null -w '%{http_code}\n' --max-time 5 \
  -H "Cookie: $SESSION_OWN" "$TARGET/api/orders/2"  # not your resource
```

Rules across all tiers:

- Prefer stopping at Tier 1 or 2. Reaching Tier 3 should be the exception,
  not the routine — if you're using it on most candidates, you're probably
  under-using the context already in the inventory.
- One value change at a time, always against a baseline, never chained into
  a working exploit (no UNION building, no payload escalation, no session
  hijacking, no data extraction).
- Never record response bodies containing another user's real data beyond
  noting "returned data" vs "did not" — do not copy PII/secrets into the
  candidate file.
- If a Tier 3 probe already looks like a full proof (e.g. a sleep-based
  timing hit, a reflected script tag executing) — stop, do not develop it
  further here. Note it as a high-confidence candidate and let the
  vulnerability-specific skill do the actual confirmation and PoC.

If a candidate's context alone is already a strong, well-known signal (e.g.
a numeric ID in a URL with no ownership check visible anywhere), skip
probing entirely and classify from context alone — don't probe just to
probe.

## 4. Map signals to a suspected vulnerability class

For each candidate, form a reasoned suspicion, not a conclusion:

| Context / signal | Suspected class |
|---|---|
| Reflected value, no/partial encoding | `cross-site-scripting` |
| Query/filter param + syntax-sensitive response (error/size/timing shift) | `sql-injection` |
| Object identifier + no visible ownership check | `access-control` |
| State-changing action referencing another user/object's ID | `access-control` |
| URL-fetch, image-import, webhook, or callback parameter with server-side fetch evidence | `ssrf`; an ordinary browser redirect alone is not SSRF |
| Reflected template expression evaluated by the server | `ssti` |
| Login, reset, MFA, logout, or session-lifecycle property | `authentication` |
| State-changing request using ambient browser credentials with a suspected missing defense | `csrf` |
| Redirect-only behavior without server-side fetching | unsupported open-redirect class; record and defer |
| File/path-like parameter without template evaluation | unsupported path/file-access class; record and defer |
| Structural/serialization-heavy (GraphQL, file upload, XML body) | classify a specific field when its signal matches a supported class; otherwise record and defer |

These are signal examples, not a frozen list of available validators. The
loaded skill registry is the source of truth: `workflow(record_candidate)`
returns `supported` and `recommended_skills` from enabled validation skill
metadata. If no validator handles a suspected class, retain the observation
with `status: deferred` and explain the missing capability. Do not call a
validator from this analysis skill. Do not invent a workflow for a
vulnerability class that doesn't have a skill yet.

A candidate can map to more than one suspected class; list all of them with
independent confidence.

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

For every candidate strong enough to include in the list, also call
`workflow(action="record_candidate", source_skill="web-input-analysis", ...)`
with its canonical `candidate_class`, method, endpoint, parameter/location,
short signals, and references to the baseline request or auth context when
available. Store references, not raw request/response bodies. The returned
Candidate ID is the handoff key for the validation skill. The workflow tool
deduplicates the same semantic target/method/endpoint/input/class tuple, so do
not manufacture alternate IDs. Weak/noisy observations that do not meet the
candidate-list bar must not be recorded. Inspect `supported` and
`recommended_skills` in the tool result before naming the next skill. For
multiple independent suspected classes, record one Candidate per class and
retain each returned ID; do not collapse them into one result.

Write `web-input-analysis/<target>/candidates.md`, using the same target
identifier as `recon` and `web-enumeration`. One entry per candidate:

```
- endpoint: GET /product
  parameter: id
  location: query
  context: object identifier
  signal: response size/time differs on syntax perturbation (' vs baseline)
  suspected_class: sql-injection
  confidence: medium
  rationale: numeric id feeding what looks like a direct lookup; single
    quote altered response shape vs baseline, not yet confirmed
  recommended_next_skill: sql-injection

- endpoint: GET /api/orders/{id}
  parameter: id
  location: path
  context: object identifier, state-changing sibling endpoints exist (PUT/DELETE)
  signal: swapped id returned 200 + body without an auth-context check visible
  suspected_class: access-control
  confidence: medium
  rationale: no ownership scoping observed; same pattern likely applies to
    PUT/DELETE variants, not tested here
  recommended_next_skill: access-control

- endpoint: GET /redirect
  parameter: next
  location: query
  context: redirect/URL-like
  signal: not probed
  suspected_class: open-redirect
  confidence: n/a
  rationale: no enabled validator handles redirect-only behavior
  recommended_next_skill: none — flag for user decision
```

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
artifact_ref="web-input-analysis/<target>/candidates.md",
current_phase="validation")`. This records
workflow progress independently of the conversational summary.

Do not turn signal-gathering into confirmation. Do not chain probes into a
working payload. Do not decide a finding exists here — that determination,
with PoC and impact, belongs entirely to the vulnerability-specific skill.
