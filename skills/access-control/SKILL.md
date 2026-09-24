---
name: access-control
description: >
  Validate horizontal/vertical privilege escalation, IDOR/BOLA, and missing
  authorization for a specific candidate that `web-input-analysis` flagged as
  `suspected_class: access-control`, using the minimum non-destructive
  testing needed to establish evidence, and using only identity/session
  material the user or a prior skill has actually provided — never
  fabricated or self-provisioned without explicit authorization. Produces
  tested evidence and calls `confirm_finding` only when that evidence meets
  the confirmed threshold. Use after `web-input-analysis` has handed off a
  specific access-control candidate, or when the user directly supplies a
  concrete endpoint/object and expected authorization boundary. Never expand
  beyond the provided candidate.
stage: validation
triggers:
  strong:
    - access control
    - idor
    - bola
    - horizontal privilege escalation
    - vertical privilege escalation
    - missing authorization
    - authorization bypass
    - function level authorization
  weak:
    - object identifier
    - object ownership
    - admin endpoint
    - authorization check
    - unauthorized access
    - cross user access
candidate-classes:
  - access-control
requires:
  - web-input-analysis
allowed-tools:
  - shell
  - http
  - file_write
  - ask_user
  - confirm_finding
  - workflow
---

# Access control playbook

## Structured workflow contract

Before recording a `confirmed` result, save a minimal redacted proof artifact,
call `workflow(action="record_evidence", candidate_id="...",
evidence_path="...")`, and use its returned `ev_...` ID in `evidence_refs`.
Keep role labels in the proof; never persist raw session material. If coverage
sync is `pending`, retry `workflow(action="sync_coverage",
candidate_id="...")` before `confirm_finding`.

Consume a matching Candidate with `workflow(action="start_validation",
candidate_id="...")`. A concrete direct request may be validated immediately;
record its details as a Candidate for result linkage without requiring earlier
reconnaissance. Record every meaningful attempt via
`workflow(action="record_result", ...)`; map missing identity/evidence to
`insufficient-evidence` and write authorization gates to
`authorization-required`. Use evidence references rather than response bodies.
Only `confirmed` is eligible for `confirm_finding`, using the Candidate ID.

You have a specific candidate that `web-input-analysis` flagged
`suspected_class: access-control`, or that the user directly supplied with a
concrete endpoint/object and expected authorization boundary. This phase
answers "can an identity that shouldn't be allowed to do
this, do it anyway?" It does not re-triage the whole inventory and does not
test parameters outside the provided candidate. It may persist a tracked finding
only after the evidence meets step 5's confirmed threshold (see step 6).

**Objective:** for each candidate routed here, either establish clear
evidence that authorization is missing or bypassable at the relevant
boundary (anonymous vs. authenticated, low- vs. high-privilege, or
same-privilege owner vs. non-owner), using only identity material already
available, or record a clear negative, blocked, or
`insufficient-identity` result. Then record the result and stop.

Default to `curl` and the built-in `http` tool. Do not pull in scanners or
authorization-fuzzing tools (Autorize-style plugins, etc.) — this skill
works from one candidate at a time, comparing a small, fixed set of
identities against a fixed set of requests.

Execution rule: substitute the real target, endpoint, and identity material
before running commands. Never write literal placeholder tokens/cookies to
files — if a value is genuinely unavailable, say so and stop rather than
inventing one. If the candidate or its context is unclear, ask once before
proceeding.

Three operational notes about the `http` tool/`curl`, since they matter
for this skill specifically:

- Requests are stateless — no cookie jar or session is carried between
  calls. Every request, including the baseline, must explicitly re-send the
  identity header(s) (`Cookie`, `Authorization`, etc.) you intend to test
  with. Nothing is inherited from a previous call.
- Neither tool sets `Content-Type` automatically. For any JSON body (e.g.
  the Tier 4 role/ownership tampering check), explicitly add
  `Content-Type: application/json` — an app may otherwise fail to parse the
  body and produce a misleading negative result.
- Permission prompts (where applicable) are cached per target host, not per
  identity — swapping `SESSION_A` for `SESSION_B` against the same host
  will not itself trigger a new prompt. Don't mistake the absence of a new
  prompt for confirmation that the identity actually changed; that must be
  verified from the response/evidence, not from tooling behavior.

## Scope

Only test concrete candidates from `web-input-analysis/<target>/candidates.md`
with `suspected_class: access-control` (or a class list that includes it), or
candidates directly supplied by the user with equivalent endpoint/object and
authorization-boundary details. Do
not:

- test candidates suspected of a different class (`sql-injection`,
  `cross-site-scripting`) — those route to their own skill instead;
- expand scope to parameters or endpoints outside the provided candidate;
- invent endpoint, object, identity, or boundary details from a generic
  request.

This skill covers: horizontal privilege escalation, vertical privilege
escalation, IDOR/BOLA, missing authorization (including unauthenticated
access to a resource that should require it), and function-level
authorization on admin-like or state-changing endpoints. It does not cover
authentication mechanics (login, password reset, MFA, session fixation),
CSRF, JWT/OAuth token vulnerabilities, or session-management bugs — those
are separate, currently-inactive skills. If a candidate turns out to be
about one of those instead of authorization, record it as `deferred (out
of scope)` with the specific reason noted (e.g. "authentication
mechanics, not authorization", "CSRF, not authorization", "session-
management bug, not authorization"), and do not test it here.

## Target identifier

`<target>` below always refers to the identifier derived by the convention
defined in `recon/SKILL.md` ("Target identifier convention"). Reuse that
identifier exactly.

## Preconditions

Before starting, you should have:

- `web-input-analysis/<target>/candidates.md` containing at least one
  candidate with `suspected_class: access-control`;
- confirmation the target is still in scope.

If no such candidate exists, or the candidate file is missing or stale, go
back to `web-input-analysis` rather than guessing at a parameter here.

## Identity material: use only what you're given

This skill has no built-in ability to create, log into, or switch between
accounts on its own. It only has `shell`/`http` (which can attach whatever
headers/cookies you hand them) and `ask_user`. Treat identity as an input
you must be handed, not a capability you have.

Before testing a candidate, determine what identity material is actually
available:

- **None** — no credentials, cookies, or tokens for the target at all.
- **Single identity** — one authenticated session/token (e.g. carried over
  from earlier enumeration).
- **Two same-privilege identities** — e.g. `SESSION_A` and `SESSION_B` for
  two distinct, same-role accounts (needed for horizontal tests).
- **Two different-privilege identities** — e.g. a normal-user session and
  an admin/elevated session (needed for vertical tests).

If what you need for a candidate isn't already available in the
conversation or in files from prior skills, use `ask_user` **once per
missing identity type** to ask the user to supply it (e.g. "I need a second
low-privilege session cookie, distinct from the first, to test horizontal
access control on `/api/orders/{id}` — can you provide one?"). Ask for all
identity gaps for the current candidate together rather than one at a time.

Do not:

- register new accounts, reset passwords, or otherwise self-provision
  identities to get a second session, unless the user has explicitly
  authorized that action for this target;
- reuse a session obtained for one user as if it were a different user;
- guess, brute-force, or otherwise attempt to obtain another user's
  session/token — that is a different vulnerability class (authentication)
  and out of scope here;
- proceed with a test that requires an identity you don't have. Record the
  candidate as `insufficient-identity` instead (step 5) and move on.

The one test that never requires a second identity is the
**anonymous-vs-required-auth** check (step 3, tier 1) — always attempt that
one first, since it needs no identity material beyond "none."

## 1. Select and restate the candidate

For each candidate you're working, restate before touching it:

- endpoint, method, and the object/action it addresses (from
  `candidates.md`);
- which authorization boundary is actually in question for this candidate:
  - anonymous vs. authenticated (missing authorization),
  - same-privilege owner vs. non-owner (horizontal / IDOR / BOLA),
  - low-privilege vs. high-privilege (vertical / function-level);
  - a candidate can implicate more than one boundary — list all that apply;
- current confidence (low/medium/high) and the signal that got it here.

Work one candidate at a time. Finish, record, then move to the next.

## 2. Establish a clean baseline

Before testing any authorization boundary, capture the "expected, legitimate"
response for comparison — the response a correctly-authorized caller gets
for their own resource:

```sh
TARGET="http://localhost:3000"   # replace with the real target
SESSION_A="..."                  # a genuinely available, valid session

curl -ksS -o /tmp/baseline_body \
  -w '%{http_code} %{size_download}\n' \
  --max-time 8 \
  -H "Cookie: $SESSION_A" \
  "$TARGET/api/orders/101"       # an object SESSION_A legitimately owns
```

**General rule: preserve the original request structure, and change only
the identity/credential under test.** Same method, same path shape, same
headers, same body — swap only the cookie/token/Authorization header (or
remove it, for the anonymous case). This mirrors the baseline discipline in
`sql-injection` and `cross-site-scripting`; don't simplify the request down
to a bare minimum that no longer matches what the app actually receives in
practice.

Record baseline status, size, and (if relevant) the identifying content
that shows this is genuinely "the owner's own data" — not the actual data
itself.

## 3. Test the relevant boundary, least intrusive first

Work through only the tiers relevant to this candidate (per step 1), in
order of what's cheapest to test. Stop as soon as a tier gives a clear,
reproducible signal for a given boundary — you don't need every tier for
every candidate.

**Tier 1 — anonymous vs. required auth (needs no second identity).** If the
candidate's inventory entry says the endpoint requires authentication,
confirm whether it actually enforces that:

```sh
curl -ksS -o /tmp/anon_body -w '%{http_code} %{size_download}\n' \
  --max-time 8 "$TARGET/api/orders/101"   # no Cookie/Authorization header
```

Compare against the baseline. If the anonymous request returns the same
resource data the authenticated baseline did (not just a generic 200 for an
empty/public response), that's a missing-authorization signal on its own.

**Tier 2 — horizontal: same-privilege owner vs. non-owner (needs two
same-level identities).** Only if two same-privilege sessions are actually
available:

```sh
curl -ksS -o /tmp/ownerB_body -w '%{http_code} %{size_download}\n' \
  --max-time 8 \
  -H "Cookie: $SESSION_B" \
  "$TARGET/api/orders/101"   # an object that belongs to A, requested as B
```

A response that returns A's actual resource content to B (not a 403/404,
not an empty/redacted body) is the core IDOR/BOLA signal. Repeat once with
a second object ID if the first result is ambiguous (e.g. object doesn't
exist) before concluding anything.

**Tier 3 — vertical: low-privilege vs. required-privilege action (needs a
low-priv identity; a high-priv identity is only needed to confirm the
"should succeed" side, and is optional if the app's docs/behavior already
make that obvious):**

```sh
curl -ksS -o /tmp/lowpriv_body -w '%{http_code} %{size_download}\n' \
  --max-time 8 \
  -H "Cookie: $SESSION_LOWPRIV" \
  -X GET "$TARGET/api/admin/users"
```

A low-privilege identity receiving the same functional response an admin
would get (data, or a state-change actually taking effect — see the
non-destructive rule below) is the vertical/function-level signal.

**Tier 4 — parameter/role tampering, only if tiers 1–3 don't apply or are
inconclusive.** Some apps infer role or ownership from a client-controlled
value (`role=admin` in a body, `user_id` in a hidden field) rather than
from the session. If the candidate's context suggests this, send one
request with that value altered, holding the session fixed at low
privilege:

```sh
curl -ksS -o /tmp/tamper_body -w '%{http_code} %{size_download}\n' \
  --max-time 8 \
  -H "Cookie: $SESSION_LOWPRIV" -H 'Content-Type: application/json' \
  -X PUT "$TARGET/api/profile" -d '{"role":"admin"}'
```

Then confirm (read-only) whether the tampered value actually took effect,
rather than assuming it did from a `200` alone.

**Tier 5 — WAF / rate-limiting / upstream interception check.** If a probe
returns `403`, `429`, or a challenge/block page, do not classify it as
`blocked` from the status code alone.

An ordinary application-level `401` or `403` can be the expected negative
authorization result and must be evaluated against the candidate's
baseline and boundary, not treated as an automatic non-result:

- application-level denial of the unauthorized identity (the request
  reached the application, and the application's own authorization logic
  rejected it) → this is a real, meaningful signal: record as
  `not confirmed` for that boundary;
- evidence that an upstream WAF, rate limiter, challenge, or other
  intermediary intercepted the request *before* application authorization
  logic ran (e.g. a block page with no application markup, a CAPTCHA, a
  vendor-specific challenge header, a response that doesn't resemble any
  other response this application has produced) → record as `blocked`; the
  application itself was never actually tested.

Do not classify an ordinary application response such as a normal `401` or
`403` as `blocked` merely from the status code. There must be evidence that
an upstream control intercepted the request before application handling —
otherwise it is an application-level response and should be evaluated as
such.

Do not retry with encoding tricks, alternate authorization headers, or
bypass techniques merely to get past an upstream control — that is outside
this skill's scope, same as in `sql-injection`/`cross-site-scripting`.

Rules across all tiers:

- One comparison at a time, always against the step 2 baseline.
- Never test with an identity you weren't actually given (see the identity
  section above) — an untested boundary is `insufficient-identity`, not a
  negative result.
- If a tier already gives a clear positive (e.g. anonymous access returns
  full resource data), you don't need to also run the higher tiers for the
  same candidate.

## 4. Bound the proof — do not escalate into impact demonstration

Once a tier gives a clear, repeatable positive signal for a candidate, stop
probing it. In particular, do not:

- perform state-changing tampering beyond the single request needed to show
  the boundary is missing (e.g. don't actually delete, transfer, or
  permanently modify another user's real object — prefer read-only
  endpoints, or a write to a resource you were given explicit permission to
  modify, or a request that can be reasoned about without executing it);
- enumerate or dump multiple other users' objects/IDs to show "how much"
  data is exposed — one clear instance is sufficient evidence;
- chain the access-control gap into further attacks (data exfiltration
  scripts, account takeover, privilege persistence);
- copy another user's actual data (PII, credentials, tokens, order
  contents) into `results.md` — note "returned data belonging to a
  different account" rather than the content itself, exactly as
  `sql-injection`/`cross-site-scripting` avoid copying real bodies;
- run automated authorization-fuzzing tools to "see how bad it is."

If a write/state-changing endpoint is the only way to demonstrate the gap
and you don't have explicit authorization to actually execute it against
another user's real resource, stop short and record the candidate as
`requires-authorization-for-write` (step 5) rather than performing it.

## 5. Record the result

Every candidate gets exactly one outcome:

- `confirmed` — a tier in step 3 produced a clear, repeatable positive
  signal (unauthorized access or action succeeded), bounded per step 4;
- `not confirmed` — the relevant boundary tier(s) were actually tested
  against the live application with real, distinct identities, and none
  showed unauthorized access;
- `blocked` — a probe was intercepted by a WAF, rate-limiter, or challenge
  page before reaching the application (step 3, tier 5); the application
  itself was never actually tested;
- `insufficient-identity` — the boundary this candidate needs (a second
  same-privilege session, a low/high-privilege pair, etc.) was not
  available and the user did not supply it when asked; the application was
  never actually tested for this boundary;
- `requires-authorization-for-write` — testing would require executing a
  state-changing action against another user's real resource, and explicit
  authorization for that wasn't given;
- `deferred (out of scope)` — the candidate turned out to be about
  authentication mechanics, CSRF, JWT/OAuth token vulnerabilities, or
  session-management bugs rather than authorization (see Scope). Record
  the specific reason (e.g. "authentication mechanics, not authorization",
  "CSRF, not authorization") alongside this outcome — the outcome string
  itself stays generic so downstream tooling can parse it consistently,
  and the reason lives in the free-text capture below.

For every candidate, regardless of outcome, capture:

- endpoint, method, and object/action;
- outcome (one of the six above);
- the specific reason for a `deferred` outcome;
- boundary(ies) tested: anonymous-vs-auth / horizontal / vertical /
  parameter-tampering, and which tier produced the result, if any;
- identity material actually used, described by role only (e.g. "session A
  vs session B, same role" / "low-priv vs admin"), never the literal
  cookie/token value;
- the exact request(s) and the specific comparison that demonstrates the
  outcome (status/size deltas, or "returned owner's data to non-owner" —
  not full response bodies, and never another user's real data);
- whether the action tested was read-only or state-changing, and if
  state-changing, exactly what was (and wasn't) executed;
- scope of proof obtained for confirmed candidates (e.g. "single-object
  horizontal read confirmed; not tested against write endpoints").

Write every candidate's result to:

`access-control/<target>/results.md`

using the same target identifier as `recon`, `web-enumeration`, and
`web-input-analysis`. One entry per candidate, in the same style as
`web-input-analysis/candidates.md`.

## 6. Confirm an evidence-backed finding

`access-control` first produces tested evidence in `results.md`. For each
candidate marked `confirmed`, call `confirm_finding` to persist the canonical
finding:

```
access-control → results.md → confirm_finding → final finding
```

Populate the tool call from the recorded evidence. Supply `title`,
`severity`, exact `url`, `parameter` when applicable, `method`, a short
proving `response_excerpt`, concrete `impact`, a copy-pasteable `curl`,
remediation, and the matching coverage class in `vuln_class` (for example,
`idor` for an IDOR), including:

- affected endpoint/method/object;
- which authorization boundary failed (missing auth / horizontal /
  vertical / tamperable role or ownership field);
- the exact request(s) and comparison evidence;
- concrete impact in one or two sentences (what an attacker with only the
  lower-privilege identity could actually do) — not a hypothetical worst
  case;
- suggested remediation direction: enforce ownership/role checks
  server-side on every request (never trust client-supplied role/user
  fields), scoped by the authenticated session — not a rewritten
  implementation, since you don't have the application's real
  authorization logic.

Do not call `confirm_finding` for `not confirmed`, `blocked`, `insufficient-identity`,
`requires-authorization-for-write`, or `deferred (out of scope)`
candidates as findings — they stay in `results.md` only. For
`insufficient-identity` and
`requires-authorization-for-write` candidates specifically, flag in the
summary exactly what identity or authorization would be needed to finish
testing them, so the user can decide whether to supply it.

Do not reuse the recon target identifier as the finding file name or
hand-roll a different finding format; `confirm_finding` owns canonical
finding persistence and naming.

## Stop conditions

Stop working a candidate when it has reached one of the six outcomes in
step 5 and been written to `results.md`.

Stop the skill entirely when every `access-control`-tagged candidate handed
to you has been worked to an outcome and `results.md` is complete.

Do not: test outside the candidates explicitly provided for this run, fabricate or
self-provision identities without explicit authorization, execute real
state-changing actions against another user's data without explicit
authorization, dump or enumerate multiple victims' data, run automated
authorization-fuzzing tools by default, retry blocked probes with
bypass tricks, or keep escalating scope on a candidate that already gave a
clear negative or `insufficient-identity` result.
