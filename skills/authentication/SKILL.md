---
name: authentication
description: >
  Validate login mechanics, password reset flows, MFA enforcement, session
  fixation, and session-invalidation-on-logout for a specific candidate that
  `web-input-analysis` flagged as `suspected_class: authentication`, using
  the minimum non-destructive testing needed to establish evidence, and
  using only credentials, test accounts, and session material the user or a
  prior skill has actually provided — never fabricated, brute-forced, or
  self-provisioned without explicit authorization. Produces tested evidence
  and calls `confirm_finding` only when that evidence meets the confirmed
  threshold. Use after `web-input-analysis` has handed off a specific
  authentication candidate, or when the user directly supplies a concrete
  authentication flow and property to validate. Never expand beyond the
  provided candidate.
stage: validation
triggers:
  strong:
    - session fixation
    - session invalidation
    - login bypass
    - mfa bypass
    - 2fa bypass
    - otp bypass
    - password reset flow
    - password reset bypass
    - logout invalidation
    - user enumeration
    - account enumeration
  weak:
    - login flow
    - logout
    - session cookie
    - mfa
    - otp
    - password reset
    - remember me
    - account lockout
candidate-classes:
  - authentication
requires:
  - web-input-analysis
allowed-tools:
  - shell
  - http
  - file_write
  - ask_user
  - confirm_finding
---

# Authentication playbook

You have a specific candidate that `web-input-analysis` flagged
`suspected_class: authentication`, or that the user directly supplied with a
concrete authentication flow and property to validate. This phase answers
"does the authentication mechanism itself
hold up — issuing, verifying, and invalidating identity correctly?" It does
not re-triage the whole inventory and does not test mechanisms this skill
wasn't provided. It may persist a tracked finding only after the evidence
meets step 5's confirmed threshold (see step 6).

**Objective:** for each candidate routed here, either establish clear
evidence that an authentication mechanism can be bypassed, weakened, or
left in an inconsistent state (a session that outlives logout, an MFA step
that can be skipped, a reset token that isn't properly bound or
consumable, a fixated pre-auth session that survives login), using only
credential/session material already available and a strictly bounded
number of live probes, or record a clear negative, blocked, or
`insufficient-identity` result. Then record the result and stop.

Default to `curl` and the built-in `http` tool. Do not pull in scanners,
credential-stuffing tools, or password-spraying lists (Hydra, Medusa,
custom wordlists, etc.) — this skill works from one candidate at a time,
with a small, fixed set of legitimate credentials and a strictly bounded
number of negative probes.

Execution rule: substitute the real target, endpoint, and credential
material before running commands. Never write literal placeholder
tokens/passwords/cookies to files — if a value is genuinely unavailable,
say so and stop rather than inventing one. If the candidate or its context
is unclear, ask once before proceeding.

Three operational notes about the `http` tool/`curl`, since they matter
for this skill specifically:

- Requests made through the built-in `http` tool are stateless — no
  cookie jar or session is carried between calls. `curl` does not inherit
  cookies between invocations either, unless the skill explicitly uses a
  cookie jar (`-c` to write, `-b` to read, as the baseline in step 2
  does). Every request, including the baseline, must therefore make the
  session/cookie material you intend to test with explicit — either via
  an explicit header or an explicit, skill-managed cookie jar file.
  Nothing is inherited implicitly.
- Neither tool sets `Content-Type` automatically. For any JSON or
  form-encoded body (login, reset-request, MFA-verify calls), explicitly
  set `Content-Type` — an app may otherwise fail to parse the body and
  produce a misleading negative result.
- Permission prompts (where applicable) are cached per target host, not
  per credential/session — swapping the pre-auth cookie for the post-auth
  cookie, or account A's session for account B's, against the same host
  will not itself trigger a new prompt. Don't mistake the absence of a new
  prompt for confirmation that the session/account actually changed; that
  must be verified from the response/evidence, not from tooling behavior.

## Scope

Only test concrete candidates from `web-input-analysis/<target>/candidates.md`
with `suspected_class: authentication` (or a class list that includes it), or
candidates directly supplied by the user with equivalent flow/property
details. Do
not:

- test candidates suspected of a different class (`access-control`,
  `sql-injection`, `cross-site-scripting`) — those route to their own
  skill instead;
- expand scope to endpoints or flows outside the provided candidate;
- invent flow, identity, credential, or expected-property details from a
  generic request.

This skill covers: login-flow mechanics (credential verification,
error-message parity, response-timing-based user enumeration observed
incidentally — not timing attacks run as a dedicated technique), session
fixation (whether a pre-auth session ID is reused unchanged after login),
session invalidation on logout, password-reset flow integrity (token
binding to the requesting account, token single-use, token expiry
enforcement — not token *guessing*), and MFA step enforcement (whether the
protected action is reachable by skipping or replaying the MFA step). It
does not cover authorization once an identity is established (horizontal
or vertical privilege boundaries — that's `access-control`), CSRF,
JWT/OAuth token *cryptographic* vulnerabilities (alg confusion, signature
stripping — a separate, currently-inactive skill), or credential-strength
policy review. If a candidate turns out to be about one of those instead
of authentication mechanics, record it as `deferred (out of scope)` with
the specific reason noted, and do not test it here.

If authentication is delegated to an external SSO/OAuth identity
provider and the relevant authentication decision occurs outside the
target application's control, do not test the provider itself here.
Test only the target application's local authentication/session boundary
that is in scope (e.g. how the application establishes and manages its
own session after the provider redirects back); otherwise record
`deferred (out of scope)` with the specific reason (e.g. "authentication
decision made by third-party IdP, outside target's control").

## Target identifier

`<target>` below always refers to the identifier derived by the convention
defined in `recon/SKILL.md` ("Target identifier convention"). Reuse that
identifier exactly.

## Preconditions

Before starting, you should have:

- `web-input-analysis/<target>/candidates.md` containing at least one
  candidate with `suspected_class: authentication`;
- confirmation the target is still in scope.

If no such candidate exists, or the candidate file is missing or stale, go
back to `web-input-analysis` rather than guessing at a flow here.

## Credential and session material: use only what you're given

This skill has no built-in ability to create accounts, know real users'
passwords, receive real users' reset emails/SMS, or guess MFA codes. It
only has `shell`/`http` (which can attach whatever headers/cookies/bodies
you hand them) and `ask_user`. Treat credentials and session material as
inputs you must be handed, not capabilities you have.

Before testing a candidate, determine what's actually available:

- **A test account you control** — username/password (and, if relevant,
  access to that account's own MFA device/authenticator or reset-email
  inbox) for an account explicitly designated for testing.
- **A second, distinct test account you control** — needed specifically
  for the Tier 4 reset-token *binding* check (does a token issued to
  account A get accepted for account B?). Not needed for the Tier 4
  single-use or expiry checks, which only require one account.
- **A valid pre-auth or post-auth session token/cookie** carried over from
  earlier work.
- **Nothing** — no credentials or session material for the target at all.

If what you need isn't already available, use `ask_user` **once per
missing item** to ask the user to supply it or confirm you may use a
specific test account (e.g. "To test whether MFA can be skipped on
`/login`, I need valid credentials for a test account with MFA enabled,
and access to read the OTP it receives — can you provide a test account or
run the OTP step yourself and share the code?"). Ask for all gaps on the
current candidate together.

If the reset or OTP delivery channel itself (email inbox, SMS provider)
is outside the tester's access even though the account is a designated
test account, treat the artifact as unavailable: ask once via `ask_user`
for either access to that channel or the delivered value, and record
`insufficient-identity` (not `not confirmed`) if it still isn't available.

Do not:

- guess, brute-force, spray, or otherwise attempt to discover a real
  user's password, OTP, or reset token — this is a different vulnerability
  class (credential strength / rate-limiting) and out of scope for
  live-guessing here even if lockout/rate-limit *presence* is itself part
  of what you're checking (see Tier 5's small fixed-attempt bound);
- register new accounts, or trigger password-reset or MFA-enrollment flows
  against real user identifiers (real emails/phone numbers you don't
  control), unless the user has explicitly authorized that action for this
  target and identifier;
- reuse a session or credential obtained for one purpose as if it were a
  different, unauthorized identity;
- proceed with a test that requires credential/session material you don't
  have. Record the candidate as `insufficient-identity` instead (step 5)
  and move on.

## 1. Select and restate the candidate

For each candidate you're working, restate before touching it:

- endpoint(s)/flow and the mechanism it addresses (from `candidates.md`):
  login, password reset, MFA, session fixation, or logout/invalidation;
- which property is actually in question for this candidate:
  - does a pre-auth session survive login unchanged (fixation)?
  - does a session remain valid after logout (invalidation)?
  - is the MFA step actually enforced before the protected action is
    reachable (bypass)?
  - is a reset token properly bound to the requesting account, single-use,
    and time-bounded (reset-flow integrity)?
  - is there any lockout/rate-limiting behavior on repeated failed
    attempts (presence check only — not a guessing attack);
  - a candidate can implicate more than one property — list all that
    apply;
- current confidence (low/medium/high) and the signal that got it here.

Work one candidate at a time. Finish, record, then move to the next.

If multiple candidates share the same test account, session, or reset/MFA
artifact, read "Isolation across candidates sharing state" (end of step 3)
before running any of them, and sequence them accordingly.

When a candidate includes an anonymous-vs-authentication or pre-auth
boundary check (e.g. session fixation, which needs only the baseline
capture), perform that least-dependent check before tests that require
additional credential or session material.

## 2. Establish a clean baseline

Before testing any property, capture the "expected, legitimate" flow for
comparison — a full, correct login (and logout, if relevant) using
credentials you were actually given.

The request below is schematic only — `/login` is a placeholder, and the
shape (method, headers, body encoding) shown is illustrative. Reconstruct
the exact candidate request from the hand-off (e.g. `POST
/api/auth/login`, `POST /graphql`, `POST /oauth/token`) before executing
anything, rather than running the example as written:

```sh
TARGET="http://localhost:3000"   # replace with the real target
TEST_USER="..."                  # a genuinely available, designated test account
TEST_PASS="..."

curl -ksS -c /tmp/cookies_pre.txt -o /tmp/pre_body \
  -w '%{http_code}\n' --max-time 8 \
  "$TARGET/login"                # capture the pre-auth session cookie

curl -ksS -b /tmp/cookies_pre.txt -c /tmp/cookies_post.txt -o /tmp/login_body \
  -w '%{http_code}\n' --max-time 8 \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data "username=$TEST_USER&password=$TEST_PASS" \
  "$TARGET/login"                # authenticate, capture the post-auth cookie
```

**General rule: preserve the original request structure, and change only
the single variable under test.** Same method, same path shape, same
headers, same body — this mirrors the baseline discipline in
`access-control`, `sql-injection`, and `cross-site-scripting`.

Record baseline status and (for fixation) the actual pre- and post-auth
session identifiers side by side — not any other account data.

## 3. Test the relevant property, least intrusive first

Work through only the tiers relevant to this candidate (per step 1), in
order of what's cheapest and least disruptive to test. Stop as soon as a
tier gives a clear, reproducible signal for a given property — you don't
need every tier for every candidate.

**Tier 1 — session fixation (needs only the baseline capture above).**
Compare the pre-auth and post-auth session identifiers from step 2. A raw
cookie value being unchanged is not sufficient on its own — the identifier
must be the one that actually carries the authenticated state (i.e. it is
the value the application uses to recognize the session as
authenticated, not an incidental CSRF token or tracking cookie that
happens to persist). Confirm this by checking that the *same* identifier,
captured before login, now grants access to an authenticated-only
resource. If it does, that's a fixation signal. If the application
rotates or replaces the authenticated session identifier using a
different cookie/header/token name after login, compare the effective
authenticated session identity (does the pre-auth value still work at
all, under whatever name/mechanism now carries it?) rather than requiring
the same transport field name to persist unchanged.

**Tier 2 — session invalidation on logout (needs a valid session plus a
logout action).** Log out using the post-auth session, then replay a
request that requires authentication with the *same, now-logged-out*
session:

```sh
curl -ksS -b /tmp/cookies_post.txt -o /tmp/logout_body \
  -w '%{http_code}\n' --max-time 8 "$TARGET/logout"

curl -ksS -b /tmp/cookies_post.txt -o /tmp/replay_body \
  -w '%{http_code} %{size_download}\n' --max-time 8 \
  "$TARGET/api/account"          # authenticated endpoint, same old cookie
```

A generic `200` alone is not sufficient — the replayed response must
demonstrate actual authenticated functionality or protected-resource
content (the same kind of check `access-control` applies to anonymous vs.
authenticated responses: compare against the step 2 baseline's
authenticated content, not just its status code). A successful-looking
response from the `/logout` call itself is not evidence that invalidation
occurred — the logout response only shows the logout endpoint responded,
not that the session was actually invalidated server-side; the post-logout
replay is the check that matters. If the replayed request still returns
authenticated content, that's an invalidation-failure signal.

**Tier 3 — MFA step enforcement (needs a test account with MFA enabled and
a way to observe or supply its OTP; do not attempt to guess the OTP).**
After primary-factor login succeeds but before completing the MFA step,
attempt to reach an MFA-protected action directly with the intermediate
session:

```sh
curl -ksS -b /tmp/cookies_post.txt -o /tmp/mfa_bypass_body \
  -w '%{http_code} %{size_download}\n' --max-time 8 \
  "$TARGET/api/protected-action"  # should require completed MFA
```

Do not treat mere possession of a post-password-step session cookie as
proof that MFA was bypassed — some applications issue a new cookie after
the primary factor that still carries only limited, pre-MFA state. The
signal is whether the *protected action itself* succeeds and returns its
real, authenticated content with that intermediate session — not whether
a request merely returns a non-error status. Prefer a read-only protected
action for this check; do not perform destructive or persistent actions
solely to demonstrate MFA bypass. If the intermediate (pre-MFA-completion)
session can reach the protected action's actual authenticated behavior,
that's an enforcement-bypass signal. Only if this alone is inconclusive,
and only with an OTP you were actually given (read from a test account's
authenticator/inbox you control), confirm the *legitimate* path also
succeeds for comparison — never attempt a different, unsupplied OTP.

**Tier 4 — password-reset flow integrity (needs a reset flow for a test
account you control; do not target real users' emails/phones).** This
tier has three sub-checks with different identity requirements — treat
them separately rather than as one pass/fail:

- **Single-use and expiry** (needs only the one primary test account).
  Trigger one reset:

```sh
curl -ksS -o /tmp/reset_request_body -w '%{http_code}\n' --max-time 8 \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data "email=$TEST_USER_EMAIL" \
  "$TARGET/password-reset/request"
```

  Using the token you actually received (from the test account's own
  inbox), check single-use (does it still work after one successful
  reset?) and expiry (if a long-lived token was already observed to be
  stale, note that — don't wait out a live expiry window just to test
  it).

- **Binding to the requesting account** (needs the second, distinct test
  account described in the identity section above). Check whether a
  token issued for account A is accepted when completing a reset for
  account B. If a second test account was not made available for this
  candidate, record the binding sub-check specifically as
  `insufficient-identity` — do not infer binding behavior from the
  single-use/expiry checks, and do not skip recording it.

Each follow-up request in this tier is against the *same* test
account(s)' own token — never against a real user's token.

If a reset token or OTP expires unexpectedly during testing (e.g. before
the single-use or binding check could be completed), do not treat the
resulting rejection as evidence that the underlying property is secure —
an expired-token rejection proves expiry enforcement works, not that
single-use or binding enforcement works. Record the artifact as
expired/stale, note which sub-check couldn't be completed as a result,
and retest only with a freshly, legitimately obtained token — do not wait
out or force an expiry window merely to observe it.

**Tier 5 — lockout / rate-limiting presence (bounded, presence-only
check).** If the candidate concerns whether failed attempts are throttled
at all, send a small, fixed number of deliberately-wrong-credential
requests against the *test account only* — cap at 5 attempts — and observe
whether a lockout, delay, or CAPTCHA appears:

```sh
for i in 1 2 3 4 5; do
  curl -ksS -o /tmp/fail_$i -w '%{http_code}\n' --max-time 8 \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data "username=$TEST_USER&password=wrong-$i" \
    "$TARGET/login"
done
```

Stop at 5 regardless of outcome. This tier answers "does a control exist
at all," not "how many attempts until it breaks" — do not continue
escalating attempt counts to find the exact threshold, and never run this
tier against a real user's account.

Absence of an observed lockout/delay/CAPTCHA within 5 attempts is not by
itself a `confirmed` finding. Many applications throttle by IP, by
progressive delay past 5 attempts, by device fingerprinting, or via an
upstream control that a 5-request sample won't surface. Only record
`confirmed` for this tier if the candidate's hand-off specifically
identified an *expected* control (e.g. "inventory notes state failed
logins should lock the account after 5 attempts") and the observed
behavior demonstrates that specific expected control is absent. If the
candidate didn't establish a specific expected control, record the raw
observation (throttled / not throttled within 5 attempts) as
`not confirmed` and note the absence of an established baseline to
compare against — this is evidence to preserve, not sufficient support for
a finding or a conclusion this skill should draw on its own. Record this bounded
observation even when the outcome is `not confirmed`; do not discard the
evidence merely because an expected control wasn't established for
comparison.

Rules across all tiers:

- One comparison at a time, always against the step 2 baseline.
- Never test with credentials/session material you weren't actually given
  — an untested property is `insufficient-identity`, not a negative
  result.
- If a tier already gives a clear positive (e.g. fixation confirmed at
  Tier 1), you don't need to also run the other tiers for the same
  candidate.
- Never run Tier 3, 4, or 5 against a real user's identifier (email,
  phone, account) — only against a designated test account.
- An ordinary application-level `401` or `403` is not by itself evidence
  of `blocked`. `blocked` requires evidence of upstream interception
  (WAF, rate-limiter, or challenge page) before the request reached
  application logic — e.g. a challenge/CAPTCHA page body, a
  provider-specific block header, or a response shape inconsistent with
  the application's normal auth-failure responses. An ordinary
  `401`/`403` that matches the application's normal failure behavior is
  a negative application response, to be recorded as `not confirmed`
  (or as the relevant tier's negative outcome), not `blocked`.

**Isolation across candidates sharing state.** When multiple candidates
route to this skill sharing the same test account, session, or reset/MFA
artifact, do not let testing one candidate consume or invalidate material
another candidate still needs. Prefer fresh, independent
sessions/artifacts per stateful candidate when legitimately available
(e.g. a fresh login for each candidate that needs its own post-auth
session). When that isn't available and candidates must share state,
sequence state-destroying checks last: run non-destructive tiers (Tier 1
fixation observation, Tier 3 MFA-bypass check, Tier 4 reset checks) before
any check that terminates or consumes the shared session or token (Tier 2
logout invalidation, a consumed single-use reset token), unless the
hand-off explicitly specifies a different order.

## 4. Bound the proof — do not escalate into impact demonstration

Once a tier gives a clear, repeatable positive signal for a candidate,
stop probing it. In particular, do not:

- attempt to actually take over a real account, even the test account's
  linked real-world resources beyond what's needed to observe the flow;
- send more than one reset-trigger or MFA-observation request per
  candidate beyond what step 3 already specifies;
- continue failed-login attempts past the Tier 5 cap of 5 to find an exact
  lockout threshold;
- chain a confirmed weakness into further attacks (session hijacking
  demonstrations against other users, mass password-reset triggering,
  MFA-bypass automation);
- copy a captured session cookie, password, or OTP value itself into
  `results.md` — note "pre- and post-auth session identifiers were
  identical" or "protected action reachable pre-MFA" rather than the raw
  secret values;
- run automated credential-testing tools to "see how bad it is."

If confirming a property would require action against a real user's
identifier or credentials you don't have explicit authorization to use,
stop short and record the candidate as `requires-authorization-for-write`
(step 5) rather than performing it.

## 5. Record the result

Each candidate has one **overall** outcome for hand-off purposes.
Individual sub-checks within a tier (e.g. Tier 4's single-use, expiry, and
binding sub-checks) may each reach their own outcome when the tier
contains genuinely independent checks — record those individually, and
derive the candidate's overall outcome from them as described below.

The six possible outcomes (for a candidate overall, or for an individual
sub-check):

- `confirmed` — a tier in step 3 produced a clear, repeatable positive
  signal (fixation, invalidation failure, MFA bypass, reset-flow defect,
  or absent throttling against a candidate-established expected control),
  bounded per step 4;
- `not confirmed` — the relevant property tier(s) were actually tested
  against the live application with real, distinct requests, and none
  showed a weakness;
- `blocked` — a probe was intercepted by a WAF, rate-limiter, or challenge
  page before reaching the application logic (see the 401/403 rule in
  step 3); the application itself was never actually tested;
- `insufficient-identity` — the credential/session/test-account/reset- or
  MFA-channel material this candidate needs was not available and the
  user did not supply it when asked; the application was never actually
  tested for this property;
- `requires-authorization-for-write` — confirming the property would
  require a state-changing authentication action against an identity or
  account the tester is not explicitly authorized to operate on, and that
  authorization wasn't given. In this skill, this outcome specifically
  covers authentication state-changing actions: triggering a password
  reset, MFA enrollment/reset, account lockout/unlock, or forced logout
  against an account or identifier the tester isn't authorized to act on;
- `deferred (out of scope)` — the candidate turned out to be about
  authorization, CSRF, token-cryptography, or an external SSO/OAuth
  provider's own decision rather than this application's authentication
  mechanics (see Scope). Record the specific reason (e.g. "authorization,
  not authentication mechanics", "delegated to third-party IdP")
  alongside this outcome — the outcome string itself stays generic so
  downstream tooling can parse it consistently, and the reason lives in
  the free-text capture below.

If a candidate's tiers produce different results across its sub-checks
(e.g. Tier 4's single-use check is `not confirmed` while its binding
sub-check is `insufficient-identity` for lack of a second test account),
record each sub-check's outcome individually rather than forcing one
outcome for the whole candidate. The candidate's overall status for
handoff purposes (step 6) is `confirmed` if any sub-check reached
`confirmed`, and the most informative non-`confirmed` outcome otherwise.

For every candidate, regardless of outcome, capture:

- endpoint(s)/flow and mechanism (login / reset / MFA / fixation /
  invalidation / lockout);
- overall outcome (one of the six above), and each sub-check's outcome
  individually if they diverged;
- the specific reason for a `deferred` outcome;
- property(ies) tested and which tier produced the result, if any;
- credential/session material actually used, described by role only
  (e.g. "designated test account", "pre- vs post-auth session"), never the
  literal password/cookie/token/OTP value;
- the exact request(s) and the specific comparison that demonstrates the
  outcome (e.g. "pre- and post-auth session identifiers matched" — not the
  identifiers themselves);
- attempt count used for Tier 5, if run, and confirmation it stayed at or
  under the 5-attempt cap, plus the raw bounded observation even when the
  outcome is `not confirmed`;
- scope of proof obtained for confirmed candidates (e.g. "fixation
  confirmed on primary login; not tested against SSO login path").

Write every candidate's result to:

`authentication/<target>/results.md`

using the same target identifier as `recon`, `web-enumeration`, and
`web-input-analysis`. One entry per candidate, in the same style as
`web-input-analysis/candidates.md`.

## 6. Confirm an evidence-backed finding

`authentication` first produces tested evidence in `results.md`. For each
candidate marked `confirmed`, call `confirm_finding` to persist the canonical
finding:

```
authentication → results.md → confirm_finding → final finding
```

Populate the tool call from the recorded evidence. Supply `title`,
`severity`, exact `url`, `parameter` when applicable, `method`, a short
proving `response_excerpt`, concrete `impact`, a copy-pasteable `curl`,
remediation, and the same canonical `vuln_class` used when recording
coverage, including:

- affected endpoint(s)/flow and mechanism;
- which property failed (fixation / invalidation / MFA bypass / reset-flow
  binding-or-reuse / missing throttling);
- the exact request(s) and comparison evidence;
- concrete impact in one or two sentences. Impact must be limited to what
  the authentication evidence actually supports: when direct impact
  (e.g. full account takeover) was not itself safely demonstrated — which
  it should not be, per step 4 — describe it as a reasoned consequence of
  the confirmed weakness, not as an action that was actually executed
  (e.g. "an attacker who obtains or intercepts the pre-auth session
  identifier could gain authenticated access without credentials" rather
  than "account takeover was demonstrated");
- suggested remediation direction: regenerate session identifiers on
  privilege change (login/logout), invalidate sessions server-side on
  logout, enforce MFA completion before issuing an authorized session, and
  bind/expire/single-use reset tokens server-side — not a rewritten
  implementation, since you don't have the application's real
  authentication logic.

Do not call `confirm_finding` for `not confirmed`, `blocked`, `insufficient-identity`,
`requires-authorization-for-write`, or `deferred (out of scope)`
candidates as findings — they stay in `results.md` only. For
`insufficient-identity` and `requires-authorization-for-write` candidates
specifically, flag in the summary exactly what credential, test account,
or authorization would be needed to finish testing them, so the user can
decide whether to supply it.

Do not reuse the recon target identifier as the finding file name or
hand-roll a different finding format; `confirm_finding` owns canonical
finding persistence and naming.

## Stop conditions

Stop working a candidate when it has reached one of the six outcomes in
step 5 and been written to `results.md`.

Stop the skill entirely when every `authentication`-tagged candidate
handed to you has been worked to an outcome and `results.md` is complete.

Do not: test outside the candidates explicitly provided for this run, guess or
brute-force real credentials/OTPs/reset tokens, trigger reset or MFA flows
against real users' identifiers, exceed the Tier 5 five-attempt cap,
fabricate or self-provision test accounts without explicit authorization,
execute real account-takeover demonstrations against another user's
identity without explicit authorization, run automated credential-testing
tools by default, retry blocked probes with bypass tricks, or keep
escalating scope on a candidate that already gave a clear negative or
`insufficient-identity` result.
