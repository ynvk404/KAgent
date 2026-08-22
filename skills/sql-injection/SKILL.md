---
name: sql-injection
description: >
  Confirm or rule out SQL injection for a specific candidate produced by
  `web-input-analysis`, using the minimum non-destructive evidence needed
  to demonstrate the vulnerability, and record the result for
  `finding-validation` to turn into a finding. Does not scan broadly, does
  not extract real data, and does not use automated exploitation frameworks
  unless explicitly requested. Covers SQL injection only, not NoSQL/operator
  injection. Use only after `web-input-analysis` has produced a candidate
  with `suspected_class: sql-injection`.
allowed-tools:
  - shell
  - http
  - file_write
---

# SQL injection playbook

You have been handed one or more candidates from
`web-input-analysis/<target>/candidates.md` with
`suspected_class: sql-injection`. This phase answers "is this candidate
actually SQL-injectable, and if so, what's the minimum evidence that proves
it?" It does not re-triage the whole inventory, does not go looking for new
candidates, does not build a working data-extraction exploit, and does not
decide on its own what becomes a tracked finding. That restraint is the
point of this skill.

**Objective:** for each in-scope candidate, either produce the smallest
reproducible proof that SQL injection exists (with impact bounded to
"proof of concept," not "full compromise"), or record a clear negative or
blocked result. Then record the result and stop. This skill produces
evidence, not a final finding — `finding-validation` owns that decision
(see step 6).

Default to `curl` and the built-in `http` tool. Do not reach for `sqlmap`,
`ghauri`, or any other automated SQLi tool unless the user explicitly asks
for one, or manual confirmation has already succeeded and the user wants
help characterizing extraction impact on an explicitly authorized target.
This skill's job is confirmation, not automated exploitation.

**Scope:** this skill covers SQL injection only (MySQL, Postgres, MSSQL,
Oracle, SQLite, etc.). If a candidate's behavior looks like NoSQL/operator
injection (e.g. MongoDB query-operator payloads, unexpected JSON structure
handling), that is a different vulnerability class with no active skill
yet — record it as `deferred (nosql, out of scope)` in results and do not
apply SQL syntax to it here.

Execution rule: substitute real values before running commands. Never write
literal placeholders to files. If a candidate, target, or scope boundary is
unclear, ask once before running commands.

## Target identifier

`<target>` below always refers to the identifier derived by the convention
defined in `recon/SKILL.md` ("Target identifier convention"). Reuse that
identifier exactly.

## Preconditions

Before starting, you should have:

- `web-input-analysis/<target>/candidates.md` containing at least one entry
  with `suspected_class: sql-injection`;
- confirmation the target is still in scope.

If no candidate file exists, or the candidate you're being asked about isn't
in it, go back to `web-input-analysis` rather than inventing a new candidate
here. This skill tests candidates that analysis already produced — it does
not discover new ones.

## 1. Select and restate the candidate

For each candidate you're working, restate before touching it:

- endpoint, method, parameter, and location (query/path/body/header/cookie);
- the context and signal that got it here (from `candidates.md`);
- current confidence (low/medium/high).

Work one candidate at a time. Don't run confirmation probes against every
`sql-injection`-tagged candidate in a batch before recording results for the
first — finish, record, then move to the next.

## 2. Establish a clean baseline

Before sending anything syntax-sensitive, capture a normal response to
compare against:

```sh
TARGET="http://localhost:3000"   # replace with the real target
PARAM="id"
VALUE="1"                        # a known-valid, benign value for this param

curl -ksS -o /tmp/baseline_body -w '%{http_code} %{size_download} %{time_total}\n' \
  --max-time 8 "$TARGET/product?$PARAM=$VALUE"
```

**General rule: preserve the original request structure, and modify only
the candidate input.** This applies regardless of method or content type —
GET query string, POST form body, JSON body, path segment, header, or
cookie. Don't simplify a request down to just the parameter under test.

In particular, if the candidate's endpoint requires authentication or a
session (check `auth:` on the inventory/candidate entry), the baseline and
every probe in step 3 must carry the same:

- session cookie;
- `Authorization` header, if the app uses one;
- CSRF token, if the request needs one to be accepted at all;
- `Content-Type` and any other header the request depends on.

Use one fixed, valid session/credential for the whole candidate's test run.
If the session expires mid-sequence, refresh it and re-run the baseline —
don't compare a probe made with a stale session against a baseline made
with a fresh one; that difference is session state, not injection.

For a POST/JSON candidate specifically: build the equivalent baseline
request with `Content-Type: application/json` and a benign value in the
target field of the JSON body, leaving every other field and header
unchanged from a realistic request.

Record the baseline status code, size, timing, and (if relevant) the
distinguishing text in the body — e.g. "0 results" vs "results found," or a
specific error string. This baseline is what every later comparison is
measured against.

## 3. Confirm with the least intrusive technique that works

Try techniques in order of intrusiveness. Stop at the first one that gives
you a clear, reproducible signal — don't run every technique against every
candidate.

**3a. Error-based / syntax-sensitivity check (single quote).** Often enough
on its own if the app leaks DB errors or behaves visibly differently:

```sh
curl -ksS -o /tmp/probe1_body -w '%{http_code} %{size_download}\n' \
  --max-time 8 "$TARGET/product?$PARAM=1'"
```

Compare against baseline: status/size delta, a DB error string (`SQL syntax`,
`ORA-`, `pg_query`, `SQLSTATE`, `Microsoft OLE DB`, etc.), or a stack trace.
A clear DB error string is often sufficient evidence by itself — if you have
one, you likely don't need step 3b or 3c.

**3b. Boolean-based differential check.** Use only if 3a was ambiguous (no
error text, but you suspect the query shape changed). Send a pair of
requests that are logically TRUE and FALSE, otherwise identical:

```sh
curl -ksS -o /tmp/true_body  -w '%{http_code} %{size_download}\n' \
  --max-time 8 "$TARGET/product?$PARAM=1 AND 1=1"
curl -ksS -o /tmp/false_body -w '%{http_code} %{size_download}\n' \
  --max-time 8 "$TARGET/product?$PARAM=1 AND 1=2"
```

A consistent, repeatable difference between the TRUE and FALSE response
(size, status, or presence/absence of the same content marker used in
`web-input-analysis`) across at least two repetitions is real evidence.
A one-off difference is not — repeat once before concluding anything.

**3c. Time-based check.** Use only when 3a and 3b are both inconclusive
(e.g. no visible content difference and no error, but you still suspect
injection based on context — typically a blind, non-reflective sink).
Compare a delayed payload against an equivalent non-delayed one, and against
the plain baseline, so a slow network isn't mistaken for a hit:

```sh
curl -ksS -o /dev/null -w 'baseline: %{time_total}\n' \
  --max-time 12 "$TARGET/product?$PARAM=1"
curl -ksS -o /dev/null -w 'delay-5: %{time_total}\n' \
  --max-time 12 "$TARGET/product?$PARAM=1;SELECT SLEEP(5)--"
curl -ksS -o /dev/null -w 'delay-0: %{time_total}\n' \
  --max-time 12 "$TARGET/product?$PARAM=1;SELECT SLEEP(0)--"
```

Use a single delay value, run it twice on separate requests to confirm
repeatability, and require the delta to roughly match the injected delay
(a `SLEEP(5)` that adds ~5s, not ~0.2s of noise). One unrepeated slow
response is not evidence.

Adjust syntax per apparent DB engine (`SLEEP()` for MySQL, `pg_sleep()` for
Postgres, `WAITFOR DELAY` for MSSQL) based on whatever `recon` or
`web-enumeration` already fingerprinted; don't blind-guess across every
engine's syntax against the same live target.

**3d. WAF / rate-limiting check.** If any probe in 3a–3c comes back as
`403`, `429`, a generic "request blocked" page, or a CAPTCHA/challenge page
— instead of an application-level response — that is not a negative result.
It means the probe was intercepted before reaching application logic. Don't
retry with encoding tricks or filter-bypass variants to get past it; that's
outside this skill's scope. Record the candidate as `blocked` (see step 5)
and stop working it. A `blocked` result is distinct from `not confirmed`:
`not confirmed` means the application responded and showed no injection
signal; `blocked` means you don't actually know, because something in front
of the application intervened.

## 4. Bound the proof — do not escalate into extraction

Once a technique in step 3 gives a clear, repeatable positive signal, stop
probing that candidate. In particular, do not:

- build or run a `UNION SELECT` chain to pull columns or table names;
- dump table/column names, credentials, session tokens, or any real row
  data;
- chain the injection into file read/write, command execution, or
  authentication bypass;
- run automated tooling (`sqlmap` etc.) to "see how bad it is."

The one exception: if the user has explicitly asked for impact
characterization on a target they've explicitly confirmed is authorized for
that depth of testing, a single minimal extraction (e.g. one non-sensitive
value like `SELECT version()` / `@@version`, not user data) is enough to
demonstrate impact. Ask before doing even that if it wasn't already part of
the request.

If step 3 never produces a clear, repeatable signal, that's a valid outcome
— record it as not confirmed rather than continuing to escalate technique
or payload variety to force a result.

## 5. Record the result

Every candidate gets exactly one outcome:

- `confirmed` — a technique in step 3 produced a clear, repeatable positive
  signal, bounded per step 4;
- `not confirmed` — error-based, boolean-based, and time-based checks were
  all tried against the live application and none produced a repeatable
  signal;
- `blocked` — a probe was intercepted by a WAF, rate-limiter, or challenge
  page before reaching the application (step 3d); the application itself
  was never actually tested;
- `deferred (nosql, out of scope)` — behavior indicates NoSQL/operator
  injection rather than SQL injection (per Scope, above).

For every candidate, regardless of outcome, capture:

- endpoint, method, parameter, location;
- outcome (one of the four above);
- technique(s) tried and which one produced the result, if any;
- the exact request(s) and the specific comparison that demonstrates the
  outcome (status/size/timing deltas, or the literal error string — not
  full response bodies, and never response bodies containing real user
  data);
- apparent DB engine, if the evidence indicates one (confirmed only);
- injection context if apparent (e.g. appears to be inside a quoted string
  in a WHERE clause vs. an unquoted numeric context) — note this as
  inference from behavior, not as confirmed query text you haven't seen;
- first-order (reflected in the same request) vs. second-order (stored,
  triggered elsewhere) if discernible. If second-order behavior is
  suspected — e.g. a value stored via one endpoint appears to influence a
  query triggered by a different endpoint — record it as
  `second-order-suspected` with what you observed, and do not automatically
  build or run a multi-request confirmation flow to chase it. That's a
  separate, larger piece of work than this skill's single-candidate
  confirmation loop; leave the decision to pursue it to the user or to
  `finding-validation`;
- scope of proof obtained for confirmed candidates (e.g. "boolean
  differential only, no data extracted").

Write every candidate's result — confirmed, not confirmed, blocked, or
deferred — to:

`sql-injection/<target>/results.md`

using the same target identifier as `recon`, `web-enumeration`, and
`web-input-analysis`. This is the durable record of what was actually
tested and what was found, independent of whether anything gets turned into
a finding. One entry per candidate, in the same style as
`web-input-analysis/candidates.md`.

## 6. Hand off to finding-validation

`sql-injection` does not create a final finding itself — it produces tested
evidence in `results.md`. Whether that evidence becomes a tracked finding,
and in what format, is `finding-validation`'s decision:

```
sql-injection → results.md → finding-validation → final finding
```

For each candidate marked `confirmed` in `results.md`, hand off to
`finding-validation` with:

- affected endpoint/parameter/method;
- confirmation technique and evidence (from step 5);
- suspected DB engine and injection context;
- proof scope (what was and wasn't done — explicitly note that data
  extraction was not performed, if it wasn't);
- suggested remediation direction (parameterized queries / prepared
  statements / ORM parameter binding for this input) — the general fix
  category is appropriate here; a rewritten, drop-in query fix is not, since
  you don't have the application's real query.

Do not hand off `not confirmed`, `blocked`, or `deferred` candidates to
`finding-validation` as findings — they stay recorded in `results.md` only.
Findings follow their own naming convention, defined in
`finding-validation` — do not reuse the recon target identifier as the
finding file name, and do not hand-roll a different finding format here.

## Stop conditions

Stop working a candidate when it has reached one of the four outcomes in
step 5 and been written to `results.md`.

Stop the skill entirely when every `sql-injection`-tagged candidate handed
to you has been worked to an outcome and `results.md` is complete.

Do not: scan for new candidates, run automated SQLi tools by default,
extract real data or credentials, chain into other vulnerability classes,
retry blocked probes with filter-bypass or encoding tricks, or keep
escalating payload complexity on a candidate that already gave you a clear
negative result.