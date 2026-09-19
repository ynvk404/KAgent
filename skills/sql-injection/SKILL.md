---
name: sql-injection
description: >
  Confirm or rule out SQL injection for a specific candidate produced by
  `web-input-analysis`, using the minimum non-destructive evidence needed
  to demonstrate the vulnerability, and — only with explicit user
  authorization after SQL injection is confirmed — optionally validate
  impact through a minimal, non-sensitive fingerprint probe. Records the
  result and calls `confirm_finding` only when the recorded evidence meets
  the confirmed threshold. Does not scan
  broadly, does not extract real data by default, and does not use
  automated exploitation frameworks unless explicitly requested. Covers
  SQL injection only, not NoSQL/operator injection. Use after
  `web-input-analysis` has produced a candidate with
  `suspected_class: sql-injection`, or when the user directly supplies a
  concrete endpoint, method, and input to validate for SQL injection.
stage: validation
triggers:
  strong:
    - sql injection
    - sqli
    - union select
    - boolean based
    - time based
    - error based
    - database error
  weak:
    - database
    - injection
    - syntax sensitive
candidate-classes:
  - sql-injection
requires:
  - web-input-analysis
allowed-tools:
  - shell
  - http
  - read_payloads
  - file_write
  - ask_user
  - confirm_finding
---

# SQL injection playbook

You have one or more concrete candidates, usually from
`web-input-analysis/<target>/candidates.md` with
`suspected_class: sql-injection`, or directly specified by the user with an
endpoint, method, and input location. This skill answers "is this candidate
actually SQL-injectable, and if so, what's the minimum evidence that proves
it?" It does not re-triage the whole inventory, does not go looking for new
candidates, and does not decide on its own what becomes a tracked finding.
That restraint is the point of this skill.

This skill covers four phases in one workflow: detection, validation,
optional out-of-band confirmation, and optional impact. Phases 1 and 2 run
as part of normal SQL injection testing. Phase 2d (OOB) and Phase 3
(impact) are both optional and independently gated — neither runs
automatically, even after SQL injection is confirmed. Phase 2d is
additionally **capability-gated**: it only runs if the runtime actually
exposes an OOB callback/listener tool (see "Phase 2d capability check"
below). No such tool is in `allowed-tools` today, so as written Phase 2d
will not execute — the section is retained so it can be re-enabled later
if that capability is added, without needing to redesign the skill.

```
Phase 1: Detection / Baseline        — establish baseline, syntax signal
        ↓
Phase 2: Validation                   — confirms SQLi (SQLI-1 / SQLI-2)
        ↓ (only if 2a–2c inconclusive AND capability present AND explicitly authorized)
Phase 2d: Out-of-band confirmation    — confirms SQLi via external channel (capability-gated)
        ↓
Phase 3: Minimal Impact Validation    — only with explicit ask_user
                                          authorization, after SQLI-2
```

**Objective:** for each in-scope candidate, either produce the smallest
reproducible proof that SQL injection exists (with impact bounded to
"proof of concept," not "full compromise"), or record a clear negative or
blocked result. Then record the result and stop. This skill produces
evidence first; only a result that meets the confirmation threshold below
may be persisted with `confirm_finding` (see "Confirm an evidence-backed
finding").

## Authorization matrix

Quick reference for what each phase requires before it may run. This is a
summary of gates defined in full further down — if this table and the
prose ever disagree, the prose (and the specific gate section it lives in)
is authoritative.

| Phase | Requires to run | Who authorizes | Can it be skipped? |
|-------|------------------|-----------------|---------------------|
| 1 (Detection/Baseline) | Scope confirmed (Preconditions) | — (standard precondition) | No — always run first |
| 2a/2b (Validation) | A Phase 1 signal (or context strongly suggesting injection) | Automatic — part of normal technique selection | 2b may be skipped if 1b/2a already gave a clear signal ("stop at the first clear signal") |
| 2c (WAF/rate-limit check) | — | — | Never — always applies whenever a block-like response is observed |
| 2d (Out-of-band) | OOB capability present in `allowed-tools` + 2a–2c exhausted/inconclusive + separate `ask_user` authorization (incl. callback domain) | User, via `ask_user` | Effectively always skipped today — no OOB tool is currently available (capability check fails at step 1) |
| 3 (Impact) | SQLI-2 already confirmed + separate `ask_user` authorization | User, via `ask_user` | Cannot be skipped into — requires explicit authorization every time, never inferred from Phase 2d authorization |

## Relationship to `payloads.txt`

`SKILL.md` and `payloads.txt` have different jobs and neither substitutes
for the other:

- **`SKILL.md` decides what you're allowed to do** — which phase you're in, what authorization it requires, what evidence bar it needs, and when to stop.
- **`payloads.txt` provides the technical how** — the actual probe strings for a phase, once `SKILL.md` says that phase is authorized to run.

Reading a section of `payloads.txt` — including a later phase's section
that happens to be visible further down the same file — is **not** by
itself authorization to run it. The gating lives here, in `SKILL.md`, not
in which lines of `payloads.txt` you've read. This is stated in both files
on purpose: gating should hold even if an agent reads `payloads.txt` first
or in isolation.

Use the built-in `http` tool for requests. Use `shell` only when
reproducing the request needs something the `http` tool can't do (e.g.
precise wall-clock timing for step 2b, or a raw request shape the tool
doesn't support). **`shell` must never be used to simulate, fake, or
locally stand in for an OOB callback/listener** — if no real OOB tool is
available, Phase 2d does not run at all (see below); it is not
approximated with shell scripting. Do not reach for `sqlmap`, `ghauri`, or
any other automated SQLi tool unless the user explicitly asks for one, or
manual confirmation has already succeeded and the user wants help
characterizing extraction impact on an explicitly authorized target. This
skill's job is confirmation, not automated exploitation.

**Scope:** this skill covers SQL injection only (MySQL, Postgres, MSSQL,
Oracle, SQLite, etc.). If a candidate's behavior looks like NoSQL/operator
injection (e.g. MongoDB query-operator payloads, unexpected JSON structure
handling), that is a different vulnerability class with no active skill
yet — record it as `deferred (nosql, out of scope)` in results and do not
apply SQL syntax to it here.

Execution rule: substitute real values before running requests. Never
write literal placeholders to files. If a candidate, target, or scope
boundary is unclear, ask once before running anything.

## Target identifier

`<target>` below always refers to the identifier derived by the convention
defined in `recon/SKILL.md` ("Target identifier convention"). Reuse that
identifier exactly.

## Preconditions

Before starting, you should have:

- `web-input-analysis/<target>/candidates.md` containing at least one entry with `suspected_class: sql-injection`;
- confirmation the target is still in scope.

If no candidate file exists, or the candidate you're being asked about isn't
in it, go back to `web-input-analysis` rather than inventing a new candidate
here. This skill tests candidates that analysis already produced — it does
not discover new ones.

## Engine identification (before choosing Phase 2 payloads)

Do not guess an engine and fire every engine's syntax at the same live
target — that inflates request volume for no benefit and can trip
rate-limiting/WAF defenses unnecessarily (see 2c).

Before selecting time-based or engine-specific payloads:

1. Check whether `recon` or `web-enumeration` already fingerprinted the
   backend (server headers, error pages, known stack, driver hints). If
   so, use that engine's payloads only.
2. If not fingerprinted, use the error-based signal from Phase 1 (1b)
   first — DB error strings are usually engine-distinctive:
   - `SQL syntax.*MySQL`, `Warning: mysqli` → MySQL
   - `pg_query`, `PostgreSQL.*ERROR`, `SQLSTATE` → Postgres
   - `Microsoft OLE DB`, `Unclosed quotation mark`, `System.Data.SqlClient` → MSSQL
   - `ORA-\d{5}` → Oracle
   - `SQLite3::`, `sqlite3.OperationalError` → SQLite
3. If Phase 1 produced no error string (silent failure or generic 500),
   don't cycle every engine's time-based payload as a fishing expedition.
   Instead, try one conservative, low-signal probe per candidate engine
   guess in order of likelihood (informed by stack fingerprinting, tech
   headers, or the target's known platform) — and stop at the first one
   that produces a repeatable signal, per the "stop at the first clear
   signal" rule in Phase 2.
4. If the engine genuinely cannot be narrowed down at all, say so in the
   candidate's result entry (`engine: undetermined`) rather than silently
   trying all five.

For a broader indicator-string reference (not exploit payloads) covering
function names, string-concatenation syntax, and comment syntax per
engine, see the "Engine fingerprinting — extended reference" block at the
top of `payloads.txt`'s Phase 1 section.

## Scope checkpoint (entering Phase 2d or Phase 3)

Phase 1 (baseline + syntax signal) and Phase 2a–2c (boolean/error/
time-based confirmation) are standard non-destructive confirmation
techniques and do not require a checkpoint beyond the normal per-candidate
scope confirmed in Preconditions.

**Phase 2d (out-of-band) requires its own, separate `ask_user`
authorization — distinct from and in addition to Phase 3's — and requires
the OOB capability check below to pass first.** OOB techniques cause the
target to make an outbound connection (typically DNS, sometimes HTTP) to
an external listener. This has scope implications beyond the target
application itself:

- it can touch infrastructure outside the application (DNS resolvers, egress proxies, firewalls) that may not be covered by the same authorization as the web app;
- it requires a callback domain/listener, which must be one the user explicitly provides or controls — never default to a public/shared OOB service (e.g. a third-party Burp Collaborator-style service) unless the user confirms that's in scope and acceptable;
- it can leave a durable external record (DNS logs on infrastructure not owned by the tester) that other confirmation techniques don't.

### Phase 2d capability check (must pass before anything else in 2d)

Before considering Phase 2d for a candidate, confirm all of the following,
in order:

1. **Capability present:** the current toolset actually includes a real
   OOB callback/listener mechanism (i.e. something in `allowed-tools`
   built for this purpose). At present `allowed-tools` for this skill
   contains no such tool, so this check fails by default and Phase 2d is
   skipped entirely — do not attempt to work around this with `shell` or
   any other tool to fake a listener or a callback.
2. **Applicable techniques exhausted:** 2a and 2b have been tried (as
   required by the "stop at the first clear signal" rule in Phase 2 — not
   every candidate needs both) and are inconclusive, and no blocking
   condition was observed under 2c. 2c is a WAF/rate-limiting guard, not a
   confirmation technique in itself — it doesn't need its own "signal" to
   be satisfied, only the absence of a block.
3. **Explicit authorization:** the user has authorized OOB testing via
   `ask_user`, including confirming the specific callback domain/listener
   to use (and confirming it is not a public/shared service, unless the
   user explicitly accepts that).

If check 1 fails, stop there — do not proceed to checks 2 or 3, do not ask
the user to authorize something that cannot currently be executed, and do
not simulate the technique. Record `phase_2d_used: no` and note
`OOB unavailable (no OOB callback tool in this environment)` in the
result's `notes` field, then finish the candidate using whatever Phase
1–2c evidence you have (see "Recording the result").

If a real OOB callback tool is added to `allowed-tools` in the future,
checks 2 and 3 (and the procedure in "2d. Out-of-band (OOB) confirmation"
below) apply as written.

**Phase 3 — Minimal Impact Validation** requires its own `ask_user`
confirmation if it has not already been established for this engagement.

> **Phase 3 contract, at a glance**
> - **Goal:** confirm minimal impact only — a single fingerprint value (e.g. engine version/banner).
> - **Requires:** SQLI-2 already confirmed, *and* a separate `ask_user` authorization for Phase 3 specifically.
> - **Explicitly not for:** enumeration, data extraction, or any form of post-exploitation.

Use `ask_user` when:

- SQL injection has just been confirmed (SQLI-2, via 2a or 2b — or 2d, if that capability is ever available) and the user hasn't yet said whether impact characterization is wanted,
- the target is a shared/production-like environment and the impact of even a minimal read is unclear,
- the user's original request didn't already specify impact characterization as part of the task.

Do not infer Phase 3 authorization merely because Phase 2d authorization
was granted, or vice versa — they are separate permissions for separate
actions.

## 1. Select and restate the candidate

For each candidate you're working, restate before touching it:

- endpoint, method, parameter, and location (query/path/body/header/cookie);
- the context and signal that got it here (from `candidates.md`);
- current confidence (low/medium/high).

Work one candidate at a time. Don't run confirmation probes against every
`sql-injection`-tagged candidate in a batch before recording results for the
first — finish, record, then move to the next.

## Phase 1: Detection / baseline

### 1a. Establish a clean baseline

Before sending anything syntax-sensitive, capture a normal response to
compare against. Send the equivalent request with a known-valid, benign
value in the candidate parameter — same method, same content type, same
path.

**General rule: preserve the original request structure, and modify only
the candidate input.** This applies regardless of method or content type —
GET query string, POST form body, JSON body, path segment, header, or
cookie. Don't simplify a request down to just the parameter under test.

In particular, if the candidate's endpoint requires authentication or a
session (check `auth:` on the inventory/candidate entry), the baseline and
every probe in Phase 1 and Phase 2 must carry the same:

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

### 1b. Syntax-sensitivity check (single quote)

Use `read_payloads(skill="sql-injection", file="payloads.txt")` — use only
the `PHASE 1 — DETECTION` section at the top of that file for this step. It
contains the single-quote, double-quote, and closing-paren probes used to
check whether the input is syntax-sensitive at all, plus an extended
engine-fingerprinting indicator reference.

Send one probe from that section in the candidate parameter, preserving the
rest of the request exactly as in the baseline. Compare against baseline:
status/size delta, a DB error string (see "Engine identification" above for
the pattern-to-engine mapping), or a stack trace.

A clear DB error string is often sufficient signal by itself to move into
Phase 2 with high confidence, and also identifies the engine (see above). A
behavior change without an explicit error string (e.g. a size/status delta)
is enough to establish **SQLI-1** — a syntax-sensitivity signal — but is not
by itself confirmation; Phase 2 is required before reporting SQLI-2.

If neither the single-quote probe nor any variant in the Phase 1 section
produces any observable change from baseline, that's a valid outcome. Don't
conclude SQL injection is absent from one probe alone — continue into
Phase 2's boolean-based check, which can surface injection that a syntax
probe alone misses (e.g. numeric contexts where a stray quote is silently
tolerated or stripped).

**Quoted vs. numeric context — try both systematically, don't guess.** If
it isn't yet clear from the parameter's observed data type (e.g. an ID that
always looks numeric vs. a value that's rendered inside quotes elsewhere in
the app) whether the injection point sits in a quoted-string or a bare
numeric context, don't assume one and skip the other. Try a
quoted-string-style variant (e.g. `1' AND '1'='1`) and a bare numeric
variant (e.g. `1 AND 1=1`) as a pair before concluding either is
inapplicable — recording which one produced a signal is what fills in
`injection_context` in the results template later, rather than guessing it
after the fact.

**Detecting second-order candidates.** Most Phase 1–2 probes are
first-order: the payload is sent and its effect observed in the same
request/response cycle. A candidate is second-order instead when the
injectable value is *stored* by one action (e.g. a profile field, a
comment, an uploaded filename) and only reaches a SQL query later, in a
different request (e.g. an admin listing page, a search reindex, an export
job). Signs a candidate may be second-order:

- the parameter under test is a "write" endpoint (create/update) rather than a read/query endpoint, and `web-input-analysis` flagged it based on a downstream usage rather than an immediate response;
- sending a syntax-breaking probe (1b) produces no immediate error or behavior change on the same endpoint, but the value is visibly stored and displayed/used elsewhere;
- the suspected sink (where the value gets used in a query) is a different endpoint than the one accepting input.

If you suspect second-order behavior, store the probe value via the input
endpoint first, then separately test the suspected downstream sink
endpoint using the same Phase 1/2 techniques against *that* endpoint's
behavior — the "candidate" for confirmation purposes is really the pair
(input endpoint, sink endpoint). Record this in the result's `order` field
as `second-order-suspected` and describe the trigger path (which endpoint
stores it, which endpoint/action triggers the query) in `notes`.

## Phase 2: Validation

Once Phase 1 has produced a syntax-sensitivity signal (or is inconclusive
but context still suggests injection), continue into validation. Try
techniques in order of intrusiveness. Stop at the first one that gives you
a clear, reproducible signal — don't run every technique against every
candidate.

### 2a. Boolean-based differential check

Use only if 1b's error-based signal was ambiguous, or absent but you
suspect the query shape changed. Use the `PHASE 2 — VALIDATION` section of
`payloads.txt` for the paired TRUE/FALSE probes — send a logically TRUE and
a logically FALSE request, otherwise identical to each other and to the
baseline.

A consistent, repeatable difference between the TRUE and FALSE response
(size, status, or presence/absence of the same content marker used in
`web-input-analysis`) across at least two repetitions is real evidence and
establishes **SQLI-2**. A one-off difference is not — repeat once before
concluding anything.

### 2b. Time-based check

Use only when 1b and 2a are both inconclusive (e.g. no visible content
difference and no error, but you still suspect injection based on context —
typically a blind, non-reflective sink). The `PHASE 2 — VALIDATION` section
also contains delay payloads per engine — see "Engine identification" above
for how to pick which engine's syntax to try, and avoid firing every
engine's delay payload at the same target speculatively.

Compare a delayed payload against an equivalent non-delayed one, and against
the plain baseline, so a slow network isn't mistaken for a hit. Use a
single delay value, run it twice on separate requests to confirm
repeatability, and require the delta to roughly match the injected delay (a
5-second delay payload that adds ~5s, not ~0.2s of noise). One unrepeated
slow response is not evidence. A confirmed, repeatable delay establishes
**SQLI-2**.

Note: SQLite has no native `SLEEP()`-equivalent function. If the
fingerprinted or suspected engine is SQLite, skip 2b and rely on 2a
(boolean-based) instead — or 2d if that capability is ever available and
authorized. Do not attempt to force a delay via recursive/heavy queries, as
that risks unintended load or denial-of-service on the target.

### 2c. WAF / rate-limiting check

If any probe in 1b–2b comes back as `403`, `429`, a generic "request
blocked" page, or a CAPTCHA/challenge page — instead of an application-level
response — that is not a negative result. It means the probe was
intercepted before reaching application logic. Don't retry with encoding
tricks or filter-bypass variants to get past it; that's outside this
skill's scope. Record the candidate as `blocked` (see Recording the result)
and stop working it. A `blocked` result is distinct from `not confirmed`:
`not confirmed` means the applicable techniques were tried against the
application (per the "stop at the first clear signal" rule, not
necessarily every technique) and none produced a signal; `blocked` means
you don't actually know, because something in front of the application
intervened.

### 2d. Out-of-band (OOB) confirmation — capability-gated, last resort

**Do not start this section until the "Phase 2d capability check" above has
passed (capability present, 2a–2c exhausted, and explicit `ask_user`
authorization including callback domain).** In the current environment,
check 1 of that gate fails — there is no OOB callback/listener tool in
`allowed-tools` — so this section does not execute; skip straight to
"Recording the result" and note `OOB unavailable` as described above. The
procedure below is preserved for if/when that capability becomes
available:

Use the `PHASE 2D — OUT-OF-BAND` section of `payloads.txt`. These payloads
attempt to make the database issue a DNS (or, where supported, HTTP)
lookup against the authorized callback domain, substituting a unique
subdomain token per request so a resulting callback can be tied to the
specific probe that caused it.

Procedure:
1. Generate one unique, random subdomain label per probe (e.g. a short hex token) so any callback received can be attributed unambiguously.
2. Send the probe once.
3. Poll or check the callback listener (via the real OOB tool — never `shell`, never a fabricated/local stand-in) for a resolution/hit matching that exact token, within a reasonable wait window (e.g. 30–60s).
4. A received callback matching the token is a clear positive and establishes **SQLI-2**. No callback is a negative for this technique specifically — record as `not confirmed` (or combine with 2a–2c results) rather than retrying the same payload repeatedly.

Do not chain OOB payloads into data exfiltration via DNS (e.g. encoding
query results character-by-character into subdomain labels) without
separate, explicit authorization — that is Phase 3 territory (impact
validation) at minimum, and may exceed even Phase 3's "minimal fingerprint"
bound if it approaches real data extraction. The confirmation use of OOB
here is binary (did a callback happen or not), not extractive.

### Bound the proof — do not escalate into extraction

Once Phase 2 (via 2a, 2b, or — if available and authorized — 2d) gives a
clear, repeatable positive signal (SQLI-2), stop probing that candidate
with anything beyond Phase 2. In particular, do not:

- build or run a `UNION SELECT` chain to pull columns or table names;
- dump table/column names, credentials, session tokens, or any real row data;
- chain the injection into file read/write, command execution, or authentication bypass;
- run automated tooling (`sqlmap` etc.) to "see how bad it is."

If Phase 2 never produces a clear, repeatable signal — including when 2d
was unavailable and therefore not attempted — that's a valid outcome:
record it as `not confirmed` rather than continuing to escalate technique
or payload variety to force a result.

## Phase 3: Minimal Impact Validation (optional)

> **Goal:** confirm minimal impact — a single fingerprint value.
> **Condition:** SQLI-2 already confirmed + a separate `ask_user`
> authorization for Phase 3.
> **Not for:** enumeration, extraction, or post-exploitation.

Do not enter this phase automatically.

Only proceed when:

1. SQL injection has already been confirmed (SQLI-2), and
2. the user explicitly authorizes deeper impact validation via `ask_user`.

Use the `PHASE 3 — IMPACT` section of `payloads.txt` for the impact probes.
That section is limited to minimal, non-sensitive fingerprint reads — e.g.
version/banner queries for the confirmed engine — not user data, not
`UNION SELECT` column/table enumeration, and not credentials.

Stop once the minimum impact necessary to establish the finding is proven
(SQLI-3). Do not continue into unrelated post-exploitation, credential
harvesting, lateral movement, or a full `UNION SELECT` extraction "just to
be thorough." If a specific, narrowly-scoped additional read is genuinely
needed to demonstrate impact beyond version/fingerprint, `ask_user` for
that specific, additional authorization rather than reaching for broader
extraction by default.

## Recording the result

Every candidate gets exactly one outcome:

- `confirmed (SQLI-2)` — a technique actually available in this environment (2a or 2b, or 2d when that capability exists) produced a clear, repeatable positive signal, bounded per "Bound the proof" above;
- `confirmed (SQLI-3)` — SQLI-2 plus a minimal, authorized impact probe from Phase 3 succeeded;
- `not confirmed` — the applicable confirmation techniques available in this environment were tried as required by the workflow (per the "stop at the first clear signal" rule — this does not mean every technique must be run against every candidate), and none produced a clear, repeatable SQL injection signal. OOB is included only when its capability check passed and the user authorized it;
- `blocked` — a probe was intercepted by a WAF, rate-limiter, or challenge page before reaching the application (step 2c); the application itself was never actually tested;
- `deferred (nosql, out of scope)` — behavior indicates NoSQL/operator injection rather than SQL injection (per Scope, above).

### Standard result entry template

Write every candidate's result to `sql-injection/<target>/results.md`
using this exact template, one entry per candidate, appended in the order
tested:

```markdown
## Candidate: <endpoint> [<method>] — param: <parameter> (<location>)

- **timestamp:** <ISO 8601 UTC timestamp when this entry was recorded, e.g. 2026-08-27T09:14:32Z>
- **agent_session_id:** <identifier for the current agent run/session, for audit-trail correlation with logs elsewhere>
- **outcome:** <confirmed (SQLI-2) | confirmed (SQLI-3) | not confirmed | blocked | deferred (nosql, out of scope)>
- **sqli_level:** <1 | 2 | 3 | none>
- **engine:** <mysql | postgres | mssql | oracle | sqlite | undetermined | n/a>
- **technique(s) tried:** <e.g. 1b error-based, 2a boolean-based, 2b time-based, 2d OOB — list all tried, mark which produced the result>
- **evidence:**
  - baseline: <status/size/timing/marker>
  - probe result: <status/size/timing/marker, or literal error string>
  - repeated: <yes/no — required for 2a/2b/2d positives>
- **injection_context:** <e.g. "appears to be inside a quoted string in a WHERE clause" | "unquoted numeric context" | unknown — inferred from behavior, not confirmed query text>
- **order:** <first-order (reflected same request) | second-order-suspected — describe trigger path if second-order>
- **phase_2d_used:** <yes/no> — if yes: <callback domain used, token, result>; if no because the capability wasn't available, note that explicitly here too
- **phase_3_status:** <not attempted | authorized and run | authorization declined | not applicable — outcome not confirmed>
- **notes:** <anything else relevant — WAF behavior, session issues, ambiguous signals, "OOB unavailable (no OOB callback tool in this environment)" when applicable>
```

This is the durable record of what was actually tested and what was found,
independent of whether anything gets turned into a finding. The
`timestamp` and `agent_session_id` fields exist purely for audit
traceability — they don't affect gating or outcome logic.

## Confirm an evidence-backed finding

`sql-injection` first produces tested evidence in `results.md`. For each
candidate marked `confirmed (SQLI-2)` or `confirmed (SQLI-3)`, call
`confirm_finding` to persist the canonical finding:

```
sql-injection → results.md → confirm_finding → final finding
```

Populate the tool call from the recorded evidence. Include `title`,
`severity`, exact `url`, `parameter`, `payload`, `method`, a short proving
`response_excerpt`, concrete `impact`, a copy-pasteable `curl`, remediation,
and `vuln_class: sqli`:

```yaml
confirm_finding:
  title: <short descriptive title>
  severity: <critical|high|medium|low|info>
  url: <exact affected endpoint>
  method: <GET|POST|...>
  parameter: <parameter>
  payload: <exact confirming payload>
  response_excerpt: <short excerpt proving the SQLi>
  impact: <concrete evidence-supported impact>
  curl: <copy-pasteable reproduction>
  remediation: "Use parameterized queries, prepared statements, or ORM parameter binding for this input."
  vuln_class: sqli
```

Keep SQLi-specific details such as level, technique, engine, injection
context, proof scope, and any separately authorized Phase 3 evidence in
`results.md` so the finding remains auditable. Do not fill in a rewritten,
drop-in query fix — the general remediation category above is appropriate;
a concrete query rewrite is not, since you don't have the application's real
query.

Do not call `confirm_finding` for `not confirmed`, `blocked`, or `deferred`
candidates — they stay recorded in `results.md` only. Do not reuse the recon
target identifier as a finding file name or hand-roll a different finding
format; `confirm_finding` owns canonical finding persistence and naming.

## Stop conditions

Stop working a candidate when it has reached one of the five outcomes in
Recording the result and been written to `results.md`.

Stop the skill entirely when every `sql-injection` candidate provided for
this run has been worked to an outcome and `results.md` is complete.

Do not: scan for new candidates, run automated SQLi tools by default,
extract real data or credentials, chain into other vulnerability classes,
retry blocked probes with filter-bypass or encoding tricks, run Phase 2d
when the capability check fails or without its own explicit, separate
authorization, simulate OOB callbacks with `shell` or any other
workaround, run Phase 3 without its own explicit authorization, use a
public/shared OOB service without user confirmation, or keep escalating
payload complexity on a candidate that already gave you a clear negative
result.
