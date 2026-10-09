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
completion-artifact: artifacts/sql-injection/{target}/results.md
requires:
  - web-input-analysis
allowed-tools:
  - shell
  - http
  - read_payloads
  - file_write
  - file_edit
  - ask_user
  - confirm_finding
  - workflow
---

# SQL injection playbook

## Structured workflow contract

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

Before recording a `confirmed` result, write or update the candidate entry in
the canonical `artifacts/sql-injection/<target>/results.md`. When that entry contains the
minimal redacted proof, register this file with
`workflow(action="record_evidence", candidate_id="...", evidence_path="...")`
and use the returned `ev_...` ID in `evidence_refs`. The workflow tool stores
a redacted, content-addressed snapshot in project-local evidence storage, so
the candidate's proof remains immutable even though the shared `results.md`
continues to be updated for later candidates. Do not edit the stored snapshot;
register the updated source again to create a new proof version. The snapshot
must remain available through finding creation and session resume.
If coverage sync is `pending`, call `workflow(action="sync_coverage",
candidate_id="...")` before `confirm_finding`.

When a matching Candidate exists, call `workflow(action="start_validation",
candidate_id="...")` and use its structured fields as the handoff. A concrete
direct user request remains valid without prior analysis: first record the
user-supplied endpoint/input as a Candidate as runtime bookkeeping; this does
not block or require earlier workflow stages before validation. If endpoint
discovery is needed, resolve the concrete backend endpoint/input first; once
resolved, record that Candidate and call `start_validation` **before** sending
active SQL probes. Preserve the originally requested route/input in the
Candidate signals or notes when discovery resolves it to a different sink. At
the end of a meaningful attempt, call `workflow(action="record_result", ...)` with the
canonical outcome, compact evidence references, techniques, repeatability,
mutation/cleanup state, and any deferred reason. Use `force=true` only when the
user explicitly requests a retest or the request/input materially changed.
Only an outcome of `confirmed` is eligible for `confirm_finding`; pass the
Candidate ID to that tool. All other outcomes stop without confirming.

For a boolean-based confirmed result under this playbook, include structured
`confirmation` evidence. Use `kind: boolean-differential`, one shared
`request_template` containing `{predicate}`, distinct `true_predicate` and
`false_predicate` values, and at least two `pairs`. Each pair records its
repetition number plus the HTTP `status`, byte `size`, and a compact content
`marker` for both `true` and `false`. The Agent must reject identical sides,
one-pass claims, and non-reproducible pairs under this playbook. Do not set `repeatable: true` from
prose or from a baseline-versus-comment comparison.
In a live run, include at least four distinct `observation_ids` from the HTTP
tool: two actually executed and captured TRUE requests and two actually
executed and captured FALSE requests, forming the two complete repeatable
pairs. Match these IDs to the requests described in `confirmation`; a written
pair or reused observation ID cannot replace a captured request. Do not call
`record_result` with `outcome: confirmed` until all four observations exist.
Use a stable semantic marker such as `token issued`; never use the token itself.
If a known volatile field changes body length between repetitions, set the
smallest justified `size_tolerance` in bytes. Status and marker must still be
stable on each side, and the tolerance cannot be used to erase the TRUE/FALSE
difference.

For time-based SQLI-2, use `kind: time-differential`, a shared
`request_template` containing `{probe}`, `expected_delay_ms`, and at least two
paired `control`/`probe` observations with integer status, size, and elapsed
milliseconds. The Agent assesses controls, repeatability and whether each observed delay supports the
declared delay; cite real adapter timing observations. Runtime checks source integrity, not SQLi semantics. OOB confirmation remains unavailable in the current runtime.

You have one or more concrete candidates, usually from
`artifacts/web-input-analysis/<target>/candidates.md` with
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
yet — record it as `deferred`, note `NoSQL/operator behavior; outside this
validator` in `deferred_reason`, and do not
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

- `artifacts/web-input-analysis/<target>/candidates.md` containing at least one entry with `suspected_class: sql-injection`;
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

### State-changing endpoints

Baseline and confirmation requests can themselves cause target writes. A
successful write acknowledgement such as `Update complete` is evidence that
the server reports a write, even if no optional impact exploit was intended.
Record this observation in the narrative; never assert that no data was written
when the response reports successful write execution. `mutation_performed`
tracks mutation during the validation attempt and drives cleanup bookkeeping.
Distinguish a write-capable request from a server-reported successful write
and from independently verified affected rows or persistent state. Set
`mutation_performed: true` for an explicit successful-write acknowledgement,
including baseline writes, and record honest cleanup status even when readback
is unavailable. An acknowledgement does not independently verify affected rows
or persistent state: state those limits explicitly. A POST, HTTP 200, or merely
write-capable request alone does not establish mutation. Cleanup still requires
separate authority; reporting a write does not authorize automatic cleanup.

If writes are observed or the endpoint is known to be state-changing, stop
further stateful probes unless the profile has valid isolation and cleanup.
An operator declaration of external reset does not establish per-case reset
freshness. Write-only INSERT without isolated readback may remain
insufficient-evidence/deferred. Do not force confirmed or not-confirmed from
syntax sensitivity or a write acknowledgement alone; the SQLI-2 confirmation
threshold remains unchanged. This guard also applies to second-order storage.

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

Before changing quote, parenthesis, or comment syntax, write down the query
shape supported by the latest database error (or `unknown` / a justified
hypothesis when ambiguous) and choose the next single probe
that distinguishes the remaining possibilities. Do not walk a punctuation
list (`--`, `-- `, `/*`, `')`, `'))`, and so on) one request at a time without
using the returned parser position/message. Cap syntax-shape adjustments at
three after the initial signal; if they do not converge, move to a different
bounded confirmation technique or record the result as inconclusive.

If neither the single-quote probe nor any variant in the Phase 1 section
produces any observable change from baseline, that's a valid outcome. Don't
conclude SQL injection is absent from one probe alone — continue into an
applicable Phase 2 technique. A context-compatible boolean-based check can
surface injection that a syntax probe alone misses (e.g. numeric contexts
where a stray quote is silently tolerated or stripped).

**Quoted vs. numeric context — use observed SQL evidence.** A numeric-looking
input or a value rendered inside quotes elsewhere does not establish its SQL
position. When both positions remain plausible, a bounded quoted-string-style
and bare numeric comparison may help distinguish them; these requests count
toward the same syntax-adjustment limit, not a new budget. Record the supported
position or uncertainty in `injection_context`; do not force both variants when
parser evidence already rules one out.

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

Select a technique using the SQL context supported by target evidence:

- **Statement shape:** SELECT, INSERT, UPDATE, DELETE, or `unknown`.
- **Input position:** quoted string, numeric expression, predicate, identifier,
  or another supported expression; record `unknown` or a justified hypothesis
  when the evidence does not resolve it.
- **Probe compatibility:** explain why the proposed expression is syntactically
  meaningful at that position and how its evaluation would be observable.

Record this uncertainty in existing fields such as `injection_context` or in
`notes`; `unknown` describes SQL context, not a validation outcome. Do not
introduce new fields or outcomes for it.

Do not infer SQL structure solely from HTTP method, endpoint name, or parameter
name, or require reconstruction of the full query before testing. Repeated
expression-type or syntax mismatches call for reconsidering the technique,
not cycling through equivalent AND/OR payloads. Boolean evaluation can occur
in INSERT/VALUES contexts; its applicability depends on the expression and
observable effect, not a blanket statement-type rule. Preserve the existing
attempt limits and state-changing endpoint isolation/cleanup guard.

Apply the evidence-to-decision checkpoint in "Recording the result" before
submitting confirmation, whatever technique supplies the proof.

### 2a. Boolean-based differential check

When boolean probes fit the observed SQL context, use this as a minimum
confirmation step, including after a clear error-based SQLI-1 signal: Phase 1
syntax sensitivity alone does not establish SQLI-2. It also applies when 1b
was absent or ambiguous but the surrounding context suggests an observable
boolean evaluation. A TRUE/FALSE pair is required for boolean confirmation,
not for every SQLi technique. Use the `PHASE 2 — VALIDATION` section of
`payloads.txt` for the paired TRUE/FALSE probes — send a logically TRUE and
a logically FALSE request, otherwise identical to each other and to the
baseline.

A consistent, repeatable difference between the TRUE and FALSE response
(size, status, or presence/absence of the same content marker used in
`web-input-analysis`) across at least two repetitions is real evidence and
establishes **SQLI-2**. A one-off difference is not — repeat once before
concluding anything.

The TRUE/FALSE requests must instantiate the same `request_template`; only the
predicate changes. A benign baseline is useful context but is not the FALSE
member of the pair. A comment-only breakout that truncates the remainder of a
query is not, by itself, a boolean differential. Record both members of both
repetitions in the structured `confirmation` object passed to
`workflow(action="record_result", ...)`. If the paired observations are equal,
record that 2a was inconclusive; never preserve a signal claiming they differed.
Likewise, a successful `UNION SELECT` response compared with a syntax error or
missing-table error is not a boolean TRUE/FALSE pair. Describe that observation
as a bounded union/error differential; do not label it boolean-based or invent
predicates to satisfy the boolean confirmation schema.

On an authentication endpoint, the TRUE member of this pair may naturally
return the application's normal successful-login response, including a session
token. The status/body differential may be used as SQLI-2 evidence, but the
token is incidental evidence: do not replay it, decode it, request it again,
or use it against another endpoint. Record only a redacted marker such as
`token issued` plus the minimum non-sensitive identity fields already visible
in the same response. Any further token or account characterization requires a
separately authorized workflow.

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
and stop working it. A `blocked` result is distinct from `not-confirmed`:
`not-confirmed` means the applicable techniques were tried against the
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
4. A received callback matching the token is a clear positive and establishes **SQLI-2**. No callback is a negative for this technique specifically — record as `not-confirmed` (or combine with 2a–2c results) rather than retrying the same payload repeatedly.

Do not chain OOB payloads into data exfiltration via DNS (e.g. encoding
query results character-by-character into subdomain labels) without
separate, explicit authorization — that is Phase 3 territory (impact
validation) at minimum, and may exceed even Phase 3's "minimal fingerprint"
bound if it approaches real data extraction. The confirmation use of OOB
here is binary (did a callback happen or not), not extractive.

### Bound the proof — do not escalate into extraction

Once an applicable Phase 2 confirmation technique gives a
clear, repeatable positive signal (SQLI-2), stop further confirmation probes
and payload escalation for that candidate. Do not automatically move into
extraction or post-exploitation. Phase 3 remains available only when its
separate authorization is granted and a minimal additional impact probe is
useful; it is never an automatic next step. In particular, do not:

- build or run a `UNION SELECT` chain to pull columns or table names;
- dump table/column names, credentials, session tokens, or any real row data;
- chain the injection into file read/write or command execution, replay an
  issued session/token against other functionality, or otherwise extend an
  authentication bypass beyond the response already observed;
- run automated tooling (`sqlmap` etc.) to "see how bad it is."

Do not send another confirming request merely to pretty-print, decode, or
enrich evidence already obtained. `jq` may be used when available for local
JSON parsing or formatting, but workflow behavior must not depend on it being
installed. Never repeat a target request just because a local formatter is
unavailable; use a portable standard-library mechanism on the already captured
response when local processing is necessary and authorized. Prefer the built-in
`http` tool for ordinary HTTP requests.

When `curl` is genuinely required, keep the body and transfer metadata in
separate files/streams. For example:

```sh
curl -o "$body_file" -w '%{http_code} %{size_download}' ...
```

Parse only that one-line metadata output. Never append a delimiter to a
multiline body and run `awk -F` over the combined response. Treat a parsing
error or evidence-related stderr as an
invalid observation, even when the shell's final command happens to exit zero.
If the HTTP status was not captured, write `status: unavailable`; never infer
`200` from a body or invent a status.

Before any evidence reaches a transcript or artifact, redact bearer tokens,
session cookies, password/password-hash fields, API keys, and sensitive profile
fields. A token prefix is not needed to prove issuance; use a placeholder such
as `[REDACTED_TOKEN]`.

Never copy an opaque cookie, JWT, or CSRF value by hand between tool calls. If a
single bounded request chain genuinely requires one, extract and consume it in
the same scoped command without printing it, then persist only a redacted marker.
For native HTTP probes, choose `max_response_bytes` to retain a complete response
within configured limits, or omit it for the default capture. A short prefix
containing a marker is not complete terminal evidence. Body/content/size comparisons
and timing comparisons requiring content must retain a positive byte cap; never
request `0` for those probes. `0` requires explicit `evidence_mode: metadata-only`
for status/header-only checks; a nonempty discarded body is still truncated
and cannot be cited as terminal evidence. Prefer complete usable observations
already available and cite only sources on which the assessment actually relies.
Do not append truncated/incomplete/unfinished sources to an otherwise sufficient
manifest. After an evidence-admissibility rejection, read the source ID/reason,
retry at most once with usable existing evidence (repair linked proof if needed),
and submit insufficient-evidence if it is insufficient. Do not generate fresh
probes just to repair the manifest; continue validation only for a separately
identified missing validation step.

If Phase 2 never produces a clear, repeatable signal — including when 2d
was unavailable and therefore not attempted — that's a valid outcome:
record it as `not-confirmed` rather than continuing to escalate technique
or payload variety to force a result.

## Phase 3: Minimal Impact Validation (optional)

> **Goal:** confirm minimal impact — a single fingerprint value.
> **Condition:** SQLI-2 already confirmed + a separate `ask_user`
> authorization for Phase 3.
> **Not for:** enumeration, extraction, or post-exploitation.

Do not enter this phase automatically.

If the confirming response already contains minimum sufficient impact evidence
(for example, a successful authentication response, a redacted session/token
issuance marker, or a visible role/admin marker), record that observed evidence
without sending another request. It can support the impact description for a
confirmed SQLI-2 result, but does not by itself make the result SQLI-3: that
level requires a separately authorized Phase 3 probe. Do not decode or replay
the token, or use it against another endpoint.

Only proceed when:

1. SQL injection has already been confirmed (SQLI-2), and
2. the user explicitly authorizes deeper impact validation via `ask_user`, and
3. the existing response does not already provide the minimum sufficient
   impact evidence.

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

- `confirmed` with `SQLI-2` in `techniques` — an applicable technique actually available in this environment (boolean, error-based, bounded UNION-based, time-based, or OOB only when its capability and authorization gates pass) produced a clear, repeatable positive signal, bounded per "Bound the proof" above;
- `confirmed` with `SQLI-3` in `techniques` — SQLI-2 plus a minimal, authorized impact probe from Phase 3 succeeded;
- `not-confirmed` — the applicable confirmation techniques available in this environment were tried as required by the workflow (per the "stop at the first clear signal" rule — this does not mean every technique must be run against every candidate), and none produced a clear, repeatable SQL injection signal. OOB is included only when its capability check passed and the user authorized it;
- `blocked` — a probe was intercepted by a WAF, rate-limiter, or challenge page before reaching the application (step 2c); the application itself was never actually tested;
- `deferred` — behavior indicates NoSQL/operator injection rather than SQL injection (per Scope, above); put that reason in `deferred_reason`.

### Evidence-to-decision checkpoint

Immediately before registering proof and submitting a `confirmed` result,
establish these five points from the recorded evidence:

- State the observed statement shape and input position (or supported
  uncertainty), using `injection_context` / `notes`.
- Explain compatibility between that context and the selected technique,
  including how evaluation would be observable. Reconsider identical
  expression-type failures rather than attributing them to controlled evaluation.
- Identify the actual observed effect supporting the claimed technique.
  Distinguish syntax sensitivity (SQLI-1), a plausible candidate, and confirmed
  SQLI-2: repeated malformed syntax errors or different parser messages alone
  do not establish SQLI-2. Error-based proof must show response characteristics
  demonstrating controlled SQL evaluation rather than merely altered parsing,
  such as an error containing the evaluated result of a controlled,
  non-sensitive expression. A reproducible error response can itself supply
  sufficient evidence; no additional state change, impact test, or boolean
  differential is required when a supported technique already proves SQLi.
  Boolean, error-based, bounded UNION-based, time-based, and other applicable
  techniques remain valid within the existing proof bounds and capability gates.
- Verify each cited `observation_id` against its corresponding request and
  response: method, URL, actual payload/marker, status, and the response
  characteristics supporting the conclusion. Attribute baseline/control/probe
  observations to their actual payloads. Include baseline observations whenever
  the conclusion depends on comparison with baseline behavior.
- Keep the conclusion no stronger than the recorded evidence. Select supporting
  observations that match the recorded conclusion; never
  claim a request, probe, differential, or technical result that was not
  actually observed. Use existing `evidence_refs` and assessment excerpts
  where appropriate, keeping excerpts consistent with their cited sources.

Counterexample: an INSERT baseline reports a write acknowledgement, a
malformed quote produces a syntax error, and AND/OR variants produce identical
non-Boolean expression errors. These observations establish parser sensitivity,
not SQLI-2 confirmation by themselves; the type errors do not demonstrate
controlled evaluation of the proposed technique.

Recheck mutation/cleanup bookkeeping for the entire attempt, including
baseline successful-write acknowledgements, under the state-changing endpoint
contract above. Record readback limitations and honest cleanup state.

### Standard result entry template

Write every candidate's result to `artifacts/sql-injection/<target>/results.md`
using this exact template, one entry per candidate, appended in the order
tested:

```markdown
## Candidate: <endpoint> [<method>] — param: <parameter> (<location>)

- **candidate_id:** <structured Workflow Candidate ID>
- **timestamp:** <ISO 8601 UTC timestamp when this entry was recorded, e.g. 2026-08-27T09:14:32Z>
- **agent_session_id:** <identifier for the current agent run/session, for audit-trail correlation with logs elsewhere>
- **outcome:** <confirmed | not-confirmed | blocked | deferred>
- **techniques:** <SQLI-2 | SQLI-3 | technique attempted>
- **deferred_reason:** <required when outcome is deferred>
- **sqli_level:** <1 | 2 | 3 | none>
- **engine:** <mysql | postgres | mssql | oracle | sqlite | undetermined | n/a>
- **technique(s) tried:** <e.g. 1b error-based, 2a boolean-based, 2b time-based, 2d OOB — list all tried, mark which produced the result>
- **structured confirmation:** <for boolean SQLI-2: shared request template, distinct TRUE/FALSE predicates, and both paired observations from at least two repetitions>
- **evidence:**
  - baseline: <status/size/timing/marker>
  - probe result: <status/size/timing/marker, or literal error string>
  - repeated: <yes/no — required for 2a/2b/2d positives>
- **injection_context:** <e.g. "appears to be inside a quoted string in a WHERE clause" | "unquoted numeric context" | unknown — inferred from behavior, not confirmed query text>
- **order:** <first-order (reflected same request) | second-order-suspected — describe trigger path if second-order>
- **phase_2d_used:** <yes/no> — if yes: <callback domain used, token, result>; if no because the capability wasn't available, note that explicitly here too
- **phase_3_status:** <not attempted | authorized and run | authorization declined | not applicable — outcome not-confirmed>
- **notes:** <anything else relevant — WAF behavior, session issues, ambiguous signals, "OOB unavailable (no OOB callback tool in this environment)" when applicable>
```

This is the durable record of what was actually tested and what was found,
independent of whether anything gets turned into a finding. The
`timestamp` and `agent_session_id` fields exist purely for audit
traceability — they don't affect gating or outcome logic. Populate them only
from runtime-supplied values. If the exact timestamp or session identifier is
not exposed, write `unavailable`; never invent a plausible value.

## Confirm an evidence-backed finding

`sql-injection` first produces tested evidence in `results.md`. For each
candidate whose canonical outcome is `confirmed` (with `SQLI-2` or `SQLI-3`
recorded in `techniques`), call
`confirm_finding` to persist the canonical finding:

```
sql-injection → results.md → confirm_finding → final finding
```

Populate the tool call from the recorded evidence. Include the required
`candidate_id` of the confirmed Candidate, `title`, `severity`, exact `url`,
`parameter`, `payload`, `method`, a short proving `response_excerpt`,
`observed_impact`, `potential_impact`, a copy-pasteable `curl`, remediation,
and `vuln_class: sqli`. The latest result and its registered evidence must be
valid. `observed_impact` may describe attacker-controlled SQL execution and
output actually shown by the evidence; `potential_impact` describes further
database access only as conditional unless the validation demonstrated it.
Do not present possible impact as observed fact:

- Report an observed count as `returned 56 rows, consistent with bypassing the
  filter`; do not call it `every row` or `the full table` unless an independently
  verified total proves that claim.
- Do not say the injection `executes arbitrary SQL`, supports stacked queries,
  or permits file read/write unless that exact capability was separately
  authorized and demonstrated. Put untested consequences in
  `potential_impact` using `could`, `may`, or an explicit condition.

```yaml
confirm_finding:
  title: <short descriptive title>
  candidate_id: <confirmed workflow Candidate ID>
  severity: <critical|high|medium|low|info>
  url: <exact affected endpoint>
  method: <GET|POST|...>
  parameter: <parameter>
  payload: <exact confirming payload>
  response_excerpt: <short excerpt proving the SQLi>
  observed_impact: <what the linked evidence demonstrates>
  potential_impact: <untested consequences stated conditionally, or "No additional impact assessed.">
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

When a login differential naturally returns an administrative session token,
describe the demonstrated impact as `obtained a valid administrative session
token` or `administrative authentication bypass`. Do not claim full
administrative access or account takeover unless a separately authorized
workflow actually validated that access against administrative functionality.

Do not call `confirm_finding` for `not-confirmed`, `blocked`, or `deferred`
candidates — they stay recorded in `results.md` only. Do not reuse the recon
target identifier as a finding file name or hand-roll a different finding
format; `confirm_finding` owns canonical finding persistence and naming.

## Stop conditions

Stop working a candidate when it has reached one of the five outcomes in
Recording the result and been written to `results.md`.

Stop the skill entirely when every `sql-injection` candidate provided for
this run has been worked to an outcome and `results.md` is complete. Then call
`workflow(action="complete_skill", skill_name="sql-injection",
artifact_ref="artifacts/sql-injection/<target>/results.md")`; runtime rejects completion
when the canonical artifact is absent or a different path is supplied.

Do not: scan for new candidates, run automated SQLi tools by default,
extract real data or credentials, chain into other vulnerability classes,
retry blocked probes with filter-bypass or encoding tricks, run Phase 2d
when the capability check fails or without its own explicit, separate
authorization, simulate OOB callbacks with `shell` or any other
workaround, run Phase 3 without its own explicit authorization, use a
public/shared OOB service without user confirmation, or keep escalating
payload complexity on a candidate that already gave you a clear negative
result.
