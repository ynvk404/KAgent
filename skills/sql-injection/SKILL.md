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
  - file_edit
  - ask_user
  - confirm_finding
  - workflow
---

# SQL injection playbook

Parser sensitivity, controlled SQL evaluation and a confirmed finding are
different evidence levels. A SQLite error without query text leaves SQL shape
a hypothesis; do not claim that SELECT or constructed SQL was observed. TRUE
and FALSE producing the same error or the same empty result do not establish
a differential. Changing technique names does not reset the syntax-adjustment
allowance. Record only requests, timeouts and responses actually observed.

Distinguish raw wire encoding from decoded application input: `%27` and a literal
quote may denote the same input after one justified decode. Do not repeatedly
decode or rewrite request hashes/identity/evidence bindings to merge probes.

Before proof/result submission, inspect the current candidate/attempt observation
inventory. Prefer completed, complete, non-truncated sources with the correct
request association; reuse an existing complete control instead of recapturing
it after choosing a truncated duplicate. Usable metadata is not impact proof.
Keep adverse evidence. Changed parents require corrected source proof and claims
plus a new immutable snapshot; registration alone does not establish terminal
eligibility. When probing stops, use the remaining budget for honest finalization;
Continue does not authorize a retest or reset declaration/recovery allowances.

Read the applicable payload guidance before the first confirmation probe, not
after spending syntax adjustments. Use its published continuation only until
the chosen technique is visible; unrelated later sections are not prerequisites.
Before each HTTP probe, state a short hypothesis, its supporting evidence,
expected observation and what would falsify it in the existing ledger/checkpoint;
no separate artifact or full query reconstruction is required. Choose a benign
seed and explain the expected oracle and prefix/predicate/suffix hypothesis.
Do not use an arbitrary nonmatching seed for an AND-filter test. Earlier analysis
observations inform planning only and remain unowned: do not copy their IDs into
terminal proof or imply ownership. Capture a necessary benign control inside the
active attempt only for an identified comparison. A quote-containing search match
may be ordinary string matching, not an established breakout shape. Parser
positions alone do not pin a LIKE literal or balance its quotes and parentheses.

Exhausted syntax adjustments are a finalization checkpoint: use another technique
only if it has a distinct evidence-supported plan within the existing bounds.
Otherwise submit `insufficient-evidence` promptly, with the missing oracle/context
and observed limitations. Do not spend finalization turns rereading unchanged
responses or payload sections to prepare another syntax adjustment. Reuse the
already visible complete captures; read only a genuinely missing range. Keep
engine/context notes separate from effect declarations; `record_attempt_state`
is not a general notes log. Reserve existing turns for proof writing, registration
and `record_result`; missing proof never prevents an honest unresolved result.
An unregistered proof file is a local artifact, not accepted evidence. Verify
the returned `result_id`, `evidence_refs` and outcome before reporting them.

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
As soon as effects need recording, use `workflow(action="record_attempt_state",
candidate_id=..., mutation_state=..., effect_basis=..., observation_ids=[...],
cleanup_state=..., cleanup_status=...)` with the actual attempt's sources.
Mutation states are `unknown`, `possible`, `reported-write`, `verified-write`,
and `no-mutation-established`. A server acknowledgement is a reported write,
not independently verified persistence. Never erase a reported write with false.
Unknown mutation uses `mutation_performed: null`; cleanup unknown/not-attempted
does not mean succeeded or not-required. Cleanup success needs owned declared
cleanup action/verification evidence and separate action authority.
Explicit `mutation_performed`/cleanup fields remain accepted on `record_result`;
omitted fields use current attempt bookkeeping and otherwise remain unknown.

Reuse visible authoritative metadata; use `workflow(action="list", candidate_id=...)`
only for missing observation IDs or adapter `elapsed_ms`;
`next_observation_offset` paginates this metadata.
Use `read_http_observation` for `obs_` response ranges, `read_tool_result` only
for `tr_` references, and registered `ev_` IDs for proof. Retrieval or ownership
failure is not a reason to resend HTTP or invent an ID. Recapturing a signal
just to read it does not resolve an oracle or identify a missing validation step.
Date headers are not timing proof.
When runtime says probing stopped, use remaining existing budget for local
effect bookkeeping, proof registration and result disposition. Do not send
more target actions or infer a negative result from anti-stall. If operator
input is unavailable, record unresolved; missing input never authorizes writes.

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

Before recording either terminal result, save a minimal redacted proof artifact.
The optional canonical `artifacts/sql-injection/<target>/results.md` report may
also serve as a proof source when it contains the required evidence. Register
the proof file with
`workflow(action="record_evidence", candidate_id="...", evidence_path="...")`
with the actual supporting `observation_ids` returned by HTTP (or retained in
authoritative evidence state), and use the returned `ev_...` ID in `evidence_refs`.
`record_evidence` accepts only `candidate_id`, `evidence_path`, and
`observation_ids` in addition to `action`; omit `attempt_id`. The attempt ID
returned by `start_validation` may be supplied to `record_result` as an equality
check, never assigned by the Agent. An observation is captured traffic, `ev_...`
is registered immutable proof, and neither is an accepted ValidationResult or a
persisted finding. The workflow tool stores
a redacted, content-addressed snapshot in project-local evidence storage, so
the candidate's proof remains immutable even though the shared `results.md`
continues to be updated for later candidates. Do not edit the stored snapshot;
register the updated source again to create a new proof version. The snapshot
must remain available through finding creation and session resume.

Every explicit observation ID in the selected candidate's proof fields, headings
or table rows is a primary parent claim, including inconclusive history and
syntax-adjustment rows. Include all cited, correctly owned sources in
`record_evidence.observation_ids`; the four successful boolean pair observations
alone do not cover additional ledger rows. Keep adverse evidence and its actual
labels. `PROOF_PARENT_MISMATCH` identifies missing IDs and 1-based line numbers
in the redacted snapshot; verify them against the current owned ledger before
repairing the manifest. These diagnostics do not establish ownership or usability.
`record_attempt_state.observation_ids` records effects only and cannot declare
proof parents; reordering an unchanged parent set cannot repair this mismatch.
Correct the source artifact if its references/claims are wrong; otherwise supply
its actual owned parents. Never edit an immutable snapshot or resend HTTP for
this repair, and keep the existing recovery budget.

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

Both terminal outcomes require `assessment` with `hypothesis`, `criteria`,
`limitations`, `observed_impact`, and `severity`; a bounded `not-confirmed` also
requires `completed_attempt: true`. For example, after completing an applicable
bounded negative test, use actual returned references and evidence-derived text:

```python
{"action": "record_result", "candidate_id": candidate_id,
 "attempt_id": attempt_id, "skill_name": "sql-injection",
 "outcome": "not-confirmed", "observation_ids": sources,
 "evidence_refs": [evidence_id], "assessment": {
     "hypothesis": hypothesis, "criteria": criteria, "limitations": limitations,
     "observed_impact": observed_impact, "severity": "info", "completed_attempt": True}}
```

`sources` contains usable current owned observations; `evidence_id` is the `ev_`
returned by `record_evidence`, not a file path. A confirmed result additionally
needs the applicable technique's proof and confirmation fields described below.
Keep engine/context notes in existing accepted fields, not new top-level arguments.

If another validation attempt is active, use `workflow(action="list",
status="validating")` to identify its Candidate and continue that attempt or
submit its honest `record_result` with the matching validator `skill_name`.
Use `insufficient-evidence` when sources or proof are insufficient, or `deferred`
when work is postponed, and explain the limitation in `deferred_reason`/`notes`.
Omit source/proof references when unavailable; never force `confirmed` or
`not-confirmed` to release ownership. An accepted unresolved result releases
the active attempt while retaining outstanding work. Only then start the next
Candidate; do not auto-close an attempt merely because another input appeared.

Selected Burp validation and same-input enrichment retain the matching capture's
endpoint/method/input identity. A different endpoint or input is independent work:
use its own Candidate provenance and validation attempt, with appropriate operator
intent/scope in a subsequent turn without that selection when the binding would
differ. Do not borrow the selected capture's references or declare a new primary
sink as a related request of the old attempt. Primary observations must belong
to the Candidate and attempt actually being assessed.
During an active attempt, enrich annotations without changing its request context
or ownership. If request context must change, record the current attempt's honest
result or unresolved closure first, then update the Candidate and start a new
attempt. Old observations remain owned by the old attempt.

Send valid JSON with only the fields accepted by the chosen Workflow action.
After an argument rejection, correct that action once using its schema and
returned IDs; do not repeat unchanged invalid calls or issue HTTP to fix JSON.
When complete, correctly owned sources already meet this playbook's evidence
contract, prioritize proof registration → result submission → required finding
persistence. Probe again only for an identified missing validation step.

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
| 2 (Boolean, controlled error-based, bounded UNION-based, time-based) | A Phase 1 signal (or context strongly suggesting injection) + compatible context/oracle | Automatic — part of normal technique selection | Select an applicable plan; no mandatory sequence; stop at the first clear, repeatable signal |
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

Use the built-in `http` tool for requests and its adapter `elapsed_ms` for
step 2b timing. Use `shell` only when reproducing a necessary request detail
needs something the `http` tool cannot express; timing alone does not require it.
**`shell` must never be used to simulate, fake, or
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

- a concrete in-scope endpoint, method, parameter and input location from either
  prior input analysis or the operator's direct validation request;
- confirmation the target is still in scope.

For analysis-led work, use the structured Candidate and canonical input context;
`artifacts/web-input-analysis/<target>/candidates.md`, when present, is an analysis
handoff. If analysis has not resolved the requested input, return to
`web-input-analysis` rather than inventing its identity. For a concrete direct
request, record the operator-supplied input as a Candidate and call
`start_validation` before active probes; a prior analysis stage or `candidates.md`
file is not required. This exception supplies bookkeeping, not permission or
scope expansion. This validator does not independently discover new inputs.

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
   - `pg_query`, `PostgreSQL.*ERROR` → Postgres
   - `Microsoft OLE DB`, `Unclosed quotation mark`, `System.Data.SqlClient` → MSSQL
   - `ORA-\d{5}` → Oracle
   - `SQLITE_ERROR`, `SQLite3::`, `sqlite3.OperationalError`, or a
     Sequelize `dialects/sqlite/` diagnostic → SQLite

   `SQLSTATE` is shared across DBMSs, not a Postgres fingerprint. Sequelize
   alone identifies an ORM, not its dialect or the full query shape.
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

Phase 1 (baseline + syntax signal) and Phase 2 confirmation (boolean, controlled
error-based, bounded UNION-based and time-based) are standard non-destructive
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

- SQL injection has just been confirmed (SQLI-2 via an applicable Phase 2 technique) and the user hasn't yet said whether impact characterization is wanted,
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

A baseline capture is not a `baseline_request_ref` for replay. Never create a
replay reference from an observation ID. With no replay baseline, use the
evidenced Direct request shape under existing gates. Before comparison, define
the validation question and capture any necessary benign control in the active
attempt, unless a suitable owned control already exists. Pre-attempt responses
inform planning only; do not adopt/rebind them as owned proof. Taking a needed
control for a missing validation step is distinct from resending traffic to repair
a manifest or retrieve an omitted body. A matching seed, a predicate that retains
its intended truth value, and an observable response oracle are separate prerequisites.

**General rule: preserve the original request structure, and modify only
the candidate input.** This applies regardless of method or content type —
GET query string, POST form body, JSON body, path segment, header, or
cookie. Don't simplify a request down to just the parameter under test.

Follow the shared `http` tool contract and current Candidate validation context
for mode choice and replay/recapture rules. For a captured baseline use
`{"phase":"validation","candidate_id":"<candidate>"}`;
omit `mutation_value` and all selectors (`input_path`, `old_value`, `occurrence`).
For a JSON email probe, add a `mutation_value` different from the baseline and
`"input_path":"/email"`; adapt the selector to the actual Candidate input.

Do not drop `candidate_id` to repair a rejected replay. Inspect retained output
with `read_http_observation` before considering another request for unreadable
SQL diagnostics; readback adds no decoder. Recapture/rebinding follows existing
attempt/retest and permission gates. If required baseline or diagnostic content
remains unavailable, record the limitation and use `insufficient-evidence` when
it prevents assessment; preserve retry bounds and existing request provenance.

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

Before changing quote, parenthesis, comment or wildcard syntax, write down the query
shape supported by the latest database error (or `unknown` / a justified
hypothesis when ambiguous) and choose the next single probe
that distinguishes the remaining possibilities. Do not walk a punctuation
list (`--`, `-- `, `/*`, `')`, `'))`, and so on) one request at a time without
using the returned parser position/message. Cap syntax-shape adjustments at
three after the initial signal, which may already have occurred in Input Analysis.
The first confirmation request counts if it changes quote/parenthesis/comment/
wildcard structure. Phase changes, technique renaming and recapture do not reset
the allowance; neither a new Attempt nor Continue may be used to reset it.
Reconcile adjustments from executed requests, not self-labelled "adjustments",
`proposal.values` or a mislabelled ledger. Account for pre-attempt requests in
planning without adopting their unowned IDs as terminal proof. A benign control,
TRUE/FALSE predicate flip within the same syntax shape, and valid repetition are
not adjustments; a predicate flip that also changes syntax shape still counts.
Calling a request a benign control cannot exempt a syntax-shape change. All
techniques share this allowance, including error-based and bounded UNION-based.
This is guidance bookkeeping, not a new Runtime counter/schema. If adjustments
do not converge, use a different applicable bounded technique only with a distinct
evidence-supported plan; otherwise record the appropriate unresolved outcome.
`inconclusive` is not an outcome.

A SQL syntax-error fragment supports parser sensitivity, not the exact `LIKE`
clause, parenthesis balance, suffix, or constructed query. Without observed full
query text, keep those query-shape explanations as hypotheses. For SQLite, `--`
outside a string literal comments through the next newline or end of input;
a space after `--` does not terminate the line comment or restore its suffix.
This syntax note is not a new payload or a reason to send additional probes.

If a syntax probe produces no observable change, preserve that observation;
it does not establish SQL injection's absence. Continue only with an applicable,
context-compatible bounded Phase 2 plan and an observable oracle. A useful boolean
check can surface injection a syntax probe misses; unresolved compatibility is
not a reason to force a pair or cycle techniques.

**Quoted vs. numeric context — use observed SQL evidence.** A numeric-looking
input or a value rendered inside quotes elsewhere does not establish its SQL
position. When both positions remain plausible, a bounded quoted-string-style
and bare numeric comparison may help distinguish them; these requests count
toward the same syntax-adjustment limit, not a new budget. Record the supported
position or uncertainty in `injection_context`; do not force both variants when
parser evidence already rules one out.

When a captured database diagnostic shows the inserted value inside a SQL
string literal, keep that quoted-string hypothesis unless later observations
contradict it. Quote characters echoed in ordinary application text do not
establish SQL context. If the diagnostic omits the insertion point or admits
multiple shapes, retain an ambiguous context and state the alternatives.
After consecutive probes return the same expression-type error, compare their
captured diagnostics and reconsider the quote/input-position hypothesis before
another request. A type error is distinct from a syntax error, a successful-write
acknowledgement, and controlled SQL evaluation. Use the remaining syntax-shape
adjustments only for a discriminating context-compatible probe; do not restart
the allowance or require every technique.

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
but context still suggests injection), continue into validation. Choose the least
intrusive applicable technique from observed behavior, candidate context, available
capability and an observable oracle. Stop at the first clear, reproducible signal;
do not run every technique. Switch techniques only for a distinct evidence-supported
plan within the shared syntax allowance, not merely because the previous test failed.

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

When boolean probes fit the observed SQL context and offer a meaningful differential,
use this as one confirmation method, including after a clear error-based SQLI-1 signal: Phase 1
syntax sensitivity alone does not establish SQLI-2. It also applies when 1b
was absent or ambiguous but the surrounding context suggests an observable
boolean evaluation. A TRUE/FALSE pair is required for boolean confirmation,
not for every SQLi technique.

**Pair decision checkpoint:**

- Use the evidence-supported quoted-string, numeric or parenthesized context,
  or a justified hypothesis; full query reconstruction is not required.
- Choose a stable benign seed for the oracle: AND-filter tests normally need
  a known match; OR tests may use a nonmatching seed. Reuse suitable owned
  observations rather than repeating a baseline without a stability question.
- Check that both predicates retain their intended truth values after the
  surrounding prefix/suffix is applied. In `LIKE '%input%'`, a generic quoted
  equality can acquire a trailing `%` and cease to be TRUE. Account for wildcard,
  quote and parenthesis boundaries before treating a corpus example as a pair.
- HTTP 200 with identical TRUE/FALSE bodies does not prove that either predicate
  was evaluated as intended. If the seed/oracle is not established, the equal
  pair remains unresolved rather than automatically becoming a completed negative.
  `data:[]` does not prove the whole payload was treated as literal text or that
  the evaluator ran its predicate. Parser errors establish parser sensitivity.
- Do not force a FALSE request while compatibility remains unresolved merely to
  fill a pair. Report that the pair was not executed when only intended TRUE or
  syntax variants ran; a benign control, intended truth value and controlled
  evaluation are distinct. An unusable probe is not a reason to try another
  technique without a useful bounded plan.

Use the `PHASE 2 — VALIDATION` section of `payloads.txt` as context-adapted
examples. Send otherwise identical TRUE/FALSE requests with the baseline's
request structure and authentication; change only the predicate within the pair.

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
Identify whether the seed/oracle, predicate compatibility or another prerequisite
is unresolved. Continue only with remaining budget and a new discriminating test;
all syntax adjustments share the existing three-adjustment limit. Do not repeat
an effective request without a specific stability/repetition or missing-validation
reason. Identical bodies/ETags alone do not establish caching or quote rewriting.
If no useful bounded test remains, apply the outcome rules below: unfinished or
unsupported context/proof stays unresolved; a completed bounded negative needs
usable observations and registered proof. Do not force another technique.
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

Use when evidence supports an engine-compatible delay and timing oracle within
resource limits, typically at a blind, non-reflective sink. An unusable boolean
pair is not a prerequisite. The `PHASE 2 — VALIDATION` section
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
fingerprinted or suspected engine is SQLite, skip 2b; select another applicable
Phase 2 plan only with supporting context/oracle, or retain the limitation.
Do not attempt to force a delay via recursive/heavy queries, as
that risks unintended load or denial-of-service on the target.

### Error-based controlled evaluation

Prerequisites: evidence-supported expression position, compatible DBMS behavior
and a response oracle that can distinguish an evaluated result from input echo
or parser diagnostics. Use a suitable owned benign control; plan one bounded,
non-sensitive constant-expression test and its falsifier. The error must expose
the computed result, absent from the control and not merely reflected request
text. Repeat the positive to establish reproducibility under the same context.
Parser sensitivity or differing syntax errors alone remain SQLI-1. Stop at
repeatable controlled evaluation (SQLI-2), or record the missing oracle/context
as unresolved when no useful bounded plan remains. No schema/table enumeration,
real-row reads, credentials or session material; fingerprint reads remain Phase 3.

### Bounded UNION-based controlled evaluation

Prerequisites: a compatible SELECT/projection hypothesis, already known projection
shape and an observable non-sensitive output slot. Do not discover column counts
or types by a sequence of UNION guesses. With an owned benign control and the
shared allowance, test only a bounded constant expression whose computed marker
is distinguishable from reflected text and ordinary rows. A synthetic computation
such as `7 * 7` illustrates evaluation; echoed `7 * 7` alone is not that oracle.
Reproduce the evaluated result under the same context before SQLI-2 confirmation.
Keep controls, errors and positives separate; a success/error contrast is not a
Boolean pair. Stop at the repeatable bounded proof. If projection compatibility
or the oracle is unknown and no discriminating bounded test is justified, retain
that limitation as unresolved. Never enumerate schema/tables, extract real rows,
credentials or session material. Version/banner reads still require Phase 3.

Both paths use existing `record_evidence` and `record_result` contracts with usable
owned observations, registered proof and the applicable repeatability evidence.
The Boolean `confirmation` pair schema and four-observation threshold apply only
to Boolean confirmation. These paths do not lower SQLI-2 or authorize Phase 3.

### 2c. WAF / rate-limiting check

If any Phase 1/2 probe comes back as `403`, `429`, a generic "request
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

If the applicable, context-compatible bounded Phase 2 tests complete with an
established oracle but without a clear, repeatable
signal — including when 2d was unavailable and therefore not attempted — record
`not-confirmed` with usable primary evidence and registered proof. This is a
bounded negative result, not proof that the endpoint has no SQL injection.
An unresolved oracle or predicate compatibility remains `insufficient-evidence`,
even when the syntax-adjustment allowance is exhausted and all captures are complete.
If testing is blocked, unfinished, or its required sources/proof are unavailable,
use the corresponding unresolved outcome below rather than forcing a terminal
assessment or escalating technique/payload variety.

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

Every meaningful attempt records one outcome; an explicit later retest may add
a new result for the same Candidate. Terminal assessments and unresolved closure
have different meanings:

- `confirmed` with `SQLI-2` in `techniques` — an applicable technique actually available in this environment (boolean, error-based, bounded UNION-based, time-based, or OOB only when its capability and authorization gates pass) produced a clear, repeatable positive signal, bounded per "Bound the proof" above;
- `confirmed` with `SQLI-3` in `techniques` — SQLI-2 plus a minimal, authorized impact probe from Phase 3 succeeded;
- `not-confirmed` — applicable, context-compatible bounded tests completed with an established oracle and none produced a clear, repeatable SQL injection signal. This does not mean every technique must be run. Unresolved predicate compatibility or syntax context requires `insufficient-evidence`; exhausting syntax adjustments alone does not complete a negative test. OOB is included only when its capability check passed and the user authorized it;
- `blocked` — a probe was intercepted by a WAF, rate-limiter, or challenge page before reaching the application (step 2c); the application itself was never actually tested;
- `deferred` — work is postponed, or behavior indicates NoSQL/operator injection
  rather than SQL injection (per Scope, above); put the reason in `deferred_reason`;
- `insufficient-evidence` — the oracle, predicate compatibility or necessary context remains unresolved, or required sources or reproducible proof are unavailable;
  explain the limitation. This closes the attempt as unresolved, without claiming
  a negative test or completed validation.

`confirmed` and `not-confirmed` require an accepted terminal ValidationResult,
registered immutable proof and usable primary observations. `blocked`, `deferred`
and `insufficient-evidence` close the attempt as unresolved and keep its work
outstanding; unavailable proof/source references may be omitted. Runtime also
supports `browser-required` and `authorization-required` when those prerequisites
block validation. None of these unresolved outcomes is eligible for a finding.

### Evidence-to-decision checkpoint

Immediately before registering proof and submitting any terminal assessment,
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

Counterexample: TRUE and FALSE both return HTTP 200 with
`{"status":"success","data":[]}`, then syntax adjustments return HTTP 500 with
`SQLITE_ERROR: incomplete input`. Separate these in the proof:

- **Observed facts:** equal empty responses and syntax errors; no boolean differential.
- **Working hypothesis:** a wildcard, quote, parenthesis or suffix may explain
  the responses; none establishes the full query shape or predicate evaluation.
- **Unresolved limitation:** the oracle is not established and controlled SQL
  evaluation is unproved. Record `insufficient-evidence` when no useful bounded
  test remains; do not turn this into SQLI-2 or a completed negative.

Recheck mutation/cleanup bookkeeping for the entire attempt, including
baseline successful-write acknowledgements, under the state-changing endpoint
contract above. Record readback limitations and honest cleanup state.

Immediately before `file_write`, reconcile each claim with the existing compact
baseline/control/probe ledger: source/reference (observation ID), effective
method/endpoint URL, redacted request payload, HTTP status, response media type,
body marker/excerpt, capture flags (completeness/truncation and execution status)
and claim confidence. Observations/documents actually read take precedence over
conflicting LLM summaries. Keep direct observation, observed from specification,
inference/hypothesis and unknown distinct in prose, without new Workflow fields.
Request Content-Type is not response Content-Type. JSON product results do not
show a SQL statement, and parser diagnostics do not prove full query shape or
controlled evaluation. The runtime
HTTP evidence envelope supplies the effective request preview, including replay
changes; `request_preview_complete: false` means unseen request text remains
unknown. A source ID or request hash alone does not recover a payload or body.
Record `request_mode`, `request_hash`, and `baseline_request_ref` when supplied.
`body_representation` describes retained response bytes, not request equivalence.
A Direct HTTP observation with a different request identity is a separate request,
never a decoded version or equivalent replay of the captured request. Document
observed differences in headers, credentials and non-candidate fields; do not
infer their preservation from the same URL, payload or Candidate/Attempt owner.
Encoded response bytes are not decoded SQL diagnostics. Readback preserves the
retained representation; it does not add a missing content decoder.
Retained response completeness, ranges read and content still in context are
separate; Content-Length is not bytes inspected. Status 200, HTML media type,
a filename or metadata-only capture proves neither body review, SPA calibration
nor operation success. Reuse trustworthy visible sources; list/read only missing
metadata or ranges through an available permitted API with real references.
If bytes cannot be retrieved, record that limitation rather than reconstructing
them from intended payloads, Markdown proof or conversation memory; never refetch,
raise caps, cache-bust or switch to shell just to recover content. Keep proof
concise, redacted and attributed in the existing artifact, without an extra ledger
or mandatory artifact for every response. Check every claimed repetition against
distinct executed observations: repeating a sentence, registering another
snapshot or reusing an observation ID does not establish repeatability.

Before writing proof and calling `record_evidence` / `record_result`, reconcile
the outcome and every countable claim against that owned ledger:
successful exploit executions, complete positive repetitions, controls and errors.
Reconcile syntax allowance used/remaining from executed requests since the initial
signal across phases and techniques. Never write exhausted when allowance remains;
state the actual stop reason without forcing its consumption. Intended probes are
not established controls or positives until the observations support those labels.
Keep Candidate status, ValidationResult outcome, goal status and finding eligibility
separate; quote canonical state when available. Phase 3 is not eligible without
SQLI-2 and its separate authorization; `insufficient-evidence` is not `not-confirmed`.
Use the effective request and actual response to assign each proof label
(`control`, `positive`, `error`, `incomplete`); do not copy a label from an earlier
LLM summary or change the controller's source association. A complete control
cannot become an exploit repeat because its observation ID was cited alongside
a positive. HTTP 200 alone does not identify a successful exploit. Keep syntax
errors separate from evidence of controlled evaluation.
Partial product responses do not establish a full catalog. HTTP 200 does not prove
SQL parsing/evaluation; equal empty bodies do not establish literal handling,
default-deny behavior or SQLi absence. Keep these explanations hypothetical unless
a discriminating observation supports them.

For example, one complete UNION positive, two complete benign controls and one
truncated UNION positive support counts of one complete positive and two controls.
They do not support "two successful complete exploit repetitions" or "two TRUE
and two FALSE executions". Keep the truncated positive in the ledger as an
incomplete capture; do not count it as a successful complete repetition or append
it to a sufficient terminal manifest. Reconcile repeatability using the applicable
technique's existing requirements. There is no fixed observation count for every
SQLi technique; this checkpoint does not alter validation or evidence admissibility.

Before choosing primary sources, check current candidate/attempt ownership,
capture flags and support for each claim. Metadata-only captures cannot prove
response content. After an admissibility rejection, inspect already captured
usable observations first. If the primary parent set changes, correct the
candidate entry and every dependent claim/excerpt, then call `record_evidence`
with the correct `observation_ids` to register a new immutable snapshot. Replace
`evidence_refs` before resubmitting; removing an ID from `record_result` alone
does not repair its derived proof. Never edit registered snapshots in place or
reuse a source from another attempt. Following the loader preface, retry at most
once with usable existing evidence, within the remaining recovery budget; this
instruction does not change the runtime retry ceiling. Do not reset the budget or
send new HTTP probes solely to repair a manifest. If a valid repair is unavailable, record
`insufficient-evidence` and stop.

### Standard result entry template

Optionally export every persisted candidate result to `artifacts/sql-injection/<target>/results.md`
using this exact template, one entry per candidate, appended in the order
tested:

```markdown
## Candidate: <endpoint> [<method>] — param: <parameter> (<location>)

- **candidate_id:** <structured Workflow Candidate ID>
- **timestamp:** <ISO 8601 UTC timestamp when this entry was recorded, e.g. 2026-08-27T09:14:32Z>
- **agent_session_id:** <identifier for the current agent run/session, for audit-trail correlation with logs elsewhere>
- **outcome:** <confirmed | not-confirmed | blocked | deferred | insufficient-evidence | browser-required | authorization-required>
- **techniques:** <SQLI-2 | SQLI-3 | technique attempted>
- **deferred_reason:** <required when outcome is deferred>
- **sqli_level:** <1 | 2 | 3 | none>
- **engine:** <mysql | postgres | mssql | oracle | sqlite | undetermined | n/a>
- **technique(s) tried:** <e.g. 1b syntax sensitivity, boolean-based, controlled error-based, bounded UNION-based, time-based, gated OOB — list only executed techniques, mark which produced the result>
- **structured confirmation:** <for boolean SQLI-2: shared request template, distinct TRUE/FALSE predicates, and both paired observations from at least two repetitions>
- **evidence:**
  - baseline: <status/size/timing/marker>
  - probe result: <status/size/timing/marker, or literal error string>
  - repeated: <yes/no — required for 2a/2b/2d positives>
- **injection_context:** <e.g. "appears to be inside a quoted string in a WHERE clause" | "unquoted numeric context" | unknown — inferred from behavior, not confirmed query text>
- **order:** <first-order (reflected same request) | second-order-suspected — describe trigger path if second-order>
- **phase_2d_used:** <yes/no> — if yes: <callback domain used, token, result>; if no because the capability wasn't available, note that explicitly here too
- **phase_3_status:** <not attempted — state unmet SQLI-2/authorization prerequisite | authorized and run | authorization declined | not needed — existing evidence sufficient>
- **notes:** <anything else relevant — WAF behavior, session issues, ambiguous signals, "OOB unavailable (no OOB callback tool in this environment)" when applicable>
```

This is the durable record of what was actually tested and what was found,
independent of whether anything gets turned into a finding. The
`timestamp` and `agent_session_id` fields exist purely for audit
traceability — they don't affect gating or outcome logic. Populate them only
from runtime-supplied values. If the exact timestamp or session identifier is
not exposed, write `unavailable`; never invent a plausible value.

## Confirm an evidence-backed finding

`sql-injection` records accepted results with immutable evidence references. For each
candidate whose canonical outcome is `confirmed` (with `SQLI-2` or `SQLI-3`
recorded in `techniques`), call
`confirm_finding` to persist the canonical finding:

```
sql-injection → accepted ValidationResult + immutable proof → confirm_finding → final finding
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

- Verify counts from complete retained data before proof/result/finding submission;
  repeated captures do not add distinct records. Do not resend HTTP just to count.
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
context, proof scope, and any separately authorized Phase 3 evidence in the
registered proof and optionally exported `results.md` so the finding remains auditable. Do not fill in a rewritten,
drop-in query fix — the general remediation category above is appropriate;
a concrete query rewrite is not, since you don't have the application's real
query.

When a login differential naturally returns an administrative session token,
describe the demonstrated impact as `obtained a valid administrative session
token` or `administrative authentication bypass`. Do not claim full
administrative access or account takeover unless a separately authorized
workflow actually validated that access against administrative functionality.

Do not call `confirm_finding` for `not-confirmed`, `blocked`, or `deferred`
candidates, or for any other unresolved outcome such as `insufficient-evidence`,
`browser-required` or `authorization-required` — they remain recorded as
ValidationResults. Do not reuse the recon
target identifier as a finding file name or hand-roll a different finding
format; `confirm_finding` owns canonical finding persistence and naming.

## Stop conditions

Stop probing a candidate when its bounded testing reaches a recorded outcome.
Accepted terminal work is resolved by the runtime contract above; unresolved
outcomes stop probing but remain outstanding. Persist required confirmed findings
and resolve cleanup and coverage before describing validation as complete.

Do not: scan for new candidates, run automated SQLi tools by default,
extract real data or credentials, chain into other vulnerability classes,
retry blocked probes with filter-bypass or encoding tricks, run Phase 2d
when the capability check fails or without its own explicit, separate
authorization, simulate OOB callbacks with `shell` or any other
workaround, run Phase 3 without its own explicit authorization, use a
public/shared OOB service without user confirmation, or keep escalating
payload complexity on a candidate that already gave you a clear negative
result.
