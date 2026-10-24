# lan-07: remaining-failure audit and offline fixes

This audit reads `experiments/scenario3/runs/lan-07/` without changing it.
It does not replay traffic, call a provider, or infer application internals from
the application name. Existing lan-06 worktree changes are preserved.

## Sources and authoritative outcome

- Debug events: `logs/session.jsonl` in the run directory.
- Session: `profile-home/.kagent/sessions/fbf1ddcd-78cf-4c94-b6e8-13d5e84b08e1.json`.
- Captures: `project/.kagent/observations/fbf1ddcd-78cf-4c94-b6e8-13d5e84b08e1.json`.
- Snapshotted playbooks, payload corpus, and generated Markdown in `project/`.
- The user's pasted transcript, reconciled against the above rather than treated
  as a workflow receipt.

The input-analysis and SQLi playbooks saved with the run exactly matched the
working files before this audit's edits. Debug logging dropped 442 records
(9 + 136 + 166 + 131). Outbound provider request bodies/schemas are not archived;
an exact reconstruction of everything the model saw is therefore unavailable.
Saved `start_validation` responses intentionally omit transient
`validation_context` on persistence; that omission does not prove the live
response lacked it.

The durable outcome is **incomplete**, with one unresolved SQLi candidate and
no finding. The runtime reached 60 outer iterations: 60 agent-loop calls and
one tool-free final synthesis, with no compaction model call. These are saved
run counters, not calls made during this audit. There are 55 native HTTP
observations in the saved store; four belong to the validation attempt.

## 1. file_edit: conflicting advice, correctly rejected execution

At iteration 43, seq 958, the model requested `file_edit` to change the candidate
artifact totals from zero dropped/two blocked to two dropped/zero blocked.
Seq 959 rejected it before dispatch. The only active skill was
`web-input-analysis`, whose contract allowed `shell`, `http`, `file_write`, and
`workflow`; neither `file_edit` nor its alias was allowed.

Registration, advertisement, and execution are different here:

1. The standard registry contains both file editors and their aliases. Before
   skill restriction, these tools can appear in the initial schema inventory.
2. `_prepare_turn_request` refreshes `_workflow_request_view` on every normal or
   malformed-retry request. That projection uses `is_tool_allowed` with
   `capability_only=True`; a registered `FileEditTool` requires permission and
   is omitted while only input analysis is active. Alias canonicalization gives
   `FileEditTool` the same restriction. `file_write` remains advertised.
3. Execution checks `is_tool_allowed` again, before the registry's independent
   permission/resource gate. That is the rejection actually observed in lan-07.
   YOLO did not bypass it.

Offline production projections reproduce this distinction. There is no evidence
of a current projection bug advertising the editor during input analysis, and
no archived outbound schema with which to prove such a historical bug. A model
can still return a withdrawn or remembered tool name.

There was a verified instruction conflict: the full base prompt unconditionally
said to use `file_write`/`file_edit` for canonical artifacts and preferred
`FileEditTool` for repository work. The playbook said to write the artifact but
did not explain the permitted update path. The model chose the unavailable
editor, then spent iterations 44 and 45 on shell/perl replacements. Those shell
calls succeeded locally; they neither widened target scope nor created native
HTTP evidence. The first replacement also failed to update the multiline
blocker paragraph, requiring the second call. The final per-input artifact
entries still described the B2B inputs as blocked even though totals and
structured dispositions said dropped.

**Fix:** qualify native file advice by the active contract in both prompt
profiles; explicitly use existing `file_write` overwrite behavior when the
editor is unavailable. The analysis playbook requires reconciling totals,
per-input entries, and handoff state. No tools or allowed-tools entries changed;
no permission or filesystem gate changed. Tests verify both schema exclusion
and dispatch rejection, then exercise artifact rewriting through `file_write`.

## 2. blocked B2B inputs: premature completion, valid operator branch

At iteration 34 the documented order endpoint returned 401 for a missing
Authorization header. Iteration 35 correctly set both inputs to `blocked`.
After disposing the other three inputs and writing the artifact, iteration 39
nevertheless called `complete_skill`. Seq 881 returned `PHASE_NOT_READY`:
input analysis cannot complete while an input is pending or blocked. Writing
the artifact and an autonomous objective do not satisfy this gate.
The playbook already required leaving a blocked phase incomplete: the attempt
to close it was a planning failure, not a missing admission check. The short
action guidance supplied only generic readiness advice, without the concrete
missing-input/exclusion recovery branch.

Iteration 40 then tried a guessed login and an invalid bearer token; both
returned 401. Neither supplied the missing authorized B2B session. A malformed
token's rejection does not demonstrate verification of a valid RS256 signature
or prove the field's downstream processing. The auth limitation is real, but
the final summary's implementation claim is stronger than these requests prove.

The existing disposition contract supports:

- `analyzed`: actual triage, not a claim of exercised field behavior;
- `blocked`: a current unmet prerequisite; resolve it and reanalyze the same
  input in the same objective;
- `dropped`: a reasoned exclusion from the current analysis, preserving the
  untested limitation; it is terminal for that input record.

The original whole-target request did not exclude authenticated inputs. Missing
credentials alone cannot justify dropping them to admit a public candidate.
There is **no unconditional autonomous path past this dependency** under that
request. The agent can finish independent pending triage and report blocked.
An already explicit unauthenticated-only boundary could justify exclusion;
this run did not have one before the question.

`ask_user` is a non-permission tool and is available even though not listed in
this skill's allowed-tools metadata. It gathers missing input or a workflow/
scope choice; it is not an action permission prompt and YOLO cannot answer it.
At iteration 41 the actual answer was **“Mark them out of scope for now.”**
That supports this assessment's exclusion; it is not an independent statement
about whether credentials exist generally. The model changed both same input
records to dropped at iteration 42. Input analysis completed at iteration 46,
then SQLi loaded at 47 and validation started at 48. Admission was preserved.

**Fix:** current blocked-input guidance now says to finish independent triage,
avoid guessing credentials/tokens, ask once for missing input or explicit
operator exclusion, and otherwise keep blocked/report incomplete. The skill
explains the same branch before completion. The runtime transition and phase
gates are unchanged. An offline regression keeps both completion and validation
blocked until the simulated operator chooses exclusion; no credentials or
HTTP requests are needed for that branch.

## 3. SQLi: real evidence insufficiency plus avoidable planning and runtime loss

Candidate: `cand_7c6872943e4564329cb5`.
Attempt: `attempt_6b5916494a2346b9b90e4a777f60773a`.

The skill loaded at iteration 47 and the attempt started at 48, leaving only
iterations 49–60 for inventory, captures, review and finalization. The bound is
per invocation, not a fresh 60-step allowance for each validator.

The analysis observations preceded the attempt and remain unowned. The empty
owned inventory at iteration 49 was correct, not lost traffic. The prior
search for two single quotes (`''`) returned product 37 whose description contained
an apostrophe (`80's coolness!`); treating that search match as an established
SQL breakout or known predicate shape was unjustified. It could inform a
hypothesis, not prove injection or supply terminal owned evidence.

The complete owned ledger is:

| Iteration / call seq | Observation | Decoded q | Result |
| --- | --- | --- | --- |
| 50 / 1083 | `obs_a661b91b8b294cd69806fe320310fff8` | `qwerty' AND '1'='1` | 200, 30 bytes, empty data |
| 51 / 1117 | `obs_38e1798433c44299a4763328cfb5da20` | `'' AND '1'='1` | 500, 974 bytes, SQLite syntax error near `1` |
| 52 / 1154 | `obs_d7486287ed3d41fe858f099ac763f33a` | `' AND '1'='1 AND '%` | 500, 974 bytes, SQLite syntax error near `%` |
| 53 / 1197 | `obs_2efde712b1d84431a2dcfeaa88913f6e` | `' AND '1'='1 AND '%'='` | 500, 974 bytes, SQLite syntax error near `1` |

All four are completed, complete, untruncated captures with the same current
candidate/attempt ownership. There are **three error observations, two distinct
error bodies**, not three distinct errors: observations two and four share
response hash `9814f5fc052878282331df029c03c6f7857e1ef0d83a9c6f84759e60d5b775a2`.
The `%` diagnostic has hash
`13198662eb16e0b2e53122b4fbc306ff5c337ec9587e8c6316643f186898dc29`.

No FALSE request was sent. There was no established matching benign control
inside the attempt, no completed pair, no repeated pair, no timing experiment,
and no error containing an evaluated controlled expression. The first request
also carried a predicate but returned 200 empty, so “every predicate-bearing
probe died at parse time” is false. An empty result does not show its predicate
was evaluated. SQLite parser positions identify diagnostics, not the full SQL
statement, exact LIKE literal, suffix, parenthesis balance, or SELECT shape.

The genuine outcome is SQLI-1/parser sensitivity with unresolved SQLI-2.
`confirmed` was unsupported. A completed `not-confirmed` was also unsupported
because the oracle/context and bounded test were unfinished. Insufficient
evidence describes this ledger accurately; it does not prove that successful
confirmation was impossible within the original bounds.

### Planning and tool use

- The first AND attempt used an arbitrary nonmatching seed. The existing
  playbook already required a known match for an AND filter and warned that
  LIKE suffixes can invalidate quoted equality examples. No clean owned benign
  control or explicit prefix/predicate/suffix plan preceded the probes.
- After the first syntax error, the model asserted a quoted LIKE context from
  `near "%"` alone, then made further speculative syntax changes. No complete
  query text was captured. The three-adjustment allowance is playbook guidance,
  not a persisted runtime syntax counter. The model declared “3 of 3” used;
  there were three changed probe shapes after its first attempted TRUE request.
  Do not describe max_steps as proof of a runtime-enforced syntax debit.
- Only at iteration 54 did it read `payloads.txt` (`limit=120`), followed by the
  correct published continuation at 55 (`source_ref=sf_0c86b1720b2a407db663a22add5bbc66`,
  `start_char=8234`, `limit=60`). The pages covered characters 0–8234 and
  8234–12609. The second contained boolean guidance. “Truncated” meant the
  remaining corpus was paginated, not that the chosen section was unavailable.
- Iterations 54 and 56 used `record_attempt_state` twice, with the same
  no-mutation/cleanup disposition, largely to store engine/context commentary.
  This action is effect bookkeeping, not a general notes log.
- Iteration 57 reread the complete last error body. At 58 it read the first
  700 of 974 characters from each of two other errors; at 59 it read the 30-byte
  empty response. These were permitted local reads, not recaptures. The two
  reader pages were clipped while the underlying captures remained complete.
  Their full bodies had already been returned with the original HTTP results.
  No evidence-admissibility rejection required this extra readback.

**Guidance fix:** make the existing ordering prominent at validator entry:
read the applicable corpus before confirmation, choose a supported seed/oracle
and hypothesis, capture the needed owned benign control, and stop speculative
syntax work when its allowance is spent. Use another technique only for a
distinct evidence-supported bounded plan. Reuse complete visible captures;
reserve existing turns for proof registration/result submission. No payloads,
confirmation thresholds, technique gates, or limits changed.

### Confirmed runtime progress mismatch

Whole-target used `record_iteration` for validation, unlike Direct's existing
`record_validation_batch`. Thus the valid new payload pages at 54 and 55,
repeated effect declaration at 56, and observation read at 57 all counted as
no progress. At the fourth consecutive iteration the runtime set
`probing_stopped=true` and gave the remaining existing iterations to local
finalization. This stop was anti-stall, not permission denial, evidence-repair
exhaustion, or a SQLi semantic decision.

**Runtime fix:** Whole-target's validation phase now reuses the existing
validation batch tracker. New source-bound ranges receive the same credit as
Direct; overlapping/repeated ranges and EOF do not. Pagination does not renew
HTTP exploration allowance. Discovery phases retain their prior tracker.
The red regression stops probing during fresh pages only in Whole-target;
after the fix, both modes credit five distinct pages, and four unchanged
rereads still stop probing. The 60-step hard limit, finite exploration
allowance, ownership checks, and recovery bounds remain intact. This corrects
premature anti-stall accounting; it does not guarantee the historical plan
would have confirmed or finished before max_steps.

## 4. Proof path, result ID, and final summary

Iteration 60 / seq 1385 wrote
`artifacts/sql-injection/127-0-0-1-8081/proof-products-search-q.md` (3,639 bytes).
It exists, but **there was no `record_evidence` call**. Workflow State has no
EvidenceArtifacts or evidence-source links for it, and no immutable registered
snapshot. A file path is not an `ev_` reference or a ValidationResult.

After that last iteration, seq 1388 used the controller-generated call ID
`terminal-closure-None-attempt_6b5916494a2346b9b90e4a777f60773a` to submit
`record_result`. The transcript's “Runtime action: record unresolved validation
disposition” was runtime closure, not the model finishing its proof flow.
The successful response at seq 1389 created:

- result ID: `result_071525bd75734ee9a468b1200626366a`;
- outcome: `insufficient-evidence`;
- reason: `Validation stopped (max_steps); no admissible conclusion/proof was committed within bounded validation`;
- `evidence_refs=[]`, `techniques=[]`, `repeatable=null`, `confirmation=null`;
- four native sources in the evidence manifest, inherited from the owned effect
  declaration, but `assessment.artifacts=[]` and `artifact_sources={}`;
- coverage sync not applicable, candidate deferred, attempt unresolved;
- no persisted finding and no accepted terminal assessment.

Offline deserialization verifies the stored candidate binding and result seal.
`accepted_result` returns false for this unresolved outcome, as designed; the
runtime did not certify a positive or completed negative. A committed unresolved
result can be valid bookkeeping without accepted terminal proof.

The final summary was correct about incomplete status, no finding, and no
repeatable boolean evidence. The proof path and result ID were both real.
However, presenting them together as “Proof recorded …; result …” obscured that
the file was unregistered and the result did not reference it. Its assertions
of three distinct errors, every predicate failing parsing, a proven LIKE
position, and enforced valid RS256 verification also exceeded the saved facts.
The proposed follow-up is a plan requiring current admission, not a completed
test or authority to reset an existing allowance. GET errors on other routes
do not establish their correct write methods or bodies.

**Fix:** tool-free synthesis now refreshes the existing bounded workflow
projection after terminal closure/checkpoint. Previously it retained the last
tool-bearing projection, which could still show an active attempt and omit the
new result, although the closure response and goal summary were present.
The reporting instruction explicitly separates a local unregistered file,
registered evidence, accepted result, and runtime stop disposition. Regressions
exercise both Direct and Whole-target with a real local file, no registration,
runtime max-step closure, and the fresh result ID/empty evidence references.
No historical result is changed or upgraded.

## Verification and lan-08 readiness

The new regression file is `tests/agent/test_lan07_audit.py`. Before fixes it
reported **7 failed, 1 passed**: two artifact guidance cases, blocked-input
recovery guidance, Whole-target reader progress, both synthesis refresh cases,
and validator ordering guidance failed; Direct pagination already passed.
After fixes: **8 passed**. Guidance assertions inspect normalized loaded
instructions; behavior tests use production dispatch and local fake responses,
not an independent SQLi classifier or a model reliability test.

The first focused responsibility suites passed: **357 passed**. The full offline
sweep (excluding `tests/live`, with live/model/container opt-ins unset) reported
**8,758 passed, 11 skipped, 5 failed**, with two existing config-sanitization
warnings. Three failures exposed additional prompt-size/admission interactions:
the artifact wording triggered compaction in two near-threshold fake-client
scenarios, and the reporting instruction affected a tiny-budget synthesis with
no workflow. The final wording is shorter, and reporting reconciliation is now
conditional on an actual workflow projection. The context budget is unchanged;
the affected tests were not weakened or edited.

The other two sweep failures were mounted Textual timing assertions:
`test_c4_proposed_postread_passes_unchanged_mounted_oracle` observed only one
recovery tick, and `test_production_boundary_keeps_textual_responsive[evidence_snapshot]`
observed a 224 ms heartbeat gap. Both passed unchanged on follow-up, together
with the corrected deterministic failures. That follow-up responsibility group
reported **243 passed**. This is evidence of timing-sensitive test behavior,
not a reason to loosen its assertions or change persistence logic in this task.
The initial full sweep is not described as an all-green run.

The final offline responsibility-group run passed **4,138 tests** in 290.19 s,
including all Agent, skill, integration, tool, state and LLM tests plus the
SQLi evidence guidance, evidence-repair guidance and recovery-contract suites:

```bash
env -u KAGENT_RUN_LIVE_TOOL_CHARACTERIZATION \
    -u KAGENT_S1_EXISTING_CONTAINER -u KAGENT_SYSTEM_LIVE \
    venv-linux/bin/python -m pytest -q \
    tests/agent tests/skills tests/integration tests/tools tests/state tests/llm \
    tests/security/test_sqli_evidence_guidance.py \
    tests/security/test_trial1_evidence_guidance.py \
    tests/security/test_evidence_recovery_contract.py --tb=short
venv-linux/bin/pyright
git diff --check
```

Full Pyright was rerun after the final production edits: **0 errors, 0 warnings,
0 informations**. `git diff --check` passed; the diff, new files and final
`git status --short` were inspected. No packages were installed and no tests
or runtime limits were relaxed. No model/provider API or live target was
called, and nothing was committed, staged or pushed. The full sweep's 11 skips
and excluded live suite were kept; no live characterization was enabled.
The unrelated lan-06 edits and the separately appearing document/output files
were left alone.

Hash checks found the saved assessment/session/observations/skills/artifacts
unchanged. A separate running process continued appending periodic
`context_snapshot` events to `logs/session.jsonl` and replacing its diagnostic
context Markdown. The original log is intact as a byte-for-byte prefix; all
appended events inspected were context snapshots. This task performed no writes
to the historical run and did not restore those external updates.

Readiness is conditional: these verified controller/guidance defects have
offline coverage; lan-07 remains unresolved. A future lan-08 must start with
current skills/code and its own authorized session, choose an honest blocked
or operator-exclusion branch, plan its bounded validator before consuming
adjustments, and distinguish proof registration from result creation. No live
run was requested or performed. Model adherence and actual target confirmation
remain unverified; the audit supplies no target-specific winning payload.
