# lan-20/21 remediation inventory

Historical run directories and pasted transcripts are evidence, never patch targets.
Severity below is engineering priority, not a vulnerability severity claim.

| ID | Evidence / root cause | Owner / priority | Minimal remedy / regression | State |
|---|---|---|---|---|
| W1 | lan-20 event 1058; whole-target admission requires global analysis marker | Workflow / high | Admit a compatible analyzed input with canonical handoff after Recon/Enumeration; retain blocked objective obligations; early/late blocker tests | runtime + regression |
| W2 | lan-20 events 1008–1187: queued candidate actionable despite admission failure | State/Planner / high | Project current admission into actionable work and prioritize admitted candidates over blocked analysis; no mutation by planning | runtime + regression |
| W3 | lan-21 events 916–920: last blocked disposition immediately triggers tool-free synthesis | Agent / high | Bounded operator/handoff opportunity within existing max_steps; no retries or synthetic candidates | bounded runtime + regression |
| W4 | lan-20 answers 1051 and 1186 differ; exclusion not committed at hard limit | Ask/Analysis / medium | Preserve actual answers, no automatic exclusion or repeated pressure; same dependency asks once; budget and cache tests | session cache + guidance + regression |
| E1 | lan-20 obs_02a88d… is POST/500/HTML, described as GET/JSON baseline | Evidence/guidance / high | Checked observation context and explicit comparison identity; never parse arbitrary Markdown as a SQL classifier | checked facts + regression; prose limit retained |
| E2 | lan-21 search variation and identical invalid-login responses described as SQLi-ready | Analysis / medium | Consumption/control distinct from class hypothesis and confirmation; adverse-evidence guidance regression | guidance + contract regression |
| D1 | Retained JS obs_cd3875… / obs_3e68ad… contains API call sites despite vendor-only claim | Enumeration / medium | Inspect bounded network-call context; retain unresolved API base/imports; no fabricated fields or requests | bounded reader + guidance + regression |
| D2 | Password, documented arrays and query field omitted from structured handoff | Enumeration/Analysis / medium | Record evidenced names/types independently of sink/scalar assumptions, redact values; array handoff and delivered-guidance regressions | guidance; existing registration contracts retained |
| D3 | Numbered source flow competes with adaptive guidance; 40/21 enumeration turns | Enumeration / medium | Conditional multi-source branches, explicit value/stop rule, no mandatory Swagger/source checklist | guidance + contract regression |
| R1 | Repeated shell/source reads, cap escalation, main.js refetch, repeated B2B auth failures | Guidance/readers / medium | Reuse visible ranges and next offsets; stop same auth dependency; bounded-source regressions | bounded reader + guidance + regression |
| A1 | lan-21 locator /spec.swaggerDoc differs from options.swaggerDoc | Attribution / medium | Exact visible binding, no inference of verified extraction from manual locator; fixture grounding | guidance; manual locator remains declared |
| A2 | /ftp SPA claim, operation count, route/status summaries conflict with observations | Artifacts / medium | Evidence-first reconciliation and explicit counting unit; avoid automatic semantic validation claims | guidance; semantic verification remains manual |
| A3 | LIKE/query shape and before-body-parsing assertions exceed response evidence | Analysis/validation / medium | Keep implementation/order hypotheses unknown; preserve SQLI-1/SQLI-2 thresholds | guidance + contract regression |
| G1 | Skills/planner/action hints repeat global barriers and source procedures | Shared guidance / medium | Synchronize per-input contract and shorten duplicate source instructions; contract tests | synchronized + regression |
| L1 | Missing B2B JWT, browser/dynamic-JS limitations | Capability / limitation | Preserve blocked/unknown; no token guessing, new adapters, or permission changes | retained |
| V1 | HEAD reproduces budget-visibility test failure: relative proof.txt resolves outside the test profile before the budget gate | Verification fixture / low | Use the exact in-profile tmp_path; retain policy-block, session-impact, no-write and consumed-budget assertions | fixture corrected; no production gate change |
| V2 | Full-suite heartbeat gap 124.18 ms ended before operation entry; identical HEAD measurement code includes startup intervals | Verification oracle / medium | Anchor the gap window at operation entry; preserve raw timeline, 120 ms threshold, real heartbeat/recovery counts and blocking positive control | HEAD deterministic RED -> 48 related tests GREEN; no Runtime change |
| V3 | Full suite reads 120-column geometry immediately after requesting 45x24; Textual resize is timer-debounced | Verification fixture / low | Wait for the requested compositor frame with a bounded timeout, then drain layout; retain every geometry/selection/scroll assertion | HEAD delayed-resize RED (2 failures) -> 26 related tests GREEN; no production UI change |
| U1 | No confirmed SQLi, full query, handler order or live improvement measurement | Unverified | No implementation claims or historical artifact rewriting; offline tests prove contracts only | retained |

## Batches and verification

1. Candidate admission, authoritative actionability and planner coordination (W1/W2/G1).
2. Bounded blocked/operator/handoff lifecycle (W3/W4).
3. Evidence and artifact grounding using existing observation/provenance boundaries (E1/E2/A1/A2/A3).
4. Adaptive enumeration and complete, efficient structured handoff (D1/D2/D3/R1/G1).

Each batch starts with focused failing regressions, then implementation and related responsibility checks.
Final verification runs the repository offline suite with the existing loopback-only plugin and all live/existing-target opt-ins unset, plus pyright and available lint checks. Disposable fixture servers are not experimental targets. No provider/target replay is authorized.

## Implemented contracts and dependencies

The four batches above are implemented. Admission was changed first because the
planner and blocker lifecycle must consume the same decision as start_validation.
Operator coordination follows admission: asking for an exclusion cannot become a
prerequisite for an independent admitted Candidate. Grounding and discovery then
use the existing provenance/reader boundary; no new executor, extraction framework
or validation classifier was introduced.

- W1/W2: Recon and Enumeration still need current completion markers and canonical
  artifacts. A new Whole-target attempt additionally needs the canonical analysis
  artifact and an exactly compatible linked **analyzed** input. Independent blocked
  inputs remain blocked and prevent global analysis/objective completion. Current
  admission is projected into Agent actionability and planner priority. Owned
  recovery, Direct and candidate-validation retain their existing gates. Generic
  route resolution uses the same prerequisite phases; execution still passes the
  shared attempt/probe controller.
- W3/W4: a blocked inventory gets at most two additional coordination turns **inside
  the existing max_steps**, when an allowed operator/artifact tool is available.
  This permits ask -> apply actual answer/write canonical handoff. It guarantees an
  opportunity, not a particular LLM choice. Dependency questions can bind exact
  blocked input_ids. Rewording the same input/reason question or changing permission
  revision returns the original answer and original question text. Explicit operator
  retry clears the bounded cache. Answers neither grant rights nor mutate inputs.
- E1: record_candidate can declare observation_ids. Wrong method/origin/path,
  unavailable/stale/revoked metadata, and known request-media mismatches reject
  atomically. Returned facts include actual method/URL/status, separate request and
  response media types and completeness. New HTTP captures retain the effective
  request media type through the existing redaction/hash path. Missing historical
  media metadata stays unknown. Analysis observations acquire no Attempt ownership,
  replay authority, proof status or confirmation. Query/body values, auth-context
  equivalence and whether a comparison controls SQL semantics still require actual
  source review; metadata matching is not a same-variable-only experiment proof.
- D1/R1: read_discovery_source optionally locates one case-sensitive literal in the
  already retained body. Scope, provenance, fresh per-read permission, existing
  64 KiB retention and 2,000-character output limits remain. It executes no JS and
  sends no HTTP. A miss concerns retained text only. This supports inspecting a
  call site beyond a vendor prefix without linear range reads or refetches.
- D2/D3/A/G: the shared prerequisite text is synchronized in the XSS validator as
  well; its proof/browser rules are unchanged. Source branches now depend on an explicit discovery question and
  expected information/cost. Keep fields (including passwords, arrays and query
  assignments), exact attribution and unresolved API-base/auth context. Selected
  source obligations and coverage accounting remain mandatory; executing every
  source branch is optional. False baseline comparisons, SQL-shape/parser-order
  claims, operation counts and SPA/status summaries get explicit reconciliation
  guidance. No semantic parser is claimed.

## Enumeration organization

The primary playbook retains scope/permissions, bounded-reading, structured input
registration, provenance, SPA calibration, normalized inventory and coverage/stop
contracts. It adds a conditional HTML/forms, captured traffic, documentation,
JavaScript and bounded path-discovery menu. It removes duplicate reader/source
procedures and compresses examples. Inline OpenAPI binding/server/security details
and selected-source disposition details move to source-reference.md, loaded only
for that question. Swagger/OpenAPI is not an Enumeration prerequisite.

The primary skill changes from 38,299 bytes / 804 lines to 35,782 bytes / 682 lines;
the optional reference is 4,488 bytes. This reduces the default loaded text, not
necessarily total package size, LLM turns or HTTP cost. No live improvement was
measured. Global workflow coordination was the higher-impact fix; Enumeration
organization is an additional bounded improvement, not a substitute for W1–W4.

## Evidence index

Event sequence numbers below equal JSONL line numbers in the retained logs.

- lan-20: experiments/scenario3/runs/lan-20/logs/session.jsonl, seq 1051 (keep
  blocked answer), 1058 (completion rejection), 1186 (different later exclusion
  answer at the hard limit). Seq 1058 rejects complete_skill, not an observed
  start_validation call. The global new-attempt gate is established separately by
  baseline source/admission tests; neither historical run opened an Attempt.
  Session state is in profile-home/.kagent/sessions/
  28ddc2ea-439b-4c94-a288-35bcf3f99c57.json under that run.
- lan-21: experiments/scenario3/runs/lan-21/logs/session.jsonl, seq 916–920
  (last blocked disposition -> blocked/actionable zero). Session state is in
  profile-home/.kagent/sessions/6ab2bbd9-f7d4-409a-a88a-541d36d1df42.json.
- lan-20 observation obs_02a88d1bf40b448781e8fc535e2c9b68 is POST, 500,
  text/html; obs_9684e9e65ce04b70b460f905c9a98a13 is GET, 500, text/html.
  They are not a same-method baseline/probe pair. Both are retained in
  project/.kagent/observations/28ddc2ea-439b-4c94-a288-35bcf3f99c57.json.
- That observation store also retains obs_cd387516d5a74dedbb8463b1b8fd9abd
  (chunk-SCY7YOCS.js) and obs_3e68ad6867c74db98d85a29a489426b3
  (chunk-7O3TTE7G.js): visible application call sites contradict vendor-only
  summaries. Computed API bases/imports remain unresolved.
- Historical artifact discrepancies: lan-20 project/artifacts/web-enumeration/
  juice-lab-8081/inventory.md:49,117 (/ftp); lan-21 equivalent:9 (operation
  count), 26,57,103 (route/status summaries); lan-20 project/artifacts/
  web-input-analysis/juice-lab-8081/candidates.md:33–44 (query-shape claims).
  Corrective guidance does not rewrite these files.

## Verification record

Current verification logs are retained locally (git-ignored) under
.kagent/verification/lan2021-remediation/. The earlier session used
/tmp/kagent-lan2021-remediation/; that temporary directory did not survive the
continuation environment. Earlier batch/full-suite numbers below are recorded
in the conversation's tool results, not reconstructed raw log files. Current
HEAD reproductions, regressions, controls and final checks have fresh retained
logs. RED failures are intentional before each batch.
Green runs overlap; counts must not be summed as unique tests.

| Batch | RED | GREEN / related responsibility checks |
|---|---|---|
| 1: admission/actionability/planner | 2 failed, 1 passed | 84 passed; compatibility follow-up 200 passed |
| 2: blocked/operator | blocked handoff failed; dependency questions 2 failed | 102 passed |
| 3: analysis evidence | 3 failed, 1 passed | 80 passed; request-media extension 2 failed -> 79 passed |
| 4: adaptive discovery/reader | 7 failed | reader 61 passed; skills/guidance 494 passed |
| Cross-component guidance | historical owned-handoff assertion failed; XSS stale global barrier 1 failed | 59 passed; final skill consistency 398 passed |
| Verification window (V2) | injected startup on unchanged HEAD: 1 failed, 1 passed | 48 related tests passed |
| Resize synchronization (V3) | delayed native resize callback on HEAD: 2 failed | 26 related tests passed; all 25 new regression cases passed |

Focused tests are tests/integration/test_lan2021_partial_admission.py,
tests/agent/test_lan2021_blocked_handoff.py,
tests/tools/test_lan2021_input_questions.py,
tests/integration/test_lan2021_analysis_observations.py,
tests/security/test_lan2021_discovery_search.py and
tests/skills/test_lan2021_adaptive_guidance.py, plus the verification regression
tests/ui/test_lan2021_measurement_window.py and tests/ui/test_lan2021_resize_sync.py. Existing phase-admission, lan-06, lan-07 and runtime-completion
regressions now assert the deliberate partial-handoff contract while still
checking blocked dispositions, no fabricated evidence/results, incomplete global
phase and same owned Attempt resume. Inline-OpenAPI tests load the conditional
reference through the actual skill-file tool; safety/attribution assertions remain.

Final commands:

```sh
env -u KAGENT_SYSTEM_LIVE -u KAGENT_RUN_LIVE_TOOL_CHARACTERIZATION -u KAGENT_S1_EXISTING_CONTAINER venv-linux/bin/python -m pytest -p tests.system.offline_suite -q -rs --durations=15
venv-linux/bin/pyright
venv-linux/bin/ruff check src tests
venv-linux/bin/ruff check tests/*/test_lan2021_*.py
git diff --check
git diff
git status --short
```

Final full offline suite: **9,236 passed, 0 failed, 12 skipped, 2 warnings** in
1,519.16 seconds (25:19), exit code 0. The complete retained log is
.kagent/verification/lan2021-remediation/full-pytest.log. The 12 skips are nine
Java benchmark cases lacking cached offline WAR/Tomcat archives, one test requiring
an explicitly selected prepared existing lab, one opt-in live system test and one
opt-in live-model characterization. No tests were newly skipped or xfailed.
The two warnings come from the existing malformed-custom-profile configuration
test intentionally supplying invalid IDs; they do not indicate new failures.
Pyright: 0 errors, 0 warnings, 0 informations.
Ruff: **not globally clean**, exit code 1, with 2,826 existing diagnostics versus
2,830 on immutable HEAD. Comparing each of
27 changed/new Python files against git show HEAD:<path> with identical Ruff
settings yields zero new (code, message) diagnostics; touched-file counts are
230 before / 226 after. All eight newly added test files pass Ruff. The measurement regression has one
local ASYNC251 annotation for its deliberate blocking positive control; no
production rule or lint configuration is relaxed. No mass lint
cleanup or weakened lint configuration was applied.

A pre-existing owned-handoff guidance failure was reproduced in an immutable
HEAD export (b197cfbce5ec0af3b86af292145682cc6a371d12): four failures in
 test_workflow_request_preparation.py -k owned_handoff. The current recovery hint
now explicitly names required request associations; the related checks pass.
An initial broad run and a responsibility-group run were interrupted to inspect
failures while implementing; neither is represented as a final suite result or a
clean immutable baseline. The first final run (1,444 passed before interruption) was also restarted after
the last cross-skill guidance correction so acceptance includes every new test.
The first completed acceptance run recorded 9,227 passed / 5 failed / 12 skipped
in 1,517.94 seconds. All five failures were inspected:

1. lan-06 expected the removed global marker error; it now checks the actual
   canonical-artifact error, unchanged state, pending disposition and no attempt.
2. Two runtime-completion cases expected an unlinked new Candidate to be
   actionable. They now require the exact admission blocker, no actionable
   Candidate and no result for that unresolved obligation.
3. The observation_ids description lost explicit heading/table proof-parent
   guidance while adding analysis context. That required wording is restored in
   production; the existing proof-parent regression remains unchanged.
4. The UI budget test fails identically on immutable HEAD (fresh reproduction in
   head-existing-failures.log).
   Its relative path hits file-outside-profile before the budget gate. Only the
   fixture path changes to the exact tmp_path; all original denial/visibility and
   no-write assertions remain. No permission ordering or gate is changed.

The focused repair group passes 140 tests. The next completed full run recorded
9,231 passed / 1 failed / 12 skipped in 1,640.35 seconds. Its only failure was
V2, test_c4_proposed_postread_passes_unchanged_mounted_oracle. The measured
124.18 ms gap ended at 68457.844316606; operation entry was 68457.84663546.
Thus the entire offending interval preceded the operation. Escape delivery was
0.985 ms, with 19 actual operation heartbeat ticks and I/O off the UI thread.
No production responsiveness improvement is inferred from this failure.

The original measurement helper matched HEAD byte-for-byte (SHA-256
4f37e8260e70ef3db159992456fd9f503cbec21c3c06cf54d5a268c885239bad).
A deterministic regression copied outside the immutable HEAD export injects a
180 ms startup callback before operation entry. HEAD reports an unrelated
186 ms startup gap and fails the nonblocking case, while the deliberately
blocking operation case remains detected. See head-measurement-window-red.log
(1 failed / 1 passed). This proves the pre-existing window defect without
assuming that a timing failure seen once is a Runtime regression.

The helper now computes gap boundaries from operation entry and subsequent real
heartbeats; the entry anchor also catches blocking before the first heartbeat.
Raw startup timestamps remain in the diagnostic timeline. assert_responsive,
120 ms, real heartbeat count, Escape latency, cancellation and recovery assertions
are unchanged. The controls log records 34.4 ms for the nonblocking operation and
206.5 ms for deliberate blocking; the latter must still be rejected. Related
checks pass 48 tests and all seven new regression files pass 23 cases.

Fresh immutable-HEAD reproductions after continuation record 20 failed / 1 passed
for the first six regression files (head-regressions-red.log), versus current
23 passed including the new two-case window regression. HEAD's original UI
budget/owned-handoff failures are also retained in head-existing-failures.log.
The full run after V2 recorded 9,233 passed / 1 failed / 12 skipped in
1,816.24 seconds (full-before-resize-sync.log). Its only failure was
 test_progress_height_resize_keeps_transcript_anchor_tail_and_copy[False]:
after requesting 45x24, the test still saw input-panel Region(width=120,
y=28, height=3), so bottom=31 exceeded 24. This is a stale frame, not evidence
of a new layout failure caused by assessment code. The test uses a mock Agent;
none of the changed Agent execution methods participates in this scenario.

Installed Textual's App._on_resize schedules _check_resize via a 1/120-second
timer. Pilot.resize_terminal posts the event and waits for already queued
messages/idle, which need not include that future timer. The standalone HEAD
case passed, so that alone was not used as proof of a pre-existing failure.
Instead, a deterministic HEAD regression delays only _check_resize to 80 ms:
both original reading/tail cases fail their unchanged geometry assertions
(head-resize-sync-red.log). The final fixture waits up to one second for
screen.region.size (the compositor frame) to equal the requested Size, then drains pending layout. It does
not poll until the assertions become true. All original geometry, line-identity,
selection, reading-anchor and follow-tail assertions remain. No production UI
handler changed. The delayed-resize regression and overview group pass 26 tests;
all eight new regression files pass 25 cases (regressions-green.log).

The first V3 synchronization attempt used Screen.size. A subsequent full run
recorded 9,234 passed / 2 failed / 12 skipped in 1,745.39 seconds
(full-before-compositor-sync.log): both failures were the new delayed-resize
regression, not the original application tests. It exposed an error in the first
test fix: Screen.size mirrors App.size immediately and does not prove that the
compositor has applied the resize. A focused pass had been insufficient to
establish that lifecycle boundary.

The final predicate is screen.region.size, obtained from the compositor's actual
widget map. The fault injection is strengthened to 200 ms; it checks that every
requested viewport receives a delayed callback without assuming an exact number
of internal timer calls. The incorrect Screen.size predicate fails both cases
(resize-compositor-red.log); the compositor predicate plus all original overview
assertions passes 26 tests (resize-compositor-green.log). Five further executions
of both delayed-resize cases pass without changing any geometry/selection/scroll
assertion, the one-second synchronization bound, or production UI code.

A new full offline run with skip reasons enabled (-rs) passes after this correction:
9,236 passed / 0 failed / 12 skipped / 2 expected warnings in 1,519.16 seconds.
It includes all 25 new regression cases in eight files and supersedes the
failed/interrupted runs; those runs are not hidden or counted as green.

Before the environment continuation, all 46 historical files had modification
times preceding the initial baseline check. A fresh 46-file SHA-256 manifest is
retained in the current verification directory. The final comparison after the
passing suite reports 46 files, no changed/removed files and no added files
(historical-integrity.json). git diff -- experiments is empty. Final
git diff --check passes. No historical experiment file was a patch target.

## Remaining limitations

- Missing JWT, inaccessible/dynamic JavaScript and unavailable browser execution
  remain real limitations. No credentials, adapters or authorization were added.
- Optional observation declarations validate metadata, not free-form SQL semantics.
  Arbitrary Markdown can still overclaim counts, locators, reachability or query
  shape. The minimal justified remedy is precise guidance plus existing proof
  gates; building a general semantic artifact verifier is outside the evidence.
- Manual attribution binds an actual source/hash but does not prove the locator
  or extract fields. No automated OpenAPI/JS extraction was added. Guidance tests
  establish the delivered contract, not that every model will follow it.
- Dependency deduplication is session-runtime bounded and keyed by exact input
  IDs/reasons; it is not semantic equivalence across different groups/reasons or a
  durable operator policy. Restored conversation answers must still be consulted.
- The bounded handoff cannot extend an exhausted max_steps or guarantee an answer
  arrives before that limit. Blocked inputs stay untested/open until a real
  resolution or explicit, separately committed operator exclusion.
- The hard max_steps limit is retained. The lan-21 /maxstep typo is operator
  command usage, not evidence of a broken max_steps gate; no one-transcript alias
  patch was added. lan-20 dropped log records and the lack of an immutable runtime
  revision pin limit historical reconstruction, not current regression results.
- No target/provider/new lan run was performed. Offline tests establish contracts;
  no increased SQLi yield, realized discovery coverage or execution-cost reduction
  is claimed. Historical results and evidence were not altered.
