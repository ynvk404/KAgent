# KAgent — Systemic tool-call reliability and Anti-stall acceptance

Date: 2026-10-24 (Asia/Saigon). Status: **READY — offline acceptance complete**.
This is a new report; historical reports and experiments are read-only.

## Baseline and pre-implementation decisions

The requested Windows cwd does not exist. The inspected KAgent checkout is
`/home/khainguyen/kagent` (Ubuntu WSL), HEAD
`1f6a2ec`; the initial worktree is clean. The prerequisite
[Tool Contract + Recovery acceptance](kagent-tool-contract-recovery-final-acceptance.md)
is complete, with its documented full-suite/harness limitations. Editors and a
Codex app-server are open; no running pytest/KAgent process was observed.
Every edited baseline file is checked against its captured bytes before writing.

Snapshot: `/tmp/kagent-systemic-q6yxo8_j`. Source/skill/test/document baseline:
670 files. Protected historical data: 3,107 files in project .kagent, artifacts,
experiments and personal sessions. Manifest aggregate SHA-256:
`5eea692d4dbca2f6226c1f556ba06ed31f9b9d1cc794192db0ed4f18896717f6`.
This is a bounded inventory, not a claim about every file on the machine.

Baseline targeted deterministic tests: 99 passed (7.51s), isolated checkout,
offline guarded harness. No target/provider requests or package installation.

## Root Cause Matrix (recorded before production edits)

| ID | Classification | Minimal counterexample / expected vs current | Root ownership / affected paths |
|---|---|---|---|
| P1 | CONFIRMED DEFECT, high | Whole-target start_validation / record_attempt_state succeeds, but progress_facts does not describe Attempt/effects transitions. At an exhausted exploration allowance and no_progress=3, a genuine declaration is no_progress=4. Direct already attempts to track these obligations. | Workflow semantic progress projection; Whole-target validation/finalization |
| P2 | CONFIRMED DEFECT, medium | Direct same admitted mutation/cleanup state with changed effect_basis or cleanup_status changes the progress signature. Rewording can reset the counter without new workflow data. | Direct progress projection serializes the entire effects declaration |
| P3 | CONFIRMED DEFECT, high | An accepted same-revision Result cleanup_state changes while its stable result fingerprint remains identical (seal deliberately excludes cleanup). Whole-target emits no cleanup fact. | Workflow progress_facts; cleanup phase; must not change assessment fingerprint/seal |
| C1 | CONTRACT GAP, medium | record_input contract marks none of endpoint/parameter/location required, though admission requires them. method may be supplied by endpoint shorthand and must remain conditionally required. | Existing ACTION_REQUIRED/ACTION_INPUTS renderer and field guidance |
| C2 | CONTRACT GAP, medium | Workflow discovery/endpoint IDs are plain strings, unlike exact ds_/ep_ producers and reader; source_bounds advertises arbitrary keys/unbounded values although SourceRecord rejects them. | Workflow schema; authoritative discovery metadata constants |
| C3 | CONTRACT GAP, medium | Discovery actions can return only generic error text without the producer lookup/retry path or field constraints. Wrong-owner/stale resources must remain rejected. | Workflow action feedback; existing structured error envelope |
| C4 | CONTRACT GAP, medium | HTTP flat schema leaves url/candidate alternative and replay-field conflicts unclear, including replacement headers; runtime rejects missing URL and mixed replay arguments. | HTTP field-level descriptions; preserve runtime admission |
| L1 | EXPECTED REJECTION / historical MODEL BEHAVIOR | obs_ used as replay baseline, guessed ds_, unknown evidence IDs, wrong input geometry, blocked phase and forbidden file_edit. | Existing guards are correct; prior guidance patches and regression coverage retained |
| L2 | DEFERRED | Broad strict/oneOf/split-tool/universal validator rollout; actual model compliance and provider server enforcement. | No demonstrated compatibility basis or offline causal measurement |

## Fix Decision Matrix (recorded before production edits)

| Root cause | Chosen smallest fix | Alternatives and risk |
|---|---|---|
| P1/P2 | Share a scoped semantic Attempt progress projection between state facts and Direct signature. Include lifecycle/probing/effect/cleanup states, exclude fresh Attempt IDs and explanatory prose. Credit a semantic fact once per run using existing tracker. | Raising thresholds/resetting on retry would conceal loops and is prohibited. Hashing the full Attempt includes IDs/dispatch noise. New facts may change offline iteration counts; test positive and duplicate/foreign controls. |
| P3 | Add separate cleanup-state facts per Result revision; leave acceptance fingerprint/seal untouched. | Changing fingerprint risks evidence/coverage compatibility and is unnecessary. Reason-only changes must not count. |
| C1/C2 | Extend existing action metadata and portable flat field schema/guidance using current bounds/constants. Preserve shorthand and all validators. | Conditional/strict schemas need compatibility proof; broad validators duplicate admission. Legacy runtime calls stay supported. |
| C3 | Use existing _workflow_error with exact lookup and correction guidance, preserving workflow_state rejection and source binding. | No auto-ID repair or automatic retry. Error values are redacted. |
| C4 | Explain direct/replay alternatives and selectors at the HTTP fields. | No tool split, argument conversion, permissions or transport changes. |
| Other risks | Verify with current contract/security/context/provider responsibility tests; classify evidenced residual gaps explicitly. | Do not expand the audit indefinitely for speculative combinations. |

These matrices were saved before production edits. The following sections record
the counterexamples, final implementation, verification and acceptance verdict.

## Historical Tool-Call Error Inventory and end-to-end traces

Read-only sources: saved sessions for Scenario 1
`3c0efc1d-d87d-40f1-8aaa-a38b4303e7cd`, lan-06
`7262ac7a-9da0-4871-8f9c-00031c3b2832`, lan-07
`fbf1ddcd-78cf-4c94-b6e8-13d5e84b08e1`, lan-08
`135686eb-ee21-4663-b266-c9e22827d7c5`; corresponding JSONL logs, observation
stores and existing RCA/acceptance documents. There are **12 error tool results**
in these saved message histories: 2 + 5 + 2 + 3. This is a defined saved-history
inventory, not a universal count across dropped debug records or experiments.

| Historical event | Available information, selection and invalid arguments | Admission/result/context/correction | Classification and current decision |
|---|---|---|---|
| Scenario 1, messages 9→10 (A) | Selected Burp retrieval and imported observation are different records. record_candidate used obs_ in source_ref for the selected-capture binding. | Correctly rejected before registration; messages 11→12 omit optional assertions under the existing unique matching selection resolver and receive canonical Candidate/source/baseline. Explicit wrong refs still reject. | EXPECTED REJECTION + historical CONTRACT GAP, fixed by prior selected-source guidance; preserve native receipt/selection regressions. No execution obs→burp conversion. |
| Scenario 1, 31→32 (B) | SQLi current contract; record_result supplied mutation_state/effect_basis belonging to record_attempt_state. | Correct invalid_args; 33→34 removes those fields, keeps common submission fields and receives accepted Result. | EXPECTED REJECTION + MODEL BEHAVIOR; flat action union remains a bounded contract limitation. Prior generated action-field guidance retained. |
| lan-06 seq 427 | record_phase_coverage supplied both phase and extra coverage_phase. | invalid_args; next workflow calls at 428/430. Current metadata-generated guidance lists exact allowed fields. | EXPECTED REJECTION; avoid treating the retired extra key as another phase authority. |
| lan-06 seq 607/608 (2 calls) | Discovery observations were read through the owned validation-observation reader. An obs_ shape alone does not establish Candidate/Attempt ownership. | Both reference_unavailable; subsequent calls 637/638 were HTTP, not successful repairs of those reads. Correct recovery is list sources → exact ds_ reader, or an explicit retrieval limitation; do not create an Attempt/refetch solely to read discovery. | EXPECTED REJECTION + historical selection/planning failure. Current reader/action guidance and source-integrity tests retained. |
| lan-06 seq 699/703 (2 calls) | record_candidate kept input_id but changed observed concrete endpoint to /rest/track-order/{orderId} or /rest/products/{productId}/reviews. | Source-path mismatch correctly rejected. Historical later registration without input identity is not evidence of valid repair; current prior handoff fix retains/inherits the canonical input. | EXPECTED REJECTION; earlier disconnected-handoff CONFIRMED DEFECT already fixed in baseline. Today: test canonical get_input handoff, preserve provenance and legacy unique-match checks. |
| lan-07 seq 881 | complete_skill(input analysis) while canonical inputs remained blocked; canonical artifact alone was insufficient. | PHASE_NOT_READY includes readiness; later 912/913 HTTP did not resolve missing legitimate credentials. Historical actual operator exclusion at ask_user allowed a later reasoned disposition/completion. | MODEL BEHAVIOR + EXPECTED REJECTION. No autonomous scope/credential inference or phase bypass. Existing explicit exclusion guidance retained. |
| lan-07 seq 959 | file_edit selected under web-input-analysis, whose active allowed-tools omitted that editor. | Rejected before execution; following BashTool calls at 965/972 were actual local work, not permission overrides. Current prompt qualifies editor advice and supports allowed file_write overwrite. | Prior prompt CONTRACT GAP fixed in baseline; present runtime rejection expected. No need to rewrite planner or widen allowed-tools. |
| lan-08 seq 278 | read_discovery_source used ds_ followed by only 32 hex digits, resembling a prefix replacement of an observation ID; exact producer IDs have 64. | invalid_args; workflow metadata lookup at 284, corrected reader at 291. Current reader already publishes the pattern and lookup instructions. | MODEL BEHAVIOR / EXPECTED REJECTION. C2 generalizes prevention to Workflow discovery/endpoint consumers, not a claim that this reader lacked a regex today. |
| lan-08 seq 477 | record_input used the same obs_ as both source_ref and baseline_request_ref. | Replay resolver rejects; subsequent workflow calls at 478/485. Valid observation provenance may remain source_ref; baseline may be omitted only when there is no replay capture, without inventing one. | EXPECTED REJECTION; current baseline/source descriptions and binding checks preserved. |
| lan-08 seq 1556 | record_evidence supplied seven observation IDs, including nonexistent IDs. | PRIMARY_REFERENCE_UNAVAILABLE with repair hints; later list at 1582/proof edit at 1607; exact owned references must be selected and dependent proof claims corrected. | MODEL BEHAVIOR + historical context-handle risk. Current guard retains controller-issued HTTP IDs during elision; no guessed ID repair. |

For every row, the audited chain is: saved prompt/playbook/tool outputs and current
projection source → chosen tool/action and arguments → current provider encoding →
authoritative runtime checks → typed result/error → next Agent request/history →
actual saved correction where available. Saved message indices and JSONL seq
numbers are different coordinate systems. Later calls are not automatically
counted as successful recovery of the original operation.

**Observation boundary:** the persisted messages, arguments, errors and receipts
are directly observable. The current Registry → ActionView → provider encoder
path is directly testable offline. Exact historical outbound provider requests,
the precise tools/schema/context the model received on every historical call,
and whether every handle survived historical provider-side context processing
were not archived; they are not reconstructed as verbatim wire evidence.
Transient validation_context is deliberately omitted from persisted Workflow
responses, so its historical absence on disk does not prove live omission.

Tool error counts do not include every historical planning/semantic incident.
lan-06's unreasoned supported-candidate deferral/disconnected handoff and lan-07's
novel-reader progress loss were confirmed and fixed in the captured baseline;
their dedicated regressions are retained. lan-07's late validation and insufficient
oracle, and lan-08's overconfident SQLi inference/counting despite accepted
workflow completion, remain model/semantic evaluation limitations. Runtime
admissibility does not certify vulnerability meaning; this audit does not rewrite
their historical results or add a target-specific oracle.

The prior TUI false-recovery, denial/resource/chronology and stale-submission
defects remain resolved by their existing acceptance tests. This audit does
not expand that ledger, UI, or recovery correlation implementation.

## Proactive Failure / Counterexample Matrix

| Equivalence class / boundary | Invalid → valid counterpart | Expected behavior and evidence |
|---|---|---|
| Every Workflow action: wrong-action/extra/missing fields | record_result plus mutation_state/effect_basis → same owner/submission with those fields on record_attempt_state only | All 18 action allowlists tested before mutation; generated ACTION_REQUIRED/ACTION_INPUTS guidance stays aligned. C1 now publishes endpoint/parameter/location for record_input and gives missing-field invalid_args. |
| Conditional method | record_input endpoint=/search without method → method=GET; or endpoint="GET /search" | Existing normalization/admission remains authoritative. Shorthand stays accepted; method is not incorrectly made universally required. |
| Discovery namespace/length | ds_+32 / obs_+32 → exact returned ds_+64; ds_ endpoint → returned ep_+64 | New schema negative tests and valid producer-backed retry; stale well-shaped IDs still reject with no mutation. Source-attribution nested ds_ schema uses the same producer pattern. |
| Processing bounds | unknown name, 0, boolean, 16MiB+1 → known name at 16MiB boundary | Shared existing bound/name constants; runtime negatives and explicit partial-source positive preserve source ID, limitations and bounded-stop acknowledgement. |
| Replay/direct HTTP | missing URL, replacement replay headers/body/method/URL, selectors without mutation → exact direct URL or existing bound Candidate replay with proper selectors | Field guidance improved; existing replay/HTTP/C1 guards remain. No source conversion, request mutation or permission shortcut. |
| Numeric/string/array validation across tools | wrong file mutation type, malformed HTTP headers, discovery paths/budgets, ask_user limits, reader offsets → valid typed arguments | Existing C1, discovery, shell, ask, coverage, file and reader tests; invalid inputs do not prepare receipts, consume execution allowance or mutate files where the contract requires early rejection. |
| Provenance despite correct shape | stale/wrong owner, origin, session, epoch, input, Candidate, Attempt or proof parents → exact current resource under current owner | Existing evidence/HTTP/readers/selection security and native integration regressions retained. Shape never creates authority. |
| Local Attempt progress at boundary | overlong effect_basis rejected at no_progress=3; corrected declaration preserves Candidate/Attempt and all state fields | Native registry declaration + semantic projection gives structured_progress only after actual commit. With exploration_cap=0 the invalid call itself grants no credit. No new grace turn or budget. |
| Direct false progress | same mutation/cleanup declaration with new effect_basis prose → unchanged signature | Native admitted declarations reproduce old defect, now stable; attempt IDs and prose excluded, candidate/objective/origin/binding checked. |
| Result cleanup | same revision with explanation-only update → no new fact; cleanup state transition → separate cleanup fact | New positive/negative projection test; acceptance fingerprint/seal unchanged. Synthetic projection fixture is not an accepted cleanup claim or Finding. Native cleanup security responsibility tests separately enforce owned action/readback. |
| Repeated/new validation response | changed obs IDs/request variants with identical body → at most one bounded verification repeat, then no_progress; genuinely different responses within allowance → exploration | Existing bounded_validation and HTTP semantic-progress regressions. No HTTP status alone creates a result or confirmation. |
| Readers and multi-call iteration | overlap/repeated page/EOF → no credit; genuinely unread bounded ranges → reader_progress | Existing skill pages, observation/tool-result pages, lan-07 and validation batch tests; exploration remains finite and pagination does not replenish HTTP novelty. One batch is one iteration. |
| Phase, source, metadata cycles | reworded reasons or previously credited selected/deferred state → no renewed credit | Existing semantic source/coverage facts and novelty saturation tests, phase-rich workflow/trial-3 reconstruction. |
| Completion and finalization | pending evidence/cleanup/coverage/Finding/goals → incomplete; complete authoritative obligations → completion | Existing direct/whole-target, generic/expert, skill/phase, cleanup and terminal synthesis tests. Accepted assessment and persisted Finding remain separate. |
| Context pressure/compaction/resume | removed body or stale reader → retain exact controller references/feedback or report limitation | Current context reducer preserves HTTP references; Workflow/skill/user-intent results use preserve policy within configured bounds. New Agent trace receives rejection, lists genuine IDs and retries; existing compaction/session/retention tests verify no promotion to success/authority. |
| Permission/resource/cancellation | denied, stale review, out-of-scope, exhausted allowance, cancelled operation → reject/preserve uncertainty | Registry, direct process, native HTTP, evidence publication and finalization regressions. No configuration or gate changes. |

Tests use representative valid/invalid classes, boundaries and state sequences;
they do not enumerate a Cartesian product or purport to prove all future calls.

## Tool Contract and Cross-Tool Reference Matrix

The native registry fixture covers **34 declarations**, including aliases,
capture tools and controller-owned readers. Initial schema validation and
encoder comparisons are against actual tool objects. Configured command
plugins/process MCP are not registered in the CLI; legacy objects reject before
host dispatch, covered by their existing tests.

| Tools / family | Model-facing contract, runtime and cross-tool responsibility | Audit disposition |
|---|---|---|
| shell, BashTool | Exact command/timeout, direct-process policy, tool/resource/phase/cancellation restrictions; outputs can yield gated tr_ references, never HTTP evidence by themselves | Existing validators and shell/security tests; no changes |
| file_read / FileReadTool, GlobTool, GrepTool | Required path/pattern, bounded search/read semantics and sensitive-path gates; generic retained output needs original capability | Runtime has some legacy coercion/default behavior; broad strict validation deferred, no new framework |
| file_write / FileWriteTool, file_edit / FileEditTool | Required typed mutation fields; empty string intentionally valid; aliases retain same permission/skill behavior | Existing C1 positive/negative/no-side-effect tests; no changes |
| http | phase annotation + direct URL or captured replay; request/body/auth binding and native observation production | C4 descriptions only; guards unchanged |
| web_fetch, web_search | Scoped/research reads, text/body caps, governed transport, URL/query requirements and typed network outcomes | Existing tools/lifecycle/security tests; no changes; output is not owned validation proof |
| content_discovery, service_discovery | Bounded exact-origin base/target, positive budgets/rates/timeouts, native provenance | Existing C1/discovery/integration tests; no changes |
| workflow (18 actions) | Shared action tables + field guidance; runtime owns IDs, phase/owner/prerequisite/evidence/cleanup admission | C1–C3 fixed using existing metadata/error envelope; no action splitting/strict mode |
| coverage (5 actions) | Progress projection; list/untested pagination; mark cannot establish verified tested coverage under runtime policy; clear requires permission/intent | Existing coverage/contextual/ambiguous-mutation tests; no changes |
| confirm_finding | Current accepted confirmed Result, owned immutable proof, cleanup and persistence; export is separate obligation | Existing assessment/Finding/publication tests; no changes |
| load_skill | Named enabled playbook and model-invocation eligibility; active capability projection and fresh runtime enforcement | Existing skill/request preparation/restricted-tool tests; no changes |
| read_payloads, read_skill_file | Loaded skill, contained path, bounded line/Unicode range and producer-issued sf_ continuation | Existing pages/grounding/containment tests; preserve guidance and gates; conditional read/path schema remains flat |
| ask_user | 1–4 real input questions with bounded choices; not permission, durable policy or an answer generated by YOLO | Existing typed validation, input-unavailable and scope-branch tests; no changes |
| permissions_status | Read actual runtime rights; metadata grants no permissions | Existing permission/security tests; no changes |
| browser_capture_status/endpoints/requests/get/snapshot/burp_tasks/burp_issues/clear | Scoped redacted metadata, retrieval and baseline binding; get can expose imported observation metadata; clear remains explicitly gated | Existing capture/selection/replay/security tests; no new namespace repair or UI change |
| read_tool_result | Published tr_+32hex; current session/generation/original producer capability, storage integrity, bounded character range | Existing retention and provider tests; no change; negative/clamped range compatibility not mislabeled a defect |
| read_http_observation | obs_+32hex plus current Candidate/Attempt/session/epoch/source integrity; exact character ranges | Existing ownership/readback tests; discovery remains separate |
| read_discovery_source | ds_+64hex metadata → retained observation association, current Whole-target source/scope/rights; no ownership transfer | Existing reader pattern/guidance preserved; Workflow consumer patterns now match producer |

| Reference producer | Accepted consumers / exact meaning | Invalid handoff or limitation |
|---|---|---|
| Capture store retrieval id (including burp:...) | browser_capture_get.id; selected record_candidate.source_ref with exact matching selection | Not obs_, baseline or read authority |
| Capture resolver baseline:... | baseline_request_ref and Candidate-based HTTP replay | Never build from obs_ or URL; availability/method/path/auth/signature must still match |
| ObservationStore obs_+32hex | Matching source_ref provenance; owned observation readback and observation_ids under current Attempt | Discovery observations do not become terminal validation sources by format; stale/cross-session/wrong owner rejected |
| Discovery SourceRecord ds_+64hex | Workflow source actions/source_attribution; read_discovery_source | retained_ref is an association to stored bytes, not a replacement ds_ |
| EndpointRecord ep_+64hex | get_endpoint and provenance graph | Different from input_, Candidate and source IDs |
| Canonical input_... | get_input, disposition and candidate linkage under active Whole-target owner | Template/concrete/source mismatches cannot be fixed by dropping input identity |
| Candidate cand_... | start_validation, evidence, result, coverage, Finding ownership | Candidate ID alone does not create a captured replay baseline |
| Attempt attempt_+32hex | Returned start_validation attempt; equality assertion and owned source ledger | Cannot assign/reset another Attempt, borrow an observation or bypass immutable request roles |
| EvidenceArtifact ev_... | record_result.evidence_refs for the matching Candidate and immutable parent set | File paths/obs_/invented ev_ do not register evidence; identical native snapshot content is content addressed |
| ValidationResult result_id | Controller-owned sealed assessment/revision and its accepted-state/persistence checks | Same-revision cleanup does not require changing the result identity/seal |
| Result retention tr_+32hex | read_tool_result only with published reference and source capability | sf_, obs_, paths and changed prefixes are invalid |
| SkillFilePages sf_... | Same reader's source_ref plus published next character offset | Not read_tool_result; stale/changed source or another reader must fail |

## Anti-stall behavioral acceptance

WholeTargetStallTracker is transient per run, with scope keyed by Workflow
generation/objective; authoritative Workflow/evidence/recovery/resource state
persists separately. It is not reconstructed from TUI event text or compacted
prose. The change adds semantic facts to existing accounting, not a second
tracker or a durable authorization/counter reset.

- Threshold remains **4 consecutive no-progress iterations**; default phase
  exploration allowance remains **8**. Novel facts are credited once per run;
  the 8,192-entry novelty saturation remains conservative without eviction.
- A genuinely committed semantic fact resets the no-progress counter and the
  existing exploration window. A phase change resets its exploration view, not
  an arbitrary no-progress failure. Repeated facts, reasons, IDs, reads and
  invalid arguments cannot create structured progress.
- Validation response novelty uses returned data, not new observation IDs.
  One bounded verification repeat is exploration. New reader ranges use the
  existing finite content/range bookkeeping; EOF/overlap do not progress and
  reading does not replenish HTTP exploration.
- Distinct actionable validation diagnostics can consume existing bounded
  exploration credits; repeats cannot renew them. A retry by itself grants no
  progress or allowance. If already exhausted, a fresh error is not promised
  unlimited repair; genuine local finalization remains subject to its own
  existing opportunity and all remaining budgets.
- The new shared Attempt projection scopes Candidate, objective, target origin
  and current Candidate binding. It reports lifecycle/probing/effect/cleanup
  states, excluding Attempt IDs, dispatch IDs, observations and explanation
  prose. Reopening an identically represented state cannot farm novelty.
- Same-revision Result cleanup has a separate fact, leaving assessment
  fingerprint/seal semantics unchanged. Prose-only cleanup updates remain
  bookkeeping. Projecting a recorded state is not evidence of its admission.
- Existing finalization stops probing once per owned Attempt and uses remaining
  existing outer iterations for permitted readback/effects/proof/result work.
  No extra HTTP/tool/max-step budget is granted. Hard limit, cancellation,
  permission/resource limits and genuine blockers remain authoritative.
- Direct requested-goal runs use the same Attempt semantics in their existing
  signature; ordinary Direct informational work does not acquire a Whole-target
  objective or phase prerequisite.
- Across new invocations the transient tracker starts fresh by design; persisted
  evidence repair counters, Attempts, grants/epochs and resource constraints do
  not gain a reset from compaction/Continue. This audit does not claim a durable
  cross-invocation no-progress counter.

| Required anti-stall case | Verification responsibility |
|---|---|
| Four no-progress iterations and a correct stop | bounded_validation regressions; trial3_stall_reconstruction; requested_goal_lifecycle |
| Structured progress reset vs duplicate facts | systemic_progress; workflow_progress_ownership; whole_target_workflow |
| Exploration inside/outside allowance; phase changes | bounded_validation regressions; whole_target_workflow; trial-3 reconstruction |
| Duplicate vs meaningful HTTP responses | http_semantic_progress; bounded_validation regressions |
| Reader pagination, unread/overlap/repeat/EOF | bounded_validation regressions; lan07_audit; HTTP/tool-result/skill reader tests |
| Repeated invalid calls and corrected owned commit near threshold | systemic_progress native declaration sequence; bounded diagnostics; new Agent source-lookup retry |
| Evidence/effects/cleanup/Result and terminal synthesis | systemic_progress; validation_finalization; agent_assessment; cleanup_actionability |
| Multiple calls per iteration | record_validation_batch tests and trial-3 real scripted Agent batches |
| Direct and Whole-target modes | systemic_progress signature/whole-target facts; requested goals; whole_target_workflow |
| Hard limits and safety budgets | requested_goal_lifecycle; bounded_probe_contract; execution/evidence-recovery/finalization tests |
| Session/persistence/compaction boundaries | existing resume_after_compaction, post_compaction, retained results, evidence recovery and ownership tests |

## Implemented changes and evidence

The final source + shipped-skill manifest contains **235 files**, canonical
path/hash-map SHA-256
`4e33bbe02e09e1c5c8c777950dd6c17b7e9f27adb735c2cf6956b3f08f83c90d`.
HEAD remains `1f6a2ecf6a10b25a07c86537d57e1ec44d0f44c5`; the uncommitted
patch and the verified copy, not HEAD alone, define this frozen audit baseline.

Five production files changed: src/workflow/state.py (shared semantic Attempt
facts and Result cleanup fact), src/agent/agent.py (consume those facts in Direct
progress), src/workflow/discovery/inventory.py (name existing regex/bound
constants), src/tools/workflow/workflow_tool.py (generated input requirements,
namespace/bounds schema and structured discovery feedback),
src/tools/http/http_tool.py (direct/replay field guidance).

Three new regression files:
tests/agent/test_systemic_progress.py,
tests/tools/test_systemic_tool_contracts.py,
tests/llm/test_systemic_contract_encoding.py. They contain **26 test cases**.
The 13 initial counterexample cases all failed against the captured baseline
for the intended production/projection/contract reasons, before source edits.
Final additions cover native corrected retry at the boundary, runtime bounds,
the next actual Agent request and all-native provider projection. The existing action-only missing-field fixture now supplies valid objective/target
context for record_input, so its invalid_args assertion tests arguments rather
than masking a workflow-state failure. The original semantic-state regression
test remains unchanged. No existing assertion or skip was removed or weakened.

No changed planner, System Prompt, playbook, permission/resource implementation,
evidence/result/Finding acceptance, persisted schema, TUI or historical data.

## Verification results

| Check | Result | Scope/limits |
|---|---|---|
| Baseline targeted | 99 passed, 7.51s | Before production edits, isolated checkout |
| Initial counterexamples before fix | 13 failed, 1.46s | Intended failures; log retained, not a product verdict after fix |
| Initial fixed set plus existing parity/provider regressions | 112 passed, 7.85s | Includes initial 13 cases |
| Cross-tool / multi-step / security checkpoint | 160 passed, 65.73s | Native effects/finalization, whole/direct goals, readers, lan-06/08 contracts, related-request correction; overlap with other groups |
| Final new regressions | 26 passed, 3.53s | Final production source/test state |
| Preliminary Pyright wrapper checks (excluded from offline acceptance) | 0 errors, 0 warnings, 0 informations | Wrapper auto-queried PyPI version metadata; no package installed; superseded by guarded local invocation |
| Full configured bundled Pyright with network disabled | **0 errors, 0 warnings, 0 informations** | Direct local Node entry point, venv-linux configuration, all final source/tests |
| First full isolated pytest | **8,895 passed, 12 skipped, 1 failed, 2 warnings**, 1,285.13s | Genuine classification regression introduced during this audit; fixed below, not called a timing/harness failure |
| Context/classification correction retest | **192 passed**, 8.75s | Original failing node, action matrix, new tests, canonical input and whole-target handoff regressions |
| Final full isolated pytest | **8,896 passed, 12 skipped, 2 warnings**, **1,283.78s** | All **8,908 collected cases**, zero failures, one clean invocation on the final source after classification fix |
| Diff, historical/source drift and artifact integrity | **PASS** | All 3,107 protected files unchanged; none added/missing; source/config/verification-copy drift empty; git diff --check clean |

The harness is /tmp/kagent-systemic-q6yxo8_j/offline_pytest.py, copied from the
previous accepted harness with its multiprocessing main guard intact. It rejects
enabled live opt-ins, protects original project/history/session paths against
writes, and blocks non-fixture socket connections. Tests use isolated tmp paths
and a disposable checkout containing source/tests/skills/config/scripts and
integration fixtures, without original runtime artifacts. The only permitted
socket activity is deterministic test infrastructure bound in the test process.
MockTransport opens no target/provider connection. No live pentest, Scenario 1
launch, lan-09, external provider or dependency installation was performed.

Main commands (logs retained under the audit directory):

~~~text
KAGENT_TEST_CHECKOUT=/tmp/kagent-systemic-q6yxo8_j/checkout venv-linux/bin/python -B /tmp/kagent-systemic-q6yxo8_j/offline_pytest.py -q tests/agent/test_systemic_progress.py tests/tools/test_systemic_tool_contracts.py tests/llm/test_systemic_contract_encoding.py --tb=short
KAGENT_TEST_CHECKOUT=/tmp/kagent-systemic-q6yxo8_j/checkout venv-linux/bin/python -B /tmp/kagent-systemic-q6yxo8_j/offline_pytest.py -q --tb=short
NODE_OPTIONS=--require=/tmp/kagent-systemic-q6yxo8_j/deny-network.cjs /usr/bin/node venv-linux/lib/python3.14/site-packages/pyright/dist/index.js
git diff --check
~~~

Logs: baseline-tests.txt, red-counterexamples.txt, first-fix-tests.txt,
provider-feedback-tests.txt, cross-tool-regression.txt, final-targeted.txt,
pyright-offline-final.txt, state-classification-retest.txt, full-pytest.txt, full-pytest-final.txt. Preliminary wrapper logs pyright-final.txt/pyright-new-tests.txt are retained for transparency and excluded from offline acceptance.

Procedural exception: preliminary invocations of the Python Pyright wrapper
automatically queried PyPI release metadata. They were not fully offline and
are explicitly excluded from acceptance evidence. No target/provider call or
package installation occurred. The replacement invokes the bundled checker
directly with local Node and a preload disabling TCP/TLS/HTTP/DNS/UDP/fetch.
No wrapper update check, npm operation or package download is used.

The first full run found an audit-introduced regression: early record_input
required-field validation masked the existing no-objective workflow_state error
as invalid_args. The correction defers that action's missing-field check until
its existing objective/target context is resolved, sharing ACTION_REQUIRED via a
small helper rather than duplicating admission. Argument-only matrix fixtures
now establish valid context; all assertions remain. The original failing test
and 191 related cases pass. A fresh full run on this final source is recorded
separately above; the first run is not relabeled green.

## Provider compatibility and frozen contracts

No provider adapter changed, and no oneOf/strict/splitting/conditional-schema
rollout was introduced. New contracts use fields already exercised by current
encoders: descriptions, properties, required guidance, integer bounds and regex.
All 34 native declarations pass local JSON Schema validation and offline
encoding tests for Direct/Whole-target with OpenAI-compatible, DeepSeek,
Anthropic and Gemini. Existing tests additionally cover objective projections,
stream/nonstream, typed/dictionary specs and mocked transport retry snapshots.

Gemini normalization deliberately drops additionalProperties and uppercases
scalar types. That constraint loss remains explicit: named source-bound fields
and numeric limits survive, while runtime rejects unknown fields/bounds even
when the provider representation cannot enforce membership. Existing nullable
schema normalization behavior is unchanged. Offline encoding does not establish
live server acceptance/enforcement or model compliance.

Hashes are canonical compact sorted JSON (ASCII escaping), using a complete
native fixture before active-skill capability filtering; actual request tool sets
vary with current skills/state/configuration and must be logged separately.

| Contract | Direct | Whole-target |
|---|---|---|
| Workflow schema SHA-256 | 8bff2dfb4c67b62ec6d1ca68bd23cfeea83b0a0f95211005cd0c13378338128e | f08db67a3d9d92bfde4174601c685fa19cbf0097e8477f9b34821311155f5271 |
| Workflow schema bytes | 16,586 | 18,373 |
| Complete 34-tool fixture SHA-256 | ed8cc30db0bc672eeabd406e4698923cd7abacaf6058bd02de5621355ec9fddb | dbfe3148c2c4f7680292a01be865bb1d6bda09f12b99579cc46948b1348e55a1 |
| Complete fixture bytes | 42,901 | 44,688 |

The captured baseline Workflow hashes exactly match the previous acceptance:
Direct e68e095f0568b23e7a0381a65bc955684365d5a1217aa18427c2f27568e7763d
(15,148 bytes), Whole-target
9686410c013b0e9dc7826df1033378ab7167a94f37b707d16339140b78344836
(16,848 bytes). The Workflow increase is 1,438/1,525 serialized characters
(approximately 360/382 tokens by the repository's crude /4 estimate, not provider
tokenization). This is the explicit prevention/context tradeoff.

## Workflow and security invariants

Registry validates/gates dispatch and freezes arguments; active-skill projection
does not replace runtime enforcement. Exact target origin/effective port,
private-host grants, permission epochs/reviews, scope, resource admission and
cancellation remain unchanged. New schema/feedback does not manufacture IDs,
change target/resource/action, reinterpret permission or send a retry.

Workflow phase prerequisites, canonical input identity, Candidate/Attempt/source
binding, immutable evidence parents/snapshots, complete/untruncated terminal
source requirements, mutation/readback/cleanup proof, accepted Result seal,
coverage/finding eligibility/persistence/export and recovery bounds all remain
under existing validators. Semantic progress facts are read-only projections,
not acceptance receipts. Persisted historical records are not migrated.

## Residual risks, limitations and explicit deferrals

- Actual first-attempt correctness and model recovery rates are **unmeasured**.
  Deterministic/scripted tests prove contracts/accounting/feedback delivery, not
  reduced LLM error probability or better SQLi/XSS reasoning.
- Flat superset schemas remain intentionally portable. Some conditional required
  fields, action-specific enum subsets and field combinations rely on generated
  guidance plus runtime rejection. Evidence/assessment meaning and ownership
  cannot be established by regex or a successful tool receipt.
- DEFERRED: universal validation or strict/oneOf/tool-splitting redesign; a broad
  change has provider/context/compatibility costs beyond these demonstrated
  defects. Legacy read/search/capture defaults/coercions and skill-reader
  read/path/source_ref dependencies remain documented compatibility behavior.
  They do not bypass existing scope/permission/evidence gates; stronger
  structural schemas need a separate evidence-driven compatibility change.
- DEFERRED wording risk: XSS's broad statement about mutation/cleanup on
  record_result can be read too broadly, but current tool field membership and
  explicit record_attempt_state example disambiguate it. No explicit wrong call
  is prescribed and historical B used SQLi, not XSS. No playbook redesign is
  justified by that history; retain this as a non-blocking ambiguity to monitor.
- SPECULATIVE RISK: arbitrary future context reduction may lose an old non-state
  handle or user prose at hard context limits. Current retention/ownership
  projections and defined floors are tested; unlimited retention is not promised.
  Old Workflow IDs can be looked up in authoritative state; denied/unavailable
  content remains an honest limitation.
- Error kinds are not a perfect historical metric taxonomy: e.g. historical
  active-skill rejection was tool_exception, while HTTP 4xx/5xx were observations.
  Metrics must inspect structured code/diagnostic/context rather than blindly
  counting every exception as invalid arguments or every success as progress.
- Tracker novelty is bounded and transient; saturation conservatively withholds
  new credit. Long sessions/resume do not acquire a newly durable counter.
  Correction at a fully spent hard/resource budget is not guaranteed.
- Editors/app-servers are open. Per-write hash checks and final inventory can
  detect drift in the audited set, not prove exclusive ownership of the machine.
- Prior acceptance's full-suite timing/harness limitations remain part of its
  history; they are not retroactively relabeled by this new verification run.

No remaining confirmed defect is intentionally hidden by widening a validator,
deleting an assertion, increasing the four-iteration threshold or counting a
retry/error/prose change as synthetic progress. Deferred/speculative items do
not justify indefinite audit expansion.

## Metrics for the next operator-run experiment

Record model/provider/protocol version and exact model ID, runtime/config and
scope/permission mode, run/session/objective IDs, source/skill hashes, actual
projected tool-schema hash per request, context/compaction settings and capture
limits. Keep independent runs and historical datasets immutable. Compare
matched conditions; a single run cannot establish causality.

| Metric | Operational definition |
|---|---|
| First-attempt valid-call rate | Valid first dispatch proposals / all first dispatch proposals for defined logical operations; valid policy-denied proposals are tracked separately from malformed ones. Report denominator, capability/phase/argument subtypes. |
| Invalid tool-call count | Count malformed JSON/types/fields/enum/bounds/ref namespace/nonexistent-ref calls and semantically wrong tool/action/phase selections separately. Do not infer missing outbound schemas. |
| Retry success rate | Rejected correctable logical operations followed by an explicitly corrected, valid, accepted retry / eligible correctable failures with remaining authority/budget. Preserve owner/resource/intent/provenance; a different successful task is not recovery. |
| Wasted calls | Dispatch proposals yielding no task progress due to preventable contract/reference/planning errors, including repeated unchanged failures. Report useful metadata/reader work separately from accepted state progress. |
| Workflow correctness | Phase prerequisites and active-skill compliance; correct Candidate/Attempt/source owner, origin/session/epoch, immutable proof and required requests/cleanup; count violations and expected guards independently. |
| Workflow completion | Authoritative current completion contract, goals, coverage sync, cleanup and Finding persistence, with unresolved/blocked/partial outcomes explicit. TUI labels alone are insufficient. |
| Evidence/Finding integrity | Real owned usable sources and immutable proof; accepted sealed Result; eligible persisted Finding and separate export status. No finding is a permissible outcome of an honest bounded test. |
| Anti-stall outcomes | Per iteration: progress_kind, observed vs credited facts, novel activities, no_progress, phase/exploration usage and stop reason. Manually review boundary traces for false stall/false progress; useful prose does not count as structured state. |

Classify separately: invalid arguments; wrong-reference/owner/phase/capability;
expected permission/scope/policy/resource denial; network/TLS/timeout/cancel;
observed HTTP validation outcomes; accepted/unresolved assessment; persistence/
export failures. Never aggregate those as one model error rate. A later changed
resource/action/owner is a different operation, not an argument repair.

## Final acceptance decision

**READY** for an operator-controlled live re-test of the frozen baseline.

The three confirmed semantic progress defects and four demonstrated contract/
feedback gaps in the decision matrix are resolved within the audited scope.
All new positive/negative cases and the preserved state-classification regression pass.
The final full run has 8,896 passed, 12 skipped and zero failures; the guarded
offline Pyright check also passes.
No failing node remains. The two pytest warnings are intentional malformed-
configuration fixtures; skipped cases retain their existing asset/opt-in gates.

The existing scope, permissions, resource bounds, phase/owner/provenance,
evidence/Finding integrity, cancellation and four-iteration Anti-stall guards
remain intact. Existing encoding transformations and live-model uncertainty
are disclosed above. This is readiness for measurement, not evidence that an
actual LLM's first-attempt validity or recovery rate has improved.

Final scope is **5 production files, 3 new test files, 1 existing argument-matrix
fixture adjustment, and this new report**. The original semantic failure test
is unchanged; no assertion/skip was weakened. All prior reports and the 3,107
protected historical files retain their bytes, with no new/missing historical
file. The reviewed source/tests match the isolated verification copy. No
reset, checkout, clean, stash, stage, commit or push was performed.

The preliminary Pyright wrapper's PyPI metadata request remains a disclosed
procedural exception, excluded from acceptance evidence and replaced by the
network-disabled local checker. No target/provider re-test or package
installation was performed. No Scenario 1, lan-09 or live pentest is launched.
Work stops at this offline acceptance; the operator decides when to re-test.
