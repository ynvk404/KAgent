# Lan-23 remediation

Implementation baseline: `8b4e5fafc2c381c290d0d1d77f73ceaed88eabef`, clean worktree.
The forensic baseline is the completed audit in this chat, checked against
`experiments/scenario3/runs/lan-23/` and the lan-22 remediation report. Actual
session: `19c63def-33e4-4c34-ba6f-c8975eec463b`. No historical run is repaired.

All execution in this task is offline. The test suite uses the existing
`tests.system.offline_suite` socket boundary; transport/model fixtures do not
constitute a live SQLi experiment. No packages, target changes, scanners,
external providers, commits or pushes are part of this remediation.

## Root causes and changes

| Responsibility | Demonstrated cause | Implementation |
|---|---|---|
| Evidence | Registration was mistaken for terminal eligibility; truncated history was registered as proof parents | Registration returns capture readiness, usable IDs and all unusable parents separately from `terminal_assessment_accepted=false`. The owned inventory exposes capture usability. Existing terminal gates remain authoritative. |
| Immutable proof | The Agent changed parents without rewriting proof content | Structured errors expose bounded canonical offending IDs. Feedback directs a genuine source rewrite and new snapshot; incomplete history stays in the ledger or a separate history artifact. No parent rebinding or snapshot edits. |
| Effects | Further requests invalidated an earlier no-mutation declaration, unnoticed during repair | Existing handoff projects declaration validity, dispatch count and uncertainty. Transient continuation feedback requires a new evidence-based declaration after necessary target actions finish. The original invalidation behavior is unchanged. |
| Negative SQLi | Equal intended Boolean responses were called a completed negative without an established oracle | New SQLi negative submissions require `assessment.oracle_status=established` and a nonempty `oracle_basis`. Unknown/inconclusive status receives `UNRESOLVED_ORACLE`, a bounded validation-step response. Historical results are not rewritten. |
| Technique choice | The Agent reused the sibling handler's Boolean hypothesis and treated ineffective syntax as a negative | Feedback requests reassessment of compatibility, competing hypotheses, capabilities and remaining limits. Boolean criteria are explicitly conditional on selecting Boolean confirmation. No technique order or exhaustive requirement is added. |
| Input provenance | Caller-supplied method/body/auth assumptions appeared canonical without clear uncertainty | `record_input` and `get_input` project provenance and unknown authentication requirements separately from the caller's input declaration. Candidate observation receipts include retained byte size and response hash tied to the exact request. Existing cross-endpoint/method admission remains enforced. |
| Documentation | The retained Swagger source was complete. Canonical inputs were recorded before referenced schema types were read; the later correct inventory did not reconcile the omitted array and incorrect object type | The specialized extraction helper remains removed. Option C defaults to reading enough relevant request/schema definitions before declaring a type, without requiring the whole document. Unknown types stay unspecified after bounded reading. Handoff/triage checks reuse available context and account for newly discovered fields; existing attributed replacement/drop is exceptional recovery for an incorrect record, preserving identity, provenance and terminal history. |
| Operator questions | Unsupported access assumptions were presented as reasons to supply credentials or exclude coverage | Input-bound questions require a kind and concrete basis. An access question for an unverified input is rejected before prompting. The displayed question identifies exact method/path/input, the Agent-reported dependency, uncertainty and the scope of Exclude. Cached answers and permissions remain unchanged. |
| Progress | Reviewed included exclusions; accepted included negatives; pending included deferred goals | The overview keeps workflow status/phase and persisted finding count. Detailed inputs, accepted results, pending goals and blocker reasons remain in canonical records and existing outcome views. |
| Loaded Skill | Skill activation was confused with phase progression in the earlier discussion | No change to Skill activation/status-bar semantics. Loading SQLi during Input Analysis remains legitimate; independent analyzed candidates can proceed while other inputs remain open. |
| Responsiveness | A guard repeatedly estimated the same large request while iterating preserved history | Cache the estimate within one guard invocation, invalidating it on each content replacement. No tokenizer policy, threshold, evidence retention or provider budget is changed. |

## Production files

- `src/tools/workflow/workflow_tool.py`: evidence readiness, effects projection,
  negative admission, input provenance and exact observation metadata.
- `src/workflow/assessment.py`: shared capture usability and bounded offending ID.
- `src/workflow/evidence/errors.py`: structured actionable repair/reassessment.
- `src/workflow/discovery/input_view.py`: read-only provenance projection.
- The temporary documentation helper and its reader integration are removed.
  `src/tools/common/tool_result.py` is back to its prior generic range/search
  implementation, including existing permissions, provenance and output limits.
- `src/tools/common/ask.py`: input dependency declaration, question clarity and
  rejection of unsupported access prerequisites.
- `src/agent/validation_guidance.py`, `src/agent/action_guidance.py`: short current
  state guidance for the new contracts, not a new planner or execution loop.
- `src/agent/agent.py`: guard-local estimate reuse only.
- `src/ui/core/outcomes.py`: compact canonical Progress only.
- `skills/sql-injection/SKILL.md`, `skills/web-input-analysis/SKILL.md`,
  `skills/web-enumeration/SKILL.md`: small updates documenting actual tool contracts.

## Offline regression evidence

New regressions are in:

- `tests/security/test_lan23_validation_lifecycle.py`: real bounded fixture captures,
  truncated history and complete replacements, rejected parents, rewrite/new
  snapshot, recovery without repair HTTP, source preservation, resume, effects
  invalidation/re-declaration, meaningful versus unresolved negatives and delivery
  of strategy feedback to a scripted model.
- `tests/tools/test_lan23_input_context.py`: unsourced input uncertainty, access
  question rejection, exact affected inputs/exclusion scope, cross-endpoint
  rejection and exact response-size attribution despite incorrect model prose.
- `tests/skills/test_inline_openapi_guidance.py` and the sanitized retained
  `tests/fixtures/lan23-swagger-initializer.js`: read-first registration of the
  correct types from relevant retained windows without replacement/drop or a
  whole-document read; recovery of existing premature object/unknown records
  after later array/string definitions; unread/truncated/unresolved/unknown
  interpretation limits. Loaded playbook contracts cover checks that reuse
  context and refer to existing recovery instructions without duplicating them.
  These are scripted actions, not real-model reasoning evidence.
- `tests/ui/test_lan23_progress.py`: excluded inputs and accepted negatives do not
  inflate Progress; loaded Skill does not complete a phase or create an attempt.
- `tests/agent/test_lan23_context_cost.py`: preserved history initially caused 80
  full estimates in one guard pass; the new pass performs at most five and leaves
  every message unchanged.
- `tests/integration/test_lan23_handoff.py`: actual cross-skill loading during
  Input Analysis and new validation for an independently analyzed candidate while
  another input remains blocked and the global analysis phase remains incomplete.

Initial RED observations before the corresponding material changes:
5 failed/1 passed for evidence/effects/negative contracts; 2 failed/1 passed for
Progress/context cost; 3 failed/1 passed for input context/document review;
1 failed for the unsupported access question. Existing valid behavior tests
remained tests of valid behavior rather than being relabeled as defects.

Existing synthetic fixtures explicitly declare their oracle basis for meaningful
SQLi negatives. Existing UI tests retain canonical result/goal assertions while
checking the intentionally simplified headline. They do not weaken evidence,
permission, timing or live-test assertions.

The additional closed-attempt regression caught an initial projection that
incorrectly showed unknown mutation after an acknowledged write. The projection
now reuses `attempt_effects`, preserving the known write and unresolved cleanup.
The temporary parser-specific tests were removed with the helper in Option B;
the existing generic reader permission/integrity/ownership regressions remain.

Verification results before the Option B simplification (do not sum overlapping runs):

| Run | Result |
|---|---|
| Initial broad responsibility run: Agent, Skills, UI, Integration, State, Tools, Security, LLM, Benchmarks | **7,975 passed, 17 failed, 11 skipped**, 1,136.95 s |
| Re-run of every failed module after contract/fixture updates | **248 passed, 1 failed**, 110.43 s; only the existing 2,200-character hint bound remained |
| Same failing continuation test after shortening guidance, without increasing its bound | **1 passed**, 9.57 s |
| Final responsibility verification, including all previously failed modules and the new regressions | **630 passed**, 174.30 s |
| Full configured `venv-linux/bin/pyright` | **0 errors, 0 warnings, 0 informations** |
| Git whitespace check | `git diff --check` passed |
| Historical hash verification | **58/58** lan-22/lan-23 files unchanged |

The 17 broad failures were traced to legacy meaningful-negative fixtures missing
the new oracle declaration, strict old lookup-shape assertions, a conditional
Boolean wording assertion and an overlong continuation hint. The hint was
shortened; existing timing/token/recovery bounds were not raised. The valid
fixture declarations were made explicit rather than weakening production admission.
All failed modules are included in the final 630-test run; the entire 8,003-case
broad run was not repeated after these corrections. The 11 existing skips were
left intact. An initial pyright pass found nine new nullable-type assertions;
these were corrected before the final zero-error pass. The installed pyright's
update notice was ignored; no package was installed.

Raw verification logs and the historical hash manifest are under
`/tmp/kagent-lan23-remediation-yomhcut0/` (`broad.txt`, `affected.txt`,
`final-focused.txt`, `pyright-final.txt`, `historical-hashes.json`,
`historical-verification.json`). Git HEAD remains the baseline; no commit/push.

## Limits and deferred work

- The historical model trace has no internal `reasoning_content` for these
  decisions. Tool calls/public prose establish reuse of the Boolean hypothesis;
  the size of any example-order bias cannot be measured from this run.
  The Input Analysis handoff/attempt criteria already selected Boolean pairs for
  both inputs, and the API attempt's public explanation explicitly reused the
  sibling's TRUE payload. The shipped Skill already allowed context-dependent
  Boolean, controlled error, bounded UNION and time techniques without a fixed
  sequence. The demonstrated defect is failure to reconsider compatibility and
  an unsupported negative, not proof that the Skill mandated Boolean testing.
- An explicit oracle declaration is still an Agent assessment. Runtime verifies
  the contract and source integrity, not speculative SQL semantics or every
  sentence of model prose. A model can still misinterpret valid observations.
- Manual document attribution stays caller-declared. Generic retained reads do
  not interpret schemas or reconcile inputs automatically. The playbooks require
  this check, but runtime cannot prove that a model read or understood every
  relevant definition. Incomplete reading, eviction, dynamic JavaScript,
  unresolved `$ref`, unknown types and unsupported schema composition remain
  explicit limitations; retained completeness is not interpretation completeness.
  No specialized OpenAPI extraction path remains, and no parser replaces it.
- Context compaction scheduling inside a long active attempt and debug writer
  priority/backpressure remain separate work. No arbitrary threshold, budget,
  transcript fidelity or diagnostic scheduling change is used to mask them.
- Scripted tests demonstrate delivery, rejection, recovery and preserved contracts;
  they do not demonstrate improved real-model SQLi detection or reasoning.

The revised lifecycle supports rewriting a Search-like proof using complete
retained observations while preserving truncated history and immutable snapshots.
It does not reopen the historical closed attempt or authorize a target retest.

## Readiness

**READY WITH LIMITATIONS.** The implemented contracts provide a valid offline
recovery path for a Search-like failure, protect unsupported negative submissions
and expose provenance/coverage uncertainty more clearly. A new explicitly
authorized lab experiment is appropriate to measure actual model behavior; none
was run in this task. Keep build/model/config/target state recorded, and inspect
the first new run for strategy reassessment, consistent proof parents and effects
ordering. Context compaction scheduling and debug-log loss remain independent
limitations, not evidence that SQLi detection has improved or the historical
lan-23 finding has been recovered.
