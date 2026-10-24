# Default TUI operation-error presentation

The default TUI presents assessment progress and results. A failed tool
invocation remains complete feedback for the model, session and raw event
consumers, but does not produce a technical error row merely because the
invocation was rejected. A later retry does not replace or clear a prior row.

The UI issue ledger, retry identities, matching/ambiguity/resource accounting,
recovered notices and unresolved-operation counters have been removed. The
independent bounded invocation ledger still rejects duplicate, retired,
unknown and stale results across Clear, turn and scope transitions. Progress
replacement, streaming, viewport and selection infrastructure is unchanged.

## Visible outcomes and native metadata

Workflow facts and `DoneEvent.stop_reason` remain authoritative for completion,
blockers, missing evidence, incomplete goals, cleanup, coverage synchronization
and confirmed-but-unsaved results. Permission and user-input modals retain
their existing lifecycle. Slash-command errors, including `/burp lists`, still
append an error entry directly; the renderer does not filter error roles.

Native producers can attach `presentation_impact` with one of four values:

- `operation`: transient feedback that does not need a default transcript row.
- `intervention`: an operator must act, such as renewing an exhausted HTTP grant.
- `session`: a session constraint, such as an exhausted execution call budget.
- `persistence`: a result could not be saved or a report could not be exported.

Exceptions carry a transient attribute without changing their type, identity,
message or propagation. `ErrorEvent` keeps its existing wire fields and unknown
runtime errors remain visible. Malformed-call retry and automatic compaction
diagnostics are explicitly marked at their producers, not recognized by prose.

`ToolOutput` and `ToolCallResult` forward the optional native annotation to the
single additive `ToolResultEvent.presentation_impact` field. Existing fields,
including `RecoveryReceipt` and `accepted_candidate_id`, remain available to raw
observability/headless consumers. No annotation grants execution rights,
changes an error status, or creates a retry or stop decision. Output prose,
including a forged export-failure marker, cannot supply presentation authority.

Native file write/edit and canonical Finding write failures retain their
exception and error outcome.
Compact report export failure retains the already persisted Finding and its
successful operation status, while exposing the failed derivative export.
Native result metadata also exposes failed or memory-only persistence. These
warnings are ordinary transcript entries; there is no replacement issue store
or inferred reconciliation after a subsequent success.

`result_issues` and its native/legacy receipt diagnostics still protect the
independent operation-completion predicate. Accepted validation/Finding
milestones continue to require actual scoped Workflow/evidence/persistence
facts. HTTP observations, including 4xx/5xx, do not establish validation success.

## Boundaries

Logging occurs before TUI projection. Projection never rewrites raw events,
model feedback, saved sessions, evidence or coverage. Headless status, benchmark
event counting/scoring, runtime iteration, permission gates and Evidence
Recovery/Validation Closure are unchanged. The native receipt is retained for
observability rather than replaced by a compatibility recovery implementation.

Runtime warnings already embedded in assistant text remain intact. They are
not removed by regex, and model prompts/content are unchanged.

This describes current behavior and supersedes the presentation policy in
`tui-presentation-audit.md`. The historical recovery RCA and acceptance reports
remain records of their original implementations and verification runs.

## Producer and consumer inventory

```text
Registry.execute / _execute (validation and permission gates unchanged)
  -> native ToolOutput or original annotated exception
  -> Agent.run_parsed_tool_call / ToolCallResult / _tool_result_event
  -> ToolResultEvent or ErrorEvent
     -> SessionDebugLogger / headless / benchmark raw-event consumers (unchanged)
     -> app.run_agent_turn.handle_event / runtime_facts / reducer
        -> TranscriptEntry / Transcript / TranscriptView
        -> _finish_outcome / TurnDetails / TurnDetailsModal
```

`record_tool_result` still records complete feedback for model history and the
next request; session persistence and raw logs keep their existing contracts.
The annotation does not enter the session schema.

Production changes are limited to these responsibilities:

| Files | Change |
| --- | --- |
| `src/ui/core/state.py` | Remove `PresentedIssue`, `_present_issue`, `_repairable`, `_retry_call`, `_recover_issues`, chronology and issue counters; append meaningful native notices; derive outcomes from current facts and requests. |
| `src/ui/core/admission.py` | Remove retry-only identities, hashes, resource/result matching and obsolete pagination-row formatting; retain invocation lookup, search semantics and completion diagnostics. |
| `src/ui/core/outcomes.py` | Remove recovery-only `operation_owner`, `operation_intent`, `operation_candidate_id` and `accepted_call`; retain scoped accepted-result, evidence, Attempt and Finding checks. |
| `src/tools/common/outcome.py`, `src/agent/events.py` | Define the optional impact contract; preserve exception identity and all existing event fields. |
| `src/agent/agent.py` | Forward native impact, annotate existing session-save/compaction/malformed-call errors and remove `_selected_capture_presentation_args`; retain execution binding and native receipts. |
| `src/permission/runtime/execution.py`, `src/permission/network/grants.py` | Annotate existing session-budget and operator-renewal failures without changing their conditions or decisions. |
| `src/tools/workflow/finding.py`, `src/tools/execution/file.py` | Annotate actual persistence failures; keep canonical Finding success separate from derivative export failure. |
| `src/ui/widgets/transcript.py` | Comment wording only; error/warning roles and renderer behavior remain available. |

The bounded `call_history`, tombstones, `pending_calls`, `_remember_call`,
`_retire_calls` and `delivered_results` remain independent of presentation.
`TurnDetails` retains stop reason, saved/unsaved findings, incomplete validations
and goals, remaining work and completed operations. Its removed counters were
derived from historical issues, rather than current requests or persisted facts.

## Offline verification

Verification used the existing `venv-linux`, fake model/tool fixtures and
MockTransport. The new regression runs with the unmodified strict
`tests.scenarios.offline_checkpoint` plugin:

```bash
venv-linux/bin/python -B -m pytest -q -p no:cacheprovider \
  -p tests.scenarios.offline_checkpoint \
  tests/ui/test_operation_error_visibility.py
```

The first 75 tests were run against the captured, already dirty production
baseline: 61 failed because operation errors were still visible, and 14 passed.
The final regression has 92 passing cases. A separate four-case regression for
forged export notices also failed before its fix and passed afterward.

Responsibility groups ran in a disposable copy of the current dirty/untracked
source, tests, skills and configuration, excluding experimental runs and durable
stores. A temporary harness reused the strict scenario boundary, redirected
stores and responsiveness fixtures into scratch, and allowed only the exact
theme/process-output probe commands required by existing tests. All sockets
remained blocked; it did not grant arbitrary loopback or subprocess access.

| Check | Result |
| --- | --- |
| Strict new presentation regression | 92 passed |
| Final affected UI and execution-policy responsibility group | 470 passed |
| Runtime metadata, native tool outcomes, shell diagnostics, execution policy, closure and benchmark counter group | 136 passed |
| Final broad UI/native receipt/integration/security/headless/debug/Finding group | 1,729 passed, 2 failed |
| Pyright (`src`, `tests`, `benchmarks`) | 0 errors, 0 warnings, 0 informations |
| `git diff --check` | Passed |

These runs overlap and are not a unique combined test count. No live provider,
target, benchmark runner or experimental run was invoked. No package was
installed or updated, and no skip/xfail was added.

The two broad-group failures are existing Markdown table-width tests:
`TestRenderMarkdown.test_wraps_long_table_cells_inside_coherent_borders`
(75 columns versus 36) and
`TestRenderMarkdown.test_narrow_table_respects_requested_terminal_width`
(61 versus 28). Both failed identically in a separate disposable copy of the
captured production baseline. Their implementation and tests were left alone.
None of the reported groups skipped tests. The full repository suite and live
integration/provider tests were not run.

The tests exercise native denial before dispatch/mutation, subsequent model
feedback, session messages and raw debug/headless event fields, HTTP request
identity/receipts and evidence/Finding integrity. Headless status and benchmark
counter checks remain independent of the UI projection.

## Baseline and data-integrity limits

Task changes were reviewed against the initial dirty worktree: 11 production
files, 19 existing test files, one new test and this document. Unrelated existing
source changes, including the Anti-Stall removal, remain intact. There was no
commit, push, reset, restore, stash or profile-hash refresh.

SHA-256 comparison covered 3,117 protected files under project `experiments`,
`artifacts` and `.kagent`. No files were added in those protected roots. Two
lan-17 files differed from the initial hashes during the task:

- `experiments/scenario3/runs/lan-17/logs/session.jsonl`
- `experiments/scenario3/runs/lan-17/profile-home/.kagent/context/6f619392-c3d3-4844-af9a-7b877a9fa960.md`

Their writer could not be identified with read-only inspection; they were not
restored. The remaining protected hashes, including lan-16 and profile
manifests/hashes, matched. Full historical-data immutability therefore cannot be
certified. This limitation and the two baseline test failures prevent a claim
of an entirely green repository or fully verified data invariance.
