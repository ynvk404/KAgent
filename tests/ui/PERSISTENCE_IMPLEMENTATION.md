# Persistence implementation checkpoint report

Base HEAD: `772aea42d559fc544a826b8117f463d81e9e003a`.
This session implemented C1 and stopped at the C2 safety gate. It did not
implement all five boundaries. Overall verdict: **NOT READY** for the requested
controlled live validation of the five-boundary fix. No live freeze root cause
is established by these offline results.

## Checkpoint verdicts

| Checkpoint | Verdict | Evidence / limitation |
|---|---|---|
| C1 session | PASS WITH LIMITATIONS | Mounted Textual oracle passes; worker, ownership, failure, checkpoint and resume regressions pass. Snapshot construction still runs on the loop; CPU cost is unmeasured. |
| C2 file / evidence | BLOCKED | A naive loop validation -> worker write handoff permits a stale receipt to write. A safe handoff preserving current authoritative checks has not been established. No C2 production edits were retained or applied. |
| C3 finding / summary | BLOCKED | Not started, following the required checkpoint ordering. |
| C4 integrated / independent review | BLOCKED | Full five-boundary acceptance and independent review were not reached. C1 regression integration and local final diff review were completed. |

The stop follows the request's hard stop when permission/runtime guards would
need changes outside scope or security guarantees cannot be established. It
is not a claim that a correct C2 design is impossible.

## Fixed boundary and execution topology

`src/session/store.py`: `Store.save()` previously performed message projection,
redaction, JSON encoding, mkdir/chmod, temp creation, write/flush/fsync and
replace synchronously in its async method. Message serialization/redaction/JSON
and filesystem persistence now execute in joined thread tasks.

Before the first await, the controller takes detached copies of messages,
target, memory, workflow and engagement projections. The worker has sole
ownership of those copies. No live WorkflowState, Agent, permission policy or
Textual object is submitted to the serializer. The controller retains workflow
projection, lock acquisition, save_count/fsync cadence and diagnostics updates.
Workers dispatch diagnostic stage strings with `loop.call_soon_threadsafe`;
they do not directly update diagnostics/UI state.

Cooperating stores with the same normalized absolute session pathname share a
weakly held asyncio lock. It covers serialization through write completion,
context snapshot writes and clear. Cancellation repeatedly shields and drains
the pending worker before releasing that lock. Worker failure during drain is
retrieved while cancellation remains the caller's outcome. Cancelled
serialization never starts a filesystem writer; cancelled in-progress writes
may complete their atomic replacement before cancellation finishes. Queued
cancelled saves do not enter a worker.

`save_context_snapshot()` and `clear()` now use joined workers under the same
ownership lock. Temp files still use exclusive creation and mode 0600; session
and context directories remain 0700. Atomic replace, per-store fsync cadence
(first and every fifth save), context fsync, redaction, file locations and JSON
schema are preserved. A failing fdopen closes the untransferred descriptor.
`load()` and synchronous startup/list helpers retain their existing API.

## Before / after measurements

All times are milliseconds; cancellation times are relative to operation start.
Baseline is this session's `--runxfail` run. After is the final C1 mounted run.

| Session save/fsync | Operation | Heartbeat gap | Esc delivery | Cancel requested | Cancel completed | Operation ticks |
|---|---:|---:|---:|---:|---:|---:|
| Before | 401.9 | 428.1 | 356.6 | 407.8 | 408.2 | 0 |
| After | 413.2 | 32.7 | 1.5 | 64.0 | 413.3 | 21 |

The held fsync now executes outside the UI thread. The final yielding control
had a 24.0 ms heartbeat gap, 0.9 ms Esc delivery and 21 operation ticks.
The original 120 ms responsiveness thresholds and all integrity/harness
assertions remain unchanged. The harness measures cooperative AbortEvent
acknowledgement after the operation, not every real Agent unwind path. Separate
worker tests exercise actual task cancellation, repeated cancellation and
asyncio deadline draining.

## C2 safety investigation

Source review found that FileWriteTool calls
`ExecutionPolicy.revalidate_active()` after parent creation and immediately
before writing. The guard binds live authority to a resource digest computed
using resolve/stat. Simply moving the whole tool body into a thread would send
live policy to a worker. Validating on the loop and then submitting a writer
adds an asynchronous window before that writer consumes the authority.

A temporary, controlled `/tmp` probe used the real ExecutionPolicy
prepare/start/revalidate APIs and held a proposed writer before mutation. After
the loop guard passed, the controller advanced the policy revision. The real
revalidation then rejected the receipt; the naive submitted writer nevertheless
created its synthetic file when released. Output:

```text
C2 probe: real controller guard rejects revoked receipt before write
C2 probe: naive final-loop-guard -> worker handoff still writes after revocation; rejected design
```

This probe tests a rejected design, not an installed production patch. It does
not exhaust safe alternatives. A future C2 implementation needs a checked
handoff covering authority/resource changes during its new worker windows,
with appropriate mutation tests, without moving live guards into workers or
weakening policy. No production FileWriteTool, evidence, finding or summary
behavior was changed in this session. Their four strict XFAILs remain.

## Verification

All Python/pytest commands used `venv-linux/bin/python`; Pyright used
`venv-linux/bin/pyright`. No dependency installs, live LLM, Burp or external
HTTP calls were performed.

- Baseline `-m pytest -q -s --tb=short -p no:cacheprovider tests/ui/test_persistence_responsiveness.py`:
  **6 passed, 5 xfailed** (33.66 s).
- Baseline same command with `--runxfail`: **5 expected responsiveness failures,
  6 passed** (20.65 s); no integrity/harness failures.
- C1 original focused group (session store, checkpoint artifacts, compaction
  resume, session debug): initially **80 passed, 2 failed**. Both failures were
  real retry saves inheriting the test's 20 ms fault-injection deadline.
  Restoring the runtime deadline for the retry resolved these; the injected
  error/timeout assertions were retained. Subsequent focused run including
  the first 13 new worker tests: **95 passed** (25.96 s).
- Final `-m pytest -q --tb=short -p no:cacheprovider tests/state/test_session_persistence_async.py`:
  **24 passed** (4.74 s). Includes held serialize/mkdir/open/replace/chmod,
  context fsync and unlink; overlapping snapshots; repeated cancellation;
  worker failure while draining; cancelled queued save; context retry; actual
  deadline draining; serializer/open/fdopen/write/flush/fsync failures; temp
  cleanup and descriptor ownership.
- Mounted full responsiveness group after C1: **7 passed, 4 xfailed** (20.24 s).
  Only session_save's strict XFAIL was removed. After the final descriptor
  cleanup refinement, reran the same group with `-k session_save`: **2 passed,
  9 deselected** (8.00 s).
- Final relevant integration/regression command: **191 passed** (40.75 s),
  no failures/XFAIL/skips:

```bash
PYTHONDONTWRITEBYTECODE=1 venv-linux/bin/python -m pytest -q --tb=short -p no:cacheprovider -p tests.scenarios.offline_checkpoint \
  tests/state/test_session_store.py \
  tests/integration/test_workflow_checkpoint_artifacts.py \
  tests/agent/test_resume_after_compaction.py \
  tests/agent/test_planner_emission.py \
  tests/agent/test_workflow_request_preparation.py \
  tests/runtime/test_session_debug.py \
  tests/security/test_session_authorization.py \
  tests/security/test_yolo_results_resume.py \
  tests/security/test_execution_policy.py
```

The offline responsibility guard covers applicable manifest tests, including
execution-policy and checkpoint tests. The Textual reproduction group retains
its own socket/DNS guards.

```bash
venv-linux/bin/pyright src/session/store.py \
  tests/state/test_session_persistence_async.py \
  tests/integration/test_workflow_checkpoint_artifacts.py \
  tests/ui/test_persistence_responsiveness.py
```

Pyright: **0 errors, 0 warnings, 0 informations**. Its available-version notice
was informational; nothing was installed. Final `git diff --check` passed.
Tracked diff, new test, marker change and worktree status were reviewed locally.
No independent reviewer was used. Full repository suite and downstream C2/C3
verification were not run because the checkpoint sequence stopped at C2.

## Safety evidence and remaining limits

Existing tests cover JSON/redaction/schema compatibility, secure file/directory
modes, exclusive temp ownership, workflow checkpoint consistency, compaction
resume, permission denial/stale review and Planner emission. New tests show
that in-process cooperating writers cannot release ownership while a cancelled
worker is still writing, and that failures preserve the previous checkpoint
and clean owned temp files. Canonical finding/evidence paths were not modified;
no new claim is made about their safety or responsiveness.

Snapshot deepcopy and WorkflowState/EngagementState projection still run on the
controller loop. Worker offloading does not guarantee freedom from GIL-related
CPU stalls. No CPU optimization/instrumentation was added without measurement.
The shared lock is for one process/event loop and the same normalized pathname;
it is not cross-process locking or inode/parent-symlink alias coordination.
Save fsync semantics match the original implementation, including the absence
of a new parent-directory fsync. Cancellation completion can wait for a slow or
stuck syscall; the UI remains free to schedule during this drain.

Synthetic I/O measurements ran under `/tmp`; ordinary regression tests use
their existing temp fixtures. Natural `/mnt/d`/WSL filesystem latency and live
Burp correlation were not measured. Four known blocking boundaries remain.

## Changed files

- `src/session/store.py`: detached session snapshot, offloaded serializer and
  atomic writers, shared ownership, cancellation drain, offloaded context/clear,
  fdopen descriptor cleanup.
- `tests/state/test_session_persistence_async.py`: 24 focused regressions.
- `tests/integration/test_workflow_checkpoint_artifacts.py`: restore the runtime
  checkpoint deadline only for retry after the artificial failure.
- `tests/ui/test_persistence_responsiveness.py`: per-boundary marker selection;
  removed only session_save's XFAIL. Oracle/harness otherwise unchanged.
- `tests/ui/PERSISTENCE_IMPLEMENTATION.md`: this report.

Pre-existing changes to `src/agent/agent.py`,
`tests/agent/test_planner_emission.py` and
`tests/ui/PERSISTENCE_REPRODUCTION.md` were preserved. No commits, pushes,
resets, restores, clean operations or live validation were performed.
