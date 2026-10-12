# Persistence freeze — instrumentation, reproduction, targeted C4 fix

Base HEAD: `a303731eece8a62de851e930cb30cfe7bf9043f9`.
Offline only; no HTTP, LLM, Burp, dependency installation or commits.
Four pre-existing untracked audit/feasibility files were preserved.

**Result:** C4 canonical post-read causes the controlled freeze and is now fixed.
This does **not** eliminate all persistence stalls. Natural WSL evidence operations
still block the loop. The historical live freeze remains unproven. C2/C3 and C5
publication were not modified; their security/ownership gates remain authoritative.

## Instrumentation and scope

`persistence_diagnostics.py` installs scoped test wrappers around production
boundaries. No instrumentation is enabled in normal runtime. `Trace.enabled=False`
disables recording; wrappers disappear at fixture teardown. Each trace uses
monotonic time, a correlation ID, thread ID and actual running-loop ownership.
The ring is capped at 256 events, or 2048 with opt-in filesystem detail. Runs
assert zero dropped events. No arguments, paths, content, return values, exception
messages, credentials or raw evidence are recorded.

Measured: operation and synchronous stage start/end/duration; real Textual timer
ticks and Esc delivery; cooperative AbortEvent request/completion; thread dispatch,
start/completion/join; actual task cancellation/drain in C4 regressions; evidence
revalidation, workflow persisted mark, summary preparation/publication/fsync,
notifier and TUI tool events. Detailed natural runs include resolve/stat/exists/
is_file and permission-aware evidence verification. Wrappers add no await inside
synchronous publication or permission checks. Instrumentation has a small timing
cost and cannot establish filesystem crash guarantees.

The harness uses real stores/tools and temporary directories with synthetic data.
Session save/context checkpoint/retry/load, new/existing FileWrite, evidence
capture/snapshot/retry, canonical finding/readback, summary export, a synthetic
confirmed SQLi finding chain and a combined C1–C5 chain are exercised. SQLi
confirmation is an explicit existing test assessment fixture; no vulnerability
testing occurs. `tui_chain` additionally binds a real WorkflowState/WorkflowTool
to the mounted UI and asserts that a finding milestone appears. The Agent run
is fake; optional runtime Burp notification is replaced with a synthetic callback.
The original mounted oracle and thresholds remain authoritative.

## Boundary evidence

Values below are milliseconds from the **before** matrix with one 400 ms injected
hold per operation. Synchronous spans are nested wall-time measurements; do not
sum them. Fast integrity checks performed by the harness may also appear.

| Boundary | Blocking span on loop | Heartbeat gap | Esc latency | Actual cause / classification | Confidence |
|---|---:|---:|---:|---|---|
| C1 session | 0.2 max; hold runs in worker | 22.1 | 0.8 | Existing joined workers; **NOT RESPONSIBLE FOR REPRODUCTION** | High for these fixtures |
| C2 FileWrite new / existing | 400.2 / 400.2 | 422.9 / 422.8 | 386.5 / 381.0 | Synchronous write; **CONFIRMED BLOCKING, LIVE IMPACT UNPROVEN** | High synthetic; natural sampled writes responsive |
| C3 capture/snapshot/retry | 401.4 | 434.7 | 396.5 | Source reads and snapshot transaction run on loop; **CONFIRMED ROOT CAUSE** of offline evidence stall | High synthetic and repeated natural WSL batch |
| C4 canonical post-read | 400.3 | 406.7 | 378.4 | Read/parse after joined writer executes on loop; **CONFIRMED ROOT CAUSE** of controlled finding stall | High; historical live impact unproven |
| C5 directory fsync | 400.2 | 406.9 | 376.6 | Post-replace fsync runs on loop; **CONFIRMED BLOCKING, LIVE IMPACT UNPROVEN** for this syscall | High synthetic; natural fsync was short |

C2 is **NOT RESPONSIBLE FOR REPRODUCTION** of the finding-only SQLi chain:
FileWrite is not invoked there. A natural summary stall also occurred in the
loaded WSL run: synchronous lookup/path/link/destination checks before dispatch
accumulated about 166 ms. It was not a slow FileWrite or a 400 ms directory fsync.
Filesystem latency sensitivity is established; attribution to a particular host
load source is a **HYPOTHESIS**, since host I/O counters were not collected.

No deadlock or permanently unfinished workflow was reproduced. Operations
completed, locks released, retry deduplicated reports, and finding status was
persisted when guards accepted the result. Cancellation delivery can starve while
synchronous work blocks; completion waiting for a joined worker is expected drain,
not an orphan or immediate rollback. C4 retains existing worker-error precedence.

## Before / after and finding timeline

Same 400 ms fault, same scenario, same heartbeat/Esc limits:

| Scenario | Operation before → after | Heartbeat before → after | Esc before → after |
|---|---:|---:|---:|
| Finding canonical post-read | 406.3 → 406.6 | 406.7 → 21.9 | 378.4 → 0.9 |
| Confirmed SQLi finding + summary + UI dispatch | 431.8 → 430.9 | 418.2 → 64.6 | 390.2 → 2.3 |
| Combined C1–C5 chain | 434.7 → 450.1 | 417.3 → 32.9 | 386.0 → 1.0 |

The original mounted production oracle independently measured C4 after the fix:
407.4 ms operation, 24.8 ms heartbeat, 2.0 ms Esc, and post-read off the UI thread.
Total I/O duration remains similar; event-loop availability improves. No artificial
sleep or threshold reduction was added to production.

Representative SQLi timeline, relative to operation start:

| Phase | Before | After |
|---|---|---|
| Pre-save evidence verification ends | 2.3 | 9.7 |
| Held canonical read | 8.6–409.0 on loop | Within joined worker; save ends 424.2 |
| Esc sent / delivered | 33.8 / 424.0 | 54.6 / 56.9 |
| Post-save evidence verification ends | 413.3 | 426.0 |
| Workflow persisted mark ends | 414.8 | 426.5 |
| Summary export ends | 429.6 | 429.9 |
| Notifier ends | 429.6 | 429.9 |
| TUI dispatch / operation ends | 431.8 | 430.9 |

The before trace isolates post-read after the writer completed, before persisted
mark/summary/UI. After the patch, those finalizers still execute on the controller.
The real workflow-backed `tui_chain` completes with a displayed finding; with a
400 ms worker read its heartbeat is 35.7 ms and Esc is 0.9 ms. No claim is made
about live optional integration callbacks.

All operation timelines and cancellation traces are in
[PERSISTENCE_FREEZE_TRACE.json](PERSISTENCE_FREEZE_TRACE.json). This bounded archive
retains boundary events and slow filesystem spans; raw tick/fast-filesystem
detail remains in `/tmp/kagent-persistence-{before,after-final,wsl,wsl-final,wsl-repeat}.json`.
Actual C4 task-cancel traces show repeated drain requests, worker completion
before save exits, and a retry blocked by shared ownership until that completion.

## Synthetic versus natural filesystem results

The matrix ran 0, 100 and 400 ms faults. Only synthetic runs hold a selected
syscall; natural runs do not sleep. On `/tmp`, before/after natural operations
took roughly 0.8–45 ms; heartbeat gaps stayed below 60 ms. Fast operations do not
need three in-operation ticks, so natural observations do not pretend to pass
the long-operation oracle by applying that assertion to sub-tick operations.

Host: WSL2 `6.18.33.2-microsoft-standard-WSL2`; `/mnt/d` is `9p`/`drvfs`.
Natural measurements use newly allocated temp directories directly under `/mnt/d`,
then remove only those owned fixtures. No project/session/evidence files are used.

| Natural isolated WSL scenario | Operation | Max measured loop span | Heartbeat gap | Esc |
|---|---:|---:|---:|---:|
| Session sequence / resume | 62.2 | 4.3 | 25.9 | 1.0 |
| FileWrite new / existing | 15.1 / 18.9 | 2.6 / 3.3 | 36.4 / 41.2 | 0.7 / 0.6 |
| Evidence capture + snapshot + retry | 115.0 | 53.3 | 136.7 | 94.2 |
| Finding save + independent integrity read | 30.3 | 3.3 | 22.7 | 4.4 |
| Summary export | 242.8 | 19.9 | 103.8 | 63.0 |
| SQLi finding chain | 217.0 | 23.6 | 84.6 | 0.7 |
| Combined chain | 295.2 | 53.5 | 112.8 | 67.7 |
| Real workflow-backed TUI chain | 260.7 | 22.9 | 91.6 | 31.9 |

The standalone finding's 3.3 ms loop read is the harness's independent integrity
assertion, not Store.save post-read. Individual spans under 120 ms can accumulate
without a scheduling yield: the evidence sequence has zero heartbeat ticks
during its synchronous operation. An isolated repeat measured 129.2 ms operation,
151.7 ms heartbeat and 109.2 ms Esc, confirming this natural batch stall.

An earlier WSL run overlapped regression tests and was substantially slower:
SQLi chain 1090.1 ms, heartbeat 573.2 ms, Esc 533.0 ms. Its 516.8 ms evidence
verification occurs **before** canonical save. Post-save verification takes
63.5 ms, then persisted mark succeeds. Summary subsequently spends about
166 ms on the loop before worker dispatch, 152 ms preparing in a worker, and
91 ms completing controller checks/replace/fsync. Thus a post-save pause can
come from later finalization. The isolated runs are reported separately; the
loaded run is not advertised as typical filesystem latency or a live incident.

## Minimal implementation and safety stop

Only production change: `src/findings/store.py` (14 insertions, 5 deletions).
Capture candidate ID/slug with rendered content before waiting for ownership.
The existing joined worker now performs write/reuse **and** canonical read/parse,
returning `(path, detached Finding)`. Field assignment remains on the loop after
joined success, under the same shared store lock. Existing cancellation/drain,
error precedence, collision handling, redaction and finalization guards remain.

C1 needs no new implementation for the measured I/O. C2/C3 remain blocked:
source/resource binding, permission lifetime and complete evidence publication
are not proved safe for worker handoff. No admission lease, pathname write
offload, evidence worker or permission changes were introduced. C5 fsync could
be a separate pinned-directory/drain patch after ownership proof; worker replace
still needs a proven publication reservation. Natural summary checks require
their own measured, guarded design. No further production fix is attempted here.

## Verification

All Python/pytest/Pyright commands used `venv-linux`; bytecode and pytest cache
writes were disabled. Focused production regressions used the fail-closed offline
checkpoint plugin with both TMPDIR and basetemp inside an owned `/tmp` container.

- Before: diagnostic matrix + original mounted oracle: **32 passed, 4 xfailed**.
- A new thread-ownership regression failed before the patch: canonical read/parse
  were on the controller, writer on another thread. It passes after the patch.
- Initial C4 focused regressions: **8 passed**; final group includes a ninth
  cancelled-queued-save test. Covers detached scalars, read/parse errors and retry,
  changed result/evidence, repeated cancel, shared lock, failed drain and unchanged
  error precedence. No cancelled caller snapshot publication.
- Final diagnostics + mounted oracle: **36 passed, 3 xfailed**. Only C4's XFAIL
  was removed after an independent `--runxfail -k finding_post_read` PASS.
  Heartbeat/Esc thresholds (120 ms), tick and integrity assertions are unchanged.
- Store/summary/C4/tool/evidence/policy/session-worker/checkpoint/UI outcome
  regression group: **259 passed**. CWE shared-lock persistence and finding
  presentation group: **35 passed**.
- Natural WSL detailed group: **9 passed, 19 deselected** (observations, not
  responsiveness assertions); isolated repeat: **3 passed, 25 deselected**.
- Pyright on changed Python files: **0 errors, 0 warnings, 0 informations**.
  Version notice ignored; no dependencies installed. `git diff --check` passed.

Two initial verification issues are retained honestly: a concurrent run had a
C1 yielding-control recovery tick count of 1, while its heartbeat stayed under
120 ms; the isolated full rerun passed the unchanged oracle. The first guarded
regression run had 8 failures and 8 teardown errors because the new tests reused
an audit fixture that hard-coded `/tmp` outside basetemp. The new test fixture now
uses tmp_path; containment was not weakened. Rerun: 259 passed.

Full repository suite, native Windows/other filesystem conformance, power-loss,
cross-process writers, large snapshot CPU/GIL stress, live Agent cancellation
unwind, optional Burp notifier and historical live correlation were not run.
Residual C2/C3 and C5 synchronous work can still pause the TUI. This patch fixes
one demonstrated boundary and does not certify the full persistence pipeline.

To reproduce the current diagnostic matrix and natural WSL observations:

```bash
PYTHONDONTWRITEBYTECODE=1 KAGENT_DIAGNOSTIC_OUTPUT=/tmp/kagent-trace.json \
  venv-linux/bin/python -m pytest -q -s -p no:cacheprovider \
  tests/ui/test_persistence_diagnostics.py tests/ui/test_persistence_responsiveness.py

PYTHONDONTWRITEBYTECODE=1 KAGENT_DIAGNOSTIC_DETAIL=1 \
  KAGENT_DIAGNOSTIC_TMP=/mnt/d KAGENT_DIAGNOSTIC_OUTPUT=/tmp/kagent-wsl-trace.json \
  venv-linux/bin/python -m pytest -q -s -p no:cacheprovider \
  tests/ui/test_persistence_diagnostics.py -k '0.0'
```
