# Worker inspection responsiveness — 02/10/2026

Baseline: `6100830915d5cf23ac7b9ebe55211e969bcbb48f`, clean worktree at task start.

## Diagnosis and historical probe

`OfflineWorker.available()` uses a small startup scratch tree, but shell/plugin/
MCP/ffuf previously called synchronous `wrap()` on the UI event loop. That walks
the actual project, including `venv-linux` on the Windows-mounted filesystem.
Safe session metadata showed file write/read, then shell, another read and final
answer. No raw prompts, credentials or process arguments were printed.

The initial regression run before production edits failed: a 0.6-second slow
walk fixture delayed an event-loop tick 1.198 seconds (the initial timing also
included broker construction). After moving the scan to a thread, that broad
measurement still included 0.593 seconds of synchronous broker setup. The final
regression schedules the tick when project inspection actually begins, isolating
the path being repaired. It checks real worker execution and timer responsiveness
together rather than asserting the delay is acceptable. This is a reproduction
of a code path, not a live stack proving every reported stall has this cause.

## Change

- `src/permission/worker.py`: async `prepare()` runs inspection off the UI loop,
  polls cancellation/current receipt identity/revisions, and bounds preparation
  to 120 seconds independently of the child-process timeout. `wrap()` cooperatively
  checks stop/deadline between filesystem operations. Root/output paths are
  rechecked after preparation, including intermediate symlink escapes.
- `src/tools/shell.py`, `plugin.py`, `mcp_integration.py`, `content_discovery.py`:
  all actual worker launches await this preparation. MCP forwards the caller's
  cancellation signal into its owner task; ffuf recomputes remaining scan time.
- `tests/security/test_worker_responsiveness.py`: real Linux worker success for
  shell/plugin/fresh stdio MCP during a slow scan, zero permission dialogs; abort,
  task cancellation, revoke, scope changes, timeout, worker/quota changes and
  output-root replacement prevent dispatch, including after the scan is released.
- `tests/security/test_cli_repair_entrypoint.py`: two new cases use actual CLI
  wiring, Textual Pilot, fake model responses and default protected profile for
  file write/read followed by shell. Timer/input remain responsive; normal
  completion restores input and writes the expected marker; Esc restores input
  without launching the worker command. No provider or target request is made.

At the initial responsiveness-only stage, existing permissions, scope, network broker, filesystem checks, process limits,
evidence/verifier behavior and refusal policy are retained. No inspection cache
or ambient host execution fallback was added.

## Real project probe

`probe_project_inspection.py` only prepares a command; it deliberately does not
execute it. Existing startup OS capability check runs `/bin/true` in the tiny
scratch worker. `project-inspection.json` records:

- Full project inspection: 106.218 seconds, successful.
- Heartbeat ticks: 2,109; maximum gap: 0.073 seconds.
- Tool dispatches/model API calls/target requests: zero.

This shows a responsive event loop while the real project scan is slow. It does
not measure full GUI rendering or claim the full scan is faster. Keeping the
Python environment outside the lab tree, or using a dedicated operator-approved
lab root, remains a separate performance improvement. Nothing was moved here.

## Verification

Initial responsiveness-only verification: 30 focused cases passed; broad
regression 2,721 passed, 1 skipped, 2 malformed-config fixture warnings. Pyright
reported zero errors/warnings; the installed version-update notice was ignored.
The skip was the opt-in live-model characterization, deliberately not enabled.
Runs are sequential with the existing WSL virtualenv;
fixtures/mocks/loopback and fake secrets only. Original historical reports/XML
are retained; new outputs are confined to this directory.

## Limits

An OS syscall can remain blocked after cancellation; Python cannot interrupt it.
The inspection thread can only inspect/build arguments and cannot launch a
process; a cancelled invocation never consumes its late result. The 120-second
budget bounds waiting and can refuse an exceptionally slow permitted tree.
It does not improve filesystem race isolation, aggregate cgroups, raw/CONNECT/
remote MCP support, complete egress controls, class verification or model
instruction immunity. No live provider/network pentest was performed. Test pass
is not comprehensive prompt-injection protection. No install/commit/push/reset.

## Follow-up: dependency pruning and HTTP cancellation lifecycle

The operator then requested pruning and reproduction/repair of cancel -> YOLO
-> same-request failures. Root causes were reported before behavior changes:

1. Actual dispatch had no standard dependency/cache prune list (only protected
   roots were pruned). `dirs[:]` now excludes the 10 requested names at every
   depth. Their content is also masked with empty read-only worker mounts,
   preventing a skipped tree from exposing unchecked IPC, device files or
   hardlinks. Directory symlinks in this list are refused. Source/project files
   elsewhere retain the same inspection; native file-tool policy is unchanged.
   This means worker commands cannot consume dependencies, compiled artifacts
   or payloads placed under `dist`, `build`, virtualenvs or other excluded trees.
   Keep permitted worker inputs outside these trees; no package was installed or
   environment moved. Filesystem races are still not comprehensively solved.
2. `HTTPPermissions.authorize()` caught all exceptions including cancellation
   and put request digests in `_declined_actions`. Registry treated cancellations
   and all policy refusals as `_denied` by args digest. Those runtime-only caches
   outlived a turn; YOLO did not reset them. The pre-follow-up passing historical
   characterization `test_cancel_during_review_reopens_only_by_operator` asserted
   this faulty state. It now asserts successful fresh invocation behavior.
   Private-host cancellation also paused the origin, and unused HTTP receipts
   could survive cancellation before reservation.

`src/permission/invocations.py` now creates controller-owned review scopes.
`Agent.run()` starts a fresh turn; Registry/direct HTTP calls inherit the live
turn or create a standalone invocation scope. Exact explicit DENY suppresses
equivalent dialogs within that turn; cleanups remove only that turn's keys.
Cancellation/errors do not record DENY. Scope/target revisions, explicit origin
or private-host decisions, session deny, tool/grant revoke, budgets and quota
journals are independent and not globally cleared. Summary/memory/model args
cannot choose the review identity. Ended-turn child contexts cannot reuse it.

HTTP actions now have unique invocation IDs in addition to effective-request
digests. Receipts bind both, cannot be used by another same-shape invocation,
and are specifically discarded on exit. Reservation-wait cleanup retires only
its own receipt. Signal cancellation interrupts HTTP review/private gate/send/
body consumption, then awaits cleanup; responses close and slots release.
Requests already started still count against quota and may have server effects.
Existing interrupted-message reconciliation repairs missing tool responses at
the next Agent turn; it does not restore execution rights.

The final regression tests both the anti-spam boundary and future independence:
whole-target runs cancel at review/private/send/body stages via task cancellation
or the UI's AbortEvent, then retry with YOLO OFF/ON; exact DENY suppresses retries
in the same turn, allows independent turns to obtain fresh rights, and does not
clear another revoked tool or HTTP origin. Review errors, transport errors,
timeouts, reservation-wait cancellation and same-shape receipt replay are covered.
Ten prune tests plus real Linux isolation confirm no descent into excluded trees
and continued source/payload access/FIFO rejection outside them.

Same real project after prune: `project-inspection-pruned.json` records 1.340s,
27 heartbeat ticks, max gap 0.051s. Before prune was 106.218s; both retained.
This is one read-only local measurement, not a universal timing guarantee.
Focused follow-up: 212 passed (`prune-and-lifecycle-focused.xml`). Final broad/
static verification is recorded after completion below. No new provider API
calls, live pentest, dependency install, commit or push.

## Final verification

- Broad regression: **2,756 passed, 1 skipped**, 2 expected malformed-config
  fixture warnings (`prune-and-lifecycle-regression-final.xml`, 123.70s pytest
  console duration). The skip is the deliberately disabled opt-in live-model
  characterization, not an offline worker acceptance skip.
- The first follow-up broad run had 2,754 passed/1 failed/1 skipped: the failure
  was the historical file-cancellation characterization requiring persistent
  invocation-declined. That assertion was replaced with successful independent
  review and proof an unrelated revoke survives. Its XML is retained separately.
- Final HTTP/policy/resume regression after the type-only cleanup callback fix:
  **162 passed** (`http-lifecycle-final.xml`). The fix replaces a callback whose
  ignored return was an optional origin with an explicit `None` return; it does
  not change cache removal behavior. No broad counts are added to rerun counts.
- Source changes are confined to worker/tool preparation, invocation review
  identity and HTTP lifecycle. CLI wiring is covered using a scripted model and
  Textual Pilot; startup, evidence, broker and vulnerability fixture regressions
  also pass. No new verifier, sandbox architecture or egress engine is claimed.

Pyright: **0 errors, 0 warnings**; version-update notice ignored, no installation.
`git diff --check`: passed. Final metadata is recorded in `verification.json`.
New audit outputs are ignored runtime artifacts on disk; tracked
REPORT/IMPLEMENTATION summaries and product/tests remain uncommitted. The
checkpoint HEAD stays `6100830915d5cf23ac7b9ebe55211e969bcbb48f`.
