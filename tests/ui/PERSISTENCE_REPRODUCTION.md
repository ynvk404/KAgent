# Controlled TUI persistence reproductions

Baseline: `772aea4`. These tests establish synthetic blocking susceptibility,
not the root cause of the historical live Burp freeze. Production persistence
is deliberately unchanged. The accompanying Planner change only removes the
initial-projection recommendation event.

## Reproduce

```bash
PYTHONDONTWRITEBYTECODE=1 venv-linux/bin/python -m pytest -q -s --tb=short -p no:cacheprovider --runxfail tests/ui/test_persistence_responsiveness.py
```

Expected baseline: **5 responsiveness failures, 6 passing controls**. Without
`--runxfail`, the five known defects are strict XFAILs. Only the dedicated
`ResponsivenessFailure` exception is expected; integrity, harness and offline
guard failures are not masked. A future nonblocking implementation produces
strict XPASS until its corresponding marker is removed.

The mounted Textual App executes an offline Agent callback which calls the
production persistence functions. Normal startup integrations are disabled;
rendering and actual Textual key handling remain active. Every test uses its
own temporary directory under `/tmp`, with connection/DNS guards which also
check for swallowed violations. No real provider, target or Burp is used.

A controller thread waits for the selected production boundary, submits an
Escape key after 50 ms, and releases the filesystem hold after 400 ms. This
thread provides a bounded release even when asyncio timers cannot run.
The Textual heartbeat interval is 20 ms. The desired oracle requires heartbeat
gap and Esc delivery below 120 ms, at least three heartbeat ticks during the
operation, and heartbeat recovery afterward. Integrity assertions run before
the responsiveness oracle.

Five representative injection points are tested: file `write_text`, first
session `fsync`, evidence source `read_bytes`, finding post-worker
`read_report`, and summary directory `fsync`. This does not individually
benchmark every path/stat/chmod/serialization/hash/flush syscall.

Each boundary has an async-wait control: the normal production operation
completes before an equally long yielding wait. This avoids submitting an
already-cancelled signal to file_write's permission gate. A separate control
holds the existing production canonical finding writer in its executor thread.
No test introduces production thread offloading.

## Baseline measurements

One corrected baseline run, elapsed milliseconds rounded to one decimal:

| Production boundary | Operation | Heartbeat gap | Esc delivery | Cancel requested* | Cancel completed* | Result |
|---|---:|---:|---:|---:|---:|---|
| File write | 401.2 | 423.3 | 378.1 | 428.9 | 429.4 | Reproduced |
| Session save/fsync | 401.9 | 424.2 | 360.0 | 411.5 | 412.2 | Reproduced |
| Evidence source read | 403.7 | 435.4 | 357.9 | 410.3 | 410.6 | Reproduced |
| Finding post-read | 409.2 | 409.8 | 354.7 | 412.5 | 413.2 | Reproduced |
| Summary directory fsync | 449.1 | 434.7 | 357.1 | 454.2 | 455.4 | Reproduced |

`*` Relative to operation start. Cancellation completion here is the offline
Agent callback acknowledging the production UI's AbortEvent after the operation;
it is not a measurement of every real Agent unwind/checkpoint path.

The five async controls had 21 heartbeat ticks each, gaps of 22.3–35.4 ms and
Esc delivery of 0.7–1.5 ms. The production finding worker control had 21 ticks,
31.7 ms maximum gap and 2.3 ms Esc delivery. Blocking cases had zero or one
heartbeat tick during the operation, then four or five recovery ticks. No
unexpected failure or timeout remained after correcting test fixtures.

## Root-cause matrix

All five sampled boundaries are confirmed synchronous work on the shared
Agent/Textual loop. They are plausible live contributors, with no live timing
or correlation evidence to select one. The canonical finding writer is already
offloaded and remained responsive. Lock contention, provider wait, CPU-bound
serialization and excessive rendering have not been established as live causes.
The tests run on `/tmp` and establish nothing about natural `/mnt/d` latency.

Checks preserve session JSON completeness/temp cleanup; immutable evidence
content, size and SHA-256; canonical finding readback and uniqueness; and
canonical report preservation plus summary visibility/temp cleanup. They do
not replace existing race, mutation, permission or cancellation-draining tests.

## Metadata-only instrumentation proposal (not implemented)

Use bounded spans with `turn_id`, `tool_call_id`, `span_id`, `parent_span_id`,
`phase`, UTC `start_at`/`end_at`, monotonic `elapsed_ms`, `status`, thread role
and aggregate byte/count fields. Do not include arguments, file content,
request/response bodies, captures, secrets, credentials or URLs.

Measure dispatch, permission queue/modal wait, tool.run, filesystem phases,
evidence read/redact/hash/verify, finding lock/worker queue/write/post-read,
summary prepare/verify/commit/fsync, session lock/serialize/JSON/write/fsync,
shared-loop heartbeat lag, event delivery/reducer/view work and actual render
completion separately. Parent spans must not double-count nested phases.

Store records in a bounded memory queue drained in batches by a writer thread;
drop records with a counter rather than blocking the loop. Rate-limit heartbeat
records and keep high-lag samples. Start/end must pair on errors/cancellation.
Existing HangDiagnostics stack dumps can help identify long blocking frames,
but do not identify ordinary asynchronous waits.

## Separate implementation checkpoints

1. Session I/O: preserve snapshot ownership, fsync cadence, atomic replace,
   write ordering and cancellation draining; add failure/overlap tests.
2. File/evidence I/O: preserve permission checks, safe paths, immutable snapshot
   identity and before/after verification; test mutation during worker windows.
3. Finding post-read/summary commit: preserve current-result revalidation,
   canonical report integrity, shared store lock and cancellation-safe ownership.

Change one boundary at a time. Do not remove checks, debounce saves or move
the entire Agent to a new loop. CPU optimization and UI redesign require
separate measured evidence. These checkpoints are a plan, not authorization
to implement persistence fixes in this session.
