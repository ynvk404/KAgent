# Local system validation

No packages, external targets or provider credentials are needed. Run from the
repository with its existing environment:

```bash
venv-linux/bin/python -m pytest tests/system -o junit_family=legacy
venv-linux/bin/python -m pytest -p tests.system.offline_suite @tests/system/offline_matrix.txt -o junit_family=legacy
venv-linux/bin/python -m pytest -p tests.system.offline_suite -o junit_family=legacy
venv-linux/bin/pyright
```

Leave `KAGENT_SYSTEM_LIVE`, `KAGENT_RUN_LIVE_TOOL_CHARACTERIZATION` and
`KAGENT_S1_EXISTING_CONTAINER` unset for offline runs. `offline_suite` rejects
real Python socket connections/DNS outside loopback, including swallowed
errors. Existing scanner responsibility tests use their own disposable local
servers and bounded process fixtures. The new system tests impose a stricter
boundary: exactly their lab's numeric address/ephemeral port, no subprocess by
default, private scratch stores only. The scanner variant admits only the
trusted prlimit/ffuf command targeting that origin and its approved wordlist;
it verifies the child's PID has exited. `/dev/null` is the only special-file
exception for subprocess standard input. No sandbox or production permission
gate is bypassed.

`LocalLab` uses `asyncio.start_server` on `127.0.0.1:0`, probes `/ready`, and
owns/joins connection tasks. It offers public/hidden routes, form/OpenAPI input,
literal reflection, deterministic SQLi-like predicates (no SQL/eval), fake auth,
an access-control mismatch with synthetic objects, redirect, evidence marker,
503/retry and held-header/held-body responses. The application ledger is
independent of model output and is compared with the actual native evidence.

The harness extends `ScenarioRunner`, `make_runtime`, `ScriptedModel`,
`TraceRecorder` and `InvariantOracle`. Model doubles emit actual tool calls and
consume production feedback/IDs; they never insert workflow state, synthetic
terminal observations or findings. The expected request schedule is specific to
this small lab, not a claim of general model planning. Production tools still
perform permission/admission, transport, immutable capture, coverage, reports
and session saves. TUI cases mount the real `KAgent` app and permission bridge;
the test operator uses real key handlers.

| Successful path | Independent functional, state and cleanup checks |
| --- | --- |
| Whole target/native HTTP | All discovery phases, input/candidate linkage, repeated comparison, accepted result, finding, coverage, real TUI idle/timers, fresh resume |
| Whole target/scanner | Real ffuf child, two approved routes, result reader, triage, manifest/hash verification, complete workflow, scratch/PID cleanup |
| Direct endpoint/input | Six actual validation responses, source/attempt identity, immutable derived proof, exactly one finding/coverage row |
| Initially missing permission | No initial grant, exact-request/modal approvals, continuation to persisted completion; no reusable grant invented |
| Resume midway | Cancel pending model after actual start-validation checkpoint, fresh runtime restores interrupted attempt with no grants/sources, new attempt completes |
| Redirect and fake auth | Same-origin redirect and anonymous/authenticated responses precede full workflow; no external hop |
| Transient retry | Real 503 then bounded successful retry, followed by full assessment and persistence |
| Capture / alternate proof | Public capture ingestion and captured replay; alternate source file plus candidate/evidence deduplication, same terminal invariants |
| Long history/streaming | 1,000 history messages and hundreds of real deltas through Agent/TUI, completed validation and clean UI ownership |

| Matrix | New system tests and reused responsibility tests |
| --- | --- |
| A direct/retry/no origin | `test_local_boundaries`, `test_local_workflow`, `test_happy_variants` |
| B insufficient/inconclusive/dedup/completion/stall | `tests/scenarios/test_safety.py`, `test_recovery.py`; `tests/agent`, whole-target integration tests |
| C permission/scope | `test_local_boundaries`; HTTP invocation lifecycle, native callback ownership, scope event lifecycle |
| D reset/resume/objective/generation | `test_ui_lifecycle`, resume happy path; turn ownership, native callback ownership, workflow progress ownership |
| E scanner | Scanner happy path; scanner lifecycle, I/O responsiveness, artifact limits, workflow recovery (real loopback and explicit synthetic process fixtures) |
| F MCP | `test_mcp_ui`; owned-session queue/timeout/caller/owner cancellation, overlapping close and teardown regressions |
| G evidence/persistence | Workflow snapshots and fresh resume; evidence atomic publication/source binding, UI persistence responsiveness, async I/O and session persistence tests |
| H stream/TUI | Real streaming Agent tests, per-delta semantic/read counters; existing transcript/context responsiveness tests |
| I input/UI | Real runtime input/picker/resize test; full `tests/ui` for selection, scroll/follow-tail and modal contracts |
| J provider simulation | Real Agent/TUI with offline timeout, rate limit, exception, malformed calls/schema, text-only response and entry failure |

Every new held/failure case retains pre-state, injection, expected invariant and
post-state in JUnit properties where applicable. Scenario traces, production
artifacts and metrics live under pytest's per-test scratch directory. Use
`--basetemp=/tmp/<new-unique-directory>` to retain a particular run. The repeat
test creates 20 independent runtime/store roots and checks no additional pending
tasks, connections, temporary checkpoint files or cross-session results remain.

The end-to-end watchdog is 60 seconds per scenario and detects hangs independently
of heartbeat. The two main whole-target/direct TUI tests record heartbeat gaps
and log warnings over 120 ms; this is a diagnostic marker, not an acceptance
budget. Their verdict requires workflow/ownership/persistence correctness, real
input recovery, idle busy/timer/modal state, settled operations and owned cleanup.
System cancellation cases separately verify Esc/cancel and resource drain.
Dedicated responsiveness tests keep their existing thresholds and recovery
oracles. A system functional/lifecycle pass does not imply those tests passed.
No performance-only production optimization is part of this change.

System runs defer only the trace recorder's extra JSON/redaction round trip
until the measured app turn has ended. Event copies and every invariant
checkpoint still run at the original transition. The runtime's sanitizers and
stores are unchanged; pending trace events are sanitized before outcome checks
or export, and sanitizer failure prevents raw export. Legacy scenarios retain
inline trace sanitization by default. `test_trace_measurement` checks checkpoint
ordering, immutable event copies, identical sanitized exports, fail-closed
export and a deliberately blocking positive control that still records a gap
over 120 ms (the diagnostic signal remains visible).

Optional probes (they add overhead; do not use their timings as an uninstrumented
baseline):

```bash
venv-linux/bin/python -m pytest -p tests.system.probe --system-probe=full --system-probe-sampling tests/system/test_local_workflow.py::test_local_pipeline_with_tui_and_fresh_resume -s -o junit_family=legacy
venv-linux/bin/python -m pytest -p tests.system.probe --system-probe=full --system-probe-inline-trace tests/system/test_local_workflow.py::test_local_pipeline_with_tui_and_fresh_resume -s -o junit_family=legacy
venv-linux/bin/python -m pytest -p tests.system.probe --system-probe-repeats=20 tests/ui/test_persistence_responsiveness.py::test_production_boundary_keeps_textual_responsive -k file_write -s
```

The last command repeats the existing test with no probe observers. Add
`--system-probe=full` for callback wall/CPU spans, GC intervals, executor queue
delay, key handlers and file I/O. Add `--system-probe-sampling` for loop-stack
samples. Async `_wall` spans include awaits and are not blocking durations.
`probe.json` and JUnit properties retain diagnostics. Modes
`no-trace-redaction`, `no-oracle`, `no-trace` remove test instrumentation for
comparison only; the last two disable independent outcome checks, so they are
never counted as correctness verification. No probe replaces a production
permission gate, target, sanitizer, model transport or store.

Heartbeat metrics retain the measured window, gaps over 120 ms and a diagnostic
warning, without subtracting instrumentation or GC time. The system verdict is
recorded separately after owned drain succeeds. Persistence metrics and timestamp/
tick timelines print before their recovery assertion, including on failure.
Dedicated thresholds, recovery windows and required tick counts are unchanged.

Optional live characterization is separate and skipped by default:

```bash
KAGENT_SYSTEM_LIVE=1 venv-linux/bin/python -m pytest tests/live/test_system_local.py -o junit_family=legacy
```

It reads the already saved provider/profile through the shared startup factory,
never persists provider changes, exposes only native exact-origin HTTP and local
artifact/workflow tools, and grants no external target scope. Provider API access
is opt-in. State/hash/wire oracles remain independent of the model. Explicit
policy refusal and incomplete model plans are recorded separately from runtime
errors; neither is reported as successful assessment. This mode has not been
executed during offline validation.
