# Scenario 1 protocol v1

This harness measures supplied-input validation for SQL injection and cross-site
scripting. It supplies one operational Candidate, then observes the production
Agent. It does not measure reconnaissance, enumeration, autonomous finding
discovery or whole-target completion. No official experiment or accuracy result
is claimed by this implementation, and its metrics are not an official OWASP
scanner score.

## Data and selection

`benchmarks.scenario1.dataset` reads BenchmarkJava's `expectedresults-1.2.csv`
and `data/benchmark-crawler-http.xml`. Truth must have an explicit version,
distinct IDs, boolean labels and correct CWE (89/79). Request mappings cross-check
servlet annotations, literal request readers, parameter maps, name enumeration,
query-string readers, cookies and the reviewed `SeparateClassRequest` helper.
Existing HTML forms must agree on action and method; body/cookie fixtures require
their form metadata. Unsupported or ambiguous plumbing fails with the exact case
ID. No selected case is silently replaced.
URL query pairs and crawler `getparam` metadata describing the same name/value
are reconciled into one occurrence, retaining URL order and then child order.
Conflicting values, duplicate names within either source, and query/form name
overlap fail explicitly: this protocol has no occurrence selector.

The inspected local dataset is version 1.2, commit
`8b67a88d73b2594570fc21150705283de884620b`: SQLi 272 vulnerable / 232 safe,
XSS 246 vulnerable / 209 safe. These counts are derived from the CSV; each
manifest records the current counts, dataset commit/dirty state and SHA-256 of
truth, crawler and all servlet/HTML/helper artifacts actually used. The mapping
protocol is `benchmarkjava-request-v1`. Execution verifies the pinned files again.
Java/HTML sources and sink annotations never reach the Agent. They are inspected
only in the parent for request plumbing and the target state requirement.

Selection protocol `sha256-rank-v1`, default seed **1729**:

1. Sort IDs in each of SQLi vulnerable, SQLi safe, XSS vulnerable and XSS safe.
2. Rank each stratum by SHA-256 of compact, sorted-key JSON encoding of
   `["sha256-rank-v1", seed, "select", class, vulnerable_boolean, case_id]`;
   break hash ties lexicographically by case ID.
3. Take 20 per stratum (`default`, 80), or 10 (`reduced`, 40). Fail if insufficient.
4. Store selected truth/operational rows sorted by case ID. Execution order ranks
   IDs by the same hash encoding of `["sha256-rank-v1", seed, "order", case_id]`.

Single selections contain exactly one ID. A run schedules an ID once; repeat
trials require separate run directories. Deterministic selection does not make
LLM behavior deterministic.

## Runtime and authorization

Runtime target and deployment context are explicit operator inputs. Dataset URL
origins are mapping metadata and never authorization. Fixtures use absolute URLs
rebound to the declared origin/context, because production native HTTP appends
relative paths to its complete target base URL. A request template is a legitimate
sample, not a captured replay baseline or injected evidence. Name-tainted inputs
are explicitly identified as input component `name`.

Each case starts a fresh Python worker, workspace, session, project stores,
HTTP context, observations, workflow, coverage and permission grants. Personal
memory/intelligence use production constructor `home` injection into
`workspace/.personal`; `KAGENT_PROJECT_ROOT` alone would not isolate them. User
HOME is unchanged. Provider configuration is read through production `load` and
`build_startup_runtime`; it is never saved, copied into the workspace or put in
the operational envelope. Use the existing secure config file or the supported
`kagent_CONFIG` path. This version uses saved provider credentials, including
Custom profiles; it does not add a separate benchmark credential store or an
environment-key fallback.

Capability profile `scenario1-native-http-confirmation-v1` exposes production
workflow, load_skill, read_payloads/read_skill_file, file_read/write/edit,
permissions_status, ask_user, coverage, confirm_finding and Agent's bounded
read_tool_result adapter. Only the two relevant production skills are loaded.
There is no shell, plugin, MCP, browser or research adapter. `ExecutionPolicy`
and the real registry gate remain active, including protected control-plane
paths. Native HTTP has one manually activated exact-origin autonomous grant with
finite request/time/body/rate/concurrency limits; YOLO is **off**. The headless
prompter permits only routine private-host review with the exact declared-origin
cache key and routine generated-artifact writes/edits under this workspace.
Other permission requests are denied. Missing `ask_user` input raises a real
refusal; no answer or approval is fabricated. Cross-origin requests and redirects
keep production behavior. These grants are session-specific, never durable policy.

Only bounded confirmation is requested; optional deeper impact is not requested.
XSS outcomes requiring unavailable browser proof remain `browser-required`.
Production playbook semantics and assessment authority are unchanged.

Process/storage isolation does **not** reset the target application. The selected
set may contain SQL servlets that perform INSERT or other writes even with a
legitimate baseline. Such selections require `--target-state external-reset`.
The operator owns application/database snapshots and resets outside this harness.
The harness does not execute reset commands, validate snapshot freshness, or
guarantee equivalent target state between cases. Sequential selected-manifest
runs can accumulate application state unless an external lab orchestrator keeps
it controlled. Record the strategy/build information in `--deployment-metadata`;
for an initial smoke pilot choose a read-only single case. `confirmation-only`
means no intended persistent exploitation; it is rejected for statically detected
mutating servlets. Static mutation detection is conservative, not a complete
application-side-effect analysis.

## Execution, freeze and authority

The worker creates the Candidate through `Registry.execute("workflow", ...
action="record_candidate")`, then calls real `Agent.run` with a neutral Candidate
ID validation request. Production initializes `candidate_validation`; the harness
does not initialize it privately. Native tools collect evidence and production
`record_evidence`/`record_result` assign ownership, IDs, source manifests and seals.
No certificate/verifier, injected result, operator revision or direct private
validator is used. Finding persistence is optional for benchmark evaluability.
Evidence admissibility checks integrity/ownership, not vulnerability correctness;
the accepted Agent assessment is the label being compared to external truth.

Monotonic `agent_seconds` begins immediately before `Agent.run` and ends after
the run and its outstanding background tasks settle. Timeout cancels and awaits
the run; outstanding background tasks are cancelled/drained on timeout/error.
A normal terminal assessment never causes early cancellation. Setup includes
initialization and registry Candidate admission; teardown measures frozen export
and metadata construction. `first_terminal_seconds` is the first terminal record
observed at a production event boundary, not its wall-clock `recorded_at`.
Parent `wall_seconds` includes process startup and process termination. Timers
never compare absolute monotonic values between processes.

The parent watchdog allows 60 seconds of finite setup/drain grace beyond the
Agent timeout, then terminates the worker process group (TERM, five-second grace,
KILL, wait). A killed worker may have no Agent/setup/teardown metrics; these remain
unknown. Parent completion is recorded only after process termination/drain.

Actual DoneEvent mapping:

| Production stop / source | Execution status |
| --- | --- |
| final_response, workflow_completed, workflow_blocked, workflow_stalled, all_tools_refused, plan_only_blocked; no ErrorEvent | completed |
| client_error | provider-error |
| max_steps, context_capacity, native explicit tool/HTTP budget denial | budget-exhausted |
| runtime_error, cancelled, invalid_response, missing/unknown done, other ErrorEvent/raised error | runtime-error |
| awaited Agent deadline or parent watchdog | timeout |
| worker setup failure | setup-error |
| unexpected nonzero worker exit | crashed |

Execution failures take precedence even if an accepted terminal assessment was
already recorded. The diagnostic export is retained but never scored. Setup
diagnostics retain exception type and bounded filename/line/function metadata,
not provider exception messages or unrestricted process logs.

One final `CaseExecution` artifact embeds the frozen canonical export: run/case/
execution/session/objective/Candidate IDs, target origin/base/revision, execution
epoch, Candidate binding, latest global result position/result ID, acceptance
projection and bounded production workflow state. Results contain the production
attempt, source/version/seal and redacted evidence manifest. Read-only hydration
does not use resume migration or create a live session/epoch/policy. Offline checks
reuse `accepted_result(..., policy=None)` plus frozen session/objective/target/
epoch/latest/provenance checks. `accepted_at_freeze=true` alone cannot pass.
Normal historical result revisions are allowed; duplicate final execution exports
or conflicting final lifecycle records are rejected. Local hashes detect artifact
corruption; they are not a cryptographic attestation against an attacker able to
rewrite the entire run and its integrity metadata.

## Recorder and offline evaluation

Schemas are v1, scenario `scenario1`, protocol `supplied-input-v1`. The parent
schedules **every** selected ID before any worker. `events.jsonl` is append-only:
scheduled -> started -> runtime-finished -> evaluated, with unique record IDs,
strict contiguous sequence, UTC timestamps, bounded references/status metadata,
manifest/operational/result hashes. Truth labels stay in the manifest/selection
and evaluation artifacts, not worker input or runtime lifecycle/result records.
One parent owns sequential writing; advisory locks and stale-history checks
reject concurrent writers. Every append flushes and fsyncs.

Recovery ignores only the final fragment lacking a newline, even if that fragment
looks like valid JSON. Complete-line or middle corruption, duplicate JSON keys,
nonfinite numbers, invalid transitions, unexpected IDs and unsupported versions
fail closed. Recovery never truncates/overwrites history. A partial tail permits
read-only lifecycle evaluation and a separate evaluation artifact, not appending
events or execution resume. Missing finish after start means interrupted execution;
a worker may already have written `results/<case_id>.json` before that interruption.
Only that started case's exact export path is admitted as an orphan diagnostic.
Complete exports must match the recorded run/case/execution identity; torn JSON
exports are retained as incomplete diagnostics. Invalid complete schemas,
duplicate JSON keys, nonfinite numbers, symlinks, oversized exports and unrelated
files still fail closed. Orphan references/hashes are frozen in the evaluation
identity and report; their contents contribute neither labels nor timing. They
never establish completion, and recovery never edits the export or history.
A scheduled case with no start is not-run. Fail-fast preserves scheduled cases
and records not-run/fail-fast. Evaluations have a deterministic identity/version;
rerunning evaluation does not append duplicate evaluated events or double-count.

Only completed execution with valid external truth and the latest accepted
Agent-provenance `confirmed` or `not-confirmed` result is evaluable:
vulnerable/confirmed=TP, vulnerable/not-confirmed=FN, safe/confirmed=FP,
safe/not-confirmed=TN. Missing canonical results and native unresolved outcomes
are unresolved. Corrupt/unaccepted/stale result exports are invalid-result.
Execution failures are execution-failed; untouched cases are not-run. The partition
accounts for all scheduled cases. Completed is a separate execution count, not
a synonym for evaluable. Neither unresolved nor execution failure is a negative.

Reports contain SQLi, XSS, overall and four-stratum counts, reasons and timing
distributions grouped by execution status. Recall=TP/(TP+FN), FPR=FP/(FP+TN),
precision=TP/(TP+FP), evaluability=evaluable/scheduled. Empty denominators are null.
Correctness metrics are conditional on the evaluable subset; low evaluability
can introduce selection bias. Balanced-sample precision is not deployment
precision. Timing reports n/mean/median/nearest-rank-ceiling p95 and do not mix
timeouts with completed runs.
Timing groups use the parent's final lifecycle status, including when it records
a crash/timeout after a worker exported `completed`. A retained Agent duration
still describes the worker's measured interval, not reconstructed crash time.

LLM metrics come from DoneEvent counts and the production request_metrics
collector: loop/compaction/final-synthesis/total calls, purpose, provider/model,
reasoning policy/settings, duration, usage and retries. Missing usage/retries stay
null. Token fields distinguish observed sums, retained request coverage and
complete totals; totals require complete records and usage for every request.
Tool proposals count ToolCallEvent; executed invocations count successful
production `policy.start` entries, excluding harness Candidate admission. They
are not HTTP sends or successful tools. Blocked/failed counts use ToolResultEvent
status/error_kind. `http_admitted` counts production HTTP reservations charged
to the exact grant (including redirects), not inferred tool proposals. No metric
is called an LLM "step".

## Commands

Use `venv-linux/bin/python` from the repository; output files/run directories must
be new. All commands below are templates; running the implementation did not
execute a pilot.

```bash
venv-linux/bin/python -m benchmarks.scenario1 list --dataset /path/to/BenchmarkJava
venv-linux/bin/python -m benchmarks.scenario1 select --dataset /path/to/BenchmarkJava --mode reduced --output /tmp/scenario1-selection.json
venv-linux/bin/python -m benchmarks.scenario1 run --dataset /path/to/BenchmarkJava --manifest /tmp/scenario1-selection.json --target http://127.0.0.1:8080 --context-path /benchmark --authorized-lab --target-state external-reset --dry-run
venv-linux/bin/python -m benchmarks.scenario1 run --dataset /path/to/BenchmarkJava --case BenchmarkTest00013 --target http://127.0.0.1:8080 --context-path /benchmark --authorized-lab --target-state confirmation-only --output artifacts/benchmarks/smoke-UNIQUE
venv-linux/bin/python -m benchmarks.scenario1 run --dataset /path/to/BenchmarkJava --manifest /tmp/scenario1-selection.json --target http://127.0.0.1:8080 --context-path /benchmark --authorized-lab --target-state external-reset --fail-fast --output artifacts/benchmarks/run-UNIQUE
venv-linux/bin/python -m benchmarks.scenario1 evaluate --run artifacts/benchmarks/run-UNIQUE
```

Dry-run only parses/maps/selects/verifies source hashes and local runtime settings;
it creates no Agent/client/worker, performs no provider probe/target health check,
and saves no user configuration. Runtime execution requires `--authorized-lab`
and finite `--timeout`, `--http-requests`, `--tool-calls`, `--agent-calls` (defaults
180 seconds / 24 / 80 / 24). Exit codes: 0 command completed, 2 input/integrity
error, 3 incomplete offline run, 4 recorded execution failures. Unresolved labels
do not make a completed execution fail. Artifacts include `manifest.json`,
`events.jsonl`, `results/<case>.json`, `workspaces/<execution-id>/`, and immutable
`evaluation-<identity>.json` containing per-case records and all metrics.

Version 1 is sequential, Linux/POSIX (process groups/advisory locks), with no
automatic retry, execution resume, cleanup, target reset or parallel runner.
Dataset mapper v1 supports the inspected BenchmarkJava request-plumbing shapes;
other layouts must fail explicitly and receive a reviewed mapping extension.
