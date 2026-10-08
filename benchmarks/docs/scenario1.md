# Scenario 1 protocol v1

This harness measures supplied-input validation for SQL injection and cross-site
scripting. It supplies one operational Candidate, then observes the production
Agent. It does not measure reconnaissance, enumeration, autonomous finding
discovery or whole-target completion. No official experiment or accuracy result
is claimed by this implementation, and its metrics are not an official OWASP
scanner score.

Implementation modules live in `benchmarks/scenario1/core/`: dataset mapping,
bindings, canonical exports, run classification, runner, runtime, worker and
evaluation. Reporting and logical reset remain sibling packages. The CLI
entrypoint stays in `benchmarks/scenario1/__main__.py`, so all commands below
continue to use `python -m benchmarks.scenario1`.

## Data and selection

`benchmarks.scenario1.core.dataset` reads BenchmarkJava's `expectedresults-1.2.csv`
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
protocol is `benchmarkjava-request-v1`. Before execution, manifest verification
reconstructs the declared selection from the current dataset and seed, then
compares its complete dataset identity, hashes, selected rows, safety metadata
and schedule with the manifest.
Java/HTML sources and sink annotations never reach the Agent. They are inspected
only in the parent for request plumbing and the target state requirement.

Selection protocol `sha256-rank-v1`, default seed **1729**:

1. Sort IDs in each of SQLi vulnerable, SQLi safe, XSS vulnerable and XSS safe.
2. Rank each stratum by SHA-256 of compact, sorted-key JSON encoding of
   `["sha256-rank-v1", seed, "select", class, vulnerable_boolean, case_id]`;
   break hash ties lexicographically by case ID.
3. Take 20 per stratum (`default`, 80), 10 (`reduced`, 40), or 3 (`smoke`, 12).
   Smoke is a balanced development subset, not the final benchmark. Fail if a
   stratum is too small.
4. Store selected truth/operational rows sorted by case ID. Execution order ranks
   IDs by the same hash encoding of `["sha256-rank-v1", seed, "order", case_id]`.

Single selections contain exactly one ID. Smoke uses the same rank formula and
one manifest, run ID, runner, worker isolation, evaluator and report as the
other modes. A run schedules an ID once; repeat trials require separate run
directories. Deterministic selection does not make LLM behavior deterministic.

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

For each captured native HTTP request, the benchmark adds a compact semantic
binding to the sealed evidence source: Candidate ownership, method, route, and
which location/component carried the designated input. It records no mutated
input value. Offline scoring requires the same method and route as the selected
case, its designated input location and name/value component, and matching
Candidate ownership. Baseline requests can remain supporting evidence; at least
one selected source must show mutation of the designated component. A same-origin
request to another route, a different parameter/location/component, or evidence
owned by another Candidate is an invalid result and receives no TP/TN/FP/FN.
Payload mutation is allowed, so evidence need not reproduce the fixture bytes.
The harness also checks prepared requests before sending: value-tainted cases
may change only the designated value. All unrelated query/body/header/cookie
fields must match the fixture. Name-tainted cases retain single-name replacement
and exact baseline provenance requirements. Generated Content-Length follows
the body. This check uses operational fixtures without truth or sink hints.
Scenario 1 does not follow redirects: `max_redirects > 0` is rejected before
traffic. Omit it or use `0`; a valid fixture's 3xx response is captured normally
without following `Location`. Production HTTP redirect support is unchanged.

Only bounded confirmation is requested; optional deeper impact is not requested.
XSS outcomes requiring unavailable browser proof remain `browser-required`.
Production playbook semantics and assessment authority are unchanged.

Production execution requires an owned exact-dataset target and `--reset-state`.
The parent closes admission, logically restores both HSQLDB catalogs and verifies
complete relevant state before authorizing each worker and after collecting its
result. Reset receipts and durations are separate from worker/Agent metrics.
Failures or unknown outcomes stop the run with `blocked.json`, exit code 5, and
untouched cases recorded as `not-run`. HTTP 200 alone never admits a case.
`external-reset` alone remains insufficient. See
[reset implementation and handoff](../scenario1/reset/README.md).

All 504 SQLi and 455 XSS cases use logical reset with verified source/target
identity. The historical audit classification does not exclude cases, including
the 272 SQL-controlled SQLi cases. This follows the operator's explicit choice
to accept unverified restoration of effects outside the databases. Run policy
and reset receipts record that limitation and scope verdict PARTIAL; no container
recreation occurs between cases. Truth, selection and scoring remain unchanged.
Reset failures and unknown outcomes still block subsequent workers. Eligibility
does not certify execution of all cases or restoration of arbitrary external effects.

Automatic default/reduced/smoke exclusion is blocked on trustworthy dataset-wide
state metadata. The existing regex is a positive write indicator, not a verified
negative classification: batch/large-update calls and helper-mediated writes can
escape it. Selection and quotas/ranking remain unchanged; known writes fail
closed at runtime rather than being replaced to fill quotas. The smallest
follow-up is a reviewed parent-only versioned state-effects catalog bound to
dataset source hashes, including unknown entries. Selection could then exclude
writes/unknowns before ranking, fail with the deficient stratum if a quota cannot
be met, and record exclusions. A catalog/isolation adapter is outside this change;
absence of a regex match does not prove a stateless endpoint.

Reproducibility snapshots retain commit/dirty state and skill hashes and now
also pin SHA-256 of Python runtime/harness sources and static dependency/type
configuration, plus installed distribution names/versions. RuntimeSettings in
the manifest pins invocation budgets and target settings. No credentials or
configuration contents are copied. Dirty development smoke remains supported;
there is no official-mode clean-tree requirement. These hashes identify the
startup file snapshot, not an immutable checkout or attestation of target state,
provider configuration, imported modules, or source changes during execution.

Evidence-admissibility errors identify rejected opaque source IDs and fixed
reasons. The Agent permits one retry and at most three repair turns (to
rewrite/register proof and resubmit). Repeated rejection or a probe-only repair
loop closes the attempt as insufficient-evidence through the normal workflow
gate. A distinct missing declared validation step retains its normal workflow
error and may continue. Budgets, evidence checks and scoring rules are unchanged.

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
to the exact grant (including redirects), not inferred tool proposals.
`http_dispatch_attempts` counts native HTTP transport dispatch attempts: each
handoff to the production transport counts once, including each actual retry or
followed redirect hop. A failure after handoff still counts. A reservation that
stops before handoff does not. Scenario 1 disallows following redirects, so its
cases have no followed hops. Neither counter proves delivery to the server,
successful response, packet count, or confirmed target interaction. Older case
artifacts without `http_dispatch_attempts` decode as null/NA, never zero. No
metric is called an LLM "step".

## Run designation

`run --run-kind {development,official}` declares the run classification;
`development` is the default and `official` requires the explicit option.
Smoke selections cannot be declared official. After writing and reading the
final `manifest.json`, the runner writes a separate, collision-safe
`run-classification.json` before launching any worker. Its versioned record
contains the run ID, declared classification, SHA-256 of the final manifest's
raw on-disk bytes, and the semantic manifest identity used by lifecycle events.
The record is never updated after a run begins and contains no ground truth
rows. This is operator-declared metadata, not a cryptographic signature or
proof of protocol compliance, a clean environment, or scientific validity.
For old runs without a record, the reader interprets smoke mode as
`development/smoke`; other modes have unknown classification, meaning official
status was not declared. Existing artifacts are not migrated.

## Commands

Use `venv-linux/bin/python` from the repository; output files/run directories must
be new. All commands below are templates; running the implementation did not
execute a pilot.

```bash
venv-linux/bin/python -m benchmarks.scenario1 list --dataset /path/to/BenchmarkJava
venv-linux/bin/python -m benchmarks.scenario1 select --dataset /path/to/BenchmarkJava --mode reduced --output artifacts/benchmarks/scenario1-selection.json
venv-linux/bin/python -m benchmarks.scenario1 select --dataset /path/to/BenchmarkJava --mode smoke --seed 1729 --output artifacts/benchmarks/scenario1-smoke.json
venv-linux/bin/python -m benchmarks.scenario1 run --dataset /path/to/BenchmarkJava --manifest artifacts/benchmarks/scenario1-smoke.json --target http://127.0.0.1:18080 --context-path /benchmark --authorized-lab --target-state external-reset --reset-state artifacts/benchmarks/target-private.json --output artifacts/benchmarks/smoke-UNIQUE
venv-linux/bin/python -m benchmarks.scenario1 evaluate --run artifacts/benchmarks/smoke-UNIQUE
venv-linux/bin/python -m benchmarks.scenario1 run --dataset /path/to/BenchmarkJava --manifest artifacts/benchmarks/scenario1-selection.json --target http://127.0.0.1:18080 --context-path /benchmark --authorized-lab --target-state external-reset --reset-state artifacts/benchmarks/target-private.json --dry-run
venv-linux/bin/python -m benchmarks.scenario1 run --dataset /path/to/BenchmarkJava --case BenchmarkTest00013 --target http://127.0.0.1:18080 --context-path /benchmark --authorized-lab --target-state external-reset --reset-state artifacts/benchmarks/target-private.json --output artifacts/benchmarks/single-UNIQUE
venv-linux/bin/python -m benchmarks.scenario1 run --dataset /path/to/BenchmarkJava --manifest artifacts/benchmarks/scenario1-selection.json --target http://127.0.0.1:18080 --context-path /benchmark --authorized-lab --target-state external-reset --reset-state artifacts/benchmarks/target-private.json --fail-fast --output artifacts/benchmarks/run-UNIQUE
venv-linux/bin/python -m benchmarks.scenario1 run --dataset /path/to/BenchmarkJava --manifest artifacts/benchmarks/scenario1-selection.json --target http://127.0.0.1:18080 --context-path /benchmark --authorized-lab --target-state external-reset --reset-state artifacts/benchmarks/target-private.json --run-kind official --output artifacts/benchmarks/official-UNIQUE
venv-linux/bin/python -m benchmarks.scenario1 evaluate --run artifacts/benchmarks/run-UNIQUE
venv-linux/bin/python -m benchmarks.scenario1 report --run artifacts/benchmarks/run-UNIQUE
```

`report` reads an existing manifest, evaluation, case results, lifecycle events,
and optional run classification; it does not run the evaluator, worker, Agent,
provider, or target. It writes `report.json`, `summary.csv`, `partitions.csv`,
`per-case.csv`, an abnormal-analysis template, `thesis-tables.md`, and eight static SVG chart types under
`<run>/report/`. Use `--evaluation evaluation-<identity>.json` when the run has
multiple evaluation artifacts. `--output` may select another new directory
inside the same run. An existing output directory is rejected without overwrite.
Only evaluable cases enter the confusion matrix. CSV and the class-rate chart
include explicit numerators and denominators; a zero denominator is NA. The
per-case final status comes from the parent `runtime-finished` event, while the
result artifact's status is kept separately as worker diagnostics. Missing
transport dispatch counts and incomplete token totals remain blank. The report
exports a restricted presentation model without target origins, request fixtures,
evidence, provider configuration, or raw messages. Legacy smoke runs without a
declaration
are labeled `Development / smoke`; other legacy runs have undeclared official
status. A smoke report is for exporter validation, not a thesis result.

The loader recomputes the existing evaluator v1 identity from the semantic
manifest, non-evaluated lifecycle rows, partial-tail flag and (when present)
orphan diagnostic bindings. Scheduled hashes, result inventory/references and
run/case/execution bindings are checked separately. Recorded evaluations must
agree, with the original fail-fast exception. Missing or unusable diagnostics
can become NA only in invalid-result/execution-failed cases; identity conflicts
fail even there. Orphans never establish completion or contribute worker metrics.
Counts are cross-checked against records, truth and parent lifecycle, including
overall/class totals and supplied strata; rates retain the evaluator's
zero-denominator null semantics. Reporting validates consistency; it does not rerun
workflow acceptance/scoring or attest that the Agent's assessment is correct.

Raw run/case identifiers, provider/model labels and commit identifiers are kept
internally for validation, then presented as deterministic pseudonyms:
`<kind>-SHA256(compact sorted-key JSON ["scenario1-report-<kind>-v1", raw])`.
Kinds are `run`, `case`, `provider`, `model`, and `commit`. This permits offline
joins to original artifacts without exporting those arbitrary strings. Metadata
exports use fixed vocabularies, booleans/numbers, the recognized dataset version
`1.2`, a bounded Python version format and the fixed capability-profile name;
unrecognized labels and known fixture-value aliases are omitted. Reasons use a
closed vocabulary. CLI argument/input/output errors and success messages do not
echo artifact text, URLs or filesystem paths. These restrictions prevent raw
opaque labels/credentials from being copied; they are not anonymization or an
absolute secret detector. Unsalted pseudonyms/hashes permit correlation and
possible dictionary guessing; allowed structured fields and numeric metrics
remain observable. Inspect exports before public release of sensitive artifacts.

Output reserves the entire root namespaces `manifest.json`, `events.jsonl`,
`run-classification.json`, `evaluation-*`, `results`, `workspaces` and writer
staging names, even when absent. A new nested report directory elsewhere inside
the run is allowed. All validation/rendering finishes before output creation.
Files are written/fsynced in a private sibling staging directory (directories
0700, files 0600), then published with Linux `renameat2(RENAME_NOREPLACE)`.
Publication is an atomic directory move and rejects even concurrent empty-directory
collisions; unsupported platforms/filesystems fail rather than using an overwrite
fallback. WSL DrvFS mounts that reject `RENAME_NOREPLACE` cannot publish through
this CLI; use a Linux filesystem for the run. A synchronous write failure or
interruption cleans only owned staging;
retry can use the same destination. There is no asynchronous/offloaded writer.
Readers see either no destination or the complete rendered report. Held directory
handles, no-follow traversal and inode/path rechecks detect parent/staging
substitution. A process with permission to rename directories can still race the
last recheck; this is a residual TOCTOU limitation, not a filesystem sandbox.
An externally moved/substituted staging directory is not blindly deleted. A hard
process kill can leave private staging; power-loss durability of the final rename
is not guaranteed. Partition SVGs include all five labeled counts (including
zeros), patterned segments and a count table, with text outside small segments.

The compatibility report figures are `charts/class-metrics.svg`,
`charts/evaluation-partitions.svg`, `charts/processing-time.svg` and
`charts/total-tokens.svg`; `charts/confusion-matrix.svg` is an appendix figure.
These compatibility figures share Arial, title/classification/subtitle placement, typography,
borders and number formatting. Accepted/evaluable results use green; unresolved
uses ochre, failures red, invalid results purple and unrun cases gray. Partition
patterns and explicit counts, metric labels, class labels and NA text preserve
meaning without color. SQLi/XSS colors are consistent across both case charts.

Processing time uses the worker's measured `agent_seconds`, excluding setup,
freeze/teardown and parent overhead. It includes available retained intervals
from unsuccessful executions, marked `*`; it is not end-to-end latency or a
completed-only timing distribution. Missing intervals are NA, not zero.
Resource usage uses `total_tokens` only when `total_tokens_complete` is true;
incomplete/unavailable totals are NA and observed partial sums are never plotted.
The token figure states complete-total coverage. This metric is preferred because
the existing smoke artifact has complete totals for every case, while its legacy
HTTP dispatch counts are absent. LLM call counts would be a less direct measure
of token consumption. No HTTP or LLM-call figure is added.

Both case figures preserve manifest execution order, identical to `per-case.csv`
row order, with run-local labels `Case 01`, `Case 02`, etc. The SVG observation's
`data-case` attribute retains the full sanitized case pseudonym for audit joins;
the ordinal is a display aid, not a new canonical case identity. Each page shows
at most 20 observations, with a shared scale across pages of the same metric.
Additional pages use `processing-time-02.svg`, `total-tokens-02.svg`, etc.; all
are listed in `report.json`. If selected as supplementary figures, insert pages individually to keep labels
readable. Values use one decimal for seconds and integer token totals; large
values use scientific notation. CSV field names and schemas remain unchanged.

### Selected thesis presentation

The default thesis selection is exactly three separate, full-width figures:

| Figure | File under `charts/` | Quantity |
|---|---|---|
| F1 | `scenario1-validation-quality.svg` | Recall, Precision, FPR, Evaluability in SQLi then XSS blocks |
| F2 | `scenario1-processing-time-median.svg` | Median available Agent interval for parent-completed cases, seconds |
| F3 | `scenario1-total-tokens-median.svg` | Median complete total tokens for parent-completed cases, thousands |

`thesis-tables.md` is a deterministic presentation projection with suggested
captions and classification context, T1A outcomes, T1B evaluable-only confusion
counts, T2A time, T2B tokens, conditional T2C non-completed resources, a separate
missing-final-status ledger when needed, and T3 workload for the entire schedule.
Table row order is SQLi/XSS/Tổng. Existing CSV schemas, canonical metrics,
per-case ordering/identifiers and compatibility SVG behavior are preserved.
New exports list these four additions in `report.json.output_files`; an existing
smoke report is never migrated or overwritten. A 12-case export now has 14 files;
larger schedules retain compatibility pagination and three fixed thesis SVGs.

F1 uses canonical rates and fractions on a fixed 0–100% scale. A zero denominator
is `NA (0/0)`; a measured zero is `0,0% (0/d)`. No overall/composite score is drawn.
F2/F3 use parent `final_status=completed`, including unresolved/invalid-result
cases with usable measurements. Worker status cannot override parent status.
Token totals require completeness true and a valid nonnegative integer, retaining
fractional medians before formatting. Time/token availability is independent;
unavailable values are NA and measured zero is `0,0`, with no artificial marks.
Linear axes start at zero and are rounded from the displayed class medians.

T2 gives median, mean, nearest-rank-ceiling p95 and min–max, with available/eligible
coverage for each metric. Overall statistics are recomputed from pooled cases.
T2C groups each actual non-completed parent status separately, keeps retained
intervals and complete tokens with independent n/N availability, and does not
call those intervals time-to-completion. Cases without a final status stay in a
separate ledger grouped by class and evaluator partition. Its display label
“Không có trạng thái kết thúc” never becomes a canonical status; not-run stays
in evaluation/scheduled accounting and is not described as an executed case.
The ledger does not infer start/finish information from worker diagnostics.
Resource captions reference T2C/ledger when present.

Every T3 metric (complete total tokens, logical LLM invocations, policy-started
tool invocations, native HTTP dispatch attempts) requires N>0 and valid measured
consumption for all N scheduled cases to display a full aggregate. Otherwise it
shows NA and n/N; missing is never zero and known-case sums are not full totals.
Valid non-completed consumption is included. HTTP dispatch is always a column;
legacy missing counts remain NA (0/N), never backfilled from admission. Tool calls
are not successful-tool counts, and HTTP attempts do not prove delivery/success.
No Agent interval sum is presented as elapsed benchmark time.

Insert selected SVGs at 16–17 cm wide (target 16.5 cm) on A4 portrait; F1 is
16.5×11 cm, F2/F3 each 16.5×5 cm. Do not place the resource figures side by side
at half-page width. The 660-unit viewBox uses Arial/sans-serif: body/value 15 units
(about 10.6 pt), class labels 16 (11.3 pt), ticks 14.2 (10.1 pt). Only labels,
units, ticks and values are visible; title/desc accessibility metadata is hidden.
Captions, cohort definitions, availability and smoke/development classification
stay in the companion Markdown. Smoke illustrations are not official results.

Resource colors are SQLi `#285c79`, XSS `#6b5b83`; F1 uses blue Recall, green
Precision, red FPR and neutral gray Evaluability. Class/metric text preserves
meaning in grayscale. White backgrounds, solid bars and light grids have no
decorative effects. Vietnamese numeric labels use a decimal comma and one
decimal place; tiny positive values that would round to zero display `<0,1`.
T3 exact counts use a dot thousands separator. CSV numeric precision is unchanged.
Physical readability/color/grayscale QA is separate from regression correctness;
actual Word import/font substitution must be checked on a Word host.

Dry-run only parses/maps/selects/verifies source hashes and local runtime settings;
it creates no Agent/client/worker, performs no provider probe/target health check,
and saves no user configuration. Runtime execution requires `--authorized-lab`
and finite `--timeout`, `--http-requests`, `--tool-calls`, `--agent-calls` (defaults
180 seconds / 24 / 80 / 24). Exit codes: 0 command completed, 2 input/integrity
error, 3 incomplete offline run, 4 recorded execution failures, 5 blocked reset or
execution boundary. Unresolved labels
do not make a completed execution fail. Artifacts include `manifest.json`,
`run-classification.json`,
`events.jsonl`, `results/<case>.json`, `workspaces/<execution-id>/`, and immutable
`evaluation-<identity>.json` containing per-case records and all metrics.

Execution is sequential, Linux/POSIX (process groups/advisory locks). The owned
target helper creates and cleans disposable containers/networks. Logical reset
does not restart Tomcat/Docker. `--resume-from` requires the same locked selection,
a new output directory and a new verified reset; it replays the full selection
without appending to previous history. There is no automatic retry or parallel runner.
Dataset mapper v1 supports the inspected BenchmarkJava request-plumbing shapes;
other layouts must fail explicitly and receive a reviewed mapping extension.
