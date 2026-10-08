# Scenario 1 logical reset handoff

The maintained implementation is here, rather than in temporary experiment files.
It uses SQL/DDL against two immutable fresh baselines. It never replaces catalog
files, edits HSQLDB internals, or restarts Tomcat/Docker during a logical reset.
BenchmarkJava source, truth, mappings, evaluator and metrics contracts are unchanged.

Required target: source `8b67a88d73b2594570fc21150705283de884620b`, HSQLDB 2.7.4,
Tomcat 9.0.122, JDK 17, Hibernate 3.6.10.Final and Spring 5.3.39. The original
handoff/prototype sources were unavailable in the supplied recovery directories.
Historical 20/20 and 28/28 results are context only, not evidence for this code.

**Status: PARTIAL.** The logical reset is implemented within the focused
SQLi/XSS scope. Full ORM parity and restoration of effects outside the databases
remain unverified. Use the focused reproduction command below to generate new
verification receipts; historical receipts are removed by `scripts/cleanup.py`.
The current parent policy admits all 504 SQLi and 455 XSS cases through logical
reset, including the 272 historically classified SQL-controlled cases. This
policy follows the operator's explicit choice to accept that external-effects
limitation; it does not extend the earlier focused verification to all cases.

The reset-blocked branch uses the evaluator and reporting loader's existing
fail-fast sentinel; `blocked.json` and event `block_reason` retain the reset cause.
Historical audit provenance is optional: pass `--reset-audit <path>` to bind an
existing audit to a new run. No default audit file is required.

## Implementation

| File | Responsibility |
|---|---|
| `java/CatalogBaseline.java` | Independent seed/column/key/procedure oracle; immutable DDL, complete rows and metadata; exact named constraints; SQL restoration and independent readback |
| `java/ResetLifecycle.java` | Rollback/close static JDBC, JNDI and Spring pools, normal/classic sessions and factories; restore both catalogs; replace pools/factories without eager Spring borrow |
| `java/ResetGate.java` | Verified idle access; closed benchmark admission, finite per-case lease, request drain, session invalidation, nonce/generation receipts and permanent failure state |
| `java/InstallProbe.java` | Live Tomcat container hierarchy, classloader, original filter instance and lifecycle listener assertions |
| `install.py` | Compile into a copy of the cached WAR and install the first filter/lifecycle listener; retain the original initializer and filters |
| `run-target.sh` | Start the owned HSQLDB server and cached Tomcat; apply Javassist `--add-opens` to the actual JVM |
| `owned_target.py` | Optional legacy/test tooling for disposable targets; not required by normal CLI execution |
| `operator_target.py`, `docker_access.py` | Existing-container inspection/control, exact URL/source/bootstrap/JVM binding; no Docker lifecycle operations |
| `client.py` | Parent-only strict control verification, target/source attestation, exclusive runner lock and durable reset receipts |
| `verify.py`, `tests/ResetProbe.java` | Fixed, model-free focused reproduction and mutations; production targets do not install probes |
| `../core/runner.py`, `../__main__.py` | CLI and sequential worker lifecycle integration |
| `../../../tests/benchmarks/test_scenario1_reset.py` | Offline admission/failure/resume/metrics/identity regressions |

Baseline capture runs after the original application initializer, while the
testcase gate remains closed. It validates the original seed inventories and
rows, column types/sizes/defaults/nullability/identity flags, keys and procedure
inventory independently. Subsequent checks compare the complete captured rows,
SCRIPT configuration/DDL/procedures/grants/identity positions, and all selected
metadata columns, including generated constraint/index names. Names are never
normalized away. Changed settings are replayed; unchanged settings are retained
to avoid HSQLDB changing collation spelling on an otherwise identical replay.

Each case requires identity verification, logical reset/readback, explicit route
authorization, worker completion/evidence, then logical reset/readback. Any
error/timeout/unknown outcome stops the parent. `blocked.json` and untouched
`not-run` events prevent those cases entering TP/TN/FP/FN. Exit code 5 means blocked.
Receipts under `reset-evidence/` record reset durations separately from worker
wall time, Agent processing time and token accounting. Control credentials and
audit classifications never enter the worker envelope. Every run's
`reset-policy.json` records `mode=logical-reset-all-cases`, `scope_verdict=PARTIAL`
and `external_effects_restoration_verified=false`. Reset receipts also record
that their verification covers database catalogs and application lifecycle,
without certifying restoration of filesystem, LDAP or other external effects.

After successful startup baseline capture, `IDLE` allows ordinary browser and
KAgent TUI HTTP requests, including requests that change target state. The reset
control endpoint still requires the existing parent-only credential. No extra
request credentials or manual commands are needed for normal access.

Under the existing exclusive target lock, the runner first records `block`,
closing admission before identity checks. Active requests may finish; the existing
`before` reset drains them, invalidates idle sessions and restores/verifies both
catalogs and JDBC/Hibernate lifecycle before authorizing the first testcase.
For operator targets, closure goes directly to the selected container's JVM,
so a failed published-port or source check cannot leave idle admission open.
Only the initial identity check may observe draining requests/sessions; it does
not certify clean state. The `before` reset must still prove zero active requests
and sessions. Subsequent cases retain the existing before/authorize/after sequence.

The final successful `after` reset is also the final run reset. The new `idle`
receipt independently verifies the installed filter/lifecycle, quiescence,
baseline, boot and generation before restoring normal access while still holding
the target lock. Worker errors can return to idle after verified cleanup; reset,
identity or idle-transition errors and interruptions remain closed. Expired
testcase leases or a crashed runner never automatically reopen idle access.
An uncertain result is a blocker, not a reason to publish idle from `finally`.

The updated Java gate requires one controlled deployment restart; source edits
do not modify the gate already loaded in a running JVM. See
[operator-setup.md](operator-setup.md#deploying-the-idle-access-update) for the
approval-gated operation. There are no restarts between testcase executions.

## Supported modes and limits

| Mode | Status |
|---|---|
| Operator-managed exact-target logical reset | Admission implemented; requires separately prepared compatible instrumentation and isolation |
| Owned exact-target logical reset | Retained for optional legacy/test tooling; regenerate focused verification with `verify.py` |
| All 504 SQLi cases | Eligible with exact source/target identity and verified logical reset; no historical allowlist admission gate |
| 455 XSS cases | Preserved and eligible under the existing native HTTP boundary; focused response samples do not certify all 455 |
| 272 historically SQL-controlled cases | Eligible for logical reset; effects outside databases remain an accepted limitation |
| Container recreation between cases | Not used |
| Arbitrary SQL/Java/filesystem/LDAP effects | No universal certification |
| Hibernate ORM cache parity | Known limitation: fresh normal cache `[2,1,3]`, database/classic `[1,1,1]`; reset reads `[1,1,1]` |
| Interruption/resume | Close/reset best effort; next invocation performs a new verified reset and replays the same selection into a new directory |

The internal network has no target egress interface. A non-root, read-only nginx
proxy publishes only a loopback port and has a fixed upstream. Target root is
read-only, capabilities dropped, privileges restricted, resource budgets finite,
and writable runtime state lives in disposable tmpfs. Deployment mounts contain
only bootstrap source copies, not benchmark evidence/control state. These bounds
do not establish safety for arbitrary SQL payloads. Unknown connections as well
as active transactions are rejected after known pools are closed.

The protocol verifies catalogs, lifecycle and startup pool configuration; it does
not claim full Hibernate first-level cache equivalence or comprehensive testing
of every possible database configuration mutation. An unsupported restoration
must retain exact comparison failure and block the run.

## Reproduce focused verification

Run in Ubuntu/WSL from `/mnt/d/DOANTOTNGHIEP/kagent`. This command uses the reusable
image/WAR cache, creates only owned disposable resources, and cleans them. It
makes fixed HTTP requests and uses injected model-free worker failures for the
production runner integration check; it does not run an Agent smoke or benchmark.

```bash
venv-linux/bin/python -m benchmarks.scenario1.reset.verify \
  --dataset /mnt/d/DOANTOTNGHIEP/benchmark-targets/BenchmarkJava \
  --war /home/khainguyen/.cache/kagent-s1-build-62da4de4df96/benchmark-offline.war \
  --output artifacts/benchmarks/reset-verification-NEW
```

Verification receipts store hashes, durations, status and redacted response
semantics under the supplied output directory. Private state contains a
credential: keep it local, never commit it or pass it to workers. Runtime copies
and private state are removed during owned cleanup. Docker Desktop/Drvfs can
invalidate the caller's directory inode during bind mounts; the resource wrapper
reacquires the same working-directory path after Docker operations.

## Operator-managed target and locked 12-case smoke

See [operator setup and exact CLI commands](operator-setup.md). The normal runner
uses `--target`, `--container`, `--reset-war`, and an existing `--ingress-container`
when needed. The operator manages Docker lifecycle through Docker Desktop.
Logical SQL/DDL reset, admission/draining, session invalidation, baseline checks,
protocol receipts and all stop conditions are unchanged. Legacy `--reset-state`
remains available for existing tooling; no creation or cleanup helper is needed
for the normal run.

The existing `owasp-benchmark` container was inspected read-only and lacks the
supported reset installation and isolation. It was not modified. Setup is a
separate operator action; missing prerequisites fail closed. Real verification
of the new admission path is pending a prepared operator-selected target.

For interruption recovery, use the same manifest, a new output path, and
`--resume-from artifacts/benchmarks/OLD-RUN`. All selected cases are replayed;
previous events/results remain immutable. This is safe restart, not append-in-place
resume or aggregation of duplicate attempts. No commit or push is part of this work.
