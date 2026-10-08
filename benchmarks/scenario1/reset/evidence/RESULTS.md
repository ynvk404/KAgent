# Focused reconstruction verification — 2026-10-08

Overall verdict: **PARTIAL**. Logical in-place reset is implemented and verified
for the focused tests. No certification covers arbitrary SQL, all 959 cases or
full Hibernate ORM cache parity. A recreation fallback is not implemented.

## Target reproduction

`final-focused/verification.json` is the clean reproduction from maintained
source and installation scripts, without patching a running target.

- 42 checks PASS, zero failed.
- Two catalogs independently verified against immutable fresh baselines.
- Committed, rolled-back/identity, DDL/procedure, Spring and Hibernate-active mutations restored.
- Static JDBC, Spring pool, normal/classic factories replaced; no eager Spring warm-up.
- Sessions/cookies invalidated, active requests drained, repeated resets verified.
- 13 representative SQLi/XSS response pairs matched status, full response hash,
  relevant security headers and redacted cookie semantics.
- Explicit INSERT Case A → reset/readback → query Case B passed.
- Drain timeout, unaccounted connection/transaction and unknown client outcome blocked admission.
- Production installer/controller/runner exercised with constant INSERT and XSS
  fixtures using a deliberately failing model-free launcher. No TP/TN was inferred.
- 33 measured reset cycles: median internal 0.979764574 s; median end-to-end 0.985657232 s.
- No Tomcat/Docker restart during successful logical-reset cycles.
- All six owned target groups cleaned; no owned target containers or networks remain.
- Final Java source digest matches the reproduction: `285a2eb1669b2e6ec196ac15e828677f1a24fdabfb2ac2c370daeacd6f4a56db`.

## Regression lineage

- `runner-focused.xml`: 23 focused runner tests PASS before the added evaluator/reporting assertions.
- `benchmark-regressions.xml`: 357 PASS, 14 infrastructure failures. These failures
  were WSL `os.getcwd()` failures after concurrent Docker Desktop drive remounts;
  one subprocess consequently could not import `benchmarks`.
- `benchmark-regressions-retry.xml`: all 14 failed tests PASS from WSL home with
  explicit PYTHONPATH; no test assertions or production core code were weakened.
- `runner-focused-final.xml`: 20 PASS; three test-harness import failures after
  adding blocked-run evaluator/reporting assertions. The import was corrected.
- `runner-blocked-evaluation.xml`: all three corrected tests PASS, including
  unchanged evaluator/reporting acceptance and absence of confusion classifications.
- `runner-successful-sequence.xml`: one PASS for sequential admission of all 12
  synthetic fixture cases with verified resets; 23 unrelated focused cases deselected.

Together these receipts cover 372 distinct benchmark regression tests (including
24 focused reset tests), with failures above resolved by the recorded targeted reruns.

The broad regression group was run once; only failures and newly strengthened
focused tests were rerun. No LLM-driven smoke, official benchmark, dataset-wide
source re-audit, commit or push was performed. BenchmarkJava worktree is unchanged.

## Boundary at the original verification

The historical audit projection in `source-boundary.json` retains all 504 SQLi
case identities: 232 input-independent SQL cases, including 28 constant INSERT
cases, are eligible with source hashes and reset verification. The other 272
cases are explicitly blocked for unbounded SQL-mediated effects. All 455 XSS
entries remain available under the native HTTP boundary. Those eligibility
counts are not verified execution counts.

Hibernate normal startup cache exposes hobby IDs [2,1,3], while the actual
database/classic cache and post-reset reads expose [1,1,1]. The tests preserve and
document this limitation; USER/HOBBY allocator probes matched repeat resets.

Development reports under `focused-development-*` retain failed iterations,
including the infrastructure and test-fixture issues. They are not clean final
verification evidence. Private runtime state/deployment copies were removed.
The original reset prototype and primary handoff were unavailable; historical
20/20, 28/28 and timing results were never treated as certification of this code.

## Subsequent policy change — 2026-10-08

The operator subsequently chose to run all 272 historically SQL-controlled cases
using logical reset, accepting the unverified restoration of effects outside
the databases. The static admission gate has been removed. All 504 SQLi and
455 XSS cases are now eligible; source/target identity, full baseline comparison,
reset failure/timeout/unknown-outcome blocking and scoring contracts remain intact.

Current run policy records `mode=logical-reset-all-cases`, `scope_verdict=PARTIAL`,
`audit_role=historical-context-only` and
`external_effects_restoration_verified=false`. Reset receipts carry the same
external-effects limitation. Historical `blocked_external_effects` entries in
`source-boundary.json` are context only and do not exclude cases.

The original 42-check target evidence and timings above remain evidence for the
unchanged Java reset helper and its focused samples. They do not certify the
newly admitted 272 cases. No LLM smoke or full benchmark was run for this change.
The current locked smoke command and owned target setup/cleanup are in `../README.md`.

Policy-change verification: `logical-all-cases-policy.xml` has 25 focused tests
PASS, including admission despite the historical blocked classification, no-audit
admission, unchanged fail-closed and explicit evidence scope. The adjacent data
contract/reliability group has 39 PASS in `logical-all-cases-contracts.xml`.
Java source digest still matches the 42-check target reproduction. No target
redeployment was needed for this parent-policy-only change; `git diff --check`
passes and the BenchmarkJava worktree remains unchanged.
