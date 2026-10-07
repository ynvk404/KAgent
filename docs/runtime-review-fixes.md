# Runtime review/report fixes retained after removing semantic variants

This is a historical implementation record. Its certificate staging/publication
and unchanged-schema descriptions below are superseded by the current
[Agent-assessed evidence contract](agent-assessed-evidence.md), which uses private
operator revisions, serialized checkpoints and canonical coverage reconciliation.
The earlier test counts below describe that earlier revision.

The semantic-variant Phase 2 implementation was removed before commit at the user's request. Its previous acceptance report is superseded by this record. Phase 1 remains the deterministic local taxonomy; a future external CWE fallback/review phase is not implemented here.

## Removed

- Immutable six-variant catalog, VariantDefinition and optional variant resolver/classify APIs.
- ValidationResult variant proposal, model-facing schema field and result merge/serialization changes.
- Trusted variant bindings, classification-specific digests, persistence/resume/revocation hooks and operator classification dialog.
- Variant fields/report metadata, variant CLI syntax and variant-only regression files.
- All changes to the CLI startup, HTTP permission lifecycle and execution-policy journal that existed only to support classification state.

`src/vulnerability/{taxonomy,__init__}.py`, `src/findings/classification.py`, `src/workflow/state.py`, `src/cli/runtime.py`, `src/permission/{network/grants,runtime/execution}.py`, the slash syntax catalog and Phase 1 taxonomy tests match HEAD. No reset of the whole worktree occurred.

## Kept: independently useful runtime bugs

| Before | Retained fix | Regression evidence |
| --- | --- | --- |
| Operator certificate published before record_result/session save | Temporary certificate is visible only to the private staged review path; the immediate-publication `operator_result()` API is removed. Publish the existing broad certificate after successful workflow/coverage/session commit and proof recheck | Success/negative result, record/coverage/save/owner failures, cancellation; no public bypass remains |
| Changed or overlapping review could commit stale conclusion | Complete transient state snapshot, per-Candidate review ticket, policy stamp, proof integrity checks and a guard immediately before workflow mutation | Changed notes with unchanged legacy fingerprint, forced identical retest, changed candidate/proof/policy, newest review wins, result changes during record_result/save |
| Existing report path returned while notifier described newly constructed Finding | Read the persisted Markdown snapshot into the Finding before notifier and returned tool result | Retry after new review/title/severity/taxonomy metadata remains pinned to the first report |
| Cancellation released store lock before its offloaded write finished | Hold the lock until the worker completes, even when caller is cancelled | Concurrent cancelled write and retry produce one original report |
| Result or evidence could change while finalization awaited proof reads or report persistence | Recheck candidate/result/evidence state and proof integrity after Store.save; do not mark, notify, or return success for stale state. A saved report remains intact for retry | Result replacement and proof-file change during save; notifier suppression; persisted retry |
| Persisted report parser treated body headings as report sections and did not prove legacy coverage | Recognize only KAgent section names and restore the historical single `Impact` format | Current and history-derived report fixtures with heading-like body/evidence text |
| Model tool-call card looked like a completed finding | Label it proposed/pending validation | TUI state regression |

There is no new pentest capability, verifier subsystem or classification-trust store. `src/workflow/review.py` contains only a transient digest used for concurrency checks. It does not change either legacy fingerprint, persist a binding, or select CWE. ObservationStore persistence keeps its existing `observations` and `results` domains; trusted adapters and legacy broad-certificate behavior remain compatible.

The existing conclusion review syntax stays:

```text
/review-result <candidate-id> <confirmed|not-confirmed> <severity> <observed impact>
```

The active classification path is:

```text
Confirmed Finding → Phase 1 local taxonomy → class-level CWE or None → persisted report
```

Future external CWE retrieval with evidence-bound review remains a separate task. No KB/MCP, retrieval, top-k or promotion mechanism was added.

## Persistence limits

Workflow/session save and controller certificate storage are separate existing stores. The review publishes no new certificate if a downstream commit fails; it does not claim a new cross-file ACID transaction. Coverage failure can retain a result with pending coverage. Owner write failure restores the previous broad certificate rather than manufacturing a new conclusion. Already persisted reports are never rewritten by retry. Existing artifact paths, modes and canonical/legacy report lookup remain unchanged. The store guarantee remains its existing in-process lock and collision-safe file creation, not a newly introduced cross-process transaction.

## Verification

Focused regressions:

```bash
pytest -q tests/data/test_findings_store.py tests/tools/test_finding.py tests/security/test_operator_review.py tests/security/test_evidence_reads.py
```

**134 passed**.

Wider review/store/finding/workflow regressions:

```bash
pytest -q tests/security tests/data/test_findings_store.py tests/tools/test_finding.py tests/tools/test_workflow.py tests/tools/test_coverage.py tests/state/test_workflow_state.py tests/state/test_session_store.py tests/integration/test_skill_workflow.py tests/integration/test_phase4_workflow_e2e.py
```

**702 passed, 1 skipped in 91.26s**.

Final verification:

```bash
pytest -q
venv-linux/bin/pyright
git diff --check
git status --short --untracked-files=all
```

- Full suite: **3,236 passed, 1 skipped, 2 warnings in 257.66s**. The warnings are the existing malformed-provider-config fallback test warnings.
- Pyright: **0 errors, 0 warnings, 0 informations**.
- Diff check: exit 0, no output. The 15 intended modified/new files remain uncommitted.
- Repository search finds no `operator_result()` call or semantic-variant proposal, catalog, trusted binding, or variant-specific review implementation. Phase 1 taxonomy files remain unchanged.

The final classification API and Candidate/ValidationResult models are exactly the Phase 1 versions. The retained tests cover generic runtime behavior independently of any variant catalog. This handoff is for runtime bug fixes only, not acceptance of the removed Phase 2 feature.

No live model or target vulnerability validation is claimed. Existing external/live skip behavior is preserved. No package installation, staging, commit or push.
