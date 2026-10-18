# Milestone C — portable verification evidence

Source freeze: **715 files**, SHA-256
`76168e98a362ef43f4636dc745fc356cfa57a425e59f89ec842b5b174bce653c`.

The original final run completed with **8,490 passed, 12 skipped, 79 warnings,
exit 0**. Targeted: 1,296 passed. Integration including Agent: 6,729 passed,
1 skipped. Pyright: 0 errors / 0 warnings. Cleanup did not rerun these suites;
source, tests and runtime/test configuration still match the exact freeze.

## Check this bundle

From the repository root:

```sh
venv-linux/bin/python docs/verification-milestone-c/audit.py
```

This checks versioned source, available local files, published artifact hashes,
recorded exit codes, complete final JUnit counts and all 51 quoted-URL regressions.
It does not run tests, contact a target/model, or write runtime state.

The historical 715-file manifest includes two ignored local-only files:
`benchmarks/scenario1/config.local.toml` and `scripts/browser_latency_protocol.mjs`.
They remain local and are not published. On the original worktree the audit checks
the exact 715-file aggregate. A fresh clone checks all **713 versioned files**
against their original hashes and explicitly reports that the complete local
freeze is unavailable. Matching those 713 hashes is not a new full-suite result.

`results.json` preserves the five final verification records, exact argv,
environment, times, skips and hashes of original logs/XML. `$REPO`, `$HOME` and
`$LOCAL_TMP` replace machine-specific paths. These are normalized historical
records, not new executions. `provenance.json` distinguishes original hashes from
the hashes of published, sanitized files.

`full.junit.xml` is a sanitized copy of the complete final JUnit. It retains every
case, status, duration and skip. Hostname and diagnostic properties were removed;
45 sensitive-looking parameter IDs were replaced by deterministic SHA-256 labels.
Its hash intentionally differs from the original XML. Original bytes remain local.
`full-output.txt` and `pyright-output.txt` are normalized copies of the original
outputs. No pass/fail/skip counts were edited.

The small reproduction/result records and `failure-classification.json` retain the
basis for the corrections. The old stall timeout remains **unresolved**: the final
stall case passed in 3.597 seconds, but no finalization fix or historical cause was
proven. M2 synchronization was reproduced; no contract violation was proven, and
production reconciliation was preserved. See the
[final corrections report](../recon-milestone-c-final-corrections.md).

## Reproduce verification

The portable runner defaults to ignored `.kagent/verification/`. Set
`KAGENT_VERIFY_OUT` to another local output directory if needed. It never overwrites
this committed evidence bundle by default. Reuse the responsibility paths in
`results.json` for `targeted`, `integration`, and `focused-final`.

```sh
env -u COLORTERM venv-linux/bin/python docs/verification-milestone-c/runner.py freeze
env -u COLORTERM venv-linux/bin/python docs/verification-milestone-c/runner.py full
venv-linux/bin/python docs/verification-milestone-c/runner.py pyright
```

`m2_audit.py` and `b-capability-probe.py` are standalone offline diagnostics; run
them from the repository root with `PYTHONPATH=.`. M2 prints a fresh result without
overwriting its historical committed JSON. Existing live/Java skip conditions and
the Burp exclusion in `pytest.ini` remain unchanged. No Scenario 3 is requested.

`diagnostics.py` preserves the stall timing observer. To run that single offline
case with observation, use the following command; new observations go to ignored
`.kagent/verification/a-observations.jsonl`. This is an optional new execution,
not a claim that the historical timeout has been explained.

```sh
PYTHONPATH=docs/verification-milestone-c:. venv-linux/bin/pytest -q -p diagnostics 'tests/benchmarks/test_scenario1_closure.py::test_owned_stop_without_declaration_records_unknown_not_false[stall]'
```

## Local archive

Raw historical evidence remains unchanged under ignored `docs/verification-stage3/`:
191 files, approximately 12.6 MB. `local-archive-index.json` records each relative
path, size and SHA-256 without including raw content. It includes intermediate
failures, invalid/stale-result diagnostics, duplicate snapshots, diff/status dumps,
and original final results. These are not committed and have not been deleted.
Historical report links with no published counterpart lead here; use the index to
locate the original locally. Older Stage 1/2 temporary directories may already be
unavailable as documented in their reports; cleanup does not reconstruct evidence.

One pre-existing corrupt loose Git object was also preserved unchanged. All 7,095
objects reachable from refs/reflogs passed typed-payload SHA verification before
staging. `git-integrity.json` records this check. This does not mean full `git fsck`
passes: it still reports the unreferenced corrupt object, which needs a separate
repair decision. No Git history or object was rewritten or removed.
