# Scenario 3 experiments

`scripts/` contains reusable launchers only. Local experiment inputs and outputs
belong here; runtime data is ignored by Git and must never be staged wholesale.

```text
experiments/scenario3/
  profiles/<run-id>/
    profile.json                 # reviewed paths, source/config hashes, limits
    whole-target-request.txt     # operator-reviewed user prompt
  runs/<run-id>/
    backup/                      # verified copies; originals are untouched
    project/
      skills/                    # exact builtin skill snapshot
      .kagent/                   # project intelligence/memory, journals, coverage,
                                 # observations, retained results/evidence
      artifacts/                 # runtime-generated evidence/reports/findings
    profile-home/.kagent/        # fresh personal intelligence/memory,
                                 # sessions/<id>.json, context/<id>.md, notes
    logs/                        # process/session logs
      headless/events.jsonl      # redacted events and terminal outcome
      headless/llm-metrics.jsonl # per-request usage/latency; no estimated cost
    launch-started.json           # exclusive single-launch marker
```

Raw provider credentials remain in the original API Config; manifests contain
only non-secret identity and its hash. Profile and run directories are created
exclusively after a reviewed `--prepare`; no existing experiment is overwritten
or deleted. Backup data stays outside the new Agent project root.

Example read-only planning command, not an experiment:

```bash
bash scripts/run_experiment.sh --dry-run \
  --run-dir /home/khainguyen/kagent/experiments/scenario3/runs/scenario3-20261018-01
```

`--prepare` creates a profile without starting Agent. `--run` defaults to the
official TUI with a prefilled user draft; Enter submits it. Headless requires
both `--headless --execute-prompt`. Choose `--interactive` for POSIX terminal
questions/reviews (TTY required), or `--non-interactive` for fail-closed input.
YOLO additionally requires explicit `--yolo --accept-unknown-http-effects` and
uses the profile's finite native HTTP grant. No mode or answer is inferred.

At step exhaustion headless saves `budget_exhausted` and stops. TUI Continue
starts another Agent turn; there is no same-turn resume API. This launcher
does not create extra turns or replenish an approved experiment budget.
See [implementation and verification](../../docs/scenario3-implementation-verification.md)
for command templates, limits and the Stage 3 freeze delta.

Offline verification logs may be stored under `runs/offline-verification-*`;
these are fixture tests, never Whole-target results. Earlier preflight evidence
under `.kagent/evaluations/scenario3-preflight-20261018/` is preserved unchanged
as a historical bundle, not imported into any new profile.
