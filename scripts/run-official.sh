#!/usr/bin/env bash
set -euo pipefail

# Run the frozen 40-case selection. Supply --manifest or configure [manifests].official.
# An optional first positional argument names the output; otherwise use a unique run.
if [[ $# -gt 0 && "$1" != --* ]]; then
  run_name="$1"
  shift
  exec python -m benchmarks.scenario1 run --mode official --authorized-lab \
    --output "artifacts/benchmarks/scenario1-official-run-${run_name}" "$@"
fi
exec python -m benchmarks.scenario1 run --mode official --authorized-lab "$@"
