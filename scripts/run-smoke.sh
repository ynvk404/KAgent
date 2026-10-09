#!/usr/bin/env bash
set -euo pipefail

# Preserve the old optional numbered-output invocation; no arguments uses a unique run.
if [[ $# -gt 0 && "$1" != --* ]]; then
  run_name="$1"
  shift
  exec python -m benchmarks.scenario1 run --mode smoke --authorized-lab \
    --output "artifacts/benchmarks/scenario1-smoke-run-${run_name}" "$@"
fi
exec python -m benchmarks.scenario1 run --mode smoke --authorized-lab "$@"
