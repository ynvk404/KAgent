#!/usr/bin/env bash
set -euo pipefail

python -m benchmarks.scenario1 run \
  --dataset /mnt/d/DOANTOTNGHIEP/benchmark-targets/BenchmarkJava \
  --manifest artifacts/benchmarks/scenario1-smoke-1729/manifest.json \
  --target http://127.0.0.1:18080 \
  --context-path /benchmark \
  --authorized-lab \
  --target-state external-reset \
  --container operator-benchmark \
  --ingress-container operator-ingress \
  --reset-war /home/khainguyen/.cache/kagent-s1-build-62da4de4df96/benchmark-offline.war \
  --output "artifacts/benchmarks/scenario1-smoke-run-$1"
