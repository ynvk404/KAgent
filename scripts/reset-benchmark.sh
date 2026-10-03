#!/usr/bin/env bash
# ==============================================================================
# scripts/reset-benchmark.sh
# Resets transient runtime state and benchmark outputs between benchmark runs.
#
# Preserves by default:
#   - .kagent/intelligence (durable learned scenarios; reset only with --reset-intelligence)
#   - .kagent/memory (durable memory facts)
#   - benchmarks/planner_cases.json (ground truth & test cases)
#   - benchmarks/REASONING.md (benchmark documentation & specifications)
#   - artifacts/audits/ and artifacts/checkpoints/
#   - source code, skills, tests, configuration
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/cleanup-common.sh
source "$SCRIPT_DIR/lib/cleanup-common.sh"

usage() {
    cat <<'EOF'
Usage: ./scripts/reset-benchmark.sh [OPTIONS]

Safely resets KAgent state between benchmark runs.

Options:
  -n, --dry-run             Show what files would be deleted without deleting anything
  --reset-intelligence     Also reset .kagent/intelligence for a cold-agent (fresh-agent) benchmark
  -h, --help                Show this help message and exit

Cleared Paths:
  - All transient runtime state (.kagent/coverage, evidence, observations, permissions, skill artifacts)
  - Benchmark run/results exports (.kagent/reasoning-*.jsonl, .kagent/*benchmark*.json*, metrics*.jsonl)
  - Optionally .kagent/intelligence/scenarios.jsonl (only if --reset-intelligence is specified)

Never Deleted:
  - benchmarks/planner_cases.json (test cases & ground truth)
  - benchmarks/REASONING.md (benchmark spec)
  - artifacts/audits/* (historical audit reports)
  - artifacts/checkpoints/* (snapshots)
  - .kagent/memory/* (durable memory facts)
  - All source code, skills, tests, and configuration
EOF
}

DRY_RUN=0
RESET_INTELLIGENCE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -n|--dry-run)
            DRY_RUN=1
            shift
            ;;
        --reset-intelligence|--fresh-intelligence)
            RESET_INTELLIGENCE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

verify_repo_root

if [[ "$DRY_RUN" -eq 1 ]]; then
    log_info "Running in DRY-RUN mode. No files will be modified."
fi

# Step 1: Clear all transient runtime state
reset_runtime_state "$DRY_RUN"

# Step 2: Clear benchmark-generated output files
log_info "Clearing benchmark-generated run outputs..."
for pattern in "${BENCHMARK_OUTPUT_PATTERNS[@]}"; do
    clear_glob_patterns ".kagent" "$pattern" "$DRY_RUN"
done

# Step 3: Handle .kagent/intelligence based on --reset-intelligence
if [[ "$RESET_INTELLIGENCE" -eq 1 ]]; then
    log_info "Resetting .kagent/intelligence for fresh-agent benchmark..."
    clear_single_file ".kagent/intelligence/scenarios.jsonl" "$DRY_RUN"
    clear_single_file ".kagent/intelligence/scenarios.jsonl.lock" "$DRY_RUN"
else
    log_preserve ".kagent/intelligence/scenarios.jsonl (retained; pass --reset-intelligence for fresh-agent benchmark)"
fi

# Step 4: Re-affirm preservation of benchmark definitions
log_preserve "benchmarks/internal/planner_cases.json (ground truth definition)"
log_preserve "benchmarks/internal/REASONING.md (benchmark specification)"

if [[ "$DRY_RUN" -eq 1 ]]; then
    log_info "Dry-run complete. No benchmark files were removed."
else
    log_info "Benchmark reset complete."
fi
