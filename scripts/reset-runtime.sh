#!/usr/bin/env bash
# ==============================================================================
# scripts/reset-runtime.sh
# Safely resets transient runtime state in KAgent between test or engagement runs.
#
# Preserves:
#   - .kagent/intelligence (durable learned scenarios)
#   - .kagent/memory (durable memory facts)
#   - .kagent/engagement.md
#   - artifacts/audits (audit reports & characterization scripts)
#   - artifacts/checkpoints (code milestones & backup manifests)
#   - benchmarks/ (planner cases, test definitions)
#   - source code, skills, tests, configuration
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/cleanup-common.sh
source "$SCRIPT_DIR/lib/cleanup-common.sh"

usage() {
    cat <<'EOF'
Usage: ./scripts/reset-runtime.sh [OPTIONS]

Safely resets transient runtime state in KAgent.

Options:
  -n, --dry-run    Show what files would be deleted without deleting anything
  -h, --help       Show this help message and exit

Cleared Paths (contents only):
  - .kagent/coverage/*
  - .kagent/evidence/*
  - .kagent/observations/*
  - .kagent/permissions/*
  - .kagent/sessions/* (if present)
  - .kagent/context/* (if present)
  - Temporary config files (.kagent.cfg.tmp.*)
  - Runtime skill artifacts (artifacts/<skill>/*, findings/*, worker/*)

Preserved Paths:
  - .kagent/intelligence (durable scenario knowledge)
  - .kagent/memory (durable facts)
  - .kagent/engagement.md (durable notes)
  - artifacts/audits/* (milestone audit reports & characterization scripts)
  - artifacts/checkpoints/* (stage snapshots & archives)
  - benchmarks/* (planner cases & benchmark specifications)
  - All source code, skills, tests, and configuration
EOF
}

DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -n|--dry-run)
            DRY_RUN=1
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

reset_runtime_state "$DRY_RUN"

if [[ "$DRY_RUN" -eq 1 ]]; then
    log_info "Dry-run complete. No files were removed."
else
    log_info "Runtime reset complete."
fi
