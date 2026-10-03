#!/usr/bin/env bash
# ==============================================================================
# scripts/prepare-benchmark.sh
# Orchestrates existing scripts to put KAgent into a clean, reproducible,
# benchmark-ready state.
#
# Workflow:
#   1. Optionally archives active run state before cleanup (--archive)
#   2. Resets transient runtime and benchmark outputs via scripts/reset-benchmark.sh
#   3. Optionally resets .kagent/intelligence for fresh-agent runs (--reset-intelligence)
#   4. Runs read-only environment verification via scripts/doctor.sh
#   5. Verifies benchmark definitions (planner_cases.json, REASONING.md)
#   6. Records benchmark prep metadata (.kagent/benchmark-prep.json)
#   7. Stops at a clear READY state (does not mutate benchmarks or start pentest)
# ==============================================================================
set -euo pipefail

if [[ ! -f "pyproject.toml" || ! -f "AGENTS.md" || ! -d "src" ]]; then
    printf "[ERROR] This script must be executed from the KAgent repository root.\n" >&2
    exit 1
fi

DRY_RUN=0
ARCHIVE=0
RESET_INTEL=0
SKIP_DOCTOR=0

usage() {
    cat <<'EOF'
Usage: ./scripts/prepare-benchmark.sh [OPTIONS]

Prepares KAgent for clean, reproducible benchmark execution.

Options:
  --archive                 Archive the current run before resetting state
  --reset-intelligence     Reset .kagent/intelligence for a cold-agent (fresh-start) benchmark
  --fresh-intelligence     Alias for --reset-intelligence
  --skip-doctor             Skip running ./scripts/doctor.sh health checks
  -n, --dry-run             Preview all preparation actions without modifying any files
  -h, --help                Show this help message and exit

Preserved:
  - benchmarks/planner_cases.json (test cases & ground truth)
  - benchmarks/REASONING.md (benchmark documentation)
  - artifacts/audits/* and artifacts/checkpoints/*
  - All source code, skills, tests, and configuration
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --archive)
            ARCHIVE=1
            shift
            ;;
        --reset-intelligence|--fresh-intelligence)
            RESET_INTEL=1
            shift
            ;;
        --skip-doctor)
            SKIP_DOCTOR=1
            shift
            ;;
        -n|--dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf "[ERROR] Unknown option: %s\n" "$1" >&2
            usage
            exit 1
            ;;
    esac
done

log_step() { printf "\n\033[1;36m==> [Step %s] %s\033[0m\n" "$1" "$2"; }
log_info() { printf "[INFO] %s\n" "$*"; }
log_ok()   { printf "\033[32m[OK] %s\033[0m\n" "$*"; }
log_err()  { printf "\033[31m[ERROR] %s\033[0m\n" "$*" >&2; }

# Step 1: Optional Archive
if [[ "$ARCHIVE" -eq 1 ]]; then
    log_step "1/5" "Archiving current run before reset..."
    ARCHIVE_FLAGS=("--latest")
    if [[ "$DRY_RUN" -eq 1 ]]; then
        ARCHIVE_FLAGS+=("--dry-run")
    fi
    ./scripts/archive-run.sh "${ARCHIVE_FLAGS[@]}"
else
    log_step "1/5" "Skipping archive (pass --archive to preserve current run state)."
fi

# Step 2: Reset Benchmark State
log_step "2/5" "Resetting runtime and benchmark state..."
RESET_FLAGS=()
if [[ "$DRY_RUN" -eq 1 ]]; then
    RESET_FLAGS+=("--dry-run")
fi
if [[ "$RESET_INTEL" -eq 1 ]]; then
    RESET_FLAGS+=("--reset-intelligence")
fi
./scripts/reset-benchmark.sh "${RESET_FLAGS[@]}"

# Step 3: Verify Environment Health
if [[ "$SKIP_DOCTOR" -eq 0 ]]; then
    log_step "3/5" "Verifying environment health via doctor..."
    if ! ./scripts/doctor.sh; then
        log_err "Doctor check failed. Please resolve the blockers above before running benchmarks."
        exit 1
    fi
else
    log_step "3/5" "Skipping doctor health check (--skip-doctor)."
fi

# Step 4: Verify Benchmark Ground Truth Integrity
log_step "4/5" "Verifying benchmark test definitions & specifications..."
PLANNER_CASES_PATH=""
if [[ -f "benchmarks/internal/planner_cases.json" && -s "benchmarks/internal/planner_cases.json" ]]; then
    PLANNER_CASES_PATH="benchmarks/internal/planner_cases.json"
elif [[ -f "benchmarks/planner_cases.json" && -s "benchmarks/planner_cases.json" ]]; then
    PLANNER_CASES_PATH="benchmarks/planner_cases.json"
fi

if [[ -z "$PLANNER_CASES_PATH" ]]; then
    log_err "Missing benchmark test cases: benchmarks/internal/planner_cases.json"
    exit 1
fi

REASONING_SPEC_PATH=""
if [[ -f "benchmarks/internal/REASONING.md" && -s "benchmarks/internal/REASONING.md" ]]; then
    REASONING_SPEC_PATH="benchmarks/internal/REASONING.md"
elif [[ -f "benchmarks/REASONING.md" && -s "benchmarks/REASONING.md" ]]; then
    REASONING_SPEC_PATH="benchmarks/REASONING.md"
fi

if [[ -z "$REASONING_SPEC_PATH" ]]; then
    log_err "Missing benchmark spec: benchmarks/internal/REASONING.md"
    exit 1
fi
log_ok "Benchmark definitions verified: $PLANNER_CASES_PATH & $REASONING_SPEC_PATH"

# Step 5: Record Benchmark Prep Metadata
log_step "5/5" "Recording benchmark preparation state..."
if [[ "$DRY_RUN" -eq 1 ]]; then
    log_info "[DRY-RUN] Would record metadata in .kagent/benchmark-prep.json"
else
    mkdir -p ".kagent"
    PYTHON_BIN="python3"
    if [[ -x "./venv-linux/bin/python3" ]]; then
        PYTHON_BIN="./venv-linux/bin/python3"
    fi

    "$PYTHON_BIN" - "$RESET_INTEL" "$PLANNER_CASES_PATH" << 'EOF'
import sys
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

reset_intel = sys.argv[1] == "1"
cases_file = sys.argv[2]

commit = "unknown"
dirty = False
try:
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain"], stderr=subprocess.DEVNULL, text=True).strip()
    dirty = bool(status)
except Exception:
    pass

cases_count = 0
cases_path = Path(cases_file)
if cases_path.exists():
    try:
        cases_count = len(json.loads(cases_path.read_text(encoding="utf-8")))
    except Exception:
        pass

metadata = {
    "prepared_at": datetime.now(timezone.utc).isoformat(),
    "git_commit": commit,
    "git_dirty": dirty,
    "intelligence_mode": "fresh" if reset_intel else "retained",
    "planner_cases_count": cases_count,
    "status": "ready"
}

out_path = Path(".kagent/benchmark-prep.json")
out_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
print(f"[INFO] Benchmark preparation record written to {out_path}")
EOF
fi

printf "\n\033[1;32m===================================================================\033[0m\n"
printf "\033[1;32m[READY] KAgent is prepared and verified for reproducible benchmark runs.\033[0m\n"
printf "\033[1;32m===================================================================\033[0m\n\n"

log_info "Suggested benchmark commands:"
log_info "  1. Planner Benchmark:"
log_info "     python -m benchmarks.internal.planner_benchmark"
log_info "  2. Reasoning Benchmark Export & Summary (see benchmarks/internal/REASONING.md):"
log_info "     python -m benchmarks.internal.reasoning_benchmark .kagent/reasoning-run-01.jsonl --run-id run-01"
printf "\n"
