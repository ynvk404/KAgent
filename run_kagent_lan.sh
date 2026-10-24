#!/usr/bin/env bash
set -Eeuo pipefail

# Usage: bash run_kagent_lan.sh 15   (or 16, 17, ...)
LAN="${1:-}"
if [[ ! "$LAN" =~ ^[1-9][0-9]*$ ]]; then
  echo "Usage: bash $0 <run_number>  (e.g. 15, 16, 17)" >&2
  exit 2
fi

PROJECT_DIR="${KAGENT_DIR:-$HOME/kagent}"
cd "$PROJECT_DIR"

RUN_DIR="$PWD/experiments/scenario3/runs/lan-$LAN"
PROFILE_DIR="$PWD/experiments/scenario3/profiles/lan-$LAN"
PROFILE="$PROFILE_DIR/profile.json"
ORIGIN="${KAGENT_ORIGIN:-http://127.0.0.1:8081}"

# Never overwrite an existing experimental run or profile.
if [[ -e "$RUN_DIR" || -e "$PROFILE_DIR" ]]; then
  echo "ERROR: lan-$LAN already exists; refusing to overwrite." >&2
  exit 1
fi

TASK_PLAN="$(mktemp "/tmp/kagent-lan${LAN}-plan.XXXXXX.json")"
trap 'rm -f "$TASK_PLAN"' EXIT

echo "[1/4] Dry run for lan-$LAN"
bash scripts/run_experiment.sh --dry-run --run-dir "$RUN_DIR" --origin "$ORIGIN" > "$TASK_PLAN"

echo "[2/4] Review generated plan"
venv-linux/bin/python - "$TASK_PLAN" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    plan = json.load(f)
print(json.dumps({k: plan[k] for k in ("origin", "provider", "run", "profile")}, indent=2, ensure_ascii=False))
PY

PLAN_SHA="$(sha256sum "$TASK_PLAN" | cut -d ' ' -f 1)"

echo "[3/4] Prepare and verify"
bash scripts/run_experiment.sh --prepare --plan "$TASK_PLAN" --approve-plan-sha256 "$PLAN_SHA"
bash scripts/run_experiment.sh --verify "$PROFILE"

echo "[4/4] Start lan-$LAN"
bash scripts/run_experiment.sh --run "$PROFILE"
