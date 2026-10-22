#!/usr/bin/env bash
# Foreground official frontend; headless/execution/YOLO each require opt-in.
set -euo pipefail
task_repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
task_python="$task_repo_dir/venv-linux/bin/python"
if [[ ! -x "$task_python" ]]; then
  printf '%s\n' 'Configured venv-linux Python is unavailable; nothing was installed.' >&2
  exit 2
fi
task_mode=--dry-run
if (($#)); then
  case "$1" in
    --prepare) task_mode=--apply; shift ;;
    --run) task_mode=--launch; shift ;;
    --verify) task_mode=--verify; shift ;;
    --dry-run) shift ;;
    --help|-h)
      printf '%s\n' \
        'Dry-run (default, data isolation only): --dry-run --run-dir ABSOLUTE_NEW_PATH [--origin URL] [--prompt-file REVIEWED_UTF8_FILE]' \
        'Prepare only: --prepare --plan REVIEWED_JSON --approve-plan-sha256 HASH' \
        'Verify only: --verify PROFILE_JSON' \
        'Interactive official TUI: --run PROFILE_JSON [--max-steps N] [-- NATIVE_CLI_OPTIONS]' \
        'Headless: --run PROFILE_JSON --headless --execute-prompt [--interactive|--non-interactive]' \
        'YOLO and native HTTP grants follow the normal KAgent CLI rules; no grant or quota is injected.' \
        'Legacy limits: select --legacy-bounded at dry-run; old v2/v3 profiles keep their reviewed behavior.' \
        'Legacy shell preset: also select --prompt-file FILE --enable-headless-shell; repeat --enable-headless-shell on Headless run.' \
        'No existing data is deleted or reset. Preparation never starts KAgent.'
      exit 0 ;;
  esac
fi
task_headless=false
task_interactive=false
for task_arg in "$@"; do
  [[ "$task_arg" != --headless ]] || task_headless=true
  [[ "$task_arg" != --interactive ]] || task_interactive=true
done
if [[ "$task_mode" == --launch && ( "$task_headless" == false || "$task_interactive" == true ) && (! -t 0 || ! -t 1) ]]; then
  printf '%s\n' '--run requires the current interactive WSL terminal (TTY); no headless fallback.' >&2
  exit 2
fi
# The default profile only redirects data. Retain the reviewed 20-minute
# foreground lifetime exclusively for old bounded v2/v3 profiles.
if [[ "$task_mode" == --launch ]] && "$task_python" -B -c \
  'import json, sys; sys.exit(0 if json.load(open(sys.argv[1])).get("version") in (2, 3) else 1)' \
  "${1:-}" 2>/dev/null; then
  if ! command -v timeout >/dev/null 2>&1; then
    printf '%s\n' 'GNU timeout is unavailable; the approved wall limit cannot be applied.' >&2
    exit 2
  fi
  exec timeout --foreground --signal=INT 1200 \
    "$task_python" -B "$task_repo_dir/scripts/experiment_profile.py" "$task_mode" "$@"
fi
# exec preserves the foreground terminal, exit status and signal delivery.
exec "$task_python" -B "$task_repo_dir/scripts/experiment_profile.py" "$task_mode" "$@"
