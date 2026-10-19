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
        'Dry-run (default): --dry-run --run-dir ABSOLUTE_NEW_PATH [--origin URL] [--prompt-file REVIEWED_UTF8_FILE]' \
        'Prepare only: --prepare --plan REVIEWED_JSON --approve-plan-sha256 HASH' \
        'Verify only: --verify PROFILE_JSON' \
        'Interactive official TUI: --run PROFILE_JSON [--max-steps 60]' \
        'Headless: --run PROFILE_JSON --headless --execute-prompt [--interactive|--non-interactive]' \
        'Bounded YOLO: add --yolo --accept-unknown-http-effects (never implicit)' \
        'Shell preset: dry-run with --prompt-file FILE --enable-headless-shell; repeat --enable-headless-shell on Headless run' \
        'Shell preset permits arbitrary commands in the existing worker; scanner traffic has no aggregate HTTP quota.' \
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
# Profiles use a 20-minute foreground lifetime starting at TUI open.
# INT uses KAgent's existing shutdown path; no forced KILL can drop evidence.
if [[ "$task_mode" == --launch ]]; then
  if ! command -v timeout >/dev/null 2>&1; then
    printf '%s\n' 'GNU timeout is unavailable; the approved wall limit cannot be applied.' >&2
    exit 2
  fi
  exec timeout --foreground --signal=INT 1200 \
    "$task_python" -B "$task_repo_dir/scripts/experiment_profile.py" "$task_mode" "$@"
fi
# exec preserves the foreground terminal, exit status and signal delivery.
exec "$task_python" -B "$task_repo_dir/scripts/experiment_profile.py" "$task_mode" "$@"
