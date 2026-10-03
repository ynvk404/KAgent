#!/usr/bin/env bash
# ==============================================================================
# scripts/archive-run.sh
# Safely preserves evidence and results from a specific KAgent run before cleanup.
#
# Archive destination:
#   artifacts/runs/<run-id>/
#
# What it archives:
#   - Session workflow state, candidates, and result summaries
#   - Linked evidence proof files (.kagent/evidence/...)
#   - Linked session observation journals (.kagent/observations/<id>.json)
#   - Linked session permissions (.kagent/permissions/<id>.json)
#   - Session coverage record (.kagent/coverage/<id>.json)
#   - Target-specific skill artifacts (artifacts/<skill>/<target>/...)
#   - Finding reports (artifacts/findings/...)
#   - Run metadata (timestamp, target, git commit, version, model)
#
# What it NEVER archives:
#   - API keys, credentials, or global provider config
#   - Durable intelligence (.kagent/intelligence)
#   - Durable memory (.kagent/memory)
#   - Unrelated sessions or evidence from other runs
#   - Historical audits/checkpoints (preserved separately)
# ==============================================================================
set -euo pipefail

if [[ ! -f "pyproject.toml" || ! -f "AGENTS.md" || ! -d "src" ]]; then
    printf "[ERROR] This script must be executed from the KAgent repository root.\n" >&2
    exit 1
fi

SESSION_ID=""
RUN_ID=""
DRY_RUN=0
LATEST=0

usage() {
    cat <<'EOF'
Usage: ./scripts/archive-run.sh [OPTIONS]

Archives run-specific state, evidence, and artifacts into artifacts/runs/<run-id>/.

Options:
  -s, --session-id <id>  Explicit session UUID to archive
  -r, --run-id <name>    Custom archive folder name (default: run-<session-id>)
  --latest               Auto-detect the most recent session
  -n, --dry-run          Show what files would be archived without copying
  -h, --help             Show this help message and exit
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--session-id)
            if [[ -z "${2:-}" ]]; then
                printf "[ERROR] --session-id requires a UUID argument.\n" >&2
                exit 1
            fi
            SESSION_ID="$2"
            shift 2
            ;;
        -r|--run-id)
            if [[ -z "${2:-}" ]]; then
                printf "[ERROR] --run-id requires an argument.\n" >&2
                exit 1
            fi
            RUN_ID="$2"
            shift 2
            ;;
        --latest)
            LATEST=1
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

# Resolve python binary
PYTHON_BIN="python3"
if [[ -x "./venv-linux/bin/python3" ]]; then
    PYTHON_BIN="./venv-linux/bin/python3"
fi

# Execute python archiver helper
"$PYTHON_BIN" - "$SESSION_ID" "$RUN_ID" "$DRY_RUN" "$LATEST" << 'EOF'
import sys
import os
import re
import json
import shutil
from pathlib import Path
from datetime import datetime, timezone
import subprocess

session_arg = sys.argv[1].strip()
run_arg = sys.argv[2].strip()
dry_run = sys.argv[3] == "1"
latest_flag = sys.argv[4] == "1"

repo_root = Path.cwd().resolve()
home_kagent = Path.home() / ".kagent"
local_kagent = repo_root / ".kagent"

def log_info(msg):
    print(f"[INFO] {msg}")

def log_action(msg):
    print(f"[ARCHIVE] {msg}")

def log_dry_run(msg):
    print(f"[DRY-RUN] Would archive: {msg}")

def log_error(msg):
    print(f"[ERROR] {msg}", file=sys.stderr)

# 1. Resolve session ID
session_id = session_arg
session_file_path = None

if not session_id:
    # Try to find latest session
    candidates = []
    # Search ~/.kagent/sessions and .kagent/sessions
    for sdir in [local_kagent / "sessions", home_kagent / "sessions"]:
        if sdir.exists():
            for f in sdir.glob("*.json"):
                if f.is_file() and not f.name.endswith(".tmp"):
                    try:
                        candidates.append((f.stat().st_mtime, f.stem, f))
                    except OSError:
                        pass
    # Also search .kagent/observations and .kagent/permissions for session IDs
    for odir in [local_kagent / "observations", local_kagent / "permissions"]:
        if odir.exists():
            for f in odir.glob("*.json"):
                if f.is_file():
                    try:
                        candidates.append((f.stat().st_mtime, f.stem, None))
                    except OSError:
                        pass

    if not candidates:
        log_error("No existing sessions or observation logs found to archive.")
        log_error("Specify --session-id <UUID> explicitly.")
        sys.exit(1)

    candidates.sort(key=lambda x: x[0], reverse=True)
    session_id = candidates[0][1]
    if candidates[0][2]:
        session_file_path = candidates[0][2]
    log_info(f"Auto-selected latest session: {session_id}")
else:
    # Validate session ID format (prevent path traversal, allow alphanumeric, dash, underscore)
    if not re.match(r"^[0-9a-zA-Z_-]+$", session_id) or ".." in session_id:
        log_error(f"Invalid session ID format: {session_id}")
        sys.exit(1)

# Find session file if not yet located
if not session_file_path:
    for sdir in [local_kagent / "sessions", home_kagent / "sessions"]:
        candidate = sdir / f"{session_id}.json"
        if candidate.exists():
            session_file_path = candidate
            break

run_id = run_arg or f"run-{session_id}"
archive_dir = repo_root / "artifacts" / "runs" / run_id

log_info(f"Target archive directory: artifacts/runs/{run_id}")

target_url = None
target_slug = None
evidence_paths = []
completed_artifacts = []

# Parse session file if available
if session_file_path and session_file_path.exists():
    try:
        data = json.loads(session_file_path.read_text(encoding="utf-8"))
        target_info = data.get("target") or {}
        target_url = target_info.get("baseURL") or target_info.get("declared_host") or ""
        if target_url:
            cleaned = re.sub(r"^https?://", "", target_url).lower()
            target_slug = re.sub(r"[^a-z0-9]+", "-", cleaned).strip("-")[:64]

        workflow = data.get("workflow") or {}
        for ev in workflow.get("evidence", []):
            if isinstance(ev, dict) and "path" in ev:
                evidence_paths.append(ev["path"])

        for k, v in workflow.get("completed_artifacts", {}).items():
            if isinstance(v, str):
                completed_artifacts.append(v)
    except Exception as e:
        log_info(f"Could not parse session details from {session_file_path}: {e}")

# Collect all files attributable to this run
files_to_archive = [] # list of (source_path, dest_rel_path)

# A. Session file
if session_file_path and session_file_path.exists():
    files_to_archive.append((session_file_path, Path("session") / f"{session_id}.json"))

# B. Coverage
cov_file = local_kagent / "coverage" / f"{session_id}.json"
if cov_file.exists():
    files_to_archive.append((cov_file, Path("coverage") / f"{session_id}.json"))

# C. Observations
obs_file = local_kagent / "observations" / f"{session_id}.json"
if obs_file.exists():
    files_to_archive.append((obs_file, Path("observations") / f"{session_id}.json"))

# D. Permissions
perm_file = local_kagent / "permissions" / f"{session_id}.json"
if perm_file.exists():
    files_to_archive.append((perm_file, Path("permissions") / f"{session_id}.json"))

# E. Context
for cdir in [local_kagent / "context", home_kagent / "context"]:
    ctx_file = cdir / f"{session_id}.md"
    if ctx_file.exists():
        files_to_archive.append((ctx_file, Path("context") / f"{session_id}.md"))
        break

# F. Evidence referenced in session
for ev_rel in set(evidence_paths):
    ev_full = repo_root / ev_rel
    if ev_full.exists() and ev_full.is_file():
        # Keep relative path under evidence/
        try:
            rel = ev_full.relative_to(local_kagent / "evidence")
            files_to_archive.append((ev_full, Path("evidence") / rel))
        except ValueError:
            files_to_archive.append((ev_full, Path("evidence") / ev_full.name))

# G. Target skill artifacts
if target_slug:
    artifacts_dir = repo_root / "artifacts"
    if artifacts_dir.exists():
        for skill_dir in artifacts_dir.iterdir():
            if skill_dir.is_dir() and skill_dir.name not in {"audits", "checkpoints", "runs"}:
                target_subdir = skill_dir / target_slug
                if target_subdir.exists() and target_subdir.is_dir():
                    for item in target_subdir.rglob("*"):
                        if item.is_file():
                            rel = item.relative_to(artifacts_dir)
                            files_to_archive.append((item, Path("artifacts") / rel))

# H. Findings created or completed artifacts
for comp in set(completed_artifacts):
    comp_path = repo_root / comp
    if comp_path.exists() and comp_path.is_file():
        try:
            rel = comp_path.relative_to(repo_root / "artifacts")
            files_to_archive.append((comp_path, Path("artifacts") / rel))
        except ValueError:
            pass

findings_dir = repo_root / "artifacts" / "findings"
if findings_dir.exists():
    for f in findings_dir.glob("*.md"):
        if f.is_file():
            files_to_archive.append((f, Path("findings") / f.name))

if not files_to_archive:
    log_error(f"No attributable files found for session {session_id}.")
    sys.exit(1)

# Deduplicate by destination path
seen_dests = set()
unique_files = []
for src, dest in files_to_archive:
    dest_str = str(dest)
    if dest_str not in seen_dests:
        seen_dests.add(dest_str)
        unique_files.append((src, dest))
files_to_archive = unique_files

log_info(f"Identified {len(files_to_archive)} attributable files for session {session_id}.")

# Git metadata
git_commit = "unknown"
git_dirty = False
try:
    git_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain"], stderr=subprocess.DEVNULL, text=True).strip()
    git_dirty = bool(status)
except Exception:
    pass

metadata = {
    "archived_at": datetime.now(timezone.utc).isoformat(),
    "session_id": session_id,
    "run_id": run_id,
    "target_url": target_url or "unknown",
    "target_slug": target_slug or "unknown",
    "git_commit": git_commit,
    "git_dirty": git_dirty,
    "archived_files_count": len(files_to_archive),
    "archived_files": [str(dest) for _, dest in files_to_archive],
}

if dry_run:
    log_info("DRY-RUN mode enabled. No files will be copied.")
    for src, dest in files_to_archive:
        log_dry_run(f"{src} -> artifacts/runs/{run_id}/{dest}")
    log_dry_run(f"metadata.json -> artifacts/runs/{run_id}/run-metadata.json")
    sys.exit(0)

# Perform archiving
archive_dir.mkdir(parents=True, exist_ok=True)
for src, dest in files_to_archive:
    target_path = archive_dir / dest
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, target_path)
    log_action(f"{src} -> {target_path}")

metadata_path = archive_dir / "run-metadata.json"
metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
log_action(f"Saved run metadata to {metadata_path}")

log_info(f"Run {run_id} successfully archived with {len(files_to_archive)} files.")
EOF
