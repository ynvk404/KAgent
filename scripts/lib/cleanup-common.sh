#!/usr/bin/env bash
# ==============================================================================
# scripts/lib/cleanup-common.sh
# Shared utility functions and path policies for KAgent reset scripts.
# ==============================================================================

# Common runtime state subdirectories under .kagent/
readonly KAGENT_RUNTIME_SUBDIRS=(
    "coverage"
    "evidence"
    "observations"
    "permissions"
    "sessions"
    "context"
)

# Known skill artifact subdirectories and runtime scratch under artifacts/
readonly ARTIFACT_RUNTIME_SUBDIRS=(
    "access-control"
    "authentication"
    "command-injection"
    "cors-misconfiguration"
    "cross-site-scripting"
    "csrf"
    "file-upload"
    "findings"
    "jwt-misconfiguration"
    "nosql-injection"
    "open-redirect"
    "path-traversal"
    "recon"
    "sql-injection"
    "ssrf"
    "ssti"
    "web-enumeration"
    "web-input-analysis"
    "worker"
    "xxe"
)

# Benchmark output patterns under .kagent/
readonly BENCHMARK_OUTPUT_PATTERNS=(
    "reasoning-*.jsonl"
    "*benchmark*.json"
    "*benchmark*.jsonl"
    "metrics*.jsonl"
)

# Strictly protected paths that MUST NEVER be deleted by runtime or benchmark reset
readonly STRICTLY_PROTECTED_PATHS=(
    "artifacts/audits"
    "artifacts/checkpoints"
    "benchmarks/internal/planner_cases.json"
    "benchmarks/internal/REASONING.md"
    "benchmarks/planner_cases.json"
    "benchmarks/REASONING.md"
    "benchmarks"
    "src"
    "skills"
    "tests"
    "docs"
    "assets"
    "Burp-integration"
    "AGENTS.md"
    "PROJECT.md"
    "pyproject.toml"
    "pytest.ini"
    "pyrightconfig.json"
    "requirements.txt"
    ".gitignore"
)

# Logging helpers
log_info() {
    printf "[INFO] %s\n" "$*"
}

log_action() {
    printf "[DELETE] %s\n" "$*"
}

log_dry_run() {
    printf "[DRY-RUN] Would delete: %s\n" "$*"
}

log_preserve() {
    printf "[PRESERVE] %s\n" "$*"
}

log_warn() {
    printf "[WARN] %s\n" "$*" >&2
}

log_error() {
    printf "[ERROR] %s\n" "$*" >&2
}

# Verify execution is strictly from the KAgent repository root
verify_repo_root() {
    local required_markers=("pyproject.toml" "AGENTS.md" "src/paths.py")
    for marker in "${required_markers[@]}"; do
        if [[ ! -e "$marker" ]]; then
            log_error "This script must be executed from the KAgent repository root."
            log_error "Missing required marker: $marker (current working directory: $PWD)"
            exit 1
        fi
    done
}

# Clear contents of a directory while preserving the directory itself
clear_directory_contents() {
    local rel_dir="$1"
    local dry_run="${2:-0}"

    if [[ ! -d "$rel_dir" ]]; then
        return 0
    fi

    # Check if directory has any contents
    if ! find "$rel_dir" -mindepth 1 -print -quit | grep -q .; then
        return 0
    fi

    if [[ "$dry_run" -eq 1 ]]; then
        while IFS= read -r -d '' item; do
            log_dry_run "$item"
        done < <(find "$rel_dir" -mindepth 1 -print0)
    else
        while IFS= read -r -d '' item; do
            log_action "$item"
        done < <(find "$rel_dir" -mindepth 1 -print0)
        find "$rel_dir" -mindepth 1 -delete
    fi
}

# Delete files matching a glob pattern within a directory
clear_glob_patterns() {
    local rel_dir="$1"
    local pattern="$2"
    local dry_run="${3:-0}"

    if [[ ! -d "$rel_dir" ]]; then
        return 0
    fi

    while IFS= read -r -d '' file; do
        if [[ "$dry_run" -eq 1 ]]; then
            log_dry_run "$file"
        else
            log_action "$file"
            rm -f "$file"
        fi
    done < <(find "$rel_dir" -maxdepth 1 -name "$pattern" -print0)
}

# Clear specific single file
clear_single_file() {
    local rel_path="$1"
    local dry_run="${2:-0}"

    if [[ ! -e "$rel_path" ]]; then
        return 0
    fi

    if [[ "$dry_run" -eq 1 ]]; then
        log_dry_run "$rel_path"
    else
        log_action "$rel_path"
        rm -f "$rel_path"
    fi
}

# Verify and report preservation of non-disposable directories in artifacts/
inspect_and_preserve_artifacts() {
    if [[ ! -d "artifacts" ]]; then
        return 0
    fi

    for entry in artifacts/*; do
        [[ -e "$entry" ]] || continue
        local base
        base="$(basename "$entry")"

        # Check if it's in the runtime whitelist
        local is_runtime=0
        for allowed in "${ARTIFACT_RUNTIME_SUBDIRS[@]}"; do
            if [[ "$base" == "$allowed" ]]; then
                is_runtime=1
                break
            fi
        done

        if [[ "$is_runtime" -eq 0 ]]; then
            log_preserve "$entry (protected or non-runtime artifact)"
        fi
    done
}

# Reset transient runtime state
reset_runtime_state() {
    local dry_run="${1:-0}"

    log_info "Clearing transient runtime state in .kagent/..."
    for subdir in "${KAGENT_RUNTIME_SUBDIRS[@]}"; do
        clear_directory_contents ".kagent/$subdir" "$dry_run"
    done

    # Clean dangling config temp files if any
    clear_glob_patterns "." ".kagent.cfg.tmp.*" "$dry_run"
    clear_glob_patterns ".kagent" ".kagent.cfg.tmp.*" "$dry_run"

    log_info "Clearing runtime skill artifacts in artifacts/..."
    for subdir in "${ARTIFACT_RUNTIME_SUBDIRS[@]}"; do
        clear_directory_contents "artifacts/$subdir" "$dry_run"
    done

    # Report preservation of protected artifact paths
    inspect_and_preserve_artifacts

    # Report preservation of durable stores
    if [[ -d ".kagent/intelligence" ]]; then
        log_preserve ".kagent/intelligence (durable scenario store)"
    fi
    if [[ -d ".kagent/memory" ]]; then
        log_preserve ".kagent/memory (durable memory store)"
    fi
    if [[ -f ".kagent/engagement.md" ]]; then
        log_preserve ".kagent/engagement.md (durable engagement notes)"
    fi
    if [[ -d ".kagent/skills" ]]; then
        log_preserve ".kagent/skills (project-local custom skills)"
    fi
}
