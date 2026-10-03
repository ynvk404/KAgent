#!/usr/bin/env bash
# ==============================================================================
# scripts/doctor.sh
# Comprehensive, 100% read-only health check for the KAgent environment.
#
# Inspects:
#   - Python runtime & virtual environment
#   - KAgent core imports & version
#   - Required & optional Python dependencies
#   - Runtime path permissions (.kagent, artifacts)
#   - Config & LLM provider presence (strictly ZERO secrets displayed)
#   - Optional scanner tools (nmap, ffuf)
#   - Burp & MCP integrations
#   - Benchmark ground truth integrity
#
# Exit codes:
#   0: All critical checks passed (warnings may be present)
#   1: One or more fatal requirements failed
# ==============================================================================
set -euo pipefail

# Ensure execution from repository root
if [[ ! -f "pyproject.toml" || ! -f "AGENTS.md" || ! -d "src" ]]; then
    printf "[FAIL] This script must be executed from the KAgent repository root.\n" >&2
    exit 1
fi

USE_COLOR=1
if [[ ! -t 1 || "${NO_COLOR:-}" != "" ]]; then
    USE_COLOR=0
fi

color() {
    local code="$1"
    shift
    if [[ "$USE_COLOR" -eq 1 ]]; then
        printf "\033[%sm%s\033[0m\n" "$code" "$*"
    else
        printf "%s\n" "$*"
    fi
}

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

report_pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    color "32" "  [PASS] $*"
}

report_warn() {
    WARN_COUNT=$((WARN_COUNT + 1))
    color "33" "  [WARN] $*"
}

report_fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    color "31" "  [FAIL] $*"
}

report_info() {
    color "36" "==> $*"
}

usage() {
    cat <<'EOF'
Usage: ./scripts/doctor.sh [OPTIONS]

Performs a read-only diagnostic check of the KAgent environment.

Options:
  --no-color       Disable ANSI color output
  -h, --help       Show this help message and exit
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-color)
            USE_COLOR=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf "Unknown option: %s\n" "$1" >&2
            usage
            exit 1
            ;;
    esac
done

printf "\n"
color "1;34" "=== KAgent Environment Doctor ==="
printf "\n"

# ------------------------------------------------------------------------------
# 1. Platform & OS
# ------------------------------------------------------------------------------
report_info "Operating System & Platform"
OS_NAME="$(uname -s)"
KERNEL="$(uname -r)"
if [[ -f "/proc/version" ]] && grep -qi "microsoft" /proc/version; then
    report_pass "Platform: Linux ($OS_NAME $KERNEL) running under WSL"
else
    report_pass "Platform: Linux ($OS_NAME $KERNEL)"
fi

# ------------------------------------------------------------------------------
# 2. Python & Virtual Environment
# ------------------------------------------------------------------------------
report_info "Python Runtime & Virtual Environment"

PYTHON_BIN=""
if [[ -n "${VIRTUAL_ENV:-}" ]] && [[ -x "${VIRTUAL_ENV}/bin/python3" ]]; then
    PYTHON_BIN="${VIRTUAL_ENV}/bin/python3"
    report_pass "Active virtual environment: $VIRTUAL_ENV"
elif [[ -x "./venv-linux/bin/python3" ]]; then
    PYTHON_BIN="./venv-linux/bin/python3"
    report_pass "Found local virtual environment at ./venv-linux"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
    report_warn "No active venv detected; falling back to system python3 ($(command -v python3))"
else
    report_fail "No python3 executable found in PATH or ./venv-linux"
fi

if [[ -n "$PYTHON_BIN" ]]; then
    PY_VER="$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")' 2>/dev/null || echo "")"
    PY_MAJOR="$("$PYTHON_BIN" -c 'import sys; print(sys.version_info.major)' 2>/dev/null || echo "0")"
    PY_MINOR="$("$PYTHON_BIN" -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo "0")"

    if [[ "$PY_MAJOR" -ge 3 && "$PY_MINOR" -ge 11 ]]; then
        report_pass "Python version: $PY_VER (satisfies >= 3.11 requirement)"
    else
        report_fail "Python version: $PY_VER (requires Python >= 3.11)"
    fi
fi

# ------------------------------------------------------------------------------
# 3. KAgent Core Imports & Packaging
# ------------------------------------------------------------------------------
report_info "KAgent Core Import & Metadata"

if [[ -n "$PYTHON_BIN" ]]; then
    if "$PYTHON_BIN" -c "import src; from src.version.version import describe; print(describe())" >/dev/null 2>&1; then
        KAGENT_VER="$("$PYTHON_BIN" -c 'from src.version.version import describe; print(describe())')"
        report_pass "KAgent import successful: $KAGENT_VER"
    else
        report_fail "Unable to import KAgent core modules from src/"
    fi

    if "$PYTHON_BIN" -c "import src.cli.main" >/dev/null 2>&1; then
        report_pass "CLI entrypoint (src.cli.main) is importable"
    else
        report_fail "Failed to import src.cli.main"
    fi
fi

# ------------------------------------------------------------------------------
# 4. Dependencies Check
# ------------------------------------------------------------------------------
report_info "Python Dependencies"

check_python_module() {
    local mod="$1"
    local desc="$2"
    local required="${3:-1}"

    if [[ -n "$PYTHON_BIN" ]] && "$PYTHON_BIN" -c "import $mod" >/dev/null 2>&1; then
        report_pass "Module $desc ($mod) installed"
    else
        if [[ "$required" -eq 1 ]]; then
            report_fail "Required module $desc ($mod) is MISSING"
        else
            report_warn "Optional module $desc ($mod) is not installed"
        fi
    fi
}

# Required dependencies from pyproject.toml
check_python_module "httpx" "HTTPX client" 1
check_python_module "mcp" "Model Context Protocol SDK" 1
check_python_module "yaml" "PyYAML" 1
check_python_module "requests" "Requests HTTP library" 1
check_python_module "rich" "Rich terminal formatting" 1
check_python_module "textual" "Textual TUI framework" 1
check_python_module "watchdog" "Watchdog filesystem monitor" 1

# Optional dependencies [dev] & [enhanced]
check_python_module "pytest" "pytest testing framework [dev]" 0
check_python_module "frontmatter" "python-frontmatter [dev]" 0
check_python_module "filelock" "filelock concurrency [enhanced]" 0
check_python_module "pygments" "Pygments syntax highlighting [enhanced]" 0

# ------------------------------------------------------------------------------
# 5. Filesystem & Runtime Directories
# ------------------------------------------------------------------------------
report_info "Filesystem & Runtime Storage"

check_writable_dir() {
    local dir="$1"
    local desc="$2"
    if [[ -d "$dir" ]]; then
        if [[ -w "$dir" ]]; then
            report_pass "$desc ($dir) exists and is writable"
        else
            report_fail "$desc ($dir) exists but is NOT writable"
        fi
    else
        # Directory does not exist yet, check if parent is writable
        local parent
        parent="$(dirname "$dir")"
        if [[ -w "$parent" ]]; then
            report_pass "$desc ($dir) does not exist yet, but parent ($parent) is writable"
        else
            report_fail "Cannot create $desc ($dir): parent directory ($parent) is NOT writable"
        fi
    fi
}

check_writable_dir ".kagent" "Project runtime data root"
check_writable_dir "artifacts" "Artifacts storage root"

# ------------------------------------------------------------------------------
# 6. LLM Provider & Config Presence (Zero-secret check)
# ------------------------------------------------------------------------------
report_info "Configured Provider & Environment (No Secrets)"

CONFIG_FOUND=0
GLOBAL_CONFIG="${HOME}/.kagent/config.json"
LOCAL_CONFIG="./config.local.json"
ENV_CONFIG="${kagent_CONFIG:-}"

if [[ -n "$ENV_CONFIG" && -f "$ENV_CONFIG" ]]; then
    report_pass "Config file detected at \$kagent_CONFIG: $ENV_CONFIG"
    CONFIG_FOUND=1
elif [[ -f "$GLOBAL_CONFIG" ]]; then
    report_pass "Global config file detected at ~/.kagent/config.json"
    CONFIG_FOUND=1
elif [[ -f "$LOCAL_CONFIG" ]]; then
    report_pass "Local config file detected at ./config.local.json"
    CONFIG_FOUND=1
fi

KNOWN_PROVIDERS_FOUND=0
check_provider_env() {
    local var_name="$1"
    local provider_name="$2"
    if [[ -n "${!var_name:-}" ]]; then
        report_pass "Provider environment: $provider_name ($var_name is set)"
        KNOWN_PROVIDERS_FOUND=1
    fi
}

check_provider_env "GEMINI_API_KEY" "Google Gemini"
check_provider_env "OPENAI_API_KEY" "OpenAI"
check_provider_env "ANTHROPIC_API_KEY" "Anthropic Claude"
check_provider_env "DEEPSEEK_API_KEY" "DeepSeek"
check_provider_env "GROQ_API_KEY" "Groq"
check_provider_env "MOONSHOT_API_KEY" "Kimi Moonshot"
check_provider_env "OPENROUTER_API_KEY" "OpenRouter"

if [[ "$CONFIG_FOUND" -eq 0 && "$KNOWN_PROVIDERS_FOUND" -eq 0 ]]; then
    report_warn "No LLM provider configuration or API keys detected in environment/config"
fi

# ------------------------------------------------------------------------------
# 7. Optional External Tools
# ------------------------------------------------------------------------------
report_info "Optional External Security Scanners"

if command -v nmap >/dev/null 2>&1; then
    report_pass "Scanner: nmap found at $(command -v nmap)"
else
    report_warn "Scanner: nmap not found in PATH (optional, KAgent native tools remain active)"
fi

if command -v ffuf >/dev/null 2>&1; then
    report_pass "Scanner: ffuf found at $(command -v ffuf)"
else
    report_warn "Scanner: ffuf not found in PATH (optional, KAgent native tools remain active)"
fi

# ------------------------------------------------------------------------------
# 8. Benchmark Ground Truth & Definitions
# ------------------------------------------------------------------------------
report_info "Benchmark Integrity"

PLANNER_CASES_PATH=""
if [[ -f "benchmarks/internal/planner_cases.json" && -s "benchmarks/internal/planner_cases.json" ]]; then
    PLANNER_CASES_PATH="benchmarks/internal/planner_cases.json"
elif [[ -f "benchmarks/planner_cases.json" && -s "benchmarks/planner_cases.json" ]]; then
    PLANNER_CASES_PATH="benchmarks/planner_cases.json"
fi

if [[ -n "$PLANNER_CASES_PATH" ]]; then
    CASES_COUNT="$("$PYTHON_BIN" -c "import json; print(len(json.load(open('$PLANNER_CASES_PATH'))))" 2>/dev/null || echo "ok")"
    report_pass "Planner benchmark cases present: $PLANNER_CASES_PATH ($CASES_COUNT cases)"
else
    report_fail "Planner benchmark cases missing: benchmarks/internal/planner_cases.json"
fi

REASONING_SPEC_PATH=""
if [[ -f "benchmarks/internal/REASONING.md" && -s "benchmarks/internal/REASONING.md" ]]; then
    REASONING_SPEC_PATH="benchmarks/internal/REASONING.md"
elif [[ -f "benchmarks/REASONING.md" && -s "benchmarks/REASONING.md" ]]; then
    REASONING_SPEC_PATH="benchmarks/REASONING.md"
fi

if [[ -n "$REASONING_SPEC_PATH" ]]; then
    report_pass "Reasoning benchmark spec present: $REASONING_SPEC_PATH"
else
    report_fail "Reasoning benchmark spec missing: benchmarks/internal/REASONING.md"
fi

# ------------------------------------------------------------------------------
# Summary & Exit
# ------------------------------------------------------------------------------
printf "\n"
color "1;34" "=== Doctor Summary ==="
color "32" "  PASS: $PASS_COUNT"
if [[ "$WARN_COUNT" -gt 0 ]]; then
    color "33" "  WARN: $WARN_COUNT"
fi
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    color "31" "  FAIL: $FAIL_COUNT"
fi
printf "\n"

if [[ "$FAIL_COUNT" -eq 0 ]]; then
    color "1;32" "Result: KAgent environment is HEALTHY."
    exit 0
else
    color "1;31" "Result: KAgent environment has FATAL blockers (see FAIL items above)."
    exit 1
fi
