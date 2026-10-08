#!/usr/bin/env bash
# ==============================================================================
# scripts/setup.sh
# Bootstrap and configure the KAgent development and runtime environment.
#
# Supported modes:
#   --minimal       (Default) Installs core runtime dependencies from pyproject.toml
#   --dev           Installs development and enhancement dependencies [dev,enhanced]
#   --check-only    Read-only check if environment is set up (does not mutate anything)
#   --with-tools    Checks optional external security scanners (nmap, ffuf)
# ==============================================================================
set -euo pipefail

if [[ ! -f "pyproject.toml" || ! -f "AGENTS.md" || ! -d "src" ]]; then
    printf "[ERROR] This script must be executed from the KAgent repository root.\n" >&2
    exit 1
fi

VENV_DIR="./venv-linux"
MODE="minimal"
CHECK_ONLY=0
CHECK_TOOLS=0

usage() {
    cat <<'EOF'
Usage: ./scripts/setup.sh [OPTIONS]

Bootstraps the KAgent Python environment and required runtime directories.

Options:
  --minimal          Install core runtime dependencies (default)
  --dev              Install development and test dependencies (pytest, frontmatter, etc.)
  --check-only       Read-only check of setup requirements without making any changes
  --with-tools       Check status of optional external tools (nmap, ffuf)
  --venv-path <dir>  Path to virtual environment (default: ./venv-linux)
  -h, --help         Show this help message and exit

Safety:
  - Preserves existing configuration and secrets
  - Does not execute sudo commands automatically
  - Does not alter system, WSL, or firewall configurations
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --minimal)
            MODE="minimal"
            shift
            ;;
        --dev)
            MODE="dev"
            shift
            ;;
        --check-only)
            CHECK_ONLY=1
            shift
            ;;
        --with-tools)
            CHECK_TOOLS=1
            shift
            ;;
        --venv-path)
            if [[ -z "${2:-}" ]]; then
                printf "[ERROR] --venv-path requires a directory argument.\n" >&2
                exit 1
            fi
            VENV_DIR="$2"
            shift 2
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

log_info() { printf "[INFO] %s\n" "$*"; }
log_ok()   { printf "[OK] %s\n" "$*"; }
log_warn() { printf "[WARN] %s\n" "$*" >&2; }
log_err()  { printf "[ERROR] %s\n" "$*" >&2; }

# A check uses the selected virtualenv; it does not require system Python.
if [[ "$CHECK_ONLY" -eq 1 ]]; then
    if [[ ! -x "$VENV_DIR/bin/python" ]]; then
        log_err "Virtual environment at '$VENV_DIR' does not exist."
        exit 1
    fi
    "$VENV_DIR/bin/python" -B - <<'PYTHON'
import importlib
import sys

if sys.version_info < (3, 11):
    print("[ERROR] KAgent requires Python >= 3.11.", file=sys.stderr)
    raise SystemExit(1)
print(f"[OK] Python {sys.version.split()[0]} in selected virtual environment.")
failed = False
for module in ("httpx", "mcp", "yaml", "requests", "reportlab", "rich", "textual", "watchdog", "src.cli.main"):
    try:
        importlib.import_module(module)
    except Exception:
        print(f"[ERROR] Cannot import required module: {module}", file=sys.stderr)
        failed = True
if failed:
    raise SystemExit(1)
print("[OK] Required dependencies and CLI entrypoint are importable.")
PYTHON
    if [[ "$CHECK_TOOLS" -eq 1 ]]; then
        command -v nmap >/dev/null 2>&1 && log_ok "Scanner: nmap found" || log_warn "Scanner: nmap not found (optional)"
        command -v ffuf >/dev/null 2>&1 && log_ok "Scanner: ffuf found" || log_warn "Scanner: ffuf not found (optional)"
    fi
    log_ok "Setup check passed."
    exit 0
fi

# Installation needs system Python to create the virtualenv.
SYSTEM_PYTHON=""
if command -v python3 >/dev/null 2>&1; then
    SYSTEM_PYTHON="python3"
elif command -v python >/dev/null 2>&1; then
    SYSTEM_PYTHON="python"
fi
if [[ -z "$SYSTEM_PYTHON" ]] || ! "$SYSTEM_PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
    log_err "Please install Python 3.11 or newer with venv support."
    exit 1
fi

# Not check-only: perform setup
if [[ ! -d "$VENV_DIR" ]]; then
    log_info "Creating virtual environment at '$VENV_DIR'..."
    "$SYSTEM_PYTHON" -m venv "$VENV_DIR"
    log_ok "Virtual environment created at '$VENV_DIR'."
else
    log_ok "Virtual environment already exists at '$VENV_DIR'."
fi

VENV_PIP="$VENV_DIR/bin/pip"
VENV_PY="$VENV_DIR/bin/python"

if [[ ! -x "$VENV_PIP" || ! -x "$VENV_PY" ]]; then
    log_err "Virtual environment is corrupted or missing pip/python binaries."
    exit 1
fi

# 3. Install project dependencies
log_info "Installing KAgent dependencies in '$MODE' mode..."
if [[ "$MODE" == "dev" ]]; then
    "$VENV_PIP" install -e ".[dev,enhanced]"
else
    "$VENV_PIP" install -e "."
fi
log_ok "Dependencies installed successfully."

# 4. Create expected runtime directory structure
log_info "Ensuring runtime directory structure exists..."
mkdir -p ".kagent/coverage" ".kagent/evidence" ".kagent/observations" ".kagent/permissions"
chmod 700 ".kagent/coverage" ".kagent/evidence" ".kagent/observations" ".kagent/permissions" 2>/dev/null || true
mkdir -p "artifacts"
chmod 755 "artifacts" 2>/dev/null || true
log_ok "Runtime directory structure verified."

# 5. Sanity check CLI
log_info "Running sanity check..."
if "$VENV_PY" -m src.cli.main --help >/dev/null 2>&1; then
    log_ok "Sanity check passed: 'python -m src.cli.main --help' succeeded."
else
    log_warn "Sanity check returned non-zero. Check your environment with ./scripts/doctor.sh."
fi

# 6. Optional tools advisory
if [[ "$CHECK_TOOLS" -eq 1 ]]; then
    log_info "Checking optional external security scanners..."
    if command -v nmap >/dev/null 2>&1; then
        log_ok "nmap found at $(command -v nmap)"
    else
        log_warn "nmap not found. You can install it with: sudo apt install nmap"
    fi
    if command -v ffuf >/dev/null 2>&1; then
        log_ok "ffuf found at $(command -v ffuf)"
    else
        log_warn "ffuf not found. You can install it with: sudo apt install ffuf (or via Go)"
    fi
fi

log_ok "Setup completed successfully."
log_info "Activate your environment with: source $VENV_DIR/bin/activate"
