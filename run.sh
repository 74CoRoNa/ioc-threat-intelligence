#!/usr/bin/env bash
#
# Launch the IOC Threat Intelligence Analyzer on macOS or Linux.
#
# The script is self-bootstrapping: it locates a suitable Python interpreter,
# creates or repairs the virtual environment, installs dependencies, and then
# serves the application. It is intended to work on a computer that has never
# run this project before.

set -euo pipefail

PORT=8000
OPEN_BROWSER=1
RELOAD=0
RECREATE=0

while [ $# -gt 0 ]; do
    case "$1" in
        -p|--port) PORT="$2"; shift 2 ;;
        --no-browser) OPEN_BROWSER=0; shift ;;
        --reload) RELOAD=1; shift ;;
        --recreate) RECREATE=1; shift ;;
        -h|--help)
            echo "Usage: ./run.sh [--port 8000] [--no-browser] [--reload] [--recreate]"
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$PROJECT_ROOT/backend"
VENV="$PROJECT_ROOT/.venv"
VENV_PYTHON="$VENV/bin/python"
REQUIREMENTS="$BACKEND/requirements.txt"
URL="http://127.0.0.1:$PORT"
LOG_PATH="$PROJECT_ROOT/server.log"

step() { printf '  \033[90m%s\033[0m\n' "$1"; }
fail() { printf '\n\033[31m%s\033[0m\n\n' "$1" >&2; exit 1; }

find_base_python() {
    local candidate version
    for candidate in python3.13 python3.12 python3.11 python3.10 python3 python; do
        command -v "$candidate" >/dev/null 2>&1 || continue
        version="$("$candidate" -c 'import sys; print("%d%02d" % sys.version_info[:2])' 2>/dev/null || echo 0)"
        if [ "$version" -ge 310 ] 2>/dev/null; then
            command -v "$candidate"
            return 0
        fi
    done
    return 1
}

venv_healthy() {
    [ -x "$VENV_PYTHON" ] && "$VENV_PYTHON" -c 'import sys' >/dev/null 2>&1
}

dependencies_installed() {
    "$VENV_PYTHON" -c 'import fastapi, uvicorn, httpx, sqlalchemy, dns, pydantic_settings' >/dev/null 2>&1
}

open_browser() {
    if [ "$OPEN_BROWSER" -eq 0 ]; then return; fi
    if command -v open >/dev/null 2>&1; then open "$URL" >/dev/null 2>&1 || true
    elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1 || true
    fi
}

is_ready() {
    curl -fsS --max-time 1 "$URL/api/health" 2>/dev/null | grep -q '"status":"ok"'
}

printf '\n\033[36mIOC Threat Intelligence\033[0m\n'

[ -f "$REQUIREMENTS" ] || fail "This script must stay inside the project folder; backend/requirements.txt was not found."

if [ ! -f "$PROJECT_ROOT/.env" ]; then
    cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
    step "Created .env from .env.example. Add provider API keys there."
fi

if [ "$RECREATE" -eq 1 ] && [ -d "$VENV" ]; then
    step "Removing the existing environment as requested."
    rm -rf "$VENV"
fi

# A virtual environment stores an absolute path to the interpreter that built
# it. If that interpreter moved, or the project folder came from another
# computer, the environment exists on disk but cannot run.
if ! venv_healthy; then
    if [ -d "$VENV" ]; then
        step "The existing environment cannot run on this computer; rebuilding it."
        rm -rf "$VENV"
    fi
    BASE_PYTHON="$(find_base_python)" || fail "No suitable Python interpreter was found on this computer.

Install Python 3.10 or newer:
  macOS         brew install python@3.12
  Debian/Ubuntu sudo apt install python3 python3-venv
  Fedora        sudo dnf install python3

Then run this script again."
    step "Using $("$BASE_PYTHON" --version 2>&1) at $BASE_PYTHON"
    step "Creating the virtual environment (first run only)..."
    "$BASE_PYTHON" -m venv "$VENV" || fail "The virtual environment could not be created.
On Debian or Ubuntu this usually means python3-venv is missing:
  sudo apt install python3-venv"
    venv_healthy || fail "The virtual environment was created but cannot run."
fi

if ! dependencies_installed; then
    step "Installing dependencies (first run only; this may take a minute)..."
    "$VENV_PYTHON" -m pip install --upgrade pip --quiet --disable-pip-version-check
    "$VENV_PYTHON" -m pip install -r "$REQUIREMENTS" --quiet --disable-pip-version-check
    dependencies_installed || fail "Dependencies could not be installed.
Check that this computer has internet access, then run the script again."
fi

if is_ready; then
    printf '  \033[32mAlready running at %s\033[0m\n' "$URL"
    open_browser
    exit 0
fi

ARGS=(-m uvicorn app.main:app --host 127.0.0.1 --port "$PORT")
[ "$RELOAD" -eq 1 ] && ARGS+=(--reload)

step "Starting the server on $URL ..."
cd "$BACKEND"
"$VENV_PYTHON" "${ARGS[@]}" 2>"$LOG_PATH" &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT INT TERM

for _ in $(seq 1 100); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        fail "The backend stopped during startup.

$(tail -n 15 "$LOG_PATH" 2>/dev/null || echo 'no output captured')"
    fi
    if is_ready; then
        printf '\n  \033[32mRunning at %s\033[0m\n\n' "$URL"
        open_browser
        printf '  \033[90mPress Ctrl+C to stop.\033[0m\n'
        wait "$SERVER_PID"
        exit 0
    fi
    sleep 0.2
done

fail "The application did not become ready in time. See $LOG_PATH"
