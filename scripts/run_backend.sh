#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== Starting PRIV6GUARD FastAPI Backend ==="
cd "$PROJECT_ROOT"

if [ ! -d ".venv" ]; then
    echo "Error: .venv not found. Please run environment setup first."
    exit 1
fi

export PATH="$HOME/.local/bin:$PROJECT_ROOT/.venv/bin:$PATH"
exec uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
