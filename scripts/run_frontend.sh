#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== Starting PRIV6GUARD React Frontend ==="
cd "$PROJECT_ROOT/frontend"

export PATH="$HOME/.local/bin:$PATH"
exec npm run dev
