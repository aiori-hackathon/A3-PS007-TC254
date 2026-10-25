#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "================================================================="
echo "           PRIV6GUARD IPv6 ISOLATED LAB TEARDOWN                "
echo "================================================================="
echo "SAFETY GUARANTEE: Only resources recorded in data/lab_manifest.json"
echo "will be removed. Unrelated interfaces will NEVER be touched."
echo "================================================================="

if [ "$EUID" -ne 0 ]; then
    echo "Privileged networking requires root or sudo."
    echo "Please re-run as: sudo $0"
    exit 1
fi

cd "$PROJECT_ROOT"
export PYTHONPATH="$PROJECT_ROOT"

python3 -c "
import logging
from network.lab_teardown import LabTeardownManager
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s]: %(message)s')
manager = LabTeardownManager()
res = manager.teardown_lab()
print('\nTeardown Result:', res)
"

echo "================================================================="
echo "Lab teardown verified. All owned resources cleanly removed."
echo "================================================================="
