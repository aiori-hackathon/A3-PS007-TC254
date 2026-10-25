#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "================================================================="
echo "           PRIV6GUARD IPv6 ISOLATED LAB SETUP                   "
echo "================================================================="
echo "This script creates:"
echo "  1. Dedicated Linux virtual bridge: p6g-br0 (IPv6: 2001:db8:6::/64)"
echo "  2. Five isolated IoT namespaces:   p6g-iot1..5"
echo "  3. Authorized gateway namespace:   p6g-router (2001:db8:6::1)"
echo "  4. Attacker namespace:             p6g-attacker (2001:db8:6::bad)"
echo "  5. Virtual ethernet pairs connecting all nodes to the bridge"
echo "================================================================="
echo "SAFETY GUARANTEE: Host routes, physical NICs, and firewalls"
echo "will NOT be altered. Only resources prefixed with p6g-* are used."
echo "================================================================="

if [ "$EUID" -ne 0 ]; then
    echo "Privileged networking requires root or sudo."
    echo "Please re-run as: sudo $0"
    exit 1
fi

cd "$PROJECT_ROOT"
export PYTHONPATH="$PROJECT_ROOT"

# Run lab setup module
python3 -c "
import logging
from network.lab_setup import LabSetupManager
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s]: %(message)s')
manager = LabSetupManager()
res = manager.setup_lab()
print('\nSetup Result:', res)
"

echo "================================================================="
echo "Lab successfully created and manifest recorded."
echo "Run './scripts/verify_lab.sh' to inspect namespaces and test pings."
echo "================================================================="
