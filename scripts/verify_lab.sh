#!/usr/bin/env bash
set -euo pipefail

echo "================================================================="
echo "           PRIV6GUARD IPv6 LAB VERIFICATION                     "
echo "================================================================="

echo -e "\n1. Active Network Namespaces:"
ip netns list | grep "p6g-" || echo "No p6g namespaces active."

echo -e "\n2. Bridge Interface Status (p6g-br0):"
ip link show p6g-br0 2>/dev/null || echo "Bridge p6g-br0 not active on host."

echo -e "\n3. Device Addresses and Routing Tables:"
for ns in p6g-router p6g-iot1 p6g-iot2 p6g-iot3 p6g-iot4 p6g-iot5 p6g-attacker; do
    if ip netns list | grep -q "\b$ns\b"; then
        echo "--- Namespace: $ns ---"
        ip -n "$ns" -6 addr show | grep -E "inet6 2001|inet6 fe80" || true
        echo "Routes:"
        ip -n "$ns" -6 route show || true
    fi
done

echo -e "\n4. Ping Connectivity Test (p6g-iot1 -> p6g-iot2):"
if ip netns list | grep -q "\bp6g-iot1\b"; then
    ip netns exec p6g-iot1 ping -6 -c 2 -W 2 2001:db8:6::12 || echo "Ping failed"
else
    echo "p6g-iot1 namespace not active."
fi

echo -e "\n5. ICMPv6 Packet Capture Guide:"
echo "To capture live ICMPv6 / NDP packets on the bridge in real time:"
echo "  sudo tcpdump -i p6g-br0 -vvv -n 'icmp6'"
echo "================================================================="
