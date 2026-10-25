# PRIV6GUARD IPv6 Lab Runbook & Operational Guide

> **AIORI Hackathon 3** | **Problem Statement**: PS-007 | **Team Code**: A3-PS007-TC254  
> **Component**: Isolated IPv6 Lab Manager & Device Inventory (Phase 2)

---

## 1. Network Topology & Lab Design

The Priv6Guard lab instantiates a real Linux virtual network using a dedicated virtual bridge and isolated network namespaces.

```
                                  [ Linux Host ]
                                         |
                   +---------------------+---------------------+
                   |      Dedicated Bridge Interface:          |
                   |               p6g-br0                     |
                   |       Prefix: 2001:db8:6::/64             |
                   +---------------------+---------------------+
                                         |
     +---------------+---------------+---+-----------+---------------+---------------+
     |               |               |               |               |               |
+----v-----+    +----v-----+    +----v-----+    +----v-----+    +----v-----+    +----v-----+
| p6g-router |  | p6g-iot1 |    | p6g-iot2 |    | p6g-iot3 |    | p6g-iot4 |    | p6g-iot5 |
| Gateway    |  | Thermostat|   | Monitor  |    | Flowmeter|    | Camera   |    | Air Sensor
| ::1        |  | ::11     |    | ::12     |    | ::13     |    | ::14     |    | ::15     |
+------------+  +----------+    +----------+    +----------+    +----------+    +----------+
```

### Addressing Matrix (RFC 3849 Documentation Prefix)
| Node Identifier | Namespace | Role | Interface | IPv6 Address | Tenant | Base MAC |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `p6g-router` | `p6g-router` | Authorized Gateway | `p6g-peer0` | `2001:db8:6::1/64` | Infrastructure | `02:00:00:00:00:00` |
| `p6g-iot1` | `p6g-iot1` | Smart Thermostat | `p6g-peer1` | `2001:db8:6::11/64` | `tenant-alpha` | `02:00:00:00:00:11` |
| `p6g-iot2` | `p6g-iot2` | Medical Heart Monitor | `p6g-peer2` | `2001:db8:6::12/64` | `tenant-alpha` | `02:00:00:00:00:12` |
| `p6g-iot3` | `p6g-iot3` | Industrial Flowmeter | `p6g-peer3` | `2001:db8:6::13/64` | `tenant-alpha` | `02:00:00:00:00:13` |
| `p6g-iot4` | `p6g-iot4` | CCTV Video Streamer | `p6g-peer4` | `2001:db8:6::14/64` | `tenant-beta` | `02:00:00:00:00:14` |
| `p6g-iot5` | `p6g-iot5` | Environmental Air Sensor | `p6g-peer5` | `2001:db8:6::15/64` | `tenant-beta` | `02:00:00:00:00:15` |
| `p6g-attacker` | `p6g-attacker`| Controlled Rogue Node | `p6g-peer-atk`| `2001:db8:6::bad/64`| Simulation | `02:00:00:00:00:ee` |

---

## 2. Safety Invariants & Cryptographic Ownership

Priv6Guard implements strict safety barriers to prevent unintended host impact:
1. **No External Attack Traffic**: The lab network is contained on virtual bridge `p6g-br0`. Packet generation binds strictly to lab interfaces.
2. **Untouched Host Routing & Firewall**: The host default route, `iptables`, `nftables`, and `ufw` are never flushed, modified, or queried.
3. **Cryptographic Lab Manifest (`data/lab_manifest.json`)**:
   - Every resource created by `lab_setup` is recorded with PID, creation timestamp, and a SHA-256 integrity checksum.
   - Teardown explicitly validates the manifest and **refuses** to remove any interface or namespace that was not created and recorded by this application.
   - Deletion is never performed purely on a prefix match.
4. **Attack Pre-flight Barrier**:
   - `preflight_attack_check()` blocks any attack simulation from executing if the lab bridge is missing or degraded.

---

## 3. Step-by-Step Operator Procedures

### A. Privileged System Setup
To instantiate the real virtual network on Linux:
```bash
sudo ./scripts/setup_lab.sh
```

### B. Verification & Inspection Procedure
To inspect the running lab:
```bash
./scripts/verify_lab.sh
```

#### Manual Verification Commands:
1. **List all 5 IoT namespaces and router**:
   ```bash
   ip netns list | grep "p6g-"
   ```
2. **Inspect IPv6 addresses inside a namespace**:
   ```bash
   ip -n p6g-iot1 -6 addr show
   ```
3. **Inspect routing table**:
   ```bash
   ip -n p6g-iot1 -6 route show
   ```
4. **Verify inter-device connectivity (ICMPv6 ping across bridge)**:
   ```bash
   ip netns exec p6g-iot1 ping -6 -c 3 2001:db8:6::12
   ```
5. **Capture live ICMPv6 packets on the virtual bridge**:
   ```bash
   sudo tcpdump -i p6g-br0 -vvv -n 'icmp6'
   ```

### C. Teardown Procedure
To safely remove all created lab resources:
```bash
sudo ./scripts/teardown_lab.sh
```
The teardown manager verifies `data/lab_manifest.json`, deletes `p6g-iot1..5`, router, attacker, removes veth pairs, deletes `p6g-br0`, and clears the manifest file.

---

## 4. Rootless Testing Mode (User Namespaces)

For automated test runners or environments where root credentials are restricted, Priv6Guard includes an unprivileged runner (`network/unprivileged_runner.py`) leveraging Linux user namespaces:
```bash
unshare -m -n -U -r bash
```
This mode creates real Linux network namespaces and bridges inside a private user namespace session, executing complete IPv6 packet exchanges without requiring `sudo`.
```bash
pytest -v tests/test_lab_lifecycle_unprivileged.py
```
