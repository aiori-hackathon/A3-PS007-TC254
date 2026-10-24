# PRIV6GUARD
**Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation**

> **AIORI Hackathon 3**  
> **Problem Statement**: PS-007  
> **Team Code**: A3-PS007-TC254  

---

## 1. Project Overview

PRIV6GUARD is an IPv6 IoT security monitoring prototype engineered to demonstrate that local network anomaly detection and intrusion monitoring can remain highly effective while IoT devices rotate temporary IPv6 addresses (RFC 8981).

Traditional intrusion detection systems rely on permanent IPv6 interface identifiers (EUI-64) or static device tracking, which introduces significant user surveillance and tracking risks. PRIV6GUARD addresses this tradeoff by introducing **cryptographic, short-lived pseudonyms**, **time-bounded authorized sessions**, and **zero-fingerprint security correlation**, paired with high-fidelity detection of:
- **Unauthorized ICMPv6 Router Advertisements (Rogue RAs)**
- **Abnormal Neighbor Discovery Protocol (NDP) Message Rates**

---

## 2. Architecture & Design Principles

```
  +-------------------------------------------------------------------------+
  |                              PRIV6GUARD LAB                             |
  |                Dedicated Isolated Bridge: priv6-br0                     |
  |                         Prefix: fd00:cafe:1::/64                        |
  +-----------------------------------+-------------------------------------+
                                      |
       +------------------------------+------------------------------+
       |                              |                              |
+--------------+              +---------------+              +---------------+
|  Authorized  |              | 5 Emulated    |              | Attacker Node |
|  Gateway     |              | IoT Devices   |              | (Rogue RA &   |
|  (fe80::1)   |              | (SLAAC / ULA) |              |  NDP Storm)   |
+--------------+              +-------+-------+              +---------------+
                                      |
                          RFC 8981 Address Rotation
                                      |
                     +----------------v----------------+
                     |  Authentication & Session Layer |
                     |  - Short-lived Session Tokens   |
                     |  - Blind Epoch Pseudonyms       |
                     |  - Automatic TTL Purging        |
                     +----------------+----------------+
                                      |
          +---------------------------+---------------------------+
          |                                                       |
+---------v---------+                                   +---------v---------+
| RA Trust Detector |                                   | NDP Rate Detector |
| (RFC 4861/6105)   |                                   | (Rolling Window)  |
+---------+---------+                                   +---------+---------+
          |                                                       |
          +---------------------------+---------------------------+
                                      |
                     +----------------v----------------+
                     | Security Event & Metrics Engine |
                     | - Tenant-Isolated DB (SQLite)   |
                     | - Verified True/False Positives |
                     +----------------+----------------+
                                      |
                 +--------------------+--------------------+
                 |                                         |
     +-----------v-----------+                +------------v------------+
     | FastAPI Backend (REST)|                | React + TS + Tailwind UI |
     +-----------------------+                +-------------------------+
```

### Core Security & Privacy Invariants:
1. **Isolated Lab Topology**: Virtual bridge `priv6-br0` and network namespaces prevent any packet leakage to host physical interfaces.
2. **Zero Behavioral Fingerprinting**: No persistent hardware profiling, TCP/TLS fingerprinting, or MAC address retention past L2 frame processing.
3. **Session-Bounded Correlation**: Devices maintain monitoring continuity across address rotation *only* via explicit, authenticated, short-lived session tokens ($TTL = 300\text{s}$).
4. **Purged Expired Mappings**: Outdated pseudonym mappings are purged and rejected by the API layer.
5. **Backend-Enforced Multi-Tenancy**: Data queries strictly filter by `tenant_id` at the database level.

---

## 3. Emulated IoT Devices

| Device ID | Device Name | Device Type | Namespace | Tenant | Base Link-Local | Initial Global IPv6 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `dev-01` | Smart Thermostat | HVAC Controller | `priv6-ns-dev1` | `tenant-alpha` | `fe80::101` | `fd00:cafe:1::101` |
| `dev-02` | Medical Heart Monitor | Vital Sensor | `priv6-ns-dev2` | `tenant-alpha` | `fe80::102` | `fd00:cafe:1::102` |
| `dev-03` | Industrial Flowmeter | Telemetry Sensor | `priv6-ns-dev3` | `tenant-alpha` | `fe80::103` | `fd00:cafe:1::103` |
| `dev-04` | CCTV Security Streamer | Video Camera | `priv6-ns-dev4` | `tenant-beta` | `fe80::104` | `fd00:cafe:1::104` |
| `dev-05` | Environmental Air Sensor | Air Quality Monitor | `priv6-ns-dev5` | `tenant-beta` | `fe80::105` | `fd00:cafe:1::105` |

---

## 4. Phase Status & Progress

- [x] **Phase 0: Environment Bootstrapping & Configuration Foundations**
  - Bootstrapped Python 3.14 virtual environment with `fastapi`, `scapy`, `pydantic-settings`, `cryptography`, `aiosqlite`, `pytest`.
  - Installed Node.js v22 LTS and Git.
  - Implemented `config/lab_config.yaml`, `config/detection_rules.yaml`, `config/app_config.py`.
  - Implemented SQLite database layer and Pydantic domain models.
  - Verified 5/5 automated unit tests.
- [ ] **Phase 1: IPv6 Lab Manager & Safe Network Topology** (Next)
- [ ] **Phase 2: IoT Device Simulation, Traffic Generation & Address Rotation**
- [ ] **Phase 3: Privacy Layer (Authentication, Pseudonyms & Correlation)**
- [ ] **Phase 4: Packet Sniffing & IPv6 Security Detectors**
- [ ] **Phase 5: FastAPI Backend, Tenant Isolation & Attack Simulators**
- [ ] **Phase 6: React Dashboard & Visualization**
- [ ] **Phase 7: End-to-End Evaluation, Automated Test Suite & Demo**

---

## 5. Running the Automated Tests

Activate the virtual environment and run the test suite:
```bash
source .venv/bin/activate
pytest -v tests/
```
