# PRIV6GUARD
**Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation**

> **AIORI Hackathon 3**  
> **Problem Statement**: PS-007  
> **Team Code**: A3-PS007-TC254  
> **Solution Video**: [Watch our YouTube Video Team Intro & Demo](https://youtu.be/BkqlxewUyNs)  

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
  |                Dedicated Isolated Bridge: p6g-br0                       |
  |                         Prefix: 2001:db8:6::/64                         |
  +-----------------------------------+-------------------------------------+
                                      |
       +------------------------------+------------------------------+
       |                              |                              |
+--------------+              +---------------+              +---------------+
|  Authorized  |              | 5 Emulated    |              | Attacker Node |
|  Gateway     |              | IoT Devices   |              | (Rogue RA &   |
| (p6g-router) |              | (p6g-iot1..5) |              |  NDP Storm)   |
| ::1          |              | ::11 - ::15   |              | ::bad         |
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
1. **Isolated Lab Topology**: Virtual bridge `p6g-br0` and network namespaces prevent any packet leakage to host physical interfaces.
2. **Zero Behavioral Fingerprinting**: No persistent hardware profiling, TCP/TLS fingerprinting, or MAC address retention past L2 frame processing.
3. **Session-Bounded Correlation**: Devices maintain monitoring continuity across address rotation *only* via explicit, authenticated, short-lived session tokens ($TTL = 300\text{s}$).
4. **Purged Expired Mappings**: Outdated pseudonym mappings are purged and rejected by the API layer.
5. **Backend-Enforced Multi-Tenancy**: Data queries strictly filter by `tenant_id` at the database level.
6. **Cryptographic Manifest Verification**: Teardown only removes resources explicitly recorded in `data/lab_manifest.json` and verified with a SHA-256 integrity checksum.
7. **Explicit Router Trust Policy**: Rogue classification evaluates gateway link-local identity and prefix ownership; routers are never classified as rogue purely because of advertisement frequency.
8. **Anomaly Indicator Classification**: High NDP message rates are flagged as anomaly indicators rather than definitive proof of malice.

---

## 3. Emulated IoT Devices

| Device ID | Device Name | Device Type | Namespace | Tenant | Base Link-Local | Assigned Global IPv6 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `p6g-iot1` | Smart Thermostat | HVAC Controller | `p6g-iot1` | `tenant-alpha` | `fe80::11` | `2001:db8:6::11` |
| `p6g-iot2` | Medical Heart Monitor | Vital Sensor | `p6g-iot2` | `tenant-alpha` | `fe80::12` | `2001:db8:6::12` |
| `p6g-iot3` | Industrial Flowmeter | Telemetry Sensor | `p6g-iot3` | `tenant-alpha` | `fe80::13` | `2001:db8:6::13` |
| `p6g-iot4` | CCTV Security Streamer | Video Camera | `p6g-iot4` | `tenant-beta` | `fe80::14` | `2001:db8:6::14` |
| `p6g-iot5` | Environmental Air Sensor | Air Quality Monitor | `p6g-iot5` | `tenant-beta` | `fe80::15` | `2001:db8:6::15` |

---

## 4. Phase Status & Progress

- [x] **Phase 0: Environment Bootstrapping & Configuration Foundations**
  - Bootstrapped Python 3.14 virtual environment with `fastapi`, `scapy`, `pydantic-settings`, `cryptography`, `aiosqlite`, `pytest`.
  - Installed Node.js v22 LTS and Git.
  - Implemented `config/lab_config.yaml`, `config/detection_rules.yaml`, `config/app_config.py`.
  - Implemented SQLite database layer and Pydantic domain models.
- [x] **Phase 1: Project Scaffolding & Environment Validation**
  - Implemented FastAPI application entrypoint with `/api/health` endpoint.
  - Implemented structured logging with sensitive token/key redaction.
  - Built React + TypeScript + Vite dashboard with Tailwind CSS cyber theme.
  - Validated 7/7 backend unit tests and 0-error TypeScript build.
- [x] **Phase 2: Isolated IPv6 Lab with Five Emulated Devices**
  - Implemented typed lab configuration with `2001:db8:6::/64` documentation prefix.
  - Implemented `network/lab_setup.py` with conflict detection, rollback, and interface provisioning.
  - Implemented `network/lab_teardown.py` with cryptographic manifest verification (`data/lab_manifest.json`).
  - Implemented `network/device_inventory.py` and `network/lab_status.py` with attack pre-flight checks.
  - Implemented `network/unprivileged_runner.py` for rootless user namespace execution.
  - Documented full operational runbook in `docs/LAB_RUNBOOK.md`.
- [x] **Phase 3: Normal Traffic, Address Rotation and Session-Scoped Pseudonyms**
  - Implemented `network/traffic_simulator.py` (benign telemetry generator with start/stop/status).
  - Implemented `network/address_rotator.py` (RFC 8981 address rotation with safe transition policy).
  - Implemented `security/auth_manager.py` (authenticated sessions, rate limiting, controllable clock).
  - Implemented `security/pseudonym_manager.py` (cryptographic random pseudonyms, expiry purge).
  - Implemented `security/correlation_engine.py` (authorized session correlation, zero fingerprinting).
  - Implemented `security/audit_logger.py` (data minimization, credential redaction).
- [x] **Phase 4: Packet Sniffing & IPv6 Security Detectors**
  - Implemented `security/ra_detector.py` enforcing RFC 4861/6105 trust policies with frequency invariance.
  - Implemented `security/ndp_detector.py` rolling-window anomaly rate counter with cooldown suppression.
  - Implemented `security/event_manager.py` for structured alert dispatch and pseudonym correlation.
  - Implemented `network/packet_capture.py` Scapy bridge packet listener with data minimization.
- [x] **Phase 5: Evaluation & Metrics Engine + REST API Integration**
  - Implemented REST API routers: `/api/lab`, `/api/devices`, `/api/events`, `/api/metrics`, `/api/attacks`.
  - Implemented strict backend multi-tenant isolation via `X-Tenant-ID` dependency injection.
  - Implemented controlled attack simulation endpoints with pre-flight check enforcement.
  - Validated 48/48 automated tests across all phases.
- [x] **Phase 6: Full Dashboard Integration & Visualization**
  - Integrated React 18 + TypeScript + Vite + Tailwind CSS frontend dashboard.
  - Implemented multi-tenant switcher (`tenant-alpha` vs `tenant-beta`) with instant state isolation.
  - Built interactive network topology diagram showing bridge, gateway, 5 IoT devices, and attacker node.
  - Built real-time device rotation control cards with live RFC 8981 address rotation button.
  - Built attack simulation control panel for one-click Rogue RA and NDP storm triggers.
  - Added empirical evaluation charts with Recharts (AreaChart latency, BarChart TPR/FPR).
- [x] **Phase 7: End-to-End Evaluation & Reproducible Demonstration**
  - Implemented `scripts/run_demo.py` for reproducible 9-step CLI evaluation.
  - Created `tests/test_end_to_end_acceptance.py` formally verifying all 13 Section 7 criteria.
  - Generated comprehensive empirical evaluation report in `docs/EVALUATION_REPORT.md`.
  - Validated 61/61 automated tests with 100% pass rate.

---

## 5. API Reference

| Endpoint | Method | Description | Tenant Isolated |
| :--- | :--- | :--- | :--- |
| `/api/health` | GET | Operational health and version | Public |
| `/api/lab/status` | GET | Status of virtual bridge & namespaces | Public |
| `/api/lab/start` | POST | Start virtual bridge monitoring & sniffer | Protected |
| `/api/lab/stop` | POST | Stop packet sniffer gracefully | Protected |
| `/api/devices` | GET | List 5 emulated devices with active pseudonyms | **Yes** (`X-Tenant-ID`) |
| `/api/devices/{id}/authenticate` | POST | Authenticate device and issue session token | **Yes** (`X-Tenant-ID`) |
| `/api/devices/{id}/rotate` | POST | Rotate IPv6 address and issue fresh pseudonym | **Yes** (`X-Tenant-ID`) |
| `/api/sessions` | GET | List active sessions and remaining TTLs | **Yes** (`X-Tenant-ID`) |
| `/api/events` | GET | Chronological security events (`ROGUE_RA`, `NDP_RATE_ANOMALY`) | **Yes** (`X-Tenant-ID`) |
| `/api/alerts` | GET | Normalized alert structures with filters | **Yes** (`X-Tenant-ID`) |
| `/api/metrics` | GET | Live evaluation metrics (detection rates, privacy index) | Global |
| `/api/experiments/normal` | POST | Run benign baseline telemetry scenario | Guarded |
| `/api/experiments/rogue-ra` | POST | Controlled Rogue RA injection experiment | Guarded |
| `/api/experiments/ndp-burst` | POST | Controlled NDP message storm experiment | Guarded |
| `/api/experiments/stop` | POST | Stop running experiment | Public |
| `/api/experiments` | GET | List recorded experiment trial records | Global |

---

## 6. Verification & Reproducibility Guide

### 6.1 Run All 69 Automated Tests
```bash
./.venv/bin/pytest -v tests/
```
*Executes all 69 unit, integration, and security tests in ~4.0 seconds.*

### 6.2 Run 13-Criteria Acceptance Test
```bash
./.venv/bin/pytest -v tests/test_end_to_end_acceptance.py
```
*Formally validates all 13 criteria from Section 7 of the problem statement.*

### 6.3 Run Live Demonstration Script
```bash
python3 scripts/run_demo.py
```
*Walks through the entire 9-step demonstration from health checks to empirical metrics.*

### 6.4 Documentation Links
- [Laboratory Runbook](docs/LAB_RUNBOOK.md)
- [Comprehensive Empirical Evaluation Report](docs/EVALUATION_REPORT.md)


