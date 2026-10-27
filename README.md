# PRIV6GUARD
**Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation**

> **AIORI Hackathon 3 | Problem Statement: PS-007 | Team Code: A3-PS007-TC254**  
> **Official Demo & Presentation**: [Watch YouTube Video](https://youtu.be/BkqlxewUyNs) | [Solution Slide Deck (PDF)](./A3-PS007-TC254-PPT.pdf) | [Architecture Guide](./docs/ARCHITECTURE.md) | [Evaluation Report](./docs/EVALUATION_REPORT.md) | [Lab Runbook](./docs/LAB_RUNBOOK.md)

---

## Table of Contents
1. [Project Title](#1-project-title)
2. [Problem Statement](#2-problem-statement)
3. [Problem Understanding](#3-problem-understanding)
4. [Proposed Solution](#4-proposed-solution)
5. [Architecture Diagram](#5-architecture-diagram)
6. [Feature List](#6-feature-list)
7. [Technology Stack](#7-technology-stack)
8. [Prerequisites](#8-prerequisites)
9. [Installation Instructions](#9-installation-instructions)
10. [Backend Startup](#10-backend-startup)
11. [Frontend Startup](#11-frontend-startup)
12. [Lab Setup](#12-lab-setup)
13. [Lab Teardown](#13-lab-teardown)
14. [How to Run Each Experiment](#14-how-to-run-each-experiment)
15. [How to Run Tests](#15-how-to-run-tests)
16. [How to Export Evaluation Results](#16-how-to-export-evaluation-results)
17. [Security Considerations](#17-security-considerations)
18. [Privacy Design](#18-privacy-design)
19. [Limitations](#19-limitations)
20. [Team Roles](#20-team-roles)
21. [Screenshots & UI Showcase](#21-screenshots--ui-showcase)
22. [Reproducible Demo Sequence](#22-reproducible-demo-sequence)

---

## 1. Project Title
**PRIV6GUARD: Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation**  
*A privacy-preserving network intrusion detection system for dynamic IPv6 environments conforming to RFC 8981, RFC 4861, and RFC 6105.*

---

## 2. Problem Statement
**Hackathon Problem Statement**: PS-007 (IPv6 IoT Security and Privacy Monitoring).  
The proliferation of Internet of Things (IoT) devices operating on IPv6 networks creates a critical friction between network security monitoring and user privacy:
- In standard IPv6 deployments, devices adopting SLAAC (Stateless Address Autoconfiguration) with EUI-64 identifiers expose their permanent MAC addresses, allowing trivial long-term tracking and device profiling across subnets.
- To counter tracking, modern privacy standards (RFC 8981) rotate temporary interface identifiers at regular intervals.
- However, traditional Network Intrusion Detection Systems (NIDS) and Security Information and Event Management (SIEM) solutions rely on static IP addresses or persistent hardware identifiers to maintain state, correlate security events, and detect multi-stage attacks.
- Consequently, when IoT devices rotate their IPv6 addresses, legacy security monitors either fail completely (losing attack context) or bypass privacy safeguards by using invasive behavioral fingerprinting (TCP timestamps, TLS ciphers, clock skews) that recreates persistent tracking.

---

## 3. Problem Understanding
1. **The Privacy-Security Dilemma**: Security operators must know *if* a device is behaving maliciously or under attack, but have no legitimate need to link distinct historical sessions together into a permanent profile of user habits.
2. **Fragility of Legacy IDS**: In an RFC 8981 environment, a rogue gateway injecting malicious Router Advertisements (RAs) or a compromised device generating high-rate Neighbor Discovery Protocol (NDP) floods can evade attribution or cause false alerts against newly assigned legitimate addresses.
3. **Flaws in Behavioral Fingerprinting**: Invasive fingerprinting techniques (measuring inter-arrival packet jitters, TCP options, or device quirks) violate user consent and break privacy promises made by operating systems implementing RFC 8981.
4. **Tenant Isolation Needs**: Multi-tenant deployments (e.g., smart buildings, managed healthcare facilities) require strict cryptographic and database separation so that security events, device pseudonyms, and telemetry cannot leak across tenants.

---

## 4. Proposed Solution
**PRIV6GUARD** introduces a zero-fingerprint security architecture that decouples physical identity from security correlation:
- **Zero Behavioral Fingerprinting**: The monitoring stack never records or correlates packets using persistent hardware profiles, device quirks, or link-layer fingerprints.
- **Short-Lived Authorized Sessions & Blind Pseudonyms**: Devices authenticate once per session with pre-shared credentials to obtain a short-lived token ($TTL=300\text{s}$). During address rotation, a cryptographic HMAC pseudonym is issued and bound strictly to that session epoch.
- **Immediate Expiry Purge**: When a session expires, the mapping table purges all correlation keys. Outdated pseudonyms return `None`/401, rendering past and future activity unlinkable.
- **RFC 4861/6105 Trust-Policy RA Detector**: Validates gateway authenticity based on link-local identity and authorized prefix ownership, independent of transmission frequency.
- **Rolling-Window NDP Anomaly Detector**: Employs ring-buffered timestamp queues to detect message storms (Solicitations/Advertisements) with cooldown suppression, classifying anomalies as non-punitive indicators.
- **Strict Multi-Tenant Isolation**: Enforced at the FastAPI dependency layer (`X-Tenant-ID`) and SQLite parameterization level.

---

## 5. Architecture Diagram

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

*For complete Mermaid diagrams covering topology, data flow, lifecycles, and detection logic, see [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md).*

---

## 6. Feature List
- **Deterministic Virtual Lab**: 5 emulated IPv6 IoT nodes across multiple tenants (`tenant-alpha`, `tenant-beta`) in isolated Linux network namespaces.
- **RFC 8981 Address Rotation Engine**: Generates cryptographically secure, randomized interface identifiers with zero downtime.
- **Session-Bounded Cryptographic Pseudonymity**: Maps ephemeral IPv6 addresses to epoch pseudonyms valid only during an active session ($TTL=300\text{s}$).
- **Automatic Memory & Database Purge**: Periodically eliminates expired pseudonym mappings, preventing post-session correlation.
- **Rogue RA Trust Detector (RFC 4861/6105)**: Identifies unauthorized gateway link-locals and rogue prefix injections with sub-millisecond detection latency.
- **NDP Anomaly Detector**: Identifies high-rate NS/NA/RS floods via a 5.0-second rolling window with cooldown suppression.
- **Data Minimization Engine**: Drops raw L2 frame payloads immediately upon ingestion (`store=False`), storing only essential normalized header fields.
- **Multi-Tenant REST API**: Full tenant partitioning via `X-Tenant-ID` header injection.
- **Cyber Dashboard UI**: Real-time topology visualization, live event stream, interactive rotation controls, and Recharts metric graphs.
- **Dual Execution Modes**: Supports both rootless live lab mode and fixture-based demonstration mode with visible terminal labeling.

---

## 7. Technology Stack
| Layer | Technologies |
| :--- | :--- |
| **Backend Core** | Python 3.12+, FastAPI, Uvicorn, Pydantic v2, `pydantic-settings` |
| **Networking & Sniffing** | Scapy, Linux `iproute2`, Network Namespaces (`ip netns`), Linux Virtual Bridge (`p6g-br0`) |
| **Cryptography & Storage** | Python `secrets`, `cryptography` (HMAC-SHA256), `aiosqlite` (SQLite WAL mode) |
| **Frontend Dashboard** | React 18, TypeScript, Vite, Tailwind CSS, Lucide React, Recharts |
| **Test & Evaluation** | Pytest, `pytest-asyncio`, Vitest, HTTPX |

---

## 8. Prerequisites
- **Operating System**: Linux (Ubuntu 22.04 LTS or Debian 12 recommended) with kernel support for `ip netns` and bridge interfaces.
- **Python**: Version 3.10 or higher (Python 3.12+ recommended).
- **Node.js**: Version 18 or higher (Node.js v22 LTS tested).
- **Package Managers**: `pip` and `npm`.
- **System Utilities**: `iproute2`, `iptables`, `sudo` (required only for live network namespace creation).

---

## 9. Installation Instructions

### Step 1: Clone Repository
```bash
git clone https://github.com/aiori-hackathon/A3-PS007-TC254.git
cd A3-PS007-TC254
```

### Step 2: Set Up Python Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Install Frontend Dependencies
```bash
cd frontend
npm install
cd ..
```

### Step 4: Configure Environment Variables
```bash
cp .env.example .env
```

---

## 10. Backend Startup

To start the FastAPI backend service:
```bash
source .venv/bin/activate
uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload
```
- API Base URL: `http://127.0.0.1:8000`
- Interactive OpenAPI Docs: `http://127.0.0.1:8000/docs`
- Health Endpoint: `http://127.0.0.1:8000/api/health`

---

## 11. Frontend Startup

In a separate terminal:
```bash
cd frontend
npm run dev
```
- Dashboard URL: `http://localhost:5173`
- Default Tenant: `tenant-alpha` (switchable in header to `tenant-beta`)

---

## 12. Lab Setup

To provision the isolated virtual bridge, network namespaces, and 5 emulated IoT nodes:
```bash
sudo ./.venv/bin/python3 network/lab_setup.py
```
*Note: If unprivileged user namespaces are supported, rootless execution is available via `network/unprivileged_runner.py`.*

To verify the lab status:
```bash
./.venv/bin/python3 -c "from network.lab_status import check_lab_status; print(check_lab_status())"
```

---

## 13. Lab Teardown

To safely tear down all virtual interfaces, bridge, and namespaces using cryptographic manifest verification (`data/lab_manifest.json`):
```bash
sudo ./.venv/bin/python3 network/lab_teardown.py
```
*Guarantees zero residual interface leaks and never modifies host physical interfaces.*

---

## 14. How to Run Each Experiment

Priv6Guard includes an automated, empirical evaluation runner: `scripts/evaluate_prototype.py`.

To run all 7 structured empirical experiments:
```bash
./.venv/bin/python3 scripts/evaluate_prototype.py
```

### Individual Experiment Details:
1. **Experiment 1: Benign Baseline**
   - Transmits normal ICMPv6 telemetry across all 5 nodes.
   - Measures baseline NDP rate and verifies zero false alarms.
2. **Experiment 2: Rogue RA Policy Detection**
   - Injects legitimate gateway RAs (`fe80::1`) and rogue RAs (`fe80::dead:beef`, unauthorized prefix `2001:db8:baad::/64`).
   - Verifies 100% true-positive classification without frequency bias.
3. **Experiment 3: NDP Rate Anomaly Storms**
   - Injects high-rate Neighbor Solicitations (50 PPS) and tests borderline threshold rates (12 PPS).
   - Validates rolling-window detection and cooldown suppression.
4. **Experiment 4: Authorized RFC 8981 Address Rotation**
   - Authenticates session and rotates IPv6 address.
   - Verifies session continuity while ensuring no behavioral fingerprinting is performed.
5. **Experiment 5: Pseudonym Expiry & Purge**
   - Advances test clock past epoch TTL ($35\text{s} > 30\text{s}$) and runs memory purge.
   - Confirms subsequent lookup returns `None` (rejection).
6. **Experiment 6: Multi-Tenant Boundary Isolation**
   - Evaluates cross-tenant data requests between `tenant-alpha` and `tenant-beta`.
   - Confirms zero cross-tenant event, session, or device leakage.
7. **Experiment 7: Restart & State Recovery**
   - Simulates backend storage restart.
   - Confirms expired mappings remain permanently expired and cannot be resurrected.

---

## 15. How to Run Tests

### Run Full Pytest Suite (100 Tests)
```bash
./.venv/bin/pytest -v tests/
```
*Executes all 100 backend unit, security, integration, and failure handling tests in ~3.5 seconds.*

### Run Frontend Vitest Suite (9 Tests)
```bash
cd frontend && npm test -- --run && cd ..
```
*Executes all component and API client test suites.*

---

## 16. How to Export Evaluation Results

When running `scripts/evaluate_prototype.py`, structured machine-readable results are automatically exported to:
- **JSON**: `data/evaluation_results.json`
- **CSV**: `data/evaluation_results.csv`

To inspect the summary metrics directly from the CLI:
```bash
./.venv/bin/python3 -c "import json; data=json.load(open('data/evaluation_results.json')); print(json.dumps(data['summary_metrics'], indent=2))"
```

---

## 17. Security Considerations
- **Target Confinement**: Attack and experiment endpoints strictly enforce that target IPs and rogue sources belong to `2001:db8:6::/64` or `fe80::/10`, rejecting public or arbitrary addresses with HTTP 400.
- **Data Minimization**: Packet sniffer runs with `store=False`, capturing only essential ICMPv6 header metadata into `NormalizedEvent` and discarding raw link payloads immediately.
- **SQL Injection Prevention**: All database operations use parameterized queries (`aiosqlite`).
- **Secret Redaction**: Structured audit logger automatically redacts session tokens, bearer headers, and device secrets before writing to disk.
- **Fail-Safe Design**: Missing lab interfaces or temporary database locks cause endpoints to fail safely with informative HTTP errors rather than crashing worker threads.

---

## 18. Privacy Design
1. **Zero Link-Layer Correlation**: Device MAC addresses are discarded after L2 ingestion and are never stored in database tables.
2. **Ephemeral Identity**: Pseudonyms are derived via HMAC-SHA256 with an ephemeral key and are valid only for a short time epoch ($120\text{s}$).
3. **Session-Bounded Scope**: Continuous correlation across address rotation is permitted **only** when accompanied by an authorized session token ($TTL=300\text{s}$).
4. **Permanent Expiry**: When a session expires, its cryptographic mapping is purged from memory and database, guaranteeing past activity cannot be linked to future sessions.
5. **Strict Tenant Boundaries**: Enforced at the controller and SQL level via `tenant_id`.

---

## 19. Limitations
1. **Traffic Analysis Correlation**: Passive eavesdroppers observing packet volume and transmission intervals (e.g., fixed sensor heartbeats every 60 seconds) could statistically infer device continuity.
2. **Application-Layer Fingerprinting**: Upper-layer protocol payloads (HTTP headers, TLS ClientHellos) are deliberately uninspected to adhere to data minimization.
3. **Local Subnet Scope**: Privacy guarantees apply to the local L2/L3 IPv6 segment. Upstream ISP routing prefixes remain visible across wide-area networks.
4. **Evaluation Scale**: Empirical trials were executed in a controlled 5-node environment (18 benchmark trials). Enterprise multi-thousand device deployments require hardware-accelerated sniffing (e.g., DPDK/AF_XDP).

---

## 20. Team Roles
**AIORI Hackathon 3 | Team Code: A3-PS007-TC254**

| Member / Role | Focus Area & Responsibilities |
| :--- | :--- |
| **Lead Security Architect** | IPv6 Network Stack, Linux Virtual Bridge (`p6g-br0`), Network Namespaces, Scapy Packet Sniffer & Data Minimization. |
| **Cryptography & Privacy Specialist** | RFC 8981 Address Rotation, HMAC-SHA256 Blind Pseudonyms, Session Token Lifecycle, and TTL Purge Engine. |
| **Detection & Systems Engineer** | RFC 4861/6105 Rogue RA Trust Detector, Rolling-Window NDP Anomaly Counter, and SQLite WAL Persistence. |
| **Full-Stack & Integration Engineer** | FastAPI REST Services, Multi-Tenant Dependency Injection, React + TypeScript Dashboard, and Automated Test Harnesses. |

---

## 21. Screenshots & UI Showcase

The Priv6Guard web interface provides real-time situational awareness:
1. **Network Topology Map**: Interactive visual diagram showing the virtual bridge, gateway, 5 IoT devices, and the attacker node.
2. **Live Event Stream**: Real-time tabular feed showing incoming ICMPv6 telemetry and alert flags.
3. **Address Rotation Control**: Interactive trigger allowing judges to rotate any device's RFC 8981 address and inspect the updated pseudonym.
4. **Attack Simulation Panel**: Controlled execution buttons for injecting Rogue RAs and NDP storms.
5. **Evaluation Metrics**: Recharts visualizations for True Positive Rate, False Alarm Rate, and Average Latency.
6. **Multi-Tenant Switcher**: Immediate toggling between `tenant-alpha` and `tenant-beta` demonstrating zero cross-tenant leakage.

---

## 22. Reproducible Demo Sequence

Run the complete 14-step automated demonstration sequence required by Phase 9 Section E:
```bash
./.venv/bin/python3 scripts/run_demo.py --mode fixture
```
*(Use `--mode live` when the live backend is running on `http://127.0.0.1:8000`)*

### 14-Step Demo Breakdown:
1. **Step 1**: Start application and verify health.
2. **Step 2**: Inspect lab status and bridge topology.
3. **Step 3**: Display all 5 emulated IPv6 devices.
4. **Step 4**: Generate benign baseline telemetry.
5. **Step 5**: Perform authorized RFC 8981 address rotation.
6. **Step 6**: Validate permitted legitimate Router Advertisement.
7. **Step 7**: Inject controlled Rogue RA scenario.
8. **Step 8**: Retrieve resulting Rogue RA security alert.
9. **Step 9**: Inject controlled NDP anomaly burst scenario.
10. **Step 10**: Retrieve resulting NDP rate anomaly indicator alert.
11. **Step 11**: Run pseudonym epoch expiry and immediate purge verification.
12. **Step 12**: Demonstrate multi-tenant boundary isolation.
13. **Step 13**: Calculate live empirical evaluation metrics.
14. **Step 14**: Gracefully stop lab and sniffer workers.
