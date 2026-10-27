# PRIV6GUARD Source Directory

The PRIV6GUARD codebase is organized into modular top-level packages:

- **`backend/`**: FastAPI REST API service, SQLite persistence, SSE live alerts stream, and experiment management.
- **`frontend/`**: Vite + React + Tailwind CSS dark cybersecurity dashboard with real-time SSE event consumption.
- **`security/`**: Rogue RA detector, NDP flood/spoof detector, blind pseudonym manager, session authorization, and cross-rotation correlation boundary.
- **`network/`**: Isolated bridge setup (`p6g-br0`), unprivileged network namespaces, address rotation simulation, Scapy packet capture, and attack injectors.
- **`config/`**: System configuration, lab definitions, and detection rule policies.
- **`scripts/`**: Lab setup/teardown, automated verification, and demonstration runners.
- **`tests/`**: Comprehensive Pytest and Vitest test suites.

Refer to the main [README.md](../README.md) for full project documentation and quickstart instructions.
