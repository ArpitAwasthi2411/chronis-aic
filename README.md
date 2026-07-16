# Chronis AIC — Hardware Firmware Sprint

Simulation-first firmware build for the Chronis wearable device.
All logic runs against a Mock Hardware Abstraction Layer (HAL) — no physical chips needed.

## Repository Structure

```
chronis-aic/
├── hw-track-1-sensors/       — Mock HAL, traces, sensor daemons, state machine
├── hw-track-2-security-boot/ — Crypto, encryption, boot, watchdog, power
├── hw-track-3-connectivity/  — Storage, OTA, BLE, CLI, cloud gateway
├── integration/              — Day 5 cross-track wiring + full-stack runs
└── docs/                     — HARDWARE_READINESS_REPORT.md, COMPONENT_SPEC_LIST.md
```

## Quick Start

```bash
pip install -r requirements.txt
cd hw-track-1-sensors
pytest tests/ -v
```

## Sprint Rules (Non-Negotiable)

1. No daemon writes to disk without encryption daemon
2. Canonical data record is append-only (no overwrites)
3. Unavailable sensor = explicit null with reason (never fake zero)
4. No daemon reaches into another daemon's internals
