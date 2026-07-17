# Chronis AIC — Hardware Firmware Sprint

Simulation-first firmware build for the Chronis wearable device. All logic runs against a Mock Hardware Abstraction Layer (HAL) — no physical chips needed.

**242 tests passing across 3 tracks + Day 5 integration + end-to-end pipeline.**

## Quick Start

```bash
pip install numpy pytest cryptography
bash run_all_tracks.sh
```

## Repository Structure
chronis-aic/
├── hw-track-1-sensors/          Sensor & Motion Logic (74 tests)
├── hw-track-2-security-boot/    Security & Boot Logic (119 tests)
├── hw-track-3-connectivity/     Connectivity, Storage & Cloud (39 tests)
├── integration/                 Day 5 Cross-Track Integration (10 tests)
├── docs/                        Readiness report + component spec
└── run_all_tracks.sh            Runs all 242 tests + e2e pipeline

## Sprint Rules (Enforced Structurally)

1. **Encrypt Before Storage** — storage only accepts encrypted types; raw data raises at runtime
2. **Append-Only Records** — overwrite or delete always fails
3. **No Fake Zeros** — unavailable sensor returns explicit status + None, never silent zero
4. **No Direct Daemon Access** — all cross-daemon communication through typed interfaces

## End-to-End Pipeline
sensor data -> capture decision -> encrypt -> vault storage -> cloud gateway -> verify -> decrypt -> canonical DB (append-only at SQLite level)

Run it: `cd hw-track-3-connectivity && python3 e2e_pipeline.py`

## Component Spec List

| Component | Part Number | Role |
|-----------|-------------|------|
| IMU | ICM-42688-P | 6-axis motion |
| PPG | MAX30102 | Heart-rate / SpO2 |
| Crypto | ATECC608B | Secure key storage |
| Camera | IMX219 | Video capture |
| RTC | DS3231-class | Clock backup |
| Compute | Radxa Zero 3W | Main board |

## Day 4 Gate: MET

Zero crashes, zero rule violations, zero fake zeros across 242 tests and 570-second extended simulation.
