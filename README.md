# Chronis AIC — Hardware Firmware Sprint

Simulation-first firmware build for the Chronis wearable device.
All logic runs against a Mock Hardware Abstraction Layer (HAL) — no physical chips needed.

**242 tests passing across 3 tracks + Day 5 integration + end-to-end pipeline.**

## Repository Structure

```
chronis-aic/
├── hw-track-1-sensors/          Track HW-1: Sensor & Motion Logic (74 tests)
│   ├── mock_hal/                  Mock IMU, PPG, Camera, Mic, GPIO + storage
│   ├── traces/                    6 synthetic sensor scenarios
│   ├── daemons/                   Motion, HR, anchor gesture, camera, audio, worn detector
│   ├── state_machine/             6-level capture intensity (L0-L5) + extended simulation
│   ├── tests/                     74 tests
│   └── docs/                      Interface spec, walkthrough, known gaps
│
├── hw-track-2-security-boot/    Track HW-2: Security & Boot Logic (119 tests)
│   ├── encryption/                AES-256-GCM + X25519 + Ed25519, key hierarchy
│   ├── boot/                      Boot sequence + failure handling (9 failure modes)
│   ├── watchdog/                  Daemon health monitoring
│   ├── power/                     Power management daemon (4 battery states)
│   └── tests/                     119 tests
│
├── hw-track-3-connectivity/     Track HW-3: Connectivity, Storage & Cloud (39 tests)
│   ├── storage/                   Vault tree, double-confirmation deletion, append-only
│   ├── ota/                       RSA-2048 signature, SHA-256, 3-boot rollback
│   ├── ble_daemon/                8 GATT services, Numeric Comparison pairing
│   ├── ble_mock/                  Mock peripheral for phone-app team
│   ├── orchestration/             Encryption-first startup ordering
│   ├── cli/                       chronis-cli debug tool (never prints plaintext)
│   ├── cloud_gateway/             Verify → decrypt → canonical append-only DB
│   ├── network/                   Firewall + SSH key-only provisioning script
│   └── tests/                     39 tests
│
├── integration/                 Day 5: Cross-Track Integration (10 tests)
│   ├── power_ceiling_combiner.py  SM level × power ceiling → lower wins
│   └── test_day5_integration.py   All 4 cross-track connections tested
│
├── docs/
│   ├── HARDWARE_READINESS_REPORT.md
│   └── COMPONENT_SPEC_LIST.md
│
└── run_all_tracks.sh            Runs all 242 tests + e2e pipeline
```

## Quick Start

```bash
pip install numpy pytest cryptography
bash run_all_tracks.sh
```

Expected output: `ALL TRACKS GREEN: 74 + 119 + 39 + 10 = 242 tests`

## End-to-End Pipeline

The full loop connecting all three tracks:

```
fake sensor data (HW-1 traces)
  → capture-intensity decision (HW-1 state machine)
  → encrypted upload (HW-2 encryption daemon)
  → vault storage (HW-3, Rule 1 + Rule 2)
  → cloud gateway verify + decrypt (HW-3)
  → structured event → canonical record DB (append-only at SQLite level)
  → device records deleted only after double confirmation
```

Run it: `cd hw-track-3-connectivity && python3 e2e_pipeline.py`

## Sprint Rules (Non-Negotiable — Enforced Structurally)

1. **Encrypt Before Storage** — storage.write() only accepts EncryptedPayload/EncryptedRecord type; raw data raises at runtime
2. **Append-Only Records** — overwrite or delete always fails (in mock storage, HW-3 storage manager, AND SQLite triggers)
3. **No Fake Zeros** — unavailable sensor → explicit status + None values, never a silent zero
4. **No Direct Daemon Access** — all cross-daemon communication through typed interfaces; clean seam for future permissions layer

## Component Spec List

| Component | Part Number | Role |
|-----------|-------------|------|
| IMU | ICM-42688-P | 6-axis motion sensor |
| PPG | MAX30102 | Heart-rate / SpO2 |
| Crypto | ATECC608B | Secure key storage |
| Camera | IMX219 | Video capture |
| RTC | DS3231-class | Clock backup |
| Compute | Radxa Zero 3W | Main board |

## Day 4 Gate: MET

- Zero crashes across 570-second extended simulation (including deliberate sensor failure injection)
- Zero rule violations across all 242 tests
- Full pipeline working: sensor → decision → encrypt → upload → verify → decrypt → permanent DB
- All four Day 5 cross-track connections tested and passing
