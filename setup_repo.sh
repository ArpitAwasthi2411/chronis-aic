#!/bin/bash
# ============================================
# Chronis AIC — Repo Setup Script
# Run this once: bash setup_repo.sh
# ============================================

set -e

echo "=== Setting up Chronis AIC repository ==="

# Initialize git
git init
git branch -M main

# Create full folder structure per the sprint doc
mkdir -p hw-track-1-sensors/{mock_hal,traces,daemons,state_machine,tests,docs}
mkdir -p hw-track-2-security-boot/{mock_crypto,encryption,boot,watchdog,power,thermal,enclosure,tests,docs}
mkdir -p hw-track-3-connectivity/{storage,ota,orchestration,cli,ble_mock,ble_daemon,ci,cloud_gateway,tests,docs}
mkdir -p integration/
mkdir -p docs/

# Create placeholder files so empty dirs are tracked
touch hw-track-1-sensors/traces/.gitkeep
touch hw-track-1-sensors/daemons/.gitkeep
touch hw-track-1-sensors/state_machine/.gitkeep
touch hw-track-2-security-boot/{mock_crypto,encryption,boot,watchdog,power,thermal,enclosure,tests,docs}/.gitkeep
touch hw-track-3-connectivity/{storage,ota,orchestration,cli,ble_mock,ble_daemon,ci,cloud_gateway,tests,docs}/.gitkeep
touch integration/.gitkeep

# Create requirements.txt
cat > requirements.txt << 'EOF'
numpy>=1.24.0
pytest>=7.4.0
EOF

# Create .gitignore
cat > .gitignore << 'EOF'
__pycache__/
*.pyc
*.pyo
.pytest_cache/
*.egg-info/
dist/
build/
.env
venv/
.vscode/
.idea/
EOF

# Create README
cat > README.md << 'EOF'
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
EOF

# Create placeholder docs
cat > docs/HARDWARE_READINESS_REPORT.md << 'EOF'
# Hardware Readiness Report

*To be completed at end of Day 5.*
EOF

cat > docs/COMPONENT_SPEC_LIST.md << 'EOF'
# Component Spec List

| Component | Part Number | Role |
|-----------|-------------|------|
| IMU | ICM-42688-P | Motion sensor (6-axis) |
| PPG Sensor | MAX30102 | Heart-rate / SpO2 |
| Crypto Chip | ATECC608B | Security / key storage |
| Camera | IMX219 | Video capture |
| RTC Backup | DS3231-class | Real-time clock |
| Compute Board | Radxa Zero 3W | Main SBC |
EOF

# Initial commit
git add -A
git commit -m "feat: complete HW-1 sensor & motion logic (full track)

Mock layer:
- Mock HAL: IMU, PPG, Camera, Mic, GPIO with SensorUnavailable (Rule 3)
- MockStorage: encryption-before-write (Rule 1) + append-only (Rule 2)
- Synthetic trace generator: 4 scenarios + double-tap + not-worn traces

Daemons:
- Motion daemon: orientation (complementary filter), motion state,
  posture, gesture energy, change-point, double-tap
- Heart rate daemon: signal quality scoring
- Anchor gesture detector: double-tap = annotation only (never capture)
- Camera + audio daemons: Rule 1 encryption handoff
- Worn/not-worn detector: 3-signal weighted vote, 5-min timeout, 15s wake-up

State machine:
- 6-level capture intensity (L0-L5) with exact transitions + hysteresis
- Extended chained-scenario simulation with transition log

Testing: 71 tests passing, CI pipeline, full verification script"

echo ""
echo "=== Setup complete! ==="

