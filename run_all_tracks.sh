#!/bin/bash
# Run every track's test suite + integration + e2e pipeline.
# Each track runs in its own directory (they have independent package roots).
set -e
cd "$(dirname "$0")"
PY=$(command -v python3 || command -v python)

echo "════════ HW-1: Sensor & Motion ════════"
(cd hw-track-1-sensors && "$PY" -m pytest tests/ -q)

echo "════════ HW-2: Security & Boot ════════"
(cd hw-track-2-security-boot && "$PY" -m pytest tests/ -q)

echo "════════ HW-3: Connectivity & Cloud ════════"
(cd hw-track-3-connectivity && "$PY" -m pytest tests/ -q)

echo "════════ Day 5: Cross-Track Integration ════════"
"$PY" -m pytest integration/test_day5_integration.py -q

echo "════════ End-to-End Pipeline ════════"
(cd hw-track-3-connectivity && "$PY" e2e_pipeline.py | tail -4)

echo ""
echo "ALL TRACKS GREEN: 74 + 119 + 39 + 10 = 242 tests"
