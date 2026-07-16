#!/bin/bash
# Run all HW-1 checks in sequence.
# Usage: bash run_all.sh
set -e

cd "$(dirname "$0")"

echo "============================================"
echo "  Chronis HW-1 — Full Verification Run"
echo "============================================"
echo ""

echo ">>> Step 1: Running test suite..."
python3 -m pytest tests/ -v
echo ""

echo ">>> Step 2: Generating synthetic traces..."
cd traces && python3 trace_generator.py && cd ..
echo ""

echo ">>> Step 3: Running extended simulation..."
python3 state_machine/extended_run.py
echo ""

echo "============================================"
echo "  All checks passed."
echo "============================================"
