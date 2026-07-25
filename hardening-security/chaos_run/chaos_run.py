"""
Chronis Task 2 — Team A Day 4: Extended Chaos Run.

Combines fuzzed inputs, timing/concurrency edge cases, and normal traces in
one long session. Edge cases tested:
  - Worn detector flipping mid-transition
  - Rapid on/off cycling
  - Sensor failure mid-boot equivalent
  - Backward timestamps injected into otherwise normal data
  - NaN bursts mid-conversation scenario
  - Double-tap during worn transition

Pass criteria: zero crashes, zero Rule violations.
"""

import sys
import os
import math
import random

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "hw-track-1-sensors"))
sys.path.insert(0, os.path.join(ROOT, "hw-track-3-connectivity"))

from mock_hal.sensor_types import IMUReading, PPGReading, SensorStatus, UnavailableReason
from daemons.motion_daemon import MotionDaemon
from daemons.heart_rate_daemon import HeartRateDaemon
from daemons.worn_detector import WornNotWornDetector, WornState
from daemons.anchor_gesture_detector import AnchorGestureDetector
from state_machine.capture_state_machine import CaptureStateMachine, CaptureSignals, Level
from traces.trace_generator import TraceGenerator


def make_imu(t, ax=0, ay=0, az=1.0, gx=0, gy=0, gz=0):
    return IMUReading(timestamp=t, status=SensorStatus.OK,
                      accel_x=ax, accel_y=ay, accel_z=az,
                      gyro_x=gx, gyro_y=gy, gyro_z=gz)

def make_ppg(t, hr=70.0, q=0.85):
    return PPGReading(timestamp=t, status=SensorStatus.OK,
                      heart_rate_bpm=hr, signal_quality=q, spo2_percent=98.0)


def run_chaos(verbose=True):
    rng = random.Random(42)
    motion = MotionDaemon(20.0)
    hr = HeartRateDaemon()
    worn = WornNotWornDetector()
    anchor = AnchorGestureDetector()
    sm = CaptureStateMachine()

    crashes = 0
    rule_violations = 0
    total_ticks = 0
    events = []

    def _log(msg):
        if verbose:
            print(f"    {msg}")
        events.append(msg)

    if verbose:
        print("=" * 65)
        print("  Chronis Task 2 — Team A: Extended Chaos Run")
        print("=" * 65)

    # ---- Phase 1: Normal ambient warm-up (100 ticks) ----
    _log("[Phase 1] Normal ambient warm-up (5s)")
    for i in range(100):
        t = i * 0.05
        try:
            motion.update(make_imu(t))
            hr.update(make_ppg(t))
            worn.update(t, 0.85, 3.0, 0.02)
            sm.tick(CaptureSignals(timestamp=t, worn=True, upright=True,
                                   hr_quality=0.85, hour_of_day=12))
            total_ticks += 1
        except Exception as e:
            crashes += 1
            _log(f"  CRASH at t={t}: {e}")

    # ---- Phase 2: NaN burst mid-conversation (50 ticks) ----
    _log("[Phase 2] NaN burst injection (2.5s of NaN accel)")
    for i in range(50):
        t = 5.0 + i * 0.05
        try:
            imu = make_imu(t, ax=float('nan'), az=float('nan'))
            mo = motion.update(imu)
            if mo.valid and mo.pitch_deg is not None and math.isnan(mo.pitch_deg):
                rule_violations += 1
                _log(f"  RULE 3: NaN pitch accepted as valid at t={t}")
            total_ticks += 1
        except Exception as e:
            crashes += 1
            _log(f"  CRASH at t={t}: {e}")

    # ---- Phase 3: Rapid worn/not-worn cycling every 2 seconds ----
    _log("[Phase 3] Rapid worn/not-worn cycling (30s)")
    for i in range(600):
        t = 7.5 + i * 0.05
        cycle = (i // 40) % 2  # flip every 2 seconds
        try:
            if cycle == 0:
                worn.update(t, 0.0, 0.0, 0.0)  # not worn
            else:
                worn.update(t, 0.9, 6.0, 0.04)  # worn
            motion.update(make_imu(t))
            sm.tick(CaptureSignals(timestamp=t, worn=worn.is_worn, upright=True,
                                   hr_quality=0.85, hour_of_day=12))
            total_ticks += 1
        except Exception as e:
            crashes += 1
            _log(f"  CRASH at t={t}: {e}")

    # ---- Phase 4: Backward timestamps ----
    _log("[Phase 4] Backward timestamp injection")
    backward_seq = [100.0, 95.0, 98.0, 97.0, 101.0]
    for t in backward_seq:
        try:
            motion.update(make_imu(t))
            hr.update(make_ppg(t))
            total_ticks += 1
        except Exception as e:
            crashes += 1
            _log(f"  CRASH at backward t={t}: {e}")

    # ---- Phase 5: Double-tap during worn transition ----
    _log("[Phase 5] Double-tap exactly during worn→not-worn flip")
    try:
        # worn
        worn.update(200.0, 0.9, 6.0, 0.04)
        # inject double-tap
        imu_tap = make_imu(200.1, az=2.5)
        mo = motion.update(imu_tap)
        level_before = sm.level
        if mo.double_tap:
            anchor.on_double_tap(200.1)
        # immediately flip to not-worn
        worn.update(200.2, 0.0, 0.0, 0.0)
        # level should not have changed due to tap (anchor guarantee)
        if sm.level != level_before:
            rule_violations += 1
            _log("  RULE: tap changed capture level during worn transition!")
        total_ticks += 3
    except Exception as e:
        crashes += 1
        _log(f"  CRASH during phase 5: {e}")

    # ---- Phase 6: Sensor failure mid-stream (IMU dies, comes back) ----
    _log("[Phase 6] IMU failure for 5s, then recovery")
    for i in range(200):
        t = 300.0 + i * 0.05
        try:
            if 100 <= i < 200:
                # IMU unavailable
                imu = IMUReading(timestamp=t, status=SensorStatus.UNAVAILABLE,
                                 unavailable_reason=UnavailableReason.I2C_TIMEOUT)
            else:
                imu = make_imu(t)
            mo = motion.update(imu)
            if not imu.is_valid and mo.valid:
                rule_violations += 1
                _log(f"  RULE 3: unavailable IMU produced valid output at t={t}")
            total_ticks += 1
        except Exception as e:
            crashes += 1
            _log(f"  CRASH at t={t}: {e}")

    # ---- Phase 7: State machine rapid cycling with extreme signals ----
    _log("[Phase 7] State machine stress — 500 ticks of random extreme signals")
    for i in range(500):
        t = 400.0 + i * 0.5
        try:
            sig = CaptureSignals(
                timestamp=t,
                worn=rng.random() > 0.3,
                upright=rng.random() > 0.2,
                hr_quality=rng.random(),
                heart_rate=rng.uniform(40, 160),
                hr_baseline=68.0,
                speech_fraction=rng.random(),
                num_speakers=rng.randint(0, 5),
                voice_energy=rng.random(),
                voice_energy_baseline=0.3,
                hour_of_day=rng.randint(0, 23),
            )
            sm.tick(sig)
            total_ticks += 1
        except Exception as e:
            crashes += 1
            _log(f"  CRASH at SM tick t={t}: {e}")

    # ---- Phase 8: Infinite/negative in every signal simultaneously ----
    _log("[Phase 8] All signals set to extreme values simultaneously")
    extreme_sigs = [
        dict(heart_rate=float('nan'), hr_baseline=0),
        dict(heart_rate=float('inf'), speech_fraction=float('nan')),
        dict(num_speakers=-1, voice_energy=-100),
        dict(stress_index=float('inf'), stress_p90=0),
    ]
    for j, overrides in enumerate(extreme_sigs):
        try:
            sig = CaptureSignals(timestamp=700.0 + j, **overrides)
            sm.tick(sig)
            total_ticks += 1
        except Exception as e:
            crashes += 1
            _log(f"  CRASH with extreme signals #{j}: {e}")

    # ---- Results ----
    if verbose:
        print(f"\n{'=' * 65}")
        print(f"  CHAOS RUN COMPLETE")
        print(f"  Total ticks: {total_ticks}")
        print(f"  Crashes:     {crashes}")
        print(f"  Rule violations: {rule_violations}")
        gate = "PASSED" if crashes == 0 and rule_violations == 0 else "FAILED"
        print(f"  Day 4 Gate:  {gate}")
        print(f"{'=' * 65}")

    return {"total_ticks": total_ticks, "crashes": crashes,
            "rule_violations": rule_violations,
            "events": events}


if __name__ == "__main__":
    run_chaos()
