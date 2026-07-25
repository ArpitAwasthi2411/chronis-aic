"""
Chronis Task 2 — Team A Day 1: Fuzzing Harness.

Feeds every Task 1 daemon deliberately bad data and logs every crash,
unhandled error, or silent bad behavior. Categories of bad input:

  1. Impossible values      (accel=99999, hr=-50, energy=infinity)
  2. Frozen readings         (same timestamp 1000 times)
  3. Impossible jumps        (HR 70→300→70 in one tick)
  4. Backward timestamps     (t=10→5→8)
  5. Duplicate timestamps    (three readings at t=5.0)
  6. NaN/None injections     (NaN as accel, None as heart_rate)
  7. Extreme edge values     (0, -0, MAX_FLOAT, MIN_FLOAT, epsilon)
  8. Type confusion          (string where float expected, list where int)
  9. Empty/corrupt traces    (empty list, missing fields, wrong JSON)
  10. Rapid state flipping   (worn→not-worn every tick)
"""

import sys
import os
import math
import json
import traceback
from dataclasses import dataclass, field
from typing import List, Callable, Any, Optional
from enum import Enum

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "hw-track-1-sensors"))
sys.path.insert(0, os.path.join(ROOT, "hw-track-3-connectivity"))

from mock_hal.sensor_types import (
    IMUReading, PPGReading, AudioReading, CameraReading,
    SensorStatus, UnavailableReason,
)


class Severity(Enum):
    CRASH = "CRASH"                    # unhandled exception -> daemon dies
    SILENT_BAD = "SILENT_BAD"          # bad data accepted as valid (Rule 3 violation)
    DEGRADED = "DEGRADED"              # partial misbehavior but no crash
    HANDLED = "HANDLED"                # daemon correctly rejected/flagged the input


@dataclass
class FuzzResult:
    daemon_name: str
    fuzz_category: str
    description: str
    severity: Severity
    detail: str = ""
    exception: Optional[str] = None


@dataclass
class FuzzReport:
    daemon_name: str
    results: List[FuzzResult] = field(default_factory=list)
    total_cases: int = 0
    crashes: int = 0
    silent_bads: int = 0
    degraded: int = 0
    handled: int = 0

    def add(self, r: FuzzResult):
        self.results.append(r)
        self.total_cases += 1
        if r.severity == Severity.CRASH:
            self.crashes += 1
        elif r.severity == Severity.SILENT_BAD:
            self.silent_bads += 1
        elif r.severity == Severity.DEGRADED:
            self.degraded += 1
        else:
            self.handled += 1

    def summary(self) -> str:
        return (f"{self.daemon_name}: {self.total_cases} cases — "
                f"{self.crashes} CRASH, {self.silent_bads} SILENT_BAD, "
                f"{self.degraded} DEGRADED, {self.handled} HANDLED")


# ============ Bad input generators ============

def make_bad_imu(t, **overrides):
    defaults = dict(timestamp=t, status=SensorStatus.OK,
                    accel_x=0.0, accel_y=0.0, accel_z=1.0,
                    gyro_x=0.0, gyro_y=0.0, gyro_z=0.0)
    defaults.update(overrides)
    return IMUReading(**defaults)


def make_bad_ppg(t, **overrides):
    defaults = dict(timestamp=t, status=SensorStatus.OK,
                    heart_rate_bpm=70.0, spo2_percent=98.0,
                    signal_quality=0.85)
    defaults.update(overrides)
    return PPGReading(**defaults)


IMU_FUZZ_CASES = [
    # Category 1: Impossible values
    ("impossible_accel_huge", "accel_x=99999", dict(accel_x=99999.0)),
    ("impossible_accel_neg_huge", "accel_x=-99999", dict(accel_x=-99999.0)),
    ("impossible_gyro_huge", "gyro_x=1e12", dict(gyro_x=1e12)),
    ("impossible_all_zero", "all axes exactly 0 (no gravity!)", dict(accel_x=0, accel_y=0, accel_z=0)),
    # Category 6: NaN injection
    ("nan_accel_x", "accel_x=NaN", dict(accel_x=float('nan'))),
    ("nan_accel_z", "accel_z=NaN", dict(accel_z=float('nan'))),
    ("nan_gyro", "gyro_x=NaN", dict(gyro_x=float('nan'))),
    ("inf_accel", "accel_x=inf", dict(accel_x=float('inf'))),
    ("neg_inf_accel", "accel_z=-inf", dict(accel_z=float('-inf'))),
    # Category 7: Extreme edge
    ("epsilon_accel", "accel=sys.float_info.epsilon", dict(accel_x=sys.float_info.epsilon)),
    ("max_float", "accel_x=MAX_FLOAT", dict(accel_x=sys.float_info.max)),
    ("min_float", "accel_x=MIN_FLOAT", dict(accel_x=sys.float_info.min)),
    ("negative_zero", "accel_x=-0.0", dict(accel_x=-0.0)),
]

PPG_FUZZ_CASES = [
    ("impossible_hr_negative", "HR=-50", dict(heart_rate_bpm=-50.0)),
    ("impossible_hr_huge", "HR=500", dict(heart_rate_bpm=500.0)),
    ("impossible_hr_zero", "HR=0.0 (not unavailable)", dict(heart_rate_bpm=0.0)),
    ("impossible_spo2", "SpO2=200%", dict(spo2_percent=200.0)),
    ("nan_hr", "HR=NaN", dict(heart_rate_bpm=float('nan'))),
    ("inf_hr", "HR=inf", dict(heart_rate_bpm=float('inf'))),
    ("nan_quality", "quality=NaN", dict(signal_quality=float('nan'))),
    ("neg_quality", "quality=-1.0", dict(signal_quality=-1.0)),
    ("huge_quality", "quality=999", dict(signal_quality=999.0)),
]


class FuzzHarness:
    """Reusable harness: takes a daemon, throws bad inputs, catches results."""

    def __init__(self, name: str):
        self.report = FuzzReport(daemon_name=name)

    def run_case(self, category: str, desc: str, fn: Callable[[], Any],
                 validator: Optional[Callable[[Any], Severity]] = None):
        """Execute one fuzz case. fn() should call the daemon. validator checks output."""
        try:
            result = fn()
            if validator:
                sev = validator(result)
            else:
                sev = Severity.HANDLED
            self.report.add(FuzzResult(
                daemon_name=self.report.daemon_name,
                fuzz_category=category, description=desc,
                severity=sev, detail=str(result)[:200],
            ))
        except Exception as e:
            self.report.add(FuzzResult(
                daemon_name=self.report.daemon_name,
                fuzz_category=category, description=desc,
                severity=Severity.CRASH,
                exception=f"{type(e).__name__}: {e}",
                detail=traceback.format_exc()[-300:],
            ))


# ============ Per-daemon fuzzers ============

def fuzz_motion_daemon() -> FuzzReport:
    from daemons.motion_daemon import MotionDaemon, MotionState
    h = FuzzHarness("motion_daemon")
    d = MotionDaemon(20.0)

    # warm up with normal data
    for i in range(20):
        d.update(make_bad_imu(i * 0.05))

    # Category 1 + 6 + 7: bad values
    for name, desc, overrides in IMU_FUZZ_CASES:
        t = 5.0
        def _run(ov=overrides, _t=t):
            return d.update(make_bad_imu(_t, **ov))
        def _check(out):
            if out is None:
                return Severity.CRASH
            # if NaN/inf input led to a "valid=True" output, that's silent bad
            if out.valid and out.pitch_deg is not None and math.isnan(out.pitch_deg):
                return Severity.SILENT_BAD
            return Severity.HANDLED
        h.run_case(name, desc, _run, _check)

    # Category 2: Frozen timestamps (same timestamp repeated)
    def _frozen():
        results = []
        for _ in range(50):
            results.append(d.update(make_bad_imu(99.0)))
        return results
    h.run_case("frozen_timestamps", "50 readings all at t=99.0", _frozen)

    # Category 3: Impossible jump
    def _jump():
        d2 = MotionDaemon(20.0)
        for i in range(20):
            d2.update(make_bad_imu(i * 0.05))
        d2.update(make_bad_imu(1.0, accel_z=1.0))
        out = d2.update(make_bad_imu(1.05, accel_z=50.0))  # sudden 50g spike
        return out
    h.run_case("impossible_jump", "accel_z goes 1.0→50.0 in one step", _jump)

    # Category 4: Backward timestamps
    def _backward():
        d3 = MotionDaemon(20.0)
        d3.update(make_bad_imu(10.0))
        d3.update(make_bad_imu(5.0))   # backward!
        return d3.update(make_bad_imu(8.0))
    h.run_case("backward_timestamps", "t=10→5→8", _backward)

    # Category 5: Duplicate timestamps
    def _dupes():
        d4 = MotionDaemon(20.0)
        results = [d4.update(make_bad_imu(5.0)) for _ in range(3)]
        return results
    h.run_case("duplicate_timestamps", "3 readings at t=5.0", _dupes)

    # Category 10: Rapid double-tap false triggers
    def _rapid_taps():
        d5 = MotionDaemon(20.0)
        for i in range(20):
            d5.update(make_bad_imu(i * 0.05))
        fires = 0
        t = 2.0
        # 20 rapid spikes in a row (should not fire 20 double-taps)
        for j in range(20):
            out = d5.update(make_bad_imu(t, accel_z=3.0))
            t += 0.05
            if out.double_tap:
                fires += 1
        return fires
    def _check_taps(fires):
        return Severity.SILENT_BAD if fires > 2 else Severity.HANDLED
    h.run_case("rapid_spike_barrage", "20 consecutive accel spikes", _rapid_taps, _check_taps)

    return h.report


def fuzz_heart_rate_daemon() -> FuzzReport:
    from daemons.heart_rate_daemon import HeartRateDaemon, HRQuality
    h = FuzzHarness("heart_rate_daemon")
    d = HeartRateDaemon()

    for name, desc, overrides in PPG_FUZZ_CASES:
        def _run(ov=overrides):
            return d.update(make_bad_ppg(1.0, **ov))
        def _check(out):
            if out is None:
                return Severity.CRASH
            hr = out.heart_rate_bpm
            # NaN HR reported as trustworthy = silent bad
            if out.trustworthy and hr is not None and (math.isnan(hr) or math.isinf(hr)):
                return Severity.SILENT_BAD
            # negative HR reported as trustworthy = silent bad
            if out.trustworthy and hr is not None and hr < 0:
                return Severity.SILENT_BAD
            return Severity.HANDLED
        h.run_case(name, desc, _run, _check)

    # impossible jump: HR 70 → 300 → 70
    def _hr_jump():
        d2 = HeartRateDaemon()
        for i in range(10):
            d2.update(make_bad_ppg(i, heart_rate_bpm=70.0))
        out1 = d2.update(make_bad_ppg(11, heart_rate_bpm=300.0))
        out2 = d2.update(make_bad_ppg(12, heart_rate_bpm=70.0))
        return (out1, out2)
    def _check_jump(outs):
        # 300bpm should not be trusted
        if outs[0].trustworthy:
            return Severity.SILENT_BAD
        return Severity.HANDLED
    h.run_case("impossible_hr_jump", "HR 70→300→70", _hr_jump, _check_jump)

    return h.report


def fuzz_anchor_gesture() -> FuzzReport:
    from daemons.anchor_gesture_detector import AnchorGestureDetector
    h = FuzzHarness("anchor_gesture_detector")

    # negative timestamp
    def _neg_ts():
        a = AnchorGestureDetector()
        return a.on_double_tap(-5.0)
    h.run_case("negative_timestamp", "double-tap at t=-5.0", _neg_ts)

    # NaN timestamp
    def _nan_ts():
        a = AnchorGestureDetector()
        return a.on_double_tap(float('nan'))
    h.run_case("nan_timestamp", "double-tap at t=NaN", _nan_ts)

    # inf timestamp
    def _inf_ts():
        a = AnchorGestureDetector()
        return a.on_double_tap(float('inf'))
    h.run_case("inf_timestamp", "double-tap at t=inf", _inf_ts)

    # massive number of taps (stress test)
    def _stress():
        a = AnchorGestureDetector()
        for i in range(10000):
            a.on_double_tap(float(i))
        return a.active_window_count
    h.run_case("stress_10k_taps", "10,000 double-taps in rapid succession", _stress)

    # attach_note with empty string
    def _empty_note():
        a = AnchorGestureDetector()
        a.on_double_tap(1.0)
        return a.attach_note(1.0, "")
    h.run_case("empty_note", "attach empty string note", _empty_note)

    # attach_note with huge string
    def _huge_note():
        a = AnchorGestureDetector()
        a.on_double_tap(1.0)
        return a.attach_note(1.0, "x" * 1_000_000)
    h.run_case("huge_note", "attach 1MB note", _huge_note)

    return h.report


def fuzz_worn_detector() -> FuzzReport:
    from daemons.worn_detector import WornNotWornDetector, WornState
    h = FuzzHarness("worn_detector")
    d = WornNotWornDetector()

    bad_inputs = [
        ("nan_hr_quality", "hr_quality=NaN", dict(hr_quality=float('nan'), orientation_variance=1.0, accel_activity=0.01)),
        ("inf_hr_quality", "hr_quality=inf", dict(hr_quality=float('inf'), orientation_variance=1.0, accel_activity=0.01)),
        ("neg_hr_quality", "hr_quality=-5", dict(hr_quality=-5.0, orientation_variance=1.0, accel_activity=0.01)),
        ("nan_orient", "orient_var=NaN", dict(hr_quality=0.8, orientation_variance=float('nan'), accel_activity=0.01)),
        ("huge_orient", "orient_var=1e15", dict(hr_quality=0.8, orientation_variance=1e15, accel_activity=0.01)),
        ("neg_accel", "accel=-100", dict(hr_quality=0.8, orientation_variance=1.0, accel_activity=-100.0)),
        ("all_nan", "all inputs NaN", dict(hr_quality=float('nan'), orientation_variance=float('nan'), accel_activity=float('nan'))),
        ("all_inf", "all inputs inf", dict(hr_quality=float('inf'), orientation_variance=float('inf'), accel_activity=float('inf'))),
        ("all_zero", "all inputs 0", dict(hr_quality=0.0, orientation_variance=0.0, accel_activity=0.0)),
    ]

    for name, desc, kwargs in bad_inputs:
        def _run(kw=kwargs):
            return d.update(1.0, **kw)
        def _check(out):
            if out is None:
                return Severity.CRASH
            if math.isnan(out.vote_score):
                return Severity.SILENT_BAD
            return Severity.HANDLED
        h.run_case(name, desc, _run, _check)

    # Category 10: rapid worn/not-worn flipping every tick
    def _rapid_flip():
        d2 = WornNotWornDetector()
        for t in range(200):
            if t % 2 == 0:
                d2.update(float(t), 0.0, 0.0, 0.0)     # not worn
            else:
                d2.update(float(t), 0.9, 6.0, 0.04)     # worn
        return d2.state
    h.run_case("rapid_worn_flip", "alternating worn/not-worn every second", _rapid_flip)

    # backward timestamp
    def _backward():
        d3 = WornNotWornDetector()
        d3.update(10.0, 0.9, 6.0, 0.04)
        return d3.update(5.0, 0.9, 6.0, 0.04)   # time goes backward
    h.run_case("backward_timestamp", "t=10 then t=5", _backward)

    return h.report


def fuzz_capture_daemons() -> FuzzReport:
    from daemons.capture_daemons import CameraDaemon, AudioDaemon, StubEncryptionDaemon
    from mock_hal.mock_storage import MockStorage
    h = FuzzHarness("capture_daemons")
    enc = StubEncryptionDaemon()
    storage = MockStorage()
    cam = CameraDaemon(enc, storage)
    aud = AudioDaemon(enc, storage)

    # Camera: unavailable frame
    def _cam_unavail():
        bad = CameraReading(timestamp=1.0, status=SensorStatus.UNAVAILABLE)
        return cam.capture_and_store(bad)
    h.run_case("camera_unavailable", "store an unavailable frame", _cam_unavail)

    # Audio: NaN energy
    def _aud_nan():
        bad = AudioReading(timestamp=1.0, status=SensorStatus.OK,
                           energy_rms=float('nan'), sample_rate_hz=16000)
        return aud.capture_and_store(bad, level="L3")
    h.run_case("audio_nan_energy", "audio with energy=NaN at L3", _aud_nan)

    # Camera: negative frame_id
    def _neg_frame():
        bad = CameraReading(timestamp=1.0, status=SensorStatus.OK,
                            frame_id=-1, width=0, height=0,
                            compression_level="none")
        return cam.capture_and_store(bad, date="2026-07-17")
    h.run_case("camera_neg_frame", "frame_id=-1, 0x0 resolution", _neg_frame)

    return h.report


def fuzz_state_machine() -> FuzzReport:
    from state_machine.capture_state_machine import CaptureStateMachine, CaptureSignals, Level
    h = FuzzHarness("capture_state_machine")

    bad_signals = [
        ("nan_heart_rate", dict(heart_rate=float('nan'))),
        ("inf_heart_rate", dict(heart_rate=float('inf'))),
        ("neg_heart_rate", dict(heart_rate=-100)),
        ("nan_hr_baseline", dict(hr_baseline=float('nan'))),
        ("zero_baseline", dict(hr_baseline=0.0)),
        ("neg_baseline", dict(hr_baseline=-10.0)),
        ("nan_speech_fraction", dict(speech_fraction=float('nan'))),
        ("huge_speakers", dict(num_speakers=999999)),
        ("neg_voice_energy", dict(voice_energy=-1.0)),
        ("nan_stress", dict(stress_index=float('nan'))),
        ("hour_neg", dict(hour_of_day=-1)),
        ("hour_huge", dict(hour_of_day=99)),
    ]

    for name, overrides in bad_signals:
        def _run(ov=overrides):
            sm = CaptureStateMachine()
            sig = CaptureSignals(timestamp=0.0, **ov)
            return sm.tick(sig)
        def _check(level):
            if level is None:
                return Severity.CRASH
            return Severity.HANDLED
        h.run_case(name, f"CaptureSignals with {name}", _run, _check)

    # rapid level cycling
    def _rapid_cycle():
        sm = CaptureStateMachine()
        for i in range(1000):
            sig = CaptureSignals(
                timestamp=float(i),
                worn=(i % 3 != 0), upright=True,
                hr_quality=0.8 if i % 2 == 0 else 0.0,
                heart_rate=70 + (i % 50), hr_baseline=68.0,
                speech_fraction=(i % 10) / 10.0,
                num_speakers=i % 5,
                hour_of_day=12,
            )
            sm.tick(sig)
        return sm.level
    h.run_case("rapid_cycling_1000", "1000 ticks with wildly varying inputs", _rapid_cycle)

    return h.report


def fuzz_trace_generator() -> FuzzReport:
    from traces.trace_generator import load_trace, TraceSample
    h = FuzzHarness("trace_generator")

    # corrupt JSON
    def _corrupt_json():
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{broken json!!!")
            path = f.name
        try:
            load_trace(path)
            return "loaded without error"  # bad
        except (json.JSONDecodeError, ValueError, KeyError):
            return "correctly rejected"
        finally:
            os.unlink(path)
    h.run_case("corrupt_json", "malformed JSON trace file", _corrupt_json)

    # missing SYNTHETIC flag
    def _no_flag():
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"_meta": {"SYNTHETIC": False}, "samples": []}, f)
            path = f.name
        try:
            load_trace(path)
            return "loaded without error"  # bad: missing flag accepted
        except ValueError:
            return "correctly rejected"
        finally:
            os.unlink(path)
    def _check_flag(result):
        return Severity.SILENT_BAD if result == "loaded without error" else Severity.HANDLED
    h.run_case("missing_synthetic_flag", "trace with SYNTHETIC=False", _no_flag, _check_flag)

    # empty samples
    def _empty():
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"_meta": {"SYNTHETIC": True}, "samples": []}, f)
            path = f.name
        try:
            result = load_trace(path)
            return len(result)
        finally:
            os.unlink(path)
    h.run_case("empty_samples", "trace with 0 samples", _empty)

    return h.report


# ============ Run all fuzzers ============

def run_all_fuzzers(verbose: bool = True) -> List[FuzzReport]:
    fuzzers = [
        fuzz_motion_daemon,
        fuzz_heart_rate_daemon,
        fuzz_anchor_gesture,
        fuzz_worn_detector,
        fuzz_capture_daemons,
        fuzz_state_machine,
        fuzz_trace_generator,
    ]
    reports = []
    for fn in fuzzers:
        if verbose:
            print(f"\nFuzzing {fn.__name__}...")
        report = fn()
        reports.append(report)
        if verbose:
            print(f"  {report.summary()}")
            for r in report.results:
                if r.severity in (Severity.CRASH, Severity.SILENT_BAD):
                    print(f"    !! [{r.severity.value}] {r.fuzz_category}: "
                          f"{r.description}")
                    if r.exception:
                        print(f"       {r.exception}")
    return reports


if __name__ == "__main__":
    print("=" * 65)
    print("  Chronis Task 2 — Team A: Fuzz Every Daemon")
    print("=" * 65)
    reports = run_all_fuzzers()
    print("\n" + "=" * 65)
    total = sum(r.total_cases for r in reports)
    crashes = sum(r.crashes for r in reports)
    silent = sum(r.silent_bads for r in reports)
    print(f"TOTAL: {total} fuzz cases | {crashes} CRASH | {silent} SILENT_BAD")
    print("=" * 65)
