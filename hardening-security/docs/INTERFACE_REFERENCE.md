# Daemon Interface Reference

Every daemon-to-daemon handoff in the Chronis firmware, documented so a
future contributor doesn't have to read source code to understand the contract.

---

## IMU → Motion Daemon
**Input:** `IMUReading`
- `timestamp: float`, `status: SensorStatus`
- `accel_x/y/z: Optional[float]` (g), `gyro_x/y/z: Optional[float]` (deg/s)
- Check `reading.is_valid` before using values

**Output:** `MotionOutput`
- `valid: bool`, `timestamp: float`
- `pitch_deg, roll_deg: Optional[float]`
- `motion_state: MotionState` (STILL / WALKING / ACTIVE / UNAVAILABLE)
- `posture: Posture` (UPRIGHT / LYING / UNKNOWN)
- `gesture_energy: Optional[float]`, `change_point: bool`, `double_tap: bool`

**Edge case behavior (proven by fuzzing):**
NaN/inf/overflow accel or gyro values → filter skips the reading, keeps last
good estimate, magnitude returns None. No crash, no NaN propagation.

---

## PPG → Heart Rate Daemon
**Input:** `PPGReading`
- `timestamp: float`, `status: SensorStatus` (OK / NOT_WORN / UNAVAILABLE)
- `heart_rate_bpm, spo2_percent, signal_quality: Optional[float]`

**Output:** `HeartRateOutput`
- `valid: bool`, `heart_rate_bpm: Optional[float]`
- `signal_quality: float` (combined 0-1 score)
- `quality_label: HRQuality` (GOOD / FAIR / POOR / UNAVAILABLE)
- `trustworthy: bool` (True only if combined quality >= 0.6)

**Edge case behavior:**
Implausible HR (>220 or <30) → plausibility=0, trustworthy=False.
NaN HR → not trusted, not added to history.

---

## Motion Daemon → Anchor Gesture Detector
**Input:** `double_tap: bool` from `MotionOutput`
**Call:** `on_double_tap(timestamp)` when `double_tap is True`

**Output:** `MomentMarkedSignal`
- `timestamp: float`, `window: AnnotationWindow` (30s span)
- `message: str = "moment_marked"`

**Guarantee:** This module has ZERO capture-state attributes. It can only
annotate, never change capture level.

---

## Phone → Anchor Gesture Detector
**Call:** `attach_note(timestamp, text)`
**Returns:** `bool` (success)

---

## All Sensor Daemons → Encryption Daemon → Storage
**Flow:** Raw sensor data → `RawPayload` → `encrypt()` → `EncryptedPayload` → `storage.write()`

**Input to encryption:** `RawPayload`
- `data: bytes`, `source_daemon: str`, `timestamp: float`

**Output:** `EncryptedPayload`
- `ciphertext: bytes`, `signature: bytes`, `key_id: str`
- `timestamp: float`, `source_daemon: str`

**Storage contract:**
- `write(path, payload)` accepts ONLY `EncryptedPayload`
- Raises `EncryptionBypassAttempt` on anything else
- Raises `AppendOnlyViolation` on overwrite or delete

---

## HR Daemon + Motion Daemon + Accel → Worn Detector
**Input:** called per tick with:
- `hr_quality: float` (0-1, from HeartRateOutput.signal_quality)
- `orientation_variance: float` (from pitch/roll window variance)
- `accel_activity: float` (from accel magnitude window mean deviation)

**Output:** `WornOutput`
- `state: WornState` (WORN / NOT_WORN / WAKING_UP)
- `vote_score: float` (0-1), `hr/orientation/accel_component: float`
- `wakeup_progress: Optional[float]`, `self_test_passed: Optional[bool]`
- `metadata_entry() -> dict` (for every metadata write)

---

## All Signals → Capture State Machine
**Input:** `CaptureSignals` (a bundle of every signal the SM reads)
- `worn, upright, asleep: bool`
- `hr_quality, heart_rate, hr_baseline: float`
- `motion_state: str`, `purposeful_motion, movement_burst: bool`
- `speech_fraction, voice_energy, voice_energy_baseline: float`
- `num_speakers: int`, `overlapping_speech: bool`
- `face_expression_changed: bool`, `stress_index, stress_p90: float`
- `hour_of_day: int`

**Output:** `Level` (L0-L5 IntEnum)
- Side effect: `self.transitions: List[LevelTransition]` appended

**Special methods:**
- `restart_at_L1(timestamp)` — called after worn detector wake-up completes
- `current_config() -> dict` — per-level camera/audio settings

---

## State Machine Level × Power Daemon Ceiling → Effective Level
**Input:** `state_machine_level: Level`, `power_ceiling: Level`
**Output:** `min(state_machine_level, power_ceiling)` — lower always wins

---

## Anchor Gesture → BLE Daemon Alert
**Wiring:** `phone_notifier` callback → `ble.push_alert("double_tap_moment_marked", ...)`
**Phone → BLE:** `svc_annotation(note, tap_timestamp)` — note linked to window

---

## BLE Device Info Service
**Reads from DeviceStateProvider interface (not daemon internals):**
- `battery_percent(), power_state(), firmware_version(), sync_status()`
- `storage_used_mb(), storage_total_mb(), capture_level()`
- `camera_killswitch(), audio_paused()`

**Guarantee:** Responses are LIVE values, not canned — proven by integration test.
