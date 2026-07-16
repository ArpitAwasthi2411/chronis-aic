"""
Chronis HW-1 — Worn / Not-Worn Detector.

Decides whether the device is actually on a body, from a weighted vote of three
signals:
  1. Heart-rate signal quality   (highest weight — best worn indicator)
  2. Orientation variance         (second — a worn device moves/tilts subtly)
  3. Accelerometer activity        (third/lowest — micro-motions of a living body)

Behavior:
  - "not worn" continuously for 5+ minutes -> low-power behavior
  - back to "worn" -> 15-second GRADUAL wake-up (not an instant jump),
    quick self-test, then resume with the capture state machine restarting at L1.

The worn state is logged on every metadata write.
"""

from dataclasses import dataclass
from enum import Enum
from collections import deque
from typing import Optional, Deque


class WornState(Enum):
    WORN = "worn"
    NOT_WORN = "not_worn"
    WAKING_UP = "waking_up"   # transitional 15s ramp


@dataclass
class WornOutput:
    timestamp: float
    state: WornState
    vote_score: float          # 0..1, >0.5 = worn
    hr_component: float
    orientation_component: float
    accel_component: float
    wakeup_progress: Optional[float] = None  # 0..1 during WAKING_UP


class WornNotWornDetector:
    """
    Feed it, each tick: hr_signal_quality (0..1), orientation_variance,
    accel_activity. It maintains timing state for the 5-min timeout and the
    15-second wake-up ramp.
    """

    # vote weights (must sum to 1.0)
    W_HR = 0.55
    W_ORIENT = 0.30
    W_ACCEL = 0.15

    WORN_THRESHOLD = 0.5
    NOT_WORN_TIMEOUT_S = 5 * 60      # 5 minutes
    WAKEUP_DURATION_S = 15.0

    def __init__(self):
        self._state = WornState.WORN
        self._not_worn_since: Optional[float] = None
        self._wakeup_start: Optional[float] = None
        # normalization references (calibrated on real hw later)
        self.ORIENT_VAR_REF = 5.0    # deg^2 that counts as "clearly worn"
        self.ACCEL_ACT_REF = 0.03    # accel activity that counts as "clearly worn"

    def _normalize_orientation(self, variance: float) -> float:
        """More orientation variance -> more likely worn. Cap at 1.0."""
        return min(1.0, variance / self.ORIENT_VAR_REF)

    def _normalize_accel(self, activity: float) -> float:
        return min(1.0, activity / self.ACCEL_ACT_REF)

    def _compute_vote(self, hr_quality: float, orient_var: float,
                      accel_act: float):
        hr_c = max(0.0, min(1.0, hr_quality))
        or_c = self._normalize_orientation(orient_var)
        ac_c = self._normalize_accel(accel_act)
        score = self.W_HR * hr_c + self.W_ORIENT * or_c + self.W_ACCEL * ac_c
        return score, hr_c, or_c, ac_c

    def update(self, timestamp: float, hr_quality: float,
               orientation_variance: float, accel_activity: float) -> WornOutput:
        score, hr_c, or_c, ac_c = self._compute_vote(
            hr_quality, orientation_variance, accel_activity)
        instantaneously_worn = score >= self.WORN_THRESHOLD

        # ---- state machine ----
        if self._state == WornState.WORN:
            if not instantaneously_worn:
                if self._not_worn_since is None:
                    self._not_worn_since = timestamp
                elif (timestamp - self._not_worn_since) >= self.NOT_WORN_TIMEOUT_S:
                    self._state = WornState.NOT_WORN
            else:
                self._not_worn_since = None  # reset timer, still worn

        elif self._state == WornState.NOT_WORN:
            if instantaneously_worn:
                # begin gradual wake-up
                self._state = WornState.WAKING_UP
                self._wakeup_start = timestamp
                self._not_worn_since = None

        elif self._state == WornState.WAKING_UP:
            progress = (timestamp - self._wakeup_start) / self.WAKEUP_DURATION_S
            if not instantaneously_worn:
                # taken off again mid-wakeup -> back to not worn
                self._state = WornState.NOT_WORN
                self._not_worn_since = timestamp
                self._wakeup_start = None
            elif progress >= 1.0:
                self._state = WornState.WORN
                self._wakeup_start = None

        wakeup_progress = None
        if self._state == WornState.WAKING_UP:
            wakeup_progress = round(
                min(1.0, (timestamp - self._wakeup_start) / self.WAKEUP_DURATION_S), 3)

        return WornOutput(
            timestamp=timestamp,
            state=self._state,
            vote_score=round(score, 3),
            hr_component=round(hr_c, 3),
            orientation_component=round(or_c, 3),
            accel_component=round(ac_c, 3),
            wakeup_progress=wakeup_progress,
        )

    @property
    def is_worn(self) -> bool:
        return self._state == WornState.WORN

    @property
    def state(self) -> WornState:
        return self._state
