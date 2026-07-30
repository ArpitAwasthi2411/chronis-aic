"""
Chronis Task 3 — Team C Day 4: OTA Apply-Window Gating.

Tightens when an OTA update may actually be APPLIED (not just downloaded).
Beyond "never mid-session", the update must be blocked when:
  1. CSE (capture state machine) is at L3 or higher
  2. The device is currently syncing
  3. The device is charging with CSE above L0

Each condition is tested individually. An update that passes signature and
hash verification still waits in the pending partition until the apply-window
is clear.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


class ApplyBlockReason(Enum):
    NONE = "clear_to_apply"
    HIGH_CAPTURE = "cse_at_L3_or_higher"
    SYNCING = "sync_in_progress"
    CHARGING_ACTIVE_CAPTURE = "charging_with_cse_above_L0"


@dataclass
class DeviceApplyContext:
    """The device state the apply-window gate checks against."""
    cse_level: int = 0          # current capture-intensity level (0-5)
    is_syncing: bool = False
    is_charging: bool = False


class OTAApplyGate:
    """
    Decides whether a verified, pending OTA update may be applied right now.

    The three blocking conditions are checked in order. If any is active,
    the update stays pending and apply is deferred.
    """

    def check(self, ctx: DeviceApplyContext) -> ApplyBlockReason:
        # Condition 1: never while CSE is at L3 or higher
        if ctx.cse_level >= 3:
            return ApplyBlockReason.HIGH_CAPTURE

        # Condition 2: never while syncing
        if ctx.is_syncing:
            return ApplyBlockReason.SYNCING

        # Condition 3: never while charging with CSE above L0
        if ctx.is_charging and ctx.cse_level > 0:
            return ApplyBlockReason.CHARGING_ACTIVE_CAPTURE

        return ApplyBlockReason.NONE

    def can_apply(self, ctx: DeviceApplyContext) -> bool:
        return self.check(ctx) == ApplyBlockReason.NONE


class GatedOTAApplier:
    """
    Wraps the apply step with the gate. Retries when the window opens.
    """
    def __init__(self):
        self.gate = OTAApplyGate()
        self.deferred_count = 0
        self.applied = False
        self.defer_log: List[str] = []

    def attempt_apply(self, ctx: DeviceApplyContext) -> bool:
        reason = self.gate.check(ctx)
        if reason != ApplyBlockReason.NONE:
            self.deferred_count += 1
            self.defer_log.append(reason.value)
            return False
        self.applied = True
        return True
