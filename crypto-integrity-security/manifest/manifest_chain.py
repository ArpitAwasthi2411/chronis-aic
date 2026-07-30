"""
Chronis Task 3 — Team C Day 3: Tamper-Evident Manifest Chain + Storage Thresholds.

Daily manifest.sha: an HMAC-SHA256 signature over each day's full file manifest,
signed with a key derived from the Device Identity Key. This makes the canonical
record tamper-EVIDENT, not just append-only.

Storage thresholds (exact spec):
  80% full → pause captures, alert phone, wait 24h for sync
  95% full + no confirmed uploads → urgent alert, throttle to L1/L2
"""

import hmac
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable
from enum import Enum


# ===================== Tamper-Evident Manifest =====================

@dataclass
class FileEntry:
    path: str
    sha256: str
    size_bytes: int
    timestamp: float


@dataclass
class DailyManifest:
    date: str
    files: List[FileEntry] = field(default_factory=list)
    manifest_hmac: Optional[str] = None
    signed: bool = False


class ManifestChain:
    """
    Produces a daily HMAC-SHA256 manifest that makes tampering detectable.

    The HMAC key is derived from the Device Identity Key (DIK) — anyone
    without the DIK cannot forge a valid manifest signature. If a single
    file's checksum is altered after signing, verification fails.
    """

    def __init__(self, dik_derived_key: bytes):
        """dik_derived_key: 32-byte HMAC key derived from DIK."""
        self._key = dik_derived_key
        self.manifests: Dict[str, DailyManifest] = {}

    def add_file(self, date: str, path: str, ciphertext: bytes, timestamp: float):
        if date not in self.manifests:
            self.manifests[date] = DailyManifest(date=date)
        entry = FileEntry(
            path=path,
            sha256=hashlib.sha256(ciphertext).hexdigest(),
            size_bytes=len(ciphertext),
            timestamp=timestamp,
        )
        self.manifests[date].files.append(entry)
        # Manifest needs re-signing after any addition
        self.manifests[date].signed = False

    def sign_manifest(self, date: str) -> str:
        """Compute HMAC-SHA256 over the full file manifest for this date."""
        m = self.manifests.get(date)
        if m is None:
            raise ValueError(f"no manifest for {date}")

        # Canonical JSON of all file entries (sorted by path for determinism)
        entries = sorted([{
            "path": f.path, "sha256": f.sha256,
            "size": f.size_bytes, "timestamp": f.timestamp
        } for f in m.files], key=lambda e: e["path"])

        canonical = json.dumps(entries, sort_keys=True, separators=(',', ':'))
        sig = hmac.new(self._key, canonical.encode(), hashlib.sha256).hexdigest()
        m.manifest_hmac = sig
        m.signed = True
        return sig

    def verify_manifest(self, date: str) -> bool:
        """Recompute HMAC and compare to stored signature. Returns False if tampered."""
        m = self.manifests.get(date)
        if m is None or m.manifest_hmac is None:
            return False

        entries = sorted([{
            "path": f.path, "sha256": f.sha256,
            "size": f.size_bytes, "timestamp": f.timestamp
        } for f in m.files], key=lambda e: e["path"])

        canonical = json.dumps(entries, sort_keys=True, separators=(',', ':'))
        expected = hmac.new(self._key, canonical.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, m.manifest_hmac)

    def tamper_file_checksum(self, date: str, path: str, fake_sha: str):
        """
        TESTING ONLY: simulate an attacker modifying a file's checksum
        in the manifest. verify_manifest() should then return False.
        """
        m = self.manifests.get(date)
        if m is None:
            return
        for f in m.files:
            if f.path == path:
                f.sha256 = fake_sha
                return


# ===================== Storage Threshold Policy =====================

class StorageState(Enum):
    NORMAL = "normal"
    WARNING_80 = "warning_80"         # 80% full
    CRITICAL_95 = "critical_95"       # 95% full, no confirmed uploads


@dataclass
class StorageThresholdPolicy:
    """
    Exact spec thresholds:
      80% full → pause captures, alert phone, wait 24h for sync
      95% full + no confirmed uploads → urgent alert, throttle to L1/L2
    """
    total_mb: int = 512000             # ~512GB SD card
    used_mb: int = 0
    state: StorageState = StorageState.NORMAL
    capture_paused: bool = False
    capture_ceiling: Optional[int] = None   # None = no ceiling, 2 = L2 max
    alerts_sent: List[str] = field(default_factory=list)
    has_confirmed_uploads: bool = False
    _alert_fn: Optional[Callable] = None

    def set_alert_fn(self, fn: Callable):
        self._alert_fn = fn

    def _alert(self, msg: str):
        self.alerts_sent.append(msg)
        if self._alert_fn:
            self._alert_fn(msg)

    @property
    def usage_percent(self) -> float:
        return (self.used_mb / self.total_mb) * 100 if self.total_mb > 0 else 0

    def update(self, used_mb: int, has_confirmed_uploads: bool = False):
        self.used_mb = used_mb
        self.has_confirmed_uploads = has_confirmed_uploads
        pct = self.usage_percent

        if pct >= 95 and not has_confirmed_uploads:
            if self.state != StorageState.CRITICAL_95:
                self.state = StorageState.CRITICAL_95
                self.capture_paused = True
                self.capture_ceiling = 2   # L1/L2 max
                self._alert("URGENT: storage 95%+ full, no confirmed uploads. "
                           "Connect to WiFi immediately. Capture throttled to L1/L2.")
        elif pct >= 80:
            if self.state != StorageState.WARNING_80:
                self.state = StorageState.WARNING_80
                self.capture_paused = True
                self.capture_ceiling = None   # paused, not throttled
                self._alert("Storage 80%+ full. Captures paused. "
                           "Waiting 24h for sync opportunity.")
        else:
            self.state = StorageState.NORMAL
            self.capture_paused = False
            self.capture_ceiling = None

    def effective_level(self, sm_level: int) -> int:
        """Apply storage ceiling on top of state machine level."""
        if self.capture_paused and self.capture_ceiling is not None:
            return min(sm_level, self.capture_ceiling)
        if self.capture_paused:
            return 0  # fully paused
        return sm_level
