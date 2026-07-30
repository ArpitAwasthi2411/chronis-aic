"""Team C — Crypto Hardening, Data Integrity & Security tests."""
import sys, os
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))

from encryption_audit.full_pipeline import (
    FullEncryptionPipeline, FullDecryptionPipeline,
    generate_key_set, dsk_only_decrypt_attempt, EncryptedRecord,
)
from kdf.transport_key import ServerTransportKey, forward_secrecy_test
from manifest.manifest_chain import (
    ManifestChain, StorageThresholdPolicy, StorageState,
)
from ota_gating.apply_gate import (
    OTAApplyGate, GatedOTAApplier, DeviceApplyContext, ApplyBlockReason,
)


# ==================== Day 1: 7-Step Encryption Pipeline ====================

class TestFullEncryptionPipeline:
    def setup_method(self):
        self.dsk, self.upk_priv, self.upk_pub = generate_key_set()
        self.enc = FullEncryptionPipeline(self.dsk, self.upk_pub)
        self.dec = FullDecryptionPipeline(self.dsk, self.upk_priv)

    def test_encrypt_decrypt_roundtrip(self):
        raw = b"sensor data from the locket " * 10
        record = self.enc.encrypt(raw, "imu", 100.0, "sensors", "2026-07-17")
        recovered = self.dec.decrypt(record)
        assert recovered == raw

    def test_vault_path_format(self):
        record = self.enc.encrypt(b"x", "camera", 1.0, "camera", "2026-07-17")
        assert record.vault_path.startswith("/vault/2026-07-17/camera/")
        assert record.vault_path.endswith(".enc")

    def test_checksum_stored(self):
        record = self.enc.encrypt(b"data", "audio", 1.0)
        import hashlib
        assert record.checksum_sha256 == hashlib.sha256(record.ciphertext).hexdigest()

    def test_compression_happens(self):
        raw = b"A" * 10000  # highly compressible
        record = self.enc.encrypt(raw, "imu", 1.0)
        assert record.compressed_size < record.original_size

    def test_unique_nonce_per_file(self):
        r1 = self.enc.encrypt(b"same data", "imu", 1.0)
        r2 = self.enc.encrypt(b"same data", "imu", 2.0)
        assert r1.dsk_nonce != r2.dsk_nonce  # random nonce per file

    def test_CRITICAL_dsk_alone_cannot_decrypt(self):
        """The dual-layer proof: DSK alone must NOT recover plaintext."""
        record = self.enc.encrypt(b"top secret", "imu", 1.0)
        # attacker has the DSK but not the UPK private key
        succeeded = dsk_only_decrypt_attempt(self.dsk, record)
        assert not succeeded, "VULNERABILITY: DSK alone decrypted the data!"

    def test_wrong_upk_cannot_decrypt(self):
        """A different UPK private key cannot decrypt."""
        record = self.enc.encrypt(b"secret", "imu", 1.0)
        _, wrong_priv, _ = generate_key_set()
        wrong_dec = FullDecryptionPipeline(self.dsk, wrong_priv)
        with pytest.raises(Exception):
            wrong_dec.decrypt(record)

    def test_tampered_ciphertext_fails_checksum(self):
        record = self.enc.encrypt(b"data", "imu", 1.0)
        record.ciphertext = record.ciphertext[:-1] + bytes([record.ciphertext[-1] ^ 0xFF])
        with pytest.raises(ValueError):
            self.dec.decrypt(record)


# ==================== Day 2: Forward Secrecy ====================

class TestForwardSecrecy:
    def test_forward_secrecy_holds(self):
        """Compromised long-term key cannot decrypt past sessions."""
        assert forward_secrecy_test() is True

    def test_session_keys_agree(self):
        dev_priv, srv_priv = ServerTransportKey.create_session()
        k1 = ServerTransportKey.derive_session_key(dev_priv, srv_priv.public_key())
        k2 = ServerTransportKey.derive_session_key(srv_priv, dev_priv.public_key())
        assert k1 == k2

    def test_each_session_unique_key(self):
        d1, s1 = ServerTransportKey.create_session()
        d2, s2 = ServerTransportKey.create_session()
        k1 = ServerTransportKey.derive_session_key(d1, s1.public_key())
        k2 = ServerTransportKey.derive_session_key(d2, s2.public_key())
        assert k1 != k2

    def test_upload_encrypt_decrypt(self):
        dev_priv, srv_priv = ServerTransportKey.create_session()
        key = ServerTransportKey.derive_session_key(dev_priv, srv_priv.public_key())
        ct, nonce = ServerTransportKey.encrypt_upload(key, b"payload")
        srv_key = ServerTransportKey.derive_session_key(srv_priv, dev_priv.public_key())
        assert ServerTransportKey.decrypt_upload(srv_key, ct, nonce) == b"payload"


# ==================== Day 3: Tamper-Evident Manifest ====================

class TestManifestChain:
    def setup_method(self):
        self.key = os.urandom(32)  # DIK-derived HMAC key
        self.chain = ManifestChain(self.key)

    def test_sign_and_verify(self):
        self.chain.add_file("2026-07-17", "/vault/2026-07-17/imu/a.enc", b"cipher1", 1.0)
        self.chain.add_file("2026-07-17", "/vault/2026-07-17/imu/b.enc", b"cipher2", 2.0)
        self.chain.sign_manifest("2026-07-17")
        assert self.chain.verify_manifest("2026-07-17") is True

    def test_CRITICAL_tamper_detected(self):
        """Altering a file checksum after signing must be caught."""
        self.chain.add_file("2026-07-17", "/vault/2026-07-17/imu/a.enc", b"cipher1", 1.0)
        self.chain.sign_manifest("2026-07-17")
        assert self.chain.verify_manifest("2026-07-17") is True

        # attacker tampers with a file's checksum entry
        self.chain.tamper_file_checksum("2026-07-17", "/vault/2026-07-17/imu/a.enc",
                                        "deadbeef" * 8)
        assert self.chain.verify_manifest("2026-07-17") is False

    def test_unsigned_manifest_fails_verify(self):
        self.chain.add_file("2026-07-17", "/vault/x.enc", b"c", 1.0)
        assert self.chain.verify_manifest("2026-07-17") is False

    def test_wrong_key_fails_verify(self):
        self.chain.add_file("2026-07-17", "/vault/x.enc", b"c", 1.0)
        self.chain.sign_manifest("2026-07-17")
        # a different key holder cannot verify (or forge)
        other = ManifestChain(os.urandom(32))
        other.manifests = self.chain.manifests  # same files
        assert other.verify_manifest("2026-07-17") is False

    def test_adding_file_invalidates_signature(self):
        self.chain.add_file("2026-07-17", "/vault/a.enc", b"c1", 1.0)
        self.chain.sign_manifest("2026-07-17")
        self.chain.add_file("2026-07-17", "/vault/b.enc", b"c2", 2.0)
        assert self.chain.manifests["2026-07-17"].signed is False


# ==================== Day 3: Storage Thresholds ====================

class TestStorageThresholds:
    def setup_method(self):
        self.policy = StorageThresholdPolicy(total_mb=100000)

    def test_normal_below_80(self):
        self.policy.update(used_mb=50000)  # 50%
        assert self.policy.state == StorageState.NORMAL
        assert not self.policy.capture_paused

    def test_80_percent_pauses_captures(self):
        self.policy.update(used_mb=82000)  # 82%
        assert self.policy.state == StorageState.WARNING_80
        assert self.policy.capture_paused
        assert any("80%" in a for a in self.policy.alerts_sent)

    def test_95_percent_no_uploads_throttles(self):
        self.policy.update(used_mb=96000, has_confirmed_uploads=False)  # 96%
        assert self.policy.state == StorageState.CRITICAL_95
        assert self.policy.capture_ceiling == 2  # L1/L2 max
        assert any("URGENT" in a for a in self.policy.alerts_sent)

    def test_95_percent_with_uploads_stays_warning(self):
        """95% but WITH confirmed uploads → not critical (spec: 95% + no uploads)."""
        self.policy.update(used_mb=96000, has_confirmed_uploads=True)
        assert self.policy.state == StorageState.WARNING_80

    def test_effective_level_throttle(self):
        self.policy.update(used_mb=96000, has_confirmed_uploads=False)
        # state machine wants L5, storage caps at L2
        assert self.policy.effective_level(5) == 2

    def test_recovery_to_normal(self):
        self.policy.update(used_mb=90000)  # warning
        self.policy.update(used_mb=40000)  # back to normal
        assert self.policy.state == StorageState.NORMAL
        assert not self.policy.capture_paused


# ==================== Day 4: OTA Apply Gating ====================

class TestOTAApplyGate:
    def setup_method(self):
        self.gate = OTAApplyGate()

    def test_clear_to_apply_when_idle(self):
        ctx = DeviceApplyContext(cse_level=0, is_syncing=False, is_charging=False)
        assert self.gate.can_apply(ctx)

    def test_blocked_at_L3(self):
        ctx = DeviceApplyContext(cse_level=3)
        assert self.gate.check(ctx) == ApplyBlockReason.HIGH_CAPTURE

    def test_blocked_at_L5(self):
        ctx = DeviceApplyContext(cse_level=5)
        assert not self.gate.can_apply(ctx)

    def test_blocked_while_syncing(self):
        ctx = DeviceApplyContext(cse_level=0, is_syncing=True)
        assert self.gate.check(ctx) == ApplyBlockReason.SYNCING

    def test_blocked_charging_with_active_capture(self):
        ctx = DeviceApplyContext(cse_level=2, is_charging=True)
        assert self.gate.check(ctx) == ApplyBlockReason.CHARGING_ACTIVE_CAPTURE

    def test_allowed_charging_at_L0(self):
        """Charging is fine if CSE is at L0."""
        ctx = DeviceApplyContext(cse_level=0, is_charging=True)
        assert self.gate.can_apply(ctx)

    def test_deferred_applier_retries(self):
        applier = GatedOTAApplier()
        # blocked at L4
        assert not applier.attempt_apply(DeviceApplyContext(cse_level=4))
        assert applier.deferred_count == 1
        # window opens
        assert applier.attempt_apply(DeviceApplyContext(cse_level=0))
        assert applier.applied


# ==================== Day 4: Crash-Log Audit ====================

class TestCrashLogAudit:
    def test_no_user_data_in_crash_logs(self):
        from security_docs.crash_log_audit import audit_fuzzing_crash_logs
        audit = audit_fuzzing_crash_logs(verbose=False)
        assert audit.leaked_logs == 0, \
            f"{audit.leaked_logs} crash logs leaked user data"
        assert audit.total_logs >= 20  # spec: audit at least 20

    def test_audit_catches_planted_leak(self):
        """Sanity: the auditor actually detects leaks when present."""
        from security_docs.crash_log_audit import audit_crash_log
        leaky = "motion_daemon crashed | heart_rate_bpm=87.5 | traceback"
        finding = audit_crash_log(leaky, 0)
        assert finding.leaked is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
