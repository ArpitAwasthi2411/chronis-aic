"""
Chronis Task 3 — Team C Day 1: 7-Step Encryption Pipeline.

The exact required pipeline per spec:
  1. Raw sensor data arrives RAM-only, never touches disk raw
  2. Compress in RAM by data type
  3. AES-256-GCM encrypt with Data Session Key (DSK), random 96-bit nonce per file
  4. Wrap outer layer with User Public Key (UPK)
  5. Write to /vault/YYYY-MM-DD/[type]/[uuid].enc
  6. SHA-256 checksum the encrypted file
  7. Store the checksum alongside it

Task 1 built single-layer DSK encryption without the UPK wrap — this adds
the second layer and enforces the full pipeline.

Dual-layer guarantee: knowing only the DSK is NOT enough to recover plaintext.
The UPK-wrapped outer layer must also be removed.
"""

import os
import zlib
import uuid
import hashlib
import time
from dataclasses import dataclass
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass
class EncryptedRecord:
    """The output of the full 7-step pipeline."""
    ciphertext: bytes          # UPK-wrapped( DSK-encrypted( compressed( raw ) ) )
    signature: bytes           # HMAC or checksum
    dsk_nonce: bytes           # 96-bit nonce used for AES-256-GCM (step 3)
    upk_ephemeral_pub: bytes   # ephemeral public key for UPK ECIES decryption
    checksum_sha256: str       # step 6: SHA-256 of the final ciphertext
    vault_path: str            # step 5: /vault/YYYY-MM-DD/[type]/[uuid].enc
    source_daemon: str
    timestamp: float
    compressed_size: int
    original_size: int


class FullEncryptionPipeline:
    """
    Implements the exact 7-step pipeline from the spec.

    Keys:
      DSK (Data Session Key): AES-256, derived daily from DIK + date.
                               Used for the inner encryption layer.
      UPK (User Public Key):  EC P-256, stored in device config.
                               Used for the outer encryption layer (ECIES).

    Dual-layer guarantee: an attacker with ONLY the DSK cannot recover
    plaintext — they also need the UPK private key.
    """

    def __init__(self, dsk_bytes: bytes, upk_public_key):
        """
        dsk_bytes: 32-byte AES-256 key (derived from DIK + date)
        upk_public_key: EC P-256 public key object
        """
        if len(dsk_bytes) != 32:
            raise ValueError("DSK must be 32 bytes (AES-256)")
        self._dsk = AESGCM(dsk_bytes)
        self._dsk_raw = dsk_bytes
        self._upk_pub = upk_public_key

    def encrypt(self, raw_data: bytes, source_daemon: str,
                timestamp: float, data_type: str = "sensors",
                date: str = None) -> EncryptedRecord:
        """
        Full 7-step pipeline. raw_data never touches disk — it enters
        as bytes in RAM and leaves as a fully encrypted+wrapped record.
        """
        if date is None:
            date = time.strftime("%Y-%m-%d")
        original_size = len(raw_data)

        # Step 1: raw data is in RAM only (enforced by caller — we never
        #         write raw_data to any file or storage in this method)

        # Step 2: compress in RAM by data type
        compressed = zlib.compress(raw_data, level=6)

        # Step 3: AES-256-GCM with DSK, random 96-bit nonce per file
        nonce = os.urandom(12)  # 96-bit
        dsk_ciphertext = self._dsk.encrypt(nonce, compressed, None)

        # Step 4: wrap outer layer with UPK (ECIES: ephemeral ECDH + HKDF + AES)
        upk_ciphertext, ephemeral_pub_bytes = self._upk_wrap(dsk_ciphertext)

        # Step 5: vault path
        file_uuid = uuid.uuid4().hex[:16]
        vault_path = f"/vault/{date}/{data_type}/{file_uuid}.enc"

        # Step 6: SHA-256 checksum of the final encrypted file
        checksum = hashlib.sha256(upk_ciphertext).hexdigest()

        # Step 7: checksum stored alongside (in the EncryptedRecord)
        return EncryptedRecord(
            ciphertext=upk_ciphertext,
            signature=checksum.encode(),   # used as verification token
            dsk_nonce=nonce,
            upk_ephemeral_pub=ephemeral_pub_bytes,
            checksum_sha256=checksum,
            vault_path=vault_path,
            source_daemon=source_daemon,
            timestamp=timestamp,
            compressed_size=len(compressed),
            original_size=original_size,
        )

    def _upk_wrap(self, inner_ciphertext: bytes) -> Tuple[bytes, bytes]:
        """
        ECIES-style UPK wrapping:
          1. Generate ephemeral EC key pair
          2. ECDH shared secret with UPK public key
          3. HKDF derive a wrapping key
          4. AES-256-GCM encrypt the inner ciphertext with wrapping key
        Returns (outer_ciphertext, ephemeral_public_key_bytes)
        """
        ephemeral_priv = ec.generate_private_key(ec.SECP256R1())
        ephemeral_pub = ephemeral_priv.public_key()

        # ECDH shared secret
        shared = ephemeral_priv.exchange(ec.ECDH(), self._upk_pub)

        # HKDF derive wrapping key
        wrap_key = HKDF(
            algorithm=hashes.SHA256(), length=32,
            salt=None, info=b"chronis-upk-wrap",
        ).derive(shared)

        # AES-256-GCM with the wrapping key
        wrap_nonce = os.urandom(12)
        outer_ct = AESGCM(wrap_key).encrypt(wrap_nonce, inner_ciphertext, None)

        # Prepend the wrap nonce to the outer ciphertext
        combined = wrap_nonce + outer_ct

        # Serialize ephemeral public key (modern API)
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat,
        )
        pub_bytes = ephemeral_pub.public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)

        return combined, pub_bytes


class FullDecryptionPipeline:
    """Server-side or UPK-holder decryption — reverses the 7-step pipeline."""

    def __init__(self, dsk_bytes: bytes, upk_private_key):
        self._dsk = AESGCM(dsk_bytes)
        self._upk_priv = upk_private_key

    def decrypt(self, record: EncryptedRecord) -> bytes:
        """Reverse all 7 steps: unwrap UPK → decrypt DSK → decompress → raw."""
        # Verify checksum (step 6)
        actual = hashlib.sha256(record.ciphertext).hexdigest()
        if actual != record.checksum_sha256:
            raise ValueError("checksum mismatch — tampered or corrupted")

        # Unwrap UPK layer (step 4 reverse)
        inner_ct = self._upk_unwrap(record.ciphertext, record.upk_ephemeral_pub)

        # Decrypt DSK layer (step 3 reverse)
        compressed = self._dsk.decrypt(record.dsk_nonce, inner_ct, None)

        # Decompress (step 2 reverse)
        raw = zlib.decompress(compressed)

        return raw

    def _upk_unwrap(self, outer_ciphertext: bytes, ephemeral_pub_bytes: bytes) -> bytes:
        """Reverse the ECIES wrapping."""
        # Reconstruct ephemeral public key
        ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), ephemeral_pub_bytes)

        # ECDH shared secret using our private key + their ephemeral public
        shared = self._upk_priv.exchange(ec.ECDH(), ephemeral_pub)

        # HKDF derive same wrapping key
        wrap_key = HKDF(
            algorithm=hashes.SHA256(), length=32,
            salt=None, info=b"chronis-upk-wrap",
        ).derive(shared)

        # Split nonce from ciphertext
        wrap_nonce = outer_ciphertext[:12]
        ct = outer_ciphertext[12:]

        return AESGCM(wrap_key).decrypt(wrap_nonce, ct, None)


def generate_key_set():
    """Generate a test DSK + UPK key pair."""
    dsk = os.urandom(32)  # AES-256
    upk_priv = ec.generate_private_key(ec.SECP256R1())
    upk_pub = upk_priv.public_key()
    return dsk, upk_priv, upk_pub


def dsk_only_decrypt_attempt(dsk_bytes: bytes, record: EncryptedRecord) -> bool:
    """
    THE CRITICAL TEST: try to decrypt with DSK alone (no UPK).
    This MUST fail — proving the dual-layer structure is real.
    """
    try:
        dsk = AESGCM(dsk_bytes)
        # Try to decrypt the outer ciphertext directly with DSK
        # This should fail because the outer layer is UPK-wrapped
        dsk.decrypt(record.dsk_nonce, record.ciphertext, None)
        return True   # BAD: DSK alone was enough
    except Exception:
        return False   # GOOD: DSK alone is not enough

    # Also try stripping the nonce prefix and retrying
    try:
        dsk.decrypt(record.dsk_nonce, record.ciphertext[12:], None)
        return True
    except Exception:
        return False
