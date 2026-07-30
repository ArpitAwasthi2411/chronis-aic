# Encryption Pipeline Audit

Audit of the Chronis encryption pipeline against the full 7-step specification.
Identifies what Task 1 built, what was missing, and what Team C added to close
the gap.

---

## The Required 7-Step Pipeline

Per spec, every piece of sensor data must pass through:

1. **Raw data arrives RAM-only** — never touches disk in plaintext
2. **Compress in RAM** by data type
3. **AES-256-GCM encrypt** with the Data Session Key (DSK), random 96-bit
   nonce per file
4. **Wrap outer layer** with the User Public Key (UPK)
5. **Write** to `/vault/YYYY-MM-DD/[type]/[uuid].enc`
6. **SHA-256 checksum** the encrypted file
7. **Store the checksum** alongside it

---

## Audit Findings

### What Task 1 built

Task 1 (HW-1 mock storage and HW-2 encryption daemon) implemented steps 1, 3,
5, 6, and 7:
- Raw data was handled in RAM and passed to the encryption daemon
- AES-256-GCM encryption with a session key was present (HW-2's daemon)
- Vault path structure was correct
- SHA-256 checksums were computed and stored

### Gap identified: missing steps 2 and 4

**Step 2 (compression):** Task 1 encrypted raw bytes directly without the
per-type compression stage. This is a functional gap — encrypted data does not
compress, so compression must happen before encryption. Storing uncompressed
data wastes the limited on-device storage.

**Step 4 (UPK outer wrap):** THIS WAS THE CRITICAL GAP. Task 1 used
single-layer DSK encryption only. The spec requires a second, outer layer
wrapped with the User Public Key. Without it, anyone who obtains the DSK — which
is derived on-device and exists in RAM — can decrypt all data. The UPK layer
ensures that even a full DSK compromise is insufficient: the attacker also
needs the UPK private key, which stays with the user.

### What Team C added

`encryption_audit/full_pipeline.py` implements all 7 steps:

- **Step 2:** `zlib.compress()` before encryption, by data type
- **Step 4:** ECIES-style UPK wrapping — ephemeral EC P-256 key pair, ECDH with
  the UPK public key, HKDF-derived wrapping key, AES-256-GCM outer encryption

The dual-layer structure is:
```
UPK-wrap( AES-256-GCM-DSK( zlib-compress( raw_data ) ) )
```

---

## The Dual-Layer Proof

The whole point of step 4 is that DSK-alone is not enough. This is proven by
`dsk_only_decrypt_attempt()`, which:

1. Takes a fully-encrypted record
2. Gives an attacker the DSK (simulating a full DSK compromise)
3. Attempts to decrypt the outer ciphertext with the DSK
4. Confirms the attempt FAILS

Test `test_CRITICAL_dsk_alone_cannot_decrypt` verifies this. A second test,
`test_wrong_upk_cannot_decrypt`, confirms that even a different UPK private key
cannot recover the data — only the correct UPK holder can.

---

## Verification Summary

| Step | Task 1 | Team C | Test |
|------|--------|--------|------|
| 1. RAM-only raw | Present | Preserved | (design) |
| 2. Compress by type | Missing | Added | `test_compression_happens` |
| 3. AES-256-GCM + DSK, random nonce | Present | Preserved | `test_unique_nonce_per_file` |
| 4. UPK outer wrap | **Missing** | **Added** | `test_CRITICAL_dsk_alone_cannot_decrypt` |
| 5. Vault path | Present | Preserved | `test_vault_path_format` |
| 6. SHA-256 checksum | Present | Preserved | `test_checksum_stored` |
| 7. Store checksum | Present | Preserved | `test_checksum_stored` |

Full round-trip (encrypt then decrypt) verified by `test_encrypt_decrypt_roundtrip`.
Tamper detection verified by `test_tampered_ciphertext_fails_checksum`.
