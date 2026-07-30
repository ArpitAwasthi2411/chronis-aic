# Chronis Threat Model

Security threat model for the Chronis wearable device. Covers the four named
adversaries and the specific protection mapped to each.

Scope: this is a planning artifact based on current design, not a completed
external penetration test. The hardware attack surface and firmware reverse-
engineering assessment scoped for later in the build still needs to happen
once real hardware and a stable firmware image both exist.

---

## Adversary 1: Network Attacker (Intercepting Traffic)

**Capability:** can observe, record, and attempt to modify all traffic between
the device and the cloud gateway. A man-in-the-middle on the WiFi network or
upstream.

**What they want:** the sensor data being uploaded, or the ability to inject
false data.

**Protections:**
- **Transport encryption:** all uploads use session-ephemeral ECDH P-256 with
  a fresh key pair per session (`transport_key.py`). The attacker sees only
  ciphertext.
- **Perfect forward secrecy:** even if the attacker records all traffic and
  later compromises a long-term key, past session transcripts cannot be
  decrypted — each session key came from ephemeral keys that no longer exist.
  Proven by `forward_secrecy_test()`.
- **Signature verification at the gateway:** the gateway verifies each payload's
  signature before accepting it. Injected or modified payloads fail verification.
- **Replay protection:** the canonical record DB uses the SHA-256 of the
  ciphertext as the primary key. A replayed payload has the same hash and is
  rejected as a duplicate.

**Residual risk:** traffic analysis (timing and volume of uploads) is still
observable. This reveals when the device is active but not what it captured.

---

## Adversary 2: Malicious Backend Operator

**Capability:** full access to the cloud gateway and canonical record database.
An insider, or an attacker who has compromised the server.

**What they want:** to read user data, or to alter/delete records without
detection.

**Protections:**
- **Dual-layer encryption (DSK + UPK):** the inner layer is encrypted with the
  Data Session Key; the outer layer is wrapped with the User Public Key. The
  backend operator does NOT hold the UPK private key, so they cannot fully
  decrypt records. Knowing the DSK alone is insufficient — proven by
  `dsk_only_decrypt_attempt()`.
- **Tamper-evident manifest chain:** each day's file manifest is signed with
  HMAC-SHA256 using a key derived from the Device Identity Key. A backend
  operator who alters any record's checksum breaks the manifest signature,
  which the device (or an auditor) detects on verification.
- **Append-only canonical record:** the record store enforces append-only at
  the SQLite level (BEFORE UPDATE and BEFORE DELETE triggers). Even direct
  database access cannot silently edit or delete a past record.

**Residual risk:** the backend operator can still refuse to serve data or
delete the entire database (denial of service). Availability is not protected
against a fully-compromised backend — only confidentiality and integrity are.

---

## Adversary 3: Device Theft

**Capability:** physical possession of the device, but no specialized lab
equipment. A pickpocket or opportunistic thief.

**What they want:** the data stored on the device, or to impersonate the device.

**Protections:**
- **Encryption at rest:** all vault data is stored dual-layer encrypted. The
  thief has ciphertext only.
- **Keys in the secure element:** the Device Identity Key never leaves the
  ATECC608B. Reading the SD card directly yields only encrypted files.
- **DSK is never stored:** the Data Session Key is re-derived daily from the
  DIK and the date. It exists only in RAM. Powering off the device destroys it.
- **BLE bond required:** a stolen device will not pair with the thief's phone
  without the Numeric Comparison confirmation on the original owner's setup.
- **Kill-switch and tamper alerts:** the physical privacy slider and tamper
  detection surface to the owner's phone.

**Residual risk:** a thief who powers on the device while the DSK is still in
RAM (device was on when stolen) has a narrow window before the daily rotation.
Mitigated by requiring re-authentication on any BLE reconnect.

---

## Adversary 4: Reverse Engineer with Physical Access

**Capability:** sustained physical access plus lab equipment — logic analyzers,
bus sniffers, potentially chip decapsulation. A determined, well-resourced
attacker.

**What they want:** to extract keys from the secure element, dump firmware, or
find exploitable vulnerabilities.

**Protections:**
- **ATECC608B secure element:** designed to resist key extraction. Keys are
  generated on-chip and never exposed.
- **Encrypted firmware updates:** OTA images are signed (RSA-2048) and
  version-gated against downgrade. A modified firmware image fails signature
  verification.
- **UART/JTAG disabling:** planned for the production build (hardware-dependent,
  on the HARDWARE_ONLY_REMAINING list).
- **Rate limiting and tamper detection:** partial mitigations against sustained
  physical probing.

**Residual risk — HONEST NOTE:** physical key extraction from the ATECC608B is
plausible given lab equipment and sustained physical access. No secure element
is unconditionally tamper-proof against a sufficiently resourced attacker with
unlimited physical access. Rate-limiting and tamper detection are partial
mitigations, not a closed problem. This risk was explicitly deferred in early
planning and remains an accepted, documented risk rather than a solved one.
Full assessment requires the hardware-stage penetration test.

---

## Summary Matrix

| Adversary | Primary Protection | Residual Risk |
|-----------|-------------------|---------------|
| Network attacker | Ephemeral ECDH + forward secrecy | Traffic analysis |
| Malicious backend | Dual-layer encryption + tamper-evident manifest | Availability (DoS) |
| Device theft | Encryption at rest + secure-element keys | Narrow warm-RAM window |
| Reverse engineer | Secure element + signed firmware | Physical key extraction (accepted, documented) |
