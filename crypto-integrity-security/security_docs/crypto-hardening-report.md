# Crypto Hardening & Security Report

**Chronis Task 3 — Team C: Crypto Hardening, Data Integrity & Security**
**Verdict: encryption brought to full 7-step spec, data made tamper-evident,
security posture documented.**

---

## Summary

| Deliverable | Status | Tests |
|-------------|--------|-------|
| 7-step encryption pipeline (DSK + UPK dual-wrap) | Complete | 8 |
| Forward-secret transport key (ephemeral ECDH) | Complete | 4 |
| KDF decision (PBKDF2 vs Argon2) | Documented | — |
| Tamper-evident manifest chain (HMAC-SHA256) | Complete | 5 |
| Storage threshold enforcement (80% / 95%) | Complete | 6 |
| OTA apply-window gating (3 conditions) | Complete | 7 |
| Crash-log privacy audit | Complete | 2 |
| THREAT_MODEL.md (4 adversaries) | Documented | — |
| DISCLOSURE_POLICY.md | Documented | — |
| **Total Team C tests** | | **32** |

---

## Day 1: Encryption Pipeline Audit + UPK Wrap

Audited the Task 1 pipeline against the 7-step spec. Found two gaps:
compression (step 2) was skipped, and — critically — the **UPK outer-wrap
layer (step 4) was entirely missing**. Task 1 used single-layer DSK encryption,
meaning a DSK compromise would expose all data.

Team C implemented the full pipeline with ECIES-style UPK wrapping. The result
is dual-layer: `UPK-wrap( AES-256-GCM-DSK( compress( raw ) ) )`.

**Key proof:** `test_CRITICAL_dsk_alone_cannot_decrypt` confirms that an
attacker holding the DSK still cannot decrypt the data — the UPK private key is
also required.

See `ENCRYPTION_PIPELINE_AUDIT.md` for the full step-by-step audit.

---

## Day 2: Forward Secrecy + KDF Decision

**Transport key:** Implemented session-ephemeral ECDH P-256. Each upload
session generates a fresh key pair; session keys are derived via ECDH + HKDF.

**Forward secrecy proof:** `forward_secrecy_test()` simulates an attacker who
obtains a long-term key AFTER a session and has a recording of the session
traffic. The attacker cannot derive the session key, because it came from
ephemeral keys that no longer exist. Test passes.

**KDF decision:** Closed the long-deferred PBKDF2-vs-Argon2 question. Decision:
**PBKDF2-HMAC-SHA256**, because the source key is a 256-bit hardware secret (not
a human password), the ATECC608B supports PBKDF2 natively (key never leaves the
chip), and it is FIPS-approved. Argon2's memory-hardness protects against
password brute-forcing, which does not apply to a 256-bit random key. Full
reasoning in `KDF-decision.md`.

---

## Day 3: Tamper-Evident Manifest + Storage Thresholds

**Manifest chain:** Each day's file manifest is signed with HMAC-SHA256 using a
key derived from the Device Identity Key. This makes the canonical record
tamper-EVIDENT, not just append-only. If any file's checksum is altered after
signing, `verify_manifest()` returns False.

**Key proof:** `test_CRITICAL_tamper_detected` signs a manifest, tampers with a
file checksum, and confirms verification fails.

**Storage thresholds:** Implemented the exact spec policy:
- 80% full → pause captures, alert phone, wait 24h for sync
- 95% full + no confirmed uploads → urgent alert, throttle to L1/L2

The `effective_level()` method applies the storage ceiling on top of the state
machine level, mirroring the power-ceiling pattern.

---

## Day 4: OTA Gating + Security Docs + Crash Audit

**OTA apply-window gating:** A verified update still waits in the pending
partition until the apply-window is clear. Three blocking conditions:
1. CSE at L3 or higher (don't interrupt a high-value capture)
2. Device is syncing
3. Device is charging with CSE above L0

Each condition is individually tested.

**Crash-log privacy audit:** Audited the crash logs from Task 2's fuzzing runs
for user-data leakage. **This caught a real bug:** the fuzz harness was logging
full daemon output objects, which included `heart_rate_bpm` values. Even in a
debug crash log, capturing user heart-rate data is a privacy violation. Team C
fixed the harness to log daemon STATE only (type, validity, status enums),
never user-data values. Post-fix audit: 67 crash logs, 0 leaks.

**Security documentation:**
- `THREAT_MODEL.md` — four named adversaries (network attacker, malicious
  backend, device theft, reverse engineer) with the specific protection mapped
  to each, and honest residual-risk notes. The physical key-extraction risk is
  documented as an accepted, deferred risk rather than a solved problem.
- `DISCLOSURE_POLICY.md` — responsible disclosure policy draft for
  chronis.in/security, with a 48-hour acknowledgment and 90-day remediation
  commitment, safe-harbor terms, and coordinated-disclosure timeline.

---

## Cross-Task Finding

The crash-log audit surfaced a genuine privacy leak in Task 2's fuzzing harness
(heart-rate values in debug logs). This is exactly the kind of issue a security
audit is meant to find — a component that was itself built to harden the system
had a small privacy gap in its own logging. Fixed, with a regression test
(`test_no_user_data_in_crash_logs`) that re-audits every fuzz crash log.

---

## Honest Scope Notes

- The encryption uses the `cryptography` library's vetted primitives
  (AES-256-GCM, EC P-256, HKDF, HMAC-SHA256) — not hand-rolled crypto.
- The UPK wrap is ECIES-style; a production implementation would pin the exact
  KEM/DEM parameters and add key-committing AEAD considerations.
- The threat model is a design-stage document. The hardware attack surface and
  firmware reverse-engineering assessment still require real hardware and a
  stable firmware image, and are explicitly listed as remaining work.
- The disclosure policy is a draft for review by whoever owns
  chronis.in/security, not a published commitment.
