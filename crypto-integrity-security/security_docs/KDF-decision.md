# KDF Decision: PBKDF2 vs Argon2 for Chronis

## Context

The Chronis wearable derives its Data Session Key (DSK) daily from the
Device Identity Key (DIK) stored in the ATECC608B secure element. The KDF
runs once per day (at midnight) on a low-power ARM target (Radxa Zero 3W,
quad-core Cortex-A55, 1GB RAM).

This decision has been explicitly deferred since Week 1 planning. This
document closes it.

## Candidates

### PBKDF2-HMAC-SHA256
- **How it works:** iterates HMAC-SHA256 a configurable number of times
- **Strengths:** universally available (OpenSSL, every language), FIPS 140-2
  approved, minimal RAM usage (~64 bytes working memory), deterministic
  execution time
- **Weaknesses:** GPU/ASIC-friendly (parallelizable), no memory-hardness
- **On our hardware:** 100,000 iterations completes in ~200ms on Cortex-A55

### Argon2id
- **How it works:** memory-hard function — fills a configurable amount of
  RAM with derived data, then iterates over it. Argon2id combines
  data-dependent (Argon2d) and data-independent (Argon2i) passes.
- **Strengths:** memory-hard (resists GPU/ASIC brute force), winner of the
  Password Hashing Competition (2015), recommended by OWASP
- **Weaknesses:** higher RAM usage (configurable, minimum ~64KB), not FIPS
  approved (may matter for enterprise customers), slightly more complex
  implementation
- **On our hardware:** 64MB memory, 3 iterations completes in ~400ms on
  Cortex-A55

## Analysis for Our Specific Use Case

### What we're protecting against

The DSK derivation is NOT a password hash — it's a key derivation from a
256-bit secret (the DIK) stored in a secure element. An attacker would need
to either:
1. Extract the DIK from the ATECC608B (physical attack, out of scope for KDF)
2. Brute-force a 256-bit key space (infeasible regardless of KDF choice)

This means the primary threat model for the KDF is NOT brute-force password
cracking (where Argon2 excels) but rather key derivation correctness and
side-channel resistance.

### Decision factors

| Factor | PBKDF2 | Argon2id | Winner |
|--------|--------|----------|--------|
| RAM on device (1GB total) | ~64B | ~64MB | PBKDF2 (lower pressure) |
| Execution time (once/day) | ~200ms | ~400ms | Tie (both acceptable) |
| FIPS compliance | Yes | No | PBKDF2 |
| GPU/ASIC resistance | Poor | Excellent | Argon2id |
| Relevance of GPU resistance* | Low | Low | Tie |
| Library availability | Universal | Good (libsodium, hashlib) | PBKDF2 |
| Secure element compatibility | Native ATECC608B support | Needs software impl | PBKDF2 |
| Side-channel resistance | Well-studied | Argon2i variant better | Tie |

*GPU resistance is low-relevance because the source key (DIK) is 256 bits,
not a human-chosen password. Brute-force is infeasible either way.

## Recommendation: PBKDF2-HMAC-SHA256

For this specific use case — deriving a session key from a 256-bit hardware-
stored secret — PBKDF2 is the correct choice:

1. **ATECC608B native support:** The secure element can perform PBKDF2
   internally, meaning the DIK never needs to leave the chip during
   derivation. Argon2 would require extracting a derived value from the chip
   and running the memory-hard function in main RAM — this is a strictly
   weaker security posture.

2. **FIPS compliance:** PBKDF2 is FIPS 140-2 approved. If Chronis ever
   targets enterprise or government customers, this avoids a certification
   blocker.

3. **Resource efficiency:** PBKDF2 uses negligible RAM. On a 1GB device
   running continuous sensor capture, camera, and audio processing, 64MB
   for Argon2 is a meaningful resource cost for minimal security benefit
   (since the source key is already 256 bits).

4. **The brute-force scenario Argon2 protects against doesn't apply here.**
   Argon2's advantage is making password guessing expensive. Our "password"
   is a 256-bit random key — there's nothing to guess.

### Parameters

```
PBKDF2-HMAC-SHA256
  iterations: 100,000
  input: DIK (256-bit, from ATECC608B)
  salt: calendar date as YYYY-MM-DD (ensures daily rotation)
  output: 256-bit DSK
```

### When to revisit

If the threat model changes to include scenarios where the DIK could be a
weak or user-derived secret (e.g., a PIN-based backup key), Argon2id should
be reconsidered for that specific derivation path.
