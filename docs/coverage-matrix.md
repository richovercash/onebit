# P1.1 — Algorithm coverage matrix

Documents read and verified, per SPEC §9 T1 exit criterion. The goal is
coverage across issuing countries AND signature algorithms, not a count.

Columns: **parse** = MRZ/DG1/SOD read over NFC; **PA** = passive auth chains to
a CSCA in the bundled master list; **circuit** = provable by a presentation
circuit (mono_faithful for RSA-PKCS1, variants pending for PSS/ECDSA).

| # | Country | Access | DSC alg | Hash | Key size | parse | PA | circuit |
|---|---------|--------|---------|------|----------|-------|----|---------|
| 1 | (first document) | PACE | ? | ? | ? | ✅ | ✅ | — (details uncaptured) |
| 2 | **USA** | ? | ? (typ. RSA-2048 PKCS#1) | ? (typ. SHA-256) | ? | ✅ | ✅ | likely mono_faithful (RSA-PKCS1) |

## Status

- **2 documents read + passively authenticated offline** (≥1 country; need ≥3
  and RSA-PKCS1 / RSA-PSS / ECDSA all represented for the exit criterion).
- **DSC crypto details for both are uncaptured** — the `?` cells. Capturing the
  actual DSC algorithm/hash/key-size needs a logcat read (the wallet parses the
  DSC during PA; a debug line would surface `DSC.getSigAlgName()` +
  `RSAPublicKey.getModulus().bitLength()`). Do this on the next tap of each doc.
- **circuit column**: `mono_faithful` proves RSA-2048 PKCS#1v1.5 / SHA-256 —
  the majority algorithm and the likely US case. PSS and ECDSA are separate
  compiled variants (P1.1 remaining), sharing the same shape.

## Next reads to seek (adversarial coverage)

- An **RSA-PSS** DSC document (some EU issuers) — needs the PSS circuit variant.
- An **ECDSA** DSC document (increasingly common; cheaper in-circuit) — needs
  the ECDSA variant (noir-ecdsa).
- A **SHA-1-era legacy** document near end of validity — **time-critical**,
  those expire within ~12 months; read any specimen on sight.
- **RSA-4096** CSCA / DSC — larger bignum params.
