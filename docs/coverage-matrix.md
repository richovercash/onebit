# P1.1 — Algorithm coverage matrix

Documents read and verified, per SPEC §9 T1 exit criterion. The goal is
coverage across issuing countries AND signature algorithms, not a count.

Columns: **parse** = MRZ/DG1/SOD read over NFC; **PA** = passive auth chains to
a CSCA in the bundled master list; **circuit** = provable by a presentation
circuit (mono_faithful for RSA-PKCS1, variants pending for PSS/ECDSA).

| # | Country | Access | DSC alg | Hash | Key size | parse | PA | circuit |
|---|---------|--------|---------|------|----------|-------|----|---------|
| 1 | (first document) | PACE | ? | ? | ? | ✅ | ✅ | — (recapture DSC on next tap) |
| 2 | **USA** | — | RSA PKCS#1 v1.5 | SHA-256 | 2048 | ✅ | ✅ | ✅ **mono_faithful — real document proven end-to-end** |

## Status

- **USA passport proven END TO END with its real bytes** (2026-07-18): the
  wallet extracted the live SOD's eContent (180 B) / signedAttrs (104 B) /
  signature into the `mono_faithful` witness, proved it natively in **4.5 s**,
  and the gate GRANTED with a real nullifier. `binding=document`. Real ICAO CMS
  passive authentication now happens inside the ZK circuit for a real document —
  not a representative one. Only the CSCA Merkle-root check remains synthetic.
- Still need **RSA-PSS** and **ECDSA** documents to exercise those variants, and
  a document #1 DSC recapture (tap it again — the app now logs `ONEBIT_COVERAGE`).
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
