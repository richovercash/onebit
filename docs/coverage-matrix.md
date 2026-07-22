# P1.1 — Algorithm coverage matrix

Documents read and verified, per SPEC §9 T1 exit criterion. The goal is
coverage across issuing countries AND signature algorithms, not a count.

Columns: **parse** = MRZ/DG1/SOD read over NFC; **PA** = passive auth chains to
a CSCA in the bundled master list; **circuit** = provable by a presentation
circuit (mono_faithful for RSA-PKCS1, variants pending for PSS/ECDSA).

| # | Country | Access | DSC alg | Hash | Key size | parse | PA | circuit |
|---|---------|--------|---------|------|----------|-------|----|---------|
| 1 | (first document) | PACE | ? | ? | ? | ✅ | ✅ | — (recapture DSC on next tap) |
| 2 | **USA** | — | RSA PKCS#1 v1.5 | SHA-256 | DSC 2048, CSCA 4096 | ✅ | ✅ | ✅ **fully-real chain: published-root→CSCA→DSC→SOD, all ZK, live** |

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
  the majority algorithm and the likely US case. `mono_faithful_ecdsa` proves an
  **ECDSA (secp256r1 / P-256) DSC** over the same real ICAO CMS structure —
  built + verifies a real P-256-signed SOD (33k gates; negative-tested:
  tampering the signature fails `verify_secp256r1_ecdsa`). Its matching enroll
  variant `enroll_dsc_ecdsa` (RSA-4096 CSCA -> P-256 DSC) commits the same
  `Poseidon2(pubkey x,y)`, so the **faithful ECDSA chain is complete**:
  CSCA->DSC (enroll_dsc_ecdsa) + DSC->SOD (mono_faithful_ecdsa) link by
  `dsc_commit`, with the EC point F1-bound to the signed cert (byte-compare;
  negative-tested). RSA-PSS DSCs are covered by `mono_faithful_pss` (verify_sha256_pss, MGF1-SHA256, 32-byte salt) -- verifies a real RSASSA-PSS SOD; negative-tested. All DSC signature algorithms (RSA PKCS#1, ECDSA P-256, RSA-PSS) now have presentation circuits.

## Next reads to seek (adversarial coverage)

- An **RSA-PSS** DSC document (some EU issuers) — `mono_faithful_pss` is built +
  verifies a real RSASSA-PSS SOD; needs a live PSS document to exercise
  end-to-end. `PssProbe` generates the witness.
- An **ECDSA** DSC document (increasingly common) — `mono_faithful_ecdsa`
  (secp256r1) is built + verifies a real P-256 SOD; needs a live P-256 document
  to exercise end-to-end. `EcdsaCmsProbe` generates the witness.
- A **SHA-1-era legacy** document near end of validity — **time-critical**,
  those expire within ~12 months; read any specimen on sight.
- **RSA-4096** CSCA / DSC — larger bignum params.

## CSCA circuit variants (enrollment)

The enrollment circuit verifies the CSCA→DSC signature. The **real** master-list
key-type distribution — measured by `verifier/js/build_tree.mjs`, counting unique
CSCAs (deduped by SPKI-sha256) — is more diverse than an earlier estimate
assumed (there is no single "160 brainpool / 4 P-384" split; six EC curves
appear, many with inline explicit params):

| CSCA key | Unique | Enroll circuit | Merkle root (published) | Status |
|----------|-------|----------------|-------|--------|
| RSA ≤4096 (2048/3072/4096) | 272 | `enroll` (35-limb, 19k gates) | `0x26e9eb1f…` | ✅ live (US passport) |
| RSA-6144 | 4 | `enroll_rsa6144` (52-limb, 23k gates) | `0x2243af1d…` | ✅ built + verifies |
| brainpoolP256r1 | 14 | `enroll_ecdsa` (43k gates) | `0x248b7481…` | ✅ built + verifies |
| secp384r1 (P-384) | 19 | `enroll_p384` (SHA-384, 298k gates) | `0x28e46754…` | ✅ built + verifies |

Covered: **309 unique CSCAs**, each with a real per-algorithm Merkle tree
(`cscatree_<alg>.json`, depth 10) whose leaf construction matches its circuit
exactly. The RSA-4096 root reproduces the previously published
`0x26e9eb1f…` byte-for-byte (regression check on the generalized builder). All
four roots are published in `verifier/allowlist.json`. Each circuit verifies a
real synthetic cert of its type (CI smoke) and carries the F1 DSC-binding fix.

**Uncovered (need their own enroll variant):** secp256r1 (20), brainpoolP384r1
(52), secp521r1 (20), brainpoolP512r1 (17) — 109 unique EC CSCAs across 4 more
curves. `build_tree.mjs` reports these in its `uncovered` census so the gap is
explicit, not silent. Adding each is a clone of the ECDSA enroll pattern with
the matching curve field/verify (and SHA-384/512 for the larger curves).
