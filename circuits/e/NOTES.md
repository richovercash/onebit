# Circuit E — enrollment proof (P1.0 — CLOSED 2026-07-21; this circuit superseded)

**Status: P1.0 is done, but not via this circuit.** The recursion it was built
for (Circuit P v1 verifying π_E in-circuit) was proven sound and measured at
20.3 s/presentation on the Pixel 9a — slower than just redoing the signature
check. The shipped design is ADR-003's two-circuit split: `enroll`
(CSCA→DSC, real master-list Merkle tree) + `mono_faithful` (DSC→SOD),
chained by `dsc_commit`; plus `present_amortized` for the Tier A sub-second
path. Circuits `e/` and `p/` stay as the working recursion pattern for
multi-credential aggregation and the V2 unlinkability upgrade. Historical
notes below.

Proves: SHA256(DG1) in eContent, RSA-2048 PKCS#1v1.5 DSC signature over
eContent, DSC in a depth-20 Poseidon Merkle tree, and C = Poseidon2(dob,
expiry, docHash, k, salt) with dates resolved by the SPEC §3.1 century rule.

Output: (C, computed R_icao root). Circuit P will take π_E as a PRIVATE input,
verify it in-circuit, assert the root equals the pinned published root, and
re-derive C from private (dob, expiry, docHash, k, salt) to bind the predicate
attributes to a validly-signed document — so C never leaves the device.

Measured (i9-13900KF/32T, bb 4.2.0): 177,495 UltraHonk gates, ~1.05 s prove,
proof verifies. Enrollment is one-time and cached.

## Original P1.0 checklist — all resolved
- [x] Circuit P v1 recursion + C-rebind: built, verifies, measured 20.3 s
      native on Pixel 9a (docs/measurement-recursion-on-device.md) → decision:
      don't recurse per presentation (ADR-003).
- [x] Coverage variants: enroll_{ecdsa,p384,bp384,bp512,secp256,secp521,
      rsa6144,dsc_ecdsa}, mono_faithful_{ecdsa,pss} all exist and route.
- [x] Real Merkle tree: built over the bundled master list
      (verifier/js/build_tree.mjs, 272 CSCAs, published root) — in the
      `enroll` circuit, not this one; this circuit's path stays synthetic.
- [x] docHash preimage: Poseidon(SHA256(eContent)) — eContent embeds the DG
      hash set unique per personalization, so cross-document uniqueness holds;
      carried into `commit` and the sealed credential.
