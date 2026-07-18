# Circuit E — enrollment proof (P1.0, in progress)

Proves: SHA256(DG1) in eContent, RSA-2048 PKCS#1v1.5 DSC signature over
eContent, DSC in a depth-20 Poseidon Merkle tree, and C = Poseidon2(dob,
expiry, docHash, k, salt) with dates resolved by the SPEC §3.1 century rule.

Output: (C, computed R_icao root). Circuit P will take π_E as a PRIVATE input,
verify it in-circuit, assert the root equals the pinned published root, and
re-derive C from private (dob, expiry, docHash, k, salt) to bind the predicate
attributes to a validly-signed document — so C never leaves the device.

Measured (i9-13900KF/32T, bb 4.2.0): 177,495 UltraHonk gates, ~1.05 s prove,
proof verifies. Enrollment is one-time and cached.

## Remaining for P1.0
- [ ] Circuit P v1: `std::verify_proof(π_E)` recursion + C-rebind assertion;
      re-measure on Pixel 9a (Circuit P currently v0, binding:"P-only").
- [ ] Coverage variants (P1.1): RSA-PSS, ECDSA (noir-ecdsa), RSA-4096.
- [ ] Real Merkle root over the bundled CSCA master list (currently synthetic
      path); wire the same tree builder into the verifier + wallet.
- [ ] docHash preimage decision: currently Poseidon(eContent hash); confirm it
      is the right document-identity binding for cross-doc uniqueness.
