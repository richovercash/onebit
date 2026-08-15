---
projectId: onebit
severity: high
status: open
created_at: 2026-08-15T03:16:42.915Z
---

# Nullifier key k unconstrained in mono_faithful / mono_slim (soundness)

**Severity:** high
**Status:** open

## Details

Source: multi-agent whole-repo review (2026-08-14), adversarially verified HIGH. Duplicate/confirmation of self-review F2 (docs/self-review-circuits.md).

circuits/mono_faithful/src/main.nr:68 and circuits/mono_slim/src/main.nr:60 compute the nullifier N = Poseidon2([k, ctx]) where k is a free private witness never constrained to the document, DSC modulus, DG1 attributes, or any commitment C. Unlike present_amortized / p (which pin k to the sealed commitment via a rebind assert), these circuits impose no binding.

Failure: one holder of a single valid credential can enumerate arbitrary k values and generate an unbounded set of accepting proofs, each with a distinct nullifier — defeating per-(verifier, epoch) uniqueness (double-presentation / one-person-one-vote / Sybil resistance). SE-sealing of k and device attestation are extrinsic mitigations only; they do not restore soundness for a holder who re-reads their own chip with a custom prover.

FIX (deferred — needs circuit rework + re-proving + SRS): bind k in-circuit to the credential commitment C (assert C == commit(...k...)), matching present_amortized. Both live presentation circuits (mono_slim = P0, mono_faithful = faithful rail) must be updated and re-verified end to end. Tracked separately from the Java fixes because it is a soundness change, not a patch.

Related: SPEC §4.1 ("Circuit proves consistency of k with C").
