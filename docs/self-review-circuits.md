# P1.3 — Circuit self-review

Hand-check of every `assert` in the live circuits against the SPEC statement and
against soundness (can a malicious prover satisfy the circuit with a false
claim?). This is the cheap bug-hunt before an external audit.

Circuits reviewed: `mono_faithful` (presentation), `enroll` (RSA CSCA),
`enroll_ecdsa` (brainpoolP256r1 CSCA).

## Findings

### F1 — CRITICAL (FIXED): committed DSC not bound to the signed certificate

`enroll` verified the CSCA signature over `dsc_tbs`, then committed
`dsc_commit = Poseidon2(dsc_modulus)` — but `dsc_modulus` was a **free witness**,
never checked against the DSC public key *inside* `dsc_tbs`.

**Exploit:** an attacker holding any real CSCA→DSC_A chain (a genuine passport's
DSC) commits their *own* key DSC_B. The enroll proof then falsely attests "a
master-list CSCA signed a DSC committing to DSC_B." At presentation,
`mono_faithful` signs a forged SOD (any DOB) with DSC_B; the two `dsc_commit`s
match; the chain "verifies." → forgeable age proof.

**Fix:** reconstruct the 18 little-endian 120-bit limbs from the 256 big-endian
modulus bytes at `dsc_modulus_off` inside `dsc_tbs` and assert equality with
`dsc_modulus`. Now the committed key must be the one the CSCA actually signed.
Applied to both `enroll` and `enroll_ecdsa`. Negative test: tampering
`dsc_modulus` fails the constraint. Cost: ~small (256 byte reads); enroll
212k→~213k, enroll_ecdsa 249k→256k gates.

### F2 — MEDIUM: nullifier key `k` is unconstrained in `mono_faithful`

`N = Poseidon2([k, ctx])` with `k` a free witness. Nothing ties `k` to the
document, so a prover can pick a different `k` per presentation → unlimited
distinct nullifiers from one document → defeats the epoch rate-limit and the
"proof farm" mitigation (SPEC §7) **at the circuit level**.

Today this rests on: the attested wallet uses the SE-sealed `k` (fixed per
credential), and device attestation (T3) gates the honest wallet. But the
persisted witness is **not yet SE-wrapped** (P1.5), so extracting it and running
a custom prover with varying `k` is currently feasible.

**Mitigations:** (a) P1.5 SE-wrap of `docwit.txt` / credential — near-term,
raises the bar to SE compromise; (b) bind `k` in-circuit — re-introduce a
per-document commitment `C = Poseidon(dob, expiry, docHash, k, salt)` (as the
SPEC specifies) and prove the presentation's `k` matches the enrolled `C`. (b)
is the real fix; (a) is the interim. Tracked for the next circuit pass.

## Notes (accepted / documented, not bugs)

- **N3 — RSA exponent hardcoded 65537.** `verify_sha256_pkcs1v15(…, 65537)`.
  Fails closed for the rare e≠65537 DSC. Parameterize when such a doc appears.
- **N4 — TD3 MRZ layout assumed.** `full_date` reads DG1 at fixed offsets
  (MRZ_OFF+57 / +65). Correct for passports (TD3); TD1/TD2 ID cards need a
  variant. DG1 is bound by the signature, so this is a coverage assumption, not
  a soundness hole.
- **N5 — century-window false-negatives.** `yy > cur_yy+10 → 19YY` (SPEC §3.1).
  A holder born >~90 years before `current` resolves to a future year and FAILS
  the age check. Fail-closed in the safe direction (never grants underage); a
  known spec heuristic. Documented.
- **N6 — ECDSA low-s required.** `verify_brainpoolp256r1_ecdsa` enforces
  canonical low-s (anti-malleability). X.509 ECDSA sigs are not required to be
  low-s, so the wallet's extraction MUST normalize `s → n−s` when `s > n/2`
  (both are valid signatures). Implemented in the probe; the real ECDSA
  extraction path must do the same.

## Verified-sound (spot checks that passed)

- **Offsets/lengths as witnesses** (`dg1_hash_off`, `econtent_hash_off`,
  `econtent_len`, `signed_attrs_len`): all bound by the hash→signature chain.
  A wrong length/offset changes a hash → breaks the RSA verify → fails closed.
  Out-of-bounds indices fail proving (Noir constrains array access).
- **Merkle membership** (`enroll`): reaching the published root from a fake
  leaf/path requires a Poseidon2 collision. `csca_modulus` used both in the sig
  verify and the leaf, so the CSCA that signed the DSC is the one in the tree.
- **dsc_commit linkage**: `mono_faithful` and `enroll` both commit
  `Poseidon2(dsc_modulus)`; verifier asserts equality → binds the two proofs to
  the same DSC. With F1 fixed, that DSC is provably CSCA-signed.
