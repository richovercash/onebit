# Stage: the enrollment circuit (CSCA→DSC trust, once)

*Implements ADR-005. The expensive, algorithm-diverse CSCA verification, moved
off the presentation path.*

## What it proves

`circuits/enroll` (RSA-4096 CSCA variant), run **once at enrollment**:

1. **CSCA signed the DSC** — RSA-4096 verification of the DSC certificate's TBS
   under the CSCA public key (`SHA256(dsc_tbs)`, variable-length).
2. **CSCA is in the master list** — Poseidon2 Merkle membership of the CSCA
   (leaf = `Poseidon2(csca_modulus)`) to the published root.
3. **Commits the DSC** — outputs `dsc_commit = Poseidon2(dsc_modulus)`.

Output: `(dsc_commit, computed_root)`. The relying party checks
`computed_root == published master-list root` (so the CSCA is genuinely
trusted), and `dsc_commit` is the handle presentation references.

Measured: **141,565 gates** (RSA-4096 dominates), desktop prove ~1.0 s (32T),
verifies. Native on-device ≈ 7–8 s — a **one-time** cost at enrollment, well
within the acceptable envelope (zkPassport enrollment is 10–50 s).

## How it chains to presentation

The two circuits meet at `dsc_commit`:

- **enroll** outputs `dsc_commit = Poseidon2(dsc_modulus)` after proving
  CSCA(-in-tree)→DSC.
- **mono_faithful** already computes `Poseidon2(dsc_modulus)` as its Merkle-leaf
  base while proving DSC→SOD→predicate. Exposing it as a public output makes the
  two proofs chain:

```
enroll:        CSCA(in master-list tree) --signs--> DSC        [dsc_commit, root]
mono_faithful: DSC --signs--> SOD, predicate, nullifier        [dsc_commit, N, ...]
verifier: root == published  AND  enroll.dsc_commit == present.dsc_commit
       => full chain CSCA -> DSC -> SOD, one bit disclosed
```

The full ICAO trust chain is then proven in ZK, split at the right seam:
CSCA→DSC once (expensive, 141k gates), DSC→SOD per presentation (cheap, 79k,
~4.5 s).

## Linkage: DEMONSTRATED

`core/ChainProbe` builds one consistent CSCA-4096 → DSC-2048 → SOD chain and
emits both witnesses from the **same DSC key**. Executing both circuits:

```
enroll         -> (dsc_commit=0x297d7f7d…, root=0x18544688…)
mono_faithful  -> (N=0x25c25b83…, dsc_commit=0x297d7f7d…)
                                   ^^^^^^^^^^^^^^^^^^^^^^^ identical
```

The two circuits agree on `dsc_commit` — the full CSCA→DSC→SOD chain holds in ZK.
`mono_faithful` now outputs `dsc_commit` (no synthetic merkle; 79k→75k gates).

## Remaining wiring (to make it live on device)

1. ~~Expose `dsc_commit` from `mono_faithful` and match it~~ — DONE (above).
   Verifier still needs to receive both proofs and assert the match + `root ==
   published`.
2. **Real master-list Merkle tree** over the CSCA moduli (poseidon2 builder,
   already validated byte-identical to the circuit); wallet supplies the real
   path for its DSC's issuing CSCA.
3. **DSC TBS sizing** — synthetic TBS here is 427 B; real DSC certs run
   ~1–1.4 KB. Size the array to ~1536/2048 (variable-length SHA keeps the cost
   proportional to the real length, not the cap).
4. Wallet: run `enroll` at document read (over the real CSCA→DSC), persist
   `π_enroll`; presentation carries it (or the verifier receives both proofs).
5. **CSCA key-type variants**: RSA-3072/6144 + ECDSA CSCAs need sibling enroll
   circuits (the P1.1 coverage diversity lives here, at the CSCA layer).

## Privacy note

`dsc_commit` is stable per DSC. A DSC signs thousands of passports, so it's a
~10³–10⁴ anonymity set, not a unique ID — but it does reveal *which DSC batch*
signed the holder's document, correlatable across verifiers. For full
unlinkability (V2), presentation would verify `π_enroll` **recursively** and
keep `dsc_commit` private — at the recursion cost measured earlier (~775k gates).
The dsc_commit-matching design is the fast, mostly-private option; recursion is
the maximal-privacy upgrade (Profile P2 territory).
