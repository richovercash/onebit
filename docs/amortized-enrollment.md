# Amortized enrollment — fast presentations without per-presentation recursion

*P1.0 follow-up. Read `measurement-recursion-on-device.md` and
`stage-circuits-E-and-P.md` first.*

## The problem

The recursive Circuit P v1 makes the credential binding real — it verifies the
enrollment proof π_E in-circuit so the birth date feeding the age check is
provably from a signed document, and `C` never leaves the device. But verifying
a Honk proof inside a circuit costs ~775k gates → **20.3 s per presentation on
the Pixel 9a** (measured, native, multi-threaded). Four times the <5 s budget.

The recursion cost is *entirely* the in-circuit verification of π_E. That
verification does not need to happen on every age check — the document doesn't
change between presentations.

## The idea

Move the expensive, one-time facts to **enrollment**, and make presentations
prove only what changes per challenge.

```
ENROLLMENT (once per document, heavy cost acceptable — think 10-30 s)
  1. Passive auth: verify CSCA -> DSC -> SOD -> DG1 (already implemented).
  2. Extract dob, expiry; doc_hash = Poseidon2(H(eContent)).
  3. Sample k (nullifier PRF key), salt. Compute
       C = Poseidon2([dob, expiry, doc_hash, k, salt], 5).
  4. Seal (dob, expiry, doc_hash, k, salt, C) in the secure element (Seal.java).

PRESENTATION (every age check — sub-second)
  circuits/present_amortized proves, over the sealed attributes:
    - rebind:   C == Poseidon2([dob, expiry, doc_hash, k, salt], 5)
    - predicate: dob + age_min*10000 <= current   AND   expiry >= current
    - nullifier: N = Poseidon2([k, ctx])
  Output: N. Nothing else leaves the device.
```

`present_amortized` is Circuit P v1's tail with the recursion (lines 1-3:
pin-vkey / verify_proof / root-check) deleted. **26 ACIR opcodes.**

## Measured (Pixel 9a, native noir-rs, 3 runs)

| Circuit | Per-presentation | Notes |
|---|---|---|
| Circuit P v1 (recursion) | **20.3 s** | verifies π_E in-circuit; 775k gates; 512 MB SRS |
| mono_faithful | ~2.5 s | re-does full passive auth every presentation |
| **present_amortized** | **~0.8 s** | 777 / 792 / 892 ms; 32k-point SRS (2 MB); verifies |

25× faster than recursion, comfortably under budget, and under the original
3.74 s T5 demo figure.

## What this closes, and what it trades

**F2 (nullifier farming) — closed at the circuit level for Tier A.** The rebind
ties the nullifier key `k` to the enrolled commitment `C`, so a given credential
yields exactly one `k` → one `N` per (verifier, epoch). A wallet cannot present
with a `k` that doesn't open its sealed `C` — negative-tested: bumping `k` while
holding `C` fails the rebind constraint (`Cannot satisfy constraint` at
main.nr:38). Combined with the SE-sealed single `C` per credential (P1.5) and
device attestation (T3), the "extract witness + vary `k`" path is shut.

**The trade — this is Tier A (SPEC §7.3).** The document's *provenance* (that
`C` commits attributes of a genuinely government-signed passport) is established
once at enrollment by the attested wallet and is **not re-proven in ZK to the
verifier** on each presentation. The verifier trusts hardware attestation that
an unmodified wallet enrolled honestly. The ZK proof still discloses exactly one
bit + a nullifier — attestation vouches for *document validity*, the proof
vouches for *the predicate over the committed attributes*.

Contrast with the current dual-proof path (enroll π + mono_faithful), which
proves the whole CSCA→DSC→SOD chain in ZK to the verifier — closer to Tier B
(no attestation trust for validity), at ~2.5 s + a separate enroll proof.

**Tier B without the recursion cost is still open.** To prove document validity
in ZK to the verifier *without* revealing `C` (which would be a cross-verifier
linkable ID, killing V2) you must verify π_E in-circuit — the recursion. The
only amortization there is per-(verifier, epoch): recurse once on first contact
with a verifier each epoch (20 s), cheap presentations after, within-epoch
linkage already accepted by the SPEC. That's the next milestone if Tier B
latency matters; for Tier A, presentations are done and sub-second.

## Status

Prototype = circuit + witness derivation + native measurement + F2 negative
test + this doc. Wiring `present_amortized` into the wallet (enrollment seals
the 6 fields; presentation reads + proves) and the verifier SDK (accept the
`present_amortized` circuit, tier A) is the integration step — mechanical, not a
design question. `circuits/present_amortized` is in the CI compile+solve smoke.
