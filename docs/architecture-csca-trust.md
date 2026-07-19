# Architecture: where the CSCA→DSC trust check lives

*From the "real Merkle tree" investigation. The master-list composition forces
the answer.*

## The question

Passive auth trusts a document because: DSC signs the SOD, **and the DSC is
signed by a CSCA in the published master list**. `mono_faithful` proves the
first half in ZK (DSC→SOD). The "real Merkle tree" task is the second half:
prove the DSC chains to a trusted CSCA, against a real tree of the master list —
not the synthetic `dsc_root` we ship today.

## The data that decides it

Composition of the bundled master list (588 CSCAs, `openssl` survey):

| CSCA key | Count |
|---|---|
| RSA-4096 | 357 |
| ECDSA (various curves) | 164 |
| RSA-3072 | 60 |
| RSA-6144 | 6 |
| RSA-2048 | 1 |

Two facts jump out:

1. **CSCA keys are large.** The majority are RSA-4096; some RSA-6144. An
   RSA-4096 verification in-circuit is ~2× an RSA-2048 (~50k+ gates); 6144 is
   worse. DSCs, by contrast, are RSA-2048 (what `mono_faithful` handles at 79k
   gates / ~4.5 s).
2. **CSCA keys are algorithm-diverse.** RSA at three sizes plus ECDSA at
   multiple curves. A circuit that verifies CSCA→DSC needs a variant per CSCA
   key type.

## The consequence

Verifying CSCA→DSC **in the presentation circuit** would:

- add an RSA-4096+ (or ECDSA) verification *every presentation* → ~145–160k
  gates → **~7–9 s native, over the 5 s budget**; and
- require dispatching among CSCA key-type circuit variants.

That's the wrong place. **The CSCA→DSC link is fixed per document** — it doesn't
change between presentations. It should be verified **once, at enrollment**, not
on every age check.

## Poseidon2 tree: confirmed buildable

The mechanics of a real tree are ready: `bb.js`'s `poseidon2Hash` produces
byte-identical output to the circuit's `Poseidon2::hash`
(`poseidon2([1,2]) = 0x038682aa…` both ways), so a Node/Java tree builder over
the master list will agree with an in-circuit Merkle fold. The tree is over
CSCA commitments and is **consumed at enrollment**, not presentation.

## The options for the CSCA trust (all establish it at enrollment)

| # | Enrollment does | Presentation does | Presentation cost | CSCA link strength |
|---|---|---|---|---|
| A | — | full chain CSCA→DSC→SOD in one circuit | ~7–9 s | ZK (but over budget) |
| B | ZK-prove CSCA→DSC (π_E) | recursively verify π_E + DSC→SOD | ~30 s+ native (recursion) | ZK |
| C | ZK-prove CSCA-in-tree signs DSC → device-bound DSC-trust credential | DSC→SOD→predicate, referencing the credential | ~4.5 s | ZK at enrollment + device binding |
| **D (today)** | Java PA (CSCA→DSC verified out-of-circuit) + attestation | DSC→SOD→predicate (`mono_faithful`) | ~4.5 s | attested-software |

- **A** is honest and simplest but busts the budget and needs the key-type
  variant matrix.
- **B** is the Circuit E/P recursion built earlier — sound, but recursion is
  ~775k gates (~30 s+ native), worse than A. Not viable per-presentation.
- **C** is the target: do the expensive, algorithm-diverse CSCA verification
  **once** at enrollment (10–50 s is fine there), emit a device-bound credential
  attesting "this DSC chains to a master-list CSCA," and keep presentation at
  ~4.5 s. The link is ZK-proven at enrollment; presentation-time trust rests on
  the SE + attestation binding that credential to the device.
- **D** is what ships today: `mono_faithful` proves DSC→SOD→predicate in ZK; the
  CSCA→DSC link is verified by the (attested) wallet's Java passive auth. Honest
  label: `binding=document` covers the ZK half; the CSCA half is
  attestation-backed.

## Decision / next step

**Recommend C**, with D as the honest interim (which is exactly the current
state). The real Merkle tree belongs in an **enrollment circuit** that verifies
CSCA(-in-tree)→DSC once; the tree builder (poseidon2-matched) is ready. This is
the same enrollment/presentation split the spec's Option B anticipated — but the
split is drawn at the CSCA boundary (expensive, once) vs the DSC→SOD boundary
(cheap, per-presentation), which the master-list data now justifies concretely.

The synthetic `dsc_root` in `mono_faithful` stays labeled until the enrollment
circuit lands; it is not a soundness hole in the DSC→SOD proof, only the
un-anchored CSCA membership.
