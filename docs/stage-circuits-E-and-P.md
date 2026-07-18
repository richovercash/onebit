# Stage: Circuit E, Circuit P, and the recursion between them

*What we built in the "start Circuit E / wire Circuit P" session. Assumes the
glossary. Read that first if a term is unfamiliar.*

## The problem this stage solves

Before this stage, the wallet could prove "I know a birth date and a secret
that satisfy `age ≥ 18`" (Circuit P v0). But nothing tied that birth date to a
**real government-signed document**. A liar could enroll a made-up DOB and the
proof would still verify. The envelope admitted this honestly with a
`binding: "P-only"` label.

Closing that gap is the whole game. We need the presentation proof to mean:
*"the birth date I'm proving `age ≥ 18` over is the one inside a passport that a
government actually signed"* — **without ever showing the passport, the birth
date, or even a stable identifier.**

The spec's answer (SPEC §4.2, Option B) is a two-circuit split with recursion.

## The two circuits

### Circuit E — enrollment (run once, on first document read)

`circuits/e/src/main.nr`. Inputs: the raw chip data (DG1, eContent, the DSC
signature) plus two fresh secrets `k` and `salt`. What it proves:

1. **`SHA256(DG1)` is in the SOD's hash list** — the birth date we read is the
   one the government hashed.
2. **The RSA signature over eContent verifies** — the SOD is genuinely signed
   by the DSC. (This is the expensive part: ~150k of the 177k gates.)
3. **The DSC is in the master-list Merkle tree** — the signer is a real
   country's certificate, not a forgery.
4. **It commits the attributes**: `C = Poseidon2(dob, expiry, docHash, k, salt)`.

It **outputs `(C, root)`** — the commitment and the Merkle root it computed.
The proof it produces is called **π_E**. Both C and π_E are stored on the
device and *never transmitted*.

Code shape (abbreviated):

```noir
// 1. DG1 hash is in the signed content
let h_dg1 = sha256::digest(dg1);
for i in 0..32 { assert(econtent[H_OFF + i] == h_dg1[i]); }

// 2. RSA-2048 signature over eContent verifies
let h_econ = sha256::digest(econtent);
assert(verify_sha256_pkcs1v15(h_econ, sig_bn, 65537));

// 3. fold the DSC hash up a depth-20 Merkle path to a root
// ... node = Poseidon2(left, right) at each level ...

// 4. resolve dates (century rule) and commit
let c = Poseidon2::hash([dob, exp, doc_hash, k, salt], 5);
(c, node)   // public outputs
```

Measured: **177,495 gates, ~1.05 s to prove on a desktop**, proof verifies.
On a phone this is a one-time cost paid at enrollment (think 10–30 s), then
cached forever — you never read the passport again.

> **Design note — why output `(C, root)` instead of taking `root` as an
> input?** If `root` were an input we'd have to compute the Merkle root outside
> the circuit to fill it in — which means running Poseidon2 in Python, which is
> painful. Outputting it is equivalent: Circuit P (below) re-checks that the
> emitted root equals the real published root. Same security, less plumbing.

### Circuit P — presentation (run every age check)

`circuits/p/src/main.nr`. This is where **recursion** happens. Circuit P takes
π_E as a *private* input and **verifies it inside itself**, then does the
predicate logic. Its soundness chain, in order:

```noir
// 1. Pin WHICH circuit produced the inner proof.
assert(Poseidon2::hash(e_vkey, 115) == e_vkey_hash);

// 2. Verify pi_E in-circuit. Its public inputs are E's outputs [C, root].
verify_proof_with_type(e_vkey, e_proof, [c, root_e], e_vkey_hash, PROOF_TYPE_HONK_ZK);

// 3. That document chained to the published master-list root.
assert(root_e == r_icao);

// 4. Reopen C from the attributes we're about to use (the "rebind").
assert(c == Poseidon2::hash([dob, expiry, doc_hash, k, salt], 5));

// 5. The actual predicate + expiry.
assert(dob + age_min * 10000 <= current);
assert(expiry >= current);

// 6. The verifier-scoped nullifier.
Poseidon2::hash([k, ctx], 2)   // = N, the only "identifier" that leaves
```

Walk through why each line is load-bearing:

- **Line 1 (pin the circuit).** `verify_proof_with_type` will happily verify a
  proof for *any* circuit whose vkey you hand it. A cheater could supply a
  vkey+proof for a trivial circuit that outputs any C they like. So we hash the
  vkey and force it to equal `e_vkey_hash`, which is a *public* input the
  relying party checks against the known, published Circuit E key. Now the only
  inner proof P will accept is a real Circuit E proof.
- **Line 2 (the recursion).** This is the cryptographic heart: P contains a
  full UltraHonk verifier and runs it on π_E. If π_E isn't a valid Circuit E
  proof for public inputs `[c, root_e]`, the witness can't be solved. This
  costs ~770k gates — the verifier is a big circuit.
- **Line 3 (real root).** E proved *a* Merkle root; here we insist it's *the*
  published ICAO root. Forged-signer documents die here.
- **Line 4 (the rebind).** This is the subtle one. E committed `C` over the
  document's real attributes. Here P recomputes `C` from the `dob`/`expiry` it's
  about to run the predicate on. If they don't match, witness fails. So the
  birth date feeding the age check is *provably the same one inside the
  signed document*. This is the line that finally kills the `binding: "P-only"`
  gap.
- **Lines 5–6** are the same predicate + nullifier logic from v0.

Nothing about the passport, the birth date, `C`, or `k` leaves the phone. The
only outputs are the nullifier and the public policy values. That's the point
of doing the verification *inside* a circuit rather than sending `C + π_E` to
the verifier: if you sent `C`, `C` would be a stable cross-session identifier
and unlinkability (V2) would be dead on arrival.

Measured: **775,800 gates, ~4.8 s to prove on a 32-thread desktop**, verifies.

## The cost surprise (and why we're about to measure on the phone)

Circuit P v0 (no recursion) was **3,026 gates / 634 ms on the Pixel 9a**.
Circuit P v1 (with recursion) is **775,800 gates** — 256× bigger. The in-circuit
proof verifier is not cheap.

Desktop proving went from ~150 ms to ~4.8 s (~32×). If the phone scales
similarly, presentation could land somewhere in the **15–30 s** range — which
would **bust the < 5 s exit criterion** from the T5 demo. That earlier 3.74 s
number was for v0, *before* the credential binding existed.

This is a real, expected fork in the road, and the roadmap called it. The
options if the phone number is too slow:

1. **Accept a slower presentation.** An age gate that takes ~10 s once per site
   per epoch may be perfectly fine UX — it's not a payment terminal.
2. **Cheaper recursion.** UltraHonk has lighter recursive-verifier variants;
   there may be gate savings in how π_E is verified.
3. **Amortize π_E.** Verify π_E once per epoch into a cheap short-lived token,
   then presentations within the epoch skip the recursion. (Adds a caching
   layer and a security argument to check.)

We don't guess between these — **we measure the real number on the Pixel 9a
first.** That's the next action.

## Supporting piece: the `commit` helper

`circuits/commit/` is a tiny circuit that computes *only* `doc_hash` and `C`
from the document + secrets — the exact math Circuit E does internally. Two
uses: (1) it let us extract `C` and `doc_hash` to build Circuit P's test
witness (E computes them privately, so we needed a way to reproduce them), and
(2) it's the computation the **wallet runs at enrollment** to persist the
credential fields `(dob, expiry, doc_hash, k, salt, C)` that Circuit P later
reopens. Its output `C` matched Circuit E's byte-for-byte, which is how we know
the two circuits agree.

## Files touched this stage

| File | What it is |
|------|------------|
| `circuits/e/src/main.nr` | Circuit E — enrollment proof (RSA-2048 variant) |
| `circuits/e/gen_inputs.py` | Builds E's test witness from a synthetic signed doc |
| `circuits/p/src/main.nr` | Circuit P v1 — presentation with recursion |
| `circuits/commit/src/main.nr` | The shared `(C, doc_hash)` computation |
| `circuits/e/NOTES.md` | Running checklist of what's left in P1.0 |

## What's still open in P1.0

- **Measure Circuit P v1 on the Pixel 9a** (next action) — get the real
  presentation number and decide among the three options above.
- Wire the wallet to run Circuit E on-device at enrollment and persist the
  credential, then feed Circuit P at presentation.
- Coverage variants (P1.1): RSA-PSS, ECDSA, RSA-4096 — each a compiled sibling
  of Circuit E with the same shape.
- Replace the synthetic Merkle path with a real tree over the bundled CSCA
  master list, built identically in circuit, wallet, and verifier.
- Review the `docHash` preimage choice for cross-document uniqueness.
