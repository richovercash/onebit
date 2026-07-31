# One-Bit Verifier — learning docs

Plain-language explainers written *as the system is built*, for someone learning
the codebase and the cryptography. Not API reference — the "why" and the "how it
fits." Everything below is written to be read top-to-bottom.

## The system in three sentences

A wallet reads the government signature already on your passport chip and seals a
birth-date credential into the phone's secure element — that's **enrollment**.
When a website asks "are you 18?", the wallet makes a fresh zero-knowledge proof
that answers exactly that one bit, bound to your device and to that website's
challenge — that's **presentation**. The website checks the proof with no network
calls, learns one bit and an unlinkable per-site pseudonym, and stores nothing.

## Read in this order

**Start here — the vocabulary and the shape of the problem**
1. **[glossary.md](glossary.md)** — every term (DSC, CSCA, SOD, nullifier,
   commitment, Poseidon…) defined in one line. Keep it open as you read the rest.
2. **[architecture-csca-trust.md](architecture-csca-trust.md)** — the passport
   trust chain (country key → document key → your data) and the key decision to
   check the expensive part *once* at enrollment, not on every age check.

**How the circuits work**
3. **[stage-enrollment-circuit.md](stage-enrollment-circuit.md)** — the one-time
   enrollment circuit: proving a real country authority signed your document.
4. **[stage-circuits-E-and-P.md](stage-circuits-E-and-P.md)** — the two circuits
   (enrollment E and presentation P) and the "recursion" that binds a ZK age
   proof to a real signed passport without revealing the passport.
5. **[self-review-circuits.md](self-review-circuits.md)** — a security pass over
   every constraint in the circuits: one critical forgery found and fixed, and
   the reasoning for what's sound.

**How fast is it — measurements on real hardware**
6. **[architecture-proving-revisit.md](architecture-proving-revisit.md)** — the
   fork in the road: one big proof (recursion) vs. a cheaper split, and why
   phone threading changed the answer.
7. **[measurement-native-proving.md](measurement-native-proving.md)** — proving
   a real passport natively on the phone, and the numbers.
8. **[measurement-recursion-on-device.md](measurement-recursion-on-device.md)** —
   the recursive proof measured on the Pixel 9a (~20 s), and why that pointed to
   a better design.

**The design that made presentations fast, and what it covers**
9. **[amortized-enrollment.md](amortized-enrollment.md)** — the payoff: move the
   expensive work to a one-time enrollment so each age check is ~0.8 s. Explains
   the trade-off (what the phone attests vs. what the proof proves).
10. **[coverage-matrix.md](coverage-matrix.md)** — which real passports/ID cards
    work today, by signature algorithm (RSA, ECDSA curves, RSA-PSS), what's
    proven end-to-end, and what's still missing.
11. **[stage-mdl-enrollment.md](stage-mdl-enrollment.md)** — accepting a US
    mobile driver's license (ISO 18013-5) as a second source credential: the
    mDL trust chain (it mirrors the passport), the CBOR/COSE plumbing, and why
    the rest of the system doesn't change.
12. **[mdl-ca-integration.md](mdl-ca-integration.md)** — the *real* California
    mDL picture from an actual license on-device: the SpruceID CA DMV Wallet, the
    OpenID4VP app-to-app presentation, CA's published IACA trust anchor, and the
    OID4VP-reader integration that remains to build.

**Security / privacy**
- **[person-binding.md](person-binding.md)** — the "kid borrows a parent's passport"
  problem: document- vs person-binding, why the mDL already avoids it (issuer does the
  face-match), why platform Face ID can't help, and the optional on-device face-match
  design. Includes the shipped `person_bound` assurance-level plumbing.

**Reference / build notes**
- **[stage-native-packaging.md](stage-native-packaging.md)** — how the ZK prover
  is packaged into the Android app (the fiddly native-library plumbing).

The authoritative specs live one level up: **`SPEC_one_bit_verifier.md`** (the
protocol) and **`ROADMAP_one_bit_verifier.md`** (what's next, phased).

## Where the code lives

| Area | Path | Language |
|------|------|----------|
| Passive Authentication + protocol logic | `core/` | Java (runs on Android + desktop) |
| Wallet app | `app/` | Java (Android) |
| Verifier SDK + demo gate | `verifier/` | Java + a Node bb.js sidecar |
| ZK circuits | `circuits/` | Noir |
| Proving benchmarks + native prover | `bench/` | Noir + Rust + scripts |
