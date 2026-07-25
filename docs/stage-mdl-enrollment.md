# Stage: mDL (mobile driver's license) enrollment

*What we're building to accept a US driver's license, not just a passport, as the
source credential. Roadmap Phase 3.1. Read the glossary and
`architecture-csca-trust.md` first — the shape mirrors the passport.*

## Why this matters

Most people don't carry a passport, but most US adults have a driver's license.
A **mobile driver's license (mDL)** is the phone version, standardized as
**ISO 18013-5**. Supporting it takes coverage from "people with passports" to
"most adults" — and for a US audience (regulators, courts) it's the credential
that actually lands.

The key framing (roadmap P3.3): we use the mDL as an **issuance rail, not a
presentation instrument.** We read it once at enrollment, derive our own
unlinkable one-bit credential, and then *never present the mDL again.* This is
the privacy repair for the mDL ecosystem's known "phone-home / linkable" problem.

## The mDL trust chain (it mirrors the passport)

| Passport (ICAO 9303) | mDL (ISO 18013-5) | Role |
|---|---|---|
| CSCA | **IACA** | country/state root authority |
| DSC | **DS** (document signer) | signs the actual credential |
| SOD (CMS/ASN.1) | **MSO** inside COSE_Sign1 (CBOR) | the signed object |
| DG1 data groups | **IssuerSignedItems** | the actual data (birth_date, …) |
| master list | **AAMVA VICAL** | the published list of trusted roots |

Same idea end to end: a state authority (IACA) signs a document-signing key
(DS); the DS signs a security object (MSO) that commits SHA-256 digests of each
data element; each data element carries a random salt so revealing one doesn't
leak the others. The one difference that matters for code: mDL is encoded in
**CBOR/COSE**, where the passport uses **ASN.1/CMS**.

## What this stage built

- **`Cbor`** — a small, dependency-free CBOR codec (RFC 8949) for exactly the
  mdoc subset (ints, byte/text strings, arrays, maps, tags, booleans). Hand-rolled
  so the wallet gains no new dependency, the same way the passport ASN.1 offsets
  were handled by hand.
- **`Mdl`** — mdoc passive authentication, the analog of `PassiveAuth`:
  1. verify the issuer's **COSE_Sign1** signature over the MSO (ECDSA — note COSE
     uses a fixed-length `r‖s` signature, converted to DER for the JVM verifier);
  2. check the **DS certificate chains to a trusted IACA** root;
  3. **bind each data element** to the MSO by recomputing `SHA-256(#6.24(IssuerSignedItem))`
     and matching the MSO's value digest;
  4. **extract** `birth_date` and `expiry_date`.
  Fails closed on any mismatch.
- **`MdlTest`** — builds a synthetic IACA→DS→MSO mDL with the codec and checks a
  valid one verifies + extracts `dob`/`expiry`, a tampered digest is rejected,
  and an untrusted IACA is rejected.

## Why the rest of the system doesn't change

The whole point of the two-part design pays off here. Enrollment produces the
**same commitment** `C = Poseidon(dob, expiry, docHash, k, salt)` regardless of
whether the attributes came from a passport or an mDL. So the **presentation
circuit and nullifier are unchanged** — an mDL-derived proof is
indistinguishable on the wire from a passport-derived one. Only the *reading and
verification* differ, and that's what this stage adds.

## What's next

- **Circuit E2** — the in-ZK version of `Mdl.verify` (COSE ECDSA over the MSO +
  data-element digest + DS in the AAMVA tree), committing the same `C`. For the
  Tier-A amortized path, the Java `Mdl.verify` above + the existing commit step is
  already enough; Circuit E2 is the faithful (no-attestation-trust) tier.
- **AAMVA VICAL trust tree** — the real per-state IACA roots, built into a Merkle
  tree the way the ICAO master list is (`build_tree.mjs`).
- **Provisioning (roadmap P3.2)** — the hard practical problem: real mDLs live in
  Apple/Google wallets and are often not exportable to a GrapheneOS phone. This
  stage works against ISO 18013-5 test-shaped credentials; a live real-mDL tap
  depends on solving provisioning, tracked separately.
