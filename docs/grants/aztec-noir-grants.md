# Aztec / Noir Grants application — draft forum post

Wave-based program: check the current wave at aztec.network/grants, then post
to forum.aztec.network → Applications. Angle: OneBit is a flagship *consumer*
Noir deployment (real government documents, phones, no chain) and the work
funds hardening + upstreamable ecosystem artifacts, not just our app.

---

Title: [Grant Application] OneBit — one-bit ZK age verification from real
passports/mDLs on phones (Noir/UltraHonk in production conditions)

## Summary

OneBit proves "over 18, yes/no" from a government-signed credential — an
ICAO 9303 passport or ISO 18013-5 mDL — entirely in Noir, natively on an
Android phone with zero network access. Real US passport and real California
mDL verified live: full ICAO CMS passive authentication (SHA-256 chain +
RSA/ECDSA DSC signature) in-circuit at presentation (~2.5–4.5 s on a
Pixel 9a), CSCA→DSC master-list membership proven once at enrollment
(10.3 s), sub-second amortized presentations. 21 circuit packages,
~1,200 lines of Noir, barretenberg 4.2.0, zkPassport's noir_rsa /
noir-ecdsa / bignum libraries throughout.

We believe this is among the hardest consumer-grade Noir deployments outside
Aztec itself, and it exercises paths the ecosystem needs data on: recursion
on mobile, native aarch64 proving, and cross-verification between noir-rs
proofs and bb.js.

## What we're asking for (~$20k)

1. **Noir circuit audit co-funding ($12k)** — under-constrained-witness
   review of the enrollment/presentation family by a Noir-fluent auditor.
   Every finding becomes a public regression fixture; the checklist itself is
   published as a reusable Noir audit artifact (Noir-native constraint
   tooling is thin — Picus et al. are circom-centric — so a worked
   real-world checklist has ecosystem value beyond us).
2. **Upstreamable findings + benchmarks ($5k)** — polish and PR/document:
   (a) the aarch64-android native-proving recipe (noir-rs + prebuilt
   barretenberg; libc++ `std::__1`-vs-`std::__ndk1` ABI bridge, platform-lib
   bundling) — currently a working private recipe, should be a reproducible
   ecosystem how-to; (b) SRS-sizing behavior for recursion in noir-rs
   (`ULTRA_HONK_SRS_MULTIPLIER` makes a 775k-gate recursive circuit demand a
   512 MB SRS and SIGABRT across the FFI on undersized CRS — reproduction +
   fix proposal); (c) published phone benchmarks: recursion vs monolithic on
   Tensor G1/G4 (headline finding: in-circuit Honk verification of one
   cached proof costs more gates than redoing the RSA check — recursion pays
   only when aggregating multiple sub-proofs).
3. **Coverage variants ($3k)** — finish and fixture the DSC/CSCA long tail
   in Noir (RSA-PSS, Brainpool + NIST ECDSA, RSA-6144, SHA-1-era legacy)
   against real documents, published as a coverage matrix others can reuse.

## Why it helps Aztec/Noir

A privacy application normal people can hold in their hands is the demo
story for "why Noir": one bit disclosed, government-grade signatures
verified in-circuit, on a phone, offline. All circuits Apache-2.0; built on
zkPassport's libraries with findings flowing back (we already run their
pinned toolchain: nargo 1.0.0-beta.20 / bb 4.2.0). Complementary, not
duplicative, to zkPassport: registry-free, one-bit-only wire grammar, mDL
as issuance rail.

## Team & links

Solo developer: Rich Overcash (richovercash@pm.me). Repo + spec +
measurement reports: [URL at submission]. Milestone cadence: monthly, each
deliverable a public commit/PR/report.
