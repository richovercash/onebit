# Aztec / Noir Grants application — ready to post

**How to submit (verified 2026-08-25):** there is no open application form any more.
The Airtable link from the 2024 blog is dead and the Notion page is the 2022 Aztec
Connect program. Since late 2025 the Foundation funds via targeted **RFGPs** posted on
the forum (Dark Forest $75k, State Migration $60k — each with its own deadline, tags,
and "post your proposal as a new topic, link it in the RFGP thread" instructions) plus
a Builder Grants bucket handled by email. Unsolicited forum applications in
Applications (ZKCompliance Apr 2026, Audit Playbook Apr 2026) got zero replies.

So, three channels, do all three:
1. **Email** the text below to hello@aztec.foundation and rahul@aztec-labs.com (the
   named RFGP contact), subject = the title line. This is the one that gets read.
2. **Post** it in forum.aztec.network → Applications (category 10) for visibility;
   link the post in the email. Forum disclaimer: everything posted is public and
   non-confidential, which is fine — it's all in the repo anyway.
3. **Watch for an RFGP** on identity / selective disclosure / client-side proving
   (search forum for "Request for Grant Proposals"); if one appears, resubmit in
   that thread's required format with its tags. That is the funded path.

Format below mirrors the RFGP-required sections (Title, Contact, Summary, Details,
Milestones, Amount, Rationale) so it can be re-tagged into an RFGP without rewriting.

---

Title: [Grant Application] OneBit — one-bit ZK age verification from real passports/mDLs on phones (Noir/UltraHonk)

**Requested amount:** $20,000 USD
**Category:** Noir ecosystem / applied cryptography (off-chain Noir; no Aztec L2 dependency)
**Stage:** Working end-to-end system, research preview, seeking audit + upstreaming funds
**Contact:** richovercash@pm.me
**Repository:** https://github.com/richovercash/onebit (AGPL-3.0 app/verifier/core; Apache-2.0 spec + circuits)

## 1. Problem

Age-verification mandates (UK Online Safety Act, US state laws upheld in *Free Speech
Coalition v. Paxton*, EU age-assurance rails) are being satisfied by ID-upload and
face-scan providers. Every provider database is a breach and subpoena target, and the
chilling effect falls hardest on anonymous access to lawful-but-sensitive content.
"Privacy-preserving age assurance" in the market today means a provider that promises
to forget; nobody has shipped the version where there is no provider.

## 2. Solution

OneBit proves "over 18, yes/no" from a government-signed credential — an ICAO 9303
passport chip or an ISO 18013-5 mDL used strictly as an issuance rail — entirely in
Noir, natively on an Android phone with **no INTERNET permission**. The verifier receives
one bit plus a verifier-scoped, epoch-rotating nullifier. No birth date, document,
name, or stable identifier leaves the device; there is no server to log or compel.

Verified end-to-end with a real US passport and a real California DMV mDL on a
GrapheneOS Pixel (no Google services). Demo videos:
https://github.com/richovercash/onebit/releases/tag/v0.1-preview

### How it uses Noir

| Component | Noir work |
|---|---|
| Enrollment (once) | CSCA→DSC signature verification + Merkle membership in the published ICAO master list (`enroll_*`, one package per signature suite: RSA-2048/4096/6144, RSA-PSS, ECDSA P-256/384/521, Brainpool 384/512) |
| Presentation (every gate) | Full ICAO CMS passive authentication in-circuit — SHA-256 hash chain DG1→SOD→signed attributes + DSC signature (`mono_faithful*`), or sub-second amortized form bound to the enrollment commitment (`present_amortized`, `present_bool`) |
| Binding | Commitment rebind tying the age predicate to the signed document; century-window date rule; nullifier = H(commitment, verifier scope, epoch) |
| Recursion (measured, shelved) | Circuit pair E/P: in-circuit Honk verification of a cached enrollment proof (ADR-003/004) |

Stack: 21 circuit packages, ~1,200 lines of Noir, nargo 1.0.0-beta.20, barretenberg
4.2.0 (UltraHonk), zkPassport's `noir_rsa` / `noir-ecdsa` / `noir-bignum` throughout,
native aarch64 proving via noir-rs, proof cross-verification against bb.js.

## 3. Technical progress (already built, before this grant)

- Passport NFC read → passive auth → enrollment proof → presentation proof → verifier
  GRANT, on-device, live with a real document.
- mDL rail: OID4VP against the real CA DMV Wallet (direct_post.jwt / A256GCM quirks
  documented in `docs/mdl-ca-integration.md`), IACA root cross-validation.
- Measured on Pixel 9a: amortized presentation 0.8 s; full in-circuit passive auth
  2.5–4.5 s; one-time enrollment 10.3 s; recursion 20.3 s (`docs/measurement-*.md`).
- Test surface: 516-challenge refusal fuzz corpus, attestation/challenge/verifier
  JUnit fixtures, compile + witness-solve of every live circuit in CI, real-proof
  fixtures verified through the bb.js sidecar (`scripts/test.sh`).
- Documented self-review: under-constrained-witness checklist
  (`docs/self-review-circuits.md`), negative tests for nullifier-key substitution.
- Protocol spec (`SPEC_one_bit_verifier.md`), security policy, coverage matrix.

## 4. Grant scope — what this funding builds (4 months)

**Milestone 1 — Noir circuit audit co-funding (Months 1–3) — $12,000**
Under-constrained-witness review of the enrollment and presentation families by a
Noir-fluent auditor (an OTF Security Lab request is also in flight; this covers the
Noir-specialist portion / top-up). Every finding becomes a public regression fixture.
*Deliverable:* published audit report + fixtures + a reusable **Noir circuit
audit checklist** worked against a real-world circuit set (Noir-native constraint
tooling is thin; Picus et al. are circom-centric).

**Milestone 2 — Upstreamable findings + benchmarks (Months 2–3) — $5,000**
(a) Reproducible aarch64-Android native-proving recipe: noir-rs + prebuilt
barretenberg, the libc++ `std::__1` vs `std::__ndk1` ABI bridge, platform-lib
bundling. Currently a working private recipe; should be an ecosystem how-to.
(b) noir-rs SRS sizing for recursion: `ULTRA_HONK_SRS_MULTIPLIER` makes a 775k-gate
recursive circuit demand a 512 MB SRS and SIGABRT across the FFI on an undersized
CRS — minimal repro + fix proposal as an issue/PR.
(c) Published phone benchmarks, recursion vs monolithic on Tensor G1/G4. Headline:
in-circuit Honk verification of one cached proof costs more gates than redoing the
RSA check, so recursion only pays when aggregating several sub-proofs.
*Deliverable:* docs PR(s) to noir-rs / awesome-noir, issue with repro, benchmark report.

**Milestone 3 — Signature-suite coverage matrix (Month 4) — $3,000**
Finish and fixture the DSC/CSCA long tail (RSA-PSS, Brainpool + NIST ECDSA,
RSA-6144, SHA-1-era legacy) against real master-list entries; publish as a coverage
matrix others verifying ICAO documents in Noir can reuse.
*Deliverable:* `docs/coverage-matrix.md` complete, fixtures in CI.

## 5. Budget

| Milestone | Work | Cost |
|---|---|---|
| M1 | Noir circuit audit co-funding, fixtures, published checklist | $12,000 |
| M2 | Native-proving recipe, noir-rs SRS repro/fix, phone benchmarks | $5,000 |
| M3 | Signature-suite coverage matrix + fixtures | $3,000 |
| **Total** | | **$20,000** |

Solo developer; no salary is drawn from this grant — M1 is auditor cost, M2/M3
are time-boxed deliverables.

## 6. Why Aztec / Noir should fund this

- **Demo story for "why Noir":** government-grade signatures verified in-circuit, on a
  phone, offline, one bit disclosed. A privacy application normal people can hold.
- **Exercises paths the ecosystem needs data on:** recursion on mobile, native
  aarch64 proving, noir-rs ↔ bb.js cross-verification, nine signature suites through
  zkPassport's libraries at once.
- **Complementary to zkPassport, not duplicative:** registry-free, one-bit-only wire
  grammar, mDL as issuance rail; findings flow back to the shared libraries.
- **Everything reusable is Apache-2.0:** circuits, spec, audit checklist, coverage
  matrix, benchmarks.

## 7. Team

Rich Overcash — solo developer. Built the full stack: Noir circuits, Android wallet
(passport NFC + StrongBox key handling + mDL Digital Credentials API), verifier SDK,
native proving integration. Responsive; monthly milestone cadence, every deliverable
a public commit/PR/report.

## 8. Open source

Already public: https://github.com/richovercash/onebit. Circuits + spec Apache-2.0
(adoptable into any stack); app/verifier/core AGPL-3.0 so a fork can't add tracking
silently. All grant deliverables are published as they land, not at the end.

## 9. Roadmap beyond this grant

- Complete the OTF Security Lab audit; remediate; drop the UNAUDITED banner.
- NLnet NGI Zero application (Sep–Nov 2026) for wallet hardening + reproducible F-Droid build.
- Verifier SDK adoption by sites facing age-assurance mandates; the wallet stays free.

## 10. Links

- Repo: https://github.com/richovercash/onebit
- Spec: https://github.com/richovercash/onebit/blob/main/SPEC_one_bit_verifier.md
- Roadmap: https://github.com/richovercash/onebit/blob/main/ROADMAP_one_bit_verifier.md
- Circuits: https://github.com/richovercash/onebit/tree/main/circuits
- Self-review checklist: https://github.com/richovercash/onebit/blob/main/docs/self-review-circuits.md
- Measurements: https://github.com/richovercash/onebit/blob/main/docs/measurement-native-proving.md ,
  https://github.com/richovercash/onebit/blob/main/docs/measurement-recursion-on-device.md
- Demo videos: https://github.com/richovercash/onebit/releases/tag/v0.1-preview
