# OTF Security Lab audit request — draft

Rolling submissions: https://www.opentech.fund/labs/security-lab/ (or email
security_lab@opentech.fund). This asks for an audit in kind, not cash — it
can run in parallel with the NLnet application. Send as email body or paste
into their portal form.

---

Subject: Audit request — OneBit, a one-bit zero-knowledge age verifier
(anti-surveillance age assurance)

## Project and internet-freedom relevance

Age-verification mandates (UK Online Safety Act enforcement, Texas
HB 1181-family laws upheld by the US Supreme Court, EU age-assurance rails)
are being satisfied by ID upload and face-scan providers — a de facto
identification layer over lawful browsing, with every provider database a
breach and subpoena target. The chilling effect on anonymous access to
lawful-but-sensitive content (LGBTQ+ resources, sexual-health information,
adult content) is the internet-freedom harm.

OneBit is a working alternative: a wallet on the holder's phone reads a
government-signed credential once (ICAO 9303 passport chip, or ISO 18013-5
mobile driving licence used strictly as an issuance rail), then answers age
gates with a zero-knowledge proof of exactly one bit plus a verifier-scoped,
epoch-rotating nullifier. No birth date, document, or stable identifier ever
leaves the device; the wallet has no network permission at all; there is no
provider in the loop to log, breach, or compel. Verified end-to-end with a
real US passport and a real California mDL on a GrapheneOS Pixel (no Google
services anywhere — de-Googled users are first-class). This architecture is
strictly stronger than France's CNIL/ARCOM "double anonymity" standard.

All code is open source: AGPL-3.0 (wallet/verifier/core), Apache-2.0
(spec/circuits). We are pre-launch (research preview) and want the audit
before regulators and at-risk users are pointed at the system — a soundness
bug found after that is strategy-fatal; found now it is a changelog entry.

## What we ask the lab to review

1. **ZK circuits (the core ask)** — ~1,165 lines of Noir across 21 packages
   (UltraHonk / barretenberg 4.2.0): under-constrained-witness review of the
   enrollment circuit family (CSCA→DSC signature check + Merkle membership in
   the published master list) and presentation family (full ICAO CMS passive
   auth in-circuit, predicate, nullifier), the commitment rebind that binds
   the predicate to the signed document, and the century-window date rule.
2. **Protocol boundary** — challenge wire grammar (refusal-first whitelist
   parser; 516-challenge fuzz corpus exists), Fiat–Shamir/context binding of
   nonce + origin, nullifier unlinkability across verifiers and epochs,
   proof-envelope and device-attestation checks (fail-closed matrix).
3. **Wallet key handling** — AndroidKeyStore/StrongBox sealing of the
   credential store (hybrid RSA-OAEP + AES-GCM envelope, biometric-gated
   decrypt), ephemeral per-presentation attested keys.

Scope sizes: Noir ~1.2k lines; Java ~5.6k lines (wallet 2,470 / core 2,525 /
verifier 628); JS ~220 lines (Merkle tree builder, bb.js verify sidecar).
A cryptographic design review of the amortized-enrollment argument
(attestation-backed provenance tier vs full in-ZK tier) would be equally
valuable if code review capacity is limited.

We have completed a documented self-review (under-constrained-witness
checklist, negative tests for nullifier-key substitution) and will publish
all findings after responsible disclosure, per lab practice.

## Practicalities

- Solo maintainer, responsive; remediation with regression fixtures
  committed for every finding (existing CI: refusal corpus + real-proof
  fixtures).
- Reproducible environment: pinned toolchain (nargo 1.0.0-beta.20,
  bb 4.2.0), benchmark harness, published trust-anchor tree builder.
- Not currently OTF-supported; applying under the "otherwise relevant to
  internet freedom" clause.
- Contact: Rich Overcash, richovercash@pm.me. Repo: [URL at submission].

---

## Submitted form answers (2026-08-25)

**Q10 preferred vendor:** Least Authority (ZK-circuit depth); ROS or 7ASecurity for Android/verifier side; flexible.

**Q11 timeline:** Flexible; ideal final report end of January 2027.

**Q12 coordinate directly:** Yes.

**Q13 problems to solve:**

Age-verification mandates (UK Online Safety Act, US state laws upheld in Free Speech Coalition v.
  Paxton, EU age-assurance rails) are being satisfied by ID-upload and face-scan providers. That builds
  a de facto identification layer over lawful browsing: every provider database is a breach and
  subpoena target, and the chilling effect falls hardest on anonymous access to lawful-but-sensitive
  content — LGBTQ+ and sexual-health resources, reproductive-health information, adult content, and
  anything a hostile government or employer would want logged.

  OneBit is a working open-source alternative: a wallet on the holder's phone reads a government-signed
  credential once (ICAO passport chip or ISO 18013-5 mDL, used only as an issuance rail) and then
  answers age gates with a zero-knowledge proof of exactly one bit plus a verifier-scoped,
  epoch-rotating nullifier. No birth date, document, or stable identifier leaves the device; the wallet
  has no network permission; there is no provider in the loop to log, breach, or compel. It runs on
  de-Googled phones (verified end-to-end on GrapheneOS with a real US passport and a real California
  mDL), so the users with the most to lose aren't excluded.

  The problem the audit solves: a privacy system like this is only as good as its circuits. An
  under-constrained witness or a linkable nullifier turns a "one bit" promise into a tracking beacon,
  and a soundness bug discovered after regulators and at-risk users are pointed at the system is
  strategy-fatal. We have done a documented self-review, but a solo maintainer cannot credibly assert
  soundness of their own ZK circuits and key handling. An independent audit (published in full after
  disclosure) gives users and digital-security trainers a basis to recommend it, gives regulators a
  concrete, reviewed existence proof that age assurance does not require identification — raising the
  bar for what "privacy-preserving" means in these mandates — and gives the internet-freedom community
  a reusable, audited building block (Apache-2.0 circuits) for other selective-disclosure credentials.

1.Soundness of the Noir circuits (highest priority). About 1,200 lines across 21 packages, UltraHonkon barretenberg 4.2.0. Specifically: (a) the presentation circuits (present_amortized,
present_bool, mono_faithful family) — is every witness that reaches the age predicate and the    nullifier actually constrained to the signed document, or can a prover satisfy the circuit with a forged or substituted value; (b) the enrollment family (enroll_*, per signature suite: RSA,  RSA-PSS, ECDSA P-256/384/521, brainpool) — CSCA→DSC signature verification and Merkle membership against the published trust-anchor tree; (c) the commitment rebind that ties the predicate to the enrollment commitment, and the century-window date rule. A single under-constrained witness here breaks the whole "one bit" claim.
2. Nullifier unlinkability. The nullifier is scoped per verifier and rotated per epoch. Confirm two
presentations to different verifiers, or the same verifier across epochs, cannot be linked, and
that a malicious verifier cannot choose a scope/epoch that collides with another's or forces reuse of a key that was meant to be ephemeral. I have negative tests for nullifier-key substitution; we want them adversarially tested.
3. Verifier boundary. The challenge wire grammar is parsed by a refusal-first whitelist parser
(516-challenge fuzz corpus exists); nonce and origin are bound into the proof. Review the proof
envelope, device-attestation checks, and the fail-closed matrix for any path that accepts a proof
it should refuse (replay, cross-origin, downgrade to a weaker circuit variant, malformed but
accepted challenge).
4. Wallet key handling (lower priority, but the most exposed to real-world compromise).
AndroidKeyStore/StrongBox sealing of the credential store (hybrid RSA-OAEP + AES-GCM envelope, biometric-gated decrypt), ephemeral per-presentation attested keys, and what a compromised OS or extracted APK can recover.

  If capacity only allows one item, item 1 alone is worth the engagement. A design review of the
  amortized-enrollment argument (attestation-backed provenance tier vs full in-ZK tier, docs/amortized-enrollment.md) is a good substitute for line-by-line review of item 4.

**Q14 focus (priority order):** 1. Noir circuit soundness (present_*, mono_faithful, enroll_* families; commitment rebind; century-window rule). 2. Nullifier unlinkability across verifiers/epochs. 3. Verifier boundary (challenge grammar, envelope, attestation, fail-closed). 4. Wallet key handling (StrongBox envelope, ephemeral attested keys).

**Q15 technical contact:** richovercash@pm.me

**Q16 links:** repo, SPEC, SECURITY.md, circuits/, docs/self-review-circuits.md, docs/architecture-csca-trust.md, docs/amortized-enrollment.md, docs/person-binding.md, docs/mdl-ca-integration.md, docs/coverage-matrix.md, release v0.1-preview demos.
