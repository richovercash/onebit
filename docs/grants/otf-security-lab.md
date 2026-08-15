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
