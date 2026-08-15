# P1.2 audit-funding applications — status

The roadmap's zero-cash audit path: apply to all three, take whichever lands
first. Drafts here are LOCAL / uncommitted until submitted.

| Program | What we ask | Mechanism | Status / next action |
|---|---|---|---|
| NLnet NGI Zero | ~€50k grant incl. security audit via their partner (Radically Open Security comes free with NLnet grants) | Web form at nlnet.nl/propose — **call reopens 2026-09-03, deadline 2026-11-03 12:00 CEST** | Draft ready (`nlnet-ngi-zero.md`). On Sep 3: confirm which fund is open (NGI Zero Core or successor), paste answers, submit. |
| OTF Security Lab (ex Red Team Lab) | Audit-in-kind (no cash): circuit + wallet + verifier review | Rolling: apply via opentech.fund/labs/security-lab, or email security_lab@opentech.fund | Draft ready (`otf-security-lab.md`). Can send NOW. |
| Aztec / Noir Grants | ~$20k for Noir-circuit audit + upstreaming the recursion/mobile-proving findings | Wave-based: post application to forum.aztec.network Applications category | Draft ready (`aztec-noir-grants.md`). Check current wave, post. |

Shared facts used in all three (verified against repo 2026-08-02):

- Working system: passport (ICAO 9303) and mDL (ISO 18013-5) → ZK age proof
  on a zero-network GrapheneOS phone; real US passport + real CA mDL verified
  live end-to-end.
- Audit scope: ~1,165 lines Noir across 21 circuit packages (enroll family,
  mono_faithful family, present_amortized/present_bool, commit helpers,
  recursion pair E/P), ~5,600 lines Java (wallet 2,470 / core 2,525 /
  verifier 628), ~220 lines JS (Merkle tree builder + bb.js sidecar).
- Toolchain: Noir/nargo 1.0.0-beta.20, barretenberg 4.2.0 (UltraHonk),
  native aarch64 proving via noir-rs.
- Measured: presentation 0.8 s (amortized) / 2.5–4.5 s (full CMS passive auth
  in-circuit) on Pixel 9a; enrollment CSCA→DSC proof 10.3 s one-time;
  recursion measured 20.3 s and deliberately shelved (ADR-003).
- Test surface: 516-challenge refusal corpus, JUnit fixtures (attestation,
  challenge signature, verifier), real-proof fixtures in CI smoke.
- Licenses: AGPL-3.0 (app/verifier/core), Apache-2.0 (spec/circuits).
