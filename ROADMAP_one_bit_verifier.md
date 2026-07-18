# ROADMAP — One-Bit Verifier
**Post-T6 action items, phased**

Status: v0.2 · Prereq: SPEC_one_bit_verifier.md T1–T6 (T1 partially open; **Circuit E and π_E recursion NOT yet built** — shipped Circuit P v0 is `binding:"P-only"`) · ADR-0003: Option B (recursive), 634 ms on-device proof, 3.74 s end-to-end on GrapheneOS

Ordering rule (two-tier):
- **Research preview** (unaudited): code MAY be published any time after P1.0 + P1.3 + P1.5, with an UNAUDITED banner on the README first screen and no fitness claims. Most ZK projects ship this way; it also starts the free-review clock.
- **Production / regulatory tier**: every Phase 5 claim (certification filings, litigation exhibits, "highly effective" mappings) and any "use this in production" language waits for P1.2 (audit) remediation. A soundness bug found *after* regulators were pointed at the system is strategy-fatal; found during a labeled preview it's a changelog entry.

Funding note: total cash need concentrates in P1.2 (audit, ~$40–80k) and P6.3 (entity, ~$2–5k). Zero-cash paths exist for the audit: NLnet **NGI Zero** grants (privacy/open-source fit is exact; includes a security audit via their partner at no cost), **OTF Red Team Lab** (funds audits for internet-freedom tools), **Aztec ecosystem grants** (Noir project). Apply at P1.0 kickoff — grant lead times ≈ build time. Everything else in Phases 1–4 and 6 is unfunded-developer-compatible.

---

## Phase 1 — Close the technical gaps (blocking)

| # | Action | Exit criterion |
|---|--------|----------------|
| P1.0 | **Build Circuit E + recursion (the actual critical path, 3–6 weeks).** Fork zkPassport sig-check/integrity circuits (Apache-2.0, toolchain already pinned: nargo 1.0.0-beta.20 / bb 4.2.0); bind outputs to commitment C; verify π_E inside Circuit P via `verify_proof` (their `outer` circuit is the working recursion pattern). Move DG1 parsing + century rule in-circuit (closes the spec §3.1 "same rule" clause — currently Java-only). Re-measure on-device p50/p95. | Presentation proof carries credential binding (envelope drops `binding:"P-only"`); Circuit-P-with-recursion timing on Pixel 9a recorded vs the <5s budget. Book/apply for P1.2 audit or audit grant at kickoff of this item, not completion. |
| P1.1 | **Complete T1 as an algorithm-coverage matrix, not a count.** Acquire 4+ documents chosen adversarially: ≥3 issuing countries; RSA-PKCS1, RSA-PSS, and ECDSA DSCs represented; ≥1 legacy document (SHA-1-era SOD — **time-critical: those documents expire within ~12 months**; read any specimen on sight, the fixture is irreplaceable). Two passes: {parse, PA} columns fill now; {Circuit E} column fills after P1.0. Passport-reading session: read-only, nothing retained (enforced by architecture; assert in logs). | Coverage table in repo: {country, DSC alg, hash alg, key size} × {parse ✅, PA ✅, Circuit E ✅}. Any unsupported cell documented as explicit non-coverage, never silent failure. |
| P1.2 | **External circuit audit** (~$40–80k, 4–8 wk booking lead — see funding note; grant paths make this $0). Scope: Circuit E witness constraints, Circuit P recursion boundary (π_E verified in-circuit; C never on wire), nullifier consistency, century-window rule, Fiat–Shamir binding of nonce+origin. Engage a ZK-specialized auditor (zkSecurity / Veridise / Least Authority; Noir/Aztec ecosystem). Signing the engagement needs an entity or fiscal sponsor → P6.3 starts on Phase 1's calendar. **Gates the production/regulatory tier only, not the research preview.** | Audit report published; all criticals/highs remediated with regression fixtures added to T6 suite. |
| P1.3 | **Under-constrained-witness self-review before the audit** (cheaper bugs found by you). Honesty note: Noir-native under-constraint tooling is thin (Picus et al. are circom-centric) — hand-check every `assert` against the spec statement in §4.2 plus property-based witness tests; that's the real coverage. Pre-found entry #1: century rule lives only in Java until P1.0 moves it in-circuit. | Checklist committed; discrepancies between spec pseudocode and circuit resolved in one direction with ADR note. |
| P1.4 | **Repo bootstrap + continuous adversarial harness.** `git init` (repo is not under version control today), then CI on ubuntu-24.04 runners (native glibc for bb — no docker workaround needed in CI). Promote the 516-challenge corpus + T6 fixtures; add mutation fuzzing on challenge JSON and proof envelopes. | CI red on any new refusal-logic or verifier regression; corpus grows monotonically. |
| P1.5 | **Pre-audit hardening (the labeled T5 debts — auditors flag these in hour one).** SE-wrap the credential store (auth-gated AES key; currently app-private prefs), wallet-side verifier-signature check on challenges, QR channel alongside deep link. Days, not weeks. | Debts closed; `ponytail:` markers removed; T6 fixtures extended to cover each. |

## Phase 2 — Publish and demonstrate

| # | Action | Exit criterion |
|---|--------|----------------|
| P2.1 | Public repo: wallet, verifier SDK, circuits, SPEC, this roadmap, reproducible benchmark harness (device model, OS build, timings). License decision (recommend permissive for SDK, consider copyleft or source-available for wallet — decide deliberately, record as ADR-004). | `git clone` → benchmark reproduces within stated tolerance on listed hardware. |
| P2.2 | **The ten-second video**: GrapheneOS Pixel passes on its published AVB key; certified-but-stale stock device fails closed on patch-level policy. Side by side, one take. | Published alongside repo; linked from README first screen. |
| P2.3 | Security disclosure policy + contact; versioned threat table kept live in repo. | SECURITY.md; first external report handled per policy. |
| P2.4 | Write-up (long-form): architecture, the linkability traps (reused C, reused device key, mdoc MSO reuse), the attestation-allowlist argument. This is the reference document journalists, litigators, and regulators get pointed at. | Published; states V0–V6 invariants in plain language. |

## Phase 3 — Coverage expansion (the 60% problem)

| # | Action | Exit criterion |
|---|--------|----------------|
| P3.1 | **Circuit E2 — mdoc/mDL enrollment path.** Verify ISO 18013-5 MSO signature (ECDSA — cheaper than passport RSA) against AAMVA Digital Trust Service certificate list (VICAL) as second trust root alongside ICAO. Same commitment C, same nullifier, unchanged Circuit P. | mDL from ≥2 states enrolls; presentation indistinguishable from Mode A passport-derived (verify with transcript diff). |
| P3.2 | **mDL provisioning matrix.** Per-state table: wallet(s) supported (Apple/Google/Samsung/state app), GrapheneOS-viable enrollment path (state app without GMS? exportable mdoc?), notes. | Published matrix for all live mDL states; GrapheneOS-viable states flagged. |
| P3.3 | Document the strategic claim from P3.1 explicitly: **mDL as issuance rail, not presentation instrument** — ingest once, derive unlinkable credential, never present the linkable MSO. Position as the privacy repair for the mDL ecosystem's known phone-home/linkability criticisms. | Section in P2.4 write-up; one-pager for state DMV / AAMVA conversations. |
| P3.4 | **Mode B design spec** (promote from "reserved"). Blind issuance (BBS+), in-person ceremony tier (notary / library / credit-union / bank-KYC), issuer retains issuance counter only, envelope `mode:"B"` per V6. Governance: who may issue, what conformance body certifies issuers (links to P6.2). | SPEC_mode_b.md drafted with its own threat table; explicit statement of the trust downgrade vs Mode A. |
| P3.5 | Record the refusal as policy: **no facial age estimation fallback, ever** (biometric pipeline; forfeits the architectural claim). | ADR-005. |
| P3.6 | Non-smartphone residue analysis: size the population left after passport + mDL + Mode B-on-a-cheap-Android; document honestly rather than hand-waving. | Coverage-equity section with numbers and sources; this is the political armor, treat it as a deliverable. |

## Phase 4 — Presentment channel and integration

| # | Action | Exit criterion |
|---|--------|----------------|
| P4.1 | **Digital Credentials API spike on GrapheneOS.** Can the wallet register as a credential provider via Android CredentialManager without GMS? | Yes → DC API is primary web channel; No → documented finding (publishable in itself) and QR/deep-link is primary. |
| P4.2 | QR/deep-link flow hardened regardless of P4.1 (sovereign fallback; also the desktop-browser path). Session-forwarding countermeasures reviewed against 18013-7 threat notes. | Relay/forwarding fixtures added to T6 suite; fail closed. |
| P4.3 | Verifier SDK packaging: one-function `verify()` in JS/TS (web, via bb.js — exists today as the node sidecar) first; Rust core is scope-TBD (no clean standalone Rust UltraHonk verifier exists — route via noir_rs/bb FFI or defer; don't let it silently eat a month). Integration guide with the liability pitch up front ("nothing to breach, nothing to subpoena, no processor agreement"). | A stranger integrates the demo gate in <1 hour using docs alone. |
| P4.4 | Reference gated site kept live as standing demo. | Public URL; uptime monitored. |

## Phase 5 — Regulatory and standards beachheads

| # | Action | Exit criterion |
|---|--------|----------------|
| P5.1 | **France first: ARCOM/CNIL double-anonymity.** Map P0–P2 conformance profiles onto the published requirements; identify certification path and gap list. Central question for the gap analysis (not an edge case): ARCOM's framework *assumes a certified age-attribute provider entity exists* — this architecture is stronger than the requirement (no provider at runtime), and "stronger than the form assumes" can read as "doesn't fit the form." | Gap analysis doc; certification application filed or blockers named (likely: legal entity, P6.3). |
| P5.2 | Ofcom "highly effective age assurance" mapping; respond to open consultations with the working system as exhibit. | Submission filed; system cited by name in the record. |
| P5.3 | Texas HB 1181-family mapping for US states: which statutory language admits a protocol vs names vendor categories; produce model statutory language mandating *properties* (one bit, no retention, no issuer visibility, open attestation roots). | Model-language memo suitable for handing to a legislator or amicus author. |
| P5.4 | IETF engagement: track/contribute to the Longfellow-ZK draft ecosystem; publish wire schemas (§6) as an internet-draft candidate. | Draft-00 submitted or contribution merged. |
| P5.5 | Litigation-exhibit package: benchmark report + video + spec + coverage analysis bundled for less-restrictive-means arguments. | One PDF/URL an attorney can cite without technical translation. |

## Phase 6 — Ecosystem and governance

| # | Action | Exit criterion |
|---|--------|----------------|
| P6.1 | **EFF conversation** (litigation exhibit + Certbot/ISRG precedent framing). Ask: amicus interest, introductions to the age-verification litigation docket, co-announcement appetite. | Meeting held; concrete ask answered either way. |
| P6.2 | **Conformance body question.** Scope an ISRG-shaped nonprofit (or joining an existing one): publishes the attestation allowlist, certifies Mode B issuers, owns the conformance test suite. Decide build vs join vs defer. | ADR-006 with decision and rationale. |
| P6.3 | Legal entity + IP posture: entity to stand behind certification filings (P5.1 blocker); engine/protocol IP boundary consistent with existing Decibel IP practice. | Entity decision made; license/ADR-004 finalized. |
| P6.4 | zkPassport / Self / OpenPassport engagement. Differentiators to state plainly: registry-free (ADR-001 — no on-chain anchoring), open attestation allowlist with GrapheneOS first-class, predicate-only wire grammar. Look for circuit-level collaboration, not duplication. | Contact made; overlap/collaboration map written. |
| P6.5 | GrapheneOS project heads-up: the system consumes their published AVB keys via raw attestation — the pattern they've lobbied relying parties toward. Possible mutual amplification. | Notified; any feedback on allowlist format incorporated. |
| P6.6 | Name the thing. "One-bit verifier" is the spec name; decide the public name before P2.1 fixes it by accident. | Name chosen; repo, spec, and write-up consistent. |

---

## Dependency notes

- **P1.0 is the critical path** — it gates P1.2 (can't audit circuits that don't exist), the P1.1 Circuit-E column, and the credible version of every public claim.
- P1.2 gates the **production/regulatory tier** (Phase 5 claims, "use in production"); the research preview needs only P1.0 + P1.3 + P1.5.
- P6.3 (entity or fiscal sponsor) signs the audit engagement → runs on Phase 1's calendar, not Phase 6's.
- Audit/grant lead time ≈ P1.0 build time — apply/book at P1.0 kickoff so they land together.
- P5.1 certification likely blocks on P6.3 (entity).
- P3.1 (mDL circuit) is independent of Phase 2 and can run in parallel with the audit.
- P4.1 spike is a day of work and informs P2.4's write-up; do it early.

## Zero-budget track (what proceeds with no funding at all)

P1.0, P1.1 (documents borrowed, not bought), P1.3, P1.4, P1.5, all of Phase 2 as *research preview* (unaudited banner), P3.1–P3.6, P4.1–P4.4 (hosting ≈ $5/mo), P5.2–P5.5 as drafts, P6.1/P6.4/P6.5/P6.6. Blocked without funds: P1.2 (unless a grant lands — apply to NLnet NGI Zero + OTF Red Team Lab + Aztec grants at P1.0 kickoff; strong topical fit for all three), P5.1 filing, P6.3 incorporation. Net: **development never stops for lack of audit money; only the regulatory claims wait.**

## Standing risks (carry on every review)

1. Circuit soundness (fails open, silent) — mitigated by P1.2/P1.3/P1.4, never eliminated.
2. Regulatory recognition of vendor-less protocols — mitigated by P5.1 (France) and P6.2/P6.3; residual political risk.
3. mDL provisioning gatekeeping (Apple/Google at enrollment) — tracked by P3.2; advocacy surface, not solvable in code.
4. Ecosystem pressure on verifiers to add policy-server calls (V1/V4 erosion) — mitigated by SDK defaults + conformance suite; watch for it in every integration request.
