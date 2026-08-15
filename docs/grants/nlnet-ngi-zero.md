# NLnet application draft — form answers

Submit at https://nlnet.nl/propose/ when the call reopens **2026-09-03**
(deadline 2026-11-03 12:00 CEST). Confirm the open fund that day (NGI Zero
Core or successor; privacy & trust-enhancing technologies track). Answers
below map 1:1 to the form fields.

## Contact

- Name: Rich Overcash
- Email: richovercash@pm.me
- Organization: (independent developer — no entity yet; entity/fiscal
  sponsorship is a named milestone, see budget)
- Country: United States

## Project name

OneBit — a one-bit, zero-knowledge age verifier

## Website / wiki

(public repo URL — publish research preview before submitting, or state
"repository published at submission time")

## Abstract (aim ≤ 1200 chars)

Age-verification mandates (UK Online Safety Act, US state laws, EU age
rails) are being met with ID uploads and face scans: surveillance
infrastructure for the entire adult population. OneBit answers an age gate
with exactly one bit and no new observers. A wallet on the holder's phone
reads a government-signed credential once — an ICAO 9303 passport chip or an
ISO 18013-5 mobile driving licence — and thereafter proves "over 18: yes"
in zero knowledge: the document, birth date, and any stable identifier never
leave the device. The phone needs no network access at presentation; there is
no issuer callback, no registry, no age-verification provider to breach or
subpoena — stronger than France's CNIL/ARCOM "double anonymity" requirement,
which still assumes a provider entity. This is working software, measured on
real documents: sub-second to ~4.5 s proofs on a Pixel 9a running GrapheneOS,
real US passport and real California mDL verified end-to-end. The blocking
step to a production/regulatory tier is an external audit of the ~1,200-line
Noir (UltraHonk) circuit family and its protocol boundary — the exact gap
this grant closes, alongside adversarial document coverage and hardening.

## Have you been involved with projects or organisations relevant to this project before?

Solo-built OneBit to its current state: complete two-circuit ZK trust chain
(CSCA→DSC enrollment proof + DSC→SOD presentation proof, chained by a
committed DSC key) proven on real documents on-device; native barretenberg
proving on aarch64 Android (upstreamable toolchain findings — libc++ ABI
bridge, SRS sizing for recursion); privacy analysis and refusal-first wire
grammar (516-challenge fuzz corpus); published measurement reports for
recursion-vs-monolithic proving on phone hardware. Prior work: [fill:
1–2 lines — relevant systems/security background.]

## Requested amount

€50,000

## Explain what the requested budget will be used for

- External ZK circuit audit (bulk of budget, ~€40k): witness-constraint
  review of the enrollment/presentation circuit family (~1,165 lines Noir,
  21 packages), nullifier consistency, Fiat–Shamir binding of nonce+origin,
  century-window date rule, and the attestation/proof envelope boundary.
  ZK-specialist firm (zkSecurity / Veridise / Least Authority); we would
  gladly substitute NLnet's in-kind security audit (Radically Open Security)
  for part of this scope.
- Remediation + regression fixtures for all findings (~€4k of effort).
- Adversarial document coverage (~€3k): acquire/borrow passports covering
  RSA-PSS and legacy SHA-1-era signers across ≥3 issuing countries
  (time-critical: SHA-1-era documents expire ~2027) and fill the published
  coverage matrix.
- Legal entity / fiscal sponsorship to stand behind the audit engagement and
  a French (ARCOM/CNIL) certification filing (~€3k).

Cost-free milestones included: research-preview publication with reproducible
benchmark harness, QR/deep-link channel hardening against 18013-7
session-forwarding, conformance test suite publication.

## Compare your own project with existing or historical efforts

zkPassport / OpenPassport / Self prove passport claims in ZK but anchor to
on-chain registries and target wallet/identity ecosystems; OneBit is
registry-free (a registry is an observer), pins an open attestation allowlist
with GrapheneOS as a first-class citizen, and restricts the wire grammar to
one-bit predicates — attribute disclosure is a protocol violation, not a
configuration. Google's Longfellow-ZK (libzk) is a proving library, not a
deployable verifier with a refusal policy. Commercial age-verification
providers (Yoti, VerifyMy) are the surveillance architecture this replaces:
they see the user, we structurally cannot. mDL presentment per ISO 18013-5
reveals a stable, linkable MSO to every verifier; OneBit uses the mDL as an
issuance rail — ingest once, derive an unlinkable credential — repairing the
linkability criticism rather than inheriting it.

## What are significant technical challenges you expect to solve during the project?

Under-constrained-witness risk in the circuit family (the audit's core);
Noir-native constraint-review tooling is thin (Picus et al. are
circom-centric), so hand-review plus property-based witness tests carry
coverage. Recursive proof verification on phones measured 4× over budget
(775k gates, 20.3 s) — solved by amortized enrollment; the audit must
validate the amortization's security argument (attestation-backed provenance
tier vs full in-ZK tier). Algorithm coverage across the real CSCA/DSC
population (RSA-PSS, ECDSA curves incl. Brainpool, RSA-6144, SHA-1 era)
without silent failure. Cross-device QR flow hardening against session
forwarding (18013-7 threat notes).

## Describe the ecosystem of the project

Holders: anyone facing an age gate; GrapheneOS/de-Googled users are
first-class (no GMS dependency anywhere). Verifiers: websites under UK OSA /
US state / EU obligations — a one-function verify() SDK. Standards and
policy: ARCOM/CNIL double-anonymity mapping (France first), Ofcom "highly
effective age assurance" consultation responses, IETF wire-schema draft;
engagement planned with EFF (litigation exhibit for less-restrictive-means
arguments), GrapheneOS project (attestation allowlist consumes their
published AVB keys), and the Noir/Aztec ecosystem (circuit collaboration
with zkPassport rather than duplication). All code AGPL-3.0/Apache-2.0.

## Attachments

SPEC_one_bit_verifier.md, ROADMAP, measurement reports
(docs/measurement-*.md), coverage matrix.

## Generative AI disclosure

Development assisted by an AI coding tool operated by the applicant; all
design decisions, measurements, and this application's claims are
human-verified against the repository.
