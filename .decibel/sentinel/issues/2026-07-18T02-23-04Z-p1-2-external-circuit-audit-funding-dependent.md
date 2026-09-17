---
projectId: onebit
severity: med
status: in_progress
created_at: 2026-07-18T02:23:04.457Z
epic_id: EPIC-0002
---

# P1.2: External circuit audit — funding-dependent

**Severity:** med
**Status:** in_progress
**Epic:** EPIC-0002

## Details

~$40-80k commercial (zkSecurity/Veridise/Least Authority, 4-8wk lead) OR $0 via grants: NLnet NGI Zero (includes security audit via partner), OTF Red Team Lab, Aztec ecosystem grants — applications filed at P1.0 kickoff. Needs entity or fiscal sponsor to sign engagement (P6.3 pulled onto Phase 1 calendar). Scope: Circuit E witness constraints, recursion boundary (C never on wire), nullifier consistency, century rule, Fiat-Shamir nonce+origin binding. GATES production/regulatory tier only — research preview publishes after P1.0+P1.3+P1.5 with UNAUDITED banner. Blocked-on-funding is an acceptable resting state; development continues regardless.

## Notes

[2026-09-17] Two of three applications SUBMITTED 2026-08-25:
- **OTF Security Lab** — form submitted (preferred vendor Least Authority; timeline
  flexible, ideal report end of Jan 2027; full answers in `docs/grants/otf-security-lab.md`).
  Awaiting vendor match; ~4 months scoping→report.
- **Aztec/Noir $20k** — emailed hello@aztec.foundation + rahul@aztec-labs.com (no open
  form; program runs via targeted RFGPs). Forum post was held by new-account moderation —
  CHECK it went live and link it in the email thread. Watch for an
  identity/selective-disclosure RFGP.
- **NLnet NGI Zero** — call OPENED 2026-09-03, deadline 2026-11-03 12:00 CEST. Draft
  ready in `docs/grants/nlnet-ngi-zero.md`, **NOT YET SUBMITTED** ← next action.

Pre-submission cleanup done: repo PUBLIC, history rewritten (gmail/name-typo/local-path
scrub), business-model.md + onebit-pitch.html purged to ../onebit-private/, demo videos
on release v0.1-preview.
