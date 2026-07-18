---
projectId: onebit
severity: critical
status: open
created_at: 2026-07-18T02:22:46.195Z
epic_id: EPIC-0002
---

# P1.0: Circuit E + pi_E recursion (critical path)

**Severity:** critical
**Status:** open
**Epic:** EPIC-0002

## Details

Fork zkPassport sig-check/id-data circuits (pinned toolchain nargo 1.0.0-beta.20 / bb 4.2.0 already local in bench/zkpassport-circuits). Bind outputs to commitment C; Circuit P verifies pi_E in-circuit via verify_proof (their outer circuit = working recursion pattern). Move DG1 parsing + century rule in-circuit (spec §3.1 same-rule clause; currently Java-only — pre-found P1.3 discrepancy). Exit: envelope drops binding:"P-only"; Circuit-P-with-recursion p50/p95 on Pixel 9a vs <5s budget. At KICKOFF (not completion): file audit grant applications (NLnet NGI Zero, OTF Red Team Lab, Aztec grants) and/or book auditor. Est 3-6 weeks.
