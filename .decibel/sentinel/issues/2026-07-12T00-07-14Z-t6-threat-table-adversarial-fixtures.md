---
projectId: onebit
severity: high
status: closed
created_at: 2026-07-12T00:07:14.830Z
epic_id: EPIC-0001
closed_at: 2026-07-12T06:17:54.380Z
---

# T6: Threat-table adversarial fixtures

**Severity:** high
**Status:** closed
**Epic:** EPIC-0001

## Details

Adversarial fixtures per SPEC §7: proof replay, cross-origin relay, expired document, wrong-century DOB, farmed nullifier burst. Exit criterion: all fail closed (V6).

## Resolution

Exit criterion met: all threat-table fixtures fail closed. Circuit level (witness generation fails — no proof can exist): expired document, underage holder, wrong-century DOB. Cryptographic: bit-flipped proof → ZK_FAIL via bb.js sidecar. Wire level (VerifySdkTest, 6 fixtures): envelope-origin relay → origin mismatch; device_sig over wrong origin → signature invalid; nonce substitution → nonce mismatch; stub proof under forbidding policy → rejected; mode B → rejected; consistent presentation passes. Challenge over-ask: 516 fuzz/adversarial cases refused (T4). LIVE on GrapheneOS Pixel 9a: replay (pull-to-refresh of granted verdict) → DENIED unknown/replayed nonce; farmed nullifier burst → 4th presentation in same epoch DENIED by rate limit, demonstrating anonymous rate-limiting (verifier counts nullifier uses without identity). Test totals: core 12 (PA 8 + challenge fuzz 4), verifier 13 (attestation 7 + wire 6), plus circuit negative fixtures via nargo.
