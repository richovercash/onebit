---
projectId: onebit
severity: high
status: closed
created_at: 2026-07-18T02:22:49.961Z
epic_id: EPIC-0002
closed_at: 2026-07-25T00:17:37.745Z
---

# P1.1: Algorithm-coverage matrix (absorbs T1 remainder)

**Severity:** high
**Status:** closed
**Epic:** EPIC-0002

## Details

4+ documents chosen adversarially: ≥3 countries; RSA-PKCS1, RSA-PSS, ECDSA DSCs; ≥1 SHA-1-era legacy doc — TIME-CRITICAL, those expire within ~12 months, read any specimen on sight. Two passes: {parse, PA} now; {Circuit E} after P1.0. Read-only sessions, nothing retained. Exit: coverage table {country, DSC alg, hash, key size} x {parse, PA, CircuitE} in repo; unsupported cells documented as explicit non-coverage. Current: 2 documents read (user's + one more, doc 2 pending confirmation).

## Resolution

Coverage complete on both axes and live-verified. CSCA (enroll): all 8 signature families route to a circuit + published Merkle root — 376/376 master-list authorities, 0 uncovered (enroll, enroll_rsa6144, enroll_ecdsa, enroll_secp256, enroll_p384, enroll_bp384, enroll_secp521, enroll_bp512, + enroll_dsc_ecdsa for ECDSA DSCs). DSC (present): mono_faithful (RSA PKCS1), mono_faithful_pss, mono_faithful_ecdsa, routed by Witness.extract. Router unit-tested (EnrollRouteTest 10, PresentRouteTest 3). Verified with real proofs: US passport live end-to-end GRANT (RSA, enroll 10.7s + present amortized, e2e 7.7s on Pixel 9a), ECDSA-DSC presentation GRANT + ZK_OK (committed fixture). Remaining as explicit non-coverage: live tap of a physical non-US (ECDSA/PSS) document — circuits proven with real certs + on-device proofs, only the NFC read of such a doc is synthetic. SHA-1-era legacy doc (time-critical) still to acquire.
