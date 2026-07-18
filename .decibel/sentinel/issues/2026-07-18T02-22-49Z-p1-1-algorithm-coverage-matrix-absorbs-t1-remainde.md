---
projectId: onebit
severity: high
status: open
created_at: 2026-07-18T02:22:49.961Z
epic_id: EPIC-0002
---

# P1.1: Algorithm-coverage matrix (absorbs T1 remainder)

**Severity:** high
**Status:** open
**Epic:** EPIC-0002

## Details

4+ documents chosen adversarially: ≥3 countries; RSA-PKCS1, RSA-PSS, ECDSA DSCs; ≥1 SHA-1-era legacy doc — TIME-CRITICAL, those expire within ~12 months, read any specimen on sight. Two passes: {parse, PA} now; {Circuit E} after P1.0. Read-only sessions, nothing retained. Exit: coverage table {country, DSC alg, hash, key size} x {parse, PA, CircuitE} in repo; unsupported cells documented as explicit non-coverage. Current: 2 documents read (user's + one more, doc 2 pending confirmation).
