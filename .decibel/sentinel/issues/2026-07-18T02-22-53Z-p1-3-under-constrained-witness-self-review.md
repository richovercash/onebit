---
projectId: onebit
severity: high
status: closed
created_at: 2026-07-18T02:22:53.246Z
epic_id: EPIC-0002
closed_at: 2026-07-21T18:39:46.388Z
---

# P1.3: Under-constrained-witness self-review

**Severity:** high
**Status:** closed
**Epic:** EPIC-0002

## Details

Hand-check every circuit assert against SPEC §4.2 statement + property-based witness tests (Noir-native under-constraint tooling is thin; Picus et al. are circom-centric — hand review carries the coverage). Checklist committed; spec-vs-circuit discrepancies resolved one direction with ADR note. Pre-found entry #1: century rule Java-only until P1.0 moves DG1 parse in-circuit.

## Resolution

Hand-review of every assert in mono_faithful/enroll/enroll_ecdsa committed as docs/self-review-circuits.md (dd4bd6f). Found + FIXED a critical soundness hole (F1: committed DSC unbound to the signed cert → forgeable age proof; fix binds dsc_modulus to the pubkey inside dsc_tbs, negative-tested). F2 (nullifier k unconstrained) documented with interim SE-wrap mitigation (P1.5) + in-circuit-commitment fix tracked for next circuit pass. N3–N6 accepted/documented.
