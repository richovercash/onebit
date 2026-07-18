---
projectId: onebit
severity: high
status: open
created_at: 2026-07-18T02:22:53.246Z
epic_id: EPIC-0002
---

# P1.3: Under-constrained-witness self-review

**Severity:** high
**Status:** open
**Epic:** EPIC-0002

## Details

Hand-check every circuit assert against SPEC §4.2 statement + property-based witness tests (Noir-native under-constraint tooling is thin; Picus et al. are circom-centric — hand review carries the coverage). Checklist committed; spec-vs-circuit discrepancies resolved one direction with ADR note. Pre-found entry #1: century rule Java-only until P1.0 moves DG1 parse in-circuit.
