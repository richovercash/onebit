---
projectId: onebit
severity: high
status: open
created_at: 2026-07-18T02:22:56.552Z
epic_id: EPIC-0002
---

# P1.4: Repo bootstrap + CI adversarial harness

**Severity:** high
**Status:** open
**Epic:** EPIC-0002

## Details

git init (project not under version control!), .gitignore (build/, node_modules/, bench clones, local.properties), then CI on ubuntu-24.04 runners (native glibc ≥2.38 for bb — no docker workaround needed in CI). Promote 516-challenge corpus + T6 fixtures + core/verifier JUnit suites; add mutation fuzzing on challenge JSON and proof envelopes. Exit: CI red on any refusal/verifier regression; corpus grows monotonically.
