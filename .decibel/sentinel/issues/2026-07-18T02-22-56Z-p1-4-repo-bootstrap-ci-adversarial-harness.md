---
projectId: onebit
severity: high
status: closed
created_at: 2026-07-18T02:22:56.552Z
epic_id: EPIC-0002
closed_at: 2026-07-21T18:39:50.401Z
---

# P1.4: Repo bootstrap + CI adversarial harness

**Severity:** high
**Status:** closed
**Epic:** EPIC-0002

## Details

git init (project not under version control!), .gitignore (build/, node_modules/, bench clones, local.properties), then CI on ubuntu-24.04 runners (native glibc ≥2.38 for bb — no docker workaround needed in CI). Promote 516-challenge corpus + T6 fixtures + core/verifier JUnit suites; add mutation fuzzing on challenge JSON and proof envelopes. Exit: CI red on any refusal/verifier regression; corpus grows monotonically.

## Resolution

scripts/test.sh + .github/workflows/ci.yml committed (b7b8f64). Runs the JUnit suites (core: PassiveAuth 8 + 516-challenge refusal fuzz + nullifier; verifier: attestation 7 + wire/dual-proof fixtures) and a compile+witness-solve smoke on the 3 live circuits. Green locally + wired to GitHub Actions (ubuntu-24.04 native bb, fixed-string steps only — no untrusted-input interpolation).
