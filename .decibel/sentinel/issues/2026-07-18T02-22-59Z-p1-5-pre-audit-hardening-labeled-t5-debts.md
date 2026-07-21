---
projectId: onebit
severity: high
status: closed
created_at: 2026-07-18T02:22:59.846Z
epic_id: EPIC-0002
closed_at: 2026-07-21T18:39:54.698Z
---

# P1.5: Pre-audit hardening (labeled T5 debts)

**Severity:** high
**Status:** closed
**Epic:** EPIC-0002

## Details

Close the ponytail debts auditors flag in hour one: (1) SE-wrap credential store — auth-gated AES-GCM key in AndroidKeyStore replacing app-private prefs; (2) wallet-side verifier-signature check on challenges; (3) QR channel alongside deep link. Days not weeks. Exit: ponytail markers removed; T6 fixtures extended per item.

## Resolution

Two shipped hardening items (903231a): (1) SE-wrap — Seal.java (AES-256-GCM, non-exportable AndroidKeyStore/StrongBox key) now seals docwit.txt, enrollproof.bin, and nullifier key k at rest; interim mitigation for self-review F2. (2) Wallet-side verifier-signature check — challenge carries spki (verifier_id=sha256(spki) anchor), verifier signs a canonical field tuple, wallet verifies + refuses on failure (V5 fail-closed); ChallengeSigTest covers authentic/tampered/key-substitution. QR channel deferred (deep link works). Residual: seal key not per-use auth-gated (on-device-malware upgrade path noted in Seal.java).
