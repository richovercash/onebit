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

[2026-08-02] RESIDUALS CLOSED. (1) Seal auth-gated via hybrid envelope: blobs now AES-256-GCM under a fresh per-blob key wrapped by RSA-2048-OAEP in AndroidKeyStore/StrongBox; the private (unwrap) half requires a Class-3 biometric within 300s, the public (seal) half needs no auth — so enrollment flows are untouched and prompt-free, while decrypt-by-malware without user presence is dead. Legacy v1 blobs unwrap via the old alias and transparently re-seal on read (enrolled devices keep their credentials). Present's single biometric moved AHEAD of witness decryption — the CryptoObject prompt for the ephemeral device-sig key also opens the Seal window; still exactly one fingerprint per presentation, now covering unseal+prove+sign. UX order change: fingerprint first, then proving. (2) QR channel shipped: gate page renders the signed challenge deep link as an inline SVG QR (zxing:core, one path element, no external requests); the wallet needs ZERO scanner code — any camera app fires VIEW onebit:// into the existing intent-filter, so the signed-challenge verification path is byte-identical to the tap path. QrTest: challenge-sized link survives QR round-trip (encode->decode) + gate page carries SVG and keeps the tap link; all 15 verifier tests green, both app flavors compile. Honest limits: Seal is AndroidKeyStore-backed so it has no JVM-unit fixture (device-verified path only); 300s-window not per-use CryptoObject (ceiling + upgrade path in Seal.java ponytail marker); cross-device QR response return rides on adb-reverse in the demo — real desktop flow is P4.2.
