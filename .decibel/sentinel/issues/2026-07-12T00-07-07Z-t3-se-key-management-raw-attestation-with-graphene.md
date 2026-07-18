projectId: onebit
severity: high
status: in_progress
created_at: 2026-07-12T00:07:07.516Z
epic_id: EPIC-0001
description: |-
  

  [2026-07-12] Plan: (1) wallet app gains per-verifier key generation in AndroidKeyStore — StrongBox-backed, setUserAuthenticationRequired(true), setAttestationChallenge(nonce), platform BiometricPrompt gating each signature; exports attestation chain + signed challenge for the verifier. (2) New verifier/ JVM module: X.509 chain validation to allowlist roots, BC ASN.1 parse of the key-attestation extension (challenge, RootOfTrust: verifiedBootState+verifiedBootKey, osPatchLevel [706], userAuthRequired via absence of noAuthRequired [503] in teeEnforced), policy per SPEC §5.2 allowlist JSON. GrapheneOS detection: chain roots to Google HW root; SelfSigned boot state + GrapheneOS AVB key hash in RootOfTrust — allowlist carries permitted verified-boot keys. Demo: P6 stock (Verified state) vs P9 GrapheneOS (SelfSigned + GOS key); stale-patch rejection via min_patch_level knob.
updated_at: 2026-07-12T01:38:27.321Z

## Resolution

Exit criterion met on hardware. Wallet: per-verifier K_v (alias kv-&lt;verifier_id&gt;) in AndroidKeyStore, StrongBox-backed (Titan M2 confirmed via securityLevel=StrongBox in attestation), setUserAuthenticationRequired + AUTH_BIOMETRIC_STRONG per-use, attestation challenge bound, platform BiometricPrompt gates signing; exports chain/nonce/sig. Verifier module: offline chain validation to allowlisted roots (both live Google HW roots pinned by SPKI), BC ASN.1 attestation-extension parse, verified-boot policy with GrapheneOS as first-class allowlist entry (SelfSigned + published AVB key hash — Pixel 9a hash 0508de44… cross-verified against grapheneos.org publications), min_patch_level knob, userAuthRequired enforcement; 7/7 unit tests on synthetic chains cover all fail-closed paths. Live demo on GrapheneOS Pixel 9a: first run rejected (key not allowlisted), allowlisted after vendor cross-check → ATTESTATION OK (StrongBox, SelfSigned, patch 202606, authRequired); min_patch_level 202607 → rejected fail-closed. Gotcha logged: USE_BIOMETRIC permission required in manifest for BiometricPrompt. Bonus: passport PA also verified on the P9a (second T1 device data point).
