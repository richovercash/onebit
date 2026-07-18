projectId: onebit
severity: high
status: in_progress
created_at: 2026-07-12T00:07:10.332Z
epic_id: EPIC-0001
description: |-
  

  [2026-07-12] Build plan: core/ gains Challenge (strict §6.1 parser: whitelist grammar {age_gte}, strict types, UNKNOWN-KEY REJECTION as the over-ask defense, fail-closed RefusalException with reason), Response envelope (§6.2), and Nullifier.ctx(verifier_id, epoch) = SHA-256(vid ‖ 0x00 ‖ epoch) mod p as the canonical public-input derivation shared by wallet and verifier SDK. N itself is computed in-circuit (Poseidon2(k, ctx)); bench/presentation circuit's ctx becomes a public input to match. Exit test: seeded fuzz (mutations over valid challenge: junk, missing/extra fields, type swaps, unknown predicates, range abuse) + hand adversarial fixtures (attribute-release over-asks) — all must refuse. Verifier-signature check on challenge deferred to T5 channel wiring. Circuit P recursion (π_E verify) also lands with T5 zkpassport fork integration.
updated_at: 2026-07-12T03:24:45.462Z

## Resolution

Exit criterion met: fuzzed malformed/over-asking challenges all refused. core/Challenge.java implements SPEC §6.1 with whitelist-everything posture: closed predicate grammar {age_gte}, strict type checks on every field, unknown-key rejection at every object level (the over-ask defense), bare-https origin, 32B nonce, hex verifier_id, RefusalException with reason; display() renders verifier+predicate for pre-auth UX. Tests: 16 hand adversarial fixtures (dob_disclose, send_dob, disclose arrays, attribute lists, range/type/tier/origin/version abuse) + 500 seeded structural mutations (key-drop/unknown-key/type-swap) — all refused; the fuzzer caught one real gap during development (attestation.allowlist_url accepted as number — presence-checked but not type-checked; fixed by type-checking every field, not just read fields). core/Nullifier.java: canonical ctx = SHA-256(verifier_id ‖ 0x00 ‖ epoch) mod p (BN254); presentation circuit takes ctx as PUBLIC input and computes N = Poseidon2(k, ctx) — cross-circuit N consistency confirmed against monolithic bench circuit (identical outputs, same k/ctx). Deferred to T5: §6.2 response envelope construction (trivial, needs the channel), verifier-signature check on challenge, Circuit P recursion (π_E in-circuit) + its on-device timing.
