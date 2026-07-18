projectId: onebit
severity: high
status: in_progress
created_at: 2026-07-12T00:07:04.680Z
epic_id: EPIC-0001
description: |-
  

  [2026-07-12] Kickoff. Device pool: Pixel 6 Pro (Tensor G1, stands in for lower tier until a true low-end phone is acquired) + Pixel 9 (GrapheneOS). Plan: (1) research current buildability of google/longfellow-zk (C++/cmake, IETF libzk draft) and zkPassport Noir circuits + barretenberg native Android; (2) representative statement = SHA-256 over ~1KB DG1/SOD + RSA-2048 sig verify + date comparison; (3) desktop numbers first for sanity, then NDK cross-compile and on-device p50/p95 vs the ≤2.5s/≤6s gate.

  [2026-07-12] Benchmark executed, decision recorded as ADR-0003: OPTION B (split+recursion, Noir/UltraHonk, fork zkPassport circuits). Data in bench/RESULTS.md. Key numbers: monolithic Option-A analog (real RSA-2048 sig, 2×SHA-256 over 1.2KB+1KB, Merkle-20, predicates, nullifier) = 177,350 UH gates, 1.13s p50 on i9-13900KF/32T → ~7-9s Pixel 6, ~15s+ low-end: fails the ≤2.5s/≤6s gate 3-6×. Independent kill: longfellow-zk has NO RSA circuits (ecdsa/sha/mdoc/cbor only) — cannot cover majority RSA-signed SODs; Longfellow desktop build also blocked locally (no clang/sudo), moot given the RSA gap. Option B core: presentation circuit 3,026 gates / 0.15s desktop; enrollment circuits cached (zkpassport dsc_rsa4096=248k, id_data_rsa2048=108k gates); their outer_count_4 aggregator = 3.29M gates as recursion upper bound. Toolchain pinned: nargo 1.0.0-beta.20 (~/.nargo), bb 4.2.0-aztecnr-rc.2 (~/.bb, needs docker ubuntu:24.04 on this glibc-2.35 host). REMAINING before closing T2: native on-device p50/p95 of Circuit P (with 1× in-circuit UH verify) on Pixel 6 + Pixel 9 once Circuit P exists — fold into T4/T5. Also: acquire true low-end reference device.
updated_at: 2026-07-12T01:30:59.412Z

## Resolution

Exit criterion met: numbers recorded vs §4.2 gate (bench/RESULTS.md) and ADR-0003 records the Option B decision. Now includes a real on-device data point: Circuit P v0 proves in 634 ms on Pixel 9a (GrapheneOS, WASM in WebView) — comfortably inside the presentation-time budget; monolithic Option A analog fails the low-end gate 3-6× by extrapolation AND Longfellow lacks RSA circuits entirely. Residual (post-MVP, tracked with Circuit E work): p50/p95 of Circuit P WITH pi_E recursion, and a true low-end reference device.
