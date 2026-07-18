projectId: onebit
severity: critical
status: in_progress
created_at: 2026-07-18T02:22:46.195Z
epic_id: EPIC-0002
description: |-
  

  [2026-07-18] Circuit E v0 built + committed (76901c1). circuits/e: proves SHA256(DG1)∈eContent, RSA-2048 PKCS#1v1.5 DSC sig, depth-20 Poseidon Merkle membership, C=Poseidon2(dob,expiry,docHash,k,salt) with §3.1 century rule in-circuit (docHash=Poseidon(eContent hash)). Outputs (C, computed root) — output form chosen so gen_inputs needn't run Poseidon in Python; Circuit P will assert root==pinned. Measured i9/32T bb4.2.0: 177,495 UH gates, ~1.05s prove, proof VERIFIES. Remaining for P1.0 (NOTES.md): Circuit P v1 with std::verify_proof(π_E) recursion + C-rebind assertion + on-Pixel-9a remeasure; coverage variants PSS/ECDSA/4096 (P1.1); real Merkle root over bundled master list (currently synthetic path); docHash preimage review. Also this session: local-only git repo initialized (git init, .gitignore excludes build/node_modules/vendored clones; 286 files, 20MB), initial commit of T1-T6 state.

  [2026-07-18] RECURSION WORKS END-TO-END + first on-device measurement (docs/measurement-recursion-on-device.md). Circuit P v1 (775,800 gates) verifies pi_E in-circuit via verify_proof_with_type(vkey[115],proof[500],[C,root],key_hash,HONK_ZK=6); pins E identity by Poseidon2(vkey)==e_vkey_hash, asserts root==r_icao, rebinds C=Poseidon2(dob,expiry,docHash,k,salt). Witness solves, desktop prove 4.8s/32T, VERIFIES. binding:P-only gap closed cryptographically. ON PIXEL 6 PRO: ~93s per proof, 3 consistent runs — but backend fell back to SINGLE-THREADED Wasm (crossOriginIsolated/SharedArrayBuffer not active in WebView despite COOP/COEP headers on intercepts). So 93s is worst-case unthreaded on the slower phone. Verdict: recursion sound + correct, too slow per-presentation. Next: (1) fix WebView threading → ~12-23s (needed regardless), (2) amortize pi_E — recurse at ENROLLMENT (already a one-time 10-30s step) or once/epoch into a device-bound session token, presentations then run the ~3k-gate cheap circuit sub-second. NOT a soundness issue — pure perf/architecture, the exact P1.0 fork the roadmap flagged. Committed: circuits/e, circuits/p v1, circuits/commit, docs/ (glossary, stage explainer, this measurement), on-device bench harness. Also P1.4 partial: local git repo initialized, 4 commits.
updated_at: 2026-07-18T06:31:22.101Z
