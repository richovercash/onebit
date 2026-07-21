# Measurement: recursive Circuit P v1 on real hardware

## Update 2026-07-21 — NATIVE multi-threaded on Pixel 9a: ~20.3 s

The 2026-07-17 number below (93 s) was the **WASM WebView** path, pinned to one
core. The path that actually runs presentations is the **native** prover
(noir-rs, all cores) — the same one that does mono_faithful in ~2.5 s. Measured
it on the Pixel 9a (tegu, Tensor G4):

| Metric | Value |
|---|---|
| Circuit | Circuit P v1, 775,800 gates (recursion: verifies π_E in-circuit) |
| Prover | native noir-rs, multi-threaded, `low_mem=false` |
| SRS load (one-time) | 5.0 s (8,388,609 G1 points) |
| vk (one-time) | 7.8 s |
| **Per-proof** | **20.3 s** (3 runs: 20.34 / 20.23 / 20.39 — dead stable) |
| Peak memory | ~2.6 GiB |
| Proof size | 16,196 bytes · VERIFY OK |
| Desktop 32-thread reference | 4.8 s |

**The crash we hit first (worth recording):** the native prover *aborted* on
Circuit P before this run. Cause was **not** the recursion opcode — it was SRS
sizing. noir-rs's `setup_srs_from_bytecode` multiplies circuit size by
`ULTRA_HONK_SRS_MULTIPLIER = 8`, so Circuit P wants a 2^23-point (~512 MB) SRS;
the bundled device `g1_big.dat` is only 150 MB (fine for the non-recursive
circuits, short for this one). It ran off the end of the slice and panicked
across the FFI boundary (SIGABRT — the Java `catch` never fires). Desktop `bb`
sizes to the real ~2^20 circuit so it never needed more than the 67 MB CRS.
Fix: push a 512 MB CRS prefix (`Range: bytes=0-536870975` from
`crs.aztec.network`, fetched host-side — the phone stays offline, V1 intact).
See memory `onebit-native-recursion-srs`.

**Verdict unchanged, now with a native number:** 20 s is 4× the <5 s
presentation budget even multi-threaded. So the decision holds and is
reinforced — **do not recurse per presentation.** Recurse once at enrollment
(a 10–30 s one-time step where 20 s is completely acceptable) and keep
presentations on the cheap ~0.6 s non-recursive circuit. The recursion is
proven correct AND fast-enough-as-a-one-time-cost on real 2025 phone hardware;
what's left is the amortization architecture, not the crypto.

---

# Measurement: recursive Circuit P v1 on real hardware (2026-07-17)

## Result

| Metric | Value |
|---|---|
| Device | Pixel 6 Pro (Tensor G1) — the slower of the two phones |
| Circuit | Circuit P v1, 775,800 gates (recursion: verifies π_E in-circuit) |
| Warm-up (load WASM + backend) | 757 ms |
| **Per-proof time** | **~93 s** (3 runs: 94.2 s, 93.2 s gaps, consistent) |
| Backend actually used | **`Wasm` — single-threaded** |
| Desktop reference (32-thread) | 4.8 s |

## The headline: it fell back to single-threaded

The prover reported backend `Wasm`, not `WasmWorker`. It ran on **one core**.
The WebView did not expose `SharedArrayBuffer` (needs `crossOriginIsolated`,
which needs COOP/COEP to take effect on the document *and* the WebView to
honor cross-origin isolation — Android WebView is finicky here). So this 93 s
is a worst-case, unthreaded number on the slowest device.

Rough headroom if threading is fixed: the Pixel 6 has 8 cores (2+2+4). Even a
conservative 4× from threading → **~23 s**; the desktop's 4-thread run was
4.8 s, and single-thread desktop would be ~19 s, so the phone's per-core is
~5× the desktop core — consistent with 93 s single-threaded.

## Verdict against the <5 s budget

Fails, as anticipated. Two independent levers, both documented in
`stage-circuits-E-and-P.md`, now with data behind them:

1. **Fix WebView threading (immediate).** Get `crossOriginIsolated` true so
   the prover uses `WasmWorker` + N threads. Expected ~4–8× → ~12–23 s. Still
   over 5 s alone, but necessary regardless.
2. **Amortize π_E (the real fix).** The 770k-gate cost is *entirely* the
   in-circuit verification of π_E. That doesn't have to happen every
   presentation. Options:
   - Verify π_E once per epoch into a cheap short-lived "session commitment,"
     then presentations within the epoch run the ~3k-gate v0-style circuit
     (sub-second). Adds a caching layer + a security argument (the session
     token must be device-bound and epoch-scoped so it can't be exported).
   - Or move the recursion to *enrollment*: prove π_E once, produce a fresh
     commitment already tied to the device key, and never recurse at
     presentation. This is the most promising — enrollment is already a
     one-time 10–30 s step where a heavy proof is acceptable.

## Decision

Recursion is **proven to work on-device** (real 775k-gate recursive proof
generated on a phone — the hard part is done and correct). It is **too slow
per-presentation** in its current form. Next session:

1. Fix WebView `crossOriginIsolated`/threads; re-measure (quick win, needed
   anyway).
2. Prototype the **amortized-π_E** architecture (recurse at enrollment or once
   per epoch, cheap presentations after). This is the design change that makes
   the binding both real *and* fast.

Neither is a soundness problem — the credential binding is cryptographically
correct today. This is purely a performance/architecture optimization, exactly
the fork the roadmap flagged for P1.0.
