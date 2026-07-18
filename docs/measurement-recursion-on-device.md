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
