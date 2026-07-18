# Architecture finding: recursion vs monolithic, and the threading wall

*From the "fix threading + prototype amortization" session. Real on-device
numbers that revise the T2/ADR-003 proving decision.*

## The two numbers that matter

Both circuits, same Pixel 6 Pro, both **single-threaded** (see threading wall
below):

| Presentation approach | Gates | Per-proof (P6, 1 thread) | Desktop (32T) |
|---|---|---|---|
| **Recursion** (Circuit P v1 verifies π_E in-circuit) | 775,800 | **~93 s** | 4.8 s |
| **Monolithic** (Option A: do the RSA every time) | 177,350 | **~29 s** | 1.13 s |

**Monolithic is ~3.2× faster than recursion on real hardware.**

## Why this is surprising — and what it means

The whole point of the enrollment/presentation *split* (ADR-003, Option B) was
to do the expensive RSA signature check **once** at enrollment, cache the proof
π_E, and make each presentation cheap. But verifying a cached proof
*recursively* (the `verify_proof_with_type` verifier) costs **775k gates** —
**more than the 177k gates it takes to just redo the RSA check from scratch.**

The recursion overhead exceeds the cost it was trying to avoid. For a credential
backed by a **single signature**, the split is counterproductive: monolithic
wins.

Why does the split pay off for zkPassport, then? Because their `outer` circuit
aggregates **4+ sub-proofs** (CSC→DSC, DSC→ID, integrity, disclosure). One
recursion amortizes many signature checks. We have exactly one (the DSC over the
SOD), so we pay recursion's fixed cost with nothing to amortize it against.

### Consequence for ADR-003

ADR-003 chose Option B (recursive split) over Option A (monolithic) on the
*assumption* that recursion would make presentation cheap. The on-device
measurement falsifies that assumption for the single-signature case. **ADR-003
should be amended**: for the current single-DSC credential, **monolithic
presentation is the faster design.** Keep recursion in reserve for when we
aggregate multiple credentials (mDL + passport, multi-document) — that's when it
earns its cost.

The recursion work is not wasted: Circuit P v1 proves the binding is
*cryptographically correct*, and the recursion machinery is exactly what the
multi-credential future needs. It's the right tool, applied one signature too
early.

## The threading wall (Part 1 of this session)

Both numbers above are **single-threaded**. bb.js can use multiple cores via Web
Workers + `SharedArrayBuffer`, which needs the document to be
`crossOriginIsolated` (COOP + COEP headers). The proof ran single-threaded
because the WebView never became cross-origin isolated.

Here's the bind, and it's structural, not a bug:

- To get `crossOriginIsolated`, the headers must reach the document. The
  **reliable** way is serving over HTTP with those headers.
- An in-app HTTP server (even localhost) **requires the `INTERNET`
  permission** — which the wallet deliberately does not hold (**invariant V1,
  zero network**). Adding it to speed up proving would trade away the
  "physically cannot phone home" guarantee that is the whole point.
- Setting COOP/COEP via `shouldInterceptRequest` (no permission needed) does
  **not** reliably trigger cross-origin isolation in Android WebView,
  especially for a synthetic `https://onebit.zk` origin.

So: **the zero-network posture (V1) and WebView WASM threading are in tension.**
You can have threaded in-WebView proving or a no-INTERNET app, not both, without
more work.

### The real fix: native proving via JNI/NDK

The performant path that respects V1 is to drop the WebView entirely for proving
and call **barretenberg's native C++ prover through JNI** (NDK build). Native
proving:

- uses all cores directly (no SharedArrayBuffer, no workers, no COI);
- needs no socket and no `INTERNET` permission (V1 intact);
- is faster per-core than WASM anyway.

Expected effect: monolithic at ~29 s single-threaded WASM → plausibly **~4–8 s**
native multi-threaded on the P6 (8 cores, plus native > WASM per core). That
finally approaches the < 5 s budget **without** recursion and **without**
network. This is the single highest-value optimization left, and it's a real
chunk of work (NDK toolchain for barretenberg + JNI bindings + bundling the
`.so`).

## Recommended plan (updates P1.0)

1. **Amend ADR-003**: monolithic presentation for the single-signature
   credential; recursion reserved for multi-credential aggregation. (ADR drafted
   this session.)
2. **Native proving spike (JNI/barretenberg)** — the threading fix that keeps
   V1. Measure monolithic native multi-threaded on the P6; that number decides
   whether we hit < 5 s.
3. Keep Circuit E + Circuit P v1 in the tree — correct, tested, and the basis
   for the multi-credential path (P3.1 mDL).

## Honest status

- Credential binding: **cryptographically done and correct** (Circuit P v1
  verifies π_E, rebinds C).
- Presentation speed: **not yet at budget**; the path to get there is native
  proving + monolithic, not recursion. Measured, not guessed.
- No soundness issue anywhere — this is entirely performance/architecture.
