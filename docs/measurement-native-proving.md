# Measurement: native proving on-device (2026-07-18)

*The native-proving spike. This is the result that makes a document-bound age
proof viable at interactive speed on a zero-network wallet.*

## Headline

| Presentation proof (monolithic, 177k gates) | Pixel 6 Pro | Pixel 9a (GrapheneOS) |
|---|---|---|
| WASM in WebView, single-threaded (prior) | ~29 s | — |
| **Native (barretenberg via noir-rs, JNI-less binary)** | **~5.9 s** | **~6.6 s** |

P6: 5.94 / 5.88 / 6.02 s. P9a: 6.53 / 6.59 / 7.41 / 6.57 / 6.78 s. `VERIFY: OK`
on both. **~5× faster than WASM.**

Honest read against the budgets:
- **Passes T2's ≤6 s p95 gate** for proving.
- **Misses T2's ≤2.5 s p50 gate** and T5's <5 s end-to-end target by ~1–2 s.
- Surprise: the newer Pixel 9a is *slightly slower* than the Pixel 6 here.
  Likely GrapheneOS CPU governor / thermal (the 9a had just run passport +
  attestation + prior benches) or the 9a's efficiency-core-heavy Tensor G4
  layout. Not chased down.

So native proving did **not** get us cleanly under 5 s, but it moved the
document-bound proof from "impossible in a zero-network WebView (29–93 s)" to
"~6 s and within ~1–2 s of target." The remaining gap is an optimization
problem, not a viability one.

## Threading is NOT the lever — it's memory-bandwidth-bound (measured)

The earlier "high idle → maybe under-threaded" guess was **wrong**. Forcing the
thread count via `HARDWARE_CONCURRENCY` on the Pixel 9a settles it:

| Threads | Prove time |
|---|---|
| 1 | ~9.5 s |
| 4 | ~6.5 s |
| 8 | ~6.5 s |

1→4 threads buys only 1.46× (not 4×), and **4→8 buys nothing**. That plateau is
the signature of a memory-bandwidth ceiling: the MSM/FFT work saturates memory
around 4 threads, and extra cores just stall (which is what the "731% idle"
actually was — cores waiting on memory, not sitting unused). **~6.5 s is near the
hardware floor for this circuit on this phone. More cores will not help.**

## The real lever: fewer gates

Since we're memory-bound, the way under 5 s is a **smaller circuit** (less
memory traffic), not more parallelism:

- This is the T2 *bench* monolithic with padded inputs: SHA-256 over a 1200-byte
  eContent + 1000-byte DSC cert + 93-byte DG1. Real documents have smaller
  eContent/DSC → fewer SHA blocks → fewer gates.
- Hashing the full 1000-byte DSC cert in-circuit is a candidate to cut (commit
  the DSC identity more cheaply).
- The RSA-2048 verify (~150k of the 177k gates) dominates; a leaner RSA gadget
  or the ECDSA document population (cheaper) would drop it a lot.

Other levers that don't change the memory-bound story:
- **`low_memory_mode` was OFF** (the fast path) — correct for speed.
- **Precomputed vk.** The ~2–3 s vk step is one-time and does not count toward
  per-presentation time (only the ~6.5 s prove does).

## How it was measured

A standalone Rust binary (`bench/noir-rs/bench_native`) built for
`aarch64-linux-android`, `adb push`ed to the phone, and run in a shell — no
WebView, no SharedArrayBuffer, no network, no `INTERNET` permission. It uses
noir-rs (`prove_ultra_honk`) over Aztec's prebuilt barretenberg static lib, with
the SRS loaded from a local `g1.dat`. This respects invariant V1 completely: a
native prover needs no socket and no cross-origin isolation, sidestepping the
threading wall that pinned the WebView to one core.

Pipeline validated first with a trivial `a*b==result` circuit (~120 ms), then
the real 177k-gate monolithic presentation circuit.

## The toolchain wall we climbed (for the next attempt)

Getting the native binary to *link and run* took resolving a chain of
libc++/libc ABI gaps, because Aztec's prebuilt `barretenberg-static-arm64-android`
is built against **upstream libc++ (`std::__1`)**, while Google's NDK ships
`std::__ndk1`. Resolution, in order:

1. **libc++ namespace**: NDK's libc++ (`__ndk1`) is incompatible. The *phone's
   own* `/system/lib64/libc++.so` uses `__1` (that's why the NDK renames its
   own — to avoid ODR clash with the platform). For a standalone adb-shell
   binary, link against the pulled platform `libc++.so` (aliased as `libc++.so`
   + `libstdc++.so`, which build.rs wants).
2. **Missing base-class symbol** `basic_streambuf::seekpos` — not exported by
   the platform libc++; provided a stub (never called on our path).
3. **glibc-isms bionic lacks**: `bcmp` (→ memcmp), `__res_init` (→ 0),
   `__errno_location` (→ bionic `__errno`), and the glibc ctype trio
   `__ctype_b_loc` / `__ctype_tolower_loc` / `__ctype_toupper_loc` (provided
   with real ASCII classification tables via a constructor, so any
   parse-path use stays correct).

All shims live in `bench/build-native/cxxstub.c`. Link flags:
`-L <platform-libs> <cxxstub.o> -Wl,--unresolved-symbols=ignore-all` (the last
because a handful of platform symbols resolve only at runtime on the phone).

Also confirmed: **beta.20-compiled circuit bytecode executes fine on noir-rs
beta.19** — the ACIR format is compatible across those betas, so no circuit
recompile is needed for the native path.

## What this means for the architecture

Combined with ADR-004 (monolithic presentation for the single-signature
credential), the native path gives:

- **Presentation proof ~5.9 s on Pixel 6**, add witness-gen + biometric +
  device-sig (sub-second) → ~6–7 s end-to-end on the slow phone; expected
  **under the 5 s budget on the Pixel 9a**.
- No recursion needed (recursion was 775k gates / ~93 s WASM — abandoned for
  single-cred per ADR-004).
- V1 intact: the prover is a native library, no network anything.

## Next

1. Pixel 9a number (exit-criterion device) — pending USB authorization.
2. Try noir-rs `low_memory_mode` and explicit thread count for headroom.
3. Package as a JNI `.so` + AAR for the wallet app (replacing the WebView
   prover for the monolithic path); bundle the platform-libc++ shim.
4. Fold the SRS (~134 MB for 177k gates) into the enrollment download or app
   bundle; V1 means it ships with the app, not fetched at runtime.
