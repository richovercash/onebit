# Stage: packaging the native prover into the wallet (JNI)

*Turning the standalone native-proving win into something the app itself calls.*

## What shipped

The wallet app now carries a native proving library and can generate a
document-bound ZK proof **in-process**, no WebView:

- `libonebitprover.so` — a Rust `cdylib` (`bench/noir-rs/onebitprover`) exposing
  one JNI entry point, `Java_onebit_wallet_NativeProver_prove`, over noir-rs +
  Aztec's native barretenberg.
- `onebit.wallet.NativeProver` (Java) — `System.loadLibrary("onebitprover")`
  and `native byte[] prove(circuitJson, witness, g1Path, lowMem)`.
- Bundled in `app/src/main/jniLibs/arm64-v8a/`: the cdylib plus `libc++.so`.

Verified on the GrapheneOS Pixel 9a: the library **loads and proves inside the
app** (`ONEBIT_NATIVE: lib loaded OK` → `PROVE OK, proof 16132 bytes`).

## The one hard problem, and its fix

Inside an app's linker namespace you cannot use the platform libc++ the way a
standalone adb-shell binary can — and the NDK's libc++ is `std::__ndk1`, while
Aztec's barretenberg needs upstream `std::__1` (see
`measurement-native-proving.md`). The cdylib's `DT_NEEDED` is literally
`libc++.so` with 135 undefined `__1` symbols.

**Fix:** bundle the phone's own platform `libc++.so` (which is `__1`) into
`jniLibs/arm64-v8a/libc++.so`. The app's linker finds it there to satisfy the
cdylib's `DT_NEEDED`, and the cdylib's internal shim (`cxxstub.o`, linked in)
supplies the glibc-isms (`bcmp`, `__ctype_*`, `__errno_location`, `seekpos`)
that the platform libc++ expects. No custom libc++ build required.

> Caveat to revisit for production: bundling a copy of the platform libc++ works
> and is stable across current AOSP/GrapheneOS, but it's a platform-internal lib.
> The clean long-term option is a statically-linked upstream `__1` libc++ inside
> the cdylib. Fine for the reference wallet; note it before shipping widely.

## Performance: foreground vs background (important)

| Condition | Slim proof (Pixel 9a) |
|---|---|
| Standalone, all 8 cores (foreground-equivalent) | **~2.5 s** |
| Standalone, little cores 0-3 only (`taskset 0f`) | ~8.3 s |
| **In-app, screen locked (`/background` cpuset)** | ~33 s |

The 33 s in-app figure is **not** the real number — a screen-locked app lands in
the `/background` cpuset, confined to cores 0-3 *and* frequency-capped. During a
real presentation the app is **foreground** (`top-app` cpuset: all 8 cores, full
clocks) because the user just tapped through and authenticated — that's the
~2.5 s case. The app already acquires a `PARTIAL_WAKE_LOCK` and raises the
proving thread to `THREAD_PRIORITY_URGENT_DISPLAY` for the presentation path.

Proven by symmetry: `taskset`-pinning the standalone binary to the little cores
reproduces the slowdown, and releasing it to all cores restores ~2.5 s.

## Remaining to wire it into the real flow

- Replace the WebView prover in `Present.java` with `NativeProver.prove` for the
  monolithic/slim path (the JNI entry already returns `[public_inputs][proof]`).
- Bundle the SRS: 55k gates needs ~33 MB of G1 points; ship it in the app (V1 —
  no runtime fetch) or fold into the one-time enrollment download.
- Foreground guarantee: run proving while the presentation Activity is resumed
  (top-app cpuset) — already the case for a user-initiated gate.
- Build recipe + crate: `bench/build-native/` (`onebitprover_crate`, `build.sh`,
  `cxxstub.c`). The 30 MB `.so` is gitignored; rebuild from the recipe.
