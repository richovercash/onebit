# Technical Learnings: onebit

> A living document of lessons learned, gotchas, and insights.

---

### [2026-07-12 06:18:15] Offline ZK proving in an Android WebView with zero network permission (bb.js + noir_js)
**Category:** integration

Pattern proven on GrapheneOS Pixel 9a (634ms UltraHonk proof, 2^12 circuit): run bb.js + noir_js inside a hidden WebView in an app with NO INTERNET permission by serving everything through WebViewClient.shouldInterceptRequest. Key traps and fixes: (1) Don't bundle — bb.js spawns module workers via new Worker(new URL('./main.worker.js', import.meta.url), {type:'module'}), which breaks single-file bundles AND import maps (workers don't inherit them); instead copy the packages' real ESM trees into assets and sed bare specifiers (comlink, pako, idb-keyval, msgpackr, @noir-lang/*) to absolute paths — those resolve in both documents and workers. (2) The bb wasm is embedded as a data: URL in dest/browser — no wasm serving needed. (3) CRS: bb.js fetches bn254 g1.dat/g2.dat AND grumpkin_g1.dat from crs.aztec-cdn.foundation / crs.aztec-labs.com — intercept both hosts; serving bn254 points for the grumpkin request fails with 'invalid vector passed to MemGrumpkinCrsFactory'. Range requests start at byte 0, so serving file prefixes with status 200 works. Steal ~/.bb-crs from any node run for the grumpkin file. (4) Set COOP/COEP/CORP headers on intercepted responses to enable SharedArrayBuffer threading. (5) UltraHonkBackend constructor in bb.js 4.2.0 takes (bytecode, api) where api = await Barretenberg.new({backend: BackendType.WasmWorker|Wasm, threads}); node defaults to a native child process that needs glibc 2.38+ — force WASM on older hosts. (6) Init is ~10x the warm prove cost: pre-warm the backend while the user reads the consent screen. (7) noir-bignum v0.10 redc param = (1 &lt;&lt; (2*modbits + 6)) / n — the +4 shift in noir_rsa's bench.nr example is stale and fails witness solving deep in brillig.

---
