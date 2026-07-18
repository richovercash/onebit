# T2 Proving Benchmark — Results (2026-07-11)

## Setup
- Desktop: i9-13900KF, 32 threads, 125 GB RAM (docker ubuntu:24.04 for glibc)
- Prover: barretenberg 4.2.0-aztecnr-rc.2 (UltraHonk), Noir 1.0.0-beta.20
- Bench circuits: `bench/noir/monolithic` (Option A analog per SPEC §4.2:
  SHA-256(DG1 93B) ∈ eContent, SHA-256(eContent 1200B), RSA-2048 PKCS#1v1.5
  verify, SHA-256(DSC 1000B) + depth-20 Poseidon2 Merkle, century-rule date
  predicates, Poseidon2 nullifier) and `bench/noir/presentation` (Option B
  Circuit-P analog: Poseidon2 commitment open + nullifier + predicates,
  recursion cost excluded). Real inputs (real RSA-2048 signature).

## Measurements (desktop)

| circuit | UH circuit size | prove p50 (5 runs) | witness gen |
|---|---|---|---|
| monolithic (Option A analog) | 177,350 | **1.13 s** | 0.47 s |
| presentation (Option B core) | 3,026 | **0.15 s** | 0.15 s |
| zkpassport `sig_check_dsc_tbs_700_rsa_pkcs_4096_sha256` | 247,569 | (gates only) | — |
| zkpassport `sig_check_id_data_tbs_700_rsa_pkcs_2048_sha256` | 108,361 | (gates only) | — |
| zkpassport `compare_age` | 80,084 | (gates only) | — |
| zkpassport `outer_count_4` (4-proof recursive aggregator) | 3,293,279 | (gates only) | — |

## Device extrapolation
Geekbench-6-multicore ratios vs i9-13900KF (~21k): Tensor G1 (Pixel 6) ≈ 3k
→ ~7×; true low-end (~$150 phone) ≈ 2× worse again. ZK proving is memory-
bandwidth-hungry; published mobile/desktop ratios run 5–10×.

- **Option A monolithic on Pixel 6: ≈ 7–9 s p50. On reference low-end:
  ≈ 15 s+. Gate is ≤ 2.5 s p50 / ≤ 6 s p95 → FAILS by 3–6×.**
- The analog *undercounts* real Option A (no X.509/TBS parsing, PKCS#1v1.5
  instead of PSS, single signature, no CSCA-level check).

## Capability finding (independent kill)
google/longfellow-zk `lib/circuits/` contains ecdsa, sha, mdoc, cbor —
**no RSA circuit exists**. RSA-2048/4096 DSCs sign the large majority of
ICAO SODs. Option A's target system cannot express the majority document
population regardless of speed. (Longfellow's published ~1–2 s Pixel numbers
apply to mdoc/ECDSA only.)

## Option B production evidence
zkPassport (Noir/UltraHonk, Apache 2.0, same architecture as SPEC Option B)
ships on-device: foundational proofs 10–50 s once at enrollment (cached),
selective-disclosure proofs < 1–10 s per presentation including their 3.3M-gate
4-proof aggregation. Our Circuit P needs ONE in-circuit proof verification,
strictly lighter than their outer_count_4.

## Conclusion → ADR-003
Option A fails the §4.2 gate on speed and fails on RSA coverage.
**Option B (split + recursion, Noir/UltraHonk, fork zkPassport circuits) is
the proving architecture.**

Open validation (tracked in T2): native on-device p50/p95 for Circuit P with
recursion on Pixel 6 / Pixel 9 (via noir_rs/Swoir-style native barretenberg),
once Circuit P exists (T4/T5). Static bb binaries are not published; the
release "static" tarballs contain only libbb-external.a.

## Repro
```
cd bench/noir && python3 gen_inputs.py
(cd monolithic && nargo execute witness)   # nargo 1.0.0-beta.20
docker run --rm -v ~/.bb:/bb -v $PWD:/w -v $PWD/crs:/root/.bb-crs ubuntu:24.04 \
  bash -c '/bb/bb write_vk --scheme ultra_honk -b /w/monolithic/target/bench_monolithic.json -o /w/monolithic/target && \
           /bb/bb prove --scheme ultra_honk -b /w/monolithic/target/bench_monolithic.json -w /w/monolithic/target/witness.gz -k /w/monolithic/target/vk -o /tmp/out'
```
