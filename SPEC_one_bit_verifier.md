# SPEC — One-Bit Verifier
**Self-issued, device-bound, unlinkable attribute verification from ICAO 9303 documents**

Status: DRAFT v0.1 · Scope: protocol + client + verifier SDK · Non-scope: issuer-fallback service implementation (Mode B, §4.3), iOS client

---

## 0. One-sentence model

A wallet derives an age credential from the government signature already present on the holder's passport/ID chip, seals it in the device secure element, and answers verifier challenges with fresh, origin-bound, zero-knowledge proofs that disclose exactly one bit.

---

## 1. Invariants

These are permanent. Any change requires an ADR and is presumed wrong.

- **V0 — One bit.** A conforming verifier learns only: predicate satisfied (yes/no), a verifier-scoped nullifier, and protocol metadata. The wire format MUST NOT be able to express attribute disclosure (no "send DOB" message exists).
- **V1 — No third party at presentation time.** Verification is a local computation against public parameters. No network call to any issuer, platform, or policy server is required or permitted by the protocol.
- **V2 — Unlinkability.** No value transmitted at presentation is reused across verifiers. Cross-verifier correlation MUST be bounded by the declared anonymity tier (§7.3). Within one verifier, correlation is bounded to one epoch via the nullifier.
- **V3 — Nothing to breach.** Verifier-side security MUST NOT depend on retained data. A conforming verifier that stores nothing is fully secure; retention is never required.
- **V4 — Open attestation roots.** Device-integrity trust is a published allowlist of verified-boot / attestation root keys controlled by the verifier (or a conformance body), never a call to a platform policy service (Play Integrity, etc.). GrapheneOS AVB keys ship in the reference allowlist.
- **V5 — Predicate-only grammar.** The policy language expresses boolean predicates over committed attributes. Extending the grammar to raw attribute release is a protocol violation, not a configuration.
- **V6 — Fail closed, degrade loudly.** Any fallback that weakens V0–V5 (Mode B issuer, weaker attestation tier) MUST be visibly labeled in the UX and in the proof envelope.

---

## 2. Actors and trust model

| Actor | Online at | Trusted for | NOT trusted for |
|---|---|---|---|
| Document signer (state, via ICAO PKI) | Never (signed years ago) | Integrity of DOB/expiry in signed DGs | Anything at runtime; never contacted |
| Holder device (wallet app + SE) | Presentation | Key custody, local auth gating, proof generation | — (holder is the principal) |
| Verifier (relying party + SDK) | Presentation | Checking proofs against public params | Seeing attributes; retaining anything; choosing platform gatekeepers |
| ICAO master list distributor | App update time | Publishing CSCA/DSC set (Merkle root, versioned) | Learning who enrolls (list ships with app) |
| Mode B issuer (fallback only) | Enrollment (once) | Blind issuance for chipless users | Learning presentation events; linking issuance to use |

Adversary model: verifier is honest-but-curious to malicious (colluding verifiers assumed); network is hostile; platform vendor is a rational monopolist (assume policy-server chokepoints will be abused); holder may be adversarial (credential sharing, proof farming, minors borrowing devices); state is honest at document-signing time, adversarial at runtime (Z0-consistent).

---

## 3. Credential lifecycle

### 3.1 Enrollment (Mode A — chip-derived, default)
1. Read MRZ (camera or manual) → derive PACE/BAC access key.
2. NFC session: read DG1 (MRZ data: DOB, expiry, doc type), SOD. DG2 (photo) MUST NOT be read unless a future profile requires it; default is never.
3. Passive Authentication, locally: `SHA-256(DG1) ∈ SOD.hashList`; DSC signature over SOD verifies; DSC chains to a CSCA in the bundled master list (version `R_icao_vN`).
4. Derive credential: `C = Poseidon(dob, expiry, docHash, k, salt)` where `k` is the nullifier PRF key, freshly sampled.
5. Seal `(dob, expiry, docHash, k, salt)` under an SE-wrapped key with `setUserAuthenticationRequired(true)`, StrongBox-backed where available. Raw DG bytes: retained encrypted iff Option-A proving is in use (needed as witness, §5.1); otherwise destroyed.
6. No network I/O during enrollment. Assert with an instrumented test (T1 exit criterion).

Century rule for MRZ `YYMMDD`: `YY > (currentYY + 10) → 19YY else 20YY`, fixed at spec level; the circuit implements the same rule (divergence = soundness bug).

### 3.2 Presentation (per gate)
See §6 wire protocol. Local user auth (BiometricPrompt class 3 or device credential) gates every SE key use. Voice MAY be an additional local factor; it MUST NOT be the sole factor (spoofability) and never appears in the protocol.

### 3.3 Mode B (issuer fallback, chipless users)
One-time ceremony with an issuer that verifies a document and blind-signs (BBS+) the attribute set. Issuer retains at most an issuance counter. Mode B proofs carry `mode: "B"` in the envelope (V6). Deferred; interface reserved.

---

## 4. Cryptographic components

### 4.1 Commitment & nullifier
- Commitment: Poseidon over the proving field. `C` is never transmitted, never published. No registry exists (a registry is an observer; rejected by ADR-002).
- Nullifier: `N = Poseidon(k, H(verifier_id ‖ epoch))`. Circuit proves consistency of `k` with `C`. Epoch length is verifier policy (default 24h); shorter epochs weaken rate-limiting, longer epochs increase same-verifier trackability. Cross-verifier: `N` values are computationally uncorrelatable.

### 4.2 Circuits

**Option A — monolithic (baseline):** one circuit per presentation.
```
PresentationStatement:
  private: DG1, SOD, DSC_cert, salt, k
  public:  R_icao_vN, T (date), predicate_id, age_min,
           nonce, origin, verifier_id, epoch, N
  assert:  SHA256(DG1) ∈ SOD.hashList
        ∧ VerifySig(DSC.pk, SOD)            // RSA-2048/PSS, PKCS1, or ECDSA
        ∧ MerkleMember(DSC, R_icao_vN)
        ∧ mrz_dob(DG1) ≤ T − age_min        // century rule per §3.1
        ∧ mrz_expiry(DG1) ≥ T
        ∧ N = Poseidon(k, H(verifier_id ‖ epoch))
```
Target system: Longfellow-ZK (transparent, no trusted setup, legacy-hash-native, IETF draft). Accept: proof size 100s of KB.

**Option B — split + recursion (upgrade path):** Circuit E (once, at enrollment) proves `C` opens to attributes of a validly signed doc → π_E, stored locally, never transmitted. Circuit P (per presentation) takes `C, π_E` as PRIVATE inputs, verifies π_E in-circuit, proves predicate + nullifier + freshness. Requirement: π_E verified inside P so `C` never leaves the device (else `C` is a linkable ID). Target system: Noir/UltraHonk (recursion-friendly; fork zkPassport passive-auth circuits).

**Decision gate (Task T2):** Option A if monolithic proving ≤ 2.5 s p50 / ≤ 6 s p95 on reference low-end device; else Option B.

### 4.3 Device binding & freshness
- Per-verifier SE keypair `K_v`, generated on first contact with a verifier, attested via raw hardware key attestation.
- At presentation, `K_v` signs `H(nonce ‖ origin ‖ proof_digest)`. Verified natively by the SDK (outside the circuit) in Tier A.
- `nonce` and `origin` are public inputs to the proof; Fiat–Shamir binds them into the transcript. Replay and cross-origin relay both fail at proof verification, independent of TLS.

---

## 5. Attestation

### 5.1 Mechanism
Raw Android key attestation (X.509 chain from `K_v` to a hardware root) / Apple App Attest on iOS (future). Verifier checks: chain validity; root ∈ allowlist; verified-boot state = locked/self-signed-locked; OS patch level ≥ policy minimum; `userAuthRequired` flag set on `K_v`.

### 5.2 Allowlist format (V4)
```json
{
  "version": 3,
  "roots": [
    {"name": "google-hw-attestation", "spki_sha256": "…"},
    {"name": "grapheneos-avb", "spki_sha256": "…", "os": "GrapheneOS"},
    {"name": "apple-app-attest", "spki_sha256": "…"}
  ],
  "min_patch_level": "2026-03",
  "signed_by": "conformance-body-key-or-verifier-key"
}
```
Published artifact, versioned, verifier-controlled. Reference allowlist includes GrapheneOS at launch (this is a thesis statement, not a feature).

### 5.3 Anonymity tiers
- **Tier A (default):** fresh `K_v` per verifier; batch attestation certs → cross-verifier linkage bounded to device-batch anonymity set (~10⁴–10⁵ devices). Cheap.
- **Tier B (maximal):** attestation chain verified inside the ZK circuit; verifier learns only "roots in allowlist." Full unlinkability; significant proving cost. Profile P2.

---

## 6. Wire protocol

### 6.1 Challenge (verifier → wallet)
```json
{
  "v": 1,
  "nonce": "b64(32B)",
  "origin": "https://example.com",
  "verifier_id": "spki_sha256_of_verifier_key",
  "epoch": "2026-07-11",
  "policy": {
    "predicate": "age_gte",
    "value": 18,
    "icao_root_min_version": 7,
    "attestation": {"allowlist_url": "…", "allowlist_hash": "…", "tier": "A"},
    "mode_b_accepted": false
  },
  "sig": "verifier signature over above"
}
```
Wallet MUST refuse any challenge whose policy is not expressible in the predicate grammar (V5) and SHOULD display verifier identity + predicate to the user before auth.

### 6.2 Response (wallet → verifier)
```json
{
  "v": 1,
  "proof": "b64",
  "public_inputs": {"T": "…", "N": "…", "nonce": "…", "origin": "…", "R_icao": "v7"},
  "device_sig": "b64(sig by K_v over H(nonce‖origin‖proof_digest))",
  "attestation_chain": ["b64 X.509 …"],
  "mode": "A",
  "tier": "A"
}
```

### 6.3 Verifier algorithm (SDK)
`verify(response, challenge, params, allowlist) → {ok, nullifier}`
1. Recompute expected public inputs from own challenge; mismatch → reject.
2. Verify ZK proof against params for `R_icao ≥ policy minimum`.
3. Verify attestation chain to allowlist; check key policy flags.
4. Verify `device_sig`.
5. Optional: nullifier rate-limit within epoch (in-memory or short-TTL store; V3 — nothing here is security-critical to retain).
Stateless. No PII path exists.

---

## 7. Threat table

| Threat | Mitigation | Residual |
|---|---|---|
| Borrowed device (minor uses adult's phone) | Class-3 biometric/credential gating every key use | Coerced/consenting adult unlock — parity with physical-world checks; out of scope |
| Credential extraction/resale | Secrets SE-wrapped, non-exportable; proof requires live `K_v` signature | SE compromise (hardware attack) — accepted |
| Proof farm (one adult proves for many) | Per-verifier-epoch nullifier rate limit; hardware attestation prevents emulated fleets | Farm of real devices w/ real documents — costly; monitor |
| Proof replay / phishing relay | nonce+origin as public inputs; device_sig | — |
| Cross-verifier tracking | Fresh `K_v`, batch certs (Tier A) or in-circuit attestation (Tier B); per-verifier nullifiers | Tier A: batch-level correlation (declared) |
| Same-verifier tracking | Nullifier scoped to epoch | Within-epoch linkage (by design, for rate limiting) |
| Verifier over-ask / scope creep | V5 grammar; wallet refusal; envelope contains no attribute fields | Out-of-band demands ("also upload ID") — legal/market fight, not protocol |
| Forged/expired documents | PA chain to ICAO root; expiry predicate; master-list versioning | CSCA key compromise → root version bump + revocation entry |
| Malicious master list update | List signed + versioned; verifiers pin minimum version; discrepancy detectable (public artifact) | — |
| Platform chokepoint (Play Integrity capture) | V1 + V4: no policy-server call exists in protocol | Ecosystem pressure on verifiers to add one — governance fight |
| Century-window soundness bug | Single spec-level rule implemented identically in parser and circuit; adversarial fixture in test vectors | — |

---

## 8. Conformance profiles

- **P0 — Web gate, Tier A, Mode A.** Browser flow via QR/deep-link (Digital Credentials API when available). The MVP.
- **P1 — Native app gate, Tier A.** Direct wallet↔app channel.
- **P2 — Maximal privacy.** Tier B in-circuit attestation. For verifiers/holders with elevated threat models.
- **P3 — Mode B accepted.** Verifier opts into issuer-fallback proofs; envelope-labeled.

---

## 9. Build sequence

| # | Task | Exit criterion |
|---|---|---|
| T1 | NFC read + Passive Authentication in the clear (no ZK); jmrtd-lineage | 5 real documents verified offline; zero network I/O asserted by test |
| T2 | **Proving benchmark** — Longfellow monolithic vs Noir/UltraHonk recursive, on reference low-end device + Pixel | Numbers vs §4.2 gate; ADR-003 records Option A/B decision |
| T3 | SE key mgmt: per-verifier keys, auth-bound, raw attestation; server-side verify with allowlist incl. GrapheneOS AVB | GrapheneOS Pixel passes; certified-but-stale device configurably fails (the demo) |
| T4 | Nullifier + challenge/response schemas + wallet refusal logic | Fuzzed malformed/over-asking challenges all refused |
| T5 | Verifier SDK (`verify()` stateless) + demo gated site | End-to-end gate on GrapheneOS in < 5 s including biometric |
| T6 | Threat-table adversarial fixtures (replay, relay, expired doc, wrong-century DOB, farmed nullifier burst) | All fail closed |

---

## 10. Open questions

1. Epoch length default and whether epoch should be holder-negotiable (privacy) vs verifier-fixed (rate limiting).
2. Master-list distribution beyond app updates (transparency log?) without creating a phone-home.
3. Mode B issuer economics and governance — who runs it, what conformance body certifies it.
4. Legal recognition: mapping P0–P2 onto Ofcom "highly effective age assurance" and Texas HB 1181 language; whether a conformance nonprofit (ISRG-pattern) is a prerequisite for regulatory acceptance.
5. iOS profile: App Attest trust semantics vs V4 (Apple root is a platform root; document the asymmetry honestly).

## ADR index
- ADR-001: No registry of commitments (registries are observers). 
- ADR-002: Raw key attestation only; policy-server calls prohibited (V1/V4).
- ADR-003: Proving architecture (pending T2).
