# Glossary — One-Bit Verifier

Plain-language definitions of every term used in the code and docs. Grouped by
area. If a term appears in a doc without explanation, it's here.

## Documents & chips

- **ICAO 9303** — the international standard for machine-readable travel
  documents (passports, some national IDs). Defines the chip layout, the data
  groups, and the signature scheme. "ICAO-compliant" = the chip follows this.
- **MRZ (Machine-Readable Zone)** — the two lines of `<`-padded text at the
  bottom of a passport photo page. Encodes document number, nationality, date
  of birth, sex, expiry. We read three fields from it to unlock the chip.
- **NFC** — near-field communication, the short-range radio the phone uses to
  talk to the passport chip. Same tech as tap-to-pay.
- **DG1 (Data Group 1)** — the chip file holding the MRZ data (DOB, expiry,
  document type). This is the *only* data group we read.
- **DG2** — the chip file holding the face photo. We deliberately never read it.
- **SOD (Document Security Object)** — a signed file on the chip. Contains a
  list of hashes (one per data group) and a signature over that list. This is
  what makes the chip tamper-evident.
- **eContent** — the actual signed bytes inside the SOD (the hash list wrapped
  in a structure). "The signature is over the eContent."
- **BAC / PACE** — the two protocols for establishing an encrypted session with
  the chip using the MRZ-derived key. BAC is the older challenge-response; PACE
  is the modern Diffie-Hellman version. Post-2014 documents often disable BAC.

## Certificates & signatures

- **CSCA (Country Signing Certificate Authority)** — a country's root signing
  key for its travel documents. The top of the trust chain.
- **DSC (Document Signer Certificate)** — a working certificate, signed by the
  CSCA, that actually signs individual passports' SODs. Countries rotate these
  often; one CSCA signs many DSCs.
- **Master list** — the published bundle of all countries' CSCA certificates.
  We ship the German BSI master list (588 certs, 116 countries) as our trust
  root. It's public data anyone can redistribute.
- **Passive Authentication (PA)** — the offline check that a passport is
  genuine: hash(DG1) is in the SOD's hash list, the SOD signature verifies
  under the DSC, and the DSC chains to a CSCA in the master list. No network,
  no challenge to the chip — hence "passive."
- **RSA / ECDSA** — the two signature algorithms passports use. RSA (usually
  2048 or 4096-bit) is the majority; ECDSA (elliptic-curve) is cheaper to
  verify. **PKCS#1 v1.5** and **PSS** are two RSA padding schemes; both appear
  in the wild.
- **SPKI (Subject Public Key Info)** — the standard encoding of a public key.
  We pin attestation roots by the SHA-256 hash of their SPKI ("spki_sha256").

## Zero-knowledge proofs

- **Zero-knowledge proof (ZKP)** — a proof that a statement is true which
  reveals nothing beyond the statement's truth. Here: "the holder is ≥18" with
  no birth date leaked.
- **Circuit** — the program whose execution the ZKP proves. Written in Noir.
  "Proving the circuit" = proving you ran it correctly on some hidden inputs.
- **Witness** — the full set of input values (public + private) that satisfy a
  circuit. Generating the witness = running the circuit; proving = turning that
  run into a ZKP.
- **Public inputs** — circuit inputs/outputs the verifier sees. **Private
  inputs (witness)** — the hidden values (DOB, keys) the prover never reveals.
- **Noir** — the programming language we write circuits in (like Rust for ZK).
  `nargo` is its compiler/runner.
- **UltraHonk** — the specific proving system (the math that turns a witness
  into a proof and checks it). Comes from Aztec's **Barretenberg** library;
  `bb` is its command-line tool, `bb.js` the browser/JS version.
- **Gate / circuit_size** — the unit of circuit complexity (one arithmetic
  constraint). Proving time scales with gate count. Our enrollment circuit is
  ~177k gates; the recursive presentation circuit ~776k.
- **CRS (Common Reference String) / SRS** — a big fixed file of cryptographic
  points the proving system needs. Same for everyone; we bundle it so proving
  works offline. bn254 and grumpkin are the two curves it covers.
- **Poseidon2** — a hash function designed to be cheap *inside* a circuit
  (normal hashes like SHA-256 are expensive in ZK). We use it for commitments
  and nullifiers.
- **Fiat–Shamir** — the trick that makes an interactive proof non-interactive
  by hashing the transcript. It's what binds `nonce` and `origin` into the
  proof so it can't be replayed or relayed.

## This protocol's own terms

- **Commitment (C)** — `Poseidon2(dob, expiry, docHash, k, salt)`. A sealed
  fingerprint of the credential. Hiding (reveals nothing) and binding (can't be
  changed). Never transmitted, never published (ADR-001).
- **Nullifier (N)** — `Poseidon2(k, ctx)` where `ctx = H(verifier_id ‖ epoch)`.
  A per-verifier, per-epoch pseudonym. Lets one verifier rate-limit a user
  within an epoch without learning who they are; uncorrelatable across
  verifiers.
- **k** — the nullifier PRF key, a random secret sampled at enrollment and
  sealed in the secure element. The seed that makes nullifiers unlinkable.
- **salt** — random blinding in the commitment so C can't be brute-forced.
- **Circuit E (enrollment)** — proves the document is validly signed and that C
  commits its attributes. Run once, its proof (π_E) cached on device.
- **π_E ("pi-E")** — the proof output by Circuit E. A private input to Circuit
  P; never sent anywhere.
- **Circuit P (presentation)** — run per age check. Verifies π_E *inside
  itself* (recursion), re-derives C to bind the attributes, checks the
  predicate and expiry, emits the nullifier.
- **Recursion (in-circuit proof verification)** — a circuit that contains a
  verifier for another proof. `verify_proof_with_type` is the Noir builtin that
  does it. This is how C stays on-device: instead of sending C+π_E to be
  checked, Circuit P checks π_E itself and only its final proof leaves.
- **Predicate** — a yes/no statement over attributes, e.g. `age_gte 18`. The
  wire grammar allows *only* predicates, never attribute release (invariant V5).
- **Verification key (vkey) / key_hash** — the vkey is the public "checker" for
  a circuit's proofs (115 field elements for us). Its `key_hash` (Poseidon2 of
  the vkey) pins *which* circuit a recursive proof came from, so a prover can't
  swap in a circuit that always says yes.

## Devices & attestation

- **Secure Element (SE) / StrongBox / Titan M2** — the tamper-resistant chip
  that holds keys the main OS can't extract. StrongBox is Android's name;
  Titan M2 is the Pixel's SE.
- **Key attestation** — a certificate chain, signed by the hardware, proving a
  key really lives in the SE and describing the device (boot state, patch
  level, whether user-auth is required). We verify this instead of calling a
  platform server (invariant V4).
- **Verified boot / AVB (Android Verified Boot)** — the check that the OS
  hasn't been tampered with. `Verified` = stock locked; `SelfSigned` =
  GrapheneOS with its own key. The attestation reports which, and the allowlist
  decides what's acceptable.
- **Allowlist** — our published, verifier-controlled list of acceptable
  attestation roots and verified-boot keys (including GrapheneOS). Replaces the
  platform gatekeeper.
- **K_v** — the per-verifier device key, freshly generated on first contact
  with each verifier, auth-bound, attested. Signs each presentation to prove
  liveness and prevent replay.

## Invariants (the permanent rules)

- **V0** — verifier learns only one bit + nullifier + metadata.
- **V1** — no third party contacted at presentation time.
- **V2** — nothing transmitted is reused across verifiers (unlinkable).
- **V3** — verifier stores nothing security-critical ("nothing to breach").
- **V4** — device trust is an open allowlist, never a platform policy server.
- **V5** — the wire grammar expresses only predicates, never attribute release.
- **V6** — any weakening fallback is loudly labeled.
