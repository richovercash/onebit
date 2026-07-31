# CA mDL integration — the real picture (2026-07-24)

*What we established with an actual California mDL on a real device. This replaces
the earlier synthetic-mdoc guesswork with ground truth.*

## What exists, confirmed

- **The credential is real and on-device.** A California mDL, provisioned into the
  **CA DMV Wallet** app (`gov.ca.dmv.wallet`, built by **SpruceID** —
  `com.spruceid.app.credible.mdl`), on a stock Pixel 6 Pro (Android 15). Google
  Wallet is **not** involved — the mDL lives in CA's own app.
- **Presentation is OpenID4VP, app-to-app.** The wallet registers the URL schemes
  `openid4vp`, `mdoc-openid4vp`, `openid-vc`, `openid-credential-offer`, `cadmv`,
  `interaction`. So a verifier requests a presentation by launching an
  `mdoc-openid4vp://…` (or `openid4vp://…`) intent; the wallet returns the
  response to the verifier's `redirect_uri`. This is an **intent flow, not
  necessarily GMS-bound** — worth testing whether it works without Play (it would
  reopen the GrapheneOS path for mDL).
- **CA publishes real trust material.** The DMV "ISO 18013-5 IACA Root
  Certificate" page serves a `did:jwk` whose `x5c` embeds an X.509 cert:
  `CN=California DMV IACA VC Signer` → issued by `CN=California DMV IACA Root`
  (P-256, valid 2026-04-10 … 2027-07-09). Saved in `trust/ca-dmv/` (prod + test /
  UAT). This is the genuine anchor — the fake self-signed root from the synthetic
  demo is gone.

## Two credential forms (don't conflate them)

CA/OpenCred exposes the license in two formats:
1. **`mso_mdoc`** (ISO 18013-5) — COSE_Sign1, X.509 `x5chain` DS→IACA. This is what
   `Mdl.java` already parses. Trust = the IACA Root above.
2. **`jwt_vc_json`** (W3C VC-JWT) — signed by the `did:jwk` key (the "VC Signer"
   cert we extracted is this one's leaf). Presented via OID4VP/VC-API/OIDC.

The saved cert is the **VC Signer** leaf. For the `mso_mdoc` path we ultimately
verify the DS cert carried in the mdoc's own `x5chain` and pin it to the
**IACA Root**; the Root's cert/fingerprint is the anchor to obtain (it names
itself `California DMV IACA Root`, and appears as the issuer of what CA
publishes).

## The integration to build (OID4VP mdoc reader)

To turn a real CA mDL into a one-bit credential, the ingestion is an **OID4VP
verifier** (replacing NFC for this product):

1. Build an OID4VP request: `response_type=vp_token`, `response_mode` for the
   DC-API/same-device flow, a fresh `nonce`, an ephemeral reader key for response
   encryption, and a `dcql_query` for `format: mso_mdoc`,
   `doctype_value: org.iso.18013.5.1.mDL`, claims `["org.iso.18013.5.1","age_over_18"]`
   (and `birth_date`/`expiry_date`).
2. Launch it via the `mdoc-openid4vp://` intent; the CA Wallet prompts the user.
3. Receive the response at our `redirect_uri`: an OID4VP `vp_token` carrying an
   **encrypted** mdoc `DeviceResponse` (CBOR). Decrypt (HPKE/JWE per 18013-7),
   pull `documents[0].issuerSigned` = `{nameSpaces, issuerAuth}`.
4. Feed `issuerSigned` to **`Mdl.verify`** against the CA IACA Root, extract
   `birth_date`/`expiry` → `commit_fields` → seal → `present_amortized` unchanged.

## Honest open items (the real work, not more circuit code)

- **Response encryption / session transcript.** The 18013-7 / DC-API flow encrypts
  the `DeviceResponse` to the reader's ephemeral key and binds it to a session
  transcript (origin + nonce). This is the bulk of the reader work.
- **mdoc DS→IACA Root trust.** Verify the DS cert from the mdoc's `x5chain` against
  the CA IACA Root (obtain the Root cert/fingerprint; the VC-Signer leaf we have
  names it as issuer).
- **GMS or not.** The scheme-based intent flow may work without Play — if so, mDL
  could work on GrapheneOS after all. Test empirically before assuming a stock-only
  build flavor.
- **SpruceID reference.** The wallet is SpruceID's; their open-source mobile/OID4VP
  libraries document the exact request/response shapes — the fastest way to get
  the wire format right instead of guessing.

## Live DC-API probe result (2026-07-24) — the real barrier

Built the DC-API verifier (`mdl` build flavor, `MdlEnrollActivity`) and fired a
real request at the CA Wallet on the Pixel 6, asking for **only** `age_over_18` /
`age_over_21`. What happened, from the wallet's own logs:

- **The pipeline works.** The Android DC API routed our request to the CA Wallet
  (`gov.ca.dmv.wallet/…dcapi.Activity`), which parsed it correctly:
  `metadata: {"claims":[["org.iso.18013.5.1","age_over_18"],["…","age_over_21"]],
  "dcql_cred_id":"mdl"}`. Our request format + minimal (no-PII) claim set are
  accepted by the wallet's parser.
- **It rejected on identity, not format:**
  `dcapi.Activity: an error occurred… java.lang.Exception: unknown origin` (SpruceID
  `Activity.kt:207`), returned to us as `GetCredentialUnknownException`, before any
  user interaction.

**Interpretation (confirmed on retry).** A second attempt that added
`client_id: web-origin:…` and `expected_origins` to the request **changed
nothing** — same `unknown origin`, and the wallet still logged only our claims,
ignoring those fields. So the block is **not** our request body: it is the
**Android DC-API caller origin**. The platform only hands a verified origin to
the wallet when the caller is a **browser** (or an app holding the privileged,
OEM-allowlisted `android.permission.CREDENTIAL_MANAGER_SET_ORIGIN`). A sideloaded
app supplies no origin, so SpruceID sees none and throws `unknown origin`
(`Activity.kt` onCreate). Sign-in state was ruled out — it failed identically
with the wallet signed in.

This is a **deliberate anti-phishing control in the DC-API design**, not a bug
and not tweakable from our side: digital credentials are released only to callers
whose origin the platform can attest (web origins / privileged apps).

**What it means for the architecture.** CA's mDL is designed to be presented to
an **origin-attested verifier** (the age-gated website via the browser DC API, or
a registered OpenCred relying party) — *not* freely ingested by an arbitrary
sovereign wallet. Our "wallet ingests the mDL once, derives one bit" model runs
into this gate. Getting past it legitimately means one of:
1. **Register as an authorized verifier** with a recognized origin (business
   process with CA / the mDL ecosystem) — then the app-to-app ingest may work.
2. **Be the website.** Run an OpenCred-style verifier at a real https origin that
   receives the mDL; but then a *server* ingests it, not the user's wallet — a
   different trust/privacy posture than the passport path.
3. Confirm whether the `unknown origin` is a fixable request/`client_id` origin
   detail vs. a hard allowlist (needs reading SpruceID's `processIntent` origin
   logic / their reader docs).

This is the honest state: **technically integrated up to the wallet's
verifier-authorization gate, blocked there.** It mirrors the provisioning
asymmetry — the passport is a bearer document you physically hold and read; the
mDL is a wallet-mediated credential that only talks to recognized verifiers.

## Live custom-scheme run (2026-07-25) — full pipeline works; trust anchor is the last gate

Switched from the DC API to the ISO 18013-7 **custom-scheme OID4VP** flow
(`MdlSchemeActivity`) with a **signed request (JAR)** and response encryption. This
got us *past* the "unknown origin" gate and all the way through a real presentation
of the user's actual California mDL. What now works, confirmed on the Pixel 6 Pro
against the real CA DMV Wallet, requesting **only `age_over_18`**:

1. **Signed request accepted.** `mdoc-openid4vp://` + RFC 9101 JAR (ES256, x5c reader
   cert, `client_id=x509_san_dns:onebit.zk`). Cleared every validation gate. Fixes
   found empirically from the wallet's own errors:
   - `response_mode` must be **`direct_post.jwt`** (the wallet rejects `fragment`).
   - response encryption must be **`A256GCM`** (the wallet rejects `A128GCM`).
2. **User consent shown + approved** — the wallet's real "share age over 18" dialog.
3. **Encrypted mdoc returned.** Wallet POSTs an ECDH-ES / A256GCM **JWE** to our
   localhost `response_uri` (`http://127.0.0.1:<port>/cb`, a tiny `ServerSocket`).
   Cleartext-to-loopback is allowed; the wallet connected and posted.
4. **We decrypt it.** `onebit.core.Jwe` (ECDH-ES + Concat-KDF + AES-GCM, unit-tested
   against RFC 7518 App C) recovers the `DeviceResponse` CBOR.
5. **The DMV's issuer signature over `age_over_18` VERIFIES.** `Mdl.verifyIssuerSigned`
   passes the IssuerAuth (COSE_Sign1) check against the DS public key — i.e. we
   cryptographically confirmed **"California DMV IACA mdoc Signer" signed this age
   attestation**. The disclosed set is exactly `age_over_18`, no PII.

**The trust anchor — and how we closed it.** The real DS is `CN=California DMV IACA
mdoc Signer` issued by `CN=California DMV IACA Root, O=CA-DMV`. The mdoc x5chain ships
**only the DS** (not the root). CA does **not** publish the IACA Root cert on the open
web — `dmv.ca.gov`'s "IACA Root Certificate" pages (prod + test) serve a `did:jwk` that
only re-gives the VC-Signer *leaf*; `crl.dmv.ca.gov/iaca/root` serves a CRL; the
`did:web` doc has no x5c chain; the developer page has no verifier enrollment. ISO
18013-5 distributes IACA roots via the **AAMVA VICAL** to enrolled verifiers.

We bootstrapped the root **public key** by cross-validation (`Mdl.crossValidatedRootKey`):
ECDSA public-key recovery on the live DS yields <=2 candidate signer keys; we accept
only the one that **also** verifies the *independently* dmv.ca.gov-published VC-Signer
(same issuer). A wrong candidate verifying a second, independent CA signature is
cryptographically negligible, so the survivor is genuinely CA's root key — established
from two independent CA artifacts, not the credential vouching for itself. Unit-tested
in `MdlKeyRecoveryTest` (recovery, cross-validation, and a negative case).

**GRANT achieved (2026-07-25).** Live on the Pixel 6 Pro against the real CA DMV Wallet:
`mdoc DS: California DMV IACA mdoc Signer` -> `IACA root bootstrapped via
cross-validation` -> `CA mDL VERIFIED via direct_post.jwt - age_over_18=true`. Full
chain on the genuine credential; only `age_over_18` disclosed; nothing persisted.

**Two honest caveats.**
1. **Trust anchor is a demo bootstrap, not a VICAL assertion.** It cryptographically
   proves the DS was signed by the same key that signed CA's published VC-Signer;
   production should pin the AAMVA VICAL root instead (drop-in: pass a real root cert
   to `anchorOf(...)` instead of `crossValidatedRootKey(...)`).
2. **Background socket + cached-app freezer — RESOLVED.** The `direct_post.jwt`
   localhost `response_uri` server is frozen by Android's cached-app freezer while the
   wallet is foreground. Fixed with `KeepAliveService`, a bare `dataSync` foreground
   service started before the wallet launch: a running FGS makes the whole process
   perceptible, so the activity's socket thread is freezer-exempt (the FGS holds no
   logic — the exemption is from its state). Re-verified with the freezer **enabled**
   (`cached_apps_freezer enabled`): GRANT still succeeds. No adb workaround needed.

## Wired into the one-bit credential (2026-07-25)

The verified mDL is now a first-class credential source, byte-identical to the
passport on the wire. Because the mDL flow requests ONLY `age_over_18` (no dob, per
the privacy rule), the credential commits the **boolean + threshold**, not a dob:

- **Enroll** (`MdlSchemeActivity.enrollBool`): after the GRANT, `C =
  Poseidon2([over=1, threshold=18, doc_hash, k, salt])` via the existing
  `commit_fields` circuit (the two u32 slots hold `over`/`threshold`), sealed to
  `acred.bin` + `credtype.txt="bool"`.
- **Present** (`circuits/present_bool`): reopens C, asserts `over==1` and
  `threshold==age_min` (so an 18+ credential can't answer a 21 check), emits the
  verifier/epoch-scoped nullifier. Same ABI as `present_amortized`, so `Present.java`
  only switches the circuit asset by `credtype`.
- **Verified live:** `PROVE OK zk/present_bool.json in 451 ms` from a signed
  `age_gte 18` challenge against the mDL-enrolled credential. Sub-second, offline, one
  bit + nullifier — no wallet contact after enrollment.
- **Verifier accepts it (loop closed):** `VerifySdk` treats `present_bool` as Tier-A
  amortized (4 public inputs `[ctx, current, age_min, N]`, same checks as
  `present_amortized`); the JS sidecar (`verify.mjs` + `verifier/js/present_bool.json`)
  returns `ZK_OK`. The response envelope reports `circuit=present_bool` (Present.java
  derives it from the amortized circuit name — a hardcoded `present_amortized` here was
  the first-attempt DENY).
- **Full DemoServer round-trip GRANTED (2026-07-25):** gate page -> deep link ->
  on-device `present_bool` proof + hardware attestation + fingerprint + device_sig ->
  `VerifySdk.verify` -> `GRANT e2e=5944ms`, `chain=[predicate over enrolled commitment
  (Tier A)]`. The ACCESS GRANTED page renders on the phone. One bit + nullifier, no PII.
  (Both apps claim `onebit://`; drive the challenge at `onebit.wallet.mdl` explicitly to
  avoid the chooser.)

## Status vs the earlier demo

The synthetic-mdoc demo proved the *parser + circuit* on made-up data with a fake
root. This doc replaces that with the real credential, real wallet, real
presentation protocol, and real trust anchor. No live CA-mDL → one-bit run has
happened yet — that needs the OID4VP reader above.
