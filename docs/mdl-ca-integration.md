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

## Status vs the earlier demo

The synthetic-mdoc demo proved the *parser + circuit* on made-up data with a fake
root. This doc replaces that with the real credential, real wallet, real
presentation protocol, and real trust anchor. No live CA-mDL → one-bit run has
happened yet — that needs the OID4VP reader above.
