# One Bit Verifier

> ## ⚠️ UNAUDITED — RESEARCH PREVIEW
> The circuits and protocol have **not** had an external security audit
> (self-review only; an audit is being arranged — see the
> [roadmap](ROADMAP_one_bit_verifier.md), P1.2). Until it completes and its
> findings are remediated, **do not rely on this software for age
> verification or any other purpose**. No claim of fitness for any use is
> made. Soundness bugs in ZK circuits fail *open* and *silently* — treat
> every proof this system accepts accordingly.

Prove you're old enough — reveal nothing else.

One Bit Verifier derives a **single bit** ("are you over 18?") from a government ID
(ICAO 9303 passport or ISO 18013-5 mobile driver's licence), seals it in the device's
secure element, and answers a verifier's challenge with a **zero-knowledge proof** that
discloses exactly that one bit plus a per-epoch **nullifier** — no name, no birth date,
no document number, no account, no uploads.

- **On-device, offline.** The `sovereign` build ships with **no `INTERNET` permission**.
- **No server to leak.** The verifier is a stateless SDK; the demo keeps nothing.
- **A shield against tracking.** Auto-rotating tokens (hourly epoch) and ephemeral,
  hardware-attested per-presentation keys mean nothing persistent leaves the device.

See [`SPEC_one_bit_verifier.md`](SPEC_one_bit_verifier.md) for the protocol and
[`ROADMAP_one_bit_verifier.md`](ROADMAP_one_bit_verifier.md) for status. Deeper notes
live in [`docs/`](docs/).

## For sites integrating the verifier

OneBit answers exactly one question: *is this person over the threshold?* It
deliberately does **not** tell you whether two accounts belong to the same
person. Nullifiers are random per credential and rotate every epoch, so one adult
can hold several accounts with you. That is the price of unlinkability, and it is
not negotiable (ADR-006): a per-document identifier would let anyone who ever
scanned the passport find the holder's accounts. Multi-account and resale
control is your job, using your own signals (rate limits, payment, phone,
behaviour).

## Modules

| Module | What it is |
|--------|------------|
| `app/` | Android wallet (holder). Flavors: **`sovereign`** (passport/NFC, GMS-free) and **`mdl`** (adds the Digital Credentials API for mDL). |
| `core/` | Shared logic: challenge parsing/verification, nullifier, mdoc/passport verify, JWE. |
| `verifier/` | Stateless verification SDK + a demo gated site (`DemoServer`). |
| `circuits/` | Noir ZK circuits (Apache-2.0 — see licensing). |

## Build & run

Requirements: JDK 17+ (Android Studio JBR), Android **minSdk 26**, an **NFC** device.
The repo pins gradle via the wrapper (`./gradlew`).

```bash
# build the privacy (sovereign) wallet
JAVA_HOME=<android-studio>/jbr ./gradlew :app:assembleSovereignDebug
adb install -r app/build/outputs/apk/sovereign/debug/app-sovereign-debug.apk
```

**Tests + circuit smoke (what CI runs):**

```bash
scripts/test.sh   # JUnit suites (516-challenge refusal fuzz, attestation,
                  # wire fixtures) + compile/witness-solve of all live circuits
                  # + real-proof verification through the bb.js sidecar
```

Toolchain pins: nargo `1.0.0-beta.20` (`NARGO=` to override), barretenberg
4.2.0 via `@aztec/bb.js` (locked in `verifier/js/package-lock.json`),
Node 18+.

**Proving needs the SRS.** Push `g1_big.dat` to the app's external files dir before
enrolling/presenting, or you'll see "Missing SRS". See
[`docs/measurement-recursion-on-device.md`](docs/measurement-recursion-on-device.md).

**Present demo (site → wallet → site):**

```bash
./gradlew :verifier:demoServer              # gate on :8317  (add -Donebit.personbound=true for a strict site)
adb reverse tcp:8317 tcp:8317               # phone localhost -> host
# open http://localhost:8317 on the phone, tap "Verify with OneBit"
# (or scan the gate page's QR with the phone camera — same signed challenge)
```

## Sharing

- **Testers:** sideload the APK (remember the SRS step). Debug-signed.
- **Public:** make a **release** build signed with your own keystore (kept out of the
  repo). Distribute via **F-Droid with reproducible builds** — letting anyone verify the
  APK matches this source is the strongest form of the "no tracking" claim — or GitHub
  Releases.

## Licensing

A deliberate split (see [`LICENSE`](LICENSE), [`LICENSE-APACHE`](LICENSE-APACHE),
[`NOTICE`](NOTICE)):

- **App + verifier + core → AGPL-3.0-only.** Copyleft, and its network clause covers the
  verifier when run as a service — anyone who deploys a modified version must publish
  their source, so tracking can't be slipped in behind a fork.
- **Protocol spec + `circuits/` → Apache-2.0.** These are meant to be adopted freely into
  other stacks; Apache's patent grant makes that safe.

Third-party components keep their own licenses (jMRTD/SCUBA are LGPL; Bouncy Castle is
MIT-style; Noir/Barretenberg are Apache/MIT) — see [`NOTICE`](NOTICE).

Security reports: see [`SECURITY.md`](SECURITY.md).
