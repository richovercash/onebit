# One Bit Verifier

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

## Modules

| Module | What it is |
|--------|------------|
| `app/` | Android wallet (holder). Flavors: **`sovereign`** (passport/NFC, GMS-free) and **`mdl`** (adds the Digital Credentials API for mDL). |
| `core/` | Shared logic: challenge parsing/verification, nullifier, mdoc/passport verify, JWE. |
| `verifier/` | Stateless verification SDK + a demo gated site (`DemoServer`). |
| `circuits/` | Noir ZK circuits (Apache-2.0 — see licensing). |

## Build & run

Requirements: JDK 17+ (Android Studio JBR), Android **minSdk 26**, an **NFC** device.

```bash
# build the privacy (sovereign) wallet
JAVA_HOME=<android-studio>/jbr gradle :app:assembleSovereignDebug
adb install -r app/build/outputs/apk/sovereign/debug/app-sovereign-debug.apk
```

**Proving needs the SRS.** Push `g1_big.dat` to the app's external files dir before
enrolling/presenting, or you'll see "Missing SRS". See
[`docs/measurement-recursion-on-device.md`](docs/measurement-recursion-on-device.md).

**Present demo (site → wallet → site):**

```bash
gradle :verifier:demoServer                 # gate on :8317  (add -Donebit.personbound=true for a strict site)
adb reverse tcp:8317 tcp:8317               # phone localhost -> host
# open http://localhost:8317 on the phone, tap "Verify with OneBit"
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
