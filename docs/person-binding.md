# Person-binding & the borrowed-document problem

*Threat model + design for binding a credential to a person, not just a document —
and why most of the time we don't need biometrics to do it. (2026-07)*

## The threat

OneBit today binds a credential to a **document** and to a **phone**:

- The ZK proof asserts *"the holder of this passport/mDL is over 18."*
- Presentation is **fingerprint-gated**, so *"whoever unlocks this phone"* must approve.

Neither binds to a **person**. The gap is the classic remote age-verification attack,
in a family setting:

> A 15-year-old enrolls a **parent's passport** on the **kid's own phone**, gates it
> with the **kid's own fingerprint**. The credential now says "over 18," the kid's
> fingerprint unlocks it, and every future check passes.

Fingerprint-at-**presentation** cannot catch this — it's binding to the wrong person.
The only thing that closes it is a **person ↔ document** check at **enrollment**: does
the live human enrolling match the portrait *inside* the document? That's the "clerk
glancing at your face vs. your ID photo" step, which disappears when age-gating moves
online.

## Two binding layers

| Layer | Binds to | Status | Defeats |
|---|---|---|---|
| SE-seal + fingerprint-at-present | this **phone** / its unlocker | shipped | cloning the credential; grabbing an unlocked phone |
| **Face-match at enrollment** (live face ↔ document portrait + liveness) | the **person** | design (below) | enrolling **someone else's** document |

## The key realization: the mDL already inherits person-binding

When a California mDL is provisioned into the CA DMV Wallet, **the DMV does the identity
proofing** — you scan your physical license and pass a **liveness selfie matched to the
license photo**. So an mDL is bound to *you at issuance*. When OneBit ingests
`age_over_18` from it, we inherit "the DMV verified this is really you, and you're 18+."
**A kid cannot provision a parent's mDL into the kid's wallet** — the borrowed-document
attack is defeated *upstream*, by the issuer.

Consequence: **face-match in OneBit is only relevant for the passport (bearer-chip) path**
— a passport chip is readable by anyone physically holding it — **and only in a regulated
tier.** For mDL, no OneBit biometric is needed.

## Platform biometrics don't help (and that's fine)

- **Neither iOS Face ID nor Android BiometricPrompt exposes a 1:1 face-match to third-party
  apps.** They answer only *"is the device's enrolled owner present?"* (pass/fail); they
  will not compare a live face to an arbitrary photo (the passport portrait), and the
  enrolled face template lives in the Secure Enclave / TEE and is never handed out.
- So we can neither run our check "against the platform tool" nor compare our credential's
  photo to the user's Face ID. The template is locked down by design.
- ⇒ If face-match is needed (passport, regulated tier), OneBit must run its own on-device
  face-recognition + liveness. It does **not** phone home.

## Design (if/when face-match is adopted)

Optional, tiered, on-device, verifier-signaled:

1. **Sovereign flavor: OFF (bearer model).** Philosophically correct — like handing over
   your physical passport in person: you hold your own document, you're an adult
   self-verifying, and *no biometric is captured*. Forcing a face scan would betray the
   sovereign promise.
2. **Consumer / regulated flavor: ON.** A **liveness-checked**, **on-device** 1:1 match of
   a selfie against the document portrait (passport **DG2**, or mDL portrait).
3. **Verifier-signaled assurance, not a global mandate** — see plumbing below.

### Privacy invariants (non-negotiable)

- **Zero upload.** Both images stay on the phone; the match runs locally; only a
  **pass/fail bit + an attested `person_bound` flag** result.
- **No face template stored** (or stored only in the SE and discarded after enrollment).
  **No biometric database, ever.** This is categorically different from cloud face-AV
  vendors — and is what CNIL prefers.
- The portrait is **PII used transiently on-device and discarded** ("used on device, never
  leaves"). For mDL this means requesting the portrait *in addition to* `age_over_18` —
  acceptable only local-only + discarded.
- **Liveness is mandatory** if we do this (else a photo of the parent spoofs it). Even done
  well it's physical-ID-parity, not perfect (twins, masks) — parity with the in-person
  check is the regulatory bar.

### On-device, open-source building blocks

- Detect/align: **MediaPipe** / **ML Kit** face detection.
- Embeddings + 1:1 match: **MobileFaceNet** (TFLite, permissive); ArcFace/InsightFace are
  stronger but often research-only licenses — check before commercial use.
- Passive liveness: **Silent-Face-Anti-Spoofing** (Apache-2.0), or active challenge
  (blink / head-turn) via MediaPipe landmarks.

## What's shipped now: the assurance-level plumbing

The **`person_bound`** flag is wired end-to-end so the market can require person-binding
per use-case, ahead of any biometric work:

- **Challenge grammar** (`Challenge.java`): `policy.person_bound` is an **optional** boolean
  (absent ⇒ bearer OK). It's part of the **signed** tuple *only when true*, so every
  existing bearer challenge/signature stays byte-identical and tampering still fails closed.
- **Verifier** (`VerifySdk`): if `policy.person_bound` is true and the presented credential
  is bearer, it **DENIES** with `"policy requires a person-bound credential; this one is
  bearer-only"`.
- **Wallet** (`Present.java`): the response reports `person_bound` = whether a face-match
  enrollment marker (`personbound.txt`) exists — **false for all of today's credentials**.
- **DemoServer** mints `person_bound: false` (accepts bearer); a strict site sets `true`.

So today: bearer credentials still GRANT everywhere. The day face-match enrollment ships
(passport, regulated tier), those credentials set the marker → `person_bound: true`, and
strict verifiers start accepting them while continuing to reject bearer ones.

## Status

- ✅ **Assurance-level plumbing** (`person_bound`) — shipped, tests green.
- ⬜ **On-device face-match + liveness enrollment** — a self-contained future project
  (passport, sovereign-off, consumer-on). mDL does not need it (issuer-bound).
