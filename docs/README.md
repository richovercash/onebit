# One-Bit Verifier — learning docs

Plain-language explainers written *as the system is built*, for someone
learning the codebase and the cryptography. Not API reference — the "why" and
the "how it fits."

Read in this order:

1. **[glossary.md](glossary.md)** — every term, defined plainly. Keep it open.
2. **[stage-circuits-E-and-P.md](stage-circuits-E-and-P.md)** — the enrollment
   circuit, the presentation circuit, and the recursion that binds a ZK age
   proof to a real signed passport without revealing anything.

More stage docs get added as we build. The authoritative specs live one level
up: `SPEC_one_bit_verifier.md` (the protocol) and
`ROADMAP_one_bit_verifier.md` (what's next, phased).

## The system in three sentences

A wallet reads the government signature already on your passport chip, and
seals a birth-date credential into the phone's secure element — that's
**enrollment** (Circuit E). When a website asks "are you 18?", the wallet makes
a fresh zero-knowledge proof that answers exactly that one bit, bound to your
device and to that specific website's challenge — that's **presentation**
(Circuit P). The website checks the proof against public parameters with no
network calls to anyone, learns one bit and an unlinkable per-site pseudonym,
and stores nothing.

## Where the code lives

| Area | Path | Language |
|------|------|----------|
| Passive Authentication + protocol logic | `core/` | Java (runs on Android + desktop) |
| Wallet app | `app/` | Java (Android) |
| Verifier SDK + demo gate | `verifier/` | Java + a Node bb.js sidecar |
| ZK circuits | `circuits/` | Noir |
| Proving benchmarks | `bench/` | Noir + scripts |
