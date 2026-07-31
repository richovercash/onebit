# Security Policy

One Bit Verifier derives a single privacy-preserving bit ("are you over N?") from a
government ID, seals it in the secure element, and answers verifier challenges with a
zero-knowledge proof disclosing exactly that one bit plus a rotating nullifier. Because
it handles identity documents and cryptographic material, we take reports seriously.

## Reporting a vulnerability

Please **do not** open a public issue for security-sensitive reports.

- Email the maintainers (see the repository owner) with details and, if possible, a
  proof of concept. Encrypt sensitive contents if you can.
- Expect an acknowledgement within a few days and a coordinated disclosure timeline.

## In scope

- Anything that leaks holder identity or more than the one intended bit.
- Nullifier linkability across verifiers or across epochs.
- Forging a GRANT, a device attestation, or a verifier challenge signature.
- Bypassing passive authentication / the CSCA→DSC trust chain.
- On-device PII persistence (the design retains **no** name, DOB, expiry, or document
  number — a report showing otherwise is in scope).

## Out of scope

- Attacks requiring a rooted/unlocked device the holder controls (the threat model
  assumes a trusted holder device; StrongBox/attestation is the anchor).
- The bundled demo verifier's in-memory state (documented as non-persistent).

## Handling test credentials

Do not commit real passport/mDL data, MRZ values, keystores, or SRS material. The MRZ
is treated as session-only PII in the app and must never be persisted or logged.
