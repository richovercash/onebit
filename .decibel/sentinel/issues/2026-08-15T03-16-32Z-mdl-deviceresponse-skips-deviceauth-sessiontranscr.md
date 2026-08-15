---
projectId: onebit
severity: high
status: open
created_at: 2026-08-15T03:16:32.887Z
---

# mDL DeviceResponse skips deviceAuth / SessionTranscript holder-binding

**Severity:** high
**Status:** open

## Details

Source: multi-agent whole-repo review (2026-08-14), adversarially verified HIGH.

Mdl.verifyDeviceResponse() (core/src/main/java/onebit/core/Mdl.java:76) extracts documents[0].issuerSigned and verifies ONLY the issuer COSE_Sign1 + DS->IACA chain + MSO value digests. The DeviceResponse's deviceSigned/deviceAuth (DeviceSignature or DeviceMac over the SessionTranscript, mandatory in ISO 18013-5 mdoc authentication) is never parsed or checked, and nothing binds the response to the OID4VP session nonce at this layer.

Failure: an attacker who obtains a victim's previously-presented issuerSigned blob (identical across presentations) wraps it in a fresh DeviceResponse and enrolls the victim's document provenance (docHash + age bool) as their own OneBit credential via MdlSchemeActivity. Holder-binding is silently discarded.

FIX IN PROGRESS this session (commit follows): verify DeviceSignature/DeviceMac over a reconstructed SessionTranscript in Mdl.verifyDeviceResponse, plumbing the OID4VP handover (clientId, responseUri, nonce, mdocGeneratedNonce/apu) from MdlSchemeActivity per the OID4VP OpenID4VPHandover / DC-API handover profile.

Author already flagged this at MdlSchemeActivity.java ("passive auth only ... not the mdoc device signature (holder-binding/anti-replay)").
