projectId: onebit
severity: high
status: in_progress
created_at: 2026-08-15T03:16:32.887Z
description: |-
  

  [2026-08-15] Java fix landed in b029c70: Mdl.verifyDeviceResponse(dr, anchor, sessionTranscript) verifies the DeviceSignature over a reconstructed ISO 18013-7 SessionTranscript; issuer-only path renamed verifyIssuerAuth (explicit no-holder-binding contract); MdlSchemeActivity (enrolling path) builds the OID4VPHandover transcript and fails closed without valid deviceAuth. 4 new MdlTest cases prove replay/missing-deviceAuth/tamper all reject (39 core tests green). REMAINING before done: one on-device pass against the CA DMV Wallet to confirm the SessionTranscript handover encoding (MdlSchemeActivity.oid4vpSessionTranscript) matches; if the wallet uses a different handover variant or DeviceMac, deviceAuth fails closed (safe) and that builder is the single spot to adjust.
updated_at: 2026-08-15T03:24:26.576Z
