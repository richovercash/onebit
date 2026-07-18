projectId: onebit
severity: high
status: in_progress
created_at: 2026-07-12T00:07:00.859Z
epic_id: EPIC-0001
description: |-
  

  [2026-07-12] Starting with the desktop-testable core: PA verification (SOD parse, DG1 hash check, DSC sig, CSCA chain) + century rule, tested against synthetic document fixtures. Android NFC wrapper + real-document runs follow once core passes.

  [2026-07-12] Core PA library done and green: core/ Gradle module (jmrtd 0.7.42 + BouncyCastle). PassiveAuth.verify() does DG1-hash-in-SOD, CMS signature under embedded DSC (BC CMSSignedData enforces signedAttrs binding), DSC→CSCA chain vs master list; Mrz implements the §3.1 century rule + ageGte/notExpired predicates. 8/8 tests pass incl. adversarial fixtures: tampered DG1, tampered SOD, rogue CSCA, wrong-century DOB (300101 must not read as 1930), exact 18th-birthday boundary, expired doc. Remaining for T1 exit: Android NFC read module (BAC/PACE via jmrtd), 5 real documents, instrumented zero-network-I/O test. Build note: run gradle with JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64; compile toolchain is Temurin 25 targeting release 11 (only full JDK on the box); PATH java is a broken stripped runtime.

  [2026-07-12] Android app module scaffolded, built, and installed on Pixel 6 Pro (Android 15). app/: AGP 8.13.2 + Gradle 8.13, daemon on Android Studio JBR 21. MainActivity: MRZ fields → NFC reader mode → IsoDep → jmrtd BAC → read DG1+SOD → core PassiveAuth.verify against assets/masterlist/. BAC only for now (ponytail note: add PACE when a BAC-less doc appears). Manifest requests ONLY android.permission.NFC — confirmed via dumpsys on device; V1 zero-network enforced by the OS, plus ManifestNoNetworkTest unit test. Master list is empty → app fails closed until CSCA certs are dropped in assets/masterlist/. Next: bundle CSCA cert(s) for real-document testing, then 5-document verification run.

  [2026-07-12] Master list bundled: BSI German Master List DE_ML_2026-05-28 (CMS verified via openssl), 588 unique CSCA certs covering 116 countries, extracted to app/src/main/assets/masterlist/masterlist.pem (1.25 MB). This is de-facto R_icao_v1; formal versioned/Merkle-rooted distribution comes with T4. App rebuilt + reinstalled on Pixel 6 Pro. Ready for real-document verification runs (need 5 docs for exit criterion).

  [2026-07-12] FIRST REAL DOCUMENT VERIFIED (1/5 for exit criterion). Passport (doc type P, PACE-only chip) read on Pixel 6 Pro: PACE access via EF.CardAccess → DG1+SOD read → Passive Authentication OK against bundled BSI master list → predicates age≥18=true, not-expired=true. Fully offline (app has no INTERNET permission). Fixes along the way: (1) PACE implemented — chip rejected BAC with 0x6985, modern SAC documents disable BAC; PACE-first with BAC fallback now. (2) targetSdk-35 enforced edge-to-edge occluded top form fields under system bars — fixed with insets padding; diagnosis required synthetic adb tap, view dump looked normal. (3) Input validation: MRZ dates are YYMMDD; users naturally type DDMMYY — live per-field validation added. Remaining: 4 more real documents, formal instrumented no-network test.
updated_at: 2026-07-12T01:06:52.944Z
