// SPDX-License-Identifier: AGPL-3.0-only
package onebit.core;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * ISO 18013-5 mDL passive authentication — the mdoc analog of passport
 * {@link PassiveAuth}. Verifies the issuer's COSE_Sign1 (IssuerAuth) over the
 * MobileSecurityObject, checks the DS certificate chains to a trusted IACA root
 * (AAMVA VICAL in production), binds a data element (birth_date / expiry_date)
 * to the MSO via its SHA-256 value digest, and extracts the attributes the
 * one-bit credential commits. Fails closed on any mismatch.
 *
 * Structures (CBOR): IssuerSigned = {nameSpaces: {ns: [#6.24(IssuerSignedItem)]},
 * issuerAuth: COSE_Sign1}. COSE_Sign1 = [protected, unprotected{33:x5chain},
 * payload=#6.24(MSO), signature=r‖s]. Digest_i = SHA256(#6.24(IssuerSignedItem)).
 */
public final class Mdl {

    public static final String NS = "org.iso.18013.5.1";
    static final Provider BC = new org.bouncycastle.jce.provider.BouncyCastleProvider();

    public static final class MdlData {
        public final Map<String, Object> elements = new java.util.LinkedHashMap<>(); // verified disclosed elements
        public int dob;          // YYYYMMDD (0 if birth_date not disclosed)
        public int expiry;       // YYYYMMDD (0 if expiry_date not disclosed)
        /** dob for an age predicate. 0 means "not disclosed" and would pass every
         *  `dob + age*10000 <= current` check, so never commit the raw field. */
        public int requireDob() throws MdlException {
            if (dob == 0) throw new MdlException("birth_date not disclosed");
            return dob;
        }
        public int requireExpiry() throws MdlException {
            if (expiry == 0) throw new MdlException("expiry_date not disclosed");
            return expiry;
        }
        public byte[] msoBytes;  // the MSO (COSE payload inner bstr) — doc-identity source
        public X509Certificate ds;
        /** Issuer-bound device public key from MSO deviceKeyInfo (null if absent).
         *  The anchor for holder-binding: deviceAuth must be signed by this key. */
        public PublicKey deviceKey;
        /** true iff the issuer-signed age_over_<n> boolean was disclosed and true. */
        public boolean ageOver(int n) { return Boolean.TRUE.equals(elements.get("age_over_" + n)); }
    }

    public static final class MdlException extends RuntimeException {
        public MdlException(String m) { super(m); }
    }

    @SuppressWarnings("unchecked")
    static Map<Object, Object> asMap(Object o) { return (Map<Object, Object>) o; }

    /** Decides whether a DS certificate is trusted (chains to an accepted IACA). */
    @FunctionalInterface public interface Anchor { boolean trusts(X509Certificate ds); }

    /** Standard anchor: DS issuer matches a bundled IACA's subject and DS verifies under it. */
    public static Anchor anchorOf(Collection<X509Certificate> trust) {
        return ds -> {
            for (X509Certificate iaca : trust) {
                if (!ds.getIssuerX500Principal().equals(iaca.getSubjectX500Principal())) continue;
                if (verifies(ds, iaca.getPublicKey())) return true;
            }
            return false;
        };
    }

    /** Verify a bare IssuerSigned mdoc structure against the trusted IACA root(s). */
    public static MdlData verify(byte[] issuerSignedCbor, Collection<X509Certificate> trust) {
        return verifyIssuerSigned(asMap(Cbor.decode(issuerSignedCbor)), anchorOf(trust));
    }

    /** Full DeviceResponse verification WITH holder-binding: issuer passive auth AND
     *  the mdoc deviceAuth (DeviceSignature over the SessionTranscript). Use this on any
     *  path that enrolls/acts on the credential — it defeats replay of a captured
     *  issuerSigned blob. `sessionTranscript` is the CBOR-encoded ISO 18013-5
     *  SessionTranscript for this exchange, built by the caller from its OID4VP session
     *  context (only the caller knows client_id / response_uri / nonce). Fails closed if
     *  deviceSigned/deviceAuth is missing or the signature does not verify. */
    @SuppressWarnings("unchecked")
    public static MdlData verifyDeviceResponse(byte[] deviceResponseCbor, Anchor trust, byte[] sessionTranscript) {
        Map<Object, Object> doc0 = firstDocument(deviceResponseCbor);
        MdlData d = verifyIssuerSigned(asMap(doc0.get("issuerSigned")), trust);
        String docType = (String) doc0.get("docType");
        verifyDeviceAuth(doc0, d, docType, sessionTranscript);
        return d;
    }

    /** Issuer/provenance verification ONLY — NO holder-binding. The returned data is
     *  authentic to the issuer but NOT bound to the presenter, so a captured
     *  issuerSigned blob replays. Safe only for display/probe paths that never enroll
     *  or grant on the result. Anything that acts on the credential must use the
     *  {@link #verifyDeviceResponse(byte[], Anchor, byte[])} holder-binding overload. */
    public static MdlData verifyIssuerAuth(byte[] deviceResponseCbor, Collection<X509Certificate> trust) {
        return verifyIssuerSigned(asMap(firstDocument(deviceResponseCbor).get("issuerSigned")), anchorOf(trust));
    }

    @SuppressWarnings("unchecked")
    static Map<Object, Object> firstDocument(byte[] deviceResponseCbor) {
        List<Object> docs = (List<Object>) asMap(Cbor.decode(deviceResponseCbor)).get("documents");
        if (docs == null || docs.isEmpty()) throw new MdlException("DeviceResponse has no documents");
        return asMap(docs.get(0));
    }

    /** Verify the mdoc DeviceSignature (holder-binding) over DeviceAuthenticationBytes =
     *  #6.24(["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]),
     *  under the issuer-bound deviceKey from the MSO. ES256 / DeviceSignature only. */
    @SuppressWarnings("unchecked")
    static void verifyDeviceAuth(Map<Object, Object> doc0, MdlData d, String docType, byte[] sessionTranscript) {
        try {
            if (d.deviceKey == null) throw new MdlException("MSO has no deviceKey — cannot bind holder");
            if (docType == null) throw new MdlException("document has no docType");
            Map<Object, Object> deviceSigned = asMap(doc0.get("deviceSigned"));
            if (deviceSigned == null) throw new MdlException("DeviceResponse has no deviceSigned (holder binding absent)");

            // DeviceNameSpacesBytes = the #6.24(bstr .cbor DeviceNameSpaces) as sent.
            Object nsObj = deviceSigned.get("nameSpaces");
            if (!(nsObj instanceof Cbor.Tag) || !(((Cbor.Tag) nsObj).v instanceof byte[]))
                throw new MdlException("deviceSigned.nameSpaces is not a tag-24 bstr");
            byte[] deviceNameSpacesBytes = Cbor.tag(24, Cbor.bstr((byte[]) ((Cbor.Tag) nsObj).v));

            Map<Object, Object> deviceAuth = asMap(deviceSigned.get("deviceAuth"));
            Object dsig = deviceAuth == null ? null : deviceAuth.get("deviceSignature");
            if (dsig == null) {
                // DeviceMac (ECDH-derived) is the other ISO option; this profile emits
                // DeviceSignature. Fail closed rather than skip holder-binding.
                throw new MdlException("deviceAuth has no DeviceSignature (DeviceMac not supported)");
            }
            List<Object> sign1 = (List<Object>) dsig;          // COSE_Sign1: [protected, unprotected, payload(nil), sig]
            byte[] protectedHdr = (byte[]) sign1.get(0);
            byte[] sigRS = (byte[]) sign1.get(3);

            // DeviceAuthenticationBytes (detached payload). sessionTranscript is embedded
            // verbatim as a pre-encoded CBOR item (array() just concatenates items).
            byte[] deviceAuthentication = Cbor.array(
                    Cbor.tstr("DeviceAuthentication"), sessionTranscript,
                    Cbor.tstr(docType), deviceNameSpacesBytes);
            byte[] deviceAuthBytes = Cbor.tag(24, Cbor.bstr(deviceAuthentication));

            byte[] sigStruct = Cbor.array(
                    Cbor.tstr("Signature1"), Cbor.bstr(protectedHdr),
                    Cbor.bstr(new byte[0]), Cbor.bstr(deviceAuthBytes));
            Signature v = Signature.getInstance("SHA256withECDSA", BC);
            v.initVerify(d.deviceKey);
            v.update(sigStruct);
            if (!v.verify(rsToDer(sigRS))) throw new MdlException("DeviceSignature invalid — holder binding failed");
        } catch (MdlException e) {
            throw e;
        } catch (Exception e) {
            throw new MdlException("deviceAuth parse/verify failed: " + e);
        }
    }

    /** EC2 COSE_Key -> JCA PublicKey. Supports P-256 (crv=1), the only curve this
     *  profile signs with (ES256). Keys: 1=kty(2=EC2), -1=crv, -2=x, -3=y. */
    static PublicKey coseEcKey(Map<Object, Object> cose) {
        try {
            Object crv = cose.get(-1L);
            if (!(crv instanceof Long) || (Long) crv != 1L) throw new MdlException("deviceKey curve not P-256");
            byte[] x = (byte[]) cose.get(-2L);
            byte[] y = (byte[]) cose.get(-3L);
            java.security.AlgorithmParameters ap = java.security.AlgorithmParameters.getInstance("EC");
            ap.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
            java.security.spec.ECParameterSpec sp = ap.getParameterSpec(java.security.spec.ECParameterSpec.class);
            java.security.spec.ECPoint pt = new java.security.spec.ECPoint(new BigInteger(1, x), new BigInteger(1, y));
            return java.security.KeyFactory.getInstance("EC")
                    .generatePublic(new java.security.spec.ECPublicKeySpec(pt, sp));
        } catch (MdlException e) {
            throw e;
        } catch (Exception e) {
            throw new MdlException("deviceKey parse failed: " + e);
        }
    }

    static boolean verifies(X509Certificate c, PublicKey k) {
        try { c.verify(k, BC); return true; } catch (Exception e) { return false; }
    }

    /** Bootstrap the (unpublished) IACA Root public key by cross-validation: recover the
     *  key that signed the live DS, and accept it only if it ALSO verifies an
     *  independently-published CA cert with the same issuer (e.g. the VC-Signer served by
     *  dmv.ca.gov). A random wrong candidate verifying a second, independent signature is
     *  cryptographically negligible, so the survivor is genuinely CA's root key.
     *  NOTE: this is a demo bootstrap, not an AAMVA VICAL trust assertion. */
    public static PublicKey crossValidatedRootKey(X509Certificate live, Collection<X509Certificate> independents) {
        for (PublicKey cand : recoverEcPublicKeys(live)) {
            if (!verifies(live, cand)) continue;
            for (X509Certificate ind : independents) {
                if (!ind.getIssuerX500Principal().equals(live.getIssuerX500Principal())) continue; // same named root
                if (verifies(ind, cand)) return cand;
            }
        }
        throw new MdlException("IACA root key cross-validation failed");
    }

    /** Recover the <=2 candidate P-256 public keys that could have produced an ECDSA
     *  certificate signature (RFC 6979 / SEC1 public-key recovery over the TBSCertificate). */
    public static List<PublicKey> recoverEcPublicKeys(X509Certificate cert) {
        try {
            org.bouncycastle.asn1.ASN1Sequence sig = org.bouncycastle.asn1.ASN1Sequence.getInstance(cert.getSignature());
            BigInteger r = ((org.bouncycastle.asn1.ASN1Integer) sig.getObjectAt(0)).getValue();
            BigInteger s = ((org.bouncycastle.asn1.ASN1Integer) sig.getObjectAt(1)).getValue();

            String dig = cert.getSigAlgName().toUpperCase().contains("SHA384") ? "SHA-384"
                       : cert.getSigAlgName().toUpperCase().contains("SHA512") ? "SHA-512" : "SHA-256";
            byte[] h = MessageDigest.getInstance(dig).digest(cert.getTBSCertificate());

            org.bouncycastle.asn1.x9.X9ECParameters x9 = org.bouncycastle.asn1.nist.NISTNamedCurves.getByName("P-256");
            org.bouncycastle.math.ec.ECCurve curve = x9.getCurve();
            BigInteger n = x9.getN();
            BigInteger q = ((org.bouncycastle.math.ec.ECCurve.Fp) curve).getQ();
            org.bouncycastle.math.ec.ECPoint G = x9.getG();
            BigInteger e = truncate(h, n);

            java.security.spec.ECParameterSpec spec = ((java.security.interfaces.ECPublicKey)
                    cert.getPublicKey()).getParams(); // any P-256 spec; leaf is P-256 too
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC");

            List<PublicKey> out = new java.util.ArrayList<>();
            BigInteger rInv = r.modInverse(n);
            for (int j = 0; j <= 1; j++) {
                BigInteger x = r.add(BigInteger.valueOf(j).multiply(n));
                if (x.compareTo(q) >= 0) continue;
                for (int yBit = 0; yBit <= 1; yBit++) {
                    try {
                        byte[] enc = new byte[33];
                        enc[0] = (byte) (0x02 | yBit);
                        byte[] xb = to32(x);
                        System.arraycopy(xb, 0, enc, 1, 32);
                        org.bouncycastle.math.ec.ECPoint R = curve.decodePoint(enc);
                        if (!R.multiply(n).isInfinity()) continue;                 // order check
                        // Q = rInv*(s*R - e*G)
                        org.bouncycastle.math.ec.ECPoint Q = org.bouncycastle.math.ec.ECAlgorithms
                                .sumOfTwoMultiplies(R, s.multiply(rInv).mod(n), G, n.subtract(e).multiply(rInv).mod(n))
                                .normalize();
                        if (Q.isInfinity()) continue;
                        java.security.spec.ECPoint jp = new java.security.spec.ECPoint(
                                Q.getAffineXCoord().toBigInteger(), Q.getAffineYCoord().toBigInteger());
                        out.add(kf.generatePublic(new java.security.spec.ECPublicKeySpec(jp, spec)));
                    } catch (Exception ignore) { }
                }
            }
            return out;
        } catch (Exception ex) { throw new MdlException("EC key recovery failed: " + ex); }
    }

    private static BigInteger truncate(byte[] h, BigInteger n) {
        BigInteger e = new BigInteger(1, h);
        int excess = h.length * 8 - n.bitLength();
        return excess > 0 ? e.shiftRight(excess) : e;
    }

    private static byte[] to32(BigInteger x) {
        byte[] b = x.toByteArray(), out = new byte[32];
        if (b.length == 32) return b;
        if (b.length > 32) System.arraycopy(b, b.length - 32, out, 0, 32);
        else System.arraycopy(b, 0, out, 32 - b.length, b.length);
        return out;
    }

    /** Extract every cert in the issuerAuth x5chain (COSE label 33) of a
     *  DeviceResponse — DS first, then any intermediate/IACA the issuer chose to
     *  ship. Cert DNs are organizational (issuer identity), never PII. Lets a caller
     *  discover which IACA anchor a real credential needs. */
    @SuppressWarnings("unchecked")
    public static List<X509Certificate> x5chain(byte[] deviceResponseCbor) {
        try {
            List<Object> docs = (List<Object>) asMap(Cbor.decode(deviceResponseCbor)).get("documents");
            Map<Object, Object> issuerSigned = asMap(asMap(docs.get(0)).get("issuerSigned"));
            Map<Object, Object> unprotected = (Map<Object, Object>) ((List<Object>) issuerSigned.get("issuerAuth")).get(1);
            Object x5 = unprotected.get(33L);
            List<byte[]> ders = new java.util.ArrayList<>();
            if (x5 instanceof List) for (Object o : (List<Object>) x5) ders.add((byte[]) o);
            else ders.add((byte[]) x5);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> out = new java.util.ArrayList<>();
            for (byte[] der : ders) out.add((X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(der)));
            return out;
        } catch (Exception e) { throw new MdlException("x5chain extract failed: " + e); }
    }

    /** Core: verify IssuerAuth + IACA chain + bind every disclosed element to its
     *  MSO value digest; returns all verified elements (no fixed required set, so a
     *  presentation disclosing only age_over_18 works). */
    @SuppressWarnings("unchecked")
    static MdlData verifyIssuerSigned(Map<Object, Object> issuerSigned, Anchor trust) {
        try {
            List<Object> auth = (List<Object>) issuerSigned.get("issuerAuth");
            byte[] protectedHdr = (byte[]) auth.get(0);
            Map<Object, Object> unprotected = (Map<Object, Object>) auth.get(1);
            byte[] payload = (byte[]) auth.get(2);   // #6.24(bstr .cbor MSO), as a bstr
            byte[] sigRS = (byte[]) auth.get(3);     // COSE fixed-length r‖s

            // DS cert from the x5chain (COSE header label 33).
            Object x5 = unprotected.get(33L);
            byte[] dsDer = x5 instanceof List ? (byte[]) ((List<Object>) x5).get(0) : (byte[]) x5;
            X509Certificate ds = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new java.io.ByteArrayInputStream(dsDer));

            // 1. IssuerAuth signature over the COSE Sig_structure.
            byte[] sigStruct = Cbor.array(
                    Cbor.tstr("Signature1"), Cbor.bstr(protectedHdr), Cbor.bstr(new byte[0]), Cbor.bstr(payload));
            Signature v = Signature.getInstance("SHA256withECDSA", BC);
            v.initVerify(ds.getPublicKey());
            v.update(sigStruct);
            if (!v.verify(rsToDer(sigRS))) throw new MdlException("IssuerAuth signature invalid");

            // 2. DS chains to a trusted IACA root (predicate: bundled certs or bootstrapped key).
            if (!trust.trusts(ds)) throw new MdlException("DS does not chain to a trusted IACA");

            // 3. MSO: unwrap the tag-24 payload, read valueDigests.
            Cbor.Tag msoTag = (Cbor.Tag) Cbor.decode(payload);
            byte[] msoBytes = (byte[]) msoTag.v;                    // bstr .cbor MSO
            Map<Object, Object> mso = (Map<Object, Object>) Cbor.decode(msoBytes);
            Map<Object, Object> nsDigests = (Map<Object, Object>)
                    ((Map<Object, Object>) mso.get("valueDigests")).get(NS);

            // 3b. Temporal validity (ISO 18013-5 §9.3.1). Fail closed: the DS cert must be
            // currently valid, and now must fall within the MSO validity window. MSOs are
            // short-lived, so an expired one means the issuer no longer vouches for the data.
            ds.checkValidity();
            Map<Object, Object> validity = (Map<Object, Object>) mso.get("validityInfo");
            if (validity == null) throw new MdlException("MSO has no validityInfo");
            java.time.Instant now = java.time.Instant.now();
            Object vf = validity.get("validFrom");
            if (vf != null && now.isBefore(tdate(vf))) throw new MdlException("MSO not yet valid");
            Object vu = validity.get("validUntil");
            if (vu == null) throw new MdlException("MSO has no validUntil");
            if (now.isAfter(tdate(vu))) throw new MdlException("MSO expired (validUntil " + tdate(vu) + ")");

            // 4. Bind each disclosed element: SHA256(#6.24(IssuerSignedItem)) == digest.
            Map<Object, Object> nameSpaces = (Map<Object, Object>) issuerSigned.get("nameSpaces");
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            MdlData d = new MdlData();
            d.ds = ds;
            d.msoBytes = msoBytes;
            // Issuer-bound device key (MSO deviceKeyInfo.deviceKey), if present. This is
            // the holder-binding anchor verifyDeviceAuth checks the DeviceSignature against.
            Object dki = mso.get("deviceKeyInfo");
            if (dki instanceof Map) {
                Object dk = ((Map<Object, Object>) dki).get("deviceKey");
                if (dk instanceof Map) d.deviceKey = coseEcKey((Map<Object, Object>) dk);
            }
            for (Object elem : (List<Object>) nameSpaces.get(NS)) {
                // each elem is Tag(24, bstr(IssuerSignedItem)); re-encode to hash the exact bytes
                byte[] itemBytes = (byte[]) ((Cbor.Tag) elem).v;
                byte[] tagged = Cbor.tag(24, Cbor.bstr(itemBytes));
                Map<Object, Object> item = (Map<Object, Object>) Cbor.decode(itemBytes);
                long digestID = (Long) item.get("digestID");
                byte[] want = (byte[]) nsDigests.get(digestID);
                if (want == null || !MessageDigest.isEqual(want, sha.digest(tagged)))
                    throw new MdlException("value digest mismatch for element " + item.get("elementIdentifier"));
                String id = (String) item.get("elementIdentifier");
                Object val = item.get("elementValue");
                d.elements.put(id, val);
                if (id.equals("birth_date")) d.dob = fullDate(val);
                else if (id.equals("expiry_date")) d.expiry = fullDate(val);
            }
            if (d.elements.isEmpty()) throw new MdlException("mDL disclosed no elements");
            return d;
        } catch (MdlException e) {
            throw e;
        } catch (Exception e) {
            throw new MdlException("mdoc parse/verify failed: " + e);
        }
    }

    /** COSE tdate (tag 0, RFC3339 date-time) or full-date (tag 1004 "YYYY-MM-DD")
     *  -> Instant. A bare date is taken at start-of-day UTC. */
    static java.time.Instant tdate(Object v) {
        String s = v instanceof Cbor.Tag ? (String) ((Cbor.Tag) v).v : (String) v;
        if (s.length() == 10) return java.time.LocalDate.parse(s)
                .atStartOfDay(java.time.ZoneOffset.UTC).toInstant();
        return java.time.Instant.parse(s);
    }

    /** full-date "YYYY-MM-DD" (tag 1004 or plain tstr) -> YYYYMMDD int. */
    static int fullDate(Object v) {
        String s = v instanceof Cbor.Tag ? (String) ((Cbor.Tag) v).v : (String) v;
        return Integer.parseInt(s.substring(0, 4) + s.substring(5, 7) + s.substring(8, 10));
    }

    /** COSE ECDSA is fixed-length r‖s; JCA verify wants a DER SEQUENCE(r, s). */
    static byte[] rsToDer(byte[] rs) throws Exception {
        int n = rs.length / 2;
        BigInteger r = new BigInteger(1, java.util.Arrays.copyOfRange(rs, 0, n));
        BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(rs, n, 2 * n));
        return new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[]{
                new org.bouncycastle.asn1.ASN1Integer(r), new org.bouncycastle.asn1.ASN1Integer(s)}).getEncoded();
    }

    private Mdl() {}
}