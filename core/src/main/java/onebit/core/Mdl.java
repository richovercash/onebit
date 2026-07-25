package onebit.core;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
        public byte[] msoBytes;  // the MSO (COSE payload inner bstr) — doc-identity source
        public X509Certificate ds;
        /** true iff the issuer-signed age_over_<n> boolean was disclosed and true. */
        public boolean ageOver(int n) { return Boolean.TRUE.equals(elements.get("age_over_" + n)); }
    }

    public static final class MdlException extends RuntimeException {
        public MdlException(String m) { super(m); }
    }

    @SuppressWarnings("unchecked")
    static Map<Object, Object> asMap(Object o) { return (Map<Object, Object>) o; }

    /** Verify a bare IssuerSigned mdoc structure against the trusted IACA root(s). */
    public static MdlData verify(byte[] issuerSignedCbor, java.util.Collection<X509Certificate> trust) {
        return verifyIssuerSigned(asMap(Cbor.decode(issuerSignedCbor)), trust);
    }

    /** Verify an ISO 18013-5 DeviceResponse (the OID4VP / DC-API vp_token payload):
     *  take documents[0].issuerSigned and verify it. This is what the wallet returns. */
    @SuppressWarnings("unchecked")
    public static MdlData verifyDeviceResponse(byte[] deviceResponseCbor, java.util.Collection<X509Certificate> trust) {
        List<Object> docs = (List<Object>) asMap(Cbor.decode(deviceResponseCbor)).get("documents");
        if (docs == null || docs.isEmpty()) throw new MdlException("DeviceResponse has no documents");
        return verifyIssuerSigned(asMap(asMap(docs.get(0)).get("issuerSigned")), trust);
    }

    /** Core: verify IssuerAuth + IACA chain + bind every disclosed element to its
     *  MSO value digest; returns all verified elements (no fixed required set, so a
     *  presentation disclosing only age_over_18 works). */
    @SuppressWarnings("unchecked")
    static MdlData verifyIssuerSigned(Map<Object, Object> issuerSigned, java.util.Collection<X509Certificate> trust) {
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

            // 2. DS chains to a trusted IACA root.
            boolean chained = false;
            for (X509Certificate iaca : trust) {
                if (!ds.getIssuerX500Principal().equals(iaca.getSubjectX500Principal())) continue;
                try { ds.verify(iaca.getPublicKey(), BC); chained = true; break; } catch (Exception ignored) { }
            }
            if (!chained) throw new MdlException("DS does not chain to a trusted IACA");

            // 3. MSO: unwrap the tag-24 payload, read valueDigests.
            Cbor.Tag msoTag = (Cbor.Tag) Cbor.decode(payload);
            byte[] msoBytes = (byte[]) msoTag.v;                    // bstr .cbor MSO
            Map<Object, Object> mso = (Map<Object, Object>) Cbor.decode(msoBytes);
            Map<Object, Object> nsDigests = (Map<Object, Object>)
                    ((Map<Object, Object>) mso.get("valueDigests")).get(NS);

            // 4. Bind each disclosed element: SHA256(#6.24(IssuerSignedItem)) == digest.
            Map<Object, Object> nameSpaces = (Map<Object, Object>) issuerSigned.get("nameSpaces");
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            MdlData d = new MdlData();
            d.ds = ds;
            d.msoBytes = msoBytes;
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
