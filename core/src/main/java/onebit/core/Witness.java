package onebit.core;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

import net.sf.scuba.tlv.TLVInputStream;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

/**
 * Extracts the mono_faithful presentation-circuit witness from a real passport
 * DG1 + SOD — the same fields core/CmsProbe measured on a synthetic SOD, now
 * from the live document. Used by the wallet at enrollment (SPEC §3.1.5: raw
 * witness retained for Option-A/monolithic proving).
 */
public final class Witness {

    public static final class Doc {
        public byte[] dg1;
        public byte[] eContent;      // LDS security object
        public byte[] signedAttrs;   // CMS signedAttributes (0x31 SET OF)
        public int dg1HashOff;       // SHA256(dg1) offset in eContent
        public int eContentHashOff;  // SHA256(eContent) offset in signedAttrs
        public BigInteger sig;
        public BigInteger modulus;
    }

    /** Parse the SOD's CMS and pull out the faithful-circuit inputs. */
    public static Doc extract(byte[] dg1, byte[] sodBytes) throws Exception {
        TLVInputStream tlv = new TLVInputStream(new ByteArrayInputStream(sodBytes));
        tlv.readTag();      // 0x77 ICAO wrapper
        tlv.readLength();
        CMSSignedData cms = new CMSSignedData(tlv.readValue());
        SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();

        Doc d = new Doc();
        d.dg1 = dg1;
        d.eContent = (byte[]) cms.getSignedContent().getContent();
        d.signedAttrs = signer.getEncodedSignedAttributes();
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        d.dg1HashOff = indexOf(d.eContent, sha.digest(dg1));
        d.eContentHashOff = indexOf(d.signedAttrs, sha.digest(d.eContent));
        d.sig = new BigInteger(1, signer.getSignature());
        org.bouncycastle.cert.X509CertificateHolder holder =
                (org.bouncycastle.cert.X509CertificateHolder)
                        cms.getCertificates().getMatches(signer.getSID()).iterator().next();
        d.modulus = org.bouncycastle.asn1.pkcs.RSAPublicKey
                .getInstance(holder.getSubjectPublicKeyInfo().parsePublicKey()).getModulus();
        return d;
    }

    /** Build the mono_faithful document witness (everything except k, ctx,
     *  current, age_min) as ABI-ordered decimal strings. Arrays padded to the
     *  circuit's compile-time sizes. Throws if the document exceeds them. */
    public static List<String> monoFaithful(Doc d, int econtentCap, int signedAttrsCap) {
        if (d.eContent.length > econtentCap)
            throw new IllegalArgumentException("eContent " + d.eContent.length + " > cap " + econtentCap);
        if (d.signedAttrs.length > signedAttrsCap)
            throw new IllegalArgumentException("signedAttrs " + d.signedAttrs.length + " > cap " + signedAttrsCap);
        BigInteger n = d.modulus;
        BigInteger redc = BigInteger.ONE.shiftLeft(2 * 2048 + 6).divide(n);
        List<String> w = new ArrayList<>();
        bytes(w, d.dg1);
        bytes(w, pad(d.eContent, econtentCap));
        w.add(String.valueOf(d.eContent.length));
        bytes(w, pad(d.signedAttrs, signedAttrsCap));
        w.add(String.valueOf(d.signedAttrs.length));
        w.add(String.valueOf(d.dg1HashOff));
        w.add(String.valueOf(d.eContentHashOff));
        limbs(w, d.sig);
        limbs(w, n);
        limbs(w, redc);
        // (no merkle here — DSC trust is the enroll proof's job, ADR-005)
        return w;
    }

    /** Build the enroll-circuit witness from the live document: the DSC cert
     *  (in the SOD) and its issuing CSCA (matched in the master list). Returns
     *  null if the CSCA is not RSA (the RSA-4096 enroll variant can't prove it).
     *  Merkle path synthetic until the real CSCA tree lands. */
    public static List<String> enroll(byte[] dg1, byte[] sodBytes,
                                      java.util.Collection<X509Certificate> masterList,
                                      String treeJson) throws Exception {
        TLVInputStream tlv = new TLVInputStream(new ByteArrayInputStream(sodBytes));
        tlv.readTag(); tlv.readLength();
        CMSSignedData cms = new CMSSignedData(tlv.readValue());
        SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();
        org.bouncycastle.cert.X509CertificateHolder holder =
                (org.bouncycastle.cert.X509CertificateHolder)
                        cms.getCertificates().getMatches(signer.getSID()).iterator().next();
        X509Certificate dsc = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                .getCertificate(holder);
        X509Certificate csca = null;
        for (X509Certificate c : masterList) {
            if (!dsc.getIssuerX500Principal().equals(c.getSubjectX500Principal())) continue;
            try { dsc.verify(c.getPublicKey()); csca = c; break; } catch (Exception ignored) { }
        }
        if (csca == null) throw new IllegalStateException("CSCA not found for DSC");
        if (!(csca.getPublicKey() instanceof RSAPublicKey)) return null; // ECDSA CSCA -> other variant

        BigInteger cscaN = ((RSAPublicKey) csca.getPublicKey()).getModulus();
        BigInteger dscN = ((RSAPublicKey) dsc.getPublicKey()).getModulus();
        BigInteger cscaSig = new BigInteger(1, dsc.getSignature());
        byte[] tbs = dsc.getTBSCertificate();
        if (cscaN.bitLength() > 4096 || tbs.length > 2048)
            throw new IllegalStateException("CSCA " + cscaN.bitLength() + "bit / TBS " + tbs.length + "B exceeds enroll caps");

        // Real Merkle path: look up this CSCA (by SPKI sha256) in the tree.
        String spkiHex = hex(MessageDigest.getInstance("SHA-256").digest(csca.getPublicKey().getEncoded()));
        com.google.gson.JsonObject tree = com.google.gson.JsonParser.parseString(treeJson).getAsJsonObject();
        com.google.gson.JsonObject paths = tree.getAsJsonObject("paths");
        if (!paths.has(spkiHex)) return null; // CSCA not in the RSA<=4096 tree (e.g. 6144/ECDSA)
        com.google.gson.JsonObject entry = paths.getAsJsonObject(spkiHex);
        int dirs = entry.get("dirs").getAsInt();
        com.google.gson.JsonArray path = entry.getAsJsonArray("path");

        List<String> w = new ArrayList<>();
        bytes(w, pad(tbs, 2048));
        w.add(String.valueOf(tbs.length));
        limbsHex(w, cscaSig, 35);
        limbsHex(w, cscaN, 35);
        limbsHex(w, BigInteger.ONE.shiftLeft(2 * 4096 + 6).divide(cscaN), 35);
        for (int i = 0; i < 10; i++) w.add(path.get(i).getAsString());
        w.add(String.valueOf(dirs)); // merkle_dirs = leaf index
        limbsHex(w, dscN, 18);
        return w;
    }

    static void limbsHex(List<String> w, BigInteger x, int n) {
        BigInteger mask = BigInteger.ONE.shiftLeft(120).subtract(BigInteger.ONE);
        for (int i = 0; i < n; i++) w.add("0x" + x.shiftRight(120 * i).and(mask).toString(16));
    }

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(Character.forDigit((x >> 4) & 0xf, 16)).append(Character.forDigit(x & 0xf, 16));
        return s.toString();
    }

    static void bytes(List<String> w, byte[] b) { for (byte x : b) w.add(String.valueOf(x & 0xff)); }

    static void limbs(List<String> w, BigInteger x) {
        BigInteger mask = BigInteger.ONE.shiftLeft(120).subtract(BigInteger.ONE);
        for (int i = 0; i < 18; i++) w.add(x.shiftRight(120 * i).and(mask).toString()); // decimal
    }

    static byte[] pad(byte[] b, int n) {
        byte[] o = new byte[n];
        System.arraycopy(b, 0, o, 0, b.length);
        return o;
    }

    static int indexOf(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) if (hay[i + j] != needle[j]) continue outer;
            return i;
        }
        return -1;
    }

    private Witness() {}
}
