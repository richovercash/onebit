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
        // dsc_modulus_off: where the 256-byte DSC modulus sits in the TBS.
        byte[] be = be256(dscN);
        int mo = indexOf(tbs, be);
        if (mo < 0) throw new IllegalStateException("DSC modulus not found in TBS");
        w.add(String.valueOf(mo));
        return w;
    }

    /** What to prove for a given CSCA algorithm: which enroll circuit + tree,
     *  and the assembled witness. `alg` also names the published root key
     *  (csca_root_<alg>) the verifier checks. */
    public static final class EnrollPlan {
        public final String alg;          // rsa4096 | rsa6144 | brainpool256 | p384
        public final String circuitAsset; // zk/enroll.json etc
        public final String treeAsset;    // zk/cscatree_<alg>.json
        public final List<String> witness;
        EnrollPlan(String alg, List<String> w) {
            this.alg = alg;
            this.circuitAsset = "zk/enroll" + (alg.equals("rsa4096") ? "" :
                    alg.equals("rsa6144") ? "_rsa6144" :
                    alg.equals("brainpool256") ? "_ecdsa" : "_p384") + ".json";
            this.treeAsset = "zk/cscatree_" + alg + ".json";
            this.witness = w;
        }
    }

    static final java.security.Provider BC = new org.bouncycastle.jce.provider.BouncyCastleProvider();
    static final BigInteger BP256_PRIME = new BigInteger(
            "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377", 16);
    static final BigInteger P384_PRIME = new BigInteger(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16);

    /** Route enrollment by CSCA algorithm. Returns the plan for the matching
     *  enroll variant, or null if unsupported (CSCA curve/size we have no circuit
     *  for, DSC not RSA-2048, or CSCA not in that algorithm's tree). `treeLoader`
     *  maps an alg to its cscatree JSON. DSC is RSA-2048 in every variant. */
    public static EnrollPlan enrollRouted(byte[] dg1, byte[] sodBytes,
                                          java.util.Collection<X509Certificate> masterList,
                                          java.util.function.Function<String, String> treeLoader) throws Exception {
        TLVInputStream tlv = new TLVInputStream(new ByteArrayInputStream(sodBytes));
        tlv.readTag(); tlv.readLength();
        CMSSignedData cms = new CMSSignedData(tlv.readValue());
        SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();
        org.bouncycastle.cert.X509CertificateHolder holder =
                (org.bouncycastle.cert.X509CertificateHolder)
                        cms.getCertificates().getMatches(signer.getSID()).iterator().next();
        X509Certificate dsc = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(holder);
        X509Certificate csca = null;
        for (X509Certificate c : masterList) {
            if (!dsc.getIssuerX500Principal().equals(c.getSubjectX500Principal())) continue;
            // BC provider: the default JCE can't verify brainpool ECDSA CSCA sigs.
            try { dsc.verify(c.getPublicKey(), BC); csca = c; break; } catch (Exception ignored) { }
        }
        if (csca == null) throw new IllegalStateException("CSCA not found for DSC");
        if (!(dsc.getPublicKey() instanceof RSAPublicKey)) return null; // ECDSA DSC -> enroll_dsc_ecdsa (not routed here)

        byte[] tbs = dsc.getTBSCertificate();
        if (tbs.length > 2048) throw new IllegalStateException("TBS " + tbs.length + "B exceeds cap");
        BigInteger dscN = ((RSAPublicKey) dsc.getPublicKey()).getModulus();

        // Classify the CSCA and build its algorithm-specific witness prefix.
        String alg;
        List<String> w = new ArrayList<>();
        bytes(w, pad(tbs, 2048));
        w.add(String.valueOf(tbs.length));
        if (csca.getPublicKey() instanceof RSAPublicKey) {
            BigInteger cscaN = ((RSAPublicKey) csca.getPublicKey()).getModulus();
            BigInteger cscaSig = new BigInteger(1, dsc.getSignature());
            int bits = cscaN.bitLength();
            if (bits <= 4096) { alg = "rsa4096"; rsaFields(w, cscaSig, cscaN, 35, 4096); }
            else if (bits <= 6144) { alg = "rsa6144"; rsaFields(w, cscaSig, cscaN, 52, 6144); }
            else return null;
        } else if (csca.getPublicKey() instanceof java.security.interfaces.ECPublicKey) {
            java.security.interfaces.ECPublicKey ec = (java.security.interfaces.ECPublicKey) csca.getPublicKey();
            BigInteger prime = ((java.security.spec.ECFieldFp) ec.getParams().getCurve().getField()).getP();
            int clen;
            if (prime.equals(BP256_PRIME)) { alg = "brainpool256"; clen = 32; }
            else if (prime.equals(P384_PRIME)) { alg = "p384"; clen = 48; }
            else return null;                                   // curve without a circuit
            BigInteger[] rs = ecSig(dsc.getSignature(), ec.getParams().getOrder());
            bytes(w, toBE(ec.getW().getAffineX(), clen));
            bytes(w, toBE(ec.getW().getAffineY(), clen));
            bytes(w, toBE(rs[0], clen));
            bytes(w, toBE(rs[1], clen));
        } else return null;

        // Real Merkle path from this algorithm's tree.
        String spkiHex = hex(MessageDigest.getInstance("SHA-256").digest(csca.getPublicKey().getEncoded()));
        com.google.gson.JsonObject tree = com.google.gson.JsonParser.parseString(treeLoader.apply(alg)).getAsJsonObject();
        com.google.gson.JsonObject paths = tree.getAsJsonObject("paths");
        if (!paths.has(spkiHex)) return null;                   // CSCA not in that tree
        com.google.gson.JsonObject entry = paths.getAsJsonObject(spkiHex);
        for (int i = 0; i < 10; i++) w.add(entry.getAsJsonArray("path").get(i).getAsString());
        w.add(String.valueOf(entry.get("dirs").getAsInt()));

        // DSC pubkey (RSA-2048) to commit + its offset in the TBS (F1 binding).
        limbsHex(w, dscN, 18);
        int mo = indexOf(tbs, be256(dscN));
        if (mo < 0) throw new IllegalStateException("DSC modulus not found in TBS");
        w.add(String.valueOf(mo));
        return new EnrollPlan(alg, w);
    }

    static void rsaFields(List<String> w, BigInteger sig, BigInteger n, int limbs, int modBits) {
        limbsHex(w, sig, limbs);
        limbsHex(w, n, limbs);
        limbsHex(w, BigInteger.ONE.shiftLeft(2 * modBits + 6).divide(n), limbs);
    }

    /** big-endian fixed-length bytes of a non-negative BigInteger. */
    static byte[] toBE(BigInteger x, int len) {
        byte[] b = x.toByteArray(), o = new byte[len];
        int n = Math.min(b.length, len);
        System.arraycopy(b, b.length - n, o, len - n, n);
        return o;
    }

    /** parse a DER ECDSA signature into (r, s), normalized to canonical low-s. */
    static BigInteger[] ecSig(byte[] der, BigInteger order) {
        org.bouncycastle.asn1.ASN1Sequence seq = org.bouncycastle.asn1.ASN1Sequence.getInstance(der);
        BigInteger r = ((org.bouncycastle.asn1.ASN1Integer) seq.getObjectAt(0)).getValue();
        BigInteger s = ((org.bouncycastle.asn1.ASN1Integer) seq.getObjectAt(1)).getValue();
        if (s.compareTo(order.shiftRight(1)) > 0) s = order.subtract(s);
        return new BigInteger[]{r, s};
    }

    /** unsigned 256-byte big-endian representation of a 2048-bit modulus. */
    static byte[] be256(BigInteger n) {
        byte[] b = n.toByteArray();               // may have a leading 0x00 sign byte
        byte[] o = new byte[256];
        int len = Math.min(b.length, 256);
        System.arraycopy(b, b.length - len, o, 256 - len, len);
        return o;
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
