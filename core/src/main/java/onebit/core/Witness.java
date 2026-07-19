package onebit.core;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
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
        // merkle_path (20) + dirs — synthetic until the real CSCA tree lands.
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        BigInteger P = new BigInteger(
                "21888242871839275222246405745257275088548364400416034343698204186575808495617");
        for (int i = 0; i < 20; i++) w.add(new BigInteger(250, rnd).mod(P).toString());
        w.add("349525"); // merkle_dirs
        return w;
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
