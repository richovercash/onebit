// SPDX-License-Identifier: AGPL-3.0-only
package onebit.core;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;

import net.sf.scuba.data.Gender;
import net.sf.scuba.tlv.TLVInputStream;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.MRZInfo;

/**
 * Characterizes the REAL ICAO passive-auth CMS structure so the faithful
 * circuit can model it: what the RSA signature actually covers (signedAttrs,
 * NOT eContent directly), and the offsets of the two nested hashes.
 *
 * Chain of hashes in real PA:
 *   SHA256(DG1)      == dataGroupHash[1] inside eContent (LDSSecurityObject)
 *   SHA256(eContent) == messageDigest attribute inside signedAttrs
 *   RSA_verify( SHA256(signedAttrs) )   -- signedAttrs re-tagged 0x31 SET OF
 */
public final class CmsProbe {
    public static void main(String[] args) throws Exception {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());

        MRZInfo mrz = new MRZInfo("P", "UTO", "DOE", "JOHN", "123456789", "UTO",
                "800101", Gender.MALE, "301231", "");
        byte[] dg1 = new DG1File(mrz).getEncoded();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair k = kpg.generateKeyPair();
        X509Certificate dsc = SodSizes.selfSigned(k);

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        Map<Integer, byte[]> hashes = new LinkedHashMap<>();
        hashes.put(1, sha.digest(dg1));
        for (int dg : new int[]{2, 14, 15}) hashes.put(dg, sha.digest(new byte[]{(byte) dg}));
        SODFile sod = new SODFile("SHA-256", "SHA256withRSA", hashes, k.getPrivate(), dsc);

        // Parse the CMS out of the SOD wrapper (0x77 ICAO tag).
        TLVInputStream tlv = new TLVInputStream(new java.io.ByteArrayInputStream(sod.getEncoded()));
        tlv.readTag();
        tlv.readLength();
        CMSSignedData cms = new CMSSignedData(tlv.readValue());
        SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();

        byte[] eContent = (byte[]) cms.getSignedContent().getContent();
        byte[] signedAttrs = signer.getEncodedSignedAttributes(); // DER, 0x31-tagged
        byte[] dg1Hash = sha.digest(dg1);
        byte[] eContentHash = sha.digest(eContent);

        System.out.println("dg1:          " + dg1.length + " bytes");
        System.out.println("eContent:     " + eContent.length + " bytes, SHA blocks=" + blocks(eContent.length));
        System.out.println("  SHA256(DG1) offset in eContent: " + indexOf(eContent, dg1Hash));
        System.out.println("signedAttrs:  " + signedAttrs.length + " bytes, SHA blocks=" + blocks(signedAttrs.length));
        System.out.println("  SHA256(eContent) offset in signedAttrs: " + indexOf(signedAttrs, eContentHash));
        System.out.println("  signedAttrs[0] tag = 0x" + String.format("%02x", signedAttrs[0]) + " (expect 0x31 SET OF)");
        System.out.println("signature:    " + signer.getSignature().length + " bytes (RSA-2048)");
        // Confirm RSA signs SHA256(signedAttrs)
        boolean sigOk = signer.verify(new org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder()
                .setProvider("BC").build(dsc));
        System.out.println("RSA verifies over signedAttrs: " + sigOk);
        System.out.println("total SHA blocks (dg1+eContent+signedAttrs): "
                + (blocks(dg1.length) + blocks(eContent.length) + blocks(signedAttrs.length)));

        // Emit the faithful-circuit witness (Prover.toml) from these real bytes.
        java.math.BigInteger n = ((java.security.interfaces.RSAPublicKey) dsc.getPublicKey()).getModulus();
        byte[] sigBytes = signer.getSignature();
        String out =
              "dg1 = " + bytes(dg1) + "\n"
            + "econtent = " + bytes(pad(eContent, 256)) + "\n"
            + "econtent_len = " + eContent.length + "\n"
            + "signed_attrs = " + bytes(pad(signedAttrs, 128)) + "\n"
            + "signed_attrs_len = " + signedAttrs.length + "\n"
            + "dg1_hash_off = " + indexOf(eContent, dg1Hash) + "\n"
            + "econtent_hash_off = " + indexOf(signedAttrs, eContentHash) + "\n"
            + "sig = " + limbs(new java.math.BigInteger(1, sigBytes)) + "\n"
            + "modulus = " + limbs(n) + "\n"
            + "redc = " + limbs(java.math.BigInteger.ONE.shiftLeft(2 * 2048 + 6).divide(n)) + "\n"
            + "merkle_path = " + rand20() + "\n"
            + "merkle_dirs = 349525\n"
            + "k = \"" + randField() + "\"\n"
            + "ctx = \"" + randField() + "\"\n"
            + "current = 20260718\n"
            + "age_min = 18\n";
        java.nio.file.Files.writeString(
                java.nio.file.Path.of(System.getProperty("out", "Prover.toml")), out);
        System.out.println("wrote Prover.toml");
    }

    static final java.math.BigInteger P = new java.math.BigInteger(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617");

    static byte[] pad(byte[] b, int n) {
        byte[] o = new byte[n];
        System.arraycopy(b, 0, o, 0, b.length);
        return o;
    }

    static String bytes(byte[] b) {
        StringBuilder s = new StringBuilder("[");
        for (int i = 0; i < b.length; i++) { if (i > 0) s.append(", "); s.append(b[i] & 0xff); }
        return s.append("]").toString();
    }

    static String limbs(java.math.BigInteger x) {
        java.math.BigInteger mask = java.math.BigInteger.ONE.shiftLeft(120).subtract(java.math.BigInteger.ONE);
        StringBuilder s = new StringBuilder("[");
        for (int i = 0; i < 18; i++) {
            if (i > 0) s.append(", ");
            s.append("\"0x").append(x.shiftRight(120 * i).and(mask).toString(16)).append("\"");
        }
        return s.append("]").toString();
    }

    static String rand20() {
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        StringBuilder s = new StringBuilder("[");
        for (int i = 0; i < 20; i++) { if (i > 0) s.append(", "); s.append("\"").append(new java.math.BigInteger(250, rnd).mod(P)).append("\""); }
        return s.append("]").toString();
    }

    static String randField() {
        return new java.math.BigInteger(250, new java.security.SecureRandom()).mod(P).toString();
    }

    static int blocks(int n) { return (n + 8 + 63) / 64; }

    static int indexOf(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) if (hay[i + j] != needle[j]) continue outer;
            return i;
        }
        return -1;
    }

    private CmsProbe() {}
}