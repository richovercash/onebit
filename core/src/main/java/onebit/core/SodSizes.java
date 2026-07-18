package onebit.core;

import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;

import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.MRZInfo;
import net.sf.scuba.data.Gender;

/**
 * Prints the real byte sizes of the parts a presentation circuit must hash,
 * for a passport carrying a realistic set of data groups. Run to size the
 * slimmed circuit with true dimensions instead of padded guesses.
 */
public final class SodSizes {
    public static void main(String[] args) throws Exception {
        MRZInfo mrz = new MRZInfo("P", "UTO", "DOE", "JOHN", "123456789", "UTO",
                "800101", Gender.MALE, "301231", "");
        byte[] dg1 = new DG1File(mrz).getEncoded();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair k = kpg.generateKeyPair();
        X509Certificate dsc = selfSigned(k);

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        // A typical ePassport: DG1(MRZ), DG2(face), DG3(fingerprint),
        // DG14(chip auth), DG15(active auth pubkey). 5 data groups.
        Map<Integer, byte[]> hashes = new LinkedHashMap<>();
        hashes.put(1, sha.digest(dg1));
        for (int dg : new int[]{2, 3, 14, 15}) hashes.put(dg, sha.digest(new byte[]{(byte) dg}));

        SODFile sod = new SODFile("SHA-256", "SHA256withRSA", hashes, k.getPrivate(), dsc);
        byte[] econtent = sod.getEContent();

        System.out.println("DG1 bytes:        " + dg1.length + "  (" + blocks(dg1.length) + " SHA blocks)");
        System.out.println("eContent bytes:   " + econtent.length + "  (" + blocks(econtent.length) + " SHA blocks)");
        System.out.println("RSA-2048 modulus: 256  (as 18 field limbs, hashed by Poseidon not SHA)");
        System.out.println("--- vs bench padding: econtent 1200 (" + blocks(1200)
                + " blocks), dsc_cert 1000 (" + blocks(1000) + " blocks) ---");
    }

    static int blocks(int n) { return (n + 8 + 63) / 64; } // +1 byte 0x80 + 8 len, round up

    static X509Certificate selfSigned(KeyPair k) throws Exception {
        var name = new org.bouncycastle.asn1.x500.X500Name("CN=Test DSC,C=UT");
        var now = System.currentTimeMillis();
        var builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                name, java.math.BigInteger.valueOf(now), new java.util.Date(now - 86400000L),
                new java.util.Date(now + 86400000L), name, k.getPublic());
        var signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                .build(k.getPrivate());
        return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                .getCertificate(builder.build(signer));
    }

    private SodSizes() {}
}
