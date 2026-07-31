// SPDX-License-Identifier: AGPL-3.0-only
package onebit.core;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Synthetic RSA-6144 CSCA -> RSA-2048 DSC chain; emits the enroll_rsa6144
 *  witness (52 CSCA limbs). Mirrors EnrollProbe/EcdsaProbe; RSA-6144 keygen is
 *  slow but one-time. Covers the 6 RSA-6144 CSCAs in the master list. */
public final class Rsa6144Probe {
    static final int LIMBS = 52;   // ceil(6144/120)

    public static void main(String[] args) throws Exception {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
        String outDir = System.getProperty("dir", ".");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(6144);
        KeyPair csca = kpg.generateKeyPair();
        kpg.initialize(2048);
        KeyPair dsc = kpg.generateKeyPair();

        long now = System.currentTimeMillis();
        X509Certificate dscCert = new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(new X500Name("CN=CSCA,C=US"), BigInteger.valueOf(now),
                        new Date(now - 86400000L), new Date(now + 10L * 365 * 86400000L),
                        new X500Name("CN=DSC,C=US"), dsc.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withRSA").build(csca.getPrivate())));

        byte[] tbs = dscCert.getTBSCertificate();
        BigInteger cscaSig = new BigInteger(1, dscCert.getSignature());
        BigInteger cscaN = ((java.security.interfaces.RSAPublicKey) csca.getPublic()).getModulus();
        BigInteger dscN = ((java.security.interfaces.RSAPublicKey) dsc.getPublic()).getModulus();

        BigInteger P = new BigInteger(
                "21888242871839275222246405745257275088548364400416034343698204186575808495617");
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        StringBuilder path = new StringBuilder("[");
        for (int i = 0; i < 10; i++) { if (i > 0) path.append(", "); path.append("\"").append(new BigInteger(250, rnd).mod(P)).append("\""); }
        path.append("]");

        String out =
              "dsc_tbs = " + bytes(pad(tbs, 2048)) + "\n"
            + "dsc_tbs_len = " + tbs.length + "\n"
            + "csca_sig = " + limbs(cscaSig, LIMBS) + "\n"
            + "csca_modulus = " + limbs(cscaN, LIMBS) + "\n"
            + "csca_redc = " + limbs(BigInteger.ONE.shiftLeft(2 * 6144 + 6).divide(cscaN), LIMBS) + "\n"
            + "merkle_path = " + path + "\n"
            + "merkle_dirs = 341\n"
            + "dsc_modulus = " + limbs(dscN, 18) + "\n"
            + "dsc_modulus_off = " + Witness.indexOf(tbs, Witness.be256(dscN)) + "\n";
        java.nio.file.Files.writeString(java.nio.file.Path.of(outDir, "enroll_rsa6144.toml"), out);
        System.out.println("CSCA RSA-" + cscaN.bitLength() + " signs DSC RSA-" + dscN.bitLength()
                + ", TBS " + tbs.length + "B -> wrote enroll_rsa6144.toml");
    }

    static byte[] pad(byte[] b, int n) { byte[] o = new byte[n]; System.arraycopy(b, 0, o, 0, b.length); return o; }
    static String bytes(byte[] b) {
        StringBuilder s = new StringBuilder("[");
        for (int i = 0; i < b.length; i++) { if (i > 0) s.append(", "); s.append(b[i] & 0xff); }
        return s.append("]").toString();
    }
    static String limbs(BigInteger x, int n) {
        BigInteger mask = BigInteger.ONE.shiftLeft(120).subtract(BigInteger.ONE);
        StringBuilder s = new StringBuilder("[");
        for (int i = 0; i < n; i++) { if (i > 0) s.append(", "); s.append("\"0x").append(x.shiftRight(120 * i).and(mask).toString(16)).append("\""); }
        return s.append("]").toString();
    }
    private Rsa6144Probe() {}
}