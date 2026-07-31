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

/** Builds a synthetic CSCA(RSA-4096) -> DSC(RSA-2048) chain and emits the
 *  enrollment-circuit witness. Same extraction the wallet does on the real
 *  DSC certificate + its issuing CSCA from the master list. */
public final class EnrollProbe {
    public static void main(String[] args) throws Exception {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
        KeyPair csca = kpg.generateKeyPair();
        kpg.initialize(2048);
        KeyPair dsc = kpg.generateKeyPair();

        // CSCA signs the DSC certificate
        long now = System.currentTimeMillis();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name("CN=Test CSCA,C=US"), BigInteger.valueOf(now),
                new Date(now - 86400000L), new Date(now + 10L * 365 * 86400000L),
                new X500Name("CN=Test DSC,C=US"), dsc.getPublic());
        X509Certificate dscCert = new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(csca.getPrivate())));

        byte[] tbs = dscCert.getTBSCertificate();
        BigInteger cscaSig = new BigInteger(1, dscCert.getSignature());
        BigInteger cscaN = ((java.security.interfaces.RSAPublicKey) csca.getPublic()).getModulus();
        BigInteger dscN = ((java.security.interfaces.RSAPublicKey) dsc.getPublic()).getModulus();

        BigInteger P = new BigInteger(
                "21888242871839275222246405745257275088548364400416034343698204186575808495617");
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        StringBuilder path = new StringBuilder("[");
        for (int i = 0; i < 20; i++) { if (i > 0) path.append(", "); path.append("\"").append(new BigInteger(250, rnd).mod(P)).append("\""); }
        path.append("]");

        String out =
              "dsc_tbs = " + bytes(pad(tbs, 1024)) + "\n"
            + "dsc_tbs_len = " + tbs.length + "\n"
            + "csca_sig = " + limbs(cscaSig, 35) + "\n"
            + "csca_modulus = " + limbs(cscaN, 35) + "\n"
            + "csca_redc = " + limbs(BigInteger.ONE.shiftLeft(2 * 4096 + 6).divide(cscaN), 35) + "\n"
            + "merkle_path = " + path + "\n"
            + "merkle_dirs = 349525\n"
            + "dsc_modulus = " + limbs(dscN, 18) + "\n";
        java.nio.file.Files.writeString(
                java.nio.file.Path.of(System.getProperty("out", "Prover.toml")), out);
        System.out.println("CSCA RSA-" + cscaN.bitLength() + " signs DSC RSA-" + dscN.bitLength()
                + ", TBS " + tbs.length + "B -> wrote Prover.toml");
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
    private EnrollProbe() {}
}