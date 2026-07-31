// SPDX-License-Identifier: AGPL-3.0-only
package onebit.core;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Synthetic RSA-4096 CSCA -> P-256 (secp256r1) DSC chain; emits the
 *  enroll_dsc_ecdsa witness. The DSC key is an EC point; dsc_commit is
 *  Poseidon2 over (x,y), matching mono_faithful_ecdsa. */
public final class DscEcdsaProbe {
    public static void main(String[] args) throws Exception {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
        String outDir = System.getProperty("dir", ".");

        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(4096);
        KeyPair csca = rsa.generateKeyPair();
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC", "BC");
        ec.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair dsc = ec.generateKeyPair();

        long now = System.currentTimeMillis();
        X509Certificate dscCert = new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(new X500Name("CN=CSCA,C=US"), BigInteger.valueOf(now),
                        new Date(now - 86400000L), new Date(now + 10L * 365 * 86400000L),
                        new X500Name("CN=DSC,C=US"), dsc.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withRSA").build(csca.getPrivate())));

        byte[] tbs = dscCert.getTBSCertificate();
        BigInteger cscaSig = new BigInteger(1, dscCert.getSignature());
        BigInteger cscaN = ((RSAPublicKey) csca.getPublic()).getModulus();
        ECPublicKey pk = (ECPublicKey) dsc.getPublic();
        byte[] qx = EcdsaProbe.to32(pk.getW().getAffineX());
        byte[] qy = EcdsaProbe.to32(pk.getW().getAffineY());

        // The uncompressed EC point (x||y) sits contiguously in the DSC SPKI.
        byte[] point = new byte[64];
        System.arraycopy(qx, 0, point, 0, 32);
        System.arraycopy(qy, 0, point, 32, 32);
        int off = Witness.indexOf(tbs, point);
        if (off < 0) throw new IllegalStateException("EC point not found in TBS");

        BigInteger P = new BigInteger(
                "21888242871839275222246405745257275088548364400416034343698204186575808495617");
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        StringBuilder path = new StringBuilder("[");
        for (int i = 0; i < 10; i++) { if (i > 0) path.append(", "); path.append("\"").append(new BigInteger(250, rnd).mod(P)).append("\""); }
        path.append("]");

        String out =
              "dsc_tbs = " + CmsProbe.bytes(CmsProbe.pad(tbs, 2048)) + "\n"
            + "dsc_tbs_len = " + tbs.length + "\n"
            + "csca_sig = " + limbs(cscaSig, 35) + "\n"
            + "csca_modulus = " + limbs(cscaN, 35) + "\n"
            + "csca_redc = " + limbs(BigInteger.ONE.shiftLeft(2 * 4096 + 6).divide(cscaN), 35) + "\n"
            + "merkle_path = " + path + "\n"
            + "merkle_dirs = 341\n"
            + "dsc_pubkey_x = " + CmsProbe.bytes(qx) + "\n"
            + "dsc_pubkey_y = " + CmsProbe.bytes(qy) + "\n"
            + "dsc_pubkey_off = " + off + "\n";
        java.nio.file.Files.writeString(java.nio.file.Path.of(outDir, "Prover.toml"), out);
        System.out.println("CSCA RSA-" + cscaN.bitLength() + " signs P-256 DSC, TBS " + tbs.length
                + "B, point@" + off + " -> wrote Prover.toml");
    }

    static String limbs(BigInteger x, int n) {
        BigInteger mask = BigInteger.ONE.shiftLeft(120).subtract(BigInteger.ONE);
        StringBuilder s = new StringBuilder("[");
        for (int i = 0; i < n; i++) { if (i > 0) s.append(", "); s.append("\"0x").append(x.shiftRight(120 * i).and(mask).toString(16)).append("\""); }
        return s.append("]").toString();
    }
    private DscEcdsaProbe() {}
}