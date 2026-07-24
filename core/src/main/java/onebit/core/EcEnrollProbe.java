package onebit.core;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Parameterized EC-CSCA enroll witness generator: synthetic <curve> CSCA ->
 *  RSA-2048 DSC chain, emitting the enroll_<curve> witness. One probe for every
 *  ECDSA CSCA variant. Coordinate length + low-s order come from the key itself.
 *  Props: -Dcurve=<jce curve> -Dsig=<SHAxxxwithECDSA> -Ddir=<out> -Dout=<file>. */
public final class EcEnrollProbe {
    public static void main(String[] args) throws Exception {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
        String curve = System.getProperty("curve", "secp256r1");
        String sigAlg = System.getProperty("sig", "SHA256withECDSA");
        String out = System.getProperty("out", System.getProperty("dir", ".") + "/Prover.toml");

        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC", "BC");
        ec.initialize(new ECGenParameterSpec(curve));
        KeyPair csca = ec.generateKeyPair();
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair dsc = rsa.generateKeyPair();

        long now = System.currentTimeMillis();
        X509Certificate dscCert = new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(new X500Name("CN=CSCA,C=US"), BigInteger.valueOf(now),
                        new Date(now - 86400000L), new Date(now + 10L * 365 * 86400000L),
                        new X500Name("CN=DSC,C=US"), dsc.getPublic())
                        .build(new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(csca.getPrivate())));

        byte[] tbs = dscCert.getTBSCertificate();
        ECPublicKey pk = (ECPublicKey) csca.getPublic();
        int clen = (pk.getParams().getCurve().getField().getFieldSize() + 7) / 8;
        BigInteger[] rs = Witness.ecSig(dscCert.getSignature(), pk.getParams().getOrder());
        BigInteger dscN = ((java.security.interfaces.RSAPublicKey) dsc.getPublic()).getModulus();

        BigInteger P = new BigInteger(
                "21888242871839275222246405745257275088548364400416034343698204186575808495617");
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        StringBuilder path = new StringBuilder("[");
        for (int i = 0; i < 10; i++) { if (i > 0) path.append(", "); path.append("\"").append(new BigInteger(250, rnd).mod(P)).append("\""); }
        path.append("]");

        StringBuilder w = new StringBuilder();
        w.append("dsc_tbs = ").append(CmsProbe.bytes(CmsProbe.pad(tbs, 2048))).append("\n");
        w.append("dsc_tbs_len = ").append(tbs.length).append("\n");
        w.append("csca_pubkey_x = ").append(CmsProbe.bytes(Witness.toBE(pk.getW().getAffineX(), clen))).append("\n");
        w.append("csca_pubkey_y = ").append(CmsProbe.bytes(Witness.toBE(pk.getW().getAffineY(), clen))).append("\n");
        w.append("csca_sig_r = ").append(CmsProbe.bytes(Witness.toBE(rs[0], clen))).append("\n");
        w.append("csca_sig_s = ").append(CmsProbe.bytes(Witness.toBE(rs[1], clen))).append("\n");
        w.append("merkle_path = ").append(path).append("\n");
        w.append("merkle_dirs = 341\n");
        w.append("dsc_modulus = ").append(limbs(dscN)).append("\n");
        w.append("dsc_modulus_off = ").append(Witness.indexOf(tbs, Witness.be256(dscN))).append("\n");
        java.nio.file.Files.writeString(java.nio.file.Path.of(out), w.toString());
        System.out.println(curve + " CSCA (" + (clen * 8) + "-bit) -> RSA-" + dscN.bitLength()
                + " DSC, TBS " + tbs.length + "B, clen=" + clen + " -> wrote " + out);
    }

    static String limbs(BigInteger x) {
        BigInteger mask = BigInteger.ONE.shiftLeft(120).subtract(BigInteger.ONE);
        StringBuilder s = new StringBuilder("[");
        for (int i = 0; i < 18; i++) { if (i > 0) s.append(", "); s.append("\"0x").append(x.shiftRight(120 * i).and(mask).toString(16)).append("\""); }
        return s.append("]").toString();
    }
    private EcEnrollProbe() {}
}
