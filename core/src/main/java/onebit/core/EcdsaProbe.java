package onebit.core;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Synthetic brainpoolP256r1 CSCA -> RSA-2048 DSC chain; emits the ECDSA enroll
 *  witness. Mirrors the extraction the wallet does on a real EU document. */
public final class EcdsaProbe {
    public static void main(String[] args) throws Exception {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
        String outDir = System.getProperty("dir", ".");

        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC", "BC");
        ec.initialize(new ECGenParameterSpec("brainpoolP256r1"));
        KeyPair csca = ec.generateKeyPair();
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair dsc = rsa.generateKeyPair();

        long now = System.currentTimeMillis();
        X509Certificate dscCert = new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(new X500Name("CN=CSCA,C=DE"), BigInteger.valueOf(now),
                        new Date(now - 86400000L), new Date(now + 10L * 365 * 86400000L),
                        new X500Name("CN=DSC,C=DE"), dsc.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(csca.getPrivate())));

        byte[] tbs = dscCert.getTBSCertificate();
        ASN1Sequence sig = ASN1Sequence.getInstance(dscCert.getSignature());
        BigInteger r = ((ASN1Integer) sig.getObjectAt(0)).getValue();
        BigInteger s = ((ASN1Integer) sig.getObjectAt(1)).getValue();
        ECPublicKey pk = (ECPublicKey) csca.getPublic();
        BigInteger qx = pk.getW().getAffineX(), qy = pk.getW().getAffineY();
        BigInteger dscN = ((java.security.interfaces.RSAPublicKey) dsc.getPublic()).getModulus();

        BigInteger P = new BigInteger(
                "21888242871839275222246405745257275088548364400416034343698204186575808495617");
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        StringBuilder path = new StringBuilder("[");
        for (int i = 0; i < 10; i++) { if (i > 0) path.append(", "); path.append("\"").append(new BigInteger(250, rnd).mod(P)).append("\""); }
        path.append("]");

        StringBuilder out = new StringBuilder();
        out.append("dsc_tbs = ").append(bytes(pad(tbs, 2048))).append("\n");
        out.append("dsc_tbs_len = ").append(tbs.length).append("\n");
        out.append("csca_pubkey_x = ").append(bytes(to32(qx))).append("\n");
        out.append("csca_pubkey_y = ").append(bytes(to32(qy))).append("\n");
        out.append("csca_sig_r = ").append(bytes(to32(r))).append("\n");
        out.append("csca_sig_s = ").append(bytes(to32(s))).append("\n");
        out.append("merkle_path = ").append(path).append("\n");
        out.append("merkle_dirs = 349525\n");
        out.append("dsc_modulus = ").append(limbs(dscN, 18)).append("\n");
        java.nio.file.Files.writeString(java.nio.file.Path.of(outDir, "enroll_ecdsa.toml"), out.toString());
        System.out.println("brainpoolP256r1 CSCA -> RSA-" + dscN.bitLength() + " DSC, TBS " + tbs.length + "B -> wrote witness");
    }

    static byte[] to32(BigInteger x) {
        byte[] b = x.toByteArray();
        byte[] o = new byte[32];
        int len = Math.min(b.length, 32);
        System.arraycopy(b, b.length - len, o, 32 - len, len);
        return o;
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
    private EcdsaProbe() {}
}
