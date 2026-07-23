package onebit.core;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import net.sf.scuba.data.Gender;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.MRZInfo;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/** Witness.enrollRouted picks the right enroll variant per CSCA algorithm and
 *  assembles a witness of the exact shape that circuit expects. A CSCA of each
 *  type signs an RSA-2048 DSC; a stub tree supplies the (dummy) Merkle path so
 *  we exercise classification + assembly without needing the published root. */
public class EnrollRouteTest {

    static byte[] dg1;

    @BeforeClass
    public static void mrz() throws Exception {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
        dg1 = new DG1File(new MRZInfo("P", "UTO", "DOE", "JOHN", "123456789", "UTO",
                "800101", Gender.MALE, "301231", "")).getEncoded();
    }

    static X509Certificate cert(String issuer, String subject, PublicKey pub,
                                PrivateKey signWith, String sigAlg) throws Exception {
        long now = System.currentTimeMillis();
        return new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(new X500Name(issuer), BigInteger.valueOf(System.nanoTime()),
                        new Date(now - 86400000L), new Date(now + 10L * 365 * 86400000L),
                        new X500Name(subject), pub)
                        .build(new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(signWith)));
    }

    /** CSCA of the given type -> RSA-2048 DSC -> SOD; returns {csca, sodBytes}. */
    static Object[] chain(String cscaSpec, String cscaSigAlg) throws Exception {
        KeyPair cscaKeys;
        if (cscaSpec.startsWith("RSA")) {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(Integer.parseInt(cscaSpec.substring(3)));
            cscaKeys = g.generateKeyPair();
        } else {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
            g.initialize(new ECGenParameterSpec(cscaSpec));
            cscaKeys = g.generateKeyPair();
        }
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair dscKeys = rsa.generateKeyPair();

        X509Certificate csca = cert("CN=CSCA,C=UT", "CN=CSCA,C=UT", cscaKeys.getPublic(), cscaKeys.getPrivate(), cscaSigAlg);
        X509Certificate dsc = cert("CN=CSCA,C=UT", "CN=DSC,C=UT", dscKeys.getPublic(), cscaKeys.getPrivate(), cscaSigAlg);

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] sod = new SODFile("SHA-256", "SHA256withRSA",
                Map.of(1, sha.digest(dg1), 2, sha.digest(new byte[]{2})), dscKeys.getPrivate(), dsc).getEncoded();
        return new Object[]{csca, sod};
    }

    /** Stub tree JSON: maps the CSCA's SPKI-sha256 to a dummy depth-10 path. */
    static Function<String, String> stubTree(X509Certificate csca) throws Exception {
        String spki = Witness.hex(MessageDigest.getInstance("SHA-256").digest(csca.getPublicKey().getEncoded()));
        StringBuilder path = new StringBuilder("[");
        for (int i = 0; i < 10; i++) path.append(i > 0 ? "," : "").append("\"0x").append(i + 1).append("\"");
        path.append("]");
        String json = "{\"paths\":{\"" + spki + "\":{\"dirs\":5,\"path\":" + path + "}}}";
        return alg -> json;
    }

    void check(String cscaSpec, String sigAlg, String wantAlg, String wantCircuit, int wantSize) throws Exception {
        Object[] c = chain(cscaSpec, sigAlg);
        X509Certificate csca = (X509Certificate) c[0];
        Witness.EnrollPlan plan = Witness.enrollRouted(dg1, (byte[]) c[1], List.of(csca), stubTree(csca));
        assertEquals(wantAlg, plan.alg);
        assertEquals("zk/" + wantCircuit, plan.circuitAsset);
        assertEquals("zk/cscatree_" + wantAlg + ".json", plan.treeAsset);
        assertEquals(wantSize, plan.witness.size());
    }

    @Test public void rsa4096()      throws Exception { check("RSA4096", "SHA256withRSA",   "rsa4096",      "enroll.json",         2184); }
    @Test public void rsa6144()      throws Exception { check("RSA6144", "SHA256withRSA",   "rsa6144",      "enroll_rsa6144.json", 2235); }
    @Test public void brainpool256() throws Exception { check("brainpoolP256r1", "SHA256withECDSA", "brainpool256", "enroll_ecdsa.json", 2207); }
    @Test public void p384()         throws Exception { check("secp384r1", "SHA384withECDSA", "p384",         "enroll_p384.json",    2271); }

    @Test public void unsupportedCurveReturnsNull() throws Exception {
        Object[] c = chain("secp521r1", "SHA512withECDSA");
        X509Certificate csca = (X509Certificate) c[0];
        assertEquals(null, Witness.enrollRouted(dg1, (byte[]) c[1], List.of(csca), stubTree(csca)));
    }
}
