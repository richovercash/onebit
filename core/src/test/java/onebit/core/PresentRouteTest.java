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
import java.util.Map;

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

/** Witness.extract tags the presentation circuit by DSC signature type and
 *  presentationWitness builds the matching shape. The ECDSA case previously
 *  threw (extract force-parsed an RSA modulus), so this also guards that fix. */
public class PresentRouteTest {

    static byte[] dg1;

    @BeforeClass
    public static void mrz() throws Exception {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
        dg1 = new DG1File(new MRZInfo("P", "UTO", "DOE", "JOHN", "123456789", "UTO",
                "800101", Gender.MALE, "301231", "")).getEncoded();
    }

    static X509Certificate self(PublicKey pub, PrivateKey priv, String sigAlg) throws Exception {
        long now = System.currentTimeMillis();
        return new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(new X500Name("CN=DSC,C=UT"), BigInteger.valueOf(System.nanoTime()),
                        new Date(now - 86400000L), new Date(now + 10L * 365 * 86400000L),
                        new X500Name("CN=DSC,C=UT"), pub)
                        .build(new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(priv)));
    }

    static byte[] sod(KeyPair dsc, String sigAlg) throws Exception {
        X509Certificate cert = self(dsc.getPublic(), dsc.getPrivate(), sigAlg);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        return new SODFile("SHA-256", sigAlg,
                Map.of(1, sha.digest(dg1), 2, sha.digest(new byte[]{2})), dsc.getPrivate(), cert).getEncoded();
    }

    static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); g.initialize(2048); return g.generateKeyPair();
    }
    static KeyPair ec(String curve) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC"); g.initialize(new ECGenParameterSpec(curve)); return g.generateKeyPair();
    }

    @Test public void rsaPkcs1() throws Exception {
        Witness.Doc d = Witness.extract(dg1, sod(rsa(), "SHA256withRSA"));
        assertEquals("mono_faithful", d.presCircuit);
        assertEquals(535, Witness.presentationWitness(d, 256, 128).size());
    }

    @Test public void ecdsaP256() throws Exception {
        Witness.Doc d = Witness.extract(dg1, sod(ec("secp256r1"), "SHA256withECDSA"));
        assertEquals("mono_faithful_ecdsa", d.presCircuit);
        assertEquals(609, Witness.presentationWitness(d, 256, 128).size());
    }

    @Test public void rsaPss() throws Exception {
        Witness.Doc d = Witness.extract(dg1, sod(rsa(), "SHA256withRSAandMGF1"));
        assertEquals("mono_faithful_pss", d.presCircuit);
        assertEquals(535, Witness.presentationWitness(d, 256, 128).size());
    }
}
