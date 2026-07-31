// SPDX-License-Identifier: AGPL-3.0-only
package onebit.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Test;

/** The cross-validated IACA-root bootstrap: recover the root public key from a leaf's
 *  signature and confirm it uniquely re-appears across a second, independent leaf.
 *  Mirrors production: two CA certs (live DS + published VC-Signer) signed by an
 *  unpublished root, from which we recover the root key. */
public class MdlKeyRecoveryTest {

    static KeyPair ec() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    static X509Certificate leaf(String cn, KeyPair subject, KeyPair rootIssuer, String issuerCn) throws Exception {
        long now = 1_700_000_000_000L;
        X500Name subj = new X500Name("CN=" + cn), iss = new X500Name("CN=" + issuerCn);
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                iss, BigInteger.valueOf(now + cn.hashCode()), new Date(now), new Date(now + 3_000_000_000L),
                subj, subject.getPublic());
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(rootIssuer.getPrivate())));
    }

    @Test public void recoversAndCrossValidatesRootKey() throws Exception {
        KeyPair root = ec(), dsKp = ec(), vcKp = ec();
        X509Certificate ds = leaf("DMV mdoc Signer", dsKp, root, "DMV IACA Root");
        X509Certificate vc = leaf("DMV VC Signer",  vcKp, root, "DMV IACA Root");

        // recovery yields the true root key among <=2 candidates
        boolean found = false;
        byte[] want = root.getPublic().getEncoded();
        for (PublicKey k : Mdl.recoverEcPublicKeys(ds))
            if (Arrays.equals(k.getEncoded(), want)) found = true;
        assertTrue("root key must be among recovered candidates", found);

        // cross-validation returns exactly the root key
        PublicKey boot = Mdl.crossValidatedRootKey(ds, Arrays.asList(vc));
        assertEquals("bootstrapped key equals real root key",
                new BigInteger(1, root.getPublic().getEncoded()), new BigInteger(1, boot.getEncoded()));
    }

    @Test public void rejectsUnrelatedIndependentCert() throws Exception {
        KeyPair root = ec(), dsKp = ec(), otherRoot = ec(), otherKp = ec();
        X509Certificate ds = leaf("DMV mdoc Signer", dsKp, root, "DMV IACA Root");
        X509Certificate unrelated = leaf("Someone Else", otherKp, otherRoot, "DMV IACA Root"); // same DN, different key
        try {
            Mdl.crossValidatedRootKey(ds, Arrays.asList(unrelated));
            fail("must not cross-validate against a cert signed by a different key");
        } catch (Mdl.MdlException expected) { }
    }
}