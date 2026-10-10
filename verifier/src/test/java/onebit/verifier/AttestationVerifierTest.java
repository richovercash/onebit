// SPDX-License-Identifier: AGPL-3.0-only
package onebit.verifier;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/** Synthetic attestation chain exercising the verifier policy paths. */
public class AttestationVerifierTest {

    static final byte[] NONCE = "test-nonce".getBytes();
    static final byte[] BOOT_KEY = new byte[32];

    static KeyPair rootKeys, leafKeys;
    static X509Certificate root;

    @BeforeClass
    public static void keys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        rootKeys = kpg.generateKeyPair();
        leafKeys = kpg.generateKeyPair();
        root = cert("CN=Fake Root", "CN=Fake Root", rootKeys, rootKeys, null);
    }

    /** builds attestation extension: version, secLevel, kmVersion, kmSecLevel,
     *  challenge, uniqueId, swEnforced, hwEnforced */
    static byte[] attExt(byte[] challenge, int patchLevel, boolean noAuth,
                         int bootState, boolean locked) throws Exception {
        return attExt(challenge, patchLevel, noAuth, bootState, locked, 0, "onebit.wallet");
    }

    static byte[] attExt(byte[] challenge, int patchLevel, boolean noAuth, int bootState,
                         boolean locked, int origin, String pkg) throws Exception {
        ASN1EncodableVector hw = new ASN1EncodableVector();
        hw.add(new DERTaggedObject(true, 1, new DERSet(new ASN1Integer(2)))); // purpose SIGN
        if (noAuth) hw.add(new DERTaggedObject(true, 503, DERNull.INSTANCE));
        hw.add(new DERTaggedObject(true, 704, new DERSequence(new ASN1Encodable[] {
                new DEROctetString(BOOT_KEY), ASN1Boolean.getInstance(locked),
                new ASN1Enumerated(bootState), new DEROctetString(new byte[32])})));
        hw.add(new DERTaggedObject(true, 702, new ASN1Integer(origin)));     // GENERATED
        hw.add(new DERTaggedObject(true, 706, new ASN1Integer(patchLevel)));
        ASN1EncodableVector att = new ASN1EncodableVector();
        att.add(new ASN1Integer(300));           // attestationVersion
        att.add(new ASN1Enumerated(1));          // TEE
        att.add(new ASN1Integer(300));
        att.add(new ASN1Enumerated(1));
        att.add(new DEROctetString(challenge));
        att.add(new DEROctetString(new byte[0]));
        ASN1EncodableVector sw = new ASN1EncodableVector();
        if (pkg != null) {                       // attestationApplicationId
            DERSequence info = new DERSequence(new ASN1Encodable[] {
                    new DEROctetString(pkg.getBytes()), new ASN1Integer(1)});
            DERSequence appId = new DERSequence(new ASN1Encodable[] {
                    new DERSet(info), new DERSet(new DEROctetString(new byte[32]))});
            sw.add(new DERTaggedObject(true, 709, new DEROctetString(appId.getEncoded())));
        }
        att.add(new DERSequence(sw));            // softwareEnforced
        att.add(new DERSequence(hw));
        return new DERSequence(att).getEncoded();
    }

    static X509Certificate cert(String issuer, String subject, KeyPair subj, KeyPair signer,
                                byte[] ext) throws Exception {
        return cert(issuer, subject, subj, signer, ext, issuer.equals(subject));
    }

    static X509Certificate cert(String issuer, String subject, KeyPair subj, KeyPair signer,
                                byte[] ext, boolean ca) throws Exception {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name(issuer), BigInteger.valueOf(System.nanoTime()),
                new Date(System.currentTimeMillis() - 86400_000L),
                new Date(System.currentTimeMillis() + 86400_000L),
                new X500Name(subject), subj.getPublic());
        if (ext != null) {
            b.addExtension(new ASN1ObjectIdentifier(AttestationVerifier.ATTESTATION_OID),
                    false, ext);
        }
        if (ca) {
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            b.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        }
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate())));
    }

    static String allowlistJson() throws Exception {
        String spki = AttestationVerifier.sha256Hex(root.getPublicKey().getEncoded());
        return "{ \"roots\": [{\"name\":\"fake-root\",\"spki_sha256\":\"" + spki + "\"}],"
                + "\"verified_boot\": ["
                + "  {\"name\":\"stock-locked\",\"state\":\"Verified\"},"
                + "  {\"name\":\"grapheneos\",\"state\":\"SelfSigned\","
                + "   \"boot_key_sha256\":[\"" + "00".repeat(32) + "\"]}],"
                + "\"min_patch_level\": 202501, \"require_user_auth\": true,"
                + "\"attestation_apps\": [{\"package\":\"onebit.wallet\"}] }";
    }

    static List<X509Certificate> chain(byte[] ext) throws Exception {
        return List.of(cert("CN=Fake Root", "CN=Leaf", leafKeys, rootKeys, ext), root);
    }

    @Test
    public void verifiedStockPasses() throws Exception {
        var r = AttestationVerifier.verify(chain(attExt(NONCE, 202606, false, 0, true)),
                NONCE, AttestationVerifier.readAllowlist(allowlistJson()));
        assertEquals("Verified", r.bootState);
        assertTrue(r.userAuthRequired);
        assertEquals("stock-locked", r.bootPolicyName);
    }

    @Test
    public void grapheneSelfSignedWithAllowlistedKeyPasses() throws Exception {
        var r = AttestationVerifier.verify(chain(attExt(NONCE, 202606, false, 1, true)),
                NONCE, AttestationVerifier.readAllowlist(allowlistJson()));
        assertEquals("grapheneos", r.bootPolicyName);
    }

    @Test
    public void stalePatchFailsClosed() throws Exception {
        try {
            AttestationVerifier.verify(chain(attExt(NONCE, 202411, false, 0, true)),
                    NONCE, AttestationVerifier.readAllowlist(allowlistJson()));
            fail("stale patch accepted");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("patch level"));
        }
    }

    @Test
    public void wrongChallengeFails() throws Exception {
        try {
            AttestationVerifier.verify(chain(attExt("evil".getBytes(), 202606, false, 0, true)),
                    NONCE, AttestationVerifier.readAllowlist(allowlistJson()));
            fail("wrong challenge accepted");
        } catch (IllegalStateException expected) { }
    }

    @Test
    public void noAuthKeyFails() throws Exception {
        try {
            AttestationVerifier.verify(chain(attExt(NONCE, 202606, true, 0, true)),
                    NONCE, AttestationVerifier.readAllowlist(allowlistJson()));
            fail("noAuthRequired key accepted");
        } catch (IllegalStateException expected) { }
    }

    @Test
    public void unlockedBootloaderFails() throws Exception {
        try {
            AttestationVerifier.verify(chain(attExt(NONCE, 202606, false, 0, false)),
                    NONCE, AttestationVerifier.readAllowlist(allowlistJson()));
            fail("unlocked bootloader accepted");
        } catch (IllegalStateException expected) { }
    }

    @Test
    public void unknownRootFails() throws Exception {
        String badList = allowlistJson().replaceFirst("\"spki_sha256\":\"[0-9a-f]+\"",
                "\"spki_sha256\":\"" + "ab".repeat(32) + "\"");
        try {
            AttestationVerifier.verify(chain(attExt(NONCE, 202606, false, 0, true)),
                    NONCE, AttestationVerifier.readAllowlist(badList));
            fail("unknown root accepted");
        } catch (IllegalStateException expected) { }
    }

    static void assertRejected(List<X509Certificate> chain, String why) throws Exception {
        try {
            AttestationVerifier.verify(chain, NONCE, AttestationVerifier.readAllowlist(allowlistJson()));
            fail(why + " accepted");
        } catch (IllegalStateException | java.security.GeneralSecurityException expected) { }
    }

    /** The forged-leaf attack: an ordinary attested key (not a CA) signs a
     *  fabricated leaf claiming StrongBox/Verified for a software key. */
    @Test
    public void leafSignedByNonCaAttestedKeyFails() throws Exception {
        KeyPair kx = KeyPairGenerator.getInstance("EC").generateKeyPair();
        X509Certificate kxCert = cert("CN=Fake Root", "CN=Kx", kx, rootKeys,
                attExt(NONCE, 202606, false, 2, false), false);   // real but unlocked
        X509Certificate forged = cert("CN=Kx", "CN=Forged", leafKeys, kx,
                attExt(NONCE, 202612, false, 0, true));           // claims locked/Verified
        assertRejected(List.of(forged, kxCert, root), "leaf under non-CA issuer");
    }

    @Test
    public void attestationExtensionOnIntermediateFails() throws Exception {
        KeyPair ik = KeyPairGenerator.getInstance("EC").generateKeyPair();
        X509Certificate inter = cert("CN=Fake Root", "CN=Inter", ik, rootKeys,
                attExt(NONCE, 202606, false, 0, true), true);
        X509Certificate leaf = cert("CN=Inter", "CN=Leaf", leafKeys, ik,
                attExt(NONCE, 202606, false, 0, true));
        assertRejected(List.of(leaf, inter, root), "attestation ext on a CA");
    }

    @Test
    public void caLeafFails() throws Exception {
        assertRejected(List.of(cert("CN=Fake Root", "CN=Leaf", leafKeys, rootKeys,
                attExt(NONCE, 202606, false, 0, true), true), root), "CA leaf");
    }

    @Test
    public void importedKeyFails() throws Exception {
        assertRejected(chain(attExt(NONCE, 202606, false, 0, true, 2, "onebit.wallet")), "IMPORTED key");
    }

    @Test
    public void foreignAppKeyFails() throws Exception {
        assertRejected(chain(attExt(NONCE, 202606, false, 0, true, 0, "com.evil.app")), "foreign app");
        assertRejected(chain(attExt(NONCE, 202606, false, 0, true, 0, null)), "missing app id");
    }
}
