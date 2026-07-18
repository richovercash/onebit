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
        ASN1EncodableVector hw = new ASN1EncodableVector();
        hw.add(new DERTaggedObject(true, 1, new DERSet(new ASN1Integer(2)))); // purpose SIGN
        if (noAuth) hw.add(new DERTaggedObject(true, 503, DERNull.INSTANCE));
        hw.add(new DERTaggedObject(true, 704, new DERSequence(new ASN1Encodable[] {
                new DEROctetString(BOOT_KEY), ASN1Boolean.getInstance(locked),
                new ASN1Enumerated(bootState), new DEROctetString(new byte[32])})));
        hw.add(new DERTaggedObject(true, 706, new ASN1Integer(patchLevel)));
        ASN1EncodableVector att = new ASN1EncodableVector();
        att.add(new ASN1Integer(300));           // attestationVersion
        att.add(new ASN1Enumerated(1));          // TEE
        att.add(new ASN1Integer(300));
        att.add(new ASN1Enumerated(1));
        att.add(new DEROctetString(challenge));
        att.add(new DEROctetString(new byte[0]));
        att.add(new DERSequence());              // softwareEnforced
        att.add(new DERSequence(hw));
        return new DERSequence(att).getEncoded();
    }

    static X509Certificate cert(String issuer, String subject, KeyPair subj, KeyPair signer,
                                byte[] ext) throws Exception {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name(issuer), BigInteger.valueOf(System.nanoTime()),
                new Date(System.currentTimeMillis() - 86400_000L),
                new Date(System.currentTimeMillis() + 86400_000L),
                new X500Name(subject), subj.getPublic());
        if (ext != null) {
            b.addExtension(new ASN1ObjectIdentifier(AttestationVerifier.ATTESTATION_OID),
                    false, ext);
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
                + "\"min_patch_level\": 202501, \"require_user_auth\": true }";
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
}
