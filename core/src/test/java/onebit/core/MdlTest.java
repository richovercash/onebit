// SPDX-License-Identifier: AGPL-3.0-only
package onebit.core;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/** Synthetic ISO 18013-5 mDL (IACA -> DS -> COSE_Sign1 over MSO) built with the
 *  hand-rolled Cbor codec, verified + extracted by Mdl. Proves the mdoc passive
 *  auth path end to end on realistic-shaped data. */
public class MdlTest {

    static X509Certificate iaca, ds;
    static KeyPair dsKeys;

    @BeforeClass
    public static void chain() throws Exception {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair iacaKeys = g.generateKeyPair();
        dsKeys = g.generateKeyPair();
        iaca = cert("CN=Test IACA,C=US", "CN=Test IACA,C=US", iacaKeys.getPublic(), iacaKeys.getPrivate());
        ds = cert("CN=Test IACA,C=US", "CN=Test DS,C=US", dsKeys.getPublic(), iacaKeys.getPrivate());
    }

    static X509Certificate cert(String issuer, String subject, PublicKey pub, PrivateKey signWith) throws Exception {
        long now = System.currentTimeMillis();
        return new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(new X500Name(issuer), BigInteger.valueOf(System.nanoTime()),
                        new Date(now - 86400000L), new Date(now + 3650L * 86400000L),
                        new X500Name(subject), pub)
                        .build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(signWith)));
    }

    static byte[] item(int digestID, String id, byte[] value) {
        byte[] salt = new byte[16];
        for (int i = 0; i < 16; i++) salt[i] = (byte) (digestID * 7 + i);
        return Cbor.map(
                Cbor.tstr("digestID"), Cbor.uint(digestID),
                Cbor.tstr("random"), Cbor.bstr(salt),
                Cbor.tstr("elementIdentifier"), Cbor.tstr(id),
                Cbor.tstr("elementValue"), value);
    }

    /** Build a full IssuerSigned mdoc; `tamper` optionally corrupts a digest. */
    static byte[] mdoc(boolean tamper) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] dobItem = item(1, "birth_date", Cbor.tag(1004, Cbor.tstr("1980-01-01")));
        byte[] expItem = item(2, "expiry_date", Cbor.tag(1004, Cbor.tstr("2030-01-01")));
        byte[] dobTagged = Cbor.tag(24, Cbor.bstr(dobItem));
        byte[] expTagged = Cbor.tag(24, Cbor.bstr(expItem));
        byte[] dobDig = sha.digest(dobTagged);
        if (tamper) dobDig[0] ^= 1;
        byte[] expDig = sha.digest(expTagged);

        byte[] valueDigests = Cbor.map(Cbor.tstr(Mdl.NS),
                Cbor.map(Cbor.uint(1), Cbor.bstr(dobDig), Cbor.uint(2), Cbor.bstr(expDig)));
        byte[] mso = Cbor.map(
                Cbor.tstr("version"), Cbor.tstr("1.0"),
                Cbor.tstr("digestAlgorithm"), Cbor.tstr("SHA-256"),
                Cbor.tstr("valueDigests"), valueDigests,
                Cbor.tstr("docType"), Cbor.tstr("org.iso.18013.5.1.mDL"),
                Cbor.tstr("validityInfo"), Cbor.map(
                        Cbor.tstr("signed"), Cbor.tag(0, Cbor.tstr("2026-01-01T00:00:00Z")),
                        Cbor.tstr("validUntil"), Cbor.tag(0, Cbor.tstr("2030-01-01T00:00:00Z"))));

        byte[] protectedHdr = Cbor.map(Cbor.uint(1), Cbor.head(1, 6));  // {1: -7} ES256
        byte[] payloadInner = Cbor.tag(24, Cbor.bstr(mso));            // MobileSecurityObjectBytes
        byte[] sigStruct = Cbor.array(Cbor.tstr("Signature1"), Cbor.bstr(protectedHdr),
                Cbor.bstr(new byte[0]), Cbor.bstr(payloadInner));
        Signature s = Signature.getInstance("SHA256withECDSA", "BC");
        s.initSign(dsKeys.getPrivate());
        s.update(sigStruct);
        byte[] rs = derToRs(s.sign(), 32);

        byte[] cose = Cbor.array(
                Cbor.bstr(protectedHdr),
                Cbor.map(Cbor.uint(33), Cbor.bstr(ds.getEncoded())),
                Cbor.bstr(payloadInner),
                Cbor.bstr(rs));
        return Cbor.map(
                Cbor.tstr("nameSpaces"), Cbor.map(Cbor.tstr(Mdl.NS), Cbor.array(dobTagged, expTagged)),
                Cbor.tstr("issuerAuth"), cose);
    }

    static byte[] derToRs(byte[] der, int n) {
        ASN1Sequence seq = ASN1Sequence.getInstance(der);
        BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
        BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getValue();
        byte[] out = new byte[2 * n];
        System.arraycopy(Witness.toBE(r, n), 0, out, 0, n);
        System.arraycopy(Witness.toBE(s, n), 0, out, n, n);
        return out;
    }

    @Test public void validMdlVerifiesAndExtracts() throws Exception {
        Mdl.MdlData d = Mdl.verify(mdoc(false), List.of(iaca));
        assertEquals(19800101, d.dob);
        assertEquals(20300101, d.expiry);
    }

    @Test public void tamperedDigestFails() throws Exception {
        try { Mdl.verify(mdoc(true), List.of(iaca)); fail("accepted tampered digest"); }
        catch (Mdl.MdlException expected) { }
    }

    // ---- holder-binding (deviceAuth) ----

    /** Full DeviceResponse: issuerSigned (with the deviceKey bound in the MSO) +
     *  deviceSigned carrying a DeviceSignature over `st`. `bindKey` chooses which key
     *  signs deviceAuth (wrong key => a bound-holder mismatch). `st` is the transcript
     *  the DEVICE signed over; the verifier is handed `stVerify` separately. */
    static byte[] deviceResponse(KeyPair devKeys, byte[] st, boolean includeDeviceSigned) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] dobItem = item(1, "birth_date", Cbor.tag(1004, Cbor.tstr("1980-01-01")));
        byte[] expItem = item(2, "expiry_date", Cbor.tag(1004, Cbor.tstr("2030-01-01")));
        byte[] dobTagged = Cbor.tag(24, Cbor.bstr(dobItem));
        byte[] expTagged = Cbor.tag(24, Cbor.bstr(expItem));
        byte[] valueDigests = Cbor.map(Cbor.tstr(Mdl.NS),
                Cbor.map(Cbor.uint(1), Cbor.bstr(sha.digest(dobTagged)),
                         Cbor.uint(2), Cbor.bstr(sha.digest(expTagged))));

        // COSE_Key EC2/P-256 for the device public key: {1:2, -1:1, -2:x, -3:y}.
        ECPublicKey dpk = (ECPublicKey) devKeys.getPublic();
        byte[] deviceKey = Cbor.map(
                Cbor.uint(1), Cbor.uint(2),
                Cbor.nint(-1), Cbor.uint(1),
                Cbor.nint(-2), Cbor.bstr(Witness.toBE(dpk.getW().getAffineX(), 32)),
                Cbor.nint(-3), Cbor.bstr(Witness.toBE(dpk.getW().getAffineY(), 32)));

        byte[] mso = Cbor.map(
                Cbor.tstr("version"), Cbor.tstr("1.0"),
                Cbor.tstr("digestAlgorithm"), Cbor.tstr("SHA-256"),
                Cbor.tstr("valueDigests"), valueDigests,
                Cbor.tstr("deviceKeyInfo"), Cbor.map(Cbor.tstr("deviceKey"), deviceKey),
                Cbor.tstr("docType"), Cbor.tstr("org.iso.18013.5.1.mDL"),
                Cbor.tstr("validityInfo"), Cbor.map(
                        Cbor.tstr("signed"), Cbor.tag(0, Cbor.tstr("2026-01-01T00:00:00Z")),
                        Cbor.tstr("validUntil"), Cbor.tag(0, Cbor.tstr("2030-01-01T00:00:00Z"))));

        byte[] protectedHdr = Cbor.map(Cbor.uint(1), Cbor.nint(-7));   // ES256
        byte[] payloadInner = Cbor.tag(24, Cbor.bstr(mso));
        byte[] issuerSig = signRs(dsKeys.getPrivate(), Cbor.array(Cbor.tstr("Signature1"),
                Cbor.bstr(protectedHdr), Cbor.bstr(new byte[0]), Cbor.bstr(payloadInner)));
        byte[] cose = Cbor.array(Cbor.bstr(protectedHdr),
                Cbor.map(Cbor.uint(33), Cbor.bstr(ds.getEncoded())),
                Cbor.bstr(payloadInner), Cbor.bstr(issuerSig));
        byte[] issuerSigned = Cbor.map(
                Cbor.tstr("nameSpaces"), Cbor.map(Cbor.tstr(Mdl.NS), Cbor.array(dobTagged, expTagged)),
                Cbor.tstr("issuerAuth"), cose);

        byte[][] docKV;
        if (includeDeviceSigned) {
            byte[] dnsBytes = Cbor.tag(24, Cbor.bstr(Cbor.map()));   // empty DeviceNameSpaces
            byte[] deviceAuthentication = Cbor.array(Cbor.tstr("DeviceAuthentication"), st,
                    Cbor.tstr("org.iso.18013.5.1.mDL"), dnsBytes);
            byte[] deviceAuthBytes = Cbor.tag(24, Cbor.bstr(deviceAuthentication));
            byte[] devSig = signRs(devKeys.getPrivate(), Cbor.array(Cbor.tstr("Signature1"),
                    Cbor.bstr(protectedHdr), Cbor.bstr(new byte[0]), Cbor.bstr(deviceAuthBytes)));
            byte[] deviceSignature = Cbor.array(Cbor.bstr(protectedHdr), Cbor.map(), Cbor.nul(), Cbor.bstr(devSig));
            byte[] deviceSigned = Cbor.map(
                    Cbor.tstr("nameSpaces"), dnsBytes,
                    Cbor.tstr("deviceAuth"), Cbor.map(Cbor.tstr("deviceSignature"), deviceSignature));
            docKV = new byte[][]{Cbor.tstr("docType"), Cbor.tstr("org.iso.18013.5.1.mDL"),
                    Cbor.tstr("issuerSigned"), issuerSigned, Cbor.tstr("deviceSigned"), deviceSigned};
        } else {
            docKV = new byte[][]{Cbor.tstr("docType"), Cbor.tstr("org.iso.18013.5.1.mDL"),
                    Cbor.tstr("issuerSigned"), issuerSigned};
        }
        return Cbor.map(Cbor.tstr("documents"), Cbor.array(Cbor.map(docKV)));
    }

    static byte[] signRs(PrivateKey key, byte[] msg) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA", "BC");
        s.initSign(key);
        s.update(msg);
        return derToRs(s.sign(), 32);
    }

    static KeyPair p256() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    static final byte[] ST = Cbor.array(Cbor.nul(), Cbor.nul(),
            Cbor.array(Cbor.bstr(new byte[]{1, 2, 3}), Cbor.bstr(new byte[]{4, 5, 6}), Cbor.tstr("nonce-xyz")));

    @Test public void deviceAuthBindsHolder() throws Exception {
        KeyPair dev = p256();
        Mdl.MdlData d = Mdl.verifyDeviceResponse(deviceResponse(dev, ST, true), Mdl.anchorOf(List.of(iaca)), ST);
        assertEquals(19800101, d.dob);   // issuer data still extracted
    }

    @Test public void replayedTranscriptFails() throws Exception {
        // device signed ST, but the verifier is handed a DIFFERENT session transcript
        byte[] other = Cbor.array(Cbor.nul(), Cbor.nul(), Cbor.array(Cbor.tstr("attacker-session")));
        try { Mdl.verifyDeviceResponse(deviceResponse(p256(), ST, true), Mdl.anchorOf(List.of(iaca)), other);
            fail("accepted response bound to a different session"); }
        catch (Mdl.MdlException expected) { }
    }

    @Test public void missingDeviceAuthFails() throws Exception {
        // issuerSigned replay: authentic issuer data, no holder binding => must reject
        try { Mdl.verifyDeviceResponse(deviceResponse(p256(), ST, false), Mdl.anchorOf(List.of(iaca)), ST);
            fail("accepted DeviceResponse with no deviceAuth"); }
        catch (Mdl.MdlException expected) { }
    }

    @Test public void tamperedDeviceSignatureFails() throws Exception {
        byte[] dr = deviceResponse(p256(), ST, true);
        dr[dr.length - 1] ^= 1;   // corrupt the trailing DeviceSignature bytes
        try { Mdl.verifyDeviceResponse(dr, Mdl.anchorOf(List.of(iaca)), ST);
            fail("accepted tampered device signature"); }
        catch (Mdl.MdlException expected) { }
    }

    @Test public void untrustedIacaFails() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair other = g.generateKeyPair();
        X509Certificate stranger = cert("CN=Other,C=US", "CN=Other,C=US", other.getPublic(), other.getPrivate());
        try { Mdl.verify(mdoc(false), List.of(stranger)); fail("accepted untrusted IACA"); }
        catch (Mdl.MdlException expected) { }
    }

    /** dob=0 ("not disclosed") passes every age predicate; enrollment must refuse it. */
    @Test public void undisclosedDobIsRefused() throws Exception {
        Mdl.MdlData d = Mdl.verify(mdoc(false), List.of(iaca));
        d.requireDob();                   // disclosed in the fixture
        d.dob = 0;
        try { d.requireDob(); fail("accepted an undisclosed birth_date"); }
        catch (Mdl.MdlException expected) { }
    }
}
