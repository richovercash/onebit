package onebit.core;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import net.sf.scuba.data.Gender;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.MRZInfo;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/** Synthetic document chain: self-signed CSCA -> DSC -> SOD over DG1. */
public class PassiveAuthTest {

    static final LocalDate T = LocalDate.of(2026, 7, 11);

    static X509Certificate csca, dsc;
    static byte[] dg1Bytes, sodBytes;

    @BeforeClass
    public static void buildChain() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair cscaKeys = kpg.generateKeyPair();
        KeyPair dscKeys = kpg.generateKeyPair();

        csca = cert("CN=Test CSCA,C=UT", "CN=Test CSCA,C=UT", cscaKeys.getPublic(), cscaKeys.getPrivate());
        dsc = cert("CN=Test CSCA,C=UT", "CN=Test DSC,C=UT", dscKeys.getPublic(), cscaKeys.getPrivate());

        MRZInfo mrz = new MRZInfo("P", "UTO", "DOE", "JOHN", "123456789", "UTO",
                "800101", Gender.MALE, "301231", "");
        dg1Bytes = new DG1File(mrz).getEncoded();

        byte[] dg1Hash = MessageDigest.getInstance("SHA-256").digest(dg1Bytes);
        // SOD must list >=2 DGs; DG2 (photo) is present on real chips but never read by us
        byte[] dg2Hash = MessageDigest.getInstance("SHA-256").digest(new byte[] {2});
        sodBytes = new SODFile("SHA-256", "SHA256withRSA",
                Map.of(1, dg1Hash, 2, dg2Hash), dscKeys.getPrivate(), dsc).getEncoded();
    }

    static X509Certificate cert(String issuer, String subject,
                                java.security.PublicKey pub, PrivateKey signWith) throws Exception {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name(issuer), BigInteger.valueOf(System.nanoTime()),
                Date.from(T.minusYears(1).atStartOfDay(java.time.ZoneOffset.UTC).toInstant()),
                Date.from(T.plusYears(10).atStartOfDay(java.time.ZoneOffset.UTC).toInstant()),
                new X500Name(subject), pub);
        return new JcaX509CertificateConverter()
                .getCertificate(b.build(new JcaContentSignerBuilder("SHA256withRSA").build(signWith)));
    }

    static List<X509Certificate> masterList() { return Collections.singletonList(csca); }

    @Test
    public void validDocumentVerifies() throws Exception {
        PassiveAuth.MrzData d = PassiveAuth.verify(dg1Bytes, sodBytes, masterList());
        assertEquals("800101", d.dateOfBirth);
        assertEquals("301231", d.dateOfExpiry);
        assertTrue(Mrz.ageGte(d.dateOfBirth, T, 18));
        assertTrue(Mrz.notExpired(d.dateOfExpiry, T));
    }

    @Test
    public void tamperedDg1Fails() {
        byte[] tampered = dg1Bytes.clone();
        tampered[tampered.length / 2] ^= 1;
        try {
            PassiveAuth.verify(tampered, sodBytes, masterList());
            fail("tampered DG1 accepted");
        } catch (PassiveAuth.PAException expected) { }
    }

    @Test
    public void tamperedSodFails() {
        // flip a bit near the end (inside the CMS signature bytes)
        byte[] tampered = sodBytes.clone();
        tampered[tampered.length - 10] ^= 1;
        try {
            PassiveAuth.verify(dg1Bytes, tampered, masterList());
            fail("tampered SOD accepted");
        } catch (PassiveAuth.PAException expected) { }
    }

    @Test
    public void unknownCscaFails() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair other = kpg.generateKeyPair();
        X509Certificate rogue = cert("CN=Rogue CSCA,C=XX", "CN=Rogue CSCA,C=XX",
                other.getPublic(), other.getPrivate());
        try {
            PassiveAuth.verify(dg1Bytes, sodBytes, Collections.singletonList(rogue));
            fail("unchained DSC accepted");
        } catch (PassiveAuth.PAException expected) { }
    }

    // ---- century rule fixtures (threat table: wrong-century soundness bug) ----

    @Test
    public void centuryRule() {
        // T=2026 -> currentYY=26, threshold 36: YY>36 -> 19YY, else 20YY
        assertEquals(1999, Mrz.resolve("990101", T).getYear());
        assertEquals(1937, Mrz.resolve("370101", T).getYear());
        assertEquals(2036, Mrz.resolve("360101", T).getYear());
        assertEquals(2030, Mrz.resolve("300101", T).getYear());
    }

    @Test
    public void wrongCenturyDobDoesNotPassAgeCheck() {
        // YY=30 resolves to 2030 (future DOB): must NOT be treated as 1930 (age 96)
        assertFalse(Mrz.ageGte("300101", T, 18));
    }

    @Test
    public void ageBoundaryExact() {
        assertTrue(Mrz.ageGte("080711", T, 18));   // 18th birthday today -> pass
        assertFalse(Mrz.ageGte("080712", T, 18));  // tomorrow -> fail
    }

    @Test
    public void expiredDocumentFailsPredicate() {
        assertFalse(Mrz.notExpired("250101", T));
        assertTrue(Mrz.notExpired("270101", T));
    }
}
