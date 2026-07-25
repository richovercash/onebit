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

/** Amortized (Tier A) mDL enrollment probe: build a synthetic ISO 18013-5 mDL,
 *  run it through Mdl.verify (real mdoc passive auth), derive the credential
 *  fields (dob, expiry, doc_hash), and emit the commit_fields witness. The
 *  resulting C is what present_amortized reopens — so an mDL credential presents
 *  through the unchanged presentation circuit. Emits dob/expiry/doc_hash/k/salt
 *  to a sidecar too, so the present step can be assembled after commit runs. */
public final class MdlEnrollProbe {
    static KeyPair dsKeys;

    public static void main(String[] args) throws Exception {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
        String dir = System.getProperty("dir", ".");

        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair iacaKeys = g.generateKeyPair();
        dsKeys = g.generateKeyPair();
        X509Certificate iaca = cert("CN=Demo IACA,C=US", "CN=Demo IACA,C=US", iacaKeys.getPublic(), iacaKeys.getPrivate());
        X509Certificate ds = cert("CN=Demo IACA,C=US", "CN=Demo DS,C=US", dsKeys.getPublic(), iacaKeys.getPrivate());
        byte[] mdoc = mdoc(ds, "1980-01-01", "2030-01-01");

        // Real mdoc passive auth (COSE verify + IACA chain + digest binding).
        Mdl.MdlData d = Mdl.verify(mdoc, List.of(iaca));

        BigInteger P = new BigInteger(
                "21888242871839275222246405745257275088548364400416034343698204186575808495617");
        // doc_hash: a deterministic per-document field from the MSO (mDL's identity
        // anchor). Only needs to be stable + reproduced at presentation.
        BigInteger docHash = new BigInteger(1, MessageDigest.getInstance("SHA-256").digest(d.msoBytes)).mod(P);
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        BigInteger k = new BigInteger(250, rnd), salt = new BigInteger(250, rnd);

        String toml = "dob = " + d.dob + "\nexpiry = " + d.expiry
                + "\ndoc_hash = \"0x" + docHash.toString(16) + "\"\nk = \"" + k + "\"\nsalt = \"" + salt + "\"\n";
        java.nio.file.Files.writeString(java.nio.file.Path.of(dir, "Prover.toml"), toml);
        // sidecar for the present_amortized step (decimal-friendly)
        java.nio.file.Files.writeString(java.nio.file.Path.of(dir, "fields.txt"),
                d.dob + "\n" + d.expiry + "\n" + docHash + "\n" + k + "\n" + salt + "\n");
        System.out.println("mDL verified: dob=" + d.dob + " expiry=" + d.expiry
                + " | wrote commit_fields witness (doc_hash from " + d.msoBytes.length + "B MSO)");
    }

    static X509Certificate cert(String issuer, String subject, PublicKey pub, PrivateKey signWith) throws Exception {
        long now = System.currentTimeMillis();
        return new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(new X500Name(issuer), BigInteger.valueOf(System.nanoTime()),
                        new Date(now - 86400000L), new Date(now + 3650L * 86400000L),
                        new X500Name(subject), pub)
                        .build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(signWith)));
    }

    static byte[] itemMap(int id, String eid, byte[] value) {
        byte[] salt = new byte[16];
        for (int i = 0; i < 16; i++) salt[i] = (byte) (id * 7 + i);
        return Cbor.map(Cbor.tstr("digestID"), Cbor.uint(id), Cbor.tstr("random"), Cbor.bstr(salt),
                Cbor.tstr("elementIdentifier"), Cbor.tstr(eid), Cbor.tstr("elementValue"), value);
    }

    static byte[] mdoc(X509Certificate ds, String birth, String expiry) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] dobItem = itemMap(1, "birth_date", Cbor.tag(1004, Cbor.tstr(birth)));
        byte[] expItem = itemMap(2, "expiry_date", Cbor.tag(1004, Cbor.tstr(expiry)));
        byte[] dobTagged = Cbor.tag(24, Cbor.bstr(dobItem));
        byte[] expTagged = Cbor.tag(24, Cbor.bstr(expItem));
        byte[] valueDigests = Cbor.map(Cbor.tstr(Mdl.NS),
                Cbor.map(Cbor.uint(1), Cbor.bstr(sha.digest(dobTagged)), Cbor.uint(2), Cbor.bstr(sha.digest(expTagged))));
        byte[] mso = Cbor.map(
                Cbor.tstr("version"), Cbor.tstr("1.0"),
                Cbor.tstr("digestAlgorithm"), Cbor.tstr("SHA-256"),
                Cbor.tstr("valueDigests"), valueDigests,
                Cbor.tstr("docType"), Cbor.tstr("org.iso.18013.5.1.mDL"),
                Cbor.tstr("validityInfo"), Cbor.map(Cbor.tstr("signed"), Cbor.tag(0, Cbor.tstr("2026-01-01T00:00:00Z")),
                        Cbor.tstr("validUntil"), Cbor.tag(0, Cbor.tstr("2030-01-01T00:00:00Z"))));
        byte[] protectedHdr = Cbor.map(Cbor.uint(1), Cbor.head(1, 6));
        byte[] payloadInner = Cbor.tag(24, Cbor.bstr(mso));
        byte[] sigStruct = Cbor.array(Cbor.tstr("Signature1"), Cbor.bstr(protectedHdr), Cbor.bstr(new byte[0]), Cbor.bstr(payloadInner));
        Signature s = Signature.getInstance("SHA256withECDSA", "BC");
        s.initSign(dsKeys.getPrivate());
        s.update(sigStruct);
        byte[] rs = derToRs(s.sign());
        byte[] cose = Cbor.array(Cbor.bstr(protectedHdr), Cbor.map(Cbor.uint(33), Cbor.bstr(ds.getEncoded())),
                Cbor.bstr(payloadInner), Cbor.bstr(rs));
        return Cbor.map(Cbor.tstr("nameSpaces"), Cbor.map(Cbor.tstr(Mdl.NS), Cbor.array(dobTagged, expTagged)),
                Cbor.tstr("issuerAuth"), cose);
    }

    static byte[] derToRs(byte[] der) {
        ASN1Sequence seq = ASN1Sequence.getInstance(der);
        BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue(), s = ((ASN1Integer) seq.getObjectAt(1)).getValue();
        byte[] out = new byte[64];
        System.arraycopy(Witness.toBE(r, 32), 0, out, 0, 32);
        System.arraycopy(Witness.toBE(s, 32), 0, out, 32, 32);
        return out;
    }

    private MdlEnrollProbe() {}
}
