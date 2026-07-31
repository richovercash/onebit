// SPDX-License-Identifier: AGPL-3.0-only
package onebit.core;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import net.sf.scuba.data.Gender;
import net.sf.scuba.tlv.TLVInputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.MRZInfo;

/** Real ICAO SOD signed by a secp256r1 (NIST P-256) DSC (SHA256withECDSA);
 *  emits the mono_faithful_ecdsa witness. Same CMS structure as CmsProbe, ECDSA
 *  DSC. P-256 is the common ECDSA DSC and is signable by the default provider
 *  (jmrtd's SODFile signs without an explicit provider). */
public final class EcdsaCmsProbe {
    public static void main(String[] args) throws Exception {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());

        MRZInfo mrz = new MRZInfo("P", "UTO", "DOE", "JOHN", "123456789", "UTO",
                "800101", Gender.MALE, "301231", "");
        byte[] dg1 = new DG1File(mrz).getEncoded();

        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC", "BC");
        ec.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair k = ec.generateKeyPair();
        long now = System.currentTimeMillis();
        X509Certificate dsc = new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(new X500Name("CN=DSC,C=UT"), BigInteger.valueOf(now),
                        new Date(now - 86400000L), new Date(now + 10L * 365 * 86400000L),
                        new X500Name("CN=DSC,C=UT"), k.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(k.getPrivate())));

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        Map<Integer, byte[]> hashes = new LinkedHashMap<>();
        hashes.put(1, sha.digest(dg1));
        for (int dg : new int[]{2, 14, 15}) hashes.put(dg, sha.digest(new byte[]{(byte) dg}));
        SODFile sod = new SODFile("SHA-256", "SHA256withECDSA", hashes, k.getPrivate(), dsc);

        TLVInputStream tlv = new TLVInputStream(new ByteArrayInputStream(sod.getEncoded()));
        tlv.readTag();
        tlv.readLength();
        CMSSignedData cms = new CMSSignedData(tlv.readValue());
        SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();
        byte[] eContent = (byte[]) cms.getSignedContent().getContent();
        byte[] signedAttrs = signer.getEncodedSignedAttributes();
        byte[] dg1Hash = sha.digest(dg1);
        byte[] eContentHash = sha.digest(eContent);
        boolean sigOk = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(dsc));

        // ECDSA (r,s), normalized to low-s (secp256r1 order n) as the circuit requires.
        ASN1Sequence sig = ASN1Sequence.getInstance(signer.getSignature());
        BigInteger r = ((ASN1Integer) sig.getObjectAt(0)).getValue();
        BigInteger s = ((ASN1Integer) sig.getObjectAt(1)).getValue();
        BigInteger n = new BigInteger(
                "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
        if (s.compareTo(n.shiftRight(1)) > 0) s = n.subtract(s);
        ECPublicKey pk = (ECPublicKey) dsc.getPublicKey();
        BigInteger qx = pk.getW().getAffineX(), qy = pk.getW().getAffineY();

        String out =
              "dg1 = " + CmsProbe.bytes(dg1) + "\n"
            + "econtent = " + CmsProbe.bytes(CmsProbe.pad(eContent, 256)) + "\n"
            + "econtent_len = " + eContent.length + "\n"
            + "signed_attrs = " + CmsProbe.bytes(CmsProbe.pad(signedAttrs, 128)) + "\n"
            + "signed_attrs_len = " + signedAttrs.length + "\n"
            + "dg1_hash_off = " + CmsProbe.indexOf(eContent, dg1Hash) + "\n"
            + "econtent_hash_off = " + CmsProbe.indexOf(signedAttrs, eContentHash) + "\n"
            + "dsc_pubkey_x = " + CmsProbe.bytes(EcdsaProbe.to32(qx)) + "\n"
            + "dsc_pubkey_y = " + CmsProbe.bytes(EcdsaProbe.to32(qy)) + "\n"
            + "dsc_sig_r = " + CmsProbe.bytes(EcdsaProbe.to32(r)) + "\n"
            + "dsc_sig_s = " + CmsProbe.bytes(EcdsaProbe.to32(s)) + "\n"
            + "k = \"" + CmsProbe.randField() + "\"\n"
            + "ctx = \"" + CmsProbe.randField() + "\"\n"
            + "current = 20260721\n"
            + "age_min = 18\n";
        java.nio.file.Files.writeString(
                java.nio.file.Path.of(System.getProperty("out", "Prover.toml")), out);
        System.out.println("secp256r1 DSC signs SOD (SHA256withECDSA), sigOk=" + sigOk
                + ", eContent=" + eContent.length + "B signedAttrs=" + signedAttrs.length + "B -> wrote Prover.toml");
    }

    private EcdsaCmsProbe() {}
}