// SPDX-License-Identifier: AGPL-3.0-only
package onebit.core;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.LinkedHashMap;
import java.util.Map;

import net.sf.scuba.data.Gender;
import net.sf.scuba.tlv.TLVInputStream;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.MRZInfo;

/** Real ICAO SOD whose signedAttrs are re-signed with RSA-PSS (RSASSA-PSS,
 *  MGF1-SHA256, 32-byte salt); emits the mono_faithful_pss witness. The CMS
 *  structure (eContent, signedAttrs) is the standard jmrtd one; only the DSC
 *  signature scheme is PSS instead of PKCS#1 v1.5. */
public final class PssProbe {
    public static void main(String[] args) throws Exception {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());

        MRZInfo mrz = new MRZInfo("P", "UTO", "DOE", "JOHN", "123456789", "UTO",
                "800101", Gender.MALE, "301231", "");
        byte[] dg1 = new DG1File(mrz).getEncoded();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair k = kpg.generateKeyPair();
        X509Certificate dsc = SodSizes.selfSigned(k);

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        Map<Integer, byte[]> hashes = new LinkedHashMap<>();
        hashes.put(1, sha.digest(dg1));
        for (int dg : new int[]{2, 14, 15}) hashes.put(dg, sha.digest(new byte[]{(byte) dg}));
        SODFile sod = new SODFile("SHA-256", "SHA256withRSA", hashes, k.getPrivate(), dsc);

        TLVInputStream tlv = new TLVInputStream(new java.io.ByteArrayInputStream(sod.getEncoded()));
        tlv.readTag();
        tlv.readLength();
        CMSSignedData cms = new CMSSignedData(tlv.readValue());
        SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();
        byte[] eContent = (byte[]) cms.getSignedContent().getContent();
        byte[] signedAttrs = signer.getEncodedSignedAttributes();
        byte[] dg1Hash = sha.digest(dg1);
        byte[] eContentHash = sha.digest(eContent);

        // Re-sign signedAttrs with RSA-PSS (salt = hash length = 32). verify_sha256_pss
        // in-circuit uses the same salt length.
        Signature pss = Signature.getInstance("RSASSA-PSS", "BC");
        pss.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        pss.initSign(k.getPrivate());
        pss.update(signedAttrs);
        byte[] sigBytes = pss.sign();
        // sanity: verify it back
        Signature v = Signature.getInstance("RSASSA-PSS", "BC");
        v.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        v.initVerify(dsc.getPublicKey());
        v.update(signedAttrs);
        boolean pssOk = v.verify(sigBytes);

        BigInteger n = ((java.security.interfaces.RSAPublicKey) dsc.getPublicKey()).getModulus();
        String out =
              "dg1 = " + CmsProbe.bytes(dg1) + "\n"
            + "econtent = " + CmsProbe.bytes(CmsProbe.pad(eContent, 256)) + "\n"
            + "econtent_len = " + eContent.length + "\n"
            + "signed_attrs = " + CmsProbe.bytes(CmsProbe.pad(signedAttrs, 128)) + "\n"
            + "signed_attrs_len = " + signedAttrs.length + "\n"
            + "dg1_hash_off = " + CmsProbe.indexOf(eContent, dg1Hash) + "\n"
            + "econtent_hash_off = " + CmsProbe.indexOf(signedAttrs, eContentHash) + "\n"
            + "sig = " + CmsProbe.limbs(new BigInteger(1, sigBytes)) + "\n"
            + "modulus = " + CmsProbe.limbs(n) + "\n"
            + "redc = " + CmsProbe.limbs(BigInteger.ONE.shiftLeft(2 * 2048 + 6).divide(n)) + "\n"
            + "k = \"" + CmsProbe.randField() + "\"\n"
            + "ctx = \"" + CmsProbe.randField() + "\"\n"
            + "current = 20260721\n"
            + "age_min = 18\n";
        java.nio.file.Files.writeString(
                java.nio.file.Path.of(System.getProperty("out", "Prover.toml")), out);
        System.out.println("RSA-2048 PSS DSC signs SOD, pssOk=" + pssOk
                + ", eContent=" + eContent.length + "B signedAttrs=" + signedAttrs.length + "B -> wrote Prover.toml");
    }

    private PssProbe() {}
}