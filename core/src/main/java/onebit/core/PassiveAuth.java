// SPDX-License-Identifier: AGPL-3.0-only
package onebit.core;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Map;

import net.sf.scuba.tlv.TLVInputStream;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.icao.DG1File;

/**
 * Passive Authentication, SPEC §3.1 step 3, entirely local:
 *   1. hash(DG1) matches the DG1 entry in SOD's hash list
 *   2. SOD's CMS signature verifies under the embedded DSC
 *   3. DSC chains to a CSCA in the supplied master list
 *
 * Pure function over byte arrays + master list: no I/O path exists (V1).
 * Fail-closed: any defect throws PAException (V6).
 */
public final class PassiveAuth {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private PassiveAuth() {}

    /** MRZ facts extracted from a passively-authenticated DG1. */
    public static final class MrzData {
        public final String documentCode;
        public final String dateOfBirth;  // YYMMDD, resolve via Mrz
        public final String dateOfExpiry; // YYMMDD
        public String dscInfo = "";       // DSC alg + key size, for coverage matrix

        MrzData(String documentCode, String dateOfBirth, String dateOfExpiry) {
            this.documentCode = documentCode;
            this.dateOfBirth = dateOfBirth;
            this.dateOfExpiry = dateOfExpiry;
        }
    }

    /** DSC algorithm + key size string, for the P1.1 coverage matrix. */
    public static String dscInfo(X509Certificate dsc) {
        String alg = dsc.getSigAlgName();
        int bits = 0;
        try {
            java.security.PublicKey pk = dsc.getPublicKey();
            if (pk instanceof java.security.interfaces.RSAPublicKey) {
                bits = ((java.security.interfaces.RSAPublicKey) pk).getModulus().bitLength();
            } else if (pk instanceof java.security.interfaces.ECPublicKey) {
                bits = ((java.security.interfaces.ECPublicKey) pk).getParams().getCurve().getField().getFieldSize();
            }
        } catch (Exception ignored) { }
        return dsc.getPublicKey().getAlgorithm() + "-" + bits + " / " + alg;
    }

    public static final class PAException extends Exception {
        public PAException(String reason) { super(reason); }
        public PAException(String reason, Throwable cause) { super(reason, cause); }
    }

    /**
     * Verifies dg1Bytes against sodBytes and the CSCA master list.
     * Returns parsed MRZ data on success, throws PAException otherwise.
     */
    public static MrzData verify(byte[] dg1Bytes, byte[] sodBytes,
                                 Collection<X509Certificate> masterList) throws PAException {
        SODFile sod;
        X509Certificate dsc;
        try {
            sod = new SODFile(new ByteArrayInputStream(sodBytes));
            dsc = sod.getDocSigningCertificate();
        } catch (Exception e) {
            throw new PAException("SOD unparseable", e);
        }
        if (dsc == null) throw new PAException("SOD carries no DSC");

        // 1. DG1 hash ∈ SOD hash list
        try {
            Map<Integer, byte[]> hashes = sod.getDataGroupHashes();
            byte[] expected = hashes.get(1);
            if (expected == null) throw new PAException("SOD has no DG1 hash");
            MessageDigest md = MessageDigest.getInstance(sod.getDigestAlgorithm(), "BC");
            if (!MessageDigest.isEqual(expected, md.digest(dg1Bytes))) {
                throw new PAException("DG1 hash mismatch");
            }
        } catch (PAException e) {
            throw e;
        } catch (Exception e) {
            throw new PAException("DG1 hash check failed", e);
        }

        // 2. CMS signature over the security object, verified under the DSC.
        // CMSSignedData enforces the signedAttrs messageDigest binding for us.
        try {
            TLVInputStream tlv = new TLVInputStream(new ByteArrayInputStream(sodBytes));
            tlv.readTag();    // 0x77 ICAO wrapper
            tlv.readLength();
            CMSSignedData cms = new CMSSignedData(tlv.readValue());
            SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();
            if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(dsc))) {
                throw new PAException("SOD signature invalid");
            }
        } catch (PAException e) {
            throw e;
        } catch (Exception e) {
            throw new PAException("SOD signature verification failed", e);
        }

        // 3. DSC chains to a CSCA in the master list.
        // ponytail: issuer-match + signature only; DSC validity windows are a
        // policy question (documents outlive DSCs) — revisit with master-list
        // versioning in T4/T6.
        boolean chained = false;
        for (X509Certificate csca : masterList) {
            if (!dsc.getIssuerX500Principal().equals(csca.getSubjectX500Principal())) continue;
            try {
                dsc.verify(csca.getPublicKey());
                chained = true;
                break;
            } catch (Exception ignored) {
                // wrong CSCA with same DN or bad signature; keep looking
            }
        }
        if (!chained) throw new PAException("DSC does not chain to master list");

        try {
            DG1File dg1 = new DG1File(new ByteArrayInputStream(dg1Bytes));
            MrzData d = new MrzData(dg1.getMRZInfo().getDocumentCode(),
                               dg1.getMRZInfo().getDateOfBirth(),
                               dg1.getMRZInfo().getDateOfExpiry());
            d.dscInfo = dscInfo(dsc);
            return d;
        } catch (Exception e) {
            throw new PAException("DG1 unparseable", e);
        }
    }
}