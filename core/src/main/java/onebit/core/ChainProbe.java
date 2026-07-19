package onebit.core;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
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

/**
 * Builds one consistent CSCA(4096) -> DSC(2048) -> SOD chain and emits BOTH
 * circuit witnesses using the SAME DSC key, so enroll.dsc_commit ==
 * mono_faithful.dsc_commit. Demonstrates the two-circuit chain end to end.
 */
public final class ChainProbe {
    public static void main(String[] args) throws Exception {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
        String outDir = System.getProperty("dir", ".");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
        KeyPair csca = kpg.generateKeyPair();
        kpg.initialize(2048);
        KeyPair dsc = kpg.generateKeyPair();
        BigInteger dscN = ((java.security.interfaces.RSAPublicKey) dsc.getPublic()).getModulus();
        BigInteger cscaN = ((java.security.interfaces.RSAPublicKey) csca.getPublic()).getModulus();

        // --- CSCA signs the DSC cert (enroll witness) ---
        long now = System.currentTimeMillis();
        X509Certificate dscCert = new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(new X500Name("CN=CSCA,C=US"), BigInteger.valueOf(now),
                        new Date(now - 86400000L), new Date(now + 10L * 365 * 86400000L),
                        new X500Name("CN=DSC,C=US"), dsc.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withRSA").build(csca.getPrivate())));
        byte[] tbs = dscCert.getTBSCertificate();

        java.security.SecureRandom rnd = new java.security.SecureRandom();
        BigInteger P = new BigInteger(
                "21888242871839275222246405745257275088548364400416034343698204186575808495617");
        StringBuilder path = new StringBuilder("[");
        for (int i = 0; i < 20; i++) { if (i > 0) path.append(", "); path.append("\"").append(new BigInteger(250, rnd).mod(P)).append("\""); }
        path.append("]");

        String enroll =
              "dsc_tbs = " + bytes(pad(tbs, 1024)) + "\n"
            + "dsc_tbs_len = " + tbs.length + "\n"
            + "csca_sig = " + limbs(new BigInteger(1, dscCert.getSignature()), 35) + "\n"
            + "csca_modulus = " + limbs(cscaN, 35) + "\n"
            + "csca_redc = " + limbs(BigInteger.ONE.shiftLeft(2 * 4096 + 6).divide(cscaN), 35) + "\n"
            + "merkle_path = " + path + "\n"
            + "merkle_dirs = 349525\n"
            + "dsc_modulus = " + limbs(dscN, 18) + "\n";
        java.nio.file.Files.writeString(java.nio.file.Path.of(outDir, "enroll.toml"), enroll);

        // --- DSC signs the SOD (mono_faithful witness), SAME dsc key ---
        MRZInfo mrz = new MRZInfo("P", "USA", "DOE", "JOHN", "123456789", "USA",
                "800101", Gender.MALE, "301231", "");
        byte[] dg1 = new DG1File(mrz).getEncoded();
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        Map<Integer, byte[]> hashes = new LinkedHashMap<>();
        hashes.put(1, sha.digest(dg1));
        for (int dgn : new int[]{2, 14, 15}) hashes.put(dgn, sha.digest(new byte[]{(byte) dgn}));
        SODFile sod = new SODFile("SHA-256", "SHA256withRSA", hashes, dsc.getPrivate(),
                SodSizes.selfSigned(dsc)); // DSC cert holder; key is what matters

        Witness.Doc d = Witness.extract(dg1, sod.getEncoded());
        List<String> w = Witness.monoFaithful(d, 256, 128);
        // append k, ctx, current, age_min
        w.add(new BigInteger(250, rnd).mod(P).toString()); // k
        w.add(new BigInteger(250, rnd).mod(P).toString()); // ctx
        w.add("20260718"); // current
        w.add("18");       // age_min
        StringBuilder pres = new StringBuilder();
        String[] names = {"dg1:93", "econtent:256", "econtent_len:1", "signed_attrs:128",
                "signed_attrs_len:1", "dg1_hash_off:1", "econtent_hash_off:1", "sig:18",
                "modulus:18", "redc:18", "k:1", "ctx:1", "current:1", "age_min:1"};
        int idx = 0;
        for (String nm : names) {
            String[] parts = nm.split(":");
            int sz = Integer.parseInt(parts[1]);
            if (sz == 1) {
                pres.append(parts[0]).append(" = \"").append(w.get(idx++)).append("\"\n");
            } else {
                pres.append(parts[0]).append(" = [");
                for (int j = 0; j < sz; j++) { if (j > 0) pres.append(", "); pres.append("\"").append(w.get(idx++)).append("\""); }
                pres.append("]\n");
            }
        }
        java.nio.file.Files.writeString(java.nio.file.Path.of(outDir, "present.toml"), pres.toString());

        System.out.println("chain: CSCA-" + cscaN.bitLength() + " -> DSC-" + dscN.bitLength()
                + " -> SOD | shared dsc_modulus -> matching dsc_commit expected");
    }

    static byte[] pad(byte[] b, int n) { byte[] o = new byte[n]; System.arraycopy(b, 0, o, 0, b.length); return o; }
    static String bytes(byte[] b) {
        StringBuilder s = new StringBuilder("[");
        for (int i = 0; i < b.length; i++) { if (i > 0) s.append(", "); s.append(b[i] & 0xff); }
        return s.append("]").toString();
    }
    static String limbs(BigInteger x, int n) {
        BigInteger mask = BigInteger.ONE.shiftLeft(120).subtract(BigInteger.ONE);
        StringBuilder s = new StringBuilder("[");
        for (int i = 0; i < n; i++) { if (i > 0) s.append(", "); s.append("\"0x").append(x.shiftRight(120 * i).and(mask).toString(16)).append("\""); }
        return s.append("]").toString();
    }
    private ChainProbe() {}
}
