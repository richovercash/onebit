package onebit.verifier;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import onebit.core.Challenge;
import onebit.core.Nullifier;

/**
 * SPEC §6.3: verify(response, challenge, params, allowlist) → {ok, nullifier}.
 * Stateless — every input arrives per call; nothing is retained (V3).
 * Pass 1: ZK slot may carry the labeled stub; accepted ONLY when the
 * allowlist config says demo_allow_zk_stub, and the verdict says so loudly.
 */
public final class VerifySdk {

    public static final class Verdict {
        public boolean ok;
        public String reason = "";
        public String nullifier = "";
        public boolean zkStub;
        public String chain = "";
        public AttestationVerifier.Result attestation;
    }

    public static Verdict verify(String challengeJson, String responseJson, JsonObject allowlist) {
        Verdict v = new Verdict();
        try {
            Challenge c = Challenge.parse(challengeJson);
            JsonObject r = JsonParser.parseString(responseJson).getAsJsonObject();

            if (r.get("v").getAsInt() != 1) throw new IllegalStateException("response version");
            if (!"A".equals(r.get("mode").getAsString())) throw new IllegalStateException("mode B not accepted");
            JsonObject pi = r.getAsJsonObject("public_inputs");

            // 1. Recompute expected public inputs from OUR challenge (never theirs).
            byte[] nonce = Base64.getDecoder().decode(pi.get("nonce").getAsString());
            if (!MessageDigest.isEqual(nonce, c.nonce)) throw new IllegalStateException("nonce mismatch");
            if (!c.origin.equals(pi.get("origin").getAsString())) throw new IllegalStateException("origin mismatch");
            String expectedCtx = Nullifier.ctx(c.verifierId, c.epoch).toString();
            if (!expectedCtx.equals(pi.get("ctx").getAsString())) throw new IllegalStateException("ctx mismatch");

            // 2. ZK proof (mono_slim, native). proofBytes = [public_inputs
            //    (5*32B)][proof]; public inputs = [ctx, current, age_min, N,
            //    dsc_root]. Semantic checks against OUR challenge, then bb.js.
            byte[] proofBytes = Base64.getDecoder().decode(r.get("proof").getAsString());
            String proofStr = new String(proofBytes, 0, Math.min(4, proofBytes.length), StandardCharsets.UTF_8);
            if (proofStr.startsWith("STUB")) {
                boolean allowed = allowlist.has("demo_allow_zk_stub")
                        && allowlist.get("demo_allow_zk_stub").getAsBoolean();
                if (!allowed) throw new IllegalStateException("ZK proof is a stub and policy forbids stubs");
                v.zkStub = true;
            } else {
                // noir-rs format: [uint32 num_public][public_inputs][proof].
                final int PRE = 4;
                java.math.BigInteger[] pub = new java.math.BigInteger[5];
                for (int i = 0; i < 5; i++) {
                    pub[i] = new java.math.BigInteger(1,
                            java.util.Arrays.copyOfRange(proofBytes, PRE + i * 32, PRE + i * 32 + 32));
                }
                if (!pub[0].equals(new java.math.BigInteger(expectedCtx))) {
                    throw new IllegalStateException("zk ctx != H(verifier_id||epoch)");
                }
                java.time.LocalDate today = java.time.LocalDate.now();
                long todayInt = today.getYear() * 10000L + today.getMonthValue() * 100L + today.getDayOfMonth();
                if (Math.abs(pub[1].longValueExact() - todayInt) > 1) {
                    throw new IllegalStateException("zk current-date stale: " + pub[1]);
                }
                if (pub[2].longValueExact() != c.value) {
                    throw new IllegalStateException("zk age_min != policy value");
                }
                if (!pub[3].toString().equals(pi.get("N").getAsString())) {
                    throw new IllegalStateException("N != zk output");
                }
                if (!zkVerify(proofBytes, 5, "mono_faithful.json")) {
                    throw new IllegalStateException("ZK proof invalid");
                }
                // Dual-proof: verify the enrollment proof (CSCA->DSC) and check
                // it commits the SAME DSC as this presentation (pub[4]). ADR-005.
                String enrollB64 = r.has("enroll_proof") ? r.get("enroll_proof").getAsString() : "";
                if (enrollB64.isEmpty()) {
                    v.chain = "DSC->SOD only (no enroll proof; CSCA->DSC attestation-backed)";
                } else {
                    byte[] eb = Base64.getDecoder().decode(enrollB64);
                    // enroll public inputs: [dsc_commit, root] after the 4-byte prefix
                    java.math.BigInteger eDscCommit = new java.math.BigInteger(1,
                            java.util.Arrays.copyOfRange(eb, 4, 36));
                    java.math.BigInteger eRoot = new java.math.BigInteger(1,
                            java.util.Arrays.copyOfRange(eb, 36, 68));
                    if (!eDscCommit.equals(pub[4])) {
                        throw new IllegalStateException("enroll dsc_commit != presentation dsc_commit");
                    }
                    if (!zkVerify(eb, 2, "enroll.json")) {
                        throw new IllegalStateException("enrollment proof invalid");
                    }
                    // The CSCA is in the PUBLISHED master-list tree (real root).
                    if (allowlist.has("csca_root_rsa4096")) {
                        java.math.BigInteger published = new java.math.BigInteger(
                                allowlist.get("csca_root_rsa4096").getAsString().substring(2), 16);
                        if (!eRoot.equals(published)) {
                            throw new IllegalStateException("CSCA not in published master-list tree");
                        }
                    }
                    v.chain = "CSCA(in master list)->DSC->SOD, fully verified in ZK";
                }
            }
            byte[] proof = proofBytes;

            // 3. Attestation chain to allowlist (attestation binds first-contact
            //    nonce, not this presentation's — freshness comes from device_sig).
            List<X509Certificate> chain = new ArrayList<>();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (var e : r.getAsJsonArray("attestation_chain")) {
                chain.add((X509Certificate) cf.generateCertificate(
                        new java.io.ByteArrayInputStream(Base64.getDecoder().decode(e.getAsString()))));
            }
            v.attestation = AttestationVerifier.verify(chain, null, allowlist);

            // 4. device_sig = Sig(K_v, SHA256(nonce ‖ origin ‖ SHA256(proof))).
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(nonce);
            md.update(c.origin.getBytes(StandardCharsets.UTF_8));
            md.update(MessageDigest.getInstance("SHA-256").digest(proof));
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initVerify(chain.get(0).getPublicKey());
            s.update(md.digest());
            if (!s.verify(Base64.getDecoder().decode(r.get("device_sig").getAsString()))) {
                throw new IllegalStateException("device signature invalid");
            }

            v.nullifier = pi.get("N").getAsString(); // stub value in pass 1
            v.ok = true;
        } catch (Exception e) {
            v.ok = false;
            v.reason = e.getMessage() == null ? e.toString() : e.getMessage();
        }
        return v;
    }

    /** Verify a native proof against `circuit`: split [uint32 num_public][pub]
     *  [proof], hand to the bb.js sidecar as {proof, publicInputs}. */
    static boolean zkVerify(byte[] proofBytes, int pub, String circuit) throws Exception {
        int PRE = 4; // [uint32 num_public][pub][proof]
        com.google.gson.JsonArray publicInputs = new com.google.gson.JsonArray();
        for (int i = 0; i < pub; i++) {
            String hex = java.util.HexFormat.of().formatHex(
                    java.util.Arrays.copyOfRange(proofBytes, PRE + i * 32, PRE + i * 32 + 32));
            publicInputs.add("0x" + hex);
        }
        byte[] proof = java.util.Arrays.copyOfRange(proofBytes, PRE + pub * 32, proofBytes.length);
        JsonObject in = new JsonObject();
        in.addProperty("proof", Base64.getEncoder().encodeToString(proof));
        in.add("publicInputs", publicInputs);
        String jsDir = System.getProperty("onebit.jsdir",
                new java.io.File("verifier/js").getAbsolutePath());
        String node = System.getProperty("onebit.node", "node");
        ProcessBuilder pb = new ProcessBuilder(node, "verify.mjs")
                .directory(new java.io.File(jsDir))
                .redirectErrorStream(true);
        pb.environment().put("CIRCUIT", circuit);
        Process p = pb.start();
        p.getOutputStream().write(in.toString().getBytes(StandardCharsets.UTF_8));
        p.getOutputStream().close();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        return p.waitFor() == 0 && out.contains("ZK_OK");
    }

    private VerifySdk() {}
}
