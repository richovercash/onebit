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

            // 2. ZK proof: semantic checks on public inputs, then cryptographic
            //    verification via the bb.js sidecar. Public-input layout of
            //    Circuit P v0: [ctx, current, age_min, N].
            byte[] proof = Base64.getDecoder().decode(r.get("proof").getAsString());
            String proofStr = new String(proof, StandardCharsets.UTF_8);
            if (proofStr.startsWith("STUB")) {
                boolean allowed = allowlist.has("demo_allow_zk_stub")
                        && allowlist.get("demo_allow_zk_stub").getAsBoolean();
                if (!allowed) throw new IllegalStateException("ZK proof is a stub and policy forbids stubs");
                v.zkStub = true;
            } else {
                var zk = pi.getAsJsonArray("zk");
                if (zk == null || zk.size() != 4) throw new IllegalStateException("bad zk public inputs");
                if (!hexEq(zk.get(0).getAsString(), new java.math.BigInteger(expectedCtx))) {
                    throw new IllegalStateException("zk ctx != H(verifier_id||epoch)");
                }
                java.time.LocalDate today = java.time.LocalDate.now();
                long current = new java.math.BigInteger(zk.get(1).getAsString().substring(2), 16).longValueExact();
                long todayInt = today.getYear() * 10000L + today.getMonthValue() * 100L + today.getDayOfMonth();
                if (Math.abs(current - todayInt) > 1) throw new IllegalStateException("zk current-date stale: " + current);
                long ageMin = new java.math.BigInteger(zk.get(2).getAsString().substring(2), 16).longValueExact();
                if (ageMin != c.value) throw new IllegalStateException("zk age_min != policy value");
                if (!zk.get(3).getAsString().equals(pi.get("N").getAsString())) {
                    throw new IllegalStateException("N != zk output");
                }
                if (!zkVerify(r.get("proof").getAsString(), zk)) {
                    throw new IllegalStateException("ZK proof invalid");
                }
            }

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

    static boolean hexEq(String hex0x, java.math.BigInteger dec) {
        return new java.math.BigInteger(hex0x.substring(2), 16).equals(dec);
    }

    /** Cryptographic UltraHonk verification via the node bb.js sidecar. */
    static boolean zkVerify(String proofB64, com.google.gson.JsonArray publicInputs) throws Exception {
        JsonObject in = new JsonObject();
        in.addProperty("proof", proofB64);
        in.add("publicInputs", publicInputs);
        String jsDir = System.getProperty("onebit.jsdir",
                new java.io.File("verifier/js").getAbsolutePath());
        String node = System.getProperty("onebit.node", "node");
        Process p = new ProcessBuilder(node, "verify.mjs")
                .directory(new java.io.File(jsDir))
                .redirectErrorStream(true)
                .start();
        p.getOutputStream().write(in.toString().getBytes(StandardCharsets.UTF_8));
        p.getOutputStream().close();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        return p.waitFor() == 0 && out.contains("ZK_OK");
    }

    private VerifySdk() {}
}
