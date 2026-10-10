// SPDX-License-Identifier: AGPL-3.0-only
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
        /** Presentation circuit the holder used. Lets a relying party describe the
         *  binding accurately: the mDL rail's issuer chain is verified at enrolment,
         *  not re-proven in ZK per presentation the way mono_faithful is. */
        public String circuit = "";
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

            // Assurance level: a person_bound policy rejects bearer credentials (ones not
            // face-matched to the document holder at enrollment). Absent ⇒ bearer OK.
            boolean personBoundCred = r.has("person_bound") && r.get("person_bound").getAsBoolean();
            if (c.personBound && !personBoundCred) {
                throw new IllegalStateException("policy requires a person-bound credential; this one is bearer-only");
            }

            byte[] proofBytes = Base64.getDecoder().decode(r.get("proof").getAsString());

            // 2. Attestation + device_sig first: cheap, and they gate the costly ZK
            //    sidecar below. The attestation binds the first-contact nonce, not
            //    this presentation's — freshness comes from device_sig.
            List<X509Certificate> chain = new ArrayList<>();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (var e : r.getAsJsonArray("attestation_chain")) {
                chain.add((X509Certificate) cf.generateCertificate(
                        new java.io.ByteArrayInputStream(Base64.getDecoder().decode(e.getAsString()))));
            }
            v.attestation = AttestationVerifier.verify(chain, null, allowlist);

            // 3. device_sig = Sig(K_v, SHA256(nonce ‖ origin ‖ SHA256(proof))).
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(nonce);
            md.update(c.origin.getBytes(StandardCharsets.UTF_8));
            md.update(MessageDigest.getInstance("SHA-256").digest(proofBytes));
            // Bind the assurance flag into the device-signed digest so a relay/MITM
            // cannot flip an unsigned "person_bound":true past the policy gate above.
            md.update((byte) (personBoundCred ? 1 : 0));
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initVerify(chain.get(0).getPublicKey());
            s.update(md.digest());
            if (!s.verify(Base64.getDecoder().decode(r.get("device_sig").getAsString()))) {
                throw new IllegalStateException("device signature invalid");
            }

            // 4. ZK proof (native). Two presentation circuits are accepted:
            //  - mono_faithful: 5 pub [ctx,current,age_min,N,dsc_root] + a separate
            //    enroll proof -> full CSCA->DSC->SOD chain proven in ZK.
            //  - present_amortized (Tier A): 4 pub [ctx,current,age_min,N]. Document
            //    provenance was established once at enrollment and is attested (T3),
            //    not re-proven per presentation. See docs/amortized-enrollment.md.
            String circuit = r.has("circuit") ? r.get("circuit").getAsString() : "mono_faithful";
            v.circuit = circuit;
            // Amortized (Tier A) family: 4 public inputs [ctx, current, age_min, N].
            // present_amortized commits (dob, expiry); present_bool commits the mDL
            // age boolean + threshold (no dob, per the privacy rule).
            java.util.Set<String> AMORTIZED = java.util.Set.of("present_amortized", "present_bool");
            boolean amortized = AMORTIZED.contains(circuit);
            // Faithful family: mono_faithful (RSA PKCS1) / _pss / _ecdsa — all 5
            // public inputs [ctx, current, age_min, N, dsc_commit].
            java.util.Set<String> FAITHFUL = java.util.Set.of(
                    "mono_faithful", "mono_faithful_pss", "mono_faithful_ecdsa");
            if (!amortized && !FAITHFUL.contains(circuit)) {
                throw new IllegalStateException("unknown presentation circuit");
            }
            // Tier A proofs carry no document provenance: the commitment C is a
            // private witness nothing public pins, so anyone can prove a made-up
            // (dob, k) and mint fresh nullifiers at will. Until enrollment is
            // bound to the presenting key, accept them only on explicit opt-in.
            if (amortized && !(allowlist.has("allow_tier_a_amortized")
                    && allowlist.get("allow_tier_a_amortized").getAsBoolean())) {
                throw new IllegalStateException(
                        "amortized (Tier A) proofs not accepted: no document provenance (allow_tier_a_amortized=false)");
            }
            int pubCount = amortized ? 4 : 5;
            String circuitJson = circuit + ".json";

            String proofStr = new String(proofBytes, 0, Math.min(4, proofBytes.length), StandardCharsets.UTF_8);
            if (proofStr.startsWith("STUB")) {
                boolean allowed = allowlist.has("demo_allow_zk_stub")
                        && allowlist.get("demo_allow_zk_stub").getAsBoolean();
                if (!allowed) throw new IllegalStateException("ZK proof is a stub and policy forbids stubs");
                v.zkStub = true;
            } else {
                // noir-rs format: [uint32 num_public][public_inputs][proof].
                final int PRE = 4;
                java.math.BigInteger[] pub = new java.math.BigInteger[pubCount];
                for (int i = 0; i < pubCount; i++) {
                    pub[i] = new java.math.BigInteger(1,
                            java.util.Arrays.copyOfRange(proofBytes, PRE + i * 32, PRE + i * 32 + 32));
                }
                if (!pub[0].equals(new java.math.BigInteger(expectedCtx))) {
                    throw new IllegalStateException("zk ctx != H(verifier_id||epoch)");
                }
                // Real date arithmetic (YYYYMMDD integers jump 70+ at month ends);
                // ±1 day tolerates the holder's timezone.
                int cur = pub[1].intValueExact();
                java.time.LocalDate curDate;
                try {
                    curDate = java.time.LocalDate.of(cur / 10000, cur / 100 % 100, cur % 100);
                } catch (java.time.DateTimeException e) {
                    throw new IllegalStateException("zk current-date malformed");
                }
                long skew = java.time.temporal.ChronoUnit.DAYS.between(java.time.LocalDate.now(), curDate);
                if (Math.abs(skew) > 1) {
                    throw new IllegalStateException("zk current-date stale: " + cur);
                }
                if (pub[2].longValueExact() != c.value) {
                    throw new IllegalStateException("zk age_min != policy value");
                }
                if (!pub[3].toString().equals(pi.get("N").getAsString())) {
                    throw new IllegalStateException("N != zk output");
                }
                if (!zkVerify(proofBytes, pubCount, circuitJson)) {
                    throw new IllegalStateException("ZK proof invalid");
                }
                if (amortized) {
                    // Provenance is not in this proof; attestation (step 3) carries it.
                    v.chain = "predicate over enrolled commitment (Tier A: provenance attested at enrollment)";
                } else {
                    // Dual-proof: verify the enrollment proof (CSCA->DSC) and check
                    // it commits the SAME DSC as this presentation (pub[4]). ADR-005.
                    String enrollB64 = r.has("enroll_proof") ? r.get("enroll_proof").getAsString() : "";
                    if (enrollB64.isEmpty()) {
                        // FAIL CLOSED: the faithful rail's presentation proof only proves
                        // DSC->SOD. The CSCA->DSC anchor to a real government master list is
                        // carried solely by enroll_proof; without it the DSC is unanchored
                        // (attacker can self-sign a SOD). Refuse rather than accept.
                        throw new IllegalStateException(
                                "faithful rail requires enroll_proof (CSCA->DSC anchor); refusing unanchored credential");
                    } else {
                        // Route the enroll verify by the CSCA algorithm the wallet
                        // used: circuit + published root must match.
                        String eAlg = r.has("enroll_alg") && !r.get("enroll_alg").getAsString().isEmpty()
                                ? r.get("enroll_alg").getAsString() : "rsa4096";
                        // Same alg->circuit map the wallet routes with (core).
                        String circuitName = onebit.core.Witness.CIRCUIT.get(eAlg);
                        if (circuitName == null) throw new IllegalStateException("unknown enroll_alg");
                        String eCircuit = circuitName + ".json";
                        // dsc_ecdsa is a P-256 DSC under an RSA-4096 CSCA -> rsa4096 tree/root.
                        String eRootKey = "csca_root_" + (eAlg.equals("dsc_ecdsa") ? "rsa4096" : eAlg);
                        byte[] eb = Base64.getDecoder().decode(enrollB64);
                        // enroll public inputs: [dsc_commit, root] after the 4-byte prefix
                        java.math.BigInteger eDscCommit = new java.math.BigInteger(1,
                                java.util.Arrays.copyOfRange(eb, 4, 36));
                        java.math.BigInteger eRoot = new java.math.BigInteger(1,
                                java.util.Arrays.copyOfRange(eb, 36, 68));
                        if (!eDscCommit.equals(pub[4])) {
                            throw new IllegalStateException("enroll dsc_commit != presentation dsc_commit");
                        }
                        if (!zkVerify(eb, 2, eCircuit)) {
                            throw new IllegalStateException("enrollment proof invalid");
                        }
                        // The CSCA is in the PUBLISHED master-list tree (real root)
                        // for its algorithm. FAIL CLOSED if the allowlist has no root for
                        // this alg: a missing trust anchor is a hard reject, not a skip —
                        // otherwise an attacker picks an unanchored alg and supplies a
                        // fabricated root (eRoot is prover-controlled).
                        if (!allowlist.has(eRootKey)) {
                            throw new IllegalStateException(
                                    "no published CSCA root for " + eAlg + " in allowlist; refusing (fail-closed)");
                        }
                        java.math.BigInteger published = new java.math.BigInteger(
                                allowlist.get(eRootKey).getAsString().substring(2), 16);
                        if (!eRoot.equals(published)) {
                            throw new IllegalStateException("CSCA not in published " + eAlg + " tree");
                        }
                        v.chain = "CSCA(" + eAlg + ", in master list)->DSC->SOD, fully verified in ZK";
                    }
                }
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
    static final long ZK_TIMEOUT_S = Long.getLong("onebit.zk_timeout_s", 120);

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
        try {
            p.getOutputStream().write(in.toString().getBytes(StandardCharsets.UTF_8));
            p.getOutputStream().close();
            // Drain on another thread so a hung sidecar can't block us past the timeout.
            var out = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                try { return new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8); }
                catch (java.io.IOException e) { return ""; }
            });
            if (!p.waitFor(ZK_TIMEOUT_S, java.util.concurrent.TimeUnit.SECONDS)) {
                throw new IllegalStateException("ZK sidecar timed out");
            }
            return p.exitValue() == 0 && out.get(5, java.util.concurrent.TimeUnit.SECONDS).contains("ZK_OK");
        } finally {
            p.destroyForcibly();
        }
    }

    private VerifySdk() {}
}