package onebit.verifier;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.junit.BeforeClass;
import org.junit.Test;

import onebit.core.Nullifier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/** T6 wire-level fixtures: relay, tamper, stub enforcement — all fail closed. */
public class VerifySdkTest {

    static final String VID = "ab".repeat(32);
    static final String EPOCH = "2026-07-11";
    static final String ORIGIN = "https://demo.onebit.local";
    static final byte[] NONCE = new byte[32];
    static final byte[] STUB = "STUB-T6".getBytes(StandardCharsets.UTF_8);

    static List<X509Certificate> chain;

    @BeforeClass
    public static void fixtures() throws Exception {
        AttestationVerifierTest.keys();
        chain = AttestationVerifierTest.chain(
                AttestationVerifierTest.attExt(NONCE, 202606, false, 0, true));
    }

    static String challenge() {
        return """
        {"v":1,"nonce":"%s","origin":"%s","verifier_id":"%s","epoch":"%s",
         "policy":{"predicate":"age_gte","value":18,"icao_root_min_version":1,
           "attestation":{"allowlist_url":"https://x","allowlist_hash":"h","tier":"A"},
           "mode_b_accepted":false},"sig":"c2ln","spki":"c2ln"}"""
                .formatted(Base64.getEncoder().encodeToString(NONCE), ORIGIN, VID, EPOCH);
    }

    /** device_sig computed over the given origin (relay = wrong origin). */
    static String response(String envelopeOrigin, String sigOrigin) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(NONCE);
        md.update(sigOrigin.getBytes(StandardCharsets.UTF_8));
        md.update(MessageDigest.getInstance("SHA-256").digest(STUB));
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(AttestationVerifierTest.leafKeys.getPrivate());
        s.update(md.digest());
        byte[] deviceSig = s.sign();

        JsonArray chainArr = new JsonArray();
        for (X509Certificate c : chain) {
            chainArr.add(Base64.getEncoder().encodeToString(c.getEncoded()));
        }
        JsonObject pi = new JsonObject();
        pi.addProperty("T", "20260711");
        pi.addProperty("N", "STUB");
        pi.addProperty("ctx", Nullifier.ctx(VID, EPOCH).toString());
        pi.addProperty("nonce", Base64.getEncoder().encodeToString(NONCE));
        pi.addProperty("origin", envelopeOrigin);
        pi.addProperty("R_icao", "v1");
        JsonObject r = new JsonObject();
        r.addProperty("v", 1);
        r.addProperty("proof", Base64.getEncoder().encodeToString(STUB));
        r.add("public_inputs", pi);
        r.addProperty("device_sig", Base64.getEncoder().encodeToString(deviceSig));
        r.add("attestation_chain", chainArr);
        r.addProperty("mode", "A");
        r.addProperty("tier", "A");
        return r.toString();
    }

    static JsonObject allowlist(boolean allowStub) throws Exception {
        JsonObject o = AttestationVerifier.readAllowlist(
                AttestationVerifierTest.allowlistJson());
        o.addProperty("demo_allow_zk_stub", allowStub);
        return o;
    }

    @Test
    public void consistentPresentationPasses() throws Exception {
        var v = VerifySdk.verify(challenge(), response(ORIGIN, ORIGIN), allowlist(true));
        assertTrue(v.reason, v.ok);
        assertTrue(v.zkStub);
    }

    @Test
    public void stubForbiddenByPolicyFailsClosed() throws Exception {
        var v = VerifySdk.verify(challenge(), response(ORIGIN, ORIGIN), allowlist(false));
        assertFalse(v.ok);
        assertTrue(v.reason, v.reason.contains("stub"));
    }

    @Test
    public void relayedOriginInEnvelopeFails() throws Exception {
        // phisher relays to the real verifier but envelope says another origin
        var v = VerifySdk.verify(challenge(), response("https://evil.example", ORIGIN), allowlist(true));
        assertFalse(v.ok);
        assertEquals("origin mismatch", v.reason);
    }

    @Test
    public void deviceSigOverWrongOriginFails() throws Exception {
        // envelope consistent, but K_v signed a different origin's digest
        var v = VerifySdk.verify(challenge(), response(ORIGIN, "https://evil.example"), allowlist(true));
        assertFalse(v.ok);
        assertEquals("device signature invalid", v.reason);
    }

    @Test
    public void wrongNonceFails() throws Exception {
        String tampered = response(ORIGIN, ORIGIN).replace(
                Base64.getEncoder().encodeToString(NONCE),
                Base64.getEncoder().encodeToString("XX".repeat(16).getBytes()));
        var v = VerifySdk.verify(challenge(), tampered, allowlist(true));
        assertFalse(v.ok);
        assertEquals("nonce mismatch", v.reason);
    }

    @Test
    public void modeBRejected() throws Exception {
        String modeB = response(ORIGIN, ORIGIN).replace("\"mode\":\"A\"", "\"mode\":\"B\"");
        var v = VerifySdk.verify(challenge(), modeB, allowlist(true));
        assertFalse(v.ok);
        assertTrue(v.reason.contains("mode B"));
    }
}
