// SPDX-License-Identifier: AGPL-3.0-only
package onebit.verifier;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.LocalDate;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.sun.net.httpserver.HttpServer;
import com.google.gson.JsonObject;

/**
 * T5 demo gated site. Serves the gate page, mints signed challenges,
 * verifies presentations via the stateless SDK. In-memory nonce set only —
 * nothing here is security-critical to retain (V3).
 */
public final class DemoServer {

    static final String ORIGIN = "https://demo.onebit.local"; // stated origin (demo runs over adb-reverse http)
    static final Map<String, String> pendingNonces = new ConcurrentHashMap<>();
    static final Map<String, Long> nonceMintedAt = new ConcurrentHashMap<>();
    /** per-epoch nullifier counts; in-memory only (V3). */
    static final Map<String, Integer> nullifierLedger = new ConcurrentHashMap<>();
    static final int EPOCH_RATE_LIMIT = 3;
    static KeyPair verifierKey;
    static String verifierId;
    static JsonObject allowlist;
    /** -Donebit.personbound=true makes this a strict site: it demands a person-bound
     *  (face-matched) credential and DENYs today's bearer credentials. */
    static final boolean PERSON_BOUND = Boolean.getBoolean("onebit.personbound");

    public static void main(String[] args) throws Exception {
        allowlist = AttestationVerifier.readAllowlist(Files.readString(Paths.get(args[0])));
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        verifierKey = kpg.generateKeyPair();
        verifierId = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(verifierKey.getPublic().getEncoded()));

        HttpServer s = HttpServer.create(new InetSocketAddress(8317), 0);
        s.createContext("/", ex -> {
            String challenge = mintChallenge();
            String link = "onebit://present?c=" + Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(challenge.getBytes(StandardCharsets.UTF_8));
            respond(ex, 200, gatePage(link));
        });
        s.createContext("/present", ex -> {
            String q = ex.getRequestURI().getRawQuery();
            String verdictHtml;
            try {
                String resp = new String(Base64.getUrlDecoder().decode(q.substring(2)), StandardCharsets.UTF_8);
                String nonceB64 = com.google.gson.JsonParser.parseString(resp).getAsJsonObject()
                        .getAsJsonObject("public_inputs").get("nonce").getAsString();
                String challenge = pendingNonces.remove(nonceB64); // single-use
                if (challenge == null) throw new IllegalStateException("unknown or replayed nonce");
                Long minted = nonceMintedAt.remove(nonceB64);
                VerifySdk.Verdict v = VerifySdk.verify(challenge, resp, allowlist);
                if (v.ok && !v.nullifier.isEmpty()) {
                    int n = nullifierLedger.merge(v.nullifier, 1, Integer::sum);
                    if (n > EPOCH_RATE_LIMIT) {
                        v.ok = false;
                        v.reason = "nullifier rate limit exceeded (" + n + " uses this epoch)";
                    }
                }
                long e2e = minted == null ? -1 : System.currentTimeMillis() - minted;
                System.out.println((v.ok ? "GRANT" : "DENY ") + " e2e=" + e2e + "ms N="
                        + v.nullifier + " chain=[" + v.chain + "]" + (v.ok ? "" : " reason=" + v.reason));
                verdictHtml = verdictPage(v, e2e);
            } catch (Exception e) {
                VerifySdk.Verdict v = new VerifySdk.Verdict();
                v.reason = String.valueOf(e.getMessage());
                verdictHtml = verdictPage(v, -1);
            }
            respond(ex, 200, verdictHtml);
        });
        s.start();
        System.out.println("gate: http://localhost:8317  verifier_id=" + verifierId);
    }

    static String mintChallenge() {
        try {
            byte[] nonce = new byte[32];
            SecureRandom.getInstanceStrong().nextBytes(nonce);
            String nonceB64 = Base64.getEncoder().encodeToString(nonce);
            JsonObject att = new JsonObject();
            att.addProperty("allowlist_url", ORIGIN + "/allowlist.json");
            att.addProperty("allowlist_hash", "demo");
            att.addProperty("tier", "A");
            JsonObject policy = new JsonObject();
            policy.addProperty("predicate", "age_gte");
            policy.addProperty("value", 18);
            policy.addProperty("icao_root_min_version", 1);
            policy.add("attestation", att);
            policy.addProperty("mode_b_accepted", false);
            policy.addProperty("person_bound", PERSON_BOUND);   // demo accepts bearer creds; strict site demands face-match
            JsonObject c = new JsonObject();
            c.addProperty("v", 1);
            c.addProperty("nonce", nonceB64);
            c.addProperty("origin", ORIGIN);
            c.addProperty("verifier_id", verifierId);
            // Hourly-rotating epoch (YYYY-MM-DD-HH): the disclosed token changes every
            // hour, so nothing persistent leaves the device — while still letting us
            // rate-limit within the hour.
            String epoch = LocalDate.now() + "-" + String.format("%02d", java.time.LocalTime.now().getHour());
            c.addProperty("epoch", epoch);
            c.add("policy", policy);
            // Sign the canonical tuple (shared with the wallet), not the JSON text,
            // and publish the SPKI so the wallet can anchor sig to verifier_id.
            String signed = onebit.core.Challenge.signedContent(nonceB64, ORIGIN, verifierId,
                    epoch, "age_gte", 18, 1, "A", false, PERSON_BOUND);
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(verifierKey.getPrivate());
            sig.update(signed.getBytes(StandardCharsets.UTF_8));
            c.addProperty("sig", Base64.getEncoder().encodeToString(sig.sign()));
            c.addProperty("spki", Base64.getEncoder().encodeToString(verifierKey.getPublic().getEncoded()));
            String json = c.toString();
            pendingNonces.put(nonceB64, json);
            nonceMintedAt.put(nonceB64, System.currentTimeMillis());
            return json;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String gatePage(String deepLink) {
        return "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
            + "<body style='font-family:sans-serif;max-width:40em;margin:2em auto;padding:0 1em'>"
            + "<h2>The Demo Saloon &#127866;</h2>"
            + "<p>Age-restricted content behind this gate. We learn one bit and nothing else.</p>"
            + "<p><a style='display:inline-block;background:#1a73e8;color:#fff;padding:.8em 1.2em;"
            + "border-radius:8px;text-decoration:none' href='" + deepLink + "'>"
            + "Verify with OneBit wallet</a></p>"
            + "<p style='color:#666;font-size:.85em'>Verifier stores nothing. No account. No ID upload.</p>";
    }

    static String verdictPage(VerifySdk.Verdict v, long e2eMs) {
        String stub = v.zkStub ? "<p style='background:#fff3cd;padding:.6em;border-radius:6px'>"
                + "&#9888;&#65039; ZK proof STUBBED — demo config only.</p>"
                : "<p style='background:#e6f4ea;padding:.6em;border-radius:6px'>"
                + "&#9989; ZK predicate proof verified (UltraHonk, on-device). "
                + "Binding: document (CSCA&rarr;DSC&rarr;SOD proven in ZK).</p>";
        if (v.ok) {
            return "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
                + "<body style='font-family:sans-serif;max-width:40em;margin:2em auto;padding:0 1em'>"
                + "<h1 style='color:#188038'>ACCESS GRANTED &#127866;</h1>" + stub
                + (v.chain.isEmpty() ? "" : "<p style='background:#e6f4ea;padding:.5em;border-radius:6px'>&#128279; chain: " + v.chain + "</p>")
                + (e2eMs >= 0 ? "<p>challenge&rarr;verdict: <b>" + e2eMs + " ms</b></p>" : "")
                + "<pre style='background:#f1f3f4;padding:1em;border-radius:6px;white-space:pre-wrap'>"
                + v.attestation + "</pre>"
                + "<p>nullifier: <code style='word-break:break-all'>" + v.nullifier + "</code></p>";
        }
        return "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
            + "<body style='font-family:sans-serif;max-width:40em;margin:2em auto;padding:0 1em'>"
            + "<h1 style='color:#d93025'>ACCESS DENIED</h1><p>fail closed: " + v.reason + "</p>";
    }

    static void respond(com.sun.net.httpserver.HttpExchange ex, int code, String html) throws java.io.IOException {
        byte[] b = html.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        ex.sendResponseHeaders(code, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }

    private DemoServer() {}
}