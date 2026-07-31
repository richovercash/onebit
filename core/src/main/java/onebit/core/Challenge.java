// SPDX-License-Identifier: AGPL-3.0-only
package onebit.core;

import java.util.Base64;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

/**
 * SPEC §6.1 challenge, parsed with a whitelist-everything posture (V5):
 * unknown keys anywhere are refusal, unknown predicates are refusal, wrong
 * types are refusal. The wire format cannot express attribute disclosure;
 * anything trying is refused before any key or credential is touched.
 */
public final class Challenge {

    /** The complete predicate grammar. Extending this to attribute release
     *  is a protocol violation (V5), not a configuration. */
    public static final Set<String> GRAMMAR = Set.of("age_gte");

    public final byte[] nonce;
    public final String origin;
    public final String verifierId;
    public final String epoch;
    public final String predicate;
    public final int value;
    public final int icaoRootMinVersion;
    public final String attestationTier;
    public final boolean modeBAccepted;
    public final boolean personBound;   // policy requires a person-bound (face-matched) credential, not a bearer one
    public final String sig;
    public final byte[] spki;   // verifier's SubjectPublicKeyInfo (DER); sha256 == verifier_id

    public static final class RefusalException extends Exception {
        public RefusalException(String why) { super(why); }
    }

    public static Challenge parse(String json) throws RefusalException {
        JsonObject o;
        try {
            o = JsonParser.parseString(json).getAsJsonObject();
        } catch (Exception e) {
            throw new RefusalException("not a JSON object");
        }
        requireKeys(o, Set.of("v", "nonce", "origin", "verifier_id", "epoch", "policy", "sig", "spki"), "top-level");
        if (asInt(o, "v") != 1) throw new RefusalException("unsupported version");

        byte[] nonce;
        try {
            nonce = Base64.getDecoder().decode(asString(o, "nonce"));
        } catch (IllegalArgumentException e) {
            throw new RefusalException("nonce not base64");
        }
        if (nonce.length != 32) throw new RefusalException("nonce must be 32 bytes");

        String origin = asString(o, "origin");
        if (!origin.matches("https://[a-z0-9.-]+(:[0-9]+)?")) {
            throw new RefusalException("origin must be a bare https origin");
        }
        String verifierId = asString(o, "verifier_id");
        if (!verifierId.matches("[0-9a-f]{64}")) {
            throw new RefusalException("verifier_id must be spki sha256 hex");
        }
        String epoch = asString(o, "epoch");
        // YYYY-MM-DD (daily) or YYYY-MM-DD-HH (hourly) — the verifier chooses the
        // rotation window. Finer = more unlinkable; coarser = better rate-limiting.
        if (!epoch.matches("\\d{4}-\\d{2}-\\d{2}(-\\d{2})?")) {
            throw new RefusalException("epoch must be YYYY-MM-DD or YYYY-MM-DD-HH");
        }

        JsonObject p = asObject(o, "policy");
        requireKeys(p, Set.of("predicate", "value", "icao_root_min_version", "attestation", "mode_b_accepted"),
                Set.of("person_bound"), "policy");
        String predicate = asString(p, "predicate");
        if (!GRAMMAR.contains(predicate)) {
            throw new RefusalException("predicate not in grammar: " + predicate);
        }
        int value = asInt(p, "value");
        if (value < 1 || value > 120) throw new RefusalException("value out of range");
        int minRoot = asInt(p, "icao_root_min_version");
        if (minRoot < 1) throw new RefusalException("icao_root_min_version out of range");

        JsonObject att = asObject(p, "attestation");
        requireKeys(att, Set.of("allowlist_url", "allowlist_hash", "tier"), "attestation");
        asString(att, "allowlist_url"); // type-check every field, not just the ones we read
        asString(att, "allowlist_hash");
        String tier = asString(att, "tier");
        if (!tier.equals("A") && !tier.equals("B")) throw new RefusalException("unknown attestation tier");

        JsonElement mb = p.get("mode_b_accepted");
        if (!(mb instanceof JsonPrimitive) || !((JsonPrimitive) mb).isBoolean()) {
            throw new RefusalException("mode_b_accepted must be boolean");
        }
        // Optional assurance flag: when true the verifier requires a person-bound
        // (face-matched-at-enrollment) credential, not a bearer one. Absent ⇒ bearer OK.
        boolean personBound = false;
        if (p.has("person_bound")) {
            JsonElement pb = p.get("person_bound");
            if (!(pb instanceof JsonPrimitive) || !((JsonPrimitive) pb).isBoolean()) {
                throw new RefusalException("person_bound must be boolean");
            }
            personBound = pb.getAsBoolean();
        }

        byte[] spki;
        try {
            spki = Base64.getDecoder().decode(asString(o, "spki"));
        } catch (IllegalArgumentException e) {
            throw new RefusalException("spki not base64");
        }

        Challenge c = new Challenge(nonce, origin, verifierId, epoch, predicate, value,
                minRoot, tier, mb.getAsBoolean(), personBound, asString(o, "sig"), spki);
        return c;
    }

    /** Human line shown to the holder before any auth (SPEC §6.1). */
    public String display() {
        return origin + " asks: " + predicate.replace("_gte", " >= ") + value
                + " (tier " + attestationTier + ", epoch " + epoch + ")";
    }

    private static void requireKeys(JsonObject o, Set<String> allowed, String where)
            throws RefusalException {
        requireKeys(o, allowed, java.util.Set.of(), where);
    }

    /** Whitelist: unknown keys (outside required ∪ optional) are refusal; every
     *  required key must be present. Optional keys may be absent. */
    private static void requireKeys(JsonObject o, Set<String> required, Set<String> optional, String where)
            throws RefusalException {
        for (Map.Entry<String, JsonElement> e : o.entrySet()) {
            if (!required.contains(e.getKey()) && !optional.contains(e.getKey())) {
                throw new RefusalException("unknown key in " + where + ": " + e.getKey());
            }
        }
        for (String k : required) {
            if (!o.has(k)) throw new RefusalException("missing key in " + where + ": " + k);
        }
    }

    private static String asString(JsonObject o, String k) throws RefusalException {
        JsonElement e = o.get(k);
        if (!(e instanceof JsonPrimitive) || !((JsonPrimitive) e).isString()) {
            throw new RefusalException(k + " must be a string");
        }
        return e.getAsString();
    }

    private static int asInt(JsonObject o, String k) throws RefusalException {
        JsonElement e = o.get(k);
        if (!(e instanceof JsonPrimitive) || !((JsonPrimitive) e).isNumber()) {
            throw new RefusalException(k + " must be a number");
        }
        double d = e.getAsDouble();
        int i = (int) d;
        if (d != i) throw new RefusalException(k + " must be an integer");
        return i;
    }

    private static JsonObject asObject(JsonObject o, String k) throws RefusalException {
        JsonElement e = o.get(k);
        if (e == null || !e.isJsonObject()) throw new RefusalException(k + " must be an object");
        return e.getAsJsonObject();
    }

    /** Canonical bytes the verifier signs and the wallet re-derives — every
     *  security-relevant field, so nothing is malleable. Static so both the
     *  verifier (mint) and the wallet (check) compute it identically without
     *  depending on JSON key order. */
    public static String signedContent(String nonceB64, String origin, String verifierId,
            String epoch, String predicate, int value, int icaoRootMinVersion,
            String attestationTier, boolean modeBAccepted) {
        return signedContent(nonceB64, origin, verifierId, epoch, predicate, value,
                icaoRootMinVersion, attestationTier, modeBAccepted, false);
    }

    public static String signedContent(String nonceB64, String origin, String verifierId,
            String epoch, String predicate, int value, int icaoRootMinVersion,
            String attestationTier, boolean modeBAccepted, boolean personBound) {
        String s = "onebit-challenge-v1\n" + nonceB64 + "\n" + origin + "\n" + verifierId + "\n"
                + epoch + "\n" + predicate + "\n" + value + "\n" + icaoRootMinVersion + "\n"
                + attestationTier + "\n" + modeBAccepted;
        // Appended only when true, so bearer challenges keep the exact original tuple
        // (backward compatible); tampering with the flag still breaks the signature.
        return personBound ? s + "\n" + personBound : s;
    }

    public String signedContent() {
        return signedContent(java.util.Base64.getEncoder().encodeToString(nonce), origin,
                verifierId, epoch, predicate, value, icaoRootMinVersion, attestationTier,
                modeBAccepted, personBound);
    }

    /** Wallet-side authenticity check (V5, fail-closed): the challenge's `sig`
     *  must be a valid ECDSA signature, by the key whose SPKI-sha256 equals
     *  `verifier_id`, over signedContent(). The verifier_id is the trust anchor
     *  (holder trusts the origin↔verifier_id binding); this proves the challenge
     *  really came from that verifier and wasn't altered in transit. */
    public boolean verifySig() {
        try {
            byte[] h = java.security.MessageDigest.getInstance("SHA-256").digest(spki);
            StringBuilder hex = new StringBuilder(64);
            for (byte b : h) hex.append(Character.forDigit((b >> 4) & 0xf, 16))
                                .append(Character.forDigit(b & 0xf, 16));
            if (!hex.toString().equals(verifierId)) return false;   // key isn't the claimed verifier
            java.security.PublicKey pk = java.security.KeyFactory.getInstance("EC")
                    .generatePublic(new java.security.spec.X509EncodedKeySpec(spki));
            java.security.Signature s = java.security.Signature.getInstance("SHA256withECDSA");
            s.initVerify(pk);
            s.update(signedContent().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return s.verify(java.util.Base64.getDecoder().decode(sig));
        } catch (Exception e) {
            return false;   // malformed key/sig → treat as invalid
        }
    }

    private Challenge(byte[] nonce, String origin, String verifierId, String epoch,
                      String predicate, int value, int icaoRootMinVersion,
                      String attestationTier, boolean modeBAccepted, boolean personBound,
                      String sig, byte[] spki) {
        this.personBound = personBound;
        this.nonce = nonce;
        this.origin = origin;
        this.verifierId = verifierId;
        this.epoch = epoch;
        this.predicate = predicate;
        this.value = value;
        this.icaoRootMinVersion = icaoRootMinVersion;
        this.attestationTier = attestationTier;
        this.modeBAccepted = modeBAccepted;
        this.sig = sig;
        this.spki = spki;
    }
}